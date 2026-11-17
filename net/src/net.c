/* net: gslib's sockets, behind net.goose, which http, ldap, dns, krb5,
   the servers of the tools and the examples share. TCP connections with
   a deadline on connecting, reads and writes with timeouts, and a check
   whether an idle connection has been closed; listening sockets and
   accepting connections; UDP, connected or not; Unix-domain stream
   sockets; waiting on several sockets; the system resolver. POSIX
   (macOS, Linux) and Windows (Winsock).
   A socket is an int64_t; strings arrive as Goose slices, { data, len },
   not NUL-terminated. An address crosses as a record of ADDR_LEN bytes
   (put_addr): the 16 bytes of the IP (IPv4 as ::ffff:a.b.c.d), its kind
   (4 or 6), a zero byte, the port (big-endian, 2 bytes) and the IPv6
   scope id (big-endian, 4 bytes); net.goose's Addr and AddrPort.

   Results: >= 0 on success, else one of the GSNET_E* codes below
   (net::ERR_* in net.goose). */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  if defined(__has_include)
#    if __has_include(<afunix.h>)
#      include <afunix.h>
#      define HAVE_AF_UNIX 1
#    endif
#  endif
typedef SOCKET sock_t;
typedef int socklen_type;
#  define BAD_SOCK INVALID_SOCKET
#else
#  define _XOPEN_SOURCE 700
#  define _DEFAULT_SOURCE
#  define _DARWIN_C_SOURCE
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <sys/un.h>
#  include <time.h>
#  include <unistd.h>
typedef int sock_t;
typedef socklen_t socklen_type;
#  define BAD_SOCK (-1)
#  define HAVE_AF_UNIX 1
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } gsnet_slice;
typedef struct { uint8_t *data; int64_t len; } gsnet_buf;
typedef struct { const int64_t *data; int64_t len; } gsnet_i64s;

#define GSNET_EARG     (-1)   /* a host or port that cannot be used */
#define GSNET_ERESOLVE (-2)   /* the name does not resolve */
#define GSNET_ECONNECT (-3)   /* refused or unreachable */
#define GSNET_ETIMEOUT (-4)
#define GSNET_EIO      (-5)   /* reset, or another error on the socket */

static int64_t now_ms(void) {
#if defined(_WIN32)
    return (int64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

#if defined(_WIN32)
static int started;
static void start(void) {
    if (!started) {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
        started = 1;
    }
}
static int sock_poll(sock_t s, short events, int timeout_ms) {
    WSAPOLLFD p;
    p.fd = s;
    p.events = events;
    p.revents = 0;
    int r = WSAPoll(&p, 1, timeout_ms);
    if (r > 0 && (p.revents & (POLLERR | POLLHUP | POLLNVAL)) && !(p.revents & events)) return 1;
    return r;
}
static void set_nonblocking(sock_t s, int on) { u_long v = on ? 1 : 0; ioctlsocket(s, FIONBIO, &v); }
static void sock_close(sock_t s) { closesocket(s); }
static int in_progress(void) { return WSAGetLastError() == WSAEWOULDBLOCK; }
static int would_block(void) { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
static void start(void) {}
/* A signal cuts poll short; it is resumed with what is left of the
   timeout, not the whole of it again (signals coming often enough would
   otherwise hold it for ever). */
static int sock_poll(sock_t s, short events, int timeout_ms) {
    struct pollfd p = { s, events, 0 };
    int64_t end = timeout_ms > 0 ? now_ms() + timeout_ms : 0;
    int r;
    for (;;) {
        r = poll(&p, 1, timeout_ms);
        if (r >= 0 || errno != EINTR) break;
        if (end) {
            int64_t l = end - now_ms();
            timeout_ms = l <= 0 ? 0 : (int)l;
        }
    }
    return r;
}
static void set_nonblocking(sock_t s, int on) {
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
}
static void sock_close(sock_t s) { close(s); }
static int in_progress(void) { return errno == EINPROGRESS; }
static int would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

/* A connected socket stays blocking, but read and write must never block
   in recv or send: POLLOUT promises room for some of a write, not all of
   it (a peer that stops reading would hold send for ever, past any
   timeout), and a POLLIN can be spurious. So write makes the socket
   non-blocking while it runs (macOS ignores MSG_DONTWAIT in send), and
   read passes MSG_DONTWAIT, or on Windows, which has no such flag, does
   as write does. */
#if defined(_WIN32) || !defined(MSG_DONTWAIT)
#  define RECV_FLAGS 0
#  define RECV_NONBLOCKING(s, on) set_nonblocking(s, on)
#else
#  define RECV_FLAGS MSG_DONTWAIT
#  define RECV_NONBLOCKING(s, on) ((void)0)
#endif

/* The time left before a deadline (ms), for poll: -1 for none. */
static int left(int64_t deadline) {
    if (deadline == 0) return -1;
    int64_t l = deadline - now_ms();
    return l < 0 ? 0 : (int)(l > 0x7fffffff ? 0x7fffffff : l);
}

/* A connection to host:port, each of its addresses tried in turn until
   timeout_ms (0: none) has passed. The host is a name or a numeric
   address, without brackets. getaddrinfo is not bounded by the timeout
   (it has none, and a thread to abandon it to would need -lpthread on
   older glibc and GetAddrInfoEx on Windows); the deadline is set before
   it, so the lookup's time comes off the time left to connect. */
int64_t gsnet_dial(gsnet_slice host, int32_t port, int32_t timeout_ms) {
    char h[256], p[16];
    if (host.len <= 0 || host.len >= (int64_t)sizeof h || port <= 0 || port > 65535) return GSNET_EARG;
    memcpy(h, host.data, (size_t)host.len);
    h[host.len] = 0;
    if (memchr(h, 0, (size_t)host.len)) return GSNET_EARG;
    snprintf(p, sizeof p, "%d", (int)port);
    start();
    int64_t deadline = timeout_ms > 0 ? now_ms() + timeout_ms : 0;
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(h, p, &hints, &res) != 0) return GSNET_ERESOLVE;
    int64_t result = GSNET_ECONNECT;
    for (ai = res; ai; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK) continue;
        set_nonblocking(s, 1);
        int ok = connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0;
        if (!ok && in_progress()) {
            int r = sock_poll(s, POLLOUT, left(deadline));
            if (r == 0) {
                sock_close(s);
                result = GSNET_ETIMEOUT;
                break;
            }
            int err = 0;
            socklen_t len = sizeof err;
            ok = r > 0 && getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len) == 0 && err == 0;
        }
        if (!ok) {
            sock_close(s);
            if (deadline && now_ms() >= deadline) { result = GSNET_ETIMEOUT; break; }
            continue;
        }
        set_nonblocking(s, 0);
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
#if defined(SO_NOSIGPIPE)
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
        result = (int64_t)s;
        break;
    }
    freeaddrinfo(res);
    return result;
}

/* Up to buf.len bytes: how many, 0 at the end of the stream, or an error;
   GSNET_ETIMEOUT if nothing came within timeout_ms (0: wait for ever). */
int64_t gsnet_read(int64_t fd, gsnet_buf buf, int32_t timeout_ms) {
    sock_t s = (sock_t)fd;
    int64_t deadline = timeout_ms > 0 ? now_ms() + timeout_ms : 0;
    size_t want = buf.len > (1 << 30) ? (size_t)1 << 30 : (size_t)buf.len;
    int64_t n;
    RECV_NONBLOCKING(s, 1);
    for (;;) {
#if defined(_WIN32)
        n = recv(s, (char *)buf.data, (int)want, RECV_FLAGS);
#else
        do { n = recv(s, buf.data, want, RECV_FLAGS); } while (n < 0 && errno == EINTR);
#endif
        if (n >= 0) break;
        if (!would_block()) { n = GSNET_EIO; break; }
        int r = sock_poll(s, POLLIN, left(deadline));
        if (r == 0) { n = GSNET_ETIMEOUT; break; }
        if (r < 0) { n = GSNET_EIO; break; }
    }
    RECV_NONBLOCKING(s, 0);
    return n;
}

/* All of data, or an error; GSNET_ETIMEOUT if the peer takes nothing
   for timeout_ms (0: wait for ever). The timeout counts from the last
   progress, not from the call: a peer that keeps taking some is waited
   for. */
int64_t gsnet_write(int64_t fd, gsnet_slice data, int32_t timeout_ms) {
    sock_t s = (sock_t)fd;
    int64_t off = 0, result = 0;
    set_nonblocking(s, 1);
    for (;;) {
        if (off >= data.len) { result = off; break; }
        int64_t want = data.len - off;
        if (want > (1 << 30)) want = 1 << 30;
        int64_t n;
#if defined(_WIN32)
        n = send(s, (const char *)data.data + off, (int)want, 0);
#elif defined(MSG_NOSIGNAL)
        do { n = send(s, data.data + off, (size_t)want, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
#else
        do { n = send(s, data.data + off, (size_t)want, 0); } while (n < 0 && errno == EINTR);
#endif
        if (n > 0) { off += n; continue; }
        if (n == 0 || !would_block()) { result = GSNET_EIO; break; }
        int r = sock_poll(s, POLLOUT, timeout_ms > 0 ? timeout_ms : -1);
        if (r == 0) { result = GSNET_ETIMEOUT; break; }
        if (r < 0) { result = GSNET_EIO; break; }
    }
    set_nonblocking(s, 0);
    return result;
}

/* Whether something has come on an idle connection: 1 (bytes, its end,
   or an error: either way it cannot carry a new request), 0 if nothing. */
int32_t gsnet_readable(int64_t fd) {
    int r = sock_poll((sock_t)fd, POLLIN, 0);
    return r != 0 ? 1 : 0;
}

void gsnet_close(int64_t fd) {
    if (fd >= 0) sock_close((sock_t)fd);
}

/* --- Addresses ---------------------------------------------------------- */

#define ADDR_LEN 24

/* A sockaddr as an address record into out (ADDR_LEN bytes): 0, or
   GSNET_EARG for a family that is neither IPv4 nor IPv6. */
static int put_addr(const struct sockaddr *sa, gsnet_buf out) {
    if (out.len < ADDR_LEN) return GSNET_EARG;
    uint8_t *o = out.data;
    memset(o, 0, ADDR_LEN);
    unsigned port;
    uint32_t scope = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
        o[10] = 0xff;
        o[11] = 0xff;
        memcpy(o + 12, &a->sin_addr, 4);
        o[16] = 4;
        port = ntohs(a->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
        memcpy(o, &a->sin6_addr, 16);
        o[16] = 6;
        port = ntohs(a->sin6_port);
        scope = (uint32_t)a->sin6_scope_id;
    } else {
        return GSNET_EARG;
    }
    o[18] = (uint8_t)(port >> 8);
    o[19] = (uint8_t)port;
    o[20] = (uint8_t)(scope >> 24);
    o[21] = (uint8_t)(scope >> 16);
    o[22] = (uint8_t)(scope >> 8);
    o[23] = (uint8_t)scope;
    return 0;
}

/* An address record as a sockaddr: its length, or 0 for a record that is
   not one. */
static socklen_type get_addr(gsnet_slice in, struct sockaddr_storage *ss) {
    if (in.len < ADDR_LEN) return 0;
    const uint8_t *a = in.data;
    unsigned port = ((unsigned)a[18] << 8) | a[19];
    memset(ss, 0, sizeof *ss);
    if (a[16] == 4) {
        struct sockaddr_in *s = (struct sockaddr_in *)ss;
        s->sin_family = AF_INET;
        s->sin_port = htons((uint16_t)port);
        memcpy(&s->sin_addr, a + 12, 4);
        return (socklen_type)sizeof *s;
    }
    if (a[16] == 6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons((uint16_t)port);
        memcpy(&s->sin6_addr, a, 16);
        s->sin6_scope_id = ((uint32_t)a[20] << 24) | ((uint32_t)a[21] << 16) | ((uint32_t)a[22] << 8) | a[23];
        return (socklen_type)sizeof *s;
    }
    return 0;
}

static int cstr(char *out, size_t cap, gsnet_slice s) {
    if (s.len < 0 || (size_t)s.len >= cap) return 0;
    memcpy(out, s.data, (size_t)s.len);
    out[s.len] = 0;
    return memchr(out, 0, (size_t)s.len) == NULL;
}

/* host:port through getaddrinfo, or NULL. passive: an empty host is every
   address (AI_PASSIVE), for listening. */
static struct addrinfo *resolve(gsnet_slice host, int32_t port, int socktype, int passive) {
    char h[256], p[16];
    if (port < 0 || port > 65535 || !cstr(h, sizeof h, host)) return NULL;
    if (!passive && !h[0]) return NULL;
    snprintf(p, sizeof p, "%d", (int)port);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    if (passive) hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(h[0] ? h : NULL, p, &hints, &res) != 0) return NULL;
    return res;
}

/* The address a socket is bound to, into out: 0, or an error. */
int64_t gsnet_local_addr(int64_t fd, gsnet_buf out) {
    struct sockaddr_storage ss;
    socklen_type len = sizeof ss;
    if (getsockname((sock_t)fd, (struct sockaddr *)&ss, &len) != 0) return GSNET_EIO;
    return put_addr((struct sockaddr *)&ss, out);
}

/* The other end of a connected socket, into out: 0, or an error. */
int64_t gsnet_peer_addr(int64_t fd, gsnet_buf out) {
    struct sockaddr_storage ss;
    socklen_type len = sizeof ss;
    if (getpeername((sock_t)fd, (struct sockaddr *)&ss, &len) != 0) return GSNET_EIO;
    return put_addr((struct sockaddr *)&ss, out);
}

/* The system resolver's addresses for host (getaddrinfo: the hosts file,
   DNS, mDNS, as the system has it), each once, into out as records, at
   most out.len / ADDR_LEN of them: how many, or GSNET_ERESOLVE. */
int64_t gsnet_lookup(gsnet_slice host, gsnet_buf out) {
    char h[256];
    if (host.len <= 0 || !cstr(h, sizeof h, host)) return GSNET_EARG;
    start();
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(h, NULL, &hints, &res) != 0) return GSNET_ERESOLVE;
    int64_t n = 0;
    for (ai = res; ai && (n + 1) * ADDR_LEN <= out.len; ai = ai->ai_next) {
        gsnet_buf slot = { out.data + n * ADDR_LEN, ADDR_LEN };
        if (put_addr(ai->ai_addr, slot) != 0) continue;
        int dup = 0;
        for (int64_t k = 0; k < n && !dup; k++)
            dup = memcmp(out.data + k * ADDR_LEN, slot.data, 17) == 0;
        if (!dup) n++;
    }
    freeaddrinfo(res);
    return n > 0 ? n : GSNET_ERESOLVE;
}

/* The name an address has in the system resolver (reverse DNS, the hosts
   file), into out: its length, GSNET_ERESOLVE when it has none, or an
   error. */
int64_t gsnet_lookup_addr(gsnet_slice addr, gsnet_buf out) {
    struct sockaddr_storage ss;
    socklen_type len = get_addr(addr, &ss);
    char h[NI_MAXHOST];
    if (!len) return GSNET_EARG;
    start();
    if (getnameinfo((struct sockaddr *)&ss, len, h, sizeof h, NULL, 0, NI_NAMEREQD) != 0) return GSNET_ERESOLVE;
    size_t n = strlen(h);
    if ((int64_t)n > out.len) return GSNET_EARG;
    memcpy(out.data, h, n);
    return (int64_t)n;
}

/* --- Listening ---------------------------------------------------------- */

/* The sockets made here (listening ones, UDP ones) are non-blocking: one
   poll calls readable may have nothing by the time it is read (a datagram
   dropped for its checksum, a connection reset before accept), and a
   blocking accept or recv would then wait for ever, past any timeout. On
   EWOULDBLOCK each waits again, until its deadline. */

/* Waits for s to be readable until deadline (0: none): > 0 if it is,
   GSNET_ETIMEOUT, or GSNET_EIO. */
static int wait_readable(sock_t s, int64_t deadline) {
    int r = sock_poll(s, POLLIN, left(deadline));
    return r == 0 ? GSNET_ETIMEOUT : r < 0 ? GSNET_EIO : r;
}

/* A socket listening on addr:port (addr "" for every address, port 0 for
   one the OS picks): UDP when tcp is 0, else TCP with a backlog of 64. */
int64_t gsnet_listen(gsnet_slice addr, int32_t port, int32_t tcp) {
    start();
    struct addrinfo *res = resolve(addr, port, tcp ? SOCK_STREAM : SOCK_DGRAM, 1), *ai;
    if (!res) return addr.len > 255 || port < 0 || port > 65535 ? GSNET_EARG : GSNET_ERESOLVE;
    int64_t result = GSNET_ECONNECT;
    for (ai = res; ai; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK) continue;
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
        if (bind(s, ai->ai_addr, (socklen_type)ai->ai_addrlen) != 0 || (tcp && listen(s, 64) != 0)) {
            sock_close(s);
            continue;
        }
        set_nonblocking(s, 1);
#if defined(_WIN32)
        /* Windows fails the next recvfrom with WSAECONNRESET after an ICMP
           port unreachable for an earlier reply: a client that went away
           would cost the server a datagram. Off, as other servers have it. */
        if (!tcp) {
#  ifndef SIO_UDP_CONNRESET
#    define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#  endif
            BOOL off = FALSE;
            DWORD got = 0;
            WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof off, NULL, 0, &got, NULL, NULL);
        }
#endif
        result = (int64_t)s;
        break;
    }
    freeaddrinfo(res);
    return result;
}

/* A connection on a listening TCP socket, or GSNET_ETIMEOUT if none came
   within timeout_ms (0: wait for ever). The connection is blocking, as
   dial's are (some systems pass on the listening socket's non-blocking
   mode), with TCP_NODELAY, and writing to it after the peer closed gives
   GSNET_EIO, not SIGPIPE. */
int64_t gsnet_accept(int64_t fd, int32_t timeout_ms) {
    int64_t deadline = timeout_ms > 0 ? now_ms() + timeout_ms : 0;
    sock_t c;
    for (;;) {
        int r = wait_readable((sock_t)fd, deadline);
        if (r < 0) return r;
        c = accept((sock_t)fd, NULL, NULL);
        if (c != BAD_SOCK) break;
        if (!would_block()) {
#if !defined(_WIN32)
            if (errno == EINTR || errno == ECONNABORTED) continue;
#endif
            return GSNET_EIO;
        }
    }
    set_nonblocking(c, 0);
    int one = 1;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
#if defined(SO_NOSIGPIPE)
    setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    return (int64_t)c;
}

/* --- UDP ---------------------------------------------------------------- */

/* A UDP socket connected to host:port: the kernel then drops datagrams
   from anyone else, and the source port is the OS's random one. */
int64_t gsnet_dial_udp(gsnet_slice host, int32_t port) {
    start();
    if (host.len <= 0 || port <= 0 || port > 65535) return GSNET_EARG;
    struct addrinfo *res = resolve(host, port, SOCK_DGRAM, 0), *ai;
    if (!res) return host.len > 255 ? GSNET_EARG : GSNET_ERESOLVE;
    int64_t result = GSNET_ECONNECT;
    for (ai = res; ai; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK) continue;
        if (connect(s, ai->ai_addr, (socklen_type)ai->ai_addrlen) != 0) { sock_close(s); continue; }
        set_nonblocking(s, 1);
        result = (int64_t)s;
        break;
    }
    freeaddrinfo(res);
    return result;
}

/* Sends one datagram on a connected socket: the bytes sent, or an error. */
int64_t gsnet_send(int64_t fd, gsnet_slice data) {
    if (data.len < 0 || data.len > 65535) return GSNET_EARG;
    int64_t n = send((sock_t)fd, (const char *)data.data, (int)data.len, 0);
    return n < 0 ? GSNET_EIO : n;
}

/* One datagram, up to buf.len bytes (the rest of a longer one is lost):
   its length, or GSNET_ETIMEOUT if none came within timeout_ms (0: wait
   for ever, < 0: not at all). On a connected socket, a refused port (ICMP)
   shows as GSNET_ECONNECT. With from (from.len >= ADDR_LEN), the sender's
   address goes there. */
int64_t gsnet_recv(int64_t fd, gsnet_buf buf, gsnet_buf from, int32_t timeout_ms) {
    int64_t deadline = timeout_ms > 0 ? now_ms() + timeout_ms : 0;
    for (;;) {
        if (timeout_ms >= 0) {
            int r = wait_readable((sock_t)fd, deadline);
            if (r < 0) return r;
        }
        struct sockaddr_storage ss;
        socklen_type len = sizeof ss;
        int want = buf.len > 65535 ? 65535 : (int)buf.len;
        int64_t n = recvfrom((sock_t)fd, (char *)buf.data, want, 0, (struct sockaddr *)&ss, &len);
        if (n >= 0) {
            if (from.len >= ADDR_LEN && put_addr((struct sockaddr *)&ss, from) != 0) memset(from.data, 0, ADDR_LEN);
            return n;
        }
#if defined(_WIN32)
        if (WSAGetLastError() == WSAEMSGSIZE) return want;
#endif
        if (!would_block()) return GSNET_ECONNECT;
        if (timeout_ms < 0) return GSNET_ETIMEOUT;
    }
}

/* Sends a datagram to an address (a record): the bytes sent, or an error. */
int64_t gsnet_send_to(int64_t fd, gsnet_slice data, gsnet_slice to) {
    struct sockaddr_storage ss;
    socklen_type len = get_addr(to, &ss);
    if (!len || data.len < 0 || data.len > 65535) return GSNET_EARG;
    int64_t n = sendto((sock_t)fd, (const char *)data.data, (int)data.len, 0, (struct sockaddr *)&ss, len);
    return n < 0 ? GSNET_EIO : n;
}

/* --- Waiting, partial writes, shutting down ----------------------------- */

#define POLL_MAX 256

/* Waits up to timeout_ms (0: wait for ever, < 0: not at all) for any of
   fds (negative entries ignored, at most POLL_MAX) to be ready: readable
   (or at its end, or failed) where want[i] has bit 1, writable where it
   has bit 2. ready[i] gets the bits that are, from what was asked: how
   many are, or GSNET_ETIMEOUT. On POSIX any descriptor (a pipe, a
   terminal), on Windows sockets only. */
int64_t gsnet_poll(gsnet_i64s fds, gsnet_slice want, gsnet_buf ready, int32_t timeout_ms) {
#if defined(_WIN32)
    WSAPOLLFD p[POLL_MAX];
#else
    struct pollfd p[POLL_MAX];
#endif
    int map[POLL_MAX];
    int n = 0;
    if (want.len < fds.len || ready.len < fds.len) return GSNET_EARG;
    for (int64_t i = 0; i < fds.len; i++) {
        ready.data[i] = 0;
        if (fds.data[i] < 0 || !(want.data[i] & 3)) continue;
        if (n == POLL_MAX) return GSNET_EARG;
        p[n].fd = (sock_t)fds.data[i];
        p[n].events = (short)(((want.data[i] & 1) ? POLLIN : 0) | ((want.data[i] & 2) ? POLLOUT : 0));
        p[n].revents = 0;
        map[n++] = (int)i;
    }
    int ms = timeout_ms > 0 ? timeout_ms : timeout_ms == 0 ? -1 : 0;
    int r;
    if (n == 0) return GSNET_EARG;
#if defined(_WIN32)
    r = WSAPoll(p, (ULONG)n, ms);
#else
    int64_t end = ms > 0 ? now_ms() + ms : 0;
    for (;;) {
        r = poll(p, (nfds_t)n, ms);
        if (r >= 0 || errno != EINTR) break;
        if (end) { int64_t l = end - now_ms(); ms = l <= 0 ? 0 : (int)l; }
    }
#endif
    if (r == 0) return GSNET_ETIMEOUT;
    if (r < 0) return GSNET_EIO;
    int64_t count = 0;
    for (int i = 0; i < n; i++) {
        short ev = p[i].revents;
        uint8_t w = want.data[map[i]], got = 0;
        /* An end or an error is news for a reader and a writer alike; and
           POLLNVAL too: macOS cannot poll device files such as /dev/null,
           and a read then says what they hold. */
        int bad = (ev & (POLLHUP | POLLERR | POLLNVAL)) != 0;
        if ((w & 1) && ((ev & POLLIN) || bad)) got |= 1;
        if ((w & 2) && ((ev & POLLOUT) || bad)) got |= 2;
        ready.data[map[i]] = got;
        if (got) count++;
    }
    return count;
}

/* One send of what fits, without waiting: how many bytes went (0 when
   the socket is full), or GSNET_EIO. */
int64_t gsnet_write_some(int64_t fd, gsnet_slice data) {
    sock_t s = (sock_t)fd;
    int want = data.len > (1 << 30) ? 1 << 30 : (int)data.len;
    int64_t n;
    set_nonblocking(s, 1);
#if defined(_WIN32)
    n = send(s, (const char *)data.data, want, 0);
#elif defined(MSG_NOSIGNAL)
    do { n = send(s, data.data, (size_t)want, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
#else
    do { n = send(s, data.data, (size_t)want, 0); } while (n < 0 && errno == EINTR);
#endif
    int blocked = n < 0 && would_block();
    set_nonblocking(s, 0);
    if (n < 0) return blocked ? 0 : GSNET_EIO;
    return n;
}

/* Ends one direction of a connection: 1 reading, 2 writing (the peer
   reads its end), 3 both. 0, or GSNET_EIO. */
int64_t gsnet_shutdown(int64_t fd, int32_t how) {
#if defined(_WIN32)
    int h = how == 1 ? SD_RECEIVE : how == 2 ? SD_SEND : SD_BOTH;
#else
    int h = how == 1 ? SHUT_RD : how == 2 ? SHUT_WR : SHUT_RDWR;
#endif
    if (how < 1 || how > 3) return GSNET_EARG;
    return shutdown((sock_t)fd, h) == 0 ? 0 : GSNET_EIO;
}

/* --- Unix-domain sockets ------------------------------------------------ */

/* A stream connection to the Unix-domain socket at path (Windows 10 1803
   and later have them too), blocking as dial's are: the socket,
   GSNET_EARG for a path too long, or GSNET_ECONNECT. */
int64_t gsnet_dial_unix(gsnet_slice path) {
#if defined(HAVE_AF_UNIX)
    struct sockaddr_un a;
    start();
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    if (path.len <= 0 || path.len >= (int64_t)sizeof a.sun_path || memchr(path.data, 0, (size_t)path.len)) return GSNET_EARG;
    memcpy(a.sun_path, path.data, (size_t)path.len);
    sock_t s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == BAD_SOCK) return GSNET_ECONNECT;
    if (connect(s, (struct sockaddr *)&a, (socklen_type)sizeof a) != 0) { sock_close(s); return GSNET_ECONNECT; }
#  if defined(SO_NOSIGPIPE)
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#  endif
    return (int64_t)s;
#else
    (void)path;
    return GSNET_EARG;
#endif
}
