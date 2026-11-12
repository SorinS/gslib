/* dnsnet: the sockets of dns.client and dns.server (client.goose,
   server.goose): UDP sockets connected to a server (so only its replies
   arrive), UDP and TCP sockets listening on an address, datagrams with
   their senders, accepting connections, and waiting on two sockets at
   once. TCP connections, reads and writes are http.client's
   (net/http/src/httpnet.c). POSIX (macOS, Linux) and Windows (Winsock).
   A socket is an int64_t; strings arrive as Goose slices, { data, len },
   not NUL-terminated.

   Results: >= 0 on success, else one of the DNSNET_E* codes below. A
   peer's address travels as the bytes of its sockaddr (at most 128). */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
typedef SOCKET sock_t;
typedef int socklen_type;
#  define BAD_SOCK INVALID_SOCKET
#else
#  define _XOPEN_SOURCE 700
#  define _DEFAULT_SOURCE
#  define _DARWIN_C_SOURCE
#  include <arpa/inet.h>
#  include <errno.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
typedef int sock_t;
typedef socklen_t socklen_type;
#  define BAD_SOCK (-1)
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } dnsnet_slice;
typedef struct { uint8_t *data; int64_t len; } dnsnet_buf;

#define DNSNET_EARG     (-1)   /* a host, port or buffer that cannot be used */
#define DNSNET_ERESOLVE (-2)   /* the name does not resolve */
#define DNSNET_ECONNECT (-3)   /* refused, unreachable, or the address is in use */
#define DNSNET_ETIMEOUT (-4)
#define DNSNET_EIO      (-5)

#if defined(_WIN32)
static int started;
static void start(void) {
    if (!started) {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
        started = 1;
    }
}
static int sock_poll(WSAPOLLFD *p, int n, int timeout_ms) { return WSAPoll(p, (ULONG)n, timeout_ms); }
typedef WSAPOLLFD pollfd_t;
static void sock_close(sock_t s) { closesocket(s); }
#else
static void start(void) {}
typedef struct pollfd pollfd_t;
static int sock_poll(struct pollfd *p, int n, int timeout_ms) {
    int r;
    do { r = poll(p, (nfds_t)n, timeout_ms); } while (r < 0 && errno == EINTR);
    return r;
}
static void sock_close(sock_t s) { close(s); }
#endif

static int cstr(char *out, size_t cap, dnsnet_slice s) {
    if (s.len < 0 || (size_t)s.len >= cap) return 0;
    memcpy(out, s.data, (size_t)s.len);
    out[s.len] = 0;
    return memchr(out, 0, (size_t)s.len) == NULL;
}

static struct addrinfo *resolve(dnsnet_slice host, int32_t port, int socktype, int passive) {
    char h[256], p[16];
    if (port < 0 || port > 65535) return NULL;
    if (!cstr(h, sizeof h, host)) return NULL;
    snprintf(p, sizeof p, "%d", (int)port);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    if (passive) hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(h[0] ? h : NULL, p, &hints, &res) != 0) return NULL;
    return res;
}

/* A UDP socket connected to host:port: the kernel then drops datagrams
   from anyone else, and the source port is the OS's random one. */
int64_t dnsnet_udp_open(dnsnet_slice host, int32_t port) {
    start();
    if (host.len <= 0 || port <= 0) return DNSNET_EARG;
    struct addrinfo *res = resolve(host, port, SOCK_DGRAM, 0), *ai;
    if (!res) return DNSNET_ERESOLVE;
    int64_t result = DNSNET_ECONNECT;
    for (ai = res; ai; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK) continue;
        if (connect(s, ai->ai_addr, (socklen_type)ai->ai_addrlen) != 0) { sock_close(s); continue; }
        result = (int64_t)s;
        break;
    }
    freeaddrinfo(res);
    return result;
}

/* Sends one datagram on a connected socket: the bytes sent, or an error. */
int64_t dnsnet_send(int64_t fd, dnsnet_slice data) {
    if (data.len < 0 || data.len > 65535) return DNSNET_EARG;
    int64_t n = send((sock_t)fd, (const char *)data.data, (int)data.len, 0);
    return n < 0 ? DNSNET_EIO : n;
}

/* One datagram, up to buf.len bytes: its length, or DNSNET_ETIMEOUT if
   none came within timeout_ms (0: wait for ever). On a connected socket,
   a refused port (ICMP) shows as DNSNET_ECONNECT. */
int64_t dnsnet_recv(int64_t fd, dnsnet_buf buf, int32_t timeout_ms) {
    pollfd_t p;
    p.fd = (sock_t)fd;
    p.events = POLLIN;
    p.revents = 0;
    int r = sock_poll(&p, 1, timeout_ms > 0 ? timeout_ms : -1);
    if (r == 0) return DNSNET_ETIMEOUT;
    if (r < 0) return DNSNET_EIO;
    int64_t n = recv((sock_t)fd, (char *)buf.data, (int)buf.len, 0);
    if (n < 0) return DNSNET_ECONNECT;
    return n;
}

void dnsnet_close(int64_t fd) { sock_close((sock_t)fd); }

/* A socket listening on addr:port (addr "" for every address, port 0 for
   one the OS picks): UDP when tcp is 0, else TCP with a backlog. */
int64_t dnsnet_listen(dnsnet_slice addr, int32_t port, int32_t tcp) {
    start();
    struct addrinfo *res = resolve(addr, port, tcp ? SOCK_STREAM : SOCK_DGRAM, 1), *ai;
    if (!res) return DNSNET_ERESOLVE;
    int64_t result = DNSNET_ECONNECT;
    for (ai = res; ai; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK) continue;
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
        if (bind(s, ai->ai_addr, (socklen_type)ai->ai_addrlen) != 0 || (tcp && listen(s, 64) != 0)) {
            sock_close(s);
            continue;
        }
        result = (int64_t)s;
        break;
    }
    freeaddrinfo(res);
    return result;
}

/* The port a socket is bound to, or an error. */
int32_t dnsnet_local_port(int64_t fd) {
    struct sockaddr_storage ss;
    socklen_type len = sizeof ss;
    if (getsockname((sock_t)fd, (struct sockaddr *)&ss, &len) != 0) return DNSNET_EIO;
    if (ss.ss_family == AF_INET) return ntohs(((struct sockaddr_in *)&ss)->sin_port);
    if (ss.ss_family == AF_INET6) return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    return DNSNET_EIO;
}

/* One datagram on a listening socket, and who sent it: the sender's
   sockaddr goes to from (its length in from_len[0]). */
int64_t dnsnet_recvfrom(int64_t fd, dnsnet_buf buf, dnsnet_buf from, dnsnet_buf from_len) {
    struct sockaddr_storage ss;
    socklen_type len = sizeof ss;
    if (from.len < (int64_t)sizeof ss || from_len.len < 1) return DNSNET_EARG;
    int64_t n = recvfrom((sock_t)fd, (char *)buf.data, (int)buf.len, 0, (struct sockaddr *)&ss, &len);
    if (n < 0) return DNSNET_EIO;
    memcpy(from.data, &ss, (size_t)len);
    from_len.data[0] = (uint8_t)len;
    return n;
}

/* Sends a datagram to the sender recvfrom gave. */
int64_t dnsnet_sendto(int64_t fd, dnsnet_slice data, dnsnet_slice to) {
    if (to.len <= 0 || to.len > (int64_t)sizeof(struct sockaddr_storage)) return DNSNET_EARG;
    struct sockaddr_storage ss;
    memcpy(&ss, to.data, (size_t)to.len);
    int64_t n = sendto((sock_t)fd, (const char *)data.data, (int)data.len, 0, (struct sockaddr *)&ss, (socklen_type)to.len);
    return n < 0 ? DNSNET_EIO : n;
}

/* The sender's address as text ("192.0.2.1" or "2001:db8::1"), into out:
   its length, or an error. */
int64_t dnsnet_addr_text(dnsnet_slice sa, dnsnet_buf out) {
    char h[64];
    if (sa.len <= 0 || sa.len > (int64_t)sizeof(struct sockaddr_storage)) return DNSNET_EARG;
    struct sockaddr_storage ss;
    memcpy(&ss, sa.data, (size_t)sa.len);
    if (getnameinfo((struct sockaddr *)&ss, (socklen_type)sa.len, h, sizeof h, NULL, 0, NI_NUMERICHOST) != 0) return DNSNET_EIO;
    size_t n = strlen(h);
    if ((int64_t)n > out.len) return DNSNET_EARG;
    memcpy(out.data, h, n);
    return (int64_t)n;
}

/* A connection on a listening TCP socket, or DNSNET_ETIMEOUT. */
int64_t dnsnet_accept(int64_t fd, int32_t timeout_ms) {
    pollfd_t p;
    p.fd = (sock_t)fd;
    p.events = POLLIN;
    p.revents = 0;
    int r = sock_poll(&p, 1, timeout_ms > 0 ? timeout_ms : -1);
    if (r == 0) return DNSNET_ETIMEOUT;
    if (r < 0) return DNSNET_EIO;
    sock_t c = accept((sock_t)fd, NULL, NULL);
    if (c == BAD_SOCK) return DNSNET_EIO;
#if defined(SO_NOSIGPIPE)
    int one = 1;
    setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    return (int64_t)c;
}

/* Waits for either socket (-1: none) to be readable: 1 for a, 2 for b,
   3 for both, or DNSNET_ETIMEOUT. */
int32_t dnsnet_wait2(int64_t a, int64_t b, int32_t timeout_ms) {
    pollfd_t p[2];
    int n = 0, ia = -1, ib = -1;
    if (a >= 0) { p[n].fd = (sock_t)a; p[n].events = POLLIN; p[n].revents = 0; ia = n++; }
    if (b >= 0) { p[n].fd = (sock_t)b; p[n].events = POLLIN; p[n].revents = 0; ib = n++; }
    if (n == 0) return DNSNET_EARG;
    int r = sock_poll(p, n, timeout_ms > 0 ? timeout_ms : -1);
    if (r == 0) return DNSNET_ETIMEOUT;
    if (r < 0) return DNSNET_EIO;
    int32_t out = 0;
    if (ia >= 0 && p[ia].revents) out |= 1;
    if (ib >= 0 && p[ib].revents) out |= 2;
    return out;
}
