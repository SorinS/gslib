/* krb5sys: what krb5 needs from the system beyond http's TCP sockets
   (net/http/src/httpnet.c, which krb5.net also uses): a UDP exchange with
   a KDC, files only their owner may read (credential caches, keytabs),
   the user's id for the default cache's name, and a host's canonical name.
   POSIX (macOS, Linux) and Windows. Strings arrive as Goose slices,
   { data, len }, not NUL-terminated.

   Results: >= 0 on success, else one of the KRB5SYS_E* codes below. */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <io.h>
#  include <fcntl.h>
#  include <sys/stat.h>
typedef SOCKET sock_t;
#  define BAD_SOCK INVALID_SOCKET
#else
#  define _XOPEN_SOURCE 700
#  define _DEFAULT_SOURCE
#  define _DARWIN_C_SOURCE
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <time.h>
#  include <unistd.h>
typedef int sock_t;
#  define BAD_SOCK (-1)
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } krb5sys_slice;
typedef struct { uint8_t *data; int64_t len; } krb5sys_buf;

#define KRB5SYS_EARG     (-1)   /* a host, port or path that cannot be used */
#define KRB5SYS_ERESOLVE (-2)   /* the name does not resolve */
#define KRB5SYS_ECONNECT (-3)   /* refused or unreachable */
#define KRB5SYS_ETIMEOUT (-4)
#define KRB5SYS_EIO      (-5)

static int cstr(char *out, size_t cap, krb5sys_slice s) {
    if (s.len <= 0 || (size_t)s.len >= cap) return 0;
    memcpy(out, s.data, (size_t)s.len);
    out[s.len] = 0;
    return memchr(out, 0, (size_t)s.len) == NULL;
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
static int wait_readable(sock_t s, int timeout_ms) {
    WSAPOLLFD p;
    p.fd = s;
    p.events = POLLIN;
    p.revents = 0;
    return WSAPoll(&p, 1, timeout_ms);
}
static void sock_close(sock_t s) { closesocket(s); }
#else
static void start(void) {}
static int wait_readable(sock_t s, int timeout_ms) {
    struct pollfd p = { s, POLLIN, 0 };
    int r;
    do { r = poll(&p, 1, timeout_ms); } while (r < 0 && errno == EINTR);
    return r;
}
static void sock_close(sock_t s) { close(s); }
#endif

/* Sends req to host:port over UDP and waits up to timeout_ms for one
   datagram back: its length (the bytes in out), or an error. Each of the
   host's addresses is tried in turn. The socket is connected, so only
   the KDC's own replies are taken. */
int64_t krb5sys_udp_exchange(krb5sys_slice host, int32_t port, krb5sys_slice req, krb5sys_buf out, int32_t timeout_ms) {
    char h[256], p[16];
    if (!cstr(h, sizeof h, host) || port <= 0 || port > 65535 || req.len <= 0 || out.len <= 0) return KRB5SYS_EARG;
    snprintf(p, sizeof p, "%d", (int)port);
    start();
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(h, p, &hints, &res) != 0) return KRB5SYS_ERESOLVE;
    int64_t result = KRB5SYS_ECONNECT;
    for (ai = res; ai; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK) continue;
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) != 0) { sock_close(s); continue; }
#if defined(_WIN32)
        int sent = send(s, (const char *)req.data, (int)req.len, 0);
#else
        ssize_t sent;
        do { sent = send(s, req.data, (size_t)req.len, 0); } while (sent < 0 && errno == EINTR);
#endif
        if (sent != req.len) { sock_close(s); result = KRB5SYS_EIO; continue; }
        int r = wait_readable(s, timeout_ms > 0 ? timeout_ms : -1);
        if (r == 0) { sock_close(s); result = KRB5SYS_ETIMEOUT; continue; }
        if (r < 0) { sock_close(s); result = KRB5SYS_EIO; continue; }
#if defined(_WIN32)
        int n = recv(s, (char *)out.data, (int)out.len, 0);
#else
        ssize_t n;
        do { n = recv(s, out.data, (size_t)out.len, 0); } while (n < 0 && errno == EINTR);
#endif
        sock_close(s);
        /* An ICMP port unreachable shows as a refused receive. */
        if (n < 0) { result = KRB5SYS_ECONNECT; continue; }
        result = (int64_t)n;
        break;
    }
    freeaddrinfo(res);
    return result;
}

/* Writes data to path, readable and writable by its owner only (0600),
   all or nothing: a new file beside it, renamed over it. 0 or an error. */
int32_t krb5sys_write_private(krb5sys_slice path, krb5sys_slice data) {
    char pth[4096], tmp[4200];
    if (!cstr(pth, sizeof pth, path) || data.len < 0) return KRB5SYS_EARG;
    for (int attempt = 0; attempt < 100; attempt++) {
#if defined(_WIN32)
        snprintf(tmp, sizeof tmp, "%s.%lu.%d.tmp", pth, (unsigned long)GetCurrentProcessId(), attempt);
        int fd = _open(tmp, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
#else
        snprintf(tmp, sizeof tmp, "%s.%ld.%d.tmp", pth, (long)getpid(), attempt);
        int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
        if (fd < 0) {
#if !defined(_WIN32)
            if (errno == EEXIST) continue;
#endif
            return KRB5SYS_EIO;
        }
        int64_t off = 0;
        while (off < data.len) {
#if defined(_WIN32)
            int n = _write(fd, data.data + off, (unsigned)(data.len - off > (1 << 30) ? (1 << 30) : data.len - off));
#else
            ssize_t n;
            do { n = write(fd, data.data + off, (size_t)(data.len - off)); } while (n < 0 && errno == EINTR);
#endif
            if (n <= 0) break;
            off += n;
        }
#if defined(_WIN32)
        int closed = _close(fd) == 0;
        int ok = off == data.len && closed && MoveFileExA(tmp, pth, MOVEFILE_REPLACE_EXISTING);
        if (!ok) _unlink(tmp);
#else
        int synced = fsync(fd) == 0;
        int closed = close(fd) == 0;
        int ok = off == data.len && synced && closed && rename(tmp, pth) == 0;
        if (!ok) unlink(tmp);
#endif
        return ok ? 0 : KRB5SYS_EIO;
    }
    return KRB5SYS_EIO;
}

/* The user's numeric id (for /tmp/krb5cc_<uid>), or -1 where there is
   none (Windows). */
int64_t krb5sys_uid(void) {
#if defined(_WIN32)
    return -1;
#else
    return (int64_t)getuid();
#endif
}

/* This machine's host name into out: its length, or an error. */
int64_t krb5sys_hostname(krb5sys_buf out) {
    char h[256];
    start();
    if (gethostname(h, sizeof h) != 0) return KRB5SYS_EIO;
    h[sizeof h - 1] = 0;
    size_t n = strlen(h);
    if ((int64_t)n > out.len) return KRB5SYS_EARG;
    memcpy(out.data, h, n);
    return (int64_t)n;
}

/* A host's canonical name as the resolver gives it (getaddrinfo's
   AI_CANONNAME, which follows CNAMEs), as MIT does for host-based service
   names with dns_canonicalize_hostname: its length, or an error. */
int64_t krb5sys_canonical_host(krb5sys_slice host, krb5sys_buf out) {
    char h[256];
    if (!cstr(h, sizeof h, host)) return KRB5SYS_EARG;
    start();
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo(h, NULL, &hints, &res) != 0) return KRB5SYS_ERESOLVE;
    int64_t result = KRB5SYS_ERESOLVE;
    if (res && res->ai_canonname) {
        size_t n = strlen(res->ai_canonname);
        if ((int64_t)n <= out.len) {
            memcpy(out.data, res->ai_canonname, n);
            result = (int64_t)n;
        } else {
            result = KRB5SYS_EARG;
        }
    }
    freeaddrinfo(res);
    return result;
}
