/* The operating system's part of the goose-ldap* tools: TCP and Unix
   (ldapi) sockets, waiting for input with a timeout, and a password read
   at the terminal without echo. POSIX: macOS and Linux. Each function
   returns -1 (or a negative value) on failure; strings arrive as Goose
   slices, { data, len }, not NUL-terminated. */

#define _XOPEN_SOURCE 600
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

typedef struct { const uint8_t *data; int64_t len; } net_slice;
typedef struct { uint8_t *data; int64_t len; } net_buf;

/* A slice as a C string, in a buffer of the caller's. */
static int cstring(net_slice s, char *out, size_t cap) {
    if (s.len < 0 || (size_t)s.len >= cap) return -1;
    memcpy(out, s.data, (size_t)s.len);
    out[s.len] = 0;
    return 0;
}

void net_init(void) { signal(SIGPIPE, SIG_IGN); }

/* host:port over TCP, each of the host's addresses in turn. */
int32_t net_connect(net_slice host, int32_t port) {
    char h[1024], p[16];
    if (cstring(host, h, sizeof h) < 0) return -1;
    snprintf(p, sizeof p, "%d", port);
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(h, p, &hints, &res) != 0) return -2;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    return fd;
}

/* A Unix socket, for ldapi://. */
int32_t net_connect_unix(net_slice path) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    if (cstring(path, a.sun_path, sizeof a.sun_path) < 0) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    return fd;
}

/* Up to buf.len bytes: how many, 0 at end of file, -1 on error, -2 when
   nothing came within timeout_ms (negative: wait for ever). */
int64_t net_read(int32_t fd, net_buf buf, int32_t timeout_ms) {
    struct pollfd p = { fd, POLLIN, 0 };
    int r;
    do { r = poll(&p, 1, timeout_ms); } while (r < 0 && errno == EINTR);
    if (r == 0) return -2;
    if (r < 0) return -1;
    ssize_t n;
    do { n = read(fd, buf.data, (size_t)buf.len); } while (n < 0 && errno == EINTR);
    return n < 0 ? -1 : (int64_t)n;
}

/* All of data, or -1. */
int64_t net_write(int32_t fd, net_slice data) {
    int64_t off = 0;
    while (off < data.len) {
        ssize_t n = write(fd, data.data + off, (size_t)(data.len - off));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += n;
    }
    return off;
}

void net_close(int32_t fd) { if (fd >= 0) close(fd); }

/* A password typed at the terminal, not echoed: its length, or -1. */
int64_t tty_secret(net_slice prompt, net_buf out) {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) return -1;
    if (write(fd, prompt.data, (size_t)prompt.len) < 0) { close(fd); return -1; }
    struct termios t, quiet;
    tcgetattr(fd, &t);
    quiet = t;
    quiet.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(fd, TCSAFLUSH, &quiet);
    int64_t n = 0;
    char ch;
    while (n < out.len && read(fd, &ch, 1) == 1 && ch != '\n' && ch != '\r') out.data[n++] = (uint8_t)ch;
    tcsetattr(fd, TCSAFLUSH, &t);
    if (write(fd, "\n", 1) < 0) {}
    close(fd);
    return n;
}
