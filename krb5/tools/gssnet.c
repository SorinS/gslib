/* gssnet: TCP for krb5's gss tool (gss.goose): a listener on 127.0.0.1
   only (the tests' hosts take no outside connections), accept, connect,
   and whole reads and writes. POSIX. Sockets are int32_t; strings arrive
   as Goose slices. */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct { const uint8_t *data; int64_t len; } gssnet_slice;
typedef struct { uint8_t *data; int64_t len; } gssnet_buf;

/* A listener on 127.0.0.1:port (0: any free port), or -1. */
int32_t gssnet_listen(int32_t port) {
    signal(SIGPIPE, SIG_IGN);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 16) != 0) { close(s); return -1; }
    return s;
}

int32_t gssnet_port(int32_t s) {
    struct sockaddr_in a;
    socklen_t n = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &n) != 0) return -1;
    return ntohs(a.sin_port);
}

int32_t gssnet_accept(int32_t s) {
    int c;
    do { c = accept(s, NULL, NULL); } while (c < 0 && errno == EINTR);
    return c;
}

int32_t gssnet_connect(gssnet_slice host, int32_t port) {
    char h[256], p[16];
    if (host.len <= 0 || host.len >= (int64_t)sizeof h) return -1;
    memcpy(h, host.data, (size_t)host.len);
    h[host.len] = 0;
    snprintf(p, sizeof p, "%d", (int)port);
    signal(SIGPIPE, SIG_IGN);
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(h, p, &hints, &res) != 0) return -1;
    int s = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    return s;
}

/* Exactly buf.len bytes: 1, or 0 at the end of the stream first, or -1. */
int32_t gssnet_read_full(int32_t s, gssnet_buf buf) {
    int64_t got = 0;
    while (got < buf.len) {
        ssize_t n;
        do { n = read(s, buf.data + got, (size_t)(buf.len - got)); } while (n < 0 && errno == EINTR);
        if (n == 0) return 0;
        if (n < 0) return -1;
        got += n;
    }
    return 1;
}

/* Up to buf.len bytes: how many, 0 at the end, -1 on an error. */
int64_t gssnet_read(int32_t s, gssnet_buf buf) {
    ssize_t n;
    do { n = read(s, buf.data, (size_t)buf.len); } while (n < 0 && errno == EINTR);
    return n;
}

int32_t gssnet_write(int32_t s, gssnet_slice data) {
    int64_t off = 0;
    while (off < data.len) {
        ssize_t n;
        do { n = write(s, data.data + off, (size_t)(data.len - off)); } while (n < 0 && errno == EINTR);
        if (n <= 0) return -1;
        off += n;
    }
    return 0;
}

void gssnet_close(int32_t s) { if (s >= 0) close(s); }
