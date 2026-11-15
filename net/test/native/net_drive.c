/* src/net.c without Goose (scripts/net_check.py): connect, write, read, timeouts,
   errors, and the idle-closed test, against servers on 127.0.0.1.
   drive HTTP_PORT SILENT_PORT */
#if defined(_WIN32)
#  include <windows.h>
#else
#  define _POSIX_C_SOURCE 200809L
#  include <time.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { const uint8_t *data; int64_t len; } gsnet_slice;
typedef struct { uint8_t *data; int64_t len; } gsnet_buf;
int64_t gsnet_dial(gsnet_slice host, int32_t port, int32_t timeout_ms);
int64_t gsnet_read(int64_t fd, gsnet_buf buf, int32_t timeout_ms);
int64_t gsnet_write(int64_t fd, gsnet_slice data, int32_t timeout_ms);
int32_t gsnet_readable(int64_t fd);
void gsnet_close(int64_t fd);
static gsnet_slice S(const char *s) { gsnet_slice x = { (const uint8_t *)s, (int64_t)strlen(s) }; return x; }
static int64_t now_ms(void) {
#if defined(_WIN32)
    return (int64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}
static int fails;
static void check(const char *name, int ok, long long v) { printf("%s %s (%lld)\n", ok ? "ok  " : "FAIL", name, v); if (!ok) fails++; }
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: drive HTTP_PORT SILENT_PORT\n"); return 2; }
    int http = atoi(argv[1]), silent = atoi(argv[2]);
    setvbuf(stdout, NULL, _IONBF, 0);   /* what ran, if the watchdog kills it */
    static uint8_t buf[1 << 16];
    gsnet_buf b = { buf, sizeof buf };
    int64_t fd = gsnet_dial(S("127.0.0.1"), http, 5000);
    check("connect", fd >= 0, fd);
    int64_t n = gsnet_write(fd, S("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 5000);
    check("write", n == 27, n);
    int64_t got = 0, r;
    while ((r = gsnet_read(fd, b, 5000)) > 0) got += r;
    check("read to the end", got > 0 && r == 0, got);
    gsnet_close(fd);
    fd = gsnet_dial(S("localhost"), http, 5000);
    check("connect by name", fd >= 0, fd);
    gsnet_write(fd, S("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), 5000);
    r = gsnet_read(fd, b, 5000);
    check("read by name", r > 12 && memcmp(buf, "HTTP/1.", 7) == 0, r);
    gsnet_close(fd);
    fd = gsnet_dial(S("127.0.0.1"), silent, 5000);
    check("connect silent", fd >= 0, fd);
    check("idle and open: not readable", gsnet_readable(fd) == 0, 0);
    r = gsnet_read(fd, b, 300);
    check("read times out", r == -4, r);
    gsnet_close(fd);
    /* A peer that never reads: more than the socket buffers hold, so the
       write fills them and must time out, not block in send. */
    fd = gsnet_dial(S("127.0.0.1"), silent, 5000);
    {
        int64_t big = (int64_t)64 << 20;
        uint8_t *p = calloc((size_t)big, 1);
        gsnet_slice d = { p, big };
        int64_t t0 = now_ms();
        r = gsnet_write(fd, d, 200);
        int64_t took = now_ms() - t0;
        check("write to a peer that never reads times out", r == -4, r);
        check("... within 5 s", took < 5000, took);
        free(p);
    }
    gsnet_close(fd);
    r = gsnet_dial(S("127.0.0.1"), 1, 3000);
    check("refused", r == -3, r);
    r = gsnet_dial(S("no-such-host.invalid"), 80, 3000);
    check("does not resolve", r == -2, r);
    r = gsnet_dial(S(""), 80, 1000);
    check("empty host", r == -1, r);
    fd = gsnet_dial(S("127.0.0.1"), http, 5000);
    gsnet_write(fd, S("GET / HTTP/1.0\r\n\r\n"), 5000);
    while ((r = gsnet_read(fd, b, 5000)) > 0) {}
    check("closed by the server: readable", gsnet_readable(fd) == 1, 0);
    gsnet_close(fd);
    printf("%d failed\n", fails);
    return fails != 0;
}
