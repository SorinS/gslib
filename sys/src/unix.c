/* sys on POSIX, the second part: signals delivered through a pipe that
   Goose waits on, resource limits and usage, sessions and process groups,
   sysctl (on Linux, /proc/sys), every user and group, another process's
   arguments, memory maps, and terminals (as Go's x/term). Errors are
   -errno. */

#if !defined(_WIN32)

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#  include <sys/sysctl.h>
#endif
#include "common.h"

/* --- Signals -------------------------------------------------------------------- */

/* A handler writes the signal's number to a pipe; signal_wait reads it.
   The pipe holds 64 KB of pending signals before more are dropped. */
static int sig_pipe[2] = { -1, -1 };

static void on_signal(int sig) {
    int saved = errno;
    unsigned char b = (unsigned char)sig;
    if (sig_pipe[1] >= 0) (void)!write(sig_pipe[1], &b, 1);
    errno = saved;
}

static int sig_ok(int32_t sig) { return sig > 0 && sig < 64 && sig != SIGKILL && sig != SIGSTOP; }

int64_t gssys_signal_notify(int32_t sig) {
    if (!sig_ok(sig)) return -EINVAL;
    if (sig_pipe[0] < 0) {
        if (pipe(sig_pipe) != 0) return -(int64_t)errno;
        for (int i = 0; i < 2; i++) {
            fcntl(sig_pipe[i], F_SETFD, FD_CLOEXEC);
            fcntl(sig_pipe[i], F_SETFL, fcntl(sig_pipe[i], F_GETFL) | O_NONBLOCK);
        }
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    return sigaction(sig, &sa, NULL) == 0 ? 0 : -(int64_t)errno;
}

int64_t gssys_signal_ignore(int32_t sig) {
    if (!sig_ok(sig)) return -EINVAL;
    return signal(sig, SIG_IGN) == SIG_ERR ? -(int64_t)errno : 0;
}

int64_t gssys_signal_reset(int32_t sig) {
    if (!sig_ok(sig)) return -EINVAL;
    return signal(sig, SIG_DFL) == SIG_ERR ? -(int64_t)errno : 0;
}

/* The next signal notify asked for, 0 when timeout_ms passed (< 0: wait
   for ever), -EINVAL before any notify. */
int64_t gssys_signal_wait(int64_t timeout_ms) {
    if (sig_pipe[0] < 0) return -EINVAL;
    unsigned char b;
    for (;;) {
        ssize_t n = read(sig_pipe[0], &b, 1);
        if (n == 1) return b;
        if (n < 0 && errno != EAGAIN && errno != EINTR) return -(int64_t)errno;
        if (n < 0 && errno == EINTR) continue;
        struct pollfd p;
        p.fd = sig_pipe[0];
        p.events = POLLIN;
        int t = timeout_ms < 0 ? -1 : timeout_ms > 2000000000 ? 2000000000 : (int)timeout_ms;
        int r = poll(&p, 1, t);
        if (r == 0) return 0;
        if (r < 0 && errno != EINTR) return -(int64_t)errno;
    }
}

/* --- Limits, usage, sessions ---------------------------------------------------------- */

/* sys's resource numbers, the same everywhere. */
static int resource_of(int32_t r) {
    switch (r) {
    case 0: return RLIMIT_CPU;
    case 1: return RLIMIT_FSIZE;
    case 2: return RLIMIT_DATA;
    case 3: return RLIMIT_STACK;
    case 4: return RLIMIT_CORE;
    case 5: return RLIMIT_NOFILE;
    case 6: return RLIMIT_AS;
#ifdef RLIMIT_NPROC
    case 7: return RLIMIT_NPROC;
#endif
#ifdef RLIMIT_MEMLOCK
    case 8: return RLIMIT_MEMLOCK;
#endif
    }
    return -1;
}

/* RLIM_INFINITY is -1 in Goose. */
static int64_t lim_out(rlim_t v) { return v == RLIM_INFINITY ? -1 : (int64_t)v; }
static rlim_t lim_in(int64_t v) { return v < 0 ? RLIM_INFINITY : (rlim_t)v; }

int64_t gssys_getrlimit(int32_t resource, gssys_Rlimit *out) {
    int r = resource_of(resource);
    if (r < 0) return -EINVAL;
    struct rlimit rl;
    if (getrlimit(r, &rl) != 0) return -(int64_t)errno;
    out->cur = lim_out(rl.rlim_cur);
    out->max = lim_out(rl.rlim_max);
    return 0;
}

int64_t gssys_setrlimit(int32_t resource, gssys_Rlimit *lim) {
    int r = resource_of(resource);
    if (r < 0) return -EINVAL;
    struct rlimit rl;
    rl.rlim_cur = lim_in(lim->cur);
    rl.rlim_max = lim_in(lim->max);
    return setrlimit(r, &rl) == 0 ? 0 : -(int64_t)errno;
}

int64_t gssys_umask(int64_t mask) { return (int64_t)umask((mode_t)(mask & 0777)); }
int64_t gssys_setsid(void) { pid_t s = setsid(); return s < 0 ? -(int64_t)errno : s; }
int64_t gssys_getsid(int64_t pid) { pid_t s = getsid((pid_t)pid); return s < 0 ? -(int64_t)errno : s; }
int64_t gssys_getpgid(int64_t pid) { pid_t s = getpgid((pid_t)pid); return s < 0 ? -(int64_t)errno : s; }
int64_t gssys_setpgid(int64_t pid, int64_t pgid) { return setpgid((pid_t)pid, (pid_t)pgid) == 0 ? 0 : -(int64_t)errno; }

/* getrusage: who 0 is this process, 1 its waited-for children. out: user
   and system time in ns, the largest resident set in bytes, minor and
   major faults, voluntary and involuntary context switches. */
int64_t gssys_rusage(int32_t who, gssys_i64s out) {
    if (out.len < 7) return -EINVAL;
    struct rusage ru;
    if (getrusage(who == 1 ? RUSAGE_CHILDREN : RUSAGE_SELF, &ru) != 0) return -(int64_t)errno;
    out.data[0] = (int64_t)ru.ru_utime.tv_sec * 1000000000 + (int64_t)ru.ru_utime.tv_usec * 1000;
    out.data[1] = (int64_t)ru.ru_stime.tv_sec * 1000000000 + (int64_t)ru.ru_stime.tv_usec * 1000;
#if defined(__APPLE__)
    out.data[2] = (int64_t)ru.ru_maxrss;            /* bytes */
#else
    out.data[2] = (int64_t)ru.ru_maxrss * 1024;     /* kilobytes */
#endif
    out.data[3] = ru.ru_minflt;
    out.data[4] = ru.ru_majflt;
    out.data[5] = ru.ru_nvcsw;
    out.data[6] = ru.ru_nivcsw;
    return 0;
}

/* --- sysctl ------------------------------------------------------------------------- */

#if defined(__linux__)
/* "kernel.hostname" is /proc/sys/kernel/hostname: the file's text, less
   its last newline. */
static int64_t proc_sys(gssys_slice name, char *buf, size_t cap) {
    if (name.len <= 0 || name.len > 200 || memchr(name.data, '/', (size_t)name.len) || memchr(name.data, 0, (size_t)name.len))
        return -EINVAL;
    char path[256] = "/proc/sys/";
    size_t base = strlen(path);
    for (int64_t i = 0; i < name.len; i++) path[base + i] = name.data[i] == '.' ? '/' : (char)name.data[i];
    path[base + name.len] = 0;
    if (strstr(path, "..")) return -EINVAL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -(int64_t)errno;
    ssize_t n = read(fd, buf, cap - 1);
    int e = errno;
    close(fd);
    if (n < 0) return -(int64_t)e;
    if (n > 0 && buf[n - 1] == '\n') n--;
    buf[n] = 0;
    return n;
}
#endif

int64_t gssys_sysctl_string(gssys_slice name, gs_rref out) {
#if defined(__linux__)
    char buf[65536];
    int64_t n = proc_sys(name, buf, sizeof buf);
    if (n >= 0) put_raw(out, buf, n);
    return n;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    char *n = cstr(name);
    if (!n) return -EINVAL;
    size_t len = 0;
    if (sysctlbyname(n, NULL, &len, NULL, 0) != 0) { int64_t r = -(int64_t)errno; free(n); return r; }
    char *buf = (char *)malloc(len + 1);
    if (!buf) { free(n); return GSSYS_ENOMEM_CODE; }
    int rc = sysctlbyname(n, buf, &len, NULL, 0);
    int64_t r = rc ? -(int64_t)errno : 0;
    free(n);
    if (r == 0) {
        while (len > 0 && buf[len - 1] == 0) len--;
        put_raw(out, buf, (int64_t)len);
        r = (int64_t)len;
    }
    free(buf);
    return r;
#else
    (void)name; (void)out;
    return GSSYS_ENOTSUP;
#endif
}

/* An integer sysctl (4 or 8 bytes; on Linux the file's first number) in
   out[0]. */
int64_t gssys_sysctl_int(gssys_slice name, gssys_i64s out) {
    if (out.len < 1) return -EINVAL;
#if defined(__linux__)
    char buf[256];
    int64_t n = proc_sys(name, buf, sizeof buf);
    if (n < 0) return n;
    char *end;
    errno = 0;
    long long v = strtoll(buf, &end, 10);
    if (end == buf || errno) return -EINVAL;
    out.data[0] = v;
    return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    char *n = cstr(name);
    if (!n) return -EINVAL;
    uint8_t buf[8];
    size_t len = sizeof buf;
    int rc = sysctlbyname(n, buf, &len, NULL, 0);
    int64_t r = rc ? -(int64_t)errno : 0;
    free(n);
    if (r) return r;
    if (len == 4) { int32_t v; memcpy(&v, buf, 4); out.data[0] = v; }
    else if (len == 8) { int64_t v; memcpy(&v, buf, 8); out.data[0] = v; }
    else return -EINVAL;
    return 0;
#else
    (void)name;
    return GSSYS_ENOTSUP;
#endif
}

/* --- Every user and group ------------------------------------------------------------ */

/* Each user as lookup_user has one: five fields. */
int64_t gssys_all_users(gs_rref out) {
    int64_t n = 0;
    char num[32];
    setpwent();
    struct passwd *pw;
    while ((pw = getpwent())) {
        put_str(out, pw->pw_name);
        snprintf(num, sizeof num, "%lld", (long long)pw->pw_uid);
        put_str(out, num);
        snprintf(num, sizeof num, "%lld", (long long)pw->pw_gid);
        put_str(out, num);
        const char *g = pw->pw_gecos ? pw->pw_gecos : "";
        const char *comma = strchr(g, ',');
        put_field(out, g, comma ? comma - g : (int64_t)strlen(g));
        put_str(out, pw->pw_dir);
        n++;
    }
    endpwent();
    return n;
}

/* Each group: its gid, its name, how many members, their names. */
int64_t gssys_all_groups(gs_rref out) {
    int64_t n = 0;
    char num[32];
    setgrent();
    struct group *gr;
    while ((gr = getgrent())) {
        snprintf(num, sizeof num, "%lld", (long long)gr->gr_gid);
        put_str(out, num);
        put_str(out, gr->gr_name);
        int64_t m = 0;
        for (char **p = gr->gr_mem; p && *p; p++) m++;
        put_i64(out, m);
        for (char **p = gr->gr_mem; p && *p; p++) put_str(out, *p);
        n++;
    }
    endgrent();
    return n;
}

/* --- Another process's arguments ------------------------------------------------------ */

int64_t gssys_process_args(int64_t pid, gs_rref out) {
#if defined(__linux__)
    char path[64];
    snprintf(path, sizeof path, "/proc/%lld/cmdline", (long long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -(int64_t)errno;
    size_t cap = 65536, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { close(fd); return GSSYS_ENOMEM_CODE; }
    for (;;) {
        if (len == cap) {
            char *nb = (char *)realloc(buf, cap * 2);
            if (!nb) { free(buf); close(fd); return GSSYS_ENOMEM_CODE; }
            buf = nb;
            cap *= 2;
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n < 0) { int64_t e = -(int64_t)errno; free(buf); close(fd); return e; }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(fd);
    int64_t count = 0;
    size_t i = 0;
    while (i < len) {
        size_t s = i;
        while (i < len && buf[i]) i++;
        put_field(out, buf + s, (int64_t)(i - s));
        count++;
        i++;
    }
    free(buf);
    return count;
#elif defined(__APPLE__)
    /* KERN_PROCARGS2: argc, the executable's path, NULs, then argv. */
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, (int)pid };
    size_t size = 0;
    int maxarg_mib[2] = { CTL_KERN, KERN_ARGMAX };
    int argmax = 0;
    size_t al = sizeof argmax;
    if (sysctl(maxarg_mib, 2, &argmax, &al, NULL, 0) != 0) return -(int64_t)errno;
    char *buf = (char *)malloc((size_t)argmax);
    if (!buf) return GSSYS_ENOMEM_CODE;
    size = (size_t)argmax;
    if (sysctl(mib, 3, buf, &size, NULL, 0) != 0) { int64_t e = -(int64_t)errno; free(buf); return e; }
    int argc;
    if (size < sizeof argc) { free(buf); return -EINVAL; }
    memcpy(&argc, buf, sizeof argc);
    size_t i = sizeof argc;
    while (i < size && buf[i]) i++;      /* the executable's path */
    while (i < size && !buf[i]) i++;     /* its padding */
    int64_t count = 0;
    while (i < size && count < argc) {
        size_t s = i;
        while (i < size && buf[i]) i++;
        put_field(out, buf + s, (int64_t)(i - s));
        count++;
        i++;
    }
    free(buf);
    return count;
#else
    (void)pid; (void)out;
    return GSSYS_ENOTSUP;
#endif
}

/* --- Memory maps ------------------------------------------------------------------------ */

/* A file's bytes [offset, offset + length) mapped shared (fd < 0:
   anonymous memory): the address, as an i64. */
int64_t gssys_mmap(int64_t fd, int64_t offset, int64_t length, int32_t writable) {
    if (length <= 0 || offset < 0) return -EINVAL;
    int prot = PROT_READ | (writable ? PROT_WRITE : 0);
    int flags = fd < 0 ? MAP_PRIVATE | MAP_ANON : MAP_SHARED;
    void *p = mmap(NULL, (size_t)length, prot, flags, fd < 0 ? -1 : (int)fd, (off_t)offset);
    if (p == MAP_FAILED) return -(int64_t)errno;
    return (int64_t)(intptr_t)p;
}

int64_t gssys_munmap(int64_t addr, int64_t length) {
    return munmap((void *)(intptr_t)addr, (size_t)length) == 0 ? 0 : -(int64_t)errno;
}

int64_t gssys_msync(int64_t addr, int64_t length) {
    return msync((void *)(intptr_t)addr, (size_t)length, MS_SYNC) == 0 ? 0 : -(int64_t)errno;
}

/* Copies out of or into a map; sys.goose's Map checks the bounds. */
int64_t gssys_mem_read(int64_t addr, int64_t offset, gssys_buf buf) {
    if (!addr || offset < 0) return -EINVAL;
    memcpy(buf.data, (const uint8_t *)(intptr_t)addr + offset, (size_t)buf.len);
    return buf.len;
}

int64_t gssys_mem_write(int64_t addr, int64_t offset, gssys_slice data) {
    if (!addr || offset < 0) return -EINVAL;
    memcpy((uint8_t *)(intptr_t)addr + offset, data.data, (size_t)data.len);
    return data.len;
}

/* --- Terminals ------------------------------------------------------------------------------ */

int64_t gssys_term_size(int64_t fd, gssys_WinSize *out) {
    struct winsize ws;
    if (ioctl((int)fd, TIOCGWINSZ, &ws) != 0) return -(int64_t)errno;
    out->rows = ws.ws_row;
    out->cols = ws.ws_col;
    out->xpixels = ws.ws_xpixel;
    out->ypixels = ws.ws_ypixel;
    return 0;
}

/* A terminal's state is its struct termios, as bytes. */
int64_t gssys_term_get_state(int64_t fd, gs_rref out) {
    struct termios t;
    if (tcgetattr((int)fd, &t) != 0) return -(int64_t)errno;
    put_raw(out, &t, sizeof t);
    return sizeof t;
}

int64_t gssys_term_set_state(int64_t fd, gssys_slice state) {
    struct termios t;
    if (state.len != (int64_t)sizeof t) return -EINVAL;
    memcpy(&t, state.data, sizeof t);
    return tcsetattr((int)fd, TCSAFLUSH, &t) == 0 ? 0 : -(int64_t)errno;
}

/* Raw mode as x/term's MakeRaw (cfmakeraw): no echo, no line editing, no
   signals from keys, no output processing, 8-bit bytes one at a time. */
int64_t gssys_term_make_raw(int64_t fd) {
    struct termios t;
    if (tcgetattr((int)fd, &t) != 0) return -(int64_t)errno;
    t.c_iflag &= ~(tcflag_t)(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    t.c_oflag &= ~(tcflag_t)OPOST;
    t.c_lflag &= ~(tcflag_t)(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t.c_cflag &= ~(tcflag_t)(CSIZE | PARENB);
    t.c_cflag |= CS8;
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    return tcsetattr((int)fd, TCSAFLUSH, &t) == 0 ? 0 : -(int64_t)errno;
}

int64_t gssys_term_set_echo(int64_t fd, int32_t on) {
    struct termios t;
    if (tcgetattr((int)fd, &t) != 0) return -(int64_t)errno;
    if (on) t.c_lflag |= ECHO;
    else { t.c_lflag &= ~(tcflag_t)ECHO; t.c_lflag |= ICANON | ISIG; t.c_iflag |= ICRNL; }
    return tcsetattr((int)fd, TCSAFLUSH, &t) == 0 ? 0 : -(int64_t)errno;
}

#endif

int gssys_unix_unit;
