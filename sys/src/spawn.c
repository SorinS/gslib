/* sys on Linux, macOS and the BSDs: child processes on pipes or a
   pseudo-terminal (process.goose), waiting on descriptors, private files,
   and what the operating system is (os_info). The Windows side is
   winspawn.c. Errors are -errno. */

#if !defined(_WIN32)

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#  include <sys/sysctl.h>
#endif
#if defined(__linux__)
#  include <sys/syscall.h>
#endif

#include "common.h"

extern char **environ;

#define ERR(rc) ((rc) < 0 ? -(int64_t)errno : 0)

/* --- What the system is ------------------------------------------------------- */

/* One value of an os-release file, unquoted ("..." or '...', with \
   escapes inside double quotes), into out; 0 when it is not there. */
static int os_release_value(const char *text, const char *key, char *out, size_t cap) {
    size_t kl = strlen(key);
    const char *p = text;
    out[0] = 0;
    while (*p) {
        const char *end = strchr(p, '\n');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len > kl && strncmp(p, key, kl) == 0 && p[kl] == '=') {
            const char *v = p + kl + 1, *ve = p + len;
            size_t n = 0;
            char q = 0;
            if (v < ve && (*v == '"' || *v == '\'')) q = *v++;
            while (v < ve && n + 1 < cap) {
                if (q && *v == q) break;
                if (q == '"' && *v == '\\' && v + 1 < ve) v++;
                out[n++] = *v++;
            }
            out[n] = 0;
            return 1;
        }
        p += len;
        if (*p == '\n') p++;
    }
    return 0;
}

#if defined(__APPLE__)
static void sysctl_str(const char *name, char *out, size_t cap) {
    size_t len = cap;
    if (sysctlbyname(name, out, &len, NULL, 0) != 0) out[0] = 0;
    else out[len < cap ? len : cap - 1] = 0;
}
#endif

/* name, id, id_like, version, version_name, build, edition, pretty. */
int64_t gssys_os_info(gs_rref out) {
    char name[256] = "", id[64] = "", like[128] = "", version[64] = "", vname[64] = "", build[64] = "",
         edition[128] = "", pretty[512] = "";
#if defined(__APPLE__)
    snprintf(name, sizeof name, "macOS");
    snprintf(id, sizeof id, "macos");
    sysctl_str("kern.osproductversion", version, sizeof version);
    sysctl_str("kern.osversion", build, sizeof build);
    snprintf(pretty, sizeof pretty, "macOS %s (%s)", version, build);
#else
    struct utsname u;
    if (uname(&u) != 0) memset(&u, 0, sizeof u);
    char text[8192];
    size_t n = 0;
    FILE *f = fopen("/etc/os-release", "re");
    if (!f) f = fopen("/usr/lib/os-release", "re");
    if (f) {
        n = fread(text, 1, sizeof text - 1, f);
        fclose(f);
    }
    text[n] = 0;
    if (n > 0) {
        os_release_value(text, "NAME", name, sizeof name);
        os_release_value(text, "ID", id, sizeof id);
        os_release_value(text, "ID_LIKE", like, sizeof like);
        os_release_value(text, "VERSION_ID", version, sizeof version);
        os_release_value(text, "VERSION_CODENAME", vname, sizeof vname);
        os_release_value(text, "BUILD_ID", build, sizeof build);
        os_release_value(text, "VARIANT", edition, sizeof edition);
        os_release_value(text, "PRETTY_NAME", pretty, sizeof pretty);
    }
    /* Without os-release (the BSDs, a bare container): uname's. */
    if (!name[0]) snprintf(name, sizeof name, "%s", u.sysname);
    if (!id[0]) {
        size_t i = 0;
        for (; u.sysname[i] && i + 1 < sizeof id; i++)
            id[i] = (char)(u.sysname[i] >= 'A' && u.sysname[i] <= 'Z' ? u.sysname[i] + 32 : u.sysname[i]);
        id[i] = 0;
    }
    if (!version[0] && !n) snprintf(version, sizeof version, "%s", u.release);
    if (!pretty[0]) snprintf(pretty, sizeof pretty, "%s %s", name, version);
#endif
    put_str(out, name);
    put_str(out, id);
    put_str(out, like);
    put_str(out, version);
    put_str(out, vname);
    put_str(out, build);
    put_str(out, edition);
    put_str(out, pretty);
    return 0;
}

/* When the system started, in seconds since 1970. */
int64_t gssys_boot_time(void) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    struct timeval boot;
    size_t len = sizeof boot;
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if (sysctl(mib, 2, &boot, &len, NULL, 0) != 0) return -(int64_t)errno;
    return boot.tv_sec;
#else
    struct timespec up, now;
    if (clock_gettime(CLOCK_BOOTTIME, &up) != 0 || clock_gettime(CLOCK_REALTIME, &now) != 0) return -(int64_t)errno;
    return (int64_t)now.tv_sec - up.tv_sec - (now.tv_nsec < up.tv_nsec ? 1 : 0);
#endif
}

/* --- Descriptors -------------------------------------------------------------------- */

/* 1 when only this user can reach fd's file: owned by the effective user,
   no permission bits for the group or others. 0 when not. */
int64_t gssys_is_private(int64_t fd) {
    struct stat st;
    if (fstat((int)fd, &st) != 0) return -(int64_t)errno;
    return st.st_uid == geteuid() && (st.st_mode & 077) == 0 ? 1 : 0;
}

/* Bytes that a read of fd would give now without waiting (FIONREAD). */
int64_t gssys_available(int64_t fd) {
    int n = 0;
    if (ioctl((int)fd, FIONREAD, &n) != 0) return -(int64_t)errno;
    return n;
}

int64_t gssys_set_nonblock(int64_t fd, int32_t on) {
    int fl = fcntl((int)fd, F_GETFL, 0);
    if (fl < 0) return -(int64_t)errno;
    int want = on ? fl | O_NONBLOCK : fl & ~O_NONBLOCK;
    if (want != fl && fcntl((int)fd, F_SETFL, want) < 0) return -(int64_t)errno;
    return 0;
}

#define POLL_READ  1
#define POLL_WRITE 2

/* Waits up to timeout_ms (-1: no limit) for any of fds (a negative entry
   is skipped) to be ready for what events[i] asks (POLL_READ, POLL_WRITE),
   and puts in events[i] what it is ready for: readable takes in the end of
   input and errors, as a read then tells them. How many are ready; 0 on
   timeout. */
int64_t gssys_poll(gssys_i64s fds, gssys_i64s events, int64_t timeout_ms) {
    if (events.len < fds.len) return -EINVAL;
    if (fds.len > 4096) return -EINVAL;
    struct pollfd small[64];
    struct pollfd *p = fds.len <= 64 ? small : (struct pollfd *)malloc(sizeof(struct pollfd) * (size_t)fds.len);
    if (!p) return GSSYS_ENOMEM_CODE;
    for (int64_t i = 0; i < fds.len; i++) {
        p[i].fd = fds.data[i] < 0 ? -1 : (int)fds.data[i];
        p[i].events = (short)(((events.data[i] & POLL_READ) ? POLLIN : 0) | ((events.data[i] & POLL_WRITE) ? POLLOUT : 0));
        p[i].revents = 0;
    }
    int ms = timeout_ms < 0 ? -1 : timeout_ms > 0x7fffffff ? 0x7fffffff : (int)timeout_ms;
    int r;
    do r = poll(p, (nfds_t)fds.len, ms); while (r < 0 && errno == EINTR);
    int64_t res = r < 0 ? -(int64_t)errno : r;
    for (int64_t i = 0; i < fds.len; i++) {
        short re = p[i].revents;
        int64_t ev = 0;
        /* POLLNVAL too: macOS cannot poll some devices (/dev/null), and a read
           then says what they hold. */
        if ((p[i].events & POLLIN) && (re & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) ev |= POLL_READ;
        if ((p[i].events & POLLOUT) && (re & (POLLOUT | POLLHUP | POLLERR | POLLNVAL))) ev |= POLL_WRITE;
        events.data[i] = r < 0 ? 0 : ev;
    }
    if (p != small) free(p);
    return res;
}

/* --- Child processes ------------------------------------------------------------------- */

/* A list of NUL-terminated strings as an argv/envp array (malloc'd, the
   strings in a copy of their own), or NULL. */
static char **string_list(gssys_slice s, char **copy) {
    *copy = NULL;
    if (s.len > 0 && s.data[s.len - 1] != 0) return NULL;
    int64_t n = 0;
    for (int64_t i = 0; i < s.len; i++) n += s.data[i] == 0;
    char **v = (char **)malloc(sizeof(char *) * (size_t)(n + 1));
    char *c = (char *)malloc((size_t)s.len + 1);
    if (!v || !c) { free(v); free(c); return NULL; }
    if (s.len) memcpy(c, s.data, (size_t)s.len);
    int64_t k = 0;
    for (int64_t i = 0; i < s.len; ) {
        v[k++] = c + i;
        while (c[i]) i++;
        i++;
    }
    v[k] = NULL;
    *copy = c;
    return v;
}

static int cloexec_pipe(int p[2]) {
#if defined(__linux__)
    return pipe2(p, O_CLOEXEC);
#else
    if (pipe(p) != 0) return -1;
    fcntl(p[0], F_SETFD, FD_CLOEXEC);
    fcntl(p[1], F_SETFD, FD_CLOEXEC);
    return 0;
#endif
}

static void close_if(int *fd) {
    if (*fd >= 0) close(*fd);
    *fd = -1;
}

/* In the child, before exec: every descriptor from 3 up closed but keep.
   Only async-signal-safe calls from here on. */
static void close_from_3(int keep) {
#if defined(__linux__) && defined(SYS_close_range)
    if (keep > 3) syscall(SYS_close_range, 3u, (unsigned)keep - 1, 0u);
    if (syscall(SYS_close_range, (unsigned)keep + 1, ~0u, 0u) == 0) return;
#endif
    struct rlimit rl;
    long max = getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY ? (long)rl.rlim_cur : 65536;
    if (max > 65536) max = 65536;
    for (long fd = 3; fd < max; fd++)
        if (fd != keep) close((int)fd);
}

/* In the child: fd onto target, which stays open across exec. */
static int put_fd(int fd, int target) {
    if (fd == target) {
        int fl = fcntl(fd, F_GETFD);
        return fl < 0 ? -1 : fcntl(fd, F_SETFD, fl & ~FD_CLOEXEC);
    }
    int r;
    do r = dup2(fd, target); while (r < 0 && errno == EINTR);
    return r < 0 ? -1 : 0;
}

static void child_fail(int errw) {
    int e = errno;
    ssize_t w;
    do w = write(errw, &e, sizeof e); while (w < 0 && errno == EINTR);
    _exit(127);
}

/* Starts path with args and env (each a list of NUL-terminated strings),
   in dir ("" for this one). stdio[0..2] are a descriptor to give the
   child, or STDIO_INHERIT, STDIO_PIPE, STDIO_NULL (and STDIO_STDOUT for
   stderr: where stdout goes). With SP_PTY the child is a session leader
   on a new pseudo-terminal of size[0] columns and size[1] rows instead,
   its master end out->stdin_fd and (a second descriptor of it) out->stdout_fd.
   exec's failure is spawn's error, through a pipe the exec closes. */
int64_t gssys_spawn(gssys_slice path, gssys_slice args, gssys_slice env, gssys_slice dir, int64_t flags,
                    gssys_i64s stdio, gssys_i64s size, gssys_Child *out) {
    out->pid = out->handle = out->pty = 0;
    out->stdin_fd = out->stdout_fd = out->stderr_fd = -1;
    if (stdio.len < 3 || (flags & SP_PTY && size.len < 2)) return -EINVAL;
    char *p = cstr(path), *d = dir.len ? cstr(dir) : NULL, *acopy, *ecopy;
    char **argv = string_list(args, &acopy), **envp = string_list(env, &ecopy);
    int64_t r = 0;
    int child_end[3] = { -1, -1, -1 }, parent_end[3] = { -1, -1, -1 }, errp[2] = { -1, -1 };
    int master = -1, slave = -1, theirs[3] = { 0, 0, 0 };
    if (!p || !argv || !envp || !argv[0] || (dir.len && !d)) { r = -EINVAL; goto done; }

    if (flags & SP_PTY) {
        master = posix_openpt(O_RDWR | O_NOCTTY);
        if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) { r = -(int64_t)errno; goto done; }
        fcntl(master, F_SETFD, FD_CLOEXEC);
        char sname[256];
#if defined(__linux__)
        if (ptsname_r(master, sname, sizeof sname) != 0) { r = -(int64_t)errno; goto done; }
#else
        const char *sn = ptsname(master);
        if (!sn) { r = -(int64_t)errno; goto done; }
        snprintf(sname, sizeof sname, "%s", sn);
#endif
        slave = open(sname, O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (slave < 0) { r = -(int64_t)errno; goto done; }
        struct winsize w;
        memset(&w, 0, sizeof w);
        w.ws_col = (unsigned short)size.data[0];
        w.ws_row = (unsigned short)size.data[1];
        ioctl(slave, TIOCSWINSZ, &w);
        child_end[0] = child_end[1] = child_end[2] = slave;
    } else {
        for (int i = 0; i < 3; i++) {
            int64_t s = stdio.data[i];
            if (s == STDIO_PIPE) {
                int pp[2];
                if (cloexec_pipe(pp) != 0) { r = -(int64_t)errno; goto done; }
                child_end[i] = i == 0 ? pp[0] : pp[1];
                parent_end[i] = i == 0 ? pp[1] : pp[0];
            } else if (s == STDIO_NULL) {
                child_end[i] = open("/dev/null", (i == 0 ? O_RDONLY : O_WRONLY) | O_CLOEXEC);
                if (child_end[i] < 0) { r = -(int64_t)errno; goto done; }
            } else if (s == STDIO_INHERIT) {
                child_end[i] = -2;                  /* left as it is */
            } else if (s == STDIO_STDOUT && i == 2) {
                child_end[i] = -3;
            } else if (s >= 0) {
                child_end[i] = (int)s;
                theirs[i] = 1;                      /* the caller's: not closed */
            } else { r = -EINVAL; goto done; }
        }
    }
    if (cloexec_pipe(errp) != 0) { r = -(int64_t)errno; goto done; }

    pid_t pid = fork();
    if (pid < 0) { r = -(int64_t)errno; goto done; }
    if (pid == 0) {
        /* The child: async-signal-safe calls only, until exec. */
        if ((flags & (SP_SETSID | SP_PTY)) && setsid() < 0) child_fail(errp[1]);
        if ((flags & SP_PGROUP) && !(flags & (SP_SETSID | SP_PTY)) && setpgid(0, 0) < 0) child_fail(errp[1]);
#if defined(TIOCSCTTY)
        if ((flags & SP_PTY) && ioctl(slave, TIOCSCTTY, 0) < 0) child_fail(errp[1]);
#endif
        /* Descriptors below 3 that must move are copied above first, so that
           one dup2 cannot close another's source. */
        int src[3];
        for (int i = 0; i < 3; i++) {
            src[i] = child_end[i];
            if (src[i] >= 0 && src[i] < 3 && src[i] != i) {
                src[i] = fcntl(src[i], F_DUPFD_CLOEXEC, 3);
                if (src[i] < 0) child_fail(errp[1]);
            }
        }
        for (int i = 0; i < 3; i++)
            if (src[i] >= 0 && put_fd(src[i], i) < 0) child_fail(errp[1]);
        if (src[2] == -3 && put_fd(1, 2) < 0) child_fail(errp[1]);
        if (flags & SP_DEFAULT_SIGNALS) {
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_handler = SIG_DFL;
            for (int s = 1; s < 32; s++)
                if (s != SIGKILL && s != SIGSTOP) sigaction(s, &sa, NULL);
        }
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        close_from_3(errp[1]);
        if (d && chdir(d) != 0) child_fail(errp[1]);
        execve(p, argv, envp);
        child_fail(errp[1]);
    }

    /* The parent: did the exec happen? */
    close_if(&errp[1]);
    int child_errno = 0;
    ssize_t got;
    do got = read(errp[0], &child_errno, sizeof child_errno); while (got < 0 && errno == EINTR);
    if (got == (ssize_t)sizeof child_errno) {
        int st;
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
        r = -(int64_t)child_errno;
        goto done;
    }
    out->pid = pid;
    out->handle = (flags & (SP_SETSID | SP_PGROUP | SP_PTY)) ? 1 : 0;   /* a group of its own */
    if (flags & SP_PTY) {
        out->stdin_fd = master;
        out->stdout_fd = fcntl(master, F_DUPFD_CLOEXEC, 0);
        out->pty = 1;
        master = -1;
    } else {
        out->stdin_fd = parent_end[0] >= 0 ? parent_end[0] : -1;
        out->stdout_fd = parent_end[1] >= 0 ? parent_end[1] : -1;
        out->stderr_fd = parent_end[2] >= 0 ? parent_end[2] : -1;
        for (int i = 0; i < 3; i++) parent_end[i] = -1;
    }

done:
    for (int i = 0; i < 3; i++) {
        if (child_end[i] >= 0 && !theirs[i] && child_end[i] != slave) close(child_end[i]);
        if (parent_end[i] >= 0) close(parent_end[i]);
    }
    close_if(&slave);
    close_if(&master);
    close_if(&errp[0]);
    close_if(&errp[1]);
    free(p); free(d); free(argv); free(acopy); free(envp); free(ecopy);
    return r;
}

/* Waits up to timeout_ms (-1: no limit, 0: not at all) for the child to
   end: 1 when it has, with status[0] its exit code (-1 when a signal
   ended it) and status[1] that signal; 0 while it runs. */
int64_t gssys_child_wait(gssys_Child *c, int64_t timeout_ms, gssys_i64s status) {
    if (c->pid <= 0 || status.len < 2) return -EINVAL;
    int st = 0;
    pid_t r;
    if (timeout_ms < 0) {
        do r = waitpid((pid_t)c->pid, &st, 0); while (r < 0 && errno == EINTR);
    } else {
        struct timespec start, now;
        clock_gettime(CLOCK_MONOTONIC, &start);
        long nap_us = 1000;
        for (;;) {
            do r = waitpid((pid_t)c->pid, &st, WNOHANG); while (r < 0 && errno == EINTR);
            if (r != 0) break;
            clock_gettime(CLOCK_MONOTONIC, &now);
            int64_t spent = ((int64_t)now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
            if (spent >= timeout_ms) return 0;
            int64_t left_us = (timeout_ms - spent) * 1000;
            struct timespec nap = { 0, (long)(nap_us < left_us ? nap_us : left_us) * 1000 };
            nanosleep(&nap, NULL);
            if (nap_us < 20000) nap_us *= 2;
        }
    }
    if (r < 0) return -(int64_t)errno;
    if (WIFEXITED(st)) { status.data[0] = WEXITSTATUS(st); status.data[1] = 0; }
    else if (WIFSIGNALED(st)) { status.data[0] = -1; status.data[1] = WTERMSIG(st); }
    else { status.data[0] = -1; status.data[1] = 0; }
    c->pid = -c->pid;                       /* reaped: never signalled again */
    return 1;
}

/* sig to the child, or to its whole group when it has one of its own. */
int64_t gssys_child_kill(gssys_Child *c, int32_t sig) {
    if (c->pid <= 0) return -ESRCH;
    pid_t target = c->handle ? -(pid_t)c->pid : (pid_t)c->pid;
    if (kill(target, sig) == 0) return 0;
    /* A group whose leader has called setsid itself, or gone: the child. */
    if (c->handle && errno == ESRCH) return ERR(kill((pid_t)c->pid, sig));
    return -(int64_t)errno;
}

/* Closes this end of the child's pipes or terminal. */
int64_t gssys_child_release(gssys_Child *c) {
    int64_t r = 0;
    int64_t *fds[3] = { &c->stdin_fd, &c->stdout_fd, &c->stderr_fd };
    for (int i = 0; i < 3; i++) {
        if (*fds[i] >= 0 && close((int)*fds[i]) != 0 && r == 0) r = -(int64_t)errno;
        *fds[i] = -1;
    }
    c->pty = 0;
    return r;
}

int64_t gssys_pty_resize(gssys_Child *c, int64_t cols, int64_t rows) {
    if (!c->pty || c->stdin_fd < 0) return -EINVAL;
    struct winsize w;
    memset(&w, 0, sizeof w);
    w.ws_col = (unsigned short)cols;
    w.ws_row = (unsigned short)rows;
    return ERR(ioctl((int)c->stdin_fd, TIOCSWINSZ, &w));
}

/* Windows' pseudo-console needs closing for its output to end; a POSIX
   terminal's ends when the child's side closes. */
int64_t gssys_pty_close(gssys_Child *c) { (void)c; return 0; }

int64_t gssys_fork(void) {
    pid_t pid = fork();
    return pid < 0 ? -(int64_t)errno : pid;
}

int64_t gssys_exit_now(int32_t code) { _exit(code); }

/* Waits for every child that has ended (none blocks): how many. */
int64_t gssys_reap(void) {
    int64_t n = 0;
    int st;
    pid_t r;
    while ((r = waitpid(-1, &st, WNOHANG)) > 0 || (r < 0 && errno == EINTR))
        if (r > 0) n++;
    return n;
}

#endif

int gssys_spawn_unit;
