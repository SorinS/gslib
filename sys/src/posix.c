/* sys on Linux, macOS and the BSDs: the host, this process, users and
   groups, and files, as Go's x/sys/unix and os/user have them. Errors are
   -errno. The Windows side is win.c; what a platform lacks is
   gssys_stubs.c's. */

#if !defined(_WIN32)

#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#  include <libproc.h>
#  include <mach-o/dyld.h>
#  include <mach/mach.h>
#  include <sys/sysctl.h>
#elif defined(__linux__)
#  include <sys/sysinfo.h>
#endif
#include "common.h"

extern char **environ;

#define ERR(rc) ((rc) < 0 ? -(int64_t)errno : 0)

int32_t gssys_platform_id(void) {
#if defined(__linux__)
    return 2;
#elif defined(__APPLE__)
    return 3;
#else
    return 4;
#endif
}

/* --- Errors ------------------------------------------------------------------- */

int64_t gssys_error_text(int64_t code, gs_rref out) {
    if (code == GSSYS_ENOTSUP) { put_raw(out, "not supported on this platform", 30); return 30; }
    if (code == GSSYS_ENOMEM_CODE) { put_raw(out, "out of memory", 13); return 13; }
    const char *s = strerror((int)(code < 0 ? -code : code));
    int64_t n = (int64_t)strlen(s);
    put_raw(out, s, n);
    return n;
}

int32_t gssys_error_is(int64_t code, int32_t cls) {
    if (code >= 0) return 0;
    if (code == GSSYS_ENOTSUP) return cls == CLS_NOT_SUPPORTED;
    int e = (int)-code;
    switch (cls) {
    case CLS_NOT_EXIST:     return e == ENOENT || e == ESRCH;
    case CLS_EXIST:         return e == EEXIST || e == ENOTEMPTY;
    case CLS_PERMISSION:    return e == EACCES || e == EPERM;
    case CLS_TIMEOUT:       return e == ETIMEDOUT;
    case CLS_NOT_SUPPORTED: return e == ENOTSUP || e == ENOSYS || e == EOPNOTSUPP;
    case CLS_WOULD_BLOCK:   return e == EAGAIN || e == EWOULDBLOCK;
    case CLS_INTERRUPTED:   return e == EINTR;
    case CLS_NOT_EMPTY:     return e == ENOTEMPTY || e == EEXIST;
    case CLS_IS_DIR:        return e == EISDIR;
    case CLS_NOT_DIR:       return e == ENOTDIR;
    case CLS_INVALID:       return e == EINVAL;
    }
    return 0;
}

int64_t gssys_last_error(void) { return -(int64_t)errno; }

/* --- The host ------------------------------------------------------------------- */

static int64_t put_cstr_raw(gs_rref out, const char *s) {
    int64_t n = (int64_t)strlen(s);
    put_raw(out, s, n);
    return n;
}

int64_t gssys_hostname(gs_rref out) {
    char buf[1024];
    if (gethostname(buf, sizeof buf) != 0) return -(int64_t)errno;
    buf[sizeof buf - 1] = 0;
    return put_cstr_raw(out, buf);
}

int64_t gssys_uname(gs_rref out) {
    struct utsname u;
    if (uname(&u) != 0) return -(int64_t)errno;
    const char *machine = u.machine;
    if (!strcmp(machine, "amd64")) machine = "x86_64";
    put_str(out, u.sysname);
    put_str(out, u.nodename);
    put_str(out, u.release);
    put_str(out, u.version);
    put_str(out, machine);
    return 0;
}

int64_t gssys_cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? n : 1;
}

int64_t gssys_page_size(void) { return (int64_t)sysconf(_SC_PAGESIZE); }

#if defined(__linux__)
/* A "Name:  123 kB" line of /proc/meminfo, in bytes; -1 if absent. */
static int64_t meminfo_field(const char *text, const char *name) {
    const char *p = strstr(text, name);
    if (!p) return -1;
    p += strlen(name);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    return (int64_t)strtoll(p, NULL, 10) * 1024;
}
#endif

int64_t gssys_mem_info(gssys_MemInfo *m) {
    memset(m, 0, sizeof *m);
#if defined(__linux__)
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -(int64_t)errno;
    char text[8192];
    size_t n = fread(text, 1, sizeof text - 1, f);
    fclose(f);
    text[n] = 0;
    m->total = meminfo_field(text, "\nMemTotal");
    if (m->total < 0) m->total = meminfo_field(text, "MemTotal");
    m->available = meminfo_field(text, "\nMemAvailable");
    if (m->available < 0) m->available = meminfo_field(text, "\nMemFree");
    m->swap_total = meminfo_field(text, "\nSwapTotal");
    m->swap_free = meminfo_field(text, "\nSwapFree");
    if (m->swap_total < 0) m->swap_total = 0;
    if (m->swap_free < 0) m->swap_free = 0;
    return 0;
#elif defined(__APPLE__)
    uint64_t mem = 0;
    size_t len = sizeof mem;
    if (sysctlbyname("hw.memsize", &mem, &len, NULL, 0) != 0) return -(int64_t)errno;
    m->total = (int64_t)mem;
    vm_statistics64_data_t vm;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vm, &count) == KERN_SUCCESS)
        m->available = (int64_t)(vm.free_count + vm.inactive_count + vm.purgeable_count) * (int64_t)sysconf(_SC_PAGESIZE);
    struct xsw_usage sw;
    len = sizeof sw;
    if (sysctlbyname("vm.swapusage", &sw, &len, NULL, 0) == 0) {
        m->swap_total = (int64_t)sw.xsu_total;
        m->swap_free = (int64_t)sw.xsu_avail;
    }
    return 0;
#else
    long pages = sysconf(_SC_PHYS_PAGES), avail = -1;
#  ifdef _SC_AVPHYS_PAGES
    avail = sysconf(_SC_AVPHYS_PAGES);
#  endif
    m->total = (int64_t)pages * sysconf(_SC_PAGESIZE);
    m->available = avail < 0 ? 0 : (int64_t)avail * sysconf(_SC_PAGESIZE);
    return 0;
#endif
}

int64_t gssys_uptime_ms(void) {
#if defined(__linux__)
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) return -(int64_t)errno;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#elif defined(__APPLE__)
    struct timeval boot;
    size_t len = sizeof boot;
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if (sysctl(mib, 2, &boot, &len, NULL, 0) != 0) return -(int64_t)errno;
    struct timeval now;
    gettimeofday(&now, NULL);
    return ((int64_t)now.tv_sec - boot.tv_sec) * 1000 + ((int64_t)now.tv_usec - boot.tv_usec) / 1000;
#else
    return GSSYS_ENOTSUP;
#endif
}

int64_t gssys_load_avg(gssys_f64s out) {
    double l[3];
    if (out.len < 3) return -EINVAL;
    if (getloadavg(l, 3) != 3) return -EIO;
    for (int i = 0; i < 3; i++) out.data[i] = l[i];
    return 3;
}

int64_t gssys_temp_dir(gs_rref out) {
    const char *t = getenv("TMPDIR");
    if (!t || !*t) t = "/tmp";
    size_t n = strlen(t);
    while (n > 1 && t[n - 1] == '/') n--;
    put_raw(out, t, (int64_t)n);
    return (int64_t)n;
}

int64_t gssys_home_dir(gs_rref out) {
    const char *h = getenv("HOME");
    if (h && *h) return put_cstr_raw(out, h);
    struct passwd pw, *res = NULL;
    char buf[4096];
    if (getpwuid_r(geteuid(), &pw, buf, sizeof buf, &res) != 0 || !res) return -ENOENT;
    return put_cstr_raw(out, pw.pw_dir);
}

/* --- This process ----------------------------------------------------------------- */

int64_t gssys_getpid(void) { return (int64_t)getpid(); }
int64_t gssys_getppid(void) { return (int64_t)getppid(); }

int64_t gssys_exe_path(gs_rref out) {
#if defined(__APPLE__)
    char buf[PATH_MAX], real[PATH_MAX];
    uint32_t size = sizeof buf;
    if (_NSGetExecutablePath(buf, &size) != 0) return -ENAMETOOLONG;
    return put_cstr_raw(out, realpath(buf, real) ? real : buf);
#elif defined(__linux__)
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n < 0) return -(int64_t)errno;
    put_raw(out, buf, n);
    return n;
#else
    return GSSYS_ENOTSUP;
#endif
}

int64_t gssys_getcwd(gs_rref out) {
    char buf[PATH_MAX];
    if (!getcwd(buf, sizeof buf)) return -(int64_t)errno;
    return put_cstr_raw(out, buf);
}

int64_t gssys_chdir(gssys_slice path) {
    char *p = cstr(path);
    if (!p) return -EINVAL;
    int rc = chdir(p);
    int64_t r = ERR(rc);
    free(p);
    return r;
}

int64_t gssys_environ(gs_rref out) {
    int64_t n = 0;
    for (char **e = environ; e && *e; e++, n++) put_str(out, *e);
    return n;
}

int64_t gssys_setenv(gssys_slice name, gssys_slice value) {
    char *k = cstr(name), *v = cstr(value);
    int64_t r = -EINVAL;
    if (k && v && *k && !strchr(k, '=')) r = ERR(setenv(k, v, 1));
    free(k);
    free(v);
    return r;
}

int64_t gssys_unsetenv(gssys_slice name) {
    char *k = cstr(name);
    int64_t r = -EINVAL;
    if (k && *k && !strchr(k, '=')) r = ERR(unsetenv(k));
    free(k);
    return r;
}

int64_t gssys_kill(int64_t pid, int32_t sig) {
    if (pid <= 0) return -EINVAL;
    return ERR(kill((pid_t)pid, sig));
}

int64_t gssys_processes(gs_rref out) {
#if defined(__APPLE__)
    int cap = proc_listallpids(NULL, 0);
    if (cap <= 0) return -(int64_t)errno;
    cap += 64;
    pid_t *pids = (pid_t *)malloc(sizeof(pid_t) * (size_t)cap);
    if (!pids) return GSSYS_ENOMEM_CODE;
    int n = proc_listallpids(pids, (int)(sizeof(pid_t) * (size_t)cap));
    int64_t count = 0;
    for (int i = 0; i < n; i++) {
        struct proc_bsdshortinfo si;
        if (proc_pidinfo(pids[i], PROC_PIDT_SHORTBSDINFO, 0, &si, sizeof si) != sizeof si) continue;
        char name[2 * MAXCOMLEN + 1];
        if (proc_name(pids[i], name, sizeof name) <= 0) {
            memcpy(name, si.pbsi_comm, MAXCOMLEN);
            name[MAXCOMLEN] = 0;
        }
        put_i64(out, pids[i]);
        put_i64(out, si.pbsi_ppid);
        put_str(out, name);
        count++;
    }
    free(pids);
    return count;
#elif defined(__linux__)
    DIR *d = opendir("/proc");
    if (!d) return -(int64_t)errno;
    int64_t count = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        char *end;
        long pid = strtol(e->d_name, &end, 10);
        if (*end || pid <= 0) continue;
        char path[64], buf[1024];
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        buf[n] = 0;
        /* pid (comm) state ppid ...: comm may hold spaces and parentheses. */
        char *open = strchr(buf, '('), *close = strrchr(buf, ')');
        if (!open || !close || close < open) continue;
        long ppid = 0;
        char state;
        if (sscanf(close + 1, " %c %ld", &state, &ppid) != 2) continue;
        put_i64(out, pid);
        put_i64(out, ppid);
        put_field(out, open + 1, close - open - 1);
        count++;
    }
    closedir(d);
    return count;
#else
    (void)out;
    return GSSYS_ENOTSUP;
#endif
}

int64_t gssys_process_exe(int64_t pid, gs_rref out) {
#if defined(__APPLE__)
    char buf[PROC_PIDPATHINFO_MAXSIZE];
    int n = proc_pidpath((pid_t)pid, buf, sizeof buf);
    if (n <= 0) return -(int64_t)errno;
    put_raw(out, buf, n);
    return n;
#elif defined(__linux__)
    char path[64], buf[PATH_MAX];
    snprintf(path, sizeof path, "/proc/%lld/exe", (long long)pid);
    ssize_t n = readlink(path, buf, sizeof buf - 1);
    if (n < 0) return -(int64_t)errno;
    put_raw(out, buf, n);
    return n;
#else
    (void)pid; (void)out;
    return GSSYS_ENOTSUP;
#endif
}

int64_t gssys_is_elevated(void) { return geteuid() == 0; }

/* --- Users and groups ----------------------------------------------------------- */

int64_t gssys_getuid(void) { return (int64_t)getuid(); }
int64_t gssys_geteuid(void) { return (int64_t)geteuid(); }
int64_t gssys_getgid(void) { return (int64_t)getgid(); }
int64_t gssys_getegid(void) { return (int64_t)getegid(); }

int64_t gssys_getgroups(gs_rref out) {
    int n = getgroups(0, NULL);
    if (n < 0) return -(int64_t)errno;
    gid_t *g = (gid_t *)malloc(sizeof(gid_t) * (size_t)(n + 1));
    if (!g) return GSSYS_ENOMEM_CODE;
    n = getgroups(n, g);
    if (n < 0) { free(g); return -(int64_t)errno; }
    for (int i = 0; i < n; i++) put_i64(out, (int64_t)g[i]);
    free(g);
    return n;
}

/* Go's user.User: username, uid, gid, name (the GECOS field's first part),
   home directory. */
static int64_t put_passwd(gs_rref out, const struct passwd *pw) {
    char num[32];
    put_str(out, pw->pw_name);
    snprintf(num, sizeof num, "%lld", (long long)pw->pw_uid);
    put_str(out, num);
    snprintf(num, sizeof num, "%lld", (long long)pw->pw_gid);
    put_str(out, num);
    const char *g = pw->pw_gecos ? pw->pw_gecos : "";
    const char *comma = strchr(g, ',');
    put_field(out, g, comma ? comma - g : (int64_t)strlen(g));
    put_str(out, pw->pw_dir);
    return 0;
}

static int64_t passwd_by(const char *name, uid_t uid, gs_rref out) {
    struct passwd pw, *res = NULL;
    size_t size = 16384;
    for (;;) {
        char *buf = (char *)malloc(size);
        if (!buf) return GSSYS_ENOMEM_CODE;
        int rc = name ? getpwnam_r(name, &pw, buf, size, &res) : getpwuid_r(uid, &pw, buf, size, &res);
        if (rc == ERANGE && size < (1 << 22)) { free(buf); size *= 4; continue; }
        int64_t r = rc ? -(int64_t)rc : !res ? -ENOENT : put_passwd(out, &pw);
        free(buf);
        return r;
    }
}

int64_t gssys_current_user(gs_rref out) { return passwd_by(NULL, geteuid(), out); }

int64_t gssys_lookup_user(gssys_slice name, gs_rref out) {
    char *n = cstr(name);
    if (!n) return -EINVAL;
    int64_t r = passwd_by(n, 0, out);
    free(n);
    return r;
}

static int parse_id(gssys_slice s, long long *v) {
    if (s.len <= 0 || s.len > 20) return 0;
    char tmp[24];
    memcpy(tmp, s.data, (size_t)s.len);
    tmp[s.len] = 0;
    char *end;
    errno = 0;
    *v = strtoll(tmp, &end, 10);
    return !*end && !errno && *v >= 0;
}

int64_t gssys_lookup_user_id(gssys_slice uid, gs_rref out) {
    long long v;
    if (!parse_id(uid, &v)) return -EINVAL;
    return passwd_by(NULL, (uid_t)v, out);
}

/* Go's user.Group, gid and name, then the member names. */
static int64_t group_by(const char *name, gid_t gid, gs_rref out) {
    struct group gr, *res = NULL;
    size_t size = 16384;
    for (;;) {
        char *buf = (char *)malloc(size);
        if (!buf) return GSSYS_ENOMEM_CODE;
        int rc = name ? getgrnam_r(name, &gr, buf, size, &res) : getgrgid_r(gid, &gr, buf, size, &res);
        if (rc == ERANGE && size < (1 << 22)) { free(buf); size *= 4; continue; }
        int64_t r = rc ? -(int64_t)rc : !res ? -ENOENT : 0;
        if (r == 0) {
            char num[32];
            snprintf(num, sizeof num, "%lld", (long long)gr.gr_gid);
            put_str(out, num);
            put_str(out, gr.gr_name);
            for (char **m = gr.gr_mem; m && *m; m++) put_str(out, *m);
        }
        free(buf);
        return r;
    }
}

int64_t gssys_lookup_group(gssys_slice name, gs_rref out) {
    char *n = cstr(name);
    if (!n) return -EINVAL;
    int64_t r = group_by(n, 0, out);
    free(n);
    return r;
}

int64_t gssys_lookup_group_id(gssys_slice gid, gs_rref out) {
    long long v;
    if (!parse_id(gid, &v)) return -EINVAL;
    return group_by(NULL, (gid_t)v, out);
}

int64_t gssys_user_group_ids(gssys_slice name, gs_rref out) {
    char *n = cstr(name);
    if (!n) return -EINVAL;
    struct passwd pw, *res = NULL;
    char buf[16384];
    int rc = getpwnam_r(n, &pw, buf, sizeof buf, &res);
    if (rc || !res) { free(n); return rc ? -(int64_t)rc : -ENOENT; }
    int count = 256;
    for (;;) {
#if defined(__APPLE__)
        int *g = (int *)malloc(sizeof(int) * (size_t)count);
        if (!g) { free(n); return GSSYS_ENOMEM_CODE; }
        int want = count;
        int r = getgrouplist(n, (int)pw.pw_gid, g, &want);
#else
        gid_t *g = (gid_t *)malloc(sizeof(gid_t) * (size_t)count);
        if (!g) { free(n); return GSSYS_ENOMEM_CODE; }
        int want = count;
        int r = getgrouplist(n, pw.pw_gid, g, &want);
#endif
        if (r < 0 && count < 65536) {
            free(g);
            count = want > count ? want : count * 4;
            continue;
        }
        char num[32];
        for (int i = 0; i < want && i < count; i++) {
            snprintf(num, sizeof num, "%lld", (long long)(unsigned)g[i]);
            put_str(out, num);
        }
        free(g);
        free(n);
        return want < count ? want : count;
    }
}

/* --- Files ------------------------------------------------------------------------ */

static int64_t ns_of(struct timespec t) { return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec; }

static void fill_stat(gssys_Stat *o, const struct stat *st) {
    memset(o, 0, sizeof *o);
    o->kind = S_ISREG(st->st_mode) ? KIND_FILE : S_ISDIR(st->st_mode) ? KIND_DIR
            : S_ISLNK(st->st_mode) ? KIND_SYMLINK : KIND_OTHER;
    o->mode = st->st_mode & 07777;
    o->size = (int64_t)st->st_size;
    o->nlink = (int64_t)st->st_nlink;
    o->uid = (int64_t)st->st_uid;
    o->gid = (int64_t)st->st_gid;
    o->dev = (int64_t)st->st_dev;
    o->ino = (int64_t)st->st_ino;
#if defined(__APPLE__)
    o->atime_ns = ns_of(st->st_atimespec);
    o->mtime_ns = ns_of(st->st_mtimespec);
    o->ctime_ns = ns_of(st->st_ctimespec);
    o->btime_ns = ns_of(st->st_birthtimespec);
#else
    o->atime_ns = ns_of(st->st_atim);
    o->mtime_ns = ns_of(st->st_mtim);
    o->ctime_ns = ns_of(st->st_ctim);
#endif
    o->attrs = (int64_t)(st->st_mode & S_IFMT);
}

#define WITH_PATH(path, p, expr)                          \
    char *p = cstr(path);                                 \
    if (!p) return -EINVAL;                               \
    int64_t r_ = (expr) < 0 ? -(int64_t)errno : 0;        \
    free(p);                                              \
    return r_

int64_t gssys_stat(gssys_slice path, gssys_Stat *out) {
    struct stat st;
    char *p = cstr(path);
    if (!p) return -EINVAL;
    int rc = stat(p, &st);
    int64_t r = ERR(rc);
    free(p);
    if (r == 0) fill_stat(out, &st);
    return r;
}

int64_t gssys_lstat(gssys_slice path, gssys_Stat *out) {
    struct stat st;
    char *p = cstr(path);
    if (!p) return -EINVAL;
    int rc = lstat(p, &st);
    int64_t r = ERR(rc);
    free(p);
    if (r == 0) fill_stat(out, &st);
    return r;
}

int64_t gssys_chmod(gssys_slice path, int64_t mode) { WITH_PATH(path, p, chmod(p, (mode_t)(mode & 07777))); }
int64_t gssys_chown(gssys_slice path, int64_t uid, int64_t gid) { WITH_PATH(path, p, chown(p, (uid_t)uid, (gid_t)gid)); }
int64_t gssys_lchown(gssys_slice path, int64_t uid, int64_t gid) { WITH_PATH(path, p, lchown(p, (uid_t)uid, (gid_t)gid)); }
int64_t gssys_truncate(gssys_slice path, int64_t size) { WITH_PATH(path, p, truncate(p, (off_t)size)); }
int64_t gssys_mkdir(gssys_slice path, int64_t mode) { WITH_PATH(path, p, mkdir(p, (mode_t)(mode & 07777))); }
int64_t gssys_rmdir(gssys_slice path) { WITH_PATH(path, p, rmdir(p)); }
int64_t gssys_unlink(gssys_slice path) { WITH_PATH(path, p, unlink(p)); }

int64_t gssys_symlink(gssys_slice target, gssys_slice newpath) {
    char *t = cstr(target), *l = cstr(newpath);
    int64_t r = -EINVAL;
    if (t && l) r = ERR(symlink(t, l));
    free(t);
    free(l);
    return r;
}

int64_t gssys_link(gssys_slice existing, gssys_slice newpath) {
    char *t = cstr(existing), *l = cstr(newpath);
    int64_t r = -EINVAL;
    if (t && l) r = ERR(link(t, l));
    free(t);
    free(l);
    return r;
}

int64_t gssys_rename(gssys_slice from, gssys_slice to) {
    char *f = cstr(from), *t = cstr(to);
    int64_t r = -EINVAL;
    if (f && t) r = ERR(rename(f, t));
    free(f);
    free(t);
    return r;
}

int64_t gssys_readlink(gssys_slice path, gs_rref out) {
    char *p = cstr(path);
    if (!p) return -EINVAL;
    char buf[PATH_MAX];
    ssize_t n = readlink(p, buf, sizeof buf);
    int64_t r = n < 0 ? -(int64_t)errno : (int64_t)n;
    free(p);
    if (r >= 0) put_raw(out, buf, r);
    return r;
}

int64_t gssys_utimes(gssys_slice path, int64_t atime_ns, int64_t mtime_ns) {
    struct timespec ts[2];
    ts[0].tv_sec = (time_t)(atime_ns / 1000000000); ts[0].tv_nsec = (long)(atime_ns % 1000000000);
    ts[1].tv_sec = (time_t)(mtime_ns / 1000000000); ts[1].tv_nsec = (long)(mtime_ns % 1000000000);
    WITH_PATH(path, p, utimensat(AT_FDCWD, p, ts, 0));
}

int64_t gssys_realpath(gssys_slice path, gs_rref out) {
    char *p = cstr(path);
    if (!p) return -EINVAL;
    char buf[PATH_MAX];
    char *r = realpath(p, buf);
    int64_t rc = r ? 0 : -(int64_t)errno;
    free(p);
    return rc ? rc : put_cstr_raw(out, buf);
}

int64_t gssys_read_dir(gssys_slice path, gs_rref out) {
    char *p = cstr(path);
    if (!p) return -EINVAL;
    DIR *d = opendir(p);
    if (!d) { int64_t r = -(int64_t)errno; free(p); return r; }
    int64_t n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        int64_t kind = KIND_UNKNOWN;
#ifdef DT_DIR
        switch (e->d_type) {
        case DT_REG: kind = KIND_FILE; break;
        case DT_DIR: kind = KIND_DIR; break;
        case DT_LNK: kind = KIND_SYMLINK; break;
        case DT_UNKNOWN: break;
        default: kind = KIND_OTHER; break;
        }
#endif
        if (kind == KIND_UNKNOWN) {
            struct stat st;
            if (fstatat(dirfd(d), e->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
                gssys_Stat s;
                fill_stat(&s, &st);
                kind = s.kind;
            }
        }
        put_str(out, e->d_name);
        put_i64(out, kind);
        n++;
    }
    closedir(d);
    free(p);
    return n;
}

/* --- Descriptors ------------------------------------------------------------------- */

int64_t gssys_open(gssys_slice path, int64_t flags, int64_t mode) {
    int f = (flags & GO_ACCESS) == GO_WRONLY ? O_WRONLY : (flags & GO_ACCESS) == GO_RDWR ? O_RDWR : O_RDONLY;
    if (flags & GO_APPEND) f |= O_APPEND;
    if (flags & GO_CREATE) f |= O_CREAT;
    if (flags & GO_EXCL) f |= O_EXCL;
    if (flags & GO_TRUNC) f |= O_TRUNC;
    if (flags & GO_SYNC) f |= O_SYNC;
    if (flags & GO_NOFOLLOW) f |= O_NOFOLLOW;
    if (flags & GO_NONBLOCK) f |= O_NONBLOCK;
    f |= O_CLOEXEC;
    char *p = cstr(path);
    if (!p) return -EINVAL;
    int fd;
    do fd = open(p, f, (mode_t)(mode & 07777)); while (fd < 0 && errno == EINTR);
    int64_t r = fd < 0 ? -(int64_t)errno : fd;
    free(p);
    return r;
}

int64_t gssys_close(int64_t fd) { return ERR(close((int)fd)); }

int64_t gssys_read(int64_t fd, gssys_buf buf) {
    ssize_t n;
    do n = read((int)fd, buf.data, (size_t)buf.len); while (n < 0 && errno == EINTR);
    return n < 0 ? -(int64_t)errno : (int64_t)n;
}

int64_t gssys_write(int64_t fd, gssys_slice data) {
    ssize_t n;
    do n = write((int)fd, data.data, (size_t)data.len); while (n < 0 && errno == EINTR);
    return n < 0 ? -(int64_t)errno : (int64_t)n;
}

int64_t gssys_pread(int64_t fd, gssys_buf buf, int64_t offset) {
    ssize_t n;
    do n = pread((int)fd, buf.data, (size_t)buf.len, (off_t)offset); while (n < 0 && errno == EINTR);
    return n < 0 ? -(int64_t)errno : (int64_t)n;
}

int64_t gssys_pwrite(int64_t fd, gssys_slice data, int64_t offset) {
    ssize_t n;
    do n = pwrite((int)fd, data.data, (size_t)data.len, (off_t)offset); while (n < 0 && errno == EINTR);
    return n < 0 ? -(int64_t)errno : (int64_t)n;
}

int64_t gssys_seek(int64_t fd, int64_t offset, int32_t whence) {
    int w = whence == 1 ? SEEK_CUR : whence == 2 ? SEEK_END : SEEK_SET;
    off_t r = lseek((int)fd, (off_t)offset, w);
    return r < 0 ? -(int64_t)errno : (int64_t)r;
}

int64_t gssys_fsync(int64_t fd) { return ERR(fsync((int)fd)); }
int64_t gssys_ftruncate(int64_t fd, int64_t size) { return ERR(ftruncate((int)fd, (off_t)size)); }

int64_t gssys_fstat(int64_t fd, gssys_Stat *out) {
    struct stat st;
    if (fstat((int)fd, &st) != 0) return -(int64_t)errno;
    fill_stat(out, &st);
    return 0;
}

int64_t gssys_lock(int64_t fd, int32_t how) {
    int op = (how & 3) == LK_SHARED ? LOCK_SH : (how & 3) == LK_EXCLUSIVE ? LOCK_EX
           : (how & 3) == LK_UNLOCK ? LOCK_UN : -1;
    if (op < 0) return -EINVAL;
    if (how & LK_NONBLOCK) op |= LOCK_NB;
    int rc;
    do rc = flock((int)fd, op); while (rc < 0 && errno == EINTR);
    return ERR(rc);
}

int64_t gssys_pipe(gssys_i64s fds) {
    int p[2];
    if (fds.len < 2) return -EINVAL;
    if (pipe(p) != 0) return -(int64_t)errno;
    fcntl(p[0], F_SETFD, FD_CLOEXEC);
    fcntl(p[1], F_SETFD, FD_CLOEXEC);
    fds.data[0] = p[0];
    fds.data[1] = p[1];
    return 0;
}

/* $VAR and ${VAR} replaced by the variable's value (empty when it is not
   set), as Go's os.ExpandEnv; a $ before anything else is kept. */
int64_t gssys_expand_env(gssys_slice s, gs_rref out) {
    int64_t n = 0, i = 0;
    while (i < s.len) {
        uint8_t c = s.data[i];
        if (c != '$' || i + 1 >= s.len) { put_raw(out, &c, 1); n++; i++; continue; }
        int64_t start, end, next;
        if (s.data[i + 1] == '{') {
            start = i + 2;
            end = start;
            while (end < s.len && s.data[end] != '}') end++;
            if (end >= s.len) { put_raw(out, &c, 1); n++; i++; continue; }
            next = end + 1;
        } else {
            start = i + 1;
            end = start;
            while (end < s.len && (s.data[end] == '_' || (s.data[end] >= '0' && s.data[end] <= '9') ||
                                   ((s.data[end] | 32) >= 'a' && (s.data[end] | 32) <= 'z'))) end++;
            if (end == start) { put_raw(out, &c, 1); n++; i++; continue; }
            next = end;
        }
        char name[256];
        int64_t len = end - start;
        if (len > 0 && len < (int64_t)sizeof name) {
            memcpy(name, s.data + start, (size_t)len);
            name[len] = 0;
            const char *v = getenv(name);
            if (v) { int64_t vl = (int64_t)strlen(v); put_raw(out, v, vl); n += vl; }
        }
        i = next;
    }
    return n;
}

int64_t gssys_std_fd(int32_t n) { return n >= 0 && n <= 2 ? n : -EINVAL; }

int64_t gssys_isatty(int64_t fd) { return isatty((int)fd) ? 1 : 0; }

#endif
