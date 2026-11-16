/* service: the native half of service.goose. Running as a Windows
   service (the service control manager's dispatcher, ServiceMain and
   control handler), or under systemd or launchd (SIGTERM, SIGINT, SIGHUP),
   with every request turned into an event in one queue that Goose waits
   on; installing and controlling Windows services; and the few things os
   does not have (the executable's path, running a command).

   Nothing here calls into Goose. The dispatcher, ServiceMain and the
   control handler run on threads of the service control manager's making,
   and they only queue events and report status; Goose takes the events
   from its own thread with gssvc_wait.

   Every function is defined on every platform (gslib's JIT library
   resolves every extern of the package's modules); one that does not apply
   returns GSSVC_ENOTSUP. Strings arrive as Goose slices, { data, len },
   not NUL-terminated. */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  define _XOPEN_SOURCE 700
#  define _DEFAULT_SOURCE
#  define _DARWIN_C_SOURCE
#  include <errno.h>
#  include <fcntl.h>
#  include <poll.h>
#  include <signal.h>
#  include <spawn.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <time.h>
#  include <unistd.h>
#  if defined(__APPLE__)
#    include <mach-o/dyld.h>
#  endif
extern char **environ;
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } gssvc_slice;
typedef struct { uint8_t *data; int64_t len; } gssvc_buf;

/* Results; Windows errors come back as their negated Win32 code. */
#define GSSVC_ENOTSUP  (-50)     /* ERROR_NOT_SUPPORTED */
#define GSSVC_EARG     (-87)     /* ERROR_INVALID_PARAMETER */
#define GSSVC_ESTATE   (-1)      /* started twice, or not started */

/* Events (service::EV_*). */
#define EV_NONE      0
#define EV_STOP      1
#define EV_SHUTDOWN  2
#define EV_RELOAD    3
#define EV_PAUSE     4
#define EV_CONTINUE  5

#define FLAG_PAUSABLE 1

/* The platform: service::PLATFORM_*. */
int32_t gssvc_platform(void) {
#if defined(_WIN32)
    return 1;
#elif defined(__linux__)
    return 2;
#elif defined(__APPLE__)
    return 3;
#else
    return 4;
#endif
}

/* --- The event queue ------------------------------------------------------ */

#define QLEN 64

#if defined(_WIN32)

static CRITICAL_SECTION q_lock;
static CONDITION_VARIABLE q_cond;
static INIT_ONCE q_once = INIT_ONCE_STATIC_INIT;
static int q_ev[QLEN];
static int q_head, q_count;

static BOOL CALLBACK q_init(PINIT_ONCE o, PVOID p, PVOID *c) {
    (void)o; (void)p; (void)c;
    InitializeCriticalSection(&q_lock);
    InitializeConditionVariable(&q_cond);
    return TRUE;
}

static void q_push(int ev) {
    InitOnceExecuteOnce(&q_once, q_init, NULL, NULL);
    EnterCriticalSection(&q_lock);
    if (q_count < QLEN) {
        q_ev[(q_head + q_count) % QLEN] = ev;
        q_count++;
    }
    LeaveCriticalSection(&q_lock);
    WakeAllConditionVariable(&q_cond);
}

static int q_pop(int32_t timeout_ms) {
    InitOnceExecuteOnce(&q_once, q_init, NULL, NULL);
    DWORD wait = timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms;
    ULONGLONG until = GetTickCount64() + (ULONGLONG)(timeout_ms < 0 ? 0 : timeout_ms);
    int ev = EV_NONE;
    EnterCriticalSection(&q_lock);
    while (q_count == 0) {
        if (!SleepConditionVariableCS(&q_cond, &q_lock, wait)) break;
        if (timeout_ms >= 0) {
            ULONGLONG now = GetTickCount64();
            if (now >= until) break;
            wait = (DWORD)(until - now);
        }
    }
    if (q_count > 0) {
        ev = q_ev[q_head];
        q_head = (q_head + 1) % QLEN;
        q_count--;
    }
    LeaveCriticalSection(&q_lock);
    return ev;
}

#else

/* POSIX: the signal handler writes the event's byte to a pipe (all that
   is safe in a handler), and gssvc_wait polls the pipe. */
static int q_pipe[2] = { -1, -1 };

static int q_open(void) {
    if (q_pipe[0] >= 0) return 0;
    if (pipe(q_pipe) != 0) return -1;
    for (int i = 0; i < 2; i++) {
        fcntl(q_pipe[i], F_SETFD, FD_CLOEXEC);
        fcntl(q_pipe[i], F_SETFL, fcntl(q_pipe[i], F_GETFL) | O_NONBLOCK);
    }
    return 0;
}

static void q_push(int ev) {
    unsigned char b = (unsigned char)ev;
    int saved = errno;
    if (q_pipe[1] >= 0) (void)!write(q_pipe[1], &b, 1);
    errno = saved;
}

static int q_pop(int32_t timeout_ms) {
    if (q_open() != 0) return EV_NONE;
    struct pollfd p = { q_pipe[0], POLLIN, 0 };
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        unsigned char b;
        if (read(q_pipe[0], &b, 1) == 1) return b;
        int left = -1;
        if (timeout_ms >= 0) {
            struct timespec t;
            clock_gettime(CLOCK_MONOTONIC, &t);
            int64_t ms = (int64_t)(t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000;
            if (ms >= timeout_ms) return EV_NONE;
            left = (int)(timeout_ms - ms);
        }
        int r = poll(&p, 1, left);
        if (r < 0 && errno != EINTR) return EV_NONE;
    }
}

#endif

/* Waits up to timeout_ms (< 0: for ever) for the next event: EV_*, or
   EV_NONE when the time passed. */
int32_t gssvc_wait(int32_t timeout_ms) {
    return q_pop(timeout_ms);
}

/* Queues an event as if it had come from the system: for tests. */
int32_t gssvc_inject(int32_t ev) {
    if (ev <= EV_NONE || ev > EV_CONTINUE) return GSSVC_EARG;
#if !defined(_WIN32)
    if (q_open() != 0) return GSSVC_ESTATE;
#endif
    q_push(ev);
    return 0;
}

/* --- Running: Windows ----------------------------------------------------- */

#if defined(_WIN32)

static int started;
static int32_t run_flags;
static wchar_t *svc_name;
static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS status;
static CRITICAL_SECTION status_lock;
static HANDLE mode_known, finished, dispatcher;
static volatile LONG mode = -1;          /* 0 interactive, 1 service, < 0 an error */

static wchar_t *widen(gssvc_slice s) {
    if (s.len < 0 || s.len > (1 << 20) || memchr(s.data, 0, (size_t)s.len)) return NULL;
    int n = s.len == 0 ? 0 : MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)s.data, (int)s.len, NULL, 0);
    if (s.len > 0 && n <= 0) return NULL;
    wchar_t *w = (wchar_t *)malloc(((size_t)n + 1) * sizeof(wchar_t));
    if (!w) return NULL;
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, (const char *)s.data, (int)s.len, w, n);
    w[n] = 0;
    return w;
}

static void report(DWORD state, DWORD exit_code, DWORD wait_hint) {
    EnterCriticalSection(&status_lock);
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = 0;
    if (state == SERVICE_RUNNING || state == SERVICE_PAUSED) {
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PARAMCHANGE;
        if (run_flags & FLAG_PAUSABLE) status.dwControlsAccepted |= SERVICE_ACCEPT_PAUSE_CONTINUE;
    }
    if (exit_code != 0) {
        status.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        status.dwServiceSpecificExitCode = exit_code;
    } else {
        status.dwWin32ExitCode = NO_ERROR;
        status.dwServiceSpecificExitCode = 0;
    }
    if (state == SERVICE_RUNNING || state == SERVICE_PAUSED || state == SERVICE_STOPPED) status.dwCheckPoint = 0;
    else status.dwCheckPoint++;
    status.dwWaitHint = wait_hint;
    if (status_handle) SetServiceStatus(status_handle, &status);
    LeaveCriticalSection(&status_lock);
}

static DWORD WINAPI handler(DWORD control, DWORD type, LPVOID data, LPVOID ctx) {
    (void)type; (void)data; (void)ctx;
    switch (control) {
    case SERVICE_CONTROL_STOP:
        report(SERVICE_STOP_PENDING, 0, 30000);
        q_push(EV_STOP);
        return NO_ERROR;
    case SERVICE_CONTROL_SHUTDOWN:
        report(SERVICE_STOP_PENDING, 0, 30000);
        q_push(EV_SHUTDOWN);
        return NO_ERROR;
    case SERVICE_CONTROL_PARAMCHANGE:
        q_push(EV_RELOAD);
        return NO_ERROR;
    case SERVICE_CONTROL_PAUSE:
        if (!(run_flags & FLAG_PAUSABLE)) return ERROR_CALL_NOT_IMPLEMENTED;
        report(SERVICE_PAUSED, 0, 0);
        q_push(EV_PAUSE);
        return NO_ERROR;
    case SERVICE_CONTROL_CONTINUE:
        if (!(run_flags & FLAG_PAUSABLE)) return ERROR_CALL_NOT_IMPLEMENTED;
        report(SERVICE_RUNNING, 0, 0);
        q_push(EV_CONTINUE);
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static volatile LONG exit_code_v;

/* Runs on a thread the service control manager starts. It must not return
   before the program is done: returning is reporting the service stopped. */
static void WINAPI service_main(DWORD argc, LPWSTR *argv) {
    (void)argc; (void)argv;
    status_handle = RegisterServiceCtrlHandlerExW(svc_name, handler, NULL);
    if (!status_handle) {
        InterlockedExchange(&mode, -(LONG)GetLastError());
        SetEvent(mode_known);
        return;
    }
    report(SERVICE_RUNNING, 0, 0);
    InterlockedExchange(&mode, 1);
    SetEvent(mode_known);
    WaitForSingleObject(finished, INFINITE);
    report(SERVICE_STOPPED, (DWORD)exit_code_v, 0);
}

static DWORD WINAPI dispatcher_thread(LPVOID p) {
    (void)p;
    SERVICE_TABLE_ENTRYW table[2] = { { svc_name, service_main }, { NULL, NULL } };
    if (!StartServiceCtrlDispatcherW(table)) {
        DWORD e = GetLastError();
        /* Not started by the service control manager: a console program. */
        InterlockedCompareExchange(&mode, e == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT ? 0 : -(LONG)e, -1);
        SetEvent(mode_known);
    }
    return 0;
}

static BOOL WINAPI console_handler(DWORD ctrl) {
    switch (ctrl) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        q_push(EV_STOP);
        return TRUE;
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        /* Windows ends the process when this returns: give the program
           its few seconds to finish. */
        q_push(ctrl == CTRL_CLOSE_EVENT ? EV_STOP : EV_SHUTDOWN);
        WaitForSingleObject(finished, 4500);
        return TRUE;
    default:
        return FALSE;
    }
}

int32_t gssvc_start(gssvc_slice name, int32_t flags) {
    if (started) return GSSVC_ESTATE;
    svc_name = widen(name);
    if (!svc_name || name.len == 0) return GSSVC_EARG;
    started = 1;
    run_flags = flags;
    InitializeCriticalSection(&status_lock);
    mode_known = CreateEventW(NULL, TRUE, FALSE, NULL);
    finished = CreateEventW(NULL, TRUE, FALSE, NULL);
    dispatcher = CreateThread(NULL, 0, dispatcher_thread, NULL, 0, NULL);
    if (!dispatcher) return -(int32_t)GetLastError();
    WaitForSingleObject(mode_known, INFINITE);
    if (mode == 0) SetConsoleCtrlHandler(console_handler, TRUE);
    return (int32_t)mode;
}

/* Reports the stop still under way, for another wait_hint_ms: for a
   program whose stopping takes longer than the 30 s the handler asked for. */
int32_t gssvc_pending(int32_t wait_hint_ms) {
    if (!started) return GSSVC_ESTATE;
    if (mode == 1) report(SERVICE_STOP_PENDING, 0, (DWORD)(wait_hint_ms < 0 ? 0 : wait_hint_ms));
    return 0;
}

void gssvc_finish(int32_t exit_code) {
    if (!started) return;
    exit_code_v = exit_code;
    SetEvent(finished);
    if (mode == 1 && dispatcher) WaitForSingleObject(dispatcher, 10000);
}

int32_t gssvc_raise(int32_t ev) {
    (void)ev;
    return GSSVC_ENOTSUP;
}

int32_t gssvc_mode(void) {
    return started ? (int32_t)mode : GSSVC_ESTATE;
}

#else

/* --- Running: POSIX ------------------------------------------------------- */

static int started, posix_mode;
static struct sigaction old_term, old_int, old_hup;

static void on_signal(int sig) {
    q_push(sig == SIGHUP ? EV_RELOAD : EV_STOP);
}

/* Under systemd or launchd, the process is the service: the mode says only
   whether it looks started by one of them. */
int32_t gssvc_start(gssvc_slice name, int32_t flags) {
    (void)flags;
    if (started) return GSSVC_ESTATE;
    if (name.len <= 0) return GSSVC_EARG;
    if (q_open() != 0) return -(int32_t)errno;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, &old_term);
    sigaction(SIGINT, &sa, &old_int);
    sigaction(SIGHUP, &sa, &old_hup);
    started = 1;
    const char *inv = getenv("INVOCATION_ID");
    const char *xpc = getenv("XPC_SERVICE_NAME");
    int service = (inv && *inv) || (xpc && *xpc && strcmp(xpc, "0") != 0) || getppid() == 1;
    posix_mode = service ? 1 : 0;
    return posix_mode;
}

int32_t gssvc_mode(void) {
    return started ? posix_mode : GSSVC_ESTATE;
}

int32_t gssvc_pending(int32_t wait_hint_ms) {
    (void)wait_hint_ms;
    return started ? 0 : GSSVC_ESTATE;
}

void gssvc_finish(int32_t exit_code) {
    (void)exit_code;
    if (!started) return;
    sigaction(SIGTERM, &old_term, NULL);
    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGHUP, &old_hup, NULL);
    started = 0;
}

/* Sends this process the signal behind an event (EV_STOP: SIGTERM,
   EV_RELOAD: SIGHUP): for tests of the handlers. */
int32_t gssvc_raise(int32_t ev) {
    int sig = ev == EV_STOP ? SIGTERM : ev == EV_RELOAD ? SIGHUP : 0;
    if (!sig) return GSSVC_EARG;
    return kill(getpid(), sig) == 0 ? 0 : -(int32_t)errno;
}

#endif

/* --- The executable, and running a command -------------------------------- */

/* This executable's full path, UTF-8, into out: its length, or < 0. */
int64_t gssvc_exe_path(gssvc_buf out) {
#if defined(_WIN32)
    wchar_t w[32768];
    DWORD n = GetModuleFileNameW(NULL, w, 32768);
    if (n == 0 || n >= 32768) return -(int64_t)GetLastError();
    int m = WideCharToMultiByte(CP_UTF8, 0, w, (int)n, (char *)out.data, (int)(out.len > 0x7fffffff ? 0x7fffffff : out.len), NULL, NULL);
    return m > 0 ? m : GSSVC_EARG;
#elif defined(__APPLE__)
    char p[4096], r[4096];
    uint32_t size = sizeof p;
    if (_NSGetExecutablePath(p, &size) != 0) return GSSVC_EARG;
    if (!realpath(p, r)) return -(int64_t)errno;
    size_t n = strlen(r);
    if ((int64_t)n > out.len) return GSSVC_EARG;
    memcpy(out.data, r, n);
    return (int64_t)n;
#elif defined(__linux__)
    char p[4096];
    ssize_t n = readlink("/proc/self/exe", p, sizeof p);
    if (n <= 0 || n >= (ssize_t)sizeof p) return GSSVC_EARG;
    if (n > out.len) return GSSVC_EARG;
    memcpy(out.data, p, (size_t)n);
    return n;
#else
    (void)out;
    return GSSVC_ENOTSUP;
#endif
}

/* The user's id, for launchctl's gui/<uid> domain and the choice between
   a user's and the system's units; -1 on Windows. */
int64_t gssvc_uid(void) {
#if defined(_WIN32)
    return -1;
#else
    return (int64_t)getuid();
#endif
}

static int64_t spawn_out_len;

/* Runs argv (its arguments each followed by a NUL) with stdin from
   /dev/null and stdout and stderr into out, as much as fits: the exit
   status, 128 + the signal that ended it, or < 0 when it could not run.
   gssvc_spawn_output_len says how much of out it wrote. POSIX only:
   systemctl and launchctl. */
int32_t gssvc_spawn(gssvc_slice argv, gssvc_buf out) {
    spawn_out_len = 0;
#if defined(_WIN32)
    (void)argv; (void)out;
    return GSSVC_ENOTSUP;
#else
    if (argv.len <= 0 || argv.len > 65536 || argv.data[argv.len - 1] != 0) return GSSVC_EARG;
    char *buf = (char *)malloc((size_t)argv.len);
    if (!buf) return GSSVC_EARG;
    memcpy(buf, argv.data, (size_t)argv.len);
    char *args[64];
    int n = 0;
    for (int64_t i = 0; i < argv.len && n < 63; ) {
        args[n++] = buf + i;
        i += (int64_t)strlen(buf + i) + 1;
    }
    args[n] = NULL;
    int fds[2];
    if (pipe(fds) != 0) { free(buf); return -(int32_t)errno; }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, fds[1], 1);
    posix_spawn_file_actions_adddup2(&fa, fds[1], 2);
    posix_spawn_file_actions_addclose(&fa, fds[0]);
    posix_spawn_file_actions_addclose(&fa, fds[1]);
    /* The child gets the default signal handling, not ours. */
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    sigset_t def;
    sigemptyset(&def);
    sigaddset(&def, SIGTERM); sigaddset(&def, SIGINT); sigaddset(&def, SIGHUP); sigaddset(&def, SIGPIPE);
    posix_spawnattr_setsigdefault(&at, &def);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGDEF);
    pid_t pid;
    int e = posix_spawnp(&pid, args[0], &fa, &at, args, environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&at);
    close(fds[1]);
    free(buf);
    if (e != 0) { close(fds[0]); return -(int32_t)e; }
    char tmp[4096];
    for (;;) {
        ssize_t r = read(fds[0], tmp, sizeof tmp);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        int64_t room = out.len - spawn_out_len;
        int64_t take = r < room ? r : room;
        if (take > 0) { memcpy(out.data + spawn_out_len, tmp, (size_t)take); spawn_out_len += take; }
    }
    close(fds[0]);
    int st;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) return -(int32_t)errno;
    }
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return GSSVC_EARG;
#endif
}

int64_t gssvc_spawn_output_len(void) {
    return spawn_out_len;
}

/* --- Windows: the service control manager --------------------------------- */

#if defined(_WIN32)

static const wchar_t EVENTLOG_KEY[] = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\";

/* The Application log's source for the service, with EventCreate.exe's
   messages (each id is "%1"), so that its entries read as written. */
static void eventlog_register(const wchar_t *name) {
    wchar_t key[512];
    if (wcslen(name) > 300) return;
    wcscpy(key, EVENTLOG_KEY);
    wcscat(key, name);
    HKEY k;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS) return;
    static const wchar_t file[] = L"%SystemRoot%\\System32\\EventCreate.exe";
    RegSetValueExW(k, L"EventMessageFile", 0, REG_EXPAND_SZ, (const BYTE *)file, sizeof file);
    DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    RegSetValueExW(k, L"TypesSupported", 0, REG_DWORD, (const BYTE *)&types, sizeof types);
    DWORD custom = 1;
    RegSetValueExW(k, L"CustomSource", 0, REG_DWORD, (const BYTE *)&custom, sizeof custom);
    RegCloseKey(k);
}

static void eventlog_remove(const wchar_t *name) {
    wchar_t key[512];
    if (wcslen(name) > 300) return;
    wcscpy(key, EVENTLOG_KEY);
    wcscat(key, name);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, key);
}

static int32_t last_err(void) {
    return -(int32_t)GetLastError();
}

#endif

/* Installs a service that runs command (the executable, quoted, and its
   arguments: one command line). start: 0 automatic, 1 manual, 2 automatic
   after a delay, 3 disabled. restart_ms > 0: restarted that long after it
   fails, three times, the count reset after a day without failures; it
   counts as failing when it stops with a non-zero exit code too. 0, or a
   negated Win32 error (-1073: ERROR_SERVICE_EXISTS). */
int32_t gssvc_win_install(gssvc_slice name, gssvc_slice display, gssvc_slice description,
                          gssvc_slice command, int32_t start, int32_t restart_ms) {
#if defined(_WIN32)
    if (name.len == 0 || command.len == 0 || start < 0 || start > 3) return GSSVC_EARG;
    wchar_t *n = widen(name), *d = widen(display.len ? display : name), *ds = widen(description), *c = widen(command);
    int32_t rc = 0;
    SC_HANDLE m = NULL, s = NULL;
    if (!n || !d || !ds || !c) { rc = GSSVC_EARG; goto out; }
    m = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!m) { rc = last_err(); goto out; }
    DWORD st = start == 1 ? SERVICE_DEMAND_START : start == 3 ? SERVICE_DISABLED : SERVICE_AUTO_START;
    s = CreateServiceW(m, n, d, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, st,
                       SERVICE_ERROR_NORMAL, c, NULL, NULL, NULL, NULL, NULL);
    if (!s) { rc = last_err(); goto out; }
    if (description.len > 0) {
        SERVICE_DESCRIPTIONW sd = { ds };
        ChangeServiceConfig2W(s, SERVICE_CONFIG_DESCRIPTION, &sd);
    }
    if (start == 2) {
        SERVICE_DELAYED_AUTO_START_INFO da = { TRUE };
        ChangeServiceConfig2W(s, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &da);
    }
    if (restart_ms > 0) {
        SC_ACTION acts[3] = {
            { SC_ACTION_RESTART, (DWORD)restart_ms }, { SC_ACTION_RESTART, (DWORD)restart_ms },
            { SC_ACTION_RESTART, (DWORD)restart_ms } };
        SERVICE_FAILURE_ACTIONSW fa = { 86400, NULL, NULL, 3, acts };
        if (!ChangeServiceConfig2W(s, SERVICE_CONFIG_FAILURE_ACTIONS, &fa)) { rc = last_err(); goto out; }
        SERVICE_FAILURE_ACTIONS_FLAG ff = { TRUE };
        ChangeServiceConfig2W(s, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &ff);
    }
    eventlog_register(n);
out:
    if (s) CloseServiceHandle(s);
    if (m) CloseServiceHandle(m);
    free(n); free(d); free(ds); free(c);
    return rc;
#else
    (void)name; (void)display; (void)description; (void)command; (void)start; (void)restart_ms;
    return GSSVC_ENOTSUP;
#endif
}

/* Marks the service for deletion (it goes when it has stopped and every
   handle to it is closed) and removes its event log source. */
int32_t gssvc_win_uninstall(gssvc_slice name) {
#if defined(_WIN32)
    wchar_t *n = widen(name);
    if (!n || name.len == 0) { free(n); return GSSVC_EARG; }
    int32_t rc = 0;
    SC_HANDLE m = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), s = NULL;
    if (!m) { rc = last_err(); goto out; }
    s = OpenServiceW(m, n, DELETE);
    if (!s || !DeleteService(s)) { rc = last_err(); goto out; }
    eventlog_remove(n);
out:
    if (s) CloseServiceHandle(s);
    if (m) CloseServiceHandle(m);
    free(n);
    return rc;
#else
    (void)name;
    return GSSVC_ENOTSUP;
#endif
}

#if defined(_WIN32)
static SC_HANDLE open_service(const wchar_t *n, DWORD access, SC_HANDLE *m) {
    *m = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!*m) return NULL;
    return OpenServiceW(*m, n, access);
}

static DWORD query_state(SC_HANDLE s) {
    SERVICE_STATUS_PROCESS sp;
    DWORD need;
    if (!QueryServiceStatusEx(s, SC_STATUS_PROCESS_INFO, (BYTE *)&sp, sizeof sp, &need)) return 0;
    return sp.dwCurrentState;
}
#endif

/* The service's state: 0 not installed, else the SERVICE_* state (1
   stopped, 2 start pending, 3 stop pending, 4 running, 5 continue pending,
   6 pause pending, 7 paused), or a negated Win32 error. */
int32_t gssvc_win_status(gssvc_slice name) {
#if defined(_WIN32)
    wchar_t *n = widen(name);
    if (!n || name.len == 0) { free(n); return GSSVC_EARG; }
    SC_HANDLE m, s = open_service(n, SERVICE_QUERY_STATUS, &m);
    int32_t rc;
    if (!s) rc = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? 0 : last_err();
    else {
        DWORD st = query_state(s);
        rc = st ? (int32_t)st : last_err();
    }
    if (s) CloseServiceHandle(s);
    if (m) CloseServiceHandle(m);
    free(n);
    return rc;
#else
    (void)name;
    return GSSVC_ENOTSUP;
#endif
}

/* Starts the service, or stops it (stop != 0), and waits up to timeout_ms
   for it to be running or stopped: 0, -1460 (ERROR_TIMEOUT), or a negated
   Win32 error (-1056: already running; -1062: not started). */
int32_t gssvc_win_control(gssvc_slice name, int32_t stop, int32_t timeout_ms) {
#if defined(_WIN32)
    wchar_t *n = widen(name);
    if (!n || name.len == 0) { free(n); return GSSVC_EARG; }
    SC_HANDLE m, s = open_service(n, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS, &m);
    int32_t rc = 0;
    if (!s) { rc = last_err(); goto out; }
    if (stop) {
        SERVICE_STATUS ss;
        if (!ControlService(s, SERVICE_CONTROL_STOP, &ss)) { rc = last_err(); goto out; }
    } else if (!StartServiceW(s, 0, NULL)) { rc = last_err(); goto out; }
    DWORD want = stop ? SERVICE_STOPPED : SERVICE_RUNNING;
    ULONGLONG until = GetTickCount64() + (ULONGLONG)(timeout_ms < 0 ? 0 : timeout_ms);
    for (;;) {
        DWORD st = query_state(s);
        if (st == want) break;
        if (!stop && st == SERVICE_STOPPED) { rc = -(int32_t)ERROR_SERVICE_NOT_ACTIVE; break; }
        if (GetTickCount64() >= until) { rc = -(int32_t)ERROR_TIMEOUT; break; }
        Sleep(100);
    }
out:
    if (s) CloseServiceHandle(s);
    if (m) CloseServiceHandle(m);
    free(n);
    return rc;
#else
    (void)name; (void)stop; (void)timeout_ms;
    return GSSVC_ENOTSUP;
#endif
}

/* Writes msg to the Application event log under the service's name:
   level 0 information, 1 warning, 2 error. 0, or a negated Win32 error. */
int32_t gssvc_win_log(gssvc_slice name, int32_t level, gssvc_slice msg) {
#if defined(_WIN32)
    static HANDLE src;
    static wchar_t *src_name;
    wchar_t *n = widen(name), *t = widen(msg);
    int32_t rc = 0;
    if (!n || !t || name.len == 0) { rc = GSSVC_EARG; goto out; }
    if (!src || wcscmp(src_name, n) != 0) {
        if (src) DeregisterEventSource(src);
        free(src_name);
        src_name = n;
        n = NULL;
        src = RegisterEventSourceW(NULL, src_name);
        if (!src) { rc = last_err(); goto out; }
    }
    WORD type = level >= 2 ? EVENTLOG_ERROR_TYPE : level == 1 ? EVENTLOG_WARNING_TYPE : EVENTLOG_INFORMATION_TYPE;
    LPCWSTR strs[1] = { t };
    if (!ReportEventW(src, type, 0, 1, NULL, 1, 0, strs, NULL)) rc = last_err();
out:
    free(n); free(t);
    return rc;
#else
    (void)name; (void)level; (void)msg;
    return GSSVC_ENOTSUP;
#endif
}
