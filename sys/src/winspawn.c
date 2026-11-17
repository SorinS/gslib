/* sys on Windows: child processes on pipes or a pseudo-console (ConPTY,
   Windows 10 1809 and later), what a pipe holds, private files, and what
   the operating system is (os_info). The POSIX side is spawn.c. Errors
   are the negated Win32 code. */

#if defined(_WIN32)

#include "wcommon.h"
#include <aclapi.h>

#define HD(fd) ((HANDLE)(intptr_t)(fd))

/* --- What the system is ----------------------------------------------------------- */

#define CURRENT_VERSION L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

static void reg_str(const wchar_t *name, wchar_t *out, DWORD cap) {
    DWORD bytes = cap * sizeof(wchar_t);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, CURRENT_VERSION, name, RRF_RT_REG_SZ, NULL, out, &bytes) != ERROR_SUCCESS)
        out[0] = 0;
}

static DWORD reg_dword(const wchar_t *name) {
    DWORD v = 0, bytes = sizeof v;
    if (RegGetValueW(HKEY_LOCAL_MACHINE, CURRENT_VERSION, name, RRF_RT_REG_DWORD, NULL, &v, &bytes) != ERROR_SUCCESS) v = 0;
    return v;
}

typedef LONG (WINAPI *rtl_version_fn)(OSVERSIONINFOW *);

/* name, id, id_like, version, version_name, build, edition, pretty. The
   registry's ProductName still says "Windows 10" on Windows 11, which is
   told by its build (22000 and later). */
int64_t gssys_os_info(gs_rref out) {
    OSVERSIONINFOEXW v;
    memset(&v, 0, sizeof v);
    v.dwOSVersionInfoSize = sizeof v;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    rtl_version_fn rgv = ntdll ? (rtl_version_fn)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    if (!rgv || rgv((OSVERSIONINFOW *)&v) != 0) return -(int64_t)ERROR_NOT_SUPPORTED;
    wchar_t product[256], display[64], edition[128], name[256], version[64], build[64], pretty[512];
    reg_str(L"ProductName", product, 256);
    reg_str(L"DisplayVersion", display, 64);
    if (!display[0]) reg_str(L"ReleaseId", display, 64);
    reg_str(L"EditionID", edition, 128);
    DWORD ubr = reg_dword(L"UBR");
    if (!product[0]) swprintf(product, 256, L"Windows");
    if (v.dwBuildNumber >= 22000 && wcsncmp(product, L"Windows 10", 10) == 0)
        swprintf(name, 256, L"Windows 11%ls", product + 10);
    else
        swprintf(name, 256, L"%ls", product);
    swprintf(version, 64, L"%lu.%lu.%lu", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
    swprintf(build, 64, L"%lu.%lu", v.dwBuildNumber, ubr);
    if (display[0]) swprintf(pretty, 512, L"%ls %ls (%ls)", name, display, build);
    else swprintf(pretty, 512, L"%ls (%ls)", name, build);
    put_wstr(out, name);
    put_str(out, "windows");
    put_str(out, "");
    put_wstr(out, version);
    put_wstr(out, display);
    put_wstr(out, build);
    put_wstr(out, edition);
    put_wstr(out, pretty);
    return 0;
}

/* When the system started, in seconds since 1970. */
int64_t gssys_boot_time(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    int64_t now = (int64_t)((((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000000ULL) - 11644473600LL;
    return now - (int64_t)(GetTickCount64() / 1000);
}

/* --- Descriptors ------------------------------------------------------------------------ */

static int sid_in(PSID s, PSID *set, int n) {
    for (int i = 0; i < n; i++)
        if (set[i] && EqualSid(s, set[i])) return 1;
    return 0;
}

/* 1 when only this user can reach fd's file: its owner is the user, SYSTEM
   or Administrators, and its DACL lets in no one else (OWNER RIGHTS aside);
   0 when not, a NULL DACL (everyone) among them. */
int64_t gssys_is_private(int64_t fd) {
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD rc = GetSecurityInfo(HD(fd), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                               &owner, NULL, &dacl, NULL, &sd);
    if (rc != ERROR_SUCCESS) return -(int64_t)rc;
    BYTE ubuf[256], sys_sid[SECURITY_MAX_SID_SIZE], adm_sid[SECURITY_MAX_SID_SIZE], ow_sid[SECURITY_MAX_SID_SIZE];
    PSID user = NULL;
    HANDLE tok;
    DWORD n;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenUser, ubuf, sizeof ubuf, &n)) user = ((TOKEN_USER *)ubuf)->User.Sid;
        CloseHandle(tok);
    }
    n = sizeof sys_sid;
    PSID system = CreateWellKnownSid(WinLocalSystemSid, NULL, sys_sid, &n) ? (PSID)sys_sid : NULL;
    n = sizeof adm_sid;
    PSID admins = CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, adm_sid, &n) ? (PSID)adm_sid : NULL;
    n = sizeof ow_sid;
    PSID owner_rights = CreateWellKnownSid(WinCreatorOwnerRightsSid, NULL, ow_sid, &n) ? (PSID)ow_sid : NULL;
    PSID trusted[4] = { user, system, admins, owner_rights };
    int64_t r = user && owner && sid_in(owner, trusted, 3) && dacl ? 1 : 0;
    for (DWORD i = 0; r == 1 && i < dacl->AceCount; i++) {
        ACE_HEADER *h;
        if (!GetAce(dacl, i, (void **)&h)) { r = WERR(); break; }
        if (h->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (h->AceType != ACCESS_ALLOWED_ACE_TYPE) { r = 0; break; }
        ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)h;
        if (a->Mask != 0 && !sid_in((PSID)&a->SidStart, trusted, 4)) r = 0;
    }
    LocalFree(sd);
    return r;
}

/* Bytes that a read of fd would give now without waiting: a pipe's
   (PeekNamedPipe; 0 once its writer has gone, when a read gives the end),
   or what is left of a file. */
int64_t gssys_available(int64_t fd) {
    DWORD avail = 0;
    if (PeekNamedPipe(HD(fd), NULL, 0, NULL, &avail, NULL)) return avail;
    DWORD e = GetLastError();
    if (e == ERROR_BROKEN_PIPE) return 0;
    if (GetFileType(HD(fd)) == FILE_TYPE_DISK) {
        LARGE_INTEGER size, pos, zero;
        zero.QuadPart = 0;
        if (!GetFileSizeEx(HD(fd), &size) || !SetFilePointerEx(HD(fd), zero, &pos, FILE_CURRENT)) return WERR();
        return size.QuadPart > pos.QuadPart ? size.QuadPart - pos.QuadPart : 0;
    }
    return -(int64_t)e;
}

/* --- Child processes ----------------------------------------------------------------------- */

typedef HRESULT (WINAPI *create_pc_fn)(COORD, HANDLE, HANDLE, DWORD, void **);
typedef HRESULT (WINAPI *resize_pc_fn)(void *, COORD);
typedef void (WINAPI *close_pc_fn)(void *);

/* ConPTY's functions, looked up in kernel32 (always loaded) so that a
   compiler whose headers predate them still builds this. */
static FARPROC k32(const char *name) {
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    return k ? GetProcAddress(k, name) : NULL;
}

/* An environment block from NUL-ended UTF-8 strings: UTF-16, each ended by
   a NUL, the whole by another. */
static wchar_t *env_block(gssys_slice env) {
    if (env.len > 0 && env.data[env.len - 1] != 0) return NULL;
    int n = env.len ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)env.data, (int)env.len, NULL, 0) : 0;
    if (env.len && n <= 0) return NULL;
    wchar_t *w = (wchar_t *)malloc(sizeof(wchar_t) * ((size_t)n + 2));
    if (!w) return NULL;
    if (n) MultiByteToWideChar(CP_UTF8, 0, (const char *)env.data, (int)env.len, w, n);
    w[n] = 0;
    w[n + 1] = 0;
    return w;
}

static void close_h(HANDLE *h) {
    if (*h && *h != INVALID_HANDLE_VALUE) CloseHandle(*h);
    *h = NULL;
}

static HANDLE inheritable_copy(HANDLE h) {
    HANDLE d = NULL;
    if (!h || h == INVALID_HANDLE_VALUE) return NULL;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, TRUE, DUPLICATE_SAME_ACCESS)) return NULL;
    return d;
}

/* Starts path with the command line args (already quoted) and env (NUL-
   ended strings), in dir ("" for this one). stdio as spawn.c's; only the
   child's three handles are inherited (PROC_THREAD_ATTRIBUTE_HANDLE_LIST),
   never every inheritable handle of this process. With SP_PTY the child
   runs on a new pseudo-console of size[0] x size[1]: out->stdin_fd writes to
   it, out->stdout_fd reads it, out->pty is it. */
int64_t gssys_spawn(gssys_slice path, gssys_slice args, gssys_slice env, gssys_slice dir, int64_t flags,
                    gssys_i64s stdio, gssys_i64s size, gssys_Child *out) {
    out->pid = out->handle = out->pty = 0;
    out->stdin_fd = out->stdout_fd = out->stderr_fd = -1;
    if (stdio.len < 3 || (flags & SP_PTY && size.len < 2)) return EARG;
    wchar_t *wpath = wstr(path), *wcmd = wstr(args), *wdir = dir.len ? wstr(dir) : NULL, *wenv = env_block(env);
    HANDLE child[3] = { NULL, NULL, NULL }, parent[3] = { NULL, NULL, NULL };
    HANDLE in_r = NULL, in_w = NULL, out_r = NULL, out_w = NULL;
    void *hpc = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    int64_t r = 0;
    STARTUPINFOEXW si;
    memset(&si, 0, sizeof si);
    si.StartupInfo.cb = sizeof si;
    BOOL inherit = FALSE;
    HANDLE list[3];
    int nlist = 0;
    if (!wpath || !wcmd || !wenv || (dir.len && !wdir)) { r = EARG; goto done; }

    SIZE_T asz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
    attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(asz);
    if (!attrs || !InitializeProcThreadAttributeList(attrs, 1, 0, &asz)) { r = WERR(); free(attrs); attrs = NULL; goto done; }

    if (flags & SP_PTY) {
        create_pc_fn create_pc = (create_pc_fn)(void *)k32("CreatePseudoConsole");
        if (!create_pc) { r = GSSYS_ENOTSUP; goto done; }
        if (!CreatePipe(&in_r, &in_w, NULL, 0) || !CreatePipe(&out_r, &out_w, NULL, 0)) { r = WERR(); goto done; }
        COORD c;
        c.X = (SHORT)size.data[0];
        c.Y = (SHORT)size.data[1];
        HRESULT hr = create_pc(c, in_r, out_w, 0, &hpc);
        if (FAILED(hr)) { r = hr; hpc = NULL; goto done; }
        if (!UpdateProcThreadAttribute(attrs, 0, 0x00020016 /* PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE */, hpc,
                                       sizeof hpc, NULL, NULL)) { r = WERR(); goto done; }
        /* No standard handles of ours: with this process's output redirected,
           a child would otherwise write there rather than to the console. */
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    } else {
        SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
        const DWORD std_id[3] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };
        for (int i = 0; i < 3; i++) {
            int64_t s = stdio.data[i];
            if (s == STDIO_PIPE) {
                HANDLE pr, pw;
                if (!CreatePipe(&pr, &pw, NULL, 0)) { r = WERR(); goto done; }
                child[i] = i == 0 ? pr : pw;
                parent[i] = i == 0 ? pw : pr;
                SetHandleInformation(child[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
            } else if (s == STDIO_NULL) {
                child[i] = CreateFileW(L"NUL", i == 0 ? GENERIC_READ : GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       &sa, OPEN_EXISTING, 0, NULL);
                if (child[i] == INVALID_HANDLE_VALUE) { child[i] = NULL; r = WERR(); goto done; }
            } else if (s == STDIO_INHERIT) {
                child[i] = inheritable_copy(GetStdHandle(std_id[i]));
            } else if (s == STDIO_STDOUT && i == 2) {
                child[i] = inheritable_copy(child[1] ? child[1] : GetStdHandle(STD_OUTPUT_HANDLE));
            } else if (s >= 0) {
                child[i] = inheritable_copy(HD(s));
                if (!child[i]) { r = WERR(); goto done; }
            } else { r = EARG; goto done; }
        }
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = child[0];
        si.StartupInfo.hStdOutput = child[1];
        si.StartupInfo.hStdError = child[2];
        for (int i = 0; i < 3; i++) {
            int seen = 0;
            for (int j = 0; j < nlist; j++) seen |= list[j] == child[i];
            if (child[i] && !seen) list[nlist++] = child[i];
        }
        if (nlist) {
            if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, sizeof(HANDLE) * (size_t)nlist,
                                           NULL, NULL)) { r = WERR(); goto done; }
            inherit = TRUE;
        }
    }
    si.lpAttributeList = attrs;

    DWORD cflags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
    if (flags & (SP_SETSID | SP_PGROUP)) cflags |= CREATE_NEW_PROCESS_GROUP;
    if (flags & SP_NO_WINDOW) cflags |= CREATE_NO_WINDOW;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof pi);
    if (!CreateProcessW(wpath, wcmd, NULL, NULL, inherit, cflags, wenv, wdir, &si.StartupInfo, &pi)) { r = WERR(); goto done; }
    CloseHandle(pi.hThread);
    out->pid = pi.dwProcessId;
    out->handle = (int64_t)(intptr_t)pi.hProcess;
    if (flags & SP_PTY) {
        out->stdin_fd = (int64_t)(intptr_t)in_w;
        out->stdout_fd = (int64_t)(intptr_t)out_r;
        out->pty = (int64_t)(intptr_t)hpc;
        in_w = out_r = NULL;
        hpc = NULL;
    } else {
        for (int i = 0; i < 3; i++) {
            if (parent[i]) {
                int64_t v = (int64_t)(intptr_t)parent[i];
                if (i == 0) out->stdin_fd = v; else if (i == 1) out->stdout_fd = v; else out->stderr_fd = v;
                parent[i] = NULL;
            }
        }
    }

done:
    for (int i = 0; i < 3; i++) {
        int dup = 0;
        for (int j = 0; j < i; j++) dup |= child[j] == child[i];
        if (!dup) close_h(&child[i]);
        close_h(&parent[i]);
    }
    close_h(&in_r); close_h(&out_w); close_h(&in_w); close_h(&out_r);
    if (hpc) {
        close_pc_fn close_pc = (close_pc_fn)(void *)k32("ClosePseudoConsole");
        if (close_pc) close_pc(hpc);
    }
    if (attrs) { DeleteProcThreadAttributeList(attrs); free(attrs); }
    free(wpath); free(wcmd); free(wdir); free(wenv);
    return r;
}

/* As spawn.c's: 1 when the child has ended (status[0] its exit code), 0
   while it runs. */
int64_t gssys_child_wait(gssys_Child *c, int64_t timeout_ms, gssys_i64s status) {
    if (c->pid <= 0 || !c->handle || status.len < 2) return EARG;
    DWORD w = WaitForSingleObject(HD(c->handle), timeout_ms < 0 ? INFINITE : timeout_ms > 0x7ffffffe ? 0x7ffffffe : (DWORD)timeout_ms);
    if (w == WAIT_TIMEOUT) return 0;
    if (w != WAIT_OBJECT_0) return WERR();
    DWORD code;
    if (!GetExitCodeProcess(HD(c->handle), &code)) return WERR();
    status.data[0] = code;
    status.data[1] = 0;
    c->pid = -c->pid;
    return 1;
}

/* Any signal but 0 ends the child (TerminateProcess, exit code 1); 0 asks
   whether it still runs. */
int64_t gssys_child_kill(gssys_Child *c, int32_t sig) {
    if (c->pid <= 0 || !c->handle) return -(int64_t)ERROR_NOT_FOUND;
    if (sig == 0) return WaitForSingleObject(HD(c->handle), 0) == WAIT_TIMEOUT ? 0 : -(int64_t)ERROR_NOT_FOUND;
    return TerminateProcess(HD(c->handle), 1) ? 0 : WERR();
}

int64_t gssys_pty_resize(gssys_Child *c, int64_t cols, int64_t rows) {
    resize_pc_fn resize_pc = (resize_pc_fn)(void *)k32("ResizePseudoConsole");
    if (!c->pty || !resize_pc) return EARG;
    COORD sz;
    sz.X = (SHORT)cols;
    sz.Y = (SHORT)rows;
    HRESULT hr = resize_pc((void *)(intptr_t)c->pty, sz);
    return FAILED(hr) ? hr : 0;
}

/* Closes the pseudo-console, which ends its output once what it holds has
   been read: read stdout while the child runs, as process::collect does,
   or this can wait for room in the pipe. */
int64_t gssys_pty_close(gssys_Child *c) {
    if (!c->pty) return 0;
    close_pc_fn close_pc = (close_pc_fn)(void *)k32("ClosePseudoConsole");
    if (close_pc) close_pc((void *)(intptr_t)c->pty);
    c->pty = 0;
    return 0;
}

/* Closes this end of the pipes or console, then the pseudo-console (its
   output pipe already closed, so that closing it cannot wait), then the
   process handle. */
int64_t gssys_child_release(gssys_Child *c) {
    int64_t *fds[3] = { &c->stdin_fd, &c->stdout_fd, &c->stderr_fd };
    for (int i = 0; i < 3; i++) {
        if (*fds[i] != -1 && *fds[i] != 0) CloseHandle(HD(*fds[i]));
        *fds[i] = -1;
    }
    gssys_pty_close(c);
    if (c->handle) CloseHandle(HD(c->handle));
    c->handle = 0;
    return 0;
}

#endif

int gssys_winspawn_unit;
