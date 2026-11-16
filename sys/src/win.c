/* sys on Windows: the host, this process and others, users and groups,
   and files by path and by HANDLE, as Go's x/sys/windows and os/user have
   them. Errors are the negated Win32 code (GetLastError); paths and names
   are UTF-8 in Goose and UTF-16 here. The POSIX side is posix.c. */

#if defined(_WIN32)

#include "wcommon.h"

int32_t gssys_platform_id(void) { return 1; }

/* --- Errors -------------------------------------------------------------------------- */

int64_t gssys_error_text(int64_t code, gs_rref out) {
    if (code == GSSYS_ENOTSUP) { put_raw(out, "not supported on this platform", 30); return 30; }
    if (code == GSSYS_ENOMEM_CODE) { put_raw(out, "out of memory", 13); return 13; }
    /* A negated Win32 code, or a failed HRESULT as itself. */
    DWORD e = (DWORD)(code < 0 && code > -0x10000 ? -code : code);
    wchar_t *msg = NULL;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, e, 0, (LPWSTR)&msg, 0, NULL);
    if (!n || !msg) {
        char b[48];
        int k = snprintf(b, sizeof b, "error %lld", (long long)code);
        put_raw(out, b, k);
        return k;
    }
    while (n && (msg[n - 1] == L'\r' || msg[n - 1] == L'\n' || msg[n - 1] == L' ' || msg[n - 1] == L'.')) n--;
    int64_t r = put_w(out, msg, (int)n, 0);
    LocalFree(msg);
    return r;
}

int32_t gssys_error_is(int64_t code, int32_t cls) {
    if (code >= 0) return 0;
    if (code == GSSYS_ENOTSUP) return cls == CLS_NOT_SUPPORTED;
    int64_t e = -code;
    switch (cls) {
    case CLS_NOT_EXIST:
        return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND || e == ERROR_INVALID_NAME
            || e == ERROR_NONE_MAPPED || e == ERROR_NO_SUCH_USER || e == ERROR_NO_SUCH_GROUP
            || e == ERROR_NO_SUCH_ALIAS || e == NERR_UserNotFound || e == NERR_GroupNotFound
            || e == ERROR_MOD_NOT_FOUND || e == ERROR_BAD_NETPATH || e == ERROR_NOT_FOUND
            || e == NERR_NetNameNotFound || e == ERROR_SERVICE_DOES_NOT_EXIST;
    case CLS_EXIST:
        return e == ERROR_ALREADY_EXISTS || e == ERROR_FILE_EXISTS || e == ERROR_DIR_NOT_EMPTY
            || e == NERR_UserExists || e == NERR_GroupExists || e == ERROR_ALIAS_EXISTS
            || e == ERROR_MEMBER_IN_ALIAS || e == NERR_DuplicateShare || e == ERROR_SERVICE_EXISTS;
    case CLS_PERMISSION:
        return e == ERROR_ACCESS_DENIED || e == ERROR_PRIVILEGE_NOT_HELD || e == ERROR_SHARING_VIOLATION
            || e == ERROR_LOCK_VIOLATION;
    case CLS_TIMEOUT:       return e == WAIT_TIMEOUT || e == ERROR_TIMEOUT || e == ERROR_SEM_TIMEOUT;
    case CLS_NOT_SUPPORTED: return e == ERROR_NOT_SUPPORTED || e == ERROR_CALL_NOT_IMPLEMENTED || e == ERROR_INVALID_FUNCTION;
    case CLS_WOULD_BLOCK:   return e == ERROR_LOCK_VIOLATION || e == ERROR_IO_PENDING || e == ERROR_NO_DATA;
    case CLS_INTERRUPTED:   return e == ERROR_OPERATION_ABORTED;
    case CLS_NOT_EMPTY:     return e == ERROR_DIR_NOT_EMPTY;
    case CLS_IS_DIR:        return e == ERROR_DIRECTORY_NOT_SUPPORTED;
    case CLS_NOT_DIR:       return e == ERROR_DIRECTORY;
    case CLS_INVALID:       return e == ERROR_INVALID_PARAMETER || e == ERROR_INVALID_HANDLE || e == ERROR_INVALID_NAME;
    }
    return 0;
}

int64_t gssys_last_error(void) { return WERR(); }

/* --- The host -------------------------------------------------------------------------- */

int64_t gssys_hostname(gs_rref out) {
    wchar_t buf[256];
    DWORD n = 256;
    if (!GetComputerNameExW(ComputerNameDnsHostname, buf, &n)) return WERR();
    return put_wraw(out, buf);
}

typedef LONG (WINAPI *rtl_get_version_fn)(OSVERSIONINFOW *);

int64_t gssys_uname(gs_rref out) {
    OSVERSIONINFOEXW v;
    memset(&v, 0, sizeof v);
    v.dwOSVersionInfoSize = sizeof v;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    rtl_get_version_fn rgv = ntdll ? (rtl_get_version_fn)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
    if (!rgv || rgv((OSVERSIONINFOW *)&v) != 0) return -(int64_t)ERROR_NOT_SUPPORTED;
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char *machine = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x86_64"
                        : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "arm64"
                        : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86" : "unknown";
    char rel[64], ver[64];
    snprintf(rel, sizeof rel, "%lu.%lu.%lu", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
    snprintf(ver, sizeof ver, "Build %lu", v.dwBuildNumber);
    wchar_t host[256];
    DWORD hn = 256;
    if (!GetComputerNameExW(ComputerNameDnsHostname, host, &hn)) host[0] = 0;
    put_str(out, "Windows");
    put_wstr(out, host);
    put_str(out, rel);
    put_str(out, ver);
    put_str(out, machine);
    return 0;
}

int64_t gssys_cpu_count(void) {
    DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return n ? n : 1;
}

int64_t gssys_page_size(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
}

int64_t gssys_mem_info(gssys_MemInfo *m) {
    MEMORYSTATUSEX s;
    memset(m, 0, sizeof *m);
    s.dwLength = sizeof s;
    if (!GlobalMemoryStatusEx(&s)) return WERR();
    m->total = (int64_t)s.ullTotalPhys;
    m->available = (int64_t)s.ullAvailPhys;
    /* The commit limit is physical memory and the page files. */
    m->swap_total = s.ullTotalPageFile > s.ullTotalPhys ? (int64_t)(s.ullTotalPageFile - s.ullTotalPhys) : 0;
    m->swap_free = s.ullAvailPageFile > s.ullAvailPhys ? (int64_t)(s.ullAvailPageFile - s.ullAvailPhys) : 0;
    if (m->swap_free > m->swap_total) m->swap_free = m->swap_total;
    return 0;
}

int64_t gssys_uptime_ms(void) { return (int64_t)GetTickCount64(); }

int64_t gssys_temp_dir(gs_rref out) {
    wchar_t buf[MAX_PATH + 2];
    DWORD n = GetTempPathW(MAX_PATH + 1, buf);
    if (!n || n > MAX_PATH + 1) return WERR();
    while (n > 3 && (buf[n - 1] == L'\\' || buf[n - 1] == L'/')) n--;
    return put_w(out, buf, (int)n, 0);
}

int64_t gssys_home_dir(gs_rref out) {
    wchar_t buf[32768];
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", buf, 32768);
    if (!n || n >= 32768) return -(int64_t)ERROR_ENVVAR_NOT_FOUND;
    return put_w(out, buf, (int)n, 0);
}

/* --- This process and others --------------------------------------------------------- */

int64_t gssys_getpid(void) { return (int64_t)GetCurrentProcessId(); }

int64_t gssys_getppid(void) {
    DWORD me = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return WERR();
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof pe;
    int64_t r = -(int64_t)ERROR_NOT_FOUND;
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
        if (pe.th32ProcessID == me) { r = pe.th32ParentProcessID; break; }
    CloseHandle(snap);
    return r;
}

int64_t gssys_exe_path(gs_rref out) {
    wchar_t buf[32768];
    DWORD n = GetModuleFileNameW(NULL, buf, 32768);
    if (!n || n >= 32768) return WERR();
    return put_w(out, buf, (int)n, 0);
}

int64_t gssys_getcwd(gs_rref out) {
    wchar_t buf[32768];
    DWORD n = GetCurrentDirectoryW(32768, buf);
    if (!n || n >= 32768) return WERR();
    return put_w(out, buf, (int)n, 0);
}

int64_t gssys_chdir(gssys_slice path) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    int64_t r = SetCurrentDirectoryW(w) ? 0 : WERR();
    free(w);
    return r;
}

int64_t gssys_environ(gs_rref out) {
    wchar_t *env = GetEnvironmentStringsW();
    if (!env) return WERR();
    int64_t n = 0;
    for (wchar_t *p = env; *p; p += wcslen(p) + 1) {
        put_wstr(out, p);
        n++;
    }
    FreeEnvironmentStringsW(env);
    return n;
}

/* The C runtime keeps its own copy of the environment (getenv); both are
   changed. */
int64_t gssys_setenv(gssys_slice name, gssys_slice value) {
    wchar_t *k = wstr(name), *v = wstr(value);
    int64_t r = EARG;
    if (k && v && *k && !wcschr(k + 1, L'=')) {
        r = SetEnvironmentVariableW(k, v) ? 0 : WERR();
        if (r == 0) _wputenv_s(k, v);
    }
    free(k);
    free(v);
    return r;
}

int64_t gssys_unsetenv(gssys_slice name) {
    wchar_t *k = wstr(name);
    int64_t r = EARG;
    if (k && *k && !wcschr(k + 1, L'=')) {
        r = SetEnvironmentVariableW(k, NULL) || GetLastError() == ERROR_ENVVAR_NOT_FOUND ? 0 : WERR();
        if (r == 0) _wputenv_s(k, L"");
    }
    free(k);
    return r;
}

int64_t gssys_kill(int64_t pid, int32_t sig) {
    if (pid <= 0) return EARG;
    HANDLE h = OpenProcess(sig ? PROCESS_TERMINATE : PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) {
        /* No such process is ERROR_INVALID_PARAMETER to OpenProcess. */
        DWORD e = GetLastError();
        return -(int64_t)(e == ERROR_INVALID_PARAMETER ? ERROR_NOT_FOUND : e);
    }
    int64_t r = 0;
    if (sig) {
        r = TerminateProcess(h, 1) ? 0 : WERR();
    } else {
        DWORD code;
        if (GetExitCodeProcess(h, &code) && code != STILL_ACTIVE) r = -(int64_t)ERROR_NOT_FOUND;
    }
    CloseHandle(h);
    return r;
}

int64_t gssys_processes(gs_rref out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return WERR();
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof pe;
    int64_t n = 0;
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        put_i64(out, pe.th32ProcessID);
        put_i64(out, pe.th32ParentProcessID);
        put_wstr(out, pe.szExeFile);
        n++;
    }
    CloseHandle(snap);
    return n;
}

int64_t gssys_process_exe(int64_t pid, gs_rref out) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return WERR();
    wchar_t buf[32768];
    DWORD n = 32768;
    int64_t r = QueryFullProcessImageNameW(h, 0, buf, &n) ? put_w(out, buf, (int)n, 0) : WERR();
    CloseHandle(h);
    return r;
}

int64_t gssys_is_elevated(void) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return WERR();
    TOKEN_ELEVATION el;
    DWORD n;
    int64_t r = GetTokenInformation(tok, TokenElevation, &el, sizeof el, &n) ? (el.TokenIsElevated != 0) : WERR();
    CloseHandle(tok);
    return r;
}

/* --- Users and groups ------------------------------------------------------------------ */

/* "S-1-5-..." for a SID, as a field. */
static int put_sid(gs_rref out, PSID sid) {
    wchar_t *s = NULL;
    if (!ConvertSidToStringSidW(sid, &s)) return 0;
    put_wstr(out, s);
    LocalFree(s);
    return 1;
}

/* A profile's directory, from the registry's ProfileList. */
static void put_profile_dir(gs_rref out, PSID sid) {
    wchar_t *s = NULL, key[256], val[MAX_PATH * 2], exp[MAX_PATH * 2];
    val[0] = 0;
    if (ConvertSidToStringSidW(sid, &s)) {
        lstrcpyW(key, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\");
        lstrcatW(key, s);
        LocalFree(s);
        DWORD size = sizeof val;
        if (RegGetValueW(HKEY_LOCAL_MACHINE, key, L"ProfileImagePath", RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                         NULL, val, &size) != ERROR_SUCCESS)
            val[0] = 0;
    }
    if (val[0] && ExpandEnvironmentStringsW(val, exp, MAX_PATH * 2)) put_wstr(out, exp);
    else put_wstr(out, val);
}

/* Go's user.User for an account's SID: DOMAIN\name, the SID, the primary
   group's SID, the full name (NetUserGetInfo; empty when it cannot be
   read) and the profile directory. */
static int64_t put_user_sid(gs_rref out, PSID sid, PSID primary_group) {
    wchar_t name[256], domain[256];
    DWORD nn = 256, dn = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(NULL, sid, name, &nn, domain, &dn, &use)) return WERR();
    if (use != SidTypeUser && use != SidTypeComputer && use != SidTypeWellKnownGroup)
        return -(int64_t)ERROR_NO_SUCH_USER;
    wchar_t full[600];
    lstrcpyW(full, domain);
    if (domain[0]) lstrcatW(full, L"\\");
    lstrcatW(full, name);
    put_wstr(out, full);
    put_sid(out, sid);
    /* The primary group: the token's, or the account's primary group RID
       under the account's domain. */
    int done = 0;
    if (primary_group) {
        done = put_sid(out, primary_group);
    } else {
        USER_INFO_4 *ui4 = NULL;
        if (NetUserGetInfo(NULL, name, 4, (LPBYTE *)&ui4) == NERR_Success && ui4) {
            DWORD subs = *GetSidSubAuthorityCount(sid);
            BYTE buf[SECURITY_MAX_SID_SIZE];
            if (subs > 0 && CopySid(sizeof buf, buf, sid)) {
                *GetSidSubAuthority(buf, subs - 1) = ui4->usri4_primary_group_id;
                done = put_sid(out, buf);
            }
            NetApiBufferFree(ui4);
        }
    }
    if (!done) put_str(out, "");
    USER_INFO_10 *ui = NULL;
    if (NetUserGetInfo(NULL, name, 10, (LPBYTE *)&ui) == NERR_Success && ui) {
        put_wstr(out, ui->usri10_full_name);
        NetApiBufferFree(ui);
    } else {
        put_str(out, "");
    }
    put_profile_dir(out, sid);
    return 0;
}

int64_t gssys_current_user(gs_rref out) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return WERR();
    BYTE ub[512], gb[512];
    DWORD n;
    int64_t r;
    if (!GetTokenInformation(tok, TokenUser, ub, sizeof ub, &n) ||
        !GetTokenInformation(tok, TokenPrimaryGroup, gb, sizeof gb, &n)) {
        r = WERR();
    } else {
        r = put_user_sid(out, ((TOKEN_USER *)ub)->User.Sid, ((TOKEN_PRIMARY_GROUP *)gb)->PrimaryGroup);
    }
    CloseHandle(tok);
    return r;
}

/* An account name's SID (malloc'd) and its kind, or NULL with the error. */
static PSID sid_of_wname(const wchar_t *w, SID_NAME_USE *use, int64_t *err) {
    DWORD sn = 0, dn = 0;
    LookupAccountNameW(NULL, w, NULL, &sn, NULL, &dn, use);
    if (!sn) { *err = WERR(); return NULL; }
    PSID sid = malloc(sn);
    wchar_t *dom = (wchar_t *)malloc(sizeof(wchar_t) * (dn + 1));
    if (!sid || !dom || !LookupAccountNameW(NULL, w, sid, &sn, dom, &dn, use)) {
        *err = sid && dom ? WERR() : GSSYS_ENOMEM_CODE;
        free(sid);
        sid = NULL;
    }
    free(dom);
    return sid;
}

static PSID sid_of_name(gssys_slice name, SID_NAME_USE *use, int64_t *err) {
    wchar_t *w = wstr(name);
    if (!w) { *err = EARG; return NULL; }
    PSID sid = sid_of_wname(w, use, err);
    free(w);
    return sid;
}

int64_t gssys_lookup_user(gssys_slice name, gs_rref out) {
    SID_NAME_USE use;
    int64_t err = 0;
    PSID sid = sid_of_name(name, &use, &err);
    if (!sid) return err;
    int64_t r = use == SidTypeUser ? put_user_sid(out, sid, NULL) : -(int64_t)ERROR_NO_SUCH_USER;
    free(sid);
    return r;
}

static PSID sid_of_string(gssys_slice s) {
    wchar_t *w = wstr(s);
    PSID sid = NULL;
    if (w && !ConvertStringSidToSidW(w, &sid)) sid = NULL;
    free(w);
    return sid;
}

int64_t gssys_lookup_user_id(gssys_slice uid, gs_rref out) {
    PSID sid = sid_of_string(uid);
    if (!sid) return -(int64_t)ERROR_INVALID_SID;
    int64_t r = put_user_sid(out, sid, NULL);
    LocalFree(sid);
    return r;
}

/* Go's user.Group for a group's SID: the SID and the name; then, for a
   local group (an alias), its members as DOMAIN\name. */
static int64_t put_group_sid(gs_rref out, PSID sid) {
    wchar_t name[256], domain[256];
    DWORD nn = 256, dn = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(NULL, sid, name, &nn, domain, &dn, &use)) return WERR();
    if (use != SidTypeGroup && use != SidTypeAlias && use != SidTypeWellKnownGroup)
        return -(int64_t)ERROR_NO_SUCH_GROUP;
    put_sid(out, sid);
    put_wstr(out, name);
    if (use == SidTypeAlias) {
        LOCALGROUP_MEMBERS_INFO_3 *m = NULL;
        DWORD read = 0, total = 0;
        if (NetLocalGroupGetMembers(NULL, name, 3, (LPBYTE *)&m, MAX_PREFERRED_LENGTH, &read, &total, NULL) == NERR_Success && m) {
            for (DWORD i = 0; i < read; i++) put_wstr(out, m[i].lgrmi3_domainandname);
            NetApiBufferFree(m);
        }
    }
    return 0;
}

int64_t gssys_lookup_group(gssys_slice name, gs_rref out) {
    SID_NAME_USE use;
    int64_t err = 0;
    PSID sid = sid_of_name(name, &use, &err);
    if (!sid) return err;
    int64_t r = put_group_sid(out, sid);
    free(sid);
    return r;
}

int64_t gssys_lookup_group_id(gssys_slice gid, gs_rref out) {
    PSID sid = sid_of_string(gid);
    if (!sid) return -(int64_t)ERROR_INVALID_SID;
    int64_t r = put_group_sid(out, sid);
    LocalFree(sid);
    return r;
}

/* The SIDs of the local groups the user is in, directly or through a
   global group. */
int64_t gssys_user_group_ids(gssys_slice name, gs_rref out) {
    wchar_t *w = wstr(name);
    if (!w) return EARG;
    LOCALGROUP_USERS_INFO_0 *g = NULL;
    DWORD read = 0, total = 0;
    NET_API_STATUS st = NetUserGetLocalGroups(NULL, w, 0, LG_INCLUDE_INDIRECT, (LPBYTE *)&g, MAX_PREFERRED_LENGTH, &read, &total);
    free(w);
    if (st != NERR_Success) return -(int64_t)st;
    int64_t n = 0;
    for (DWORD i = 0; i < read; i++) {
        SID_NAME_USE use;
        int64_t err = 0;
        PSID sid = sid_of_wname(g[i].lgrui0_name, &use, &err);
        if (!sid) continue;
        if (put_sid(out, sid)) n++;
        free(sid);
    }
    NetApiBufferFree(g);
    return n;
}

/* --- Files ------------------------------------------------------------------------------- */

/* 100 ns intervals since 1601 to nanoseconds since 1970, and back. */
static int64_t ft_ns(FILETIME ft) {
    int64_t t = (int64_t)(((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime);
    return (t - 116444736000000000LL) * 100;
}

static FILETIME ns_ft(int64_t ns) {
    uint64_t t = (uint64_t)(ns / 100 + 116444736000000000LL);
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)t;
    ft.dwHighDateTime = (DWORD)(t >> 32);
    return ft;
}

/* Go's mode bits for Windows attributes: 0444 or 0666, and 0111 for a
   directory. */
static int64_t mode_of(DWORD attrs) {
    int64_t m = (attrs & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) m |= 0111;
    return m;
}

static int64_t kind_of(DWORD attrs, DWORD reparse_tag) {
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) &&
        (reparse_tag == IO_REPARSE_TAG_SYMLINK || reparse_tag == IO_REPARSE_TAG_MOUNT_POINT))
        return KIND_SYMLINK;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) return KIND_DIR;
    if (attrs & FILE_ATTRIBUTE_DEVICE) return KIND_OTHER;
    return KIND_FILE;
}

static int64_t stat_handle(HANDLE h, gssys_Stat *o) {
    BY_HANDLE_FILE_INFORMATION fi;
    memset(o, 0, sizeof *o);
    o->uid = o->gid = -1;
    if (!GetFileInformationByHandle(h, &fi)) {
        /* A pipe or a console. */
        DWORD type = GetFileType(h);
        if (type == FILE_TYPE_UNKNOWN && GetLastError() != NO_ERROR) return WERR();
        o->kind = type == FILE_TYPE_DISK ? KIND_FILE : KIND_OTHER;
        o->mode = 0666;
        return 0;
    }
    FILE_ATTRIBUTE_TAG_INFO tag;
    DWORD reparse = 0;
    if ((fi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
        GetFileInformationByHandleEx(h, FileAttributeTagInfo, &tag, sizeof tag))
        reparse = tag.ReparseTag;
    o->kind = kind_of(fi.dwFileAttributes, reparse);
    o->mode = mode_of(fi.dwFileAttributes);
    o->size = (int64_t)(((uint64_t)fi.nFileSizeHigh << 32) | fi.nFileSizeLow);
    o->nlink = fi.nNumberOfLinks;
    o->dev = fi.dwVolumeSerialNumber;
    o->ino = (int64_t)(((uint64_t)fi.nFileIndexHigh << 32) | fi.nFileIndexLow);
    o->atime_ns = ft_ns(fi.ftLastAccessTime);
    o->mtime_ns = ft_ns(fi.ftLastWriteTime);
    o->ctime_ns = o->mtime_ns;
    FILE_BASIC_INFO bi;
    if (GetFileInformationByHandleEx(h, FileBasicInfo, &bi, sizeof bi)) {
        FILETIME ct;
        ct.dwLowDateTime = (DWORD)bi.ChangeTime.QuadPart;
        ct.dwHighDateTime = (DWORD)((uint64_t)bi.ChangeTime.QuadPart >> 32);
        o->ctime_ns = ft_ns(ct);
    }
    o->btime_ns = ft_ns(fi.ftCreationTime);
    o->attrs = fi.dwFileAttributes;
    return 0;
}

static int64_t stat_path(gssys_slice path, gssys_Stat *o, int follow) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    DWORD flags = FILE_FLAG_BACKUP_SEMANTICS | (follow ? 0 : FILE_FLAG_OPEN_REPARSE_POINT);
    HANDLE h = CreateFileW(w, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, flags, NULL);
    int64_t r;
    if (h == INVALID_HANDLE_VALUE) {
        /* A file that cannot be opened at all (the page file) still has
           attributes. */
        r = WERR();
        WIN32_FILE_ATTRIBUTE_DATA d;
        if (r == -(int64_t)ERROR_SHARING_VIOLATION && GetFileAttributesExW(w, GetFileExInfoStandard, &d)) {
            memset(o, 0, sizeof *o);
            o->kind = kind_of(d.dwFileAttributes, 0);
            o->mode = mode_of(d.dwFileAttributes);
            o->size = (int64_t)(((uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow);
            o->nlink = 1;
            o->uid = o->gid = -1;
            o->atime_ns = ft_ns(d.ftLastAccessTime);
            o->mtime_ns = o->ctime_ns = ft_ns(d.ftLastWriteTime);
            o->btime_ns = ft_ns(d.ftCreationTime);
            o->attrs = d.dwFileAttributes;
            r = 0;
        }
    } else {
        r = stat_handle(h, o);
        CloseHandle(h);
    }
    free(w);
    return r;
}

int64_t gssys_stat(gssys_slice path, gssys_Stat *out) { return stat_path(path, out, 1); }
int64_t gssys_lstat(gssys_slice path, gssys_Stat *out) { return stat_path(path, out, 0); }

/* Only the owner's write bit means anything: without it the file is
   read-only. */
int64_t gssys_chmod(gssys_slice path, int64_t mode) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    int64_t r;
    DWORD a = GetFileAttributesW(w);
    if (a == INVALID_FILE_ATTRIBUTES) {
        r = WERR();
    } else {
        DWORD na = (mode & 0200) ? (a & ~(DWORD)FILE_ATTRIBUTE_READONLY) : (a | FILE_ATTRIBUTE_READONLY);
        if (na == 0) na = FILE_ATTRIBUTE_NORMAL;
        r = na == a || SetFileAttributesW(w, na) ? 0 : WERR();
    }
    free(w);
    return r;
}

int64_t gssys_symlink(gssys_slice target, gssys_slice newpath) {
    wchar_t *t = wstr(target), *l = wstr(newpath);
    int64_t r = EARG;
    if (t && l) {
        for (wchar_t *p = t; *p; p++) if (*p == L'/') *p = L'\\';
        /* A link to a directory must say so: look at the target, from the
           link's directory when it is relative. */
        DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
        DWORD a = INVALID_FILE_ATTRIBUTES;
        int absolute = (t[0] && t[1] == L':') || t[0] == L'\\';
        if (absolute) {
            a = GetFileAttributesW(t);
        } else {
            size_t ln = wcslen(l), tn = wcslen(t);
            wchar_t *full = (wchar_t *)malloc(sizeof(wchar_t) * (ln + tn + 2));
            if (full) {
                wcscpy(full, l);
                wchar_t *slash = NULL;
                for (wchar_t *p = full; *p; p++) if (*p == L'\\' || *p == L'/') slash = p;
                if (slash) slash[1] = 0; else full[0] = 0;
                wcscat(full, t);
                a = GetFileAttributesW(full);
                free(full);
            }
        }
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;
        r = CreateSymbolicLinkW(l, t, flags) ? 0 : WERR();
        if (r == EARG) {
            /* Before Windows 10 1703 the unprivileged flag is unknown. */
            r = CreateSymbolicLinkW(l, t, flags & ~(DWORD)SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) ? 0 : WERR();
        }
    }
    free(t);
    free(l);
    return r;
}

/* REPARSE_DATA_BUFFER, which only the driver kit declares: a symbolic
   link has a ULONG of flags before its path buffer, a mount point none. */
typedef struct {
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    BYTE rest[1];
} gssys_reparse;

#define GSSYS_SYMLINK_FLAG_RELATIVE 1

int64_t gssys_readlink(gssys_slice path, gs_rref out) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    HANDLE h = CreateFileW(w, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return WERR();
    BYTE *buf = (BYTE *)malloc(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    if (!buf) { CloseHandle(h); return GSSYS_ENOMEM_CODE; }
    DWORD n;
    int64_t r;
    if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, buf, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &n, NULL)) {
        r = WERR();
        if (r == -(int64_t)ERROR_NOT_A_REPARSE_POINT) r = EARG;
    } else {
        gssys_reparse *rp = (gssys_reparse *)buf;
        const BYTE *pathbuf = NULL;
        int relative = 0;
        if (rp->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
            ULONG flags;
            memcpy(&flags, rp->rest, sizeof flags);
            relative = (flags & GSSYS_SYMLINK_FLAG_RELATIVE) != 0;
            pathbuf = rp->rest + sizeof(ULONG);
        } else if (rp->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
            pathbuf = rp->rest;
        }
        if (!pathbuf) {
            r = EARG;
        } else {
            /* The print name, as Go's os.Readlink gives it; else the
               substitute name (\??\C:\...) without its prefix. */
            const wchar_t *p = (const wchar_t *)(pathbuf + rp->PrintNameOffset);
            int len = rp->PrintNameLength / 2;
            if (len == 0) {
                p = (const wchar_t *)(pathbuf + rp->SubstituteNameOffset);
                len = rp->SubstituteNameLength / 2;
                if (!relative && len >= 4 && p[0] == L'\\' && p[1] == L'?' && p[2] == L'?' && p[3] == L'\\') { p += 4; len -= 4; }
            }
            r = put_w(out, p, len, 0);
        }
    }
    free(buf);
    CloseHandle(h);
    return r;
}

int64_t gssys_link(gssys_slice existing, gssys_slice newpath) {
    wchar_t *t = wstr(existing), *l = wstr(newpath);
    int64_t r = EARG;
    if (t && l) r = CreateHardLinkW(l, t, NULL) ? 0 : WERR();
    free(t);
    free(l);
    return r;
}

int64_t gssys_truncate(gssys_slice path, int64_t size) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    HANDLE h = CreateFileW(w, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return WERR();
    FILE_END_OF_FILE_INFO eof;
    eof.EndOfFile.QuadPart = size;
    int64_t r = SetFileInformationByHandle(h, FileEndOfFileInfo, &eof, sizeof eof) ? 0 : WERR();
    CloseHandle(h);
    return r;
}

int64_t gssys_utimes(gssys_slice path, int64_t atime_ns, int64_t mtime_ns) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    HANDLE h = CreateFileW(w, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return WERR();
    FILETIME a = ns_ft(atime_ns), m = ns_ft(mtime_ns);
    int64_t r = SetFileTime(h, NULL, &a, &m) ? 0 : WERR();
    CloseHandle(h);
    return r;
}

int64_t gssys_realpath(gssys_slice path, gs_rref out) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    HANDLE h = CreateFileW(w, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return WERR();
    wchar_t *buf = (wchar_t *)malloc(sizeof(wchar_t) * 32768);
    if (!buf) { CloseHandle(h); return GSSYS_ENOMEM_CODE; }
    DWORD n = GetFinalPathNameByHandleW(h, buf, 32768, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    int64_t r;
    if (!n || n >= 32768) {
        r = WERR();
    } else {
        const wchar_t *p = buf;
        /* \\?\C:\x as C:\x, and \\?\UNC\server\share as \\server\share. */
        if (n >= 8 && !wcsncmp(p, L"\\\\?\\UNC\\", 8)) {
            p += 6;
            buf[6] = L'\\';
        } else if (n >= 4 && !wcsncmp(p, L"\\\\?\\", 4)) {
            p += 4;
        }
        r = put_wraw(out, p);
    }
    free(buf);
    CloseHandle(h);
    return r;
}

int64_t gssys_mkdir(gssys_slice path, int64_t mode) {
    (void)mode;
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    int64_t r = CreateDirectoryW(w, NULL) ? 0 : WERR();
    free(w);
    return r;
}

int64_t gssys_rmdir(gssys_slice path) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    int64_t r = RemoveDirectoryW(w) ? 0 : WERR();
    free(w);
    return r;
}

int64_t gssys_unlink(gssys_slice path) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    int64_t r = DeleteFileW(w) ? 0 : WERR();
    if (r == -(int64_t)ERROR_ACCESS_DENIED) {
        /* A read-only file, which POSIX would remove. */
        DWORD a = GetFileAttributesW(w);
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_READONLY) && !(a & FILE_ATTRIBUTE_DIRECTORY) &&
            SetFileAttributesW(w, a & ~(DWORD)FILE_ATTRIBUTE_READONLY)) {
            r = DeleteFileW(w) ? 0 : WERR();
            if (r) SetFileAttributesW(w, a);
        }
    }
    free(w);
    return r;
}

int64_t gssys_rename(gssys_slice from, gssys_slice to) {
    wchar_t *f = wstr(from), *t = wstr(to);
    int64_t r = EARG;
    if (f && t) r = MoveFileExW(f, t, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : WERR();
    free(f);
    free(t);
    return r;
}

int64_t gssys_read_dir(gssys_slice path, gs_rref out) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    size_t n = wcslen(w);
    wchar_t *pat = (wchar_t *)malloc(sizeof(wchar_t) * (n + 3));
    if (!pat) { free(w); return GSSYS_ENOMEM_CODE; }
    wcscpy(pat, w);
    if (n && pat[n - 1] != L'\\' && pat[n - 1] != L'/') pat[n++] = L'\\';
    pat[n++] = L'*';
    pat[n] = 0;
    free(w);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileExW(pat, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
    free(pat);
    if (h == INVALID_HANDLE_VALUE) {
        int64_t e = WERR();
        return e == -(int64_t)ERROR_FILE_NOT_FOUND ? 0 : e;
    }
    int64_t count = 0;
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        put_wstr(out, fd.cFileName);
        put_i64(out, kind_of(fd.dwFileAttributes, fd.dwReserved0));
        count++;
    } while (FindNextFileW(h, &fd));
    DWORD e = GetLastError();
    FindClose(h);
    return e == ERROR_NO_MORE_FILES ? count : -(int64_t)e;
}

/* --- HANDLEs ------------------------------------------------------------------------------ */

static HANDLE H(int64_t fd) { return (HANDLE)(intptr_t)fd; }

int64_t gssys_open(gssys_slice path, int64_t flags, int64_t mode) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    DWORD access = (flags & GO_ACCESS) == GO_WRONLY ? GENERIC_WRITE
                 : (flags & GO_ACCESS) == GO_RDWR ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ;
    if (flags & GO_APPEND) access = (access & ~(DWORD)GENERIC_WRITE) | FILE_APPEND_DATA;
    DWORD disp;
    if ((flags & GO_CREATE) && (flags & GO_EXCL)) disp = CREATE_NEW;
    else if ((flags & GO_CREATE) && (flags & GO_TRUNC)) disp = CREATE_ALWAYS;
    else if (flags & GO_CREATE) disp = OPEN_ALWAYS;
    else if (flags & GO_TRUNC) disp = TRUNCATE_EXISTING;
    else disp = OPEN_EXISTING;
    DWORD attrs = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS;
    if ((flags & GO_CREATE) && !(mode & 0200)) attrs |= FILE_ATTRIBUTE_READONLY;
    if (flags & GO_SYNC) attrs |= FILE_FLAG_WRITE_THROUGH;
    HANDLE h = CreateFileW(w, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, disp, attrs, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return WERR();
    return (int64_t)(intptr_t)h;
}

int64_t gssys_close(int64_t fd) { return CloseHandle(H(fd)) ? 0 : WERR(); }

int64_t gssys_read(int64_t fd, gssys_buf buf) {
    DWORD n = 0, want = buf.len > 0x40000000 ? 0x40000000 : (DWORD)buf.len;
    if (!ReadFile(H(fd), buf.data, want, &n, NULL)) {
        DWORD e = GetLastError();
        return e == ERROR_BROKEN_PIPE || e == ERROR_HANDLE_EOF ? 0 : -(int64_t)e;
    }
    return n;
}

int64_t gssys_write(int64_t fd, gssys_slice data) {
    DWORD n = 0, want = data.len > 0x40000000 ? 0x40000000 : (DWORD)data.len;
    if (!WriteFile(H(fd), data.data, want, &n, NULL)) return WERR();
    return n;
}

int64_t gssys_pread(int64_t fd, gssys_buf buf, int64_t offset) {
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)offset;
    ov.OffsetHigh = (DWORD)((uint64_t)offset >> 32);
    DWORD n = 0, want = buf.len > 0x40000000 ? 0x40000000 : (DWORD)buf.len;
    if (!ReadFile(H(fd), buf.data, want, &n, &ov)) {
        DWORD e = GetLastError();
        return e == ERROR_HANDLE_EOF ? 0 : -(int64_t)e;
    }
    return n;
}

int64_t gssys_pwrite(int64_t fd, gssys_slice data, int64_t offset) {
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)offset;
    ov.OffsetHigh = (DWORD)((uint64_t)offset >> 32);
    DWORD n = 0, want = data.len > 0x40000000 ? 0x40000000 : (DWORD)data.len;
    if (!WriteFile(H(fd), data.data, want, &n, &ov)) return WERR();
    return n;
}

int64_t gssys_seek(int64_t fd, int64_t offset, int32_t whence) {
    LARGE_INTEGER d, r;
    d.QuadPart = offset;
    DWORD w = whence == 1 ? FILE_CURRENT : whence == 2 ? FILE_END : FILE_BEGIN;
    if (!SetFilePointerEx(H(fd), d, &r, w)) return WERR();
    return r.QuadPart;
}

int64_t gssys_fsync(int64_t fd) { return FlushFileBuffers(H(fd)) ? 0 : WERR(); }

int64_t gssys_ftruncate(int64_t fd, int64_t size) {
    FILE_END_OF_FILE_INFO eof;
    eof.EndOfFile.QuadPart = size;
    return SetFileInformationByHandle(H(fd), FileEndOfFileInfo, &eof, sizeof eof) ? 0 : WERR();
}

int64_t gssys_fstat(int64_t fd, gssys_Stat *out) { return stat_handle(H(fd), out); }

/* The whole file, as flock locks it. */
int64_t gssys_lock(int64_t fd, int32_t how) {
    OVERLAPPED ov;
    memset(&ov, 0, sizeof ov);
    int kind = how & 3;
    if (kind == LK_UNLOCK) return UnlockFileEx(H(fd), 0, MAXDWORD, MAXDWORD, &ov) ? 0 : WERR();
    if (kind != LK_SHARED && kind != LK_EXCLUSIVE) return EARG;
    DWORD flags = (kind == LK_EXCLUSIVE ? LOCKFILE_EXCLUSIVE_LOCK : 0) | ((how & LK_NONBLOCK) ? LOCKFILE_FAIL_IMMEDIATELY : 0);
    return LockFileEx(H(fd), flags, 0, MAXDWORD, MAXDWORD, &ov) ? 0 : WERR();
}

int64_t gssys_pipe(gssys_i64s fds) {
    if (fds.len < 2) return EARG;
    HANDLE r, w;
    if (!CreatePipe(&r, &w, NULL, 0)) return WERR();
    fds.data[0] = (int64_t)(intptr_t)r;
    fds.data[1] = (int64_t)(intptr_t)w;
    return 0;
}

int64_t gssys_std_fd(int32_t n) {
    DWORD which = n == 0 ? STD_INPUT_HANDLE : n == 1 ? STD_OUTPUT_HANDLE : n == 2 ? STD_ERROR_HANDLE : 0;
    if (!which) return EARG;
    HANDLE h = GetStdHandle(which);
    if (h == INVALID_HANDLE_VALUE) return WERR();
    if (!h) return -(int64_t)ERROR_INVALID_HANDLE;
    return (int64_t)(intptr_t)h;
}

int64_t gssys_isatty(int64_t fd) {
    DWORD mode;
    return GetFileType(H(fd)) == FILE_TYPE_CHAR && GetConsoleMode(H(fd), &mode) ? 1 : 0;
}


/* --- Another process's arguments ------------------------------------------------------ */

/* The command line split as the C runtime splits it (CommandLineToArgvW's
   rules): spaces separate words, "..." groups, 2n backslashes before a
   quote are n and the quote is special, 2n+1 are n and a literal quote. */
static int64_t put_argv(gs_rref out, const wchar_t *c, int n) {
    int64_t count = 0;
    wchar_t *w = (wchar_t *)malloc(sizeof(wchar_t) * ((size_t)n + 1));
    if (!w) return GSSYS_ENOMEM_CODE;
    int i = 0;
    /* The program's name: up to the next space, or quoted, no escapes. */
    while (i < n && (c[i] == L' ' || c[i] == L'\t')) i++;
    if (i < n) {
        int len = 0;
        if (c[i] == L'"') {
            i++;
            while (i < n && c[i] != L'"') w[len++] = c[i++];
            if (i < n) i++;
        } else {
            while (i < n && c[i] != L' ' && c[i] != L'\t') w[len++] = c[i++];
        }
        put_w(out, w, len, 1);
        count++;
    }
    for (;;) {
        while (i < n && (c[i] == L' ' || c[i] == L'\t')) i++;
        if (i >= n) break;
        int len = 0, quoted = 0;
        while (i < n && (quoted || (c[i] != L' ' && c[i] != L'\t'))) {
            if (c[i] == L'\\') {
                int bs = 0;
                while (i < n && c[i] == L'\\') { bs++; i++; }
                if (i < n && c[i] == L'"') {
                    for (int k = 0; k < bs / 2; k++) w[len++] = L'\\';
                    if (bs % 2) { w[len++] = L'"'; i++; }
                } else {
                    for (int k = 0; k < bs; k++) w[len++] = L'\\';
                }
            } else if (c[i] == L'"') {
                if (quoted && i + 1 < n && c[i + 1] == L'"') { w[len++] = L'"'; i += 2; }
                else { quoted = !quoted; i++; }
            } else {
                w[len++] = c[i++];
            }
        }
        put_w(out, w, len, 1);
        count++;
    }
    free(w);
    return count;
}

typedef LONG (WINAPI *nt_query_fn)(HANDLE, int, PVOID, ULONG, PULONG);
typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } gssys_ustring;

int64_t gssys_process_args(int64_t pid, gs_rref out) {
    if ((DWORD)pid == GetCurrentProcessId()) {
        const wchar_t *c = GetCommandLineW();
        return put_argv(out, c, (int)wcslen(c));
    }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    nt_query_fn q = ntdll ? (nt_query_fn)(void *)GetProcAddress(ntdll, "NtQueryInformationProcess") : NULL;
    if (!q) return -(int64_t)ERROR_NOT_SUPPORTED;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) {
        DWORD e = GetLastError();
        return -(int64_t)(e == ERROR_INVALID_PARAMETER ? ERROR_NOT_FOUND : e);
    }
    /* ProcessCommandLineInformation (60), Windows 8.1 on: a UNICODE_STRING
       and the text after it. */
    ULONG need = 0;
    q(h, 60, NULL, 0, &need);
    int64_t r;
    BYTE *buf = need ? (BYTE *)malloc(need) : NULL;
    if (!need) r = -(int64_t)ERROR_NOT_SUPPORTED;
    else if (!buf) r = GSSYS_ENOMEM_CODE;
    else if (q(h, 60, buf, need, &need) != 0) r = -(int64_t)ERROR_ACCESS_DENIED;
    else {
        gssys_ustring *u = (gssys_ustring *)buf;
        r = put_argv(out, u->Buffer, u->Length / 2);
    }
    free(buf);
    CloseHandle(h);
    return r;
}

/* --- Memory maps ------------------------------------------------------------------------ */

/* A view of a file's bytes [offset, offset + length) (fd < 0: of the page
   file, which is anonymous memory): the address. offset must be a
   multiple of the allocation granularity (64 KB). */
int64_t gssys_mmap(int64_t fd, int64_t offset, int64_t length, int32_t writable) {
    if (length <= 0 || offset < 0) return EARG;
    uint64_t end = (uint64_t)offset + (uint64_t)length;
    HANDLE file = fd < 0 ? INVALID_HANDLE_VALUE : H(fd);
    HANDLE m = CreateFileMappingW(file, NULL, writable ? PAGE_READWRITE : PAGE_READONLY,
                                  fd < 0 ? (DWORD)(end >> 32) : 0, fd < 0 ? (DWORD)end : 0, NULL);
    if (!m) return WERR();
    void *p = MapViewOfFile(m, writable ? FILE_MAP_WRITE : FILE_MAP_READ,
                            (DWORD)((uint64_t)offset >> 32), (DWORD)offset, (SIZE_T)length);
    int64_t r = p ? (int64_t)(intptr_t)p : WERR();
    CloseHandle(m);   /* the view keeps the mapping */
    return r;
}

int64_t gssys_munmap(int64_t addr, int64_t length) {
    (void)length;
    return UnmapViewOfFile((void *)(intptr_t)addr) ? 0 : WERR();
}

int64_t gssys_msync(int64_t addr, int64_t length) {
    return FlushViewOfFile((void *)(intptr_t)addr, (SIZE_T)length) ? 0 : WERR();
}

int64_t gssys_mem_read(int64_t addr, int64_t offset, gssys_buf buf) {
    if (!addr || offset < 0) return EARG;
    memcpy(buf.data, (const uint8_t *)(intptr_t)addr + offset, (size_t)buf.len);
    return buf.len;
}

int64_t gssys_mem_write(int64_t addr, int64_t offset, gssys_slice data) {
    if (!addr || offset < 0) return EARG;
    memcpy((uint8_t *)(intptr_t)addr + offset, data.data, (size_t)data.len);
    return data.len;
}

/* --- Consoles ------------------------------------------------------------------------------ */

int64_t gssys_term_size(int64_t fd, gssys_WinSize *out) {
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (!GetConsoleScreenBufferInfo(H(fd), &info)) return WERR();
    out->rows = info.srWindow.Bottom - info.srWindow.Top + 1;
    out->cols = info.srWindow.Right - info.srWindow.Left + 1;
    out->xpixels = out->ypixels = 0;
    return 0;
}

/* A console's state is its mode, 4 bytes. */
int64_t gssys_term_get_state(int64_t fd, gs_rref out) {
    DWORD mode;
    if (!GetConsoleMode(H(fd), &mode)) return WERR();
    put_raw(out, &mode, sizeof mode);
    return sizeof mode;
}

int64_t gssys_term_set_state(int64_t fd, gssys_slice state) {
    DWORD mode;
    if (state.len != (int64_t)sizeof mode) return EARG;
    memcpy(&mode, state.data, sizeof mode);
    return SetConsoleMode(H(fd), mode) ? 0 : WERR();
}

/* As x/term's MakeRaw on Windows: no echo, line input or Ctrl+C
   processing; virtual terminal input. */
int64_t gssys_term_make_raw(int64_t fd) {
    DWORD mode;
    if (!GetConsoleMode(H(fd), &mode)) return WERR();
    mode &= ~(DWORD)(ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_OUTPUT);
    mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
    return SetConsoleMode(H(fd), mode) ? 0 : WERR();
}

int64_t gssys_term_set_echo(int64_t fd, int32_t on) {
    DWORD mode;
    if (!GetConsoleMode(H(fd), &mode)) return WERR();
    if (on) mode |= ENABLE_ECHO_INPUT;
    else mode = (mode & ~(DWORD)ENABLE_ECHO_INPUT) | ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT;
    return SetConsoleMode(H(fd), mode) ? 0 : WERR();
}

#endif

int gssys_win_unit;
