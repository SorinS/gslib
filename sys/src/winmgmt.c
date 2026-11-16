/* sys's Windows management, as iamacarpet/go-win64api has it: local user
   accounts and groups (the NetUser and NetLocalGroup functions), sessions
   (Remote Desktop Services), services and their configuration, shares,
   and a process's owner and memory. Installed software is read from the
   registry in windows.goose. Errors are negated Win32 or NERR_ codes.

   Lists come back as fields, a fixed number per entry, in the order each
   function's comment gives. */

#if defined(_WIN32)

#include "wcommon.h"
#include <wtsapi32.h>
#include <psapi.h>

#define NERR(st) (-(int64_t)(st))

/* --- Local users -------------------------------------------------------------------- */

/* Each account: name, full name, comment, flags (UF_*), privilege
   (USER_PRIV_*), last logon (seconds since 1970, 0 if never), bad
   password count, logons, password age (seconds), home directory. */
int64_t gssys_net_users(gs_rref out) {
    DWORD resume = 0;
    int64_t n = 0;
    NET_API_STATUS st;
    do {
        USER_INFO_3 *buf = NULL;
        DWORD read = 0, total = 0;
        st = NetUserEnum(NULL, 3, FILTER_NORMAL_ACCOUNT, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (st != NERR_Success && st != ERROR_MORE_DATA) return NERR(st);
        for (DWORD i = 0; i < read; i++) {
            USER_INFO_3 *u = &buf[i];
            put_wstr(out, u->usri3_name);
            put_wstr(out, u->usri3_full_name);
            put_wstr(out, u->usri3_comment);
            put_i64(out, u->usri3_flags);
            put_i64(out, u->usri3_priv);
            put_i64(out, u->usri3_last_logon);
            put_i64(out, u->usri3_bad_pw_count);
            put_i64(out, u->usri3_num_logons);
            put_i64(out, u->usri3_password_age);
            put_wstr(out, u->usri3_home_dir);
            n++;
        }
        if (buf) NetApiBufferFree(buf);
    } while (st == ERROR_MORE_DATA);
    return n;
}

int64_t gssys_net_user_add(gssys_slice name, gssys_slice password, gssys_slice full_name, gssys_slice comment, int64_t flags) {
    wchar_t *n = wstr(name), *p = wstr(password), *c = wstr(comment), *f = wstr(full_name);
    int64_t r = EARG;
    if (n && p && c && f && *n) {
        USER_INFO_1 ui;
        memset(&ui, 0, sizeof ui);
        ui.usri1_name = n;
        ui.usri1_password = p;
        ui.usri1_priv = USER_PRIV_USER;
        ui.usri1_comment = c;
        ui.usri1_flags = (DWORD)flags | UF_SCRIPT;
        DWORD bad = 0;
        NET_API_STATUS st = NetUserAdd(NULL, 1, (LPBYTE)&ui, &bad);
        r = st == NERR_Success ? 0 : NERR(st);
        if (r == 0 && *f) {
            USER_INFO_1011 fi;
            fi.usri1011_full_name = f;
            NetUserSetInfo(NULL, n, 1011, (LPBYTE)&fi, NULL);
        }
    }
    if (p) SecureZeroMemory(p, wcslen(p) * sizeof(wchar_t));
    free(n); free(p); free(c); free(f);
    return r;
}

int64_t gssys_net_user_delete(gssys_slice name) {
    wchar_t *n = wstr(name);
    if (!n) return EARG;
    NET_API_STATUS st = NetUserDel(NULL, n);
    free(n);
    return st == NERR_Success ? 0 : NERR(st);
}

int64_t gssys_net_user_set_password(gssys_slice name, gssys_slice password) {
    wchar_t *n = wstr(name), *p = wstr(password);
    int64_t r = EARG;
    if (n && p) {
        USER_INFO_1003 pi;
        pi.usri1003_password = p;
        NET_API_STATUS st = NetUserSetInfo(NULL, n, 1003, (LPBYTE)&pi, NULL);
        r = st == NERR_Success ? 0 : NERR(st);
    }
    if (p) SecureZeroMemory(p, wcslen(p) * sizeof(wchar_t));
    free(n); free(p);
    return r;
}

/* The account's flags with set added and clear taken away (UF_ACCOUNTDISABLE
   to disable it, UF_DONT_EXPIRE_PASSWD, UF_LOCKOUT to clear a lockout). */
int64_t gssys_net_user_set_flags(gssys_slice name, int64_t set, int64_t clear) {
    wchar_t *n = wstr(name);
    if (!n) return EARG;
    USER_INFO_1 *ui = NULL;
    NET_API_STATUS st = NetUserGetInfo(NULL, n, 1, (LPBYTE *)&ui);
    if (st == NERR_Success) {
        USER_INFO_1008 fi;
        fi.usri1008_flags = (ui->usri1_flags | (DWORD)set) & ~(DWORD)clear;
        NetApiBufferFree(ui);
        st = NetUserSetInfo(NULL, n, 1008, (LPBYTE)&fi, NULL);
    }
    free(n);
    return st == NERR_Success ? 0 : NERR(st);
}

int64_t gssys_net_user_set_full_name(gssys_slice name, gssys_slice full_name) {
    wchar_t *n = wstr(name), *f = wstr(full_name);
    int64_t r = EARG;
    if (n && f) {
        USER_INFO_1011 fi;
        fi.usri1011_full_name = f;
        NET_API_STATUS st = NetUserSetInfo(NULL, n, 1011, (LPBYTE)&fi, NULL);
        r = st == NERR_Success ? 0 : NERR(st);
    }
    free(n); free(f);
    return r;
}

/* --- Local groups ----------------------------------------------------------------------- */

/* Each local group: name, comment. */
int64_t gssys_net_groups(gs_rref out) {
    DWORD_PTR resume = 0;
    int64_t n = 0;
    NET_API_STATUS st;
    do {
        LOCALGROUP_INFO_1 *buf = NULL;
        DWORD read = 0, total = 0;
        st = NetLocalGroupEnum(NULL, 1, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (st != NERR_Success && st != ERROR_MORE_DATA) return NERR(st);
        for (DWORD i = 0; i < read; i++) {
            put_wstr(out, buf[i].lgrpi1_name);
            put_wstr(out, buf[i].lgrpi1_comment);
            n++;
        }
        if (buf) NetApiBufferFree(buf);
    } while (st == ERROR_MORE_DATA);
    return n;
}

int64_t gssys_net_group_add(gssys_slice name, gssys_slice comment) {
    wchar_t *n = wstr(name), *c = wstr(comment);
    int64_t r = EARG;
    if (n && c && *n) {
        LOCALGROUP_INFO_1 gi;
        gi.lgrpi1_name = n;
        gi.lgrpi1_comment = c;
        NET_API_STATUS st = NetLocalGroupAdd(NULL, 1, (LPBYTE)&gi, NULL);
        r = st == NERR_Success ? 0 : NERR(st);
    }
    free(n); free(c);
    return r;
}

int64_t gssys_net_group_delete(gssys_slice name) {
    wchar_t *n = wstr(name);
    if (!n) return EARG;
    NET_API_STATUS st = NetLocalGroupDel(NULL, n);
    free(n);
    return st == NERR_Success ? 0 : NERR(st);
}

/* Each member: DOMAIN\name, its SID, and what it is (SidTypeUser 1,
   SidTypeGroup 2, SidTypeWellKnownGroup 5, ...). */
int64_t gssys_net_group_members(gssys_slice name, gs_rref out) {
    wchar_t *g = wstr(name);
    if (!g) return EARG;
    DWORD_PTR resume = 0;
    int64_t n = 0;
    NET_API_STATUS st;
    do {
        LOCALGROUP_MEMBERS_INFO_2 *buf = NULL;
        DWORD read = 0, total = 0;
        st = NetLocalGroupGetMembers(NULL, g, 2, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (st != NERR_Success && st != ERROR_MORE_DATA) { free(g); return NERR(st); }
        for (DWORD i = 0; i < read; i++) {
            put_wstr(out, buf[i].lgrmi2_domainandname);
            wchar_t *s = NULL;
            if (ConvertSidToStringSidW(buf[i].lgrmi2_sid, &s)) { put_wstr(out, s); LocalFree(s); }
            else put_str(out, "");
            put_i64(out, buf[i].lgrmi2_sidusage);
            n++;
        }
        if (buf) NetApiBufferFree(buf);
    } while (st == ERROR_MORE_DATA);
    free(g);
    return n;
}

static int64_t group_member(gssys_slice group, gssys_slice member, int add) {
    wchar_t *g = wstr(group), *m = wstr(member);
    int64_t r = EARG;
    if (g && m && *m) {
        LOCALGROUP_MEMBERS_INFO_3 mi;
        mi.lgrmi3_domainandname = m;
        NET_API_STATUS st = add ? NetLocalGroupAddMembers(NULL, g, 3, (LPBYTE)&mi, 1)
                                : NetLocalGroupDelMembers(NULL, g, 3, (LPBYTE)&mi, 1);
        r = st == NERR_Success ? 0 : NERR(st);
    }
    free(g); free(m);
    return r;
}

int64_t gssys_net_group_add_member(gssys_slice group, gssys_slice member) { return group_member(group, member, 1); }
int64_t gssys_net_group_remove_member(gssys_slice group, gssys_slice member) { return group_member(group, member, 0); }

/* --- Sessions ----------------------------------------------------------------------------- */

static void put_wts_string(gs_rref out, DWORD id, WTS_INFO_CLASS cls) {
    LPWSTR s = NULL;
    DWORD bytes = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, cls, &s, &bytes) && s) {
        put_wstr(out, s);
        WTSFreeMemory(s);
    } else {
        put_str(out, "");
    }
}

/* Each session: its id, state (WTS_CONNECTSTATE_CLASS: 0 active, 1
   connected, 4 disconnected, 6 listening, ...), window station, user,
   domain, client name, logon time (seconds since 1970, 0 unknown). */
int64_t gssys_sessions(gs_rref out) {
    WTS_SESSION_INFOW *s = NULL;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &s, &count)) return WERR();
    for (DWORD i = 0; i < count; i++) {
        put_i64(out, s[i].SessionId);
        put_i64(out, s[i].State);
        put_wstr(out, s[i].pWinStationName);
        put_wts_string(out, s[i].SessionId, WTSUserName);
        put_wts_string(out, s[i].SessionId, WTSDomainName);
        put_wts_string(out, s[i].SessionId, WTSClientName);
        int64_t logon = 0;
        WTSINFOW *info = NULL;
        DWORD bytes = 0;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, s[i].SessionId, WTSSessionInfo, (LPWSTR *)&info, &bytes) && info) {
            if (info->LogonTime.QuadPart) logon = (info->LogonTime.QuadPart - 116444736000000000LL) / 10000000;
            WTSFreeMemory(info);
        }
        put_i64(out, logon);
    }
    WTSFreeMemory(s);
    return count;
}

/* --- Services ----------------------------------------------------------------------------- */

/* Each Win32 service: name, display name, type (SERVICE_WIN32_*), state
   (SERVICE_STOPPED 1 ... SERVICE_PAUSED 7), process id, start type
   (SERVICE_AUTO_START 2, DEMAND 3, DISABLED 4, ...), binary path,
   account; the last three empty or -1 when its configuration cannot be
   read. */
int64_t gssys_services(gs_rref out) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (!scm) return WERR();
    DWORD need = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &need, &count, &resume, NULL);
    if (GetLastError() != ERROR_MORE_DATA) { int64_t e = WERR(); CloseServiceHandle(scm); return e; }
    int64_t n = 0;
    resume = 0;
    BYTE *buf = NULL;
    for (;;) {
        need += 4096;
        free(buf);
        buf = (BYTE *)malloc(need);
        if (!buf) { CloseServiceHandle(scm); return GSSYS_ENOMEM_CODE; }
        BOOL ok = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buf, need, &need, &count, &resume, NULL);
        DWORD err = ok ? 0 : GetLastError();
        if (!ok && err != ERROR_MORE_DATA) { free(buf); CloseServiceHandle(scm); return -(int64_t)err; }
        ENUM_SERVICE_STATUS_PROCESSW *e = (ENUM_SERVICE_STATUS_PROCESSW *)buf;
        for (DWORD i = 0; i < count; i++) {
            put_wstr(out, e[i].lpServiceName);
            put_wstr(out, e[i].lpDisplayName);
            put_i64(out, e[i].ServiceStatusProcess.dwServiceType);
            put_i64(out, e[i].ServiceStatusProcess.dwCurrentState);
            put_i64(out, e[i].ServiceStatusProcess.dwProcessId);
            int done = 0;
            SC_HANDLE svc = OpenServiceW(scm, e[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (svc) {
                DWORD cn = 0;
                QueryServiceConfigW(svc, NULL, 0, &cn);
                QUERY_SERVICE_CONFIGW *cfg = cn ? (QUERY_SERVICE_CONFIGW *)malloc(cn) : NULL;
                if (cfg && QueryServiceConfigW(svc, cfg, cn, &cn)) {
                    put_i64(out, cfg->dwStartType);
                    put_wstr(out, cfg->lpBinaryPathName);
                    put_wstr(out, cfg->lpServiceStartName);
                    done = 1;
                }
                free(cfg);
                CloseServiceHandle(svc);
            }
            if (!done) { put_i64(out, -1); put_str(out, ""); put_str(out, ""); }
            n++;
        }
        if (ok) break;
    }
    free(buf);
    CloseServiceHandle(scm);
    return n;
}

/* --- Shares ---------------------------------------------------------------------------------- */

/* Each share: name, type (STYPE_*: 0 disk, 1 printer, 3 IPC, with
   STYPE_SPECIAL 0x80000000 for an administrative one), remark, path, the
   most users it takes (-1 unlimited), how many it has. The path and the
   counts need an administrator (level 2); otherwise they are "" and -1. */
int64_t gssys_shares(gs_rref out) {
    DWORD resume = 0;
    int64_t n = 0;
    NET_API_STATUS st;
    int level = 2;
    do {
        BYTE *buf = NULL;
        DWORD read = 0, total = 0;
        st = NetShareEnum(NULL, level, &buf, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (st == ERROR_ACCESS_DENIED && level == 2 && n == 0) { level = 1; st = ERROR_MORE_DATA; resume = 0; continue; }
        if (st != NERR_Success && st != ERROR_MORE_DATA) return NERR(st);
        for (DWORD i = 0; i < read; i++) {
            if (level == 2) {
                SHARE_INFO_2 *s = &((SHARE_INFO_2 *)buf)[i];
                put_wstr(out, s->shi2_netname);
                put_i64(out, s->shi2_type);
                put_wstr(out, s->shi2_remark);
                put_wstr(out, s->shi2_path);
                put_i64(out, s->shi2_max_uses == (DWORD)-1 ? -1 : (int64_t)s->shi2_max_uses);
                put_i64(out, s->shi2_current_uses);
            } else {
                SHARE_INFO_1 *s = &((SHARE_INFO_1 *)buf)[i];
                put_wstr(out, s->shi1_netname);
                put_i64(out, s->shi1_type);
                put_wstr(out, s->shi1_remark);
                put_str(out, "");
                put_i64(out, -1);
                put_i64(out, -1);
            }
            n++;
        }
        if (buf) NetApiBufferFree(buf);
    } while (st == ERROR_MORE_DATA);
    return n;
}

int64_t gssys_share_add(gssys_slice name, gssys_slice path, gssys_slice remark) {
    wchar_t *n = wstr(name), *p = wstr(path), *r = wstr(remark);
    int64_t res = EARG;
    if (n && p && r && *n && *p) {
        SHARE_INFO_2 si;
        memset(&si, 0, sizeof si);
        si.shi2_netname = n;
        si.shi2_type = STYPE_DISKTREE;
        si.shi2_remark = r;
        si.shi2_permissions = 0;
        si.shi2_max_uses = (DWORD)-1;
        si.shi2_path = p;
        DWORD bad = 0;
        NET_API_STATUS st = NetShareAdd(NULL, 2, (LPBYTE)&si, &bad);
        res = st == NERR_Success ? 0 : NERR(st);
    }
    free(n); free(p); free(r);
    return res;
}

int64_t gssys_share_delete(gssys_slice name) {
    wchar_t *n = wstr(name);
    if (!n) return EARG;
    NET_API_STATUS st = NetShareDel(NULL, n, 0);
    free(n);
    return st == NERR_Success ? 0 : NERR(st);
}

/* --- A process's owner and memory --------------------------------------------------------------- */

int64_t gssys_process_owner(int64_t pid, gs_rref out) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) {
        DWORD e = GetLastError();
        return -(int64_t)(e == ERROR_INVALID_PARAMETER ? ERROR_NOT_FOUND : e);
    }
    HANDLE tok;
    int64_t r;
    if (!OpenProcessToken(h, TOKEN_QUERY, &tok)) {
        r = WERR();
    } else {
        BYTE ub[512];
        DWORD n;
        if (!GetTokenInformation(tok, TokenUser, ub, sizeof ub, &n)) {
            r = WERR();
        } else {
            wchar_t name[256], domain[256], full[600];
            DWORD nn = 256, dn = 256;
            SID_NAME_USE use;
            if (!LookupAccountSidW(NULL, ((TOKEN_USER *)ub)->User.Sid, name, &nn, domain, &dn, &use)) {
                r = WERR();
            } else {
                lstrcpyW(full, domain);
                if (domain[0]) lstrcatW(full, L"\\");
                lstrcatW(full, name);
                r = put_wraw(out, full);
            }
        }
        CloseHandle(tok);
    }
    CloseHandle(h);
    return r;
}

/* The working set, its peak, the page file use (commit) and its peak, in
   bytes. */
int64_t gssys_process_memory(int64_t pid, gssys_i64s out) {
    if (out.len < 4) return EARG;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) {
        DWORD e = GetLastError();
        return -(int64_t)(e == ERROR_INVALID_PARAMETER ? ERROR_NOT_FOUND : e);
    }
    PROCESS_MEMORY_COUNTERS pmc;
    pmc.cb = sizeof pmc;
    int64_t r = K32GetProcessMemoryInfo(h, &pmc, sizeof pmc) ? 0 : WERR();
    if (r == 0) {
        out.data[0] = (int64_t)pmc.WorkingSetSize;
        out.data[1] = (int64_t)pmc.PeakWorkingSetSize;
        out.data[2] = (int64_t)pmc.PagefileUsage;
        out.data[3] = (int64_t)pmc.PeakPagefileUsage;
    }
    CloseHandle(h);
    return r;
}

#endif

int gssys_winmgmt_unit;
