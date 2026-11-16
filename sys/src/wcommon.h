/* sys on Windows: what win.c and winreg.c share: the headers, errors as
   negated Win32 codes, and UTF-8 to UTF-16 and back. */

#ifndef GSSYS_WCOMMON_H
#define GSSYS_WCOMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <winioctl.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <lm.h>
#include <stdio.h>
#include <wchar.h>
#include "common.h"

#define WERR() (-(int64_t)GetLastError())
#define EARG (-(int64_t)ERROR_INVALID_PARAMETER)

/* --- UTF-8 and UTF-16 ------------------------------------------------------------- */

/* A NUL-terminated UTF-16 copy of a UTF-8 slice (malloc'd), or NULL. */
static inline wchar_t *wstr(gssys_slice s) {
    if (s.len < 0 || (s.len > 0 && memchr(s.data, 0, (size_t)s.len))) return NULL;
    int n = s.len ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)s.data, (int)s.len, NULL, 0) : 0;
    if (s.len && n <= 0) return NULL;
    wchar_t *w = (wchar_t *)malloc(sizeof(wchar_t) * ((size_t)n + 1));
    if (!w) return NULL;
    if (n) MultiByteToWideChar(CP_UTF8, 0, (const char *)s.data, (int)s.len, w, n);
    w[n] = 0;
    return w;
}

/* The UTF-8 of n UTF-16 units (n < 0: up to the NUL), appended to out as
   raw bytes or as a field: the number of bytes. */
static inline int64_t put_w(gs_rref out, const wchar_t *w, int n, int as_field) {
    if (!w) w = L"";
    if (n < 0) n = (int)wcslen(w);
    int len = n ? WideCharToMultiByte(CP_UTF8, 0, w, n, NULL, 0, NULL, NULL) : 0;
    char small[512];
    char *b = len <= (int)sizeof small ? small : (char *)malloc((size_t)len);
    if (!b) return GSSYS_ENOMEM_CODE;
    if (len) WideCharToMultiByte(CP_UTF8, 0, w, n, b, len, NULL, NULL);
    if (as_field) put_field(out, b, len); else put_raw(out, b, len);
    if (b != small) free(b);
    return len;
}

static inline int64_t put_wraw(gs_rref out, const wchar_t *w) { return put_w(out, w, -1, 0); }
static inline void put_wstr(gs_rref out, const wchar_t *w) { put_w(out, w, -1, 1); }

#endif
