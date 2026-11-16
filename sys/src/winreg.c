/* sys's Windows registry, as Go's x/sys/windows/registry has it: keys
   opened and created under a root, read and written by value type,
   enumerated and deleted. A key is its HKEY as an i64; a root is one of
   registry.goose's constants, which are the predefined HKEYs' values.
   Errors are negated Win32 codes (the Reg* functions return them).

   The one function every platform has here, expand_env, expands %VAR% on
   Windows and $VAR and ${VAR} elsewhere (as Go's os.ExpandEnv). */

#if defined(_WIN32)

#include "wcommon.h"

#define RERR(rc) (-(int64_t)(rc))

static HKEY K(int64_t k) { return (HKEY)(intptr_t)k; }

/* The predefined roots, which Goose passes as their low 32 bits. */
static HKEY root_of(int64_t r) {
    switch ((uint32_t)r) {
    case 0x80000000u: return HKEY_CLASSES_ROOT;
    case 0x80000001u: return HKEY_CURRENT_USER;
    case 0x80000002u: return HKEY_LOCAL_MACHINE;
    case 0x80000003u: return HKEY_USERS;
    case 0x80000004u: return HKEY_PERFORMANCE_DATA;
    case 0x80000005u: return HKEY_CURRENT_CONFIG;
    }
    return K(r);
}

int64_t gssys_reg_open(int64_t root, gssys_slice path, int64_t access) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    HKEY k;
    LSTATUS rc = RegOpenKeyExW(root_of(root), w, 0, (REGSAM)access, &k);
    free(w);
    return rc ? RERR(rc) : (int64_t)(intptr_t)k;
}

int64_t gssys_reg_create(int64_t root, gssys_slice path, int64_t access, gssys_i64s existed) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    HKEY k;
    DWORD disp = 0;
    LSTATUS rc = RegCreateKeyExW(root_of(root), w, 0, NULL, REG_OPTION_NON_VOLATILE, (REGSAM)access, NULL, &k, &disp);
    free(w);
    if (rc) return RERR(rc);
    if (existed.len > 0) existed.data[0] = disp == REG_OPENED_EXISTING_KEY;
    return (int64_t)(intptr_t)k;
}

int64_t gssys_reg_close(int64_t key) {
    LSTATUS rc = RegCloseKey(K(key));
    return rc ? RERR(rc) : 0;
}

/* access may hold KEY_WOW64_32KEY or KEY_WOW64_64KEY: the view to delete
   from. */
int64_t gssys_reg_delete_key(int64_t root, gssys_slice path, int64_t access) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    LSTATUS rc = RegDeleteKeyExW(root_of(root), w, (REGSAM)(access & (KEY_WOW64_32KEY | KEY_WOW64_64KEY)), 0);
    free(w);
    return rc ? RERR(rc) : 0;
}

int64_t gssys_reg_delete_tree(int64_t root, gssys_slice path) {
    wchar_t *w = wstr(path);
    if (!w) return EARG;
    LSTATUS rc = RegDeleteTreeW(root_of(root), w);
    if (rc == ERROR_SUCCESS) rc = RegDeleteKeyW(root_of(root), w);
    free(w);
    return rc && rc != ERROR_FILE_NOT_FOUND ? RERR(rc) : 0;
}

/* A value's type (REG_*), and its size in bytes in size[0]. */
int64_t gssys_reg_value_type(int64_t key, gssys_slice name, gssys_i64s size) {
    wchar_t *w = wstr(name);
    if (!w) return EARG;
    DWORD type = 0, n = 0;
    LSTATUS rc = RegQueryValueExW(K(key), w, NULL, &type, NULL, &n);
    free(w);
    if (rc) return RERR(rc);
    if (size.len > 0) size.data[0] = n;
    return type;
}

/* A value's type and bytes (malloc'd, with two NULs after them), or the
   error. */
static int64_t query(int64_t key, gssys_slice name, BYTE **data, DWORD *len) {
    wchar_t *w = wstr(name);
    if (!w) return EARG;
    DWORD type = 0, n = 0;
    LSTATUS rc;
    *data = NULL;
    for (;;) {
        rc = RegQueryValueExW(K(key), w, NULL, &type, NULL, &n);
        if (rc) break;
        BYTE *b = (BYTE *)malloc((size_t)n + 4);
        if (!b) { free(w); return GSSYS_ENOMEM_CODE; }
        DWORD got = n;
        rc = RegQueryValueExW(K(key), w, NULL, &type, b, &got);
        if (rc == ERROR_MORE_DATA) { free(b); continue; }   /* it grew */
        if (rc) { free(b); break; }
        memset(b + got, 0, 4);
        *data = b;
        *len = got;
        break;
    }
    free(w);
    return rc ? RERR(rc) : (int64_t)type;
}

/* A REG_SZ or REG_EXPAND_SZ as UTF-8 (not expanded): its type. */
int64_t gssys_reg_get_string(int64_t key, gssys_slice name, gs_rref out) {
    BYTE *b;
    DWORD n;
    int64_t t = query(key, name, &b, &n);
    if (t < 0) return t;
    if (t != REG_SZ && t != REG_EXPAND_SZ) { free(b); return -(int64_t)ERROR_UNSUPPORTED_TYPE; }
    int units = (int)(n / 2);
    const wchar_t *w = (const wchar_t *)b;
    while (units > 0 && w[units - 1] == 0) units--;
    put_w(out, w, units, 0);
    free(b);
    return t;
}

/* A REG_MULTI_SZ, each string a field: how many. */
int64_t gssys_reg_get_strings(int64_t key, gssys_slice name, gs_rref out) {
    BYTE *b;
    DWORD n;
    int64_t t = query(key, name, &b, &n);
    if (t < 0) return t;
    if (t != REG_MULTI_SZ) { free(b); return -(int64_t)ERROR_UNSUPPORTED_TYPE; }
    const wchar_t *w = (const wchar_t *)b, *end = w + n / 2;
    int64_t count = 0;
    /* Strings each ended by a NUL, the list by another; tolerate a missing
       last NUL. An empty string ends the list, as Go's GetStringsValue. */
    while (w < end && *w) {
        const wchar_t *s = w;
        while (w < end && *w) w++;
        put_w(out, s, (int)(w - s), 1);
        count++;
        w++;
    }
    free(b);
    return count;
}

/* A REG_DWORD (either byte order) or REG_QWORD in out[0]: its type. */
int64_t gssys_reg_get_int(int64_t key, gssys_slice name, gssys_i64s out) {
    BYTE *b;
    DWORD n;
    if (out.len < 1) return EARG;
    int64_t t = query(key, name, &b, &n);
    if (t < 0) return t;
    int64_t r = t;
    if (t == REG_DWORD && n == 4) {
        out.data[0] = (int64_t)((uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24);
    } else if (t == REG_DWORD_BIG_ENDIAN && n == 4) {
        out.data[0] = (int64_t)((uint32_t)b[3] | (uint32_t)b[2] << 8 | (uint32_t)b[1] << 16 | (uint32_t)b[0] << 24);
    } else if (t == REG_QWORD && n == 8) {
        uint64_t v = 0;
        for (int i = 7; i >= 0; i--) v = v << 8 | b[i];
        out.data[0] = (int64_t)v;
    } else {
        r = -(int64_t)ERROR_UNSUPPORTED_TYPE;
    }
    free(b);
    return r;
}

/* Any value's bytes as they are stored: its type. */
int64_t gssys_reg_get_binary(int64_t key, gssys_slice name, gs_rref out) {
    BYTE *b;
    DWORD n;
    int64_t t = query(key, name, &b, &n);
    if (t < 0) return t;
    put_raw(out, b, n);
    free(b);
    return t;
}

static int64_t set_value(int64_t key, gssys_slice name, DWORD type, const BYTE *data, DWORD n) {
    wchar_t *w = wstr(name);
    if (!w) return EARG;
    LSTATUS rc = RegSetValueExW(K(key), w, 0, type, data, n);
    free(w);
    return rc ? RERR(rc) : 0;
}

int64_t gssys_reg_set_string(int64_t key, gssys_slice name, gssys_slice value, int32_t vtype) {
    if (vtype != REG_SZ && vtype != REG_EXPAND_SZ) return EARG;
    wchar_t *v = wstr(value);
    if (!v) return EARG;
    int64_t r = set_value(key, name, (DWORD)vtype, (const BYTE *)v, (DWORD)((wcslen(v) + 1) * sizeof(wchar_t)));
    free(v);
    return r;
}

/* values: the strings, each followed by a NUL; none may be empty. */
int64_t gssys_reg_set_strings(int64_t key, gssys_slice name, gssys_slice values) {
    if (values.len > 0 && values.data[values.len - 1] != 0) return EARG;
    int units = values.len ? MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)values.data, (int)values.len, NULL, 0) : 0;
    if (values.len && units <= 0) return EARG;
    wchar_t *w = (wchar_t *)malloc(sizeof(wchar_t) * ((size_t)units + 1));
    if (!w) return GSSYS_ENOMEM_CODE;
    if (units) MultiByteToWideChar(CP_UTF8, 0, (const char *)values.data, (int)values.len, w, units);
    for (int i = 0; i + 1 < units; i++)
        if (w[i] == 0 && w[i + 1] == 0) { free(w); return EARG; }
    if (units && w[0] == 0) { free(w); return EARG; }
    w[units] = 0;   /* the list's own NUL */
    int64_t r = set_value(key, name, REG_MULTI_SZ, (const BYTE *)w, (DWORD)((units + 1) * sizeof(wchar_t)));
    free(w);
    return r;
}

int64_t gssys_reg_set_int(int64_t key, gssys_slice name, int64_t value, int32_t vtype) {
    BYTE b[8];
    uint64_t v = (uint64_t)value;
    for (int i = 0; i < 8; i++) b[i] = (BYTE)(v >> (8 * i));
    if (vtype == REG_DWORD) return set_value(key, name, REG_DWORD, b, 4);
    if (vtype == REG_QWORD) return set_value(key, name, REG_QWORD, b, 8);
    return EARG;
}

int64_t gssys_reg_set_binary(int64_t key, gssys_slice name, gssys_slice value) {
    return set_value(key, name, REG_BINARY, value.data, (DWORD)value.len);
}

int64_t gssys_reg_delete_value(int64_t key, gssys_slice name) {
    wchar_t *w = wstr(name);
    if (!w) return EARG;
    LSTATUS rc = RegDeleteValueW(K(key), w);
    free(w);
    return rc ? RERR(rc) : 0;
}

int64_t gssys_reg_subkeys(int64_t key, gs_rref out) {
    wchar_t name[256];
    int64_t n = 0;
    for (DWORD i = 0;; i++) {
        DWORD len = 256;
        LSTATUS rc = RegEnumKeyExW(K(key), i, name, &len, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc) return RERR(rc);
        put_w(out, name, (int)len, 1);
        n++;
    }
    return n;
}

int64_t gssys_reg_value_names(int64_t key, gs_rref out) {
    DWORD max = 0;
    LSTATUS rc = RegQueryInfoKeyW(K(key), NULL, NULL, NULL, NULL, NULL, NULL, NULL, &max, NULL, NULL, NULL);
    if (rc) return RERR(rc);
    wchar_t *name = (wchar_t *)malloc(sizeof(wchar_t) * ((size_t)max + 2));
    if (!name) return GSSYS_ENOMEM_CODE;
    int64_t n = 0;
    for (DWORD i = 0;; i++) {
        DWORD len = max + 1;
        rc = RegEnumValueW(K(key), i, name, &len, NULL, NULL, NULL, NULL);
        if (rc == ERROR_NO_MORE_ITEMS) { rc = 0; break; }
        if (rc) break;
        put_w(out, name, (int)len, 1);
        n++;
    }
    free(name);
    return rc ? RERR(rc) : n;
}

/* Go's KeyInfo: subkeys, the longest subkey name, values, the longest
   value name, the longest value, and when it was last written (ns since
   1970). */
int64_t gssys_reg_info(int64_t key, gssys_i64s out) {
    if (out.len < 6) return EARG;
    DWORD sub = 0, maxsub = 0, vals = 0, maxname = 0, maxval = 0;
    FILETIME ft;
    LSTATUS rc = RegQueryInfoKeyW(K(key), NULL, NULL, NULL, &sub, &maxsub, NULL, &vals, &maxname, &maxval, NULL, &ft);
    if (rc) return RERR(rc);
    int64_t t = (int64_t)(((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime);
    out.data[0] = sub;
    out.data[1] = maxsub;
    out.data[2] = vals;
    out.data[3] = maxname;
    out.data[4] = maxval;
    out.data[5] = (t - 116444736000000000LL) * 100;
    return 0;
}

int64_t gssys_expand_env(gssys_slice s, gs_rref out) {
    wchar_t *w = wstr(s);
    if (!w) return EARG;
    DWORD n = ExpandEnvironmentStringsW(w, NULL, 0);
    wchar_t *e = n ? (wchar_t *)malloc(sizeof(wchar_t) * n) : NULL;
    int64_t r;
    if (!n) r = WERR();
    else if (!e) r = GSSYS_ENOMEM_CODE;
    else if (!ExpandEnvironmentStringsW(w, e, n)) r = WERR();
    else r = put_wraw(out, e);
    free(e);
    free(w);
    return r;
}

#endif

int gssys_winreg_unit;
