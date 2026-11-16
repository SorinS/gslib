/* sspi: the native half of sspi.goose, Windows' Security Support Provider
   Interface (secur32): credentials, security contexts (Negotiate, NTLM,
   Kerberos, Schannel's TLS), and the messages they protect.

   SSPI's handles stay here, in two tables; Goose sees an id (the slot
   plus one). A context also keeps the bytes it has been given and not yet
   used: a TLS record split over two reads, the extra bytes after a
   handshake message, decrypted data not yet taken. So Goose only moves
   bytes between the socket and these functions.

   The functions are looked up in secur32.dll and crypt32.dll at their
   first use, and the structures SSPI takes are declared here rather than
   taken from <sspi.h> and <schannel.h>: every C compiler goose drives
   (TinyCC under goose run among them) has <windows.h>, not all have
   those, and nothing needs linking.

   Every function is defined on every platform (gslib's JIT library
   resolves every extern of the package's modules); elsewhere they return
   SEC_E_UNSUPPORTED_FUNCTION. Results are SSPI's own status codes, as
   int32 values widened: 0 is SEC_E_OK, SEC_I_* are positive, SEC_E_* are
   negative. Ids, lengths and counts are >= 0. Strings arrive as Goose
   slices, { data, len }, UTF-8, not NUL-terminated. */

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } gsspi_slice;
typedef struct { uint8_t *data; int64_t len; } gsspi_buf;

#define S_OK_               0
#define S_CONTINUE_NEEDED   0x00090312
#define S_COMPLETE_NEEDED   0x00090313
#define S_COMPLETE_CONTINUE 0x00090314
#define S_CONTEXT_EXPIRED   0x00090317
#define S_RENEGOTIATE       0x00090321
#define E_INVALID_HANDLE    ((int32_t)0x80090301)
#define E_UNSUPPORTED       ((int32_t)0x80090302)
#define E_INTERNAL          ((int32_t)0x80090304)
#define E_INCOMPLETE        ((int32_t)0x80090318)
#define E_BUFFER_TOO_SMALL  ((int32_t)0x80090321)
#define E_INVALID_PARAMETER ((int32_t)0x8009035D)
#define E_NO_MEMORY         ((int32_t)0x80090300)

/* Not SSPI's: the end of a TLS stream (close_notify), and a peer's
   renegotiation, which is refused. */
#define GSSPI_END           (-100)
#define GSSPI_RENEGOTIATE   (-101)

/* What the platform is: sspi::platform(). */
int32_t gsspi_platform(void) {
#if defined(_WIN32)
    return 1;
#else
    return 0;
#endif
}

#if defined(_WIN32)

/* --- SSPI's declarations (sspi.h, schannel.h, wincrypt.h) ---------------- */

typedef struct { ULONG_PTR lower, upper; } gs_handle;
typedef struct { ULONG cb; ULONG type; void *pv; } gs_secbuf;
typedef struct { ULONG version; ULONG count; gs_secbuf *bufs; } gs_secdesc;
typedef struct {
    ULONG caps; USHORT version; USHORT rpcid; ULONG max_token;
    wchar_t *name; wchar_t *comment;
} gs_pkginfo;
typedef struct {
    USHORT *user; ULONG user_len; USHORT *domain; ULONG domain_len;
    USHORT *password; ULONG password_len; ULONG flags;
} gs_identity;
typedef struct {
    DWORD version, ncreds; void **creds; void *root_store; DWORD nmappers; void **mappers;
    DWORD nalgs; DWORD *algs; DWORD enabled_protocols, min_strength, max_strength,
    session_lifespan, flags, cred_format;
} gs_schannel_cred;                     /* SCHANNEL_CRED, version 4 */
typedef struct {
    DWORD nalpn; void *alpn; DWORD disabled_protocols; DWORD ndisabled_crypto;
    void *disabled_crypto; DWORD flags;
} gs_tls_parameters;
typedef struct {
    DWORD version, cred_format, ncreds; void **creds; void *root_store; DWORD nmappers;
    void **mappers; DWORD session_lifespan, flags, nparams; gs_tls_parameters *params;
} gs_sch_credentials;                   /* SCH_CREDENTIALS, version 5 */
typedef struct { ULONG header, trailer, max_message, buffers, block; } gs_stream_sizes;
typedef struct { ULONG max_token, max_signature, block, trailer; } gs_sizes;
typedef struct { DWORD protocol, cipher, cipher_strength, hash, hash_strength, exch, exch_strength; } gs_conn_info;
typedef struct {
    DWORD version, protocol, suite, base_suite;
    WCHAR suite_name[64], cipher[64]; DWORD cipher_len, cipher_block;
    WCHAR hash[64]; DWORD hash_len; WCHAR exchange[64]; DWORD min_exch, max_exch;
    WCHAR certificate[64]; DWORD key_type;
} gs_cipher_info;
typedef struct { DWORD encoding; BYTE *encoded; DWORD size; void *info; void *store; } gs_cert_context;

#define CRED_INBOUND   1
#define CRED_OUTBOUND  2
#define NATIVE_DREP    0x10
#define B_EMPTY        0
#define B_DATA         1
#define B_TOKEN        2
#define B_EXTRA        5
#define B_TRAILER      6
#define B_HEADER       7
#define B_PADDING      9
#define B_STREAM       10
#define B_ALERT        17
#define ISC_ALLOCATE   0x100
#define ATTR_SIZES     0
#define ATTR_NAMES     1
#define ATTR_STREAM    4
#define ATTR_PACKAGE   10
#define ATTR_NEGOTIATION 12
#define ATTR_REMOTE_CERT 0x53
#define ATTR_CONN_INFO 0x5a
#define ATTR_CIPHER_INFO 0x64
#define SCH_CLIENT_PROTOCOLS (0x20 | 0x80 | 0x200 | 0x800 | 0x2000)   /* SSL3, TLS 1.0 to 1.3, client */
#define SCHANNEL_SHUTDOWN 1

typedef LONG (WINAPI *fn_enum)(ULONG *, gs_pkginfo **);
typedef LONG (WINAPI *fn_query_pkg)(wchar_t *, gs_pkginfo **);
typedef LONG (WINAPI *fn_acquire)(wchar_t *, wchar_t *, ULONG, void *, void *, void *, void *, gs_handle *, LARGE_INTEGER *);
typedef LONG (WINAPI *fn_free_cred)(gs_handle *);
typedef LONG (WINAPI *fn_init)(gs_handle *, gs_handle *, wchar_t *, ULONG, ULONG, ULONG, gs_secdesc *, ULONG, gs_handle *, gs_secdesc *, ULONG *, LARGE_INTEGER *);
typedef LONG (WINAPI *fn_accept)(gs_handle *, gs_handle *, gs_secdesc *, ULONG, ULONG, gs_handle *, gs_secdesc *, ULONG *, LARGE_INTEGER *);
typedef LONG (WINAPI *fn_complete)(gs_handle *, gs_secdesc *);
typedef LONG (WINAPI *fn_delete)(gs_handle *);
typedef LONG (WINAPI *fn_control)(gs_handle *, gs_secdesc *);
typedef LONG (WINAPI *fn_query_ctx)(gs_handle *, ULONG, void *);
typedef LONG (WINAPI *fn_free_buf)(void *);
typedef LONG (WINAPI *fn_crypt)(gs_handle *, ULONG, gs_secdesc *, ULONG);
typedef LONG (WINAPI *fn_decrypt)(gs_handle *, gs_secdesc *, ULONG, ULONG *);
typedef BOOL (WINAPI *fn_free_cert)(const void *);

static struct {
    int state;                          /* 0 not tried, 1 loaded, -1 missing */
    fn_enum enum_packages;
    fn_query_pkg query_package;
    fn_acquire acquire;
    fn_free_cred free_cred;
    fn_init init;
    fn_accept accept;
    fn_complete complete;
    fn_delete delete_ctx;
    fn_control control;
    fn_query_ctx query;
    fn_free_buf free_buf;
    fn_crypt encrypt, sign;
    fn_decrypt decrypt, verify;
    fn_free_cert free_cert;
} api;

static int gsspi_load(void) {
    if (api.state) return api.state > 0;
    HMODULE s = LoadLibraryW(L"secur32.dll");
    HMODULE c = LoadLibraryW(L"crypt32.dll");
    if (!s || !c) { api.state = -1; return 0; }
    api.enum_packages = (fn_enum)(void *)GetProcAddress(s, "EnumerateSecurityPackagesW");
    api.query_package = (fn_query_pkg)(void *)GetProcAddress(s, "QuerySecurityPackageInfoW");
    api.acquire = (fn_acquire)(void *)GetProcAddress(s, "AcquireCredentialsHandleW");
    api.free_cred = (fn_free_cred)(void *)GetProcAddress(s, "FreeCredentialsHandle");
    api.init = (fn_init)(void *)GetProcAddress(s, "InitializeSecurityContextW");
    api.accept = (fn_accept)(void *)GetProcAddress(s, "AcceptSecurityContext");
    api.complete = (fn_complete)(void *)GetProcAddress(s, "CompleteAuthToken");
    api.delete_ctx = (fn_delete)(void *)GetProcAddress(s, "DeleteSecurityContext");
    api.control = (fn_control)(void *)GetProcAddress(s, "ApplyControlToken");
    api.query = (fn_query_ctx)(void *)GetProcAddress(s, "QueryContextAttributesW");
    api.free_buf = (fn_free_buf)(void *)GetProcAddress(s, "FreeContextBuffer");
    api.encrypt = (fn_crypt)(void *)GetProcAddress(s, "EncryptMessage");
    api.sign = (fn_crypt)(void *)GetProcAddress(s, "MakeSignature");
    api.decrypt = (fn_decrypt)(void *)GetProcAddress(s, "DecryptMessage");
    api.verify = (fn_decrypt)(void *)GetProcAddress(s, "VerifySignature");
    api.free_cert = (fn_free_cert)(void *)GetProcAddress(c, "CertFreeCertificateContext");
    int ok = api.enum_packages && api.query_package && api.acquire && api.free_cred &&
             api.init && api.accept && api.complete && api.delete_ctx && api.control &&
             api.query && api.free_buf && api.encrypt && api.sign && api.decrypt &&
             api.verify && api.free_cert;
    api.state = ok ? 1 : -1;
    return ok;
}

static wchar_t *gsspi_widen(gsspi_slice s) {
    if (s.len < 0 || s.len > (1 << 20) || (s.len > 0 && memchr(s.data, 0, (size_t)s.len))) return NULL;
    int n = s.len == 0 ? 0 : MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)s.data, (int)s.len, NULL, 0);
    if (s.len > 0 && n <= 0) return NULL;
    wchar_t *w = (wchar_t *)malloc(((size_t)n + 1) * sizeof(wchar_t));
    if (!w) return NULL;
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, (const char *)s.data, (int)s.len, w, n);
    w[n] = 0;
    return w;
}

/* A wide string as UTF-8 into out: its length, or E_BUFFER_TOO_SMALL. */
static int64_t gsspi_narrow(const wchar_t *w, gsspi_buf out) {
    if (!w) return 0;
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 1) return 0;
    if (n - 1 > out.len) return E_BUFFER_TOO_SMALL;
    char *tmp = (char *)malloc((size_t)n);
    if (!tmp) return E_NO_MEMORY;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, tmp, n, NULL, NULL);
    memcpy(out.data, tmp, (size_t)n - 1);
    free(tmp);
    return n - 1;
}

/* --- The tables ------------------------------------------------------------ */

#define MAX_CREDS 256
#define MAX_CTXS  1024

typedef struct {
    volatile LONG used;
    gs_handle h;
    int schannel;
} gs_cred;

typedef struct {
    volatile LONG used;
    int64_t cred;
    int schannel, server, has_handle, done, closed;
    gs_handle h;
    ULONG attrs;
    LONG last;
    uint8_t *in; size_t in_len, in_cap;          /* bytes given, not yet used */
    uint8_t *plain; size_t plain_len, plain_off; /* decrypted, not yet taken */
    int64_t out_len;                             /* the last token made */
    uint8_t *pend; size_t pend_len;              /* TLS bytes to send (TLS 1.3's KeyUpdate) */
    int renego, tls13;                           /* a post-handshake message under way */
    gs_stream_sizes ss; int have_ss;
    gs_sizes sz; int have_sz;
} gs_ctx;

static gs_cred creds[MAX_CREDS];
static gs_ctx ctxs[MAX_CTXS];

static gs_cred *cred_of(int64_t id) {
    if (id < 1 || id > MAX_CREDS || !creds[id - 1].used) return NULL;
    return &creds[id - 1];
}

static gs_ctx *ctx_of(int64_t id) {
    if (id < 1 || id > MAX_CTXS || !ctxs[id - 1].used) return NULL;
    return &ctxs[id - 1];
}

static int64_t cred_slot(void) {
    for (int i = 0; i < MAX_CREDS; i++)
        if (InterlockedCompareExchange(&creds[i].used, 1, 0) == 0) return i + 1;
    return E_NO_MEMORY;
}

static int in_append(gs_ctx *c, const uint8_t *p, size_t n) {
    if (c->in_len + n > c->in_cap) {
        size_t cap = c->in_cap ? c->in_cap : 16384;
        while (cap < c->in_len + n) cap *= 2;
        uint8_t *q = (uint8_t *)realloc(c->in, cap);
        if (!q) return 0;
        c->in = q;
        c->in_cap = cap;
    }
    if (n) memcpy(c->in + c->in_len, p, n);
    c->in_len += n;
    return 1;
}

/* Keeps the last n bytes of the input (SECBUFFER_EXTRA's), drops the rest. */
static void in_keep_tail(gs_ctx *c, size_t n) {
    if (n > c->in_len) n = c->in_len;
    memmove(c->in, c->in + (c->in_len - n), n);
    c->in_len = n;
}

static int64_t copy_out(gs_secbuf *b, gsspi_buf out, int64_t at) {
    if (!b->pv || b->cb == 0) return at;
    if (at + (int64_t)b->cb > out.len) return E_BUFFER_TOO_SMALL;
    memcpy(out.data + at, b->pv, b->cb);
    return at + b->cb;
}

/* A package as a line: "name\tcapabilities\tversion\trpcid\tmax_token\t
   comment\n" (wsprintf would need user32, and not every C library has
   snprintf). Its length; line has room for 2048 bytes. */
static int pkg_line(char *line, const gs_pkginfo *p) {
    char name[256] = "", comment[1024] = "";
    WideCharToMultiByte(CP_UTF8, 0, p->name ? p->name : L"", -1, name, sizeof name, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, p->comment ? p->comment : L"", -1, comment, sizeof comment, NULL, NULL);
    unsigned long nums[4] = { (unsigned long)p->caps, p->version, p->rpcid, (unsigned long)p->max_token };
    int n = 0;
    for (const char *q = name; *q; q++) line[n++] = *q;
    for (int i = 0; i < 4; i++) {
        char d[24];
        int k = 0;
        unsigned long v = nums[i];
        do { d[k++] = (char)('0' + v % 10); v /= 10; } while (v);
        line[n++] = '\t';
        while (k) line[n++] = d[--k];
    }
    line[n++] = '\t';
    for (const char *q = comment; *q; q++) line[n++] = (*q == '\t' || *q == '\n' || *q == '\r') ? ' ' : *q;
    line[n++] = '\n';
    return n;
}

#endif /* _WIN32 */

/* --- Packages ---------------------------------------------------------------- */

/* Every security package, one line each: "name\tcapabilities\tversion\t
   rpcid\tmax_token\tcomment\n". The bytes it takes (out may be too small:
   then call again with that many), or a status < 0. */
int64_t gsspi_packages(gsspi_buf out) {
#if defined(_WIN32)
    if (!gsspi_load()) return E_UNSUPPORTED;
    ULONG n = 0;
    gs_pkginfo *p = NULL;
    LONG st = api.enum_packages(&n, &p);
    if (st != 0) return st;
    int64_t total = 0;
    char line[2048];
    for (ULONG i = 0; i < n; i++) {
        int len = pkg_line(line, &p[i]);
        if (total + len <= out.len) memcpy(out.data + total, line, (size_t)len);
        total += len;
    }
    api.free_buf(p);
    return total;
#else
    (void)out;
    return E_UNSUPPORTED;
#endif
}

/* One package, as a line of gsspi_packages: its length, or a status < 0
   (SEC_E_SECPKG_NOT_FOUND when there is none of that name). */
int64_t gsspi_package_info(gsspi_slice name, gsspi_buf out) {
#if defined(_WIN32)
    if (!gsspi_load()) return E_UNSUPPORTED;
    wchar_t *w = gsspi_widen(name);
    if (!w || name.len == 0) { free(w); return E_INVALID_PARAMETER; }
    gs_pkginfo *p = NULL;
    LONG st = api.query_package(w, &p);
    free(w);
    if (st != 0) return st;
    char line[2048];
    int len = pkg_line(line, p);
    api.free_buf(p);
    if (len > out.len) return E_BUFFER_TOO_SMALL;
    memcpy(out.data, line, (size_t)len);
    return len;
#else
    (void)name; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* --- Credentials ------------------------------------------------------------- */

/* Credentials for a package (Negotiate, NTLM, Kerberos, ...): use is 1
   inbound (a server's), 2 outbound (a client's), 3 both. With user empty,
   the logged-on user's; else that user's, with domain and password. The
   credentials' id, or a status < 0. */
int64_t gsspi_acquire(gsspi_slice package, int32_t use, gsspi_slice user, gsspi_slice domain, gsspi_slice password) {
#if defined(_WIN32)
    if (!gsspi_load()) return E_UNSUPPORTED;
    if (use < 1 || use > 3) return E_INVALID_PARAMETER;
    wchar_t *pkg = gsspi_widen(package), *u = gsspi_widen(user), *d = gsspi_widen(domain), *p = gsspi_widen(password);
    int64_t rc;
    if (!pkg || !u || !d || !p || package.len == 0) { rc = E_INVALID_PARAMETER; goto out; }
    rc = cred_slot();
    if (rc < 0) goto out;
    {
        gs_cred *c = &creds[rc - 1];
        gs_identity id;
        memset(&id, 0, sizeof id);
        id.user = (USHORT *)u; id.user_len = (ULONG)wcslen(u);
        id.domain = (USHORT *)d; id.domain_len = (ULONG)wcslen(d);
        id.password = (USHORT *)p; id.password_len = (ULONG)wcslen(p);
        id.flags = 2;                                    /* SEC_WINNT_AUTH_IDENTITY_UNICODE */
        LARGE_INTEGER expiry;
        LONG st = api.acquire(NULL, pkg, (ULONG)use, NULL, user.len ? &id : NULL, NULL, NULL, &c->h, &expiry);
        SecureZeroMemory(p, wcslen(p) * sizeof(wchar_t));
        if (st != 0) { c->used = 0; rc = st; goto out; }
        c->schannel = 0;
    }
out:
    if (p) SecureZeroMemory(p, wcslen(p) * sizeof(wchar_t));
    free(pkg); free(u); free(d); free(p);
    return rc;
#else
    (void)package; (void)use; (void)user; (void)domain; (void)password;
    return E_UNSUPPORTED;
#endif
}

/* Schannel's client credentials. flags are SCH_CRED_* (manual
   validation, no revocation checks, ...); min_version and max_version are
   TLS's (0x0301 to 0x0304), 0 for the system's default. SCH_CREDENTIALS,
   which TLS 1.3 needs, and SCHANNEL_CRED where the system predates it.
   The credentials' id, or a status < 0. */
int64_t gsspi_acquire_schannel(int32_t flags, int32_t min_version, int32_t max_version) {
#if defined(_WIN32)
    if (!gsspi_load()) return E_UNSUPPORTED;
    DWORD enabled = 0;
    static const struct { int32_t v; DWORD bit; } versions[] = {
        { 0x0300, 0x20 }, { 0x0301, 0x80 }, { 0x0302, 0x200 }, { 0x0303, 0x800 }, { 0x0304, 0x2000 },
    };
    int32_t lo = min_version ? min_version : 0x0301, hi = max_version ? max_version : 0x0304;
    if (lo > hi) return E_INVALID_PARAMETER;
    for (int i = 0; i < 5; i++)
        if (versions[i].v >= lo && versions[i].v <= hi) enabled |= versions[i].bit;
    if (!enabled) return E_INVALID_PARAMETER;
    int64_t id = cred_slot();
    if (id < 0) return id;
    gs_cred *c = &creds[id - 1];
    LARGE_INTEGER expiry;
    gs_tls_parameters tp;
    memset(&tp, 0, sizeof tp);
    tp.disabled_protocols = (min_version || max_version) ? (SCH_CLIENT_PROTOCOLS & ~enabled) : 0;
    gs_sch_credentials sc;
    memset(&sc, 0, sizeof sc);
    sc.version = 5;
    sc.flags = (DWORD)flags;
    sc.nparams = 1;
    sc.params = &tp;
    LONG st = api.acquire(NULL, L"Microsoft Unified Security Protocol Provider", CRED_OUTBOUND,
                          NULL, &sc, NULL, NULL, &c->h, &expiry);
    if (st != 0) {
        /* Older than Windows 10 1809: SCHANNEL_CRED, without TLS 1.3. */
        gs_schannel_cred old;
        memset(&old, 0, sizeof old);
        old.version = 4;
        old.flags = (DWORD)flags;
        old.enabled_protocols = (min_version || max_version) ? (enabled & ~0x2000u) : 0;
        st = api.acquire(NULL, L"Microsoft Unified Security Protocol Provider", CRED_OUTBOUND,
                         NULL, &old, NULL, NULL, &c->h, &expiry);
    }
    if (st != 0) { c->used = 0; return st; }
    c->schannel = 1;
    return id;
#else
    (void)flags; (void)min_version; (void)max_version;
    return E_UNSUPPORTED;
#endif
}

int32_t gsspi_free_credentials(int64_t id) {
#if defined(_WIN32)
    gs_cred *c = cred_of(id);
    if (!c) return E_INVALID_HANDLE;
    LONG st = api.free_cred(&c->h);
    memset(&c->h, 0, sizeof c->h);
    c->used = 0;
    return st;
#else
    (void)id;
    return E_UNSUPPORTED;
#endif
}

/* --- Contexts ------------------------------------------------------------------ */

/* A new context on credentials, client (server 0) or server (1): its id,
   or a status < 0. The SSPI context itself comes with the first step. */
int64_t gsspi_context(int64_t cred, int32_t server) {
#if defined(_WIN32)
    gs_cred *cr = cred_of(cred);
    if (!cr) return E_INVALID_HANDLE;
    for (int i = 0; i < MAX_CTXS; i++) {
        if (InterlockedCompareExchange(&ctxs[i].used, 1, 0) == 0) {
            gs_ctx *c = &ctxs[i];
            c->cred = cred;
            c->schannel = cr->schannel;
            c->server = server != 0;
            c->has_handle = c->done = c->closed = 0;
            c->attrs = 0;
            c->last = 0;
            c->in_len = c->plain_len = c->plain_off = 0;
            c->out_len = 0;
            c->have_ss = c->have_sz = 0;
            c->pend_len = 0;
            c->renego = c->tls13 = 0;
            return i + 1;
        }
    }
    return E_NO_MEMORY;
#else
    (void)cred; (void)server;
    return E_UNSUPPORTED;
#endif
}

int32_t gsspi_delete_context(int64_t id) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c) return E_INVALID_HANDLE;
    LONG st = 0;
    if (c->has_handle) st = api.delete_ctx(&c->h);
    if (c->in) { SecureZeroMemory(c->in, c->in_cap); free(c->in); }
    if (c->plain) { SecureZeroMemory(c->plain, c->plain_len); free(c->plain); }
    free(c->pend);
    c->pend = NULL;
    c->pend_len = 0;
    c->in = c->plain = NULL;
    c->in_cap = c->in_len = c->plain_len = c->plain_off = 0;
    c->has_handle = 0;
    c->used = 0;
    return st;
#else
    (void)id;
    return E_UNSUPPORTED;
#endif
}

/* Bytes from the peer for the context's next step (a token, or TLS
   records): how many it now holds, or a status < 0. */
int64_t gsspi_feed(int64_t id, gsspi_slice data) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c) return E_INVALID_HANDLE;
    if (data.len < 0 || !in_append(c, data.data, (size_t)data.len)) return E_NO_MEMORY;
    return (int64_t)c->in_len;
#else
    (void)id; (void)data;
    return E_UNSUPPORTED;
#endif
}

/* How many bytes the context holds from the peer and has not used. */
int64_t gsspi_pending_input(int64_t id) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    return c ? (int64_t)c->in_len : E_INVALID_HANDLE;
#else
    (void)id;
    return E_UNSUPPORTED;
#endif
}

#if defined(_WIN32)
static void after_done(gs_ctx *c) {
    c->done = 1;
    if (c->schannel) {
        gs_conn_info ci;
        c->have_ss = api.query(&c->h, ATTR_STREAM, &c->ss) == 0;
        c->tls13 = api.query(&c->h, ATTR_CONN_INFO, &ci) == 0 && (ci.protocol & (0x1000 | 0x2000)) != 0;
    }
    else c->have_sz = api.query(&c->h, ATTR_SIZES, &c->sz) == 0;
}
#endif

/* One step of the handshake: InitializeSecurityContext (a client) or
   AcceptSecurityContext (a server), on what gsspi_feed gave it. The token
   to send goes into out (gsspi_out_len says how long; it is also sent
   when the step fails, as a TLS alert). SEC_E_OK when the context is
   established, SEC_I_CONTINUE_NEEDED when the peer has more to say,
   SEC_E_INCOMPLETE_MESSAGE when more of its bytes are needed, else an
   error. target is the server's name (a client's), flags ISC_REQ_* or
   ASC_REQ_*. */
int64_t gsspi_step(int64_t id, gsspi_slice target, int32_t flags, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c) return E_INVALID_HANDLE;
    gs_cred *cr = cred_of(c->cred);
    if (!cr) return E_INVALID_HANDLE;
    c->out_len = 0;
    wchar_t *t = NULL;
    if (target.len > 0) { t = gsspi_widen(target); if (!t) return E_INVALID_PARAMETER; }
    gs_secbuf ib[2], ob[3];
    gs_secdesc in = { 0, 0, ib }, outd = { 0, 0, ob };
    int have_in = c->in_len > 0;
    ib[0].type = B_TOKEN; ib[0].cb = (ULONG)c->in_len; ib[0].pv = c->in;
    ib[1].type = B_EMPTY; ib[1].cb = 0; ib[1].pv = NULL;
    in.count = c->schannel ? 2 : 1;
    ob[0].type = B_TOKEN; ob[0].cb = 0; ob[0].pv = NULL;
    ob[1].type = B_ALERT; ob[1].cb = 0; ob[1].pv = NULL;
    ob[2].type = B_EMPTY; ob[2].cb = 0; ob[2].pv = NULL;
    outd.count = c->schannel ? 2 : 1;
    ULONG attrs = 0;
    LARGE_INTEGER expiry;
    gs_handle nh;
    LONG st;
    if (c->server) {
        st = api.accept(&cr->h, c->has_handle ? &c->h : NULL, have_in ? &in : NULL,
                        (ULONG)flags | ISC_ALLOCATE, NATIVE_DREP,
                        c->has_handle ? &c->h : &nh, &outd, &attrs, &expiry);
    } else {
        st = api.init(&cr->h, c->has_handle ? &c->h : NULL, t, (ULONG)flags | ISC_ALLOCATE, 0,
                      c->schannel ? 0 : NATIVE_DREP, have_in ? &in : NULL, 0,
                      c->has_handle ? &c->h : &nh, &outd, &attrs, &expiry);
    }
    free(t);
    if (!c->has_handle && (st == 0 || st == S_CONTINUE_NEEDED || st == S_COMPLETE_NEEDED ||
                           st == S_COMPLETE_CONTINUE || st == E_INCOMPLETE)) {
        if (st != E_INCOMPLETE) { c->h = nh; c->has_handle = 1; }
    } else if (!c->has_handle && st < 0 && ob[0].cb && ob[0].pv) {
        /* A failed first step can still have made an alert; there is no
           context to keep. */
    }
    if (st == S_COMPLETE_NEEDED || st == S_COMPLETE_CONTINUE) {
        LONG cs = api.complete(&c->h, &outd);
        if (cs != 0) st = cs;
        else st = st == S_COMPLETE_NEEDED ? 0 : S_CONTINUE_NEEDED;
    }
    c->attrs = attrs;
    c->last = st;
    int64_t at = 0;
    for (ULONG i = 0; i < outd.count; i++) {
        if (ob[i].pv && ob[i].cb) {
            if (at >= 0) at = copy_out(&ob[i], out, at);
            api.free_buf(ob[i].pv);
        }
    }
    if (at < 0) return at;
    c->out_len = at;
    if (st == E_INCOMPLETE) return st;                  /* keep the input, wait for more */
    if (c->schannel && have_in && ib[1].type == B_EXTRA && ib[1].cb > 0) in_keep_tail(c, ib[1].cb);
    else c->in_len = 0;
    if (st == 0) after_done(c);
    return st;
#else
    (void)id; (void)target; (void)flags; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* The length of the token the last step made. */
int64_t gsspi_out_len(int64_t id) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    return c ? c->out_len : E_INVALID_HANDLE;
#else
    (void)id;
    return E_UNSUPPORTED;
#endif
}

/* The ISC_RET_* or ASC_RET_* flags the last step gave the context. */
int64_t gsspi_context_flags(int64_t id) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    return c ? (int64_t)c->attrs : E_INVALID_HANDLE;
#else
    (void)id;
    return E_UNSUPPORTED;
#endif
}

/* The package that was negotiated (NTLM or Kerberos under Negotiate; the
   package itself otherwise), into out: its length, or a status < 0. */
int64_t gsspi_context_package(int64_t id, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->has_handle) return E_INVALID_HANDLE;
    struct { gs_pkginfo *info; ULONG state; } neg = { NULL, 0 };
    int64_t rc;
    if (api.query(&c->h, ATTR_NEGOTIATION, &neg) == 0 && neg.info) {
        rc = gsspi_narrow(neg.info->name, out);
        api.free_buf(neg.info);
        return rc;
    }
    gs_pkginfo *p = NULL;
    LONG st = api.query(&c->h, ATTR_PACKAGE, &p);
    if (st != 0) return st;
    rc = gsspi_narrow(p ? p->name : NULL, out);
    if (p) api.free_buf(p);
    return rc;
#else
    (void)id; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* The name the context authenticated: a server's client ("DOMAIN\user"),
   a client's own. Its length, or a status < 0. */
int64_t gsspi_context_user(int64_t id, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->has_handle) return E_INVALID_HANDLE;
    wchar_t *name = NULL;
    LONG st = api.query(&c->h, ATTR_NAMES, &name);
    if (st != 0) return st;
    int64_t rc = gsspi_narrow(name, out);
    if (name) api.free_buf(name);
    return rc;
#else
    (void)id; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* Schannel: the server's certificate (DER) into out: its length, or a
   status < 0. */
int64_t gsspi_peer_certificate(int64_t id, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->has_handle) return E_INVALID_HANDLE;
    gs_cert_context *cert = NULL;
    LONG st = api.query(&c->h, ATTR_REMOTE_CERT, &cert);
    if (st != 0) return st;
    if (!cert) return E_INTERNAL;
    int64_t rc = (int64_t)cert->size;
    if (rc > out.len) rc = E_BUFFER_TOO_SMALL;
    else memcpy(out.data, cert->encoded, cert->size);
    api.free_cert(cert);
    return rc;
#else
    (void)id; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* Schannel: what was negotiated. which: 0 the protocol (TLS's version,
   0x0303 or 0x0304), 1 the cipher suite (IANA's number), 2 the cipher's
   strength in bits. The suite's name goes into out with which 3 (its
   length). A status < 0 if it cannot say. */
int64_t gsspi_connection(int64_t id, int32_t which, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->has_handle) return E_INVALID_HANDLE;
    if (which == 0 || which == 2) {
        gs_conn_info ci;
        LONG st = api.query(&c->h, ATTR_CONN_INFO, &ci);
        if (st != 0) return st;
        if (which == 2) return ci.cipher_strength;
        DWORD p = ci.protocol;
        if (p & (0x1000 | 0x2000)) return 0x0304;
        if (p & (0x400 | 0x800)) return 0x0303;
        if (p & (0x100 | 0x200)) return 0x0302;
        if (p & (0x40 | 0x80)) return 0x0301;
        if (p & (0x10 | 0x20)) return 0x0300;
        return 0;
    }
    gs_cipher_info info;
    memset(&info, 0, sizeof info);
    info.version = 1;
    LONG st = api.query(&c->h, ATTR_CIPHER_INFO, &info);
    if (st != 0) return st;
    if (which == 1) return info.suite;
    if (which == 3) return gsspi_narrow(info.suite_name, out);
    return E_INVALID_PARAMETER;
#else
    (void)id; (void)which; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* --- TLS records (Schannel) ------------------------------------------------- */

/* The largest plaintext one record takes, once the handshake is done. */
int64_t gsspi_max_message(int64_t id) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c) return E_INVALID_HANDLE;
    if (!c->have_ss) return E_INVALID_HANDLE;
    return c->ss.max_message;
#else
    (void)id;
    return E_UNSUPPORTED;
#endif
}

/* data (at most gsspi_max_message bytes) as one TLS record into out: the
   record's length, or a status < 0. */
int64_t gsspi_encrypt(int64_t id, gsspi_slice data, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->have_ss || c->closed) return E_INVALID_HANDLE;
    if (data.len < 0 || data.len > (int64_t)c->ss.max_message) return E_INVALID_PARAMETER;
    int64_t need = (int64_t)c->ss.header + data.len + c->ss.trailer;
    if (need > out.len) return E_BUFFER_TOO_SMALL;
    gs_secbuf b[4];
    b[0].type = B_HEADER; b[0].cb = c->ss.header; b[0].pv = out.data;
    b[1].type = B_DATA; b[1].cb = (ULONG)data.len; b[1].pv = out.data + c->ss.header;
    b[2].type = B_TRAILER; b[2].cb = c->ss.trailer; b[2].pv = out.data + c->ss.header + data.len;
    b[3].type = B_EMPTY; b[3].cb = 0; b[3].pv = NULL;
    if (data.len) memcpy(b[1].pv, data.data, (size_t)data.len);
    gs_secdesc d = { 0, 4, b };
    LONG st = api.encrypt(&c->h, 0, &d, 0);
    if (st != 0) return st;
    return (int64_t)b[0].cb + b[1].cb + b[2].cb;
#else
    (void)id; (void)data; (void)out;
    return E_UNSUPPORTED;
#endif
}

#if defined(_WIN32)
/* TLS 1.3's messages after the handshake (NewSessionTicket, KeyUpdate)
   come out of DecryptMessage as SEC_I_RENEGOTIATE, with the records from
   that message on in an EXTRA buffer; InitializeSecurityContext takes
   them, and what it makes (a KeyUpdate of ours) is sent before the next
   record. A TLS 1.2 server's HelloRequest comes the same way and would
   make a ClientHello: that renegotiation is refused. E_INCOMPLETE while
   the message is not all there. */
static LONG post_handshake(gs_ctx *c) {
    gs_cred *cr = cred_of(c->cred);
    if (!cr) return E_INVALID_HANDLE;
    gs_secbuf ib[2], ob[2];
    ib[0].type = B_TOKEN; ib[0].cb = (ULONG)c->in_len; ib[0].pv = c->in;
    ib[1].type = B_EMPTY; ib[1].cb = 0; ib[1].pv = NULL;
    ob[0].type = B_TOKEN; ob[0].cb = 0; ob[0].pv = NULL;
    ob[1].type = B_ALERT; ob[1].cb = 0; ob[1].pv = NULL;
    gs_secdesc in = { 0, 2, ib }, outd = { 0, 2, ob };
    ULONG attrs = 0;
    LARGE_INTEGER expiry;
    LONG st = api.init(&cr->h, &c->h, NULL, ISC_ALLOCATE | 0x8000 | 0x10 | 0x8 | 0x4, 0, 0,
                       &in, 0, &c->h, &outd, &attrs, &expiry);
    LONG rc = st;
    for (int i = 0; i < 2; i++) {
        if (!ob[i].pv) continue;
        if (ob[i].cb && rc == 0) {
            if (!c->tls13) rc = GSSPI_RENEGOTIATE;
            else {
                uint8_t *q = (uint8_t *)realloc(c->pend, c->pend_len + ob[i].cb);
                if (!q) rc = E_NO_MEMORY;
                else {
                    memcpy(q + c->pend_len, ob[i].pv, ob[i].cb);
                    c->pend = q;
                    c->pend_len += ob[i].cb;
                }
            }
        }
        api.free_buf(ob[i].pv);
    }
    if (st == E_INCOMPLETE) return st;
    if (st == S_CONTINUE_NEEDED) return GSSPI_RENEGOTIATE;
    if (ib[1].type == B_EXTRA && ib[1].cb > 0) in_keep_tail(c, ib[1].cb);
    else c->in_len = 0;
    return rc;
}
#endif

/* Plaintext from the records gsspi_feed gave it, into out: how many bytes
   (> 0), 0 when it needs more of the peer's bytes, GSSPI_END (-100) at the
   peer's close_notify, GSSPI_RENEGOTIATE (-101) when the peer asked to
   renegotiate (refused), or a status < 0. After each call, bytes to send
   may wait in gsspi_take_output. */
int64_t gsspi_decrypt(int64_t id, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->have_ss) return E_INVALID_HANDLE;
    for (;;) {
        if (c->plain_off < c->plain_len) {
            size_t n = c->plain_len - c->plain_off;
            if ((int64_t)n > out.len) n = (size_t)out.len;
            memcpy(out.data, c->plain + c->plain_off, n);
            c->plain_off += n;
            if (c->plain_off == c->plain_len) c->plain_off = c->plain_len = 0;
            return (int64_t)n;
        }
        if (c->closed) return GSSPI_END;
        if (c->in_len == 0) return 0;
        if (c->renego) {
            LONG ps = post_handshake(c);
            if (ps == E_INCOMPLETE) return 0;
            if (ps != 0) return ps;
            c->renego = 0;
            continue;
        }
        gs_secbuf b[4];
        b[0].type = B_DATA; b[0].cb = (ULONG)c->in_len; b[0].pv = c->in;
        for (int i = 1; i < 4; i++) { b[i].type = B_EMPTY; b[i].cb = 0; b[i].pv = NULL; }
        gs_secdesc d = { 0, 4, b };
        LONG st = api.decrypt(&c->h, &d, 0, NULL);
        if (st == E_INCOMPLETE) return 0;
        if (st != 0 && st != S_CONTEXT_EXPIRED && st != S_RENEGOTIATE) return st;
        gs_secbuf *data = NULL, *extra = NULL;
        for (int i = 0; i < 4; i++) {
            if (b[i].type == B_DATA && !data) data = &b[i];
            else if (b[i].type == B_EXTRA && !extra) extra = &b[i];
        }
        /* At close_notify (SEC_I_CONTEXT_EXPIRED) the DATA buffer is the
           alert record itself, not plaintext. */
        if (st == 0 && data && data->cb) {
            uint8_t *q = (uint8_t *)realloc(c->plain, data->cb);
            if (!q) return E_NO_MEMORY;
            c->plain = q;
            memcpy(c->plain, data->pv, data->cb);
            c->plain_len = data->cb;
            c->plain_off = 0;
        }
        if (extra && extra->cb) in_keep_tail(c, extra->cb);
        else c->in_len = 0;
        if (st == S_RENEGOTIATE) {
            if (!c->tls13) return GSSPI_RENEGOTIATE;
            c->renego = 1;
            if (c->in_len == 0) return 0;
        }
        if (st == S_CONTEXT_EXPIRED) c->closed = 1;
    }
#else
    (void)id; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* TLS bytes the context made to send (TLS 1.3's KeyUpdate in answer to
   the server's), into out: how many, 0 when none; then they are gone. */
int64_t gsspi_take_output(int64_t id, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c) return E_INVALID_HANDLE;
    if ((int64_t)c->pend_len > out.len) return E_BUFFER_TOO_SMALL;
    int64_t n = (int64_t)c->pend_len;
    if (n) memcpy(out.data, c->pend, (size_t)n);
    c->pend_len = 0;
    return n;
#else
    (void)id; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* The close_notify alert to send, into out: its length, or a status < 0. */
int64_t gsspi_shutdown(int64_t id, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->has_handle) return E_INVALID_HANDLE;
    gs_cred *cr = cred_of(c->cred);
    if (!cr) return E_INVALID_HANDLE;
    DWORD kind = SCHANNEL_SHUTDOWN;
    gs_secbuf tb = { sizeof kind, B_TOKEN, &kind };
    gs_secdesc td = { 0, 1, &tb };
    LONG st = api.control(&c->h, &td);
    if (st != 0) return st;
    gs_secbuf ob = { 0, B_TOKEN, NULL };
    gs_secdesc od = { 0, 1, &ob };
    ULONG attrs = 0;
    LARGE_INTEGER expiry;
    st = api.init(&cr->h, &c->h, NULL, ISC_ALLOCATE | 0x8000 | 0x10 | 0x8 | 0x4, 0, 0,
                  NULL, 0, &c->h, &od, &attrs, &expiry);
    int64_t n = 0;
    if (ob.pv) { n = copy_out(&ob, out, 0); api.free_buf(ob.pv); }
    c->closed = 1;
    if (st != 0 && st != S_CONTEXT_EXPIRED) return st;
    return n;
#else
    (void)id; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* --- Messages (Negotiate, NTLM, Kerberos) ----------------------------------- */

#if defined(_WIN32)
static int ensure_sizes(gs_ctx *c) {
    if (!c->have_sz) c->have_sz = api.query(&c->h, ATTR_SIZES, &c->sz) == 0;
    return c->have_sz;
}
#endif

/* The signature of msg (MakeSignature) into out: its length, or a status
   < 0. */
int64_t gsspi_sign(int64_t id, gsspi_slice msg, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->done || !ensure_sizes(c)) return E_INVALID_HANDLE;
    if (out.len < (int64_t)c->sz.max_signature) return E_BUFFER_TOO_SMALL;
    uint8_t *copy = (uint8_t *)malloc(msg.len > 0 ? (size_t)msg.len : 1);
    if (!copy) return E_NO_MEMORY;
    if (msg.len) memcpy(copy, msg.data, (size_t)msg.len);
    gs_secbuf b[2];
    b[0].type = B_DATA; b[0].cb = (ULONG)msg.len; b[0].pv = copy;
    b[1].type = B_TOKEN; b[1].cb = c->sz.max_signature; b[1].pv = out.data;
    gs_secdesc d = { 0, 2, b };
    LONG st = api.sign(&c->h, 0, &d, 0);
    free(copy);
    return st != 0 ? st : (int64_t)b[1].cb;
#else
    (void)id; (void)msg; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* Checks sig over msg (VerifySignature): SEC_E_OK or SEC_E_MESSAGE_ALTERED,
   SEC_E_OUT_OF_SEQUENCE, ... */
int64_t gsspi_verify(int64_t id, gsspi_slice msg, gsspi_slice sig) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->done) return E_INVALID_HANDLE;
    uint8_t *m = (uint8_t *)malloc(msg.len > 0 ? (size_t)msg.len : 1);
    uint8_t *s = (uint8_t *)malloc(sig.len > 0 ? (size_t)sig.len : 1);
    if (!m || !s) { free(m); free(s); return E_NO_MEMORY; }
    if (msg.len) memcpy(m, msg.data, (size_t)msg.len);
    if (sig.len) memcpy(s, sig.data, (size_t)sig.len);
    gs_secbuf b[2];
    b[0].type = B_DATA; b[0].cb = (ULONG)msg.len; b[0].pv = m;
    b[1].type = B_TOKEN; b[1].cb = (ULONG)sig.len; b[1].pv = s;
    gs_secdesc d = { 0, 2, b };
    ULONG qop = 0;
    LONG st = api.verify(&c->h, &d, 0, &qop);
    free(m); free(s);
    return st;
#else
    (void)id; (void)msg; (void)sig;
    return E_UNSUPPORTED;
#endif
}

/* msg sealed (EncryptMessage) into out as the security token, then the
   ciphertext, then any padding: GSS-API's wrap token as NTLM and Kerberos
   lay it out ([MS-NLMP] 3.4.6: signature, then the sealed message). Its
   length, or a status < 0. */
int64_t gsspi_seal(int64_t id, gsspi_slice msg, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->done || !ensure_sizes(c)) return E_INVALID_HANDLE;
    int64_t need = (int64_t)c->sz.trailer + msg.len + c->sz.block;
    if (need > out.len) return E_BUFFER_TOO_SMALL;
    uint8_t *tok = (uint8_t *)malloc(c->sz.trailer + 1), *pad = (uint8_t *)malloc(c->sz.block + 1);
    uint8_t *data = (uint8_t *)malloc(msg.len > 0 ? (size_t)msg.len : 1);
    if (!tok || !pad || !data) { free(tok); free(pad); free(data); return E_NO_MEMORY; }
    if (msg.len) memcpy(data, msg.data, (size_t)msg.len);
    gs_secbuf b[3];
    b[0].type = B_TOKEN; b[0].cb = c->sz.trailer; b[0].pv = tok;
    b[1].type = B_DATA; b[1].cb = (ULONG)msg.len; b[1].pv = data;
    b[2].type = B_PADDING; b[2].cb = c->sz.block; b[2].pv = pad;
    gs_secdesc d = { 0, 3, b };
    LONG st = api.encrypt(&c->h, 0, &d, 0);
    int64_t n = st;
    if (st == 0) {
        n = 0;
        for (int i = 0; i < 3; i++) { memcpy(out.data + n, b[i].pv, b[i].cb); n += b[i].cb; }
    }
    free(tok); free(pad); free(data);
    return n;
#else
    (void)id; (void)msg; (void)out;
    return E_UNSUPPORTED;
#endif
}

/* A sealed message (gsspi_seal's layout) back to the plaintext, into out:
   its length, or a status < 0. SSPI finds the token's end (a STREAM
   buffer); a package that cannot is given the first max-trailer bytes as
   the token. */
int64_t gsspi_unseal(int64_t id, gsspi_slice msg, gsspi_buf out) {
#if defined(_WIN32)
    gs_ctx *c = ctx_of(id);
    if (!c || !c->done || !ensure_sizes(c)) return E_INVALID_HANDLE;
    uint8_t *copy = (uint8_t *)malloc(msg.len > 0 ? (size_t)msg.len : 1);
    if (!copy) return E_NO_MEMORY;
    if (msg.len) memcpy(copy, msg.data, (size_t)msg.len);
    gs_secbuf b[2];
    b[0].type = B_STREAM; b[0].cb = (ULONG)msg.len; b[0].pv = copy;
    b[1].type = B_DATA; b[1].cb = 0; b[1].pv = NULL;
    gs_secdesc d = { 0, 2, b };
    ULONG qop = 0;
    LONG st = api.decrypt(&c->h, &d, 0, &qop);
    int64_t n;
    if (st == 0) {
        n = b[1].cb;
        if (n > out.len) n = E_BUFFER_TOO_SMALL;
        else if (n) memcpy(out.data, b[1].pv, (size_t)n);
    } else {
        /* No STREAM support: the token, then the data. */
        if (msg.len) memcpy(copy, msg.data, (size_t)msg.len);
        ULONG tl = c->sz.trailer;
        if ((int64_t)tl > msg.len) { free(copy); return st; }
        b[0].type = B_TOKEN; b[0].cb = tl; b[0].pv = copy;
        b[1].type = B_DATA; b[1].cb = (ULONG)(msg.len - tl); b[1].pv = copy + tl;
        st = api.decrypt(&c->h, &d, 0, &qop);
        if (st != 0) n = st;
        else {
            n = b[1].cb;
            if (n > out.len) n = E_BUFFER_TOO_SMALL;
            else if (n) memcpy(out.data, b[1].pv, (size_t)n);
        }
    }
    SecureZeroMemory(copy, msg.len > 0 ? (size_t)msg.len : 1);
    free(copy);
    return n;
#else
    (void)id; (void)msg; (void)out;
    return E_UNSUPPORTED;
#endif
}
