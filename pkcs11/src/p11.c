/* p11: pkcs11's C. It loads a PKCS#11 module (dlopen, or LoadLibrary on
   Windows), takes its CK_FUNCTION_LIST from C_GetFunctionList, and calls
   through it. Goose hands over flat byte encodings, which this file turns
   into the C structures the module wants:

     a template     repeated { u64 type, u64 len, len bytes }
     a mechanism    u64 type, u64 kind, then the kind's fields (P11_PARAM_*)
     attribute types (GetAttributeValue)  repeated u64

   Results that vary in size are appended to a Goose byte builder; integers
   in them, and every u64 above, are little-endian 64-bit. Every call returns
   the module's CK_RV (as uint64_t), or one of the P11_E* codes when this
   file fails before the module is reached.

   The types are declared here rather than taken from the OASIS headers,
   only as far as they are used, with CK_ULONG as the platform's unsigned
   long (4 bytes on Windows) and Windows' 1-byte structure packing. Strings
   arrive as Goose slices, { data, len }, not NUL-terminated. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "goose.h"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  pragma pack(push, 1)
#else
#  include <dlfcn.h>
#endif

typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV;

typedef struct { CK_BYTE major, minor; } CK_VERSION;

typedef struct {
    CK_VERSION cryptokiVersion;
    CK_BYTE manufacturerID[32];
    CK_ULONG flags;
    CK_BYTE libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef struct {
    CK_BYTE slotDescription[64];
    CK_BYTE manufacturerID[32];
    CK_ULONG flags;
    CK_VERSION hardwareVersion, firmwareVersion;
} CK_SLOT_INFO;

typedef struct {
    CK_BYTE label[32], manufacturerID[32], model[16], serialNumber[16];
    CK_ULONG flags, ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount, ulRwSessionCount,
             ulMaxPinLen, ulMinPinLen, ulTotalPublicMemory, ulFreePublicMemory,
             ulTotalPrivateMemory, ulFreePrivateMemory;
    CK_VERSION hardwareVersion, firmwareVersion;
    CK_BYTE utcTime[16];
} CK_TOKEN_INFO;

typedef struct { CK_ULONG slotID, state, flags, ulDeviceError; } CK_SESSION_INFO;
typedef struct { CK_ULONG ulMinKeySize, ulMaxKeySize, flags; } CK_MECHANISM_INFO;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

typedef struct {
    void *CreateMutex, *DestroyMutex, *LockMutex, *UnlockMutex;
    CK_ULONG flags;
    void *pReserved;
} CK_C_INITIALIZE_ARGS;

/* Mechanism parameters with pointers in them. */
typedef struct { CK_BYTE *pIv; CK_ULONG ulIvLen, ulIvBits; CK_BYTE *pAAD; CK_ULONG ulAADLen, ulTagBits; } CK_GCM_PARAMS;
typedef struct { CK_ULONG hashAlg, mgf, source; void *pSourceData; CK_ULONG ulSourceDataLen; } CK_RSA_PKCS_OAEP_PARAMS;
typedef struct { CK_ULONG hashAlg, mgf, sLen; } CK_RSA_PKCS_PSS_PARAMS;
typedef struct { CK_ULONG kdf, ulSharedDataLen; CK_BYTE *pSharedData; CK_ULONG ulPublicDataLen; CK_BYTE *pPublicData; } CK_ECDH1_DERIVE_PARAMS;
typedef struct { CK_ULONG ulAESKeyBits; CK_RSA_PKCS_OAEP_PARAMS *pOAEPParams; } CK_RSA_AES_KEY_WRAP_PARAMS;
typedef struct { CK_BYTE phFlag; CK_ULONG ulContextDataLen; CK_BYTE *pContextData; } CK_EDDSA_PARAMS;

typedef CK_RV (*FN)(void);   /* the slots of the list, cast to their types at the call */

/* CK_FUNCTION_LIST (PKCS#11 2.40 §5.2): the version, then the 68 functions in
   the order the standard lists them. */
typedef struct {
    CK_VERSION version;
    CK_RV (*C_Initialize)(void *);
    CK_RV (*C_Finalize)(void *);
    CK_RV (*C_GetInfo)(CK_INFO *);
    FN C_GetFunctionList;
    CK_RV (*C_GetSlotList)(CK_BYTE, CK_ULONG *, CK_ULONG *);
    CK_RV (*C_GetSlotInfo)(CK_ULONG, CK_SLOT_INFO *);
    CK_RV (*C_GetTokenInfo)(CK_ULONG, CK_TOKEN_INFO *);
    CK_RV (*C_GetMechanismList)(CK_ULONG, CK_ULONG *, CK_ULONG *);
    CK_RV (*C_GetMechanismInfo)(CK_ULONG, CK_ULONG, CK_MECHANISM_INFO *);
    CK_RV (*C_InitToken)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *);
    CK_RV (*C_InitPIN)(CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_SetPIN)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_OpenSession)(CK_ULONG, CK_ULONG, void *, void *, CK_ULONG *);
    CK_RV (*C_CloseSession)(CK_ULONG);
    CK_RV (*C_CloseAllSessions)(CK_ULONG);
    CK_RV (*C_GetSessionInfo)(CK_ULONG, CK_SESSION_INFO *);
    CK_RV (*C_GetOperationState)(CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SetOperationState)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_ULONG, CK_ULONG);
    CK_RV (*C_Login)(CK_ULONG, CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_Logout)(CK_ULONG);
    CK_RV (*C_CreateObject)(CK_ULONG, CK_ATTRIBUTE *, CK_ULONG, CK_ULONG *);
    CK_RV (*C_CopyObject)(CK_ULONG, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG, CK_ULONG *);
    CK_RV (*C_DestroyObject)(CK_ULONG, CK_ULONG);
    CK_RV (*C_GetObjectSize)(CK_ULONG, CK_ULONG, CK_ULONG *);
    CK_RV (*C_GetAttributeValue)(CK_ULONG, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_SetAttributeValue)(CK_ULONG, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_FindObjectsInit)(CK_ULONG, CK_ATTRIBUTE *, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_ULONG, CK_ULONG *, CK_ULONG, CK_ULONG *);
    CK_RV (*C_FindObjectsFinal)(CK_ULONG);
    CK_RV (*C_EncryptInit)(CK_ULONG, CK_MECHANISM *, CK_ULONG);
    CK_RV (*C_Encrypt)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_EncryptUpdate)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_EncryptFinal)(CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptInit)(CK_ULONG, CK_MECHANISM *, CK_ULONG);
    CK_RV (*C_Decrypt)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptUpdate)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptFinal)(CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DigestInit)(CK_ULONG, CK_MECHANISM *);
    CK_RV (*C_Digest)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DigestUpdate)(CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_DigestKey)(CK_ULONG, CK_ULONG);
    CK_RV (*C_DigestFinal)(CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SignInit)(CK_ULONG, CK_MECHANISM *, CK_ULONG);
    CK_RV (*C_Sign)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SignUpdate)(CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_SignFinal)(CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SignRecoverInit)(CK_ULONG, CK_MECHANISM *, CK_ULONG);
    CK_RV (*C_SignRecover)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_VerifyInit)(CK_ULONG, CK_MECHANISM *, CK_ULONG);
    CK_RV (*C_Verify)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_VerifyUpdate)(CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_VerifyFinal)(CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_VerifyRecoverInit)(CK_ULONG, CK_MECHANISM *, CK_ULONG);
    CK_RV (*C_VerifyRecover)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DigestEncryptUpdate)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptDigestUpdate)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_SignEncryptUpdate)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_DecryptVerifyUpdate)(CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_GenerateKey)(CK_ULONG, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_ULONG *);
    CK_RV (*C_GenerateKeyPair)(CK_ULONG, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG,
                               CK_ULONG *, CK_ULONG *);
    CK_RV (*C_WrapKey)(CK_ULONG, CK_MECHANISM *, CK_ULONG, CK_ULONG, CK_BYTE *, CK_ULONG *);
    CK_RV (*C_UnwrapKey)(CK_ULONG, CK_MECHANISM *, CK_ULONG, CK_BYTE *, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG,
                         CK_ULONG *);
    CK_RV (*C_DeriveKey)(CK_ULONG, CK_MECHANISM *, CK_ULONG, CK_ATTRIBUTE *, CK_ULONG, CK_ULONG *);
    CK_RV (*C_SeedRandom)(CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_GenerateRandom)(CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV (*C_GetFunctionStatus)(CK_ULONG);
    CK_RV (*C_CancelFunction)(CK_ULONG);
    CK_RV (*C_WaitForSlotEvent)(CK_ULONG, CK_ULONG *, void *);
} CK_FUNCTION_LIST;

#if defined(_WIN32)
#  pragma pack(pop)
#endif

typedef struct { const uint8_t *data; int64_t len; } p11_slice;

/* Failures of this file's own, kept apart from every CKR_ value (which are
   below 2^32). */
#define P11_E_LOAD       0x100000001ULL   /* the module would not load */
#define P11_E_SYMBOL     0x100000002ULL   /* no C_GetFunctionList, or it failed */
#define P11_E_ENCODING   0x100000003ULL   /* a template or mechanism Goose sent is malformed */
#define P11_E_MEMORY     0x100000004ULL
#define P11_E_NO_MODULE  0x100000005ULL   /* a context that was destroyed, or never loaded */
#define P11_E_MODULE     0x100000006ULL   /* the module said it wrote past the buffer it was given */

/* Whether a u64 survives as a CK_ULONG: always where that is 8 bytes; on
   Windows (4) a larger handle, type, flag or length is refused rather than
   cut short. */
#define FITS(v) ((uint64_t)(CK_ULONG)(v) == (uint64_t)(v))
#define NEED(c) do { if (!(c)) return P11_E_ENCODING; } while (0)

#define CKR_OK 0
#define CKR_BUFFER_TOO_SMALL 0x150
#define CK_UNAVAILABLE ((CK_ULONG)~0UL)

typedef struct {
    void *handle;
    CK_FUNCTION_LIST *f;
} p11_ctx;

static CK_FUNCTION_LIST *fl(uint64_t ctx) {
    p11_ctx *c = (p11_ctx *)(uintptr_t)ctx;
    return c ? c->f : NULL;
}

#define FL(ctx) CK_FUNCTION_LIST *f = fl(ctx); if (!f) return P11_E_NO_MODULE

static void put64(gs_rref out, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    gs_bld_append(out, b, 8);
}

static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

static void put_version(gs_rref out, CK_VERSION v) {
    gs_bld_append(out, &v.major, 1);
    gs_bld_append(out, &v.minor, 1);
}

/* --- Loading ----------------------------------------------------------------- */

/* The module at path, or 0 with the loader's message appended to err. */
uint64_t p11_load(p11_slice path, gs_rref err) {
    char *p = malloc((size_t)path.len + 1);
    if (!p) return 0;
    memcpy(p, path.data, (size_t)path.len);
    p[path.len] = 0;
    p11_ctx *c = calloc(1, sizeof *c);
    if (!c) { free(p); return 0; }
    CK_RV (*get_list)(CK_FUNCTION_LIST **) = NULL;
#if defined(_WIN32)
    HMODULE h = LoadLibraryA(p);
    free(p);
    if (!h) { gs_bld_append(err, "LoadLibrary failed", 18); free(c); return 0; }
    get_list = (CK_RV (*)(CK_FUNCTION_LIST **))GetProcAddress(h, "C_GetFunctionList");
#else
    void *h = dlopen(p, RTLD_NOW | RTLD_LOCAL);
    free(p);
    if (!h) {
        const char *e = dlerror();
        if (e) gs_bld_append(err, e, (int64_t)strlen(e));
        free(c);
        return 0;
    }
    get_list = (CK_RV (*)(CK_FUNCTION_LIST **))dlsym(h, "C_GetFunctionList");
#endif
    if (!get_list || get_list(&c->f) != CKR_OK || !c->f) {
        gs_bld_append(err, "no C_GetFunctionList", 20);
#if defined(_WIN32)
        FreeLibrary(h);
#else
        dlclose(h);
#endif
        free(c);
        return 0;
    }
    c->handle = h;
    return (uint64_t)(uintptr_t)c;
}

void p11_unload(uint64_t ctx) {
    p11_ctx *c = (p11_ctx *)(uintptr_t)ctx;
    if (!c) return;
#if defined(_WIN32)
    if (c->handle) FreeLibrary((HMODULE)c->handle);
#else
    if (c->handle) dlclose(c->handle);
#endif
    free(c);
}

int64_t p11_ulong_size(void) { return (int64_t)sizeof(CK_ULONG); }

/* --- Templates and mechanisms ------------------------------------------------ */

/* A template decoded: n attributes pointing into the encoding itself. */
static int decode_template(p11_slice t, CK_ATTRIBUTE **out, CK_ULONG *n) {
    int64_t count = 0, at = 0;
    *out = NULL;
    *n = 0;
    while (at < t.len) {
        if (t.len - at < 16) return 0;
        uint64_t len = get64(t.data + at + 8);
        if (len > (uint64_t)(t.len - at - 16) || !FITS(len) || !FITS(get64(t.data + at))) return 0;
        at += 16 + (int64_t)len;
        count++;
    }
    /* An empty template is still a pointer: SoftHSM, among others, refuses
       NULL even with a count of 0. */
    CK_ATTRIBUTE *a = calloc((size_t)(count ? count : 1), sizeof *a);
    if (!a) return 0;
    at = 0;
    for (int64_t i = 0; i < count; i++) {
        uint64_t len = get64(t.data + at + 8);
        a[i].type = (CK_ULONG)get64(t.data + at);
        a[i].pValue = len ? (void *)(t.data + at + 16) : NULL;
        a[i].ulValueLen = (CK_ULONG)len;
        at += 16 + (int64_t)len;
    }
    *out = a;
    *n = (CK_ULONG)count;
    return 1;
}

/* Parameter kinds of an encoded mechanism (pkcs11.goose's PARAM_*). */
#define P11_PARAM_NONE   0     /* no parameter */
#define P11_PARAM_RAW    1     /* u64 len, bytes: the parameter as it is (an IV, ...) */
#define P11_PARAM_GCM    2     /* iv, aad (each u64 len + bytes), u64 tag bits */
#define P11_PARAM_OAEP   3     /* u64 hash, u64 mgf, u64 source, source data (len + bytes) */
#define P11_PARAM_PSS    4     /* u64 hash, u64 mgf, u64 salt length */
#define P11_PARAM_ECDH1  5     /* u64 kdf, shared data, public data (each len + bytes) */
#define P11_PARAM_RSA_AES_KW 6 /* u64 AES key bits, then an OAEP parameter's fields */
#define P11_PARAM_EDDSA  7     /* u64 prehash flag, context data (len + bytes) */
#define P11_PARAM_ULONG  8     /* u64: a CK_ULONG parameter (a MAC length, ...) */
#define P11_PARAM_CCM    9     /* u64 data len, nonce, aad (each len + bytes), u64 MAC len */

/* A mechanism decoded, with what its parameter points at: the encoding Goose
   passed and this struct, both gone when the call returns. Modules copy the
   parameter at Init (PKCS#11 §5.11 leaves it to them; SoftHSM does); one
   that writes a GCM IV back after Init, as CloudHSM may, would write into
   freed memory, so such modules are not supported. */
typedef struct {
    CK_MECHANISM m;
    union {
        CK_GCM_PARAMS gcm;
        CK_RSA_PKCS_OAEP_PARAMS oaep;
        CK_RSA_PKCS_PSS_PARAMS pss;
        CK_ECDH1_DERIVE_PARAMS ecdh1;
        struct { CK_RSA_AES_KEY_WRAP_PARAMS kw; CK_RSA_PKCS_OAEP_PARAMS oaep; } rsa_aes;
        CK_EDDSA_PARAMS eddsa;
        CK_ULONG ul;
        struct { CK_ULONG ulDataLen; CK_BYTE *pNonce; CK_ULONG ulNonceLen; CK_BYTE *pAAD; CK_ULONG ulAADLen, ulMACLen; } ccm;
    } p;
} p11_mech;

typedef struct { const uint8_t *d; int64_t len, at; int ok; } reader;

static uint64_t r64(reader *r) {
    if (r->len - r->at < 8) { r->ok = 0; return 0; }
    uint64_t v = get64(r->d + r->at);
    r->at += 8;
    return v;
}

/* A u64 that must fit a CK_ULONG. */
static CK_ULONG rul(reader *r) {
    uint64_t v = r64(r);
    if (!FITS(v)) r->ok = 0;
    return (CK_ULONG)v;
}

static CK_BYTE *rbytes(reader *r, CK_ULONG *n) {
    uint64_t len = r64(r);
    if (!r->ok || len > (uint64_t)(r->len - r->at) || !FITS(len)) { r->ok = 0; *n = 0; return NULL; }
    CK_BYTE *p = len ? (CK_BYTE *)(r->d + r->at) : NULL;
    r->at += (int64_t)len;
    *n = (CK_ULONG)len;
    return p;
}

static void read_oaep(reader *r, CK_RSA_PKCS_OAEP_PARAMS *o) {
    o->hashAlg = rul(r);
    o->mgf = rul(r);
    o->source = rul(r);
    o->pSourceData = rbytes(r, &o->ulSourceDataLen);
}

static int decode_mechanism(p11_slice s, p11_mech *pm) {
    reader r = { s.data, s.len, 0, 1 };
    memset(pm, 0, sizeof *pm);
    pm->m.mechanism = rul(&r);
    uint64_t kind = r64(&r);
    switch (kind) {
    case P11_PARAM_NONE:
        break;
    case P11_PARAM_RAW:
        pm->m.pParameter = rbytes(&r, &pm->m.ulParameterLen);
        break;
    case P11_PARAM_GCM:
        pm->p.gcm.pIv = rbytes(&r, &pm->p.gcm.ulIvLen);
        pm->p.gcm.ulIvBits = pm->p.gcm.ulIvLen * 8;
        pm->p.gcm.pAAD = rbytes(&r, &pm->p.gcm.ulAADLen);
        pm->p.gcm.ulTagBits = rul(&r);
        pm->m.pParameter = &pm->p.gcm;
        pm->m.ulParameterLen = sizeof pm->p.gcm;
        break;
    case P11_PARAM_OAEP:
        read_oaep(&r, &pm->p.oaep);
        pm->m.pParameter = &pm->p.oaep;
        pm->m.ulParameterLen = sizeof pm->p.oaep;
        break;
    case P11_PARAM_PSS:
        pm->p.pss.hashAlg = rul(&r);
        pm->p.pss.mgf = rul(&r);
        pm->p.pss.sLen = rul(&r);
        pm->m.pParameter = &pm->p.pss;
        pm->m.ulParameterLen = sizeof pm->p.pss;
        break;
    case P11_PARAM_ECDH1:
        pm->p.ecdh1.kdf = rul(&r);
        pm->p.ecdh1.pSharedData = rbytes(&r, &pm->p.ecdh1.ulSharedDataLen);
        pm->p.ecdh1.pPublicData = rbytes(&r, &pm->p.ecdh1.ulPublicDataLen);
        pm->m.pParameter = &pm->p.ecdh1;
        pm->m.ulParameterLen = sizeof pm->p.ecdh1;
        break;
    case P11_PARAM_RSA_AES_KW:
        pm->p.rsa_aes.kw.ulAESKeyBits = rul(&r);
        read_oaep(&r, &pm->p.rsa_aes.oaep);
        pm->p.rsa_aes.kw.pOAEPParams = &pm->p.rsa_aes.oaep;
        pm->m.pParameter = &pm->p.rsa_aes.kw;
        pm->m.ulParameterLen = sizeof pm->p.rsa_aes.kw;
        break;
    case P11_PARAM_EDDSA:
        pm->p.eddsa.phFlag = (CK_BYTE)(r64(&r) != 0);
        pm->p.eddsa.pContextData = rbytes(&r, &pm->p.eddsa.ulContextDataLen);
        pm->m.pParameter = &pm->p.eddsa;
        pm->m.ulParameterLen = sizeof pm->p.eddsa;
        break;
    case P11_PARAM_ULONG:
        pm->p.ul = rul(&r);
        pm->m.pParameter = &pm->p.ul;
        pm->m.ulParameterLen = sizeof pm->p.ul;
        break;
    case P11_PARAM_CCM:
        pm->p.ccm.ulDataLen = rul(&r);
        pm->p.ccm.pNonce = rbytes(&r, &pm->p.ccm.ulNonceLen);
        pm->p.ccm.pAAD = rbytes(&r, &pm->p.ccm.ulAADLen);
        pm->p.ccm.ulMACLen = rul(&r);
        pm->m.pParameter = &pm->p.ccm;
        pm->m.ulParameterLen = sizeof pm->p.ccm;
        break;
    default:
        return 0;
    }
    return r.ok && r.at == r.len;
}

/* --- General ------------------------------------------------------------------ */

uint64_t p11_initialize(uint64_t ctx, uint64_t flags) {
    FL(ctx);
    NEED(FITS(flags));
    CK_C_INITIALIZE_ARGS a;
    memset(&a, 0, sizeof a);
    a.flags = (CK_ULONG)flags;
    return f->C_Initialize(&a);
}

uint64_t p11_finalize(uint64_t ctx) {
    FL(ctx);
    return f->C_Finalize(NULL);
}

/* u64 flags, cryptoki version (2), library version (2), manufacturer (32),
   description (32). */
uint64_t p11_get_info(uint64_t ctx, gs_rref out) {
    FL(ctx);
    CK_INFO i;
    memset(&i, 0, sizeof i);
    CK_RV rv = f->C_GetInfo(&i);
    if (rv != CKR_OK) return rv;
    put64(out, i.flags);
    put_version(out, i.cryptokiVersion);
    put_version(out, i.libraryVersion);
    gs_bld_append(out, i.manufacturerID, 32);
    gs_bld_append(out, i.libraryDescription, 32);
    return rv;
}

/* A list of CK_ULONGs (slots, mechanisms) appended as u64s. */
static uint64_t put_list(gs_rref out, CK_ULONG *xs, CK_ULONG n) {
    for (CK_ULONG i = 0; i < n; i++) put64(out, xs[i]);
    return CKR_OK;
}

uint64_t p11_get_slot_list(uint64_t ctx, uint8_t present, gs_rref out) {
    FL(ctx);
    for (;;) {
        CK_ULONG n = 0;
        CK_RV rv = f->C_GetSlotList(present, NULL, &n);
        if (rv != CKR_OK) return rv;
        CK_ULONG *xs = calloc(n ? n : 1, sizeof *xs);
        if (!xs) return P11_E_MEMORY;
        CK_ULONG cap = n;
        rv = f->C_GetSlotList(present, xs, &n);
        if (rv == CKR_BUFFER_TOO_SMALL) { free(xs); continue; }   /* a slot came */
        if (rv == CKR_OK && n > cap) { free(xs); return P11_E_MODULE; }
        if (rv == CKR_OK) put_list(out, xs, n);
        free(xs);
        return rv;
    }
}

/* u64 flags, hardware version (2), firmware version (2), description (64),
   manufacturer (32). */
uint64_t p11_get_slot_info(uint64_t ctx, uint64_t slot, gs_rref out) {
    FL(ctx);
    NEED(FITS(slot));
    CK_SLOT_INFO i;
    memset(&i, 0, sizeof i);
    CK_RV rv = f->C_GetSlotInfo((CK_ULONG)slot, &i);
    if (rv != CKR_OK) return rv;
    put64(out, i.flags);
    put_version(out, i.hardwareVersion);
    put_version(out, i.firmwareVersion);
    gs_bld_append(out, i.slotDescription, 64);
    gs_bld_append(out, i.manufacturerID, 32);
    return rv;
}

/* 11 u64s (flags, the session counts, the PIN lengths, the memory), hardware
   and firmware versions (2 + 2), label (32), manufacturer (32), model (16),
   serial number (16), UTC time (16). */
uint64_t p11_get_token_info(uint64_t ctx, uint64_t slot, gs_rref out) {
    FL(ctx);
    NEED(FITS(slot));
    CK_TOKEN_INFO i;
    memset(&i, 0, sizeof i);
    CK_RV rv = f->C_GetTokenInfo((CK_ULONG)slot, &i);
    if (rv != CKR_OK) return rv;
    CK_ULONG v[11] = { i.flags, i.ulMaxSessionCount, i.ulSessionCount, i.ulMaxRwSessionCount, i.ulRwSessionCount,
                       i.ulMaxPinLen, i.ulMinPinLen, i.ulTotalPublicMemory, i.ulFreePublicMemory,
                       i.ulTotalPrivateMemory, i.ulFreePrivateMemory };
    for (int k = 0; k < 11; k++) put64(out, v[k] == CK_UNAVAILABLE ? UINT64_MAX : v[k]);
    put_version(out, i.hardwareVersion);
    put_version(out, i.firmwareVersion);
    gs_bld_append(out, i.label, 32);
    gs_bld_append(out, i.manufacturerID, 32);
    gs_bld_append(out, i.model, 16);
    gs_bld_append(out, i.serialNumber, 16);
    gs_bld_append(out, i.utcTime, 16);
    return rv;
}

uint64_t p11_get_mechanism_list(uint64_t ctx, uint64_t slot, gs_rref out) {
    FL(ctx);
    NEED(FITS(slot));
    CK_ULONG n = 0;
    CK_RV rv = f->C_GetMechanismList((CK_ULONG)slot, NULL, &n);
    if (rv != CKR_OK) return rv;
    CK_ULONG *xs = calloc(n ? n : 1, sizeof *xs);
    if (!xs) return P11_E_MEMORY;
    CK_ULONG cap = n;
    rv = f->C_GetMechanismList((CK_ULONG)slot, xs, &n);
    if (rv == CKR_OK && n > cap) { free(xs); return P11_E_MODULE; }
    if (rv == CKR_OK) put_list(out, xs, n);
    free(xs);
    return rv;
}

/* u64 min key size, u64 max key size, u64 flags. */
uint64_t p11_get_mechanism_info(uint64_t ctx, uint64_t slot, uint64_t mech, gs_rref out) {
    FL(ctx);
    NEED(FITS(slot) && FITS(mech));
    CK_MECHANISM_INFO i;
    memset(&i, 0, sizeof i);
    CK_RV rv = f->C_GetMechanismInfo((CK_ULONG)slot, (CK_ULONG)mech, &i);
    if (rv != CKR_OK) return rv;
    put64(out, i.ulMinKeySize);
    put64(out, i.ulMaxKeySize);
    put64(out, i.flags);
    return rv;
}

/* The label is padded with blanks to 32 bytes, as C_InitToken wants it; a
   longer one is refused. */
uint64_t p11_init_token(uint64_t ctx, uint64_t slot, p11_slice pin, p11_slice label) {
    FL(ctx);
    NEED(label.len <= 32 && FITS(slot) && FITS(pin.len));
    CK_BYTE l[32];
    memset(l, ' ', 32);
    memcpy(l, label.data, (size_t)label.len);
    return f->C_InitToken((CK_ULONG)slot, (CK_BYTE *)pin.data, (CK_ULONG)pin.len, l);
}

uint64_t p11_init_pin(uint64_t ctx, uint64_t sh, p11_slice pin) {
    FL(ctx);
    NEED(FITS(sh) && FITS(pin.len));
    return f->C_InitPIN((CK_ULONG)sh, (CK_BYTE *)pin.data, (CK_ULONG)pin.len);
}

uint64_t p11_set_pin(uint64_t ctx, uint64_t sh, p11_slice old, p11_slice pin) {
    FL(ctx);
    NEED(FITS(sh) && FITS(old.len) && FITS(pin.len));
    return f->C_SetPIN((CK_ULONG)sh, (CK_BYTE *)old.data, (CK_ULONG)old.len, (CK_BYTE *)pin.data, (CK_ULONG)pin.len);
}

/* --- Sessions ---------------------------------------------------------------------- */

uint64_t p11_open_session(uint64_t ctx, uint64_t slot, uint64_t flags, uint64_t *sh) {
    FL(ctx);
    NEED(FITS(slot) && FITS(flags));
    CK_ULONG h = 0;
    CK_RV rv = f->C_OpenSession((CK_ULONG)slot, (CK_ULONG)flags, NULL, NULL, &h);
    *sh = h;
    return rv;
}

uint64_t p11_close_session(uint64_t ctx, uint64_t sh) { FL(ctx); NEED(FITS(sh)); return f->C_CloseSession((CK_ULONG)sh); }
uint64_t p11_close_all_sessions(uint64_t ctx, uint64_t slot) { FL(ctx); NEED(FITS(slot)); return f->C_CloseAllSessions((CK_ULONG)slot); }

/* u64 slot, u64 state, u64 flags, u64 device error. */
uint64_t p11_get_session_info(uint64_t ctx, uint64_t sh, gs_rref out) {
    FL(ctx);
    NEED(FITS(sh));
    CK_SESSION_INFO i;
    memset(&i, 0, sizeof i);
    CK_RV rv = f->C_GetSessionInfo((CK_ULONG)sh, &i);
    if (rv != CKR_OK) return rv;
    put64(out, i.slotID);
    put64(out, i.state);
    put64(out, i.flags);
    put64(out, i.ulDeviceError);
    return rv;
}

uint64_t p11_login(uint64_t ctx, uint64_t sh, uint64_t user, p11_slice pin) {
    FL(ctx);
    NEED(FITS(sh) && FITS(user) && FITS(pin.len));
    return f->C_Login((CK_ULONG)sh, (CK_ULONG)user, (CK_BYTE *)pin.data, (CK_ULONG)pin.len);
}

uint64_t p11_logout(uint64_t ctx, uint64_t sh) { FL(ctx); NEED(FITS(sh)); return f->C_Logout((CK_ULONG)sh); }

uint64_t p11_set_operation_state(uint64_t ctx, uint64_t sh, p11_slice state, uint64_t enc, uint64_t auth) {
    FL(ctx);
    NEED(FITS(sh) && FITS(state.len) && FITS(enc) && FITS(auth));
    return f->C_SetOperationState((CK_ULONG)sh, (CK_BYTE *)state.data, (CK_ULONG)state.len, (CK_ULONG)enc,
                                  (CK_ULONG)auth);
}

/* --- Objects ------------------------------------------------------------------------- */

uint64_t p11_create_object(uint64_t ctx, uint64_t sh, p11_slice t, uint64_t *obj) {
    FL(ctx);
    NEED(FITS(sh));
    CK_ATTRIBUTE *a;
    CK_ULONG n;
    if (!decode_template(t, &a, &n)) return P11_E_ENCODING;
    CK_ULONG h = 0;
    CK_RV rv = f->C_CreateObject((CK_ULONG)sh, a, n, &h);
    free(a);
    *obj = h;
    return rv;
}

uint64_t p11_copy_object(uint64_t ctx, uint64_t sh, uint64_t o, p11_slice t, uint64_t *obj) {
    FL(ctx);
    NEED(FITS(sh) && FITS(o));
    CK_ATTRIBUTE *a;
    CK_ULONG n;
    if (!decode_template(t, &a, &n)) return P11_E_ENCODING;
    CK_ULONG h = 0;
    CK_RV rv = f->C_CopyObject((CK_ULONG)sh, (CK_ULONG)o, a, n, &h);
    free(a);
    *obj = h;
    return rv;
}

uint64_t p11_destroy_object(uint64_t ctx, uint64_t sh, uint64_t o) { FL(ctx); NEED(FITS(sh) && FITS(o)); return f->C_DestroyObject((CK_ULONG)sh, (CK_ULONG)o); }

uint64_t p11_get_object_size(uint64_t ctx, uint64_t sh, uint64_t o, uint64_t *size) {
    FL(ctx);
    NEED(FITS(sh) && FITS(o));
    CK_ULONG n = 0;
    CK_RV rv = f->C_GetObjectSize((CK_ULONG)sh, (CK_ULONG)o, &n);
    *size = n == CK_UNAVAILABLE ? UINT64_MAX : n;
    return rv;
}

/* The attributes of the types listed (u64s) appended as { u64 type, u64 len,
   len bytes }, len 2^64 - 1 with no bytes for one the module cannot give
   (sensitive, or not the object's). The module's result is returned: it
   may be CKR_ATTRIBUTE_SENSITIVE or CKR_ATTRIBUTE_TYPE_INVALID with the
   other attributes all there. */
uint64_t p11_get_attribute_value(uint64_t ctx, uint64_t sh, uint64_t o, p11_slice types, gs_rref out) {
    FL(ctx);
    NEED(FITS(sh) && FITS(o));
    if (types.len % 8 != 0) return P11_E_ENCODING;
    CK_ULONG n = (CK_ULONG)(types.len / 8);
    if (n == 0) return CKR_OK;
    CK_ATTRIBUTE *a = calloc(n, sizeof *a);
    if (!a) return P11_E_MEMORY;
    for (CK_ULONG i = 0; i < n; i++) {
        uint64_t ty = get64(types.data + 8 * i);
        if (!FITS(ty)) { free(a); return P11_E_ENCODING; }
        a[i].type = (CK_ULONG)ty;
    }
    /* uint64_t, not CK_RV: P11_E_MEMORY does not fit Windows' 32-bit CK_ULONG. */
    uint64_t rv = f->C_GetAttributeValue((CK_ULONG)sh, (CK_ULONG)o, a, n);
    int usable = rv == CKR_OK || rv == 0x11 /* SENSITIVE */ || rv == 0x12 /* TYPE_INVALID */;
    if (!usable) { free(a); return rv; }
    for (CK_ULONG i = 0; i < n; i++) {
        if (a[i].ulValueLen != CK_UNAVAILABLE) {
            a[i].pValue = malloc(a[i].ulValueLen ? a[i].ulValueLen : 1);
            if (!a[i].pValue) rv = P11_E_MEMORY;
        }
    }
    if (rv != P11_E_MEMORY) {
        /* Only the attributes that have a value are asked again. */
        CK_ATTRIBUTE *b = calloc(n, sizeof *b);
        CK_ULONG m = 0;
        if (!b) rv = P11_E_MEMORY;
        else {
            for (CK_ULONG i = 0; i < n; i++) if (a[i].pValue) b[m++] = a[i];
            CK_RV rv2 = m ? f->C_GetAttributeValue((CK_ULONG)sh, (CK_ULONG)o, b, m) : CKR_OK;
            int past = 0;
            m = 0;
            for (CK_ULONG i = 0; i < n; i++) {
                if (!a[i].pValue) continue;
                CK_ULONG got = b[m++].ulValueLen;
                /* Longer than the first call said: past the buffer. */
                if (got != CK_UNAVAILABLE && got > a[i].ulValueLen) past = 1;
                a[i].ulValueLen = got;
            }
            free(b);
            if (rv2 != CKR_OK) rv = rv2;
            if (past) rv = P11_E_MODULE;
            for (CK_ULONG i = 0; i < n && !past; i++) {
                put64(out, a[i].type);
                if (!a[i].pValue || a[i].ulValueLen == CK_UNAVAILABLE) {
                    put64(out, UINT64_MAX);
                } else {
                    put64(out, a[i].ulValueLen);
                    gs_bld_append(out, a[i].pValue, (int64_t)a[i].ulValueLen);
                }
            }
        }
    }
    for (CK_ULONG i = 0; i < n; i++) free(a[i].pValue);
    free(a);
    return rv;
}

uint64_t p11_set_attribute_value(uint64_t ctx, uint64_t sh, uint64_t o, p11_slice t) {
    FL(ctx);
    NEED(FITS(sh) && FITS(o));
    CK_ATTRIBUTE *a;
    CK_ULONG n;
    if (!decode_template(t, &a, &n)) return P11_E_ENCODING;
    CK_RV rv = f->C_SetAttributeValue((CK_ULONG)sh, (CK_ULONG)o, a, n);
    free(a);
    return rv;
}

uint64_t p11_find_objects_init(uint64_t ctx, uint64_t sh, p11_slice t) {
    FL(ctx);
    NEED(FITS(sh));
    CK_ATTRIBUTE *a;
    CK_ULONG n;
    if (!decode_template(t, &a, &n)) return P11_E_ENCODING;
    CK_RV rv = f->C_FindObjectsInit((CK_ULONG)sh, a, n);
    free(a);
    return rv;
}

/* Up to max handles, appended as u64s. */
uint64_t p11_find_objects(uint64_t ctx, uint64_t sh, uint64_t max, gs_rref out) {
    FL(ctx);
    NEED(FITS(sh) && FITS(max));
    if (max == 0) return CKR_OK;
    CK_ULONG *xs = calloc((size_t)max, sizeof *xs);
    if (!xs) return P11_E_MEMORY;
    CK_ULONG n = 0;
    CK_RV rv = f->C_FindObjects((CK_ULONG)sh, xs, (CK_ULONG)max, &n);
    if (rv == CKR_OK && n > max) { free(xs); return P11_E_MODULE; }
    if (rv == CKR_OK) put_list(out, xs, n);
    free(xs);
    return rv;
}

uint64_t p11_find_objects_final(uint64_t ctx, uint64_t sh) { FL(ctx); NEED(FITS(sh)); return f->C_FindObjectsFinal((CK_ULONG)sh); }

/* --- Cryptographic operations ------------------------------------------------------- */

/* The operations that start with an Init (pkcs11.goose's OP_*). */
#define OP_ENCRYPT 1
#define OP_DECRYPT 2
#define OP_DIGEST 3
#define OP_SIGN 4
#define OP_SIGN_RECOVER 5
#define OP_VERIFY 6
#define OP_VERIFY_RECOVER 7

uint64_t p11_op_init(uint64_t ctx, int64_t op, uint64_t sh, p11_slice mech, uint64_t key) {
    FL(ctx);
    NEED(FITS(sh) && FITS(key));
    p11_mech pm;
    if (!decode_mechanism(mech, &pm)) return P11_E_ENCODING;
    CK_ULONG s = (CK_ULONG)sh, k = (CK_ULONG)key;
    switch (op) {
    case OP_ENCRYPT: return f->C_EncryptInit(s, &pm.m, k);
    case OP_DECRYPT: return f->C_DecryptInit(s, &pm.m, k);
    case OP_DIGEST: return f->C_DigestInit(s, &pm.m);
    case OP_SIGN: return f->C_SignInit(s, &pm.m, k);
    case OP_SIGN_RECOVER: return f->C_SignRecoverInit(s, &pm.m, k);
    case OP_VERIFY: return f->C_VerifyInit(s, &pm.m, k);
    case OP_VERIFY_RECOVER: return f->C_VerifyRecoverInit(s, &pm.m, k);
    }
    return P11_E_ENCODING;
}

/* The calls that take data and give data, by the convention of PKCS#11 §5.2:
   one call with no buffer for the length, then one with a buffer of it. */
#define IO_ENCRYPT 1
#define IO_ENCRYPT_UPDATE 2
#define IO_DECRYPT 3
#define IO_DECRYPT_UPDATE 4
#define IO_DIGEST 5
#define IO_SIGN 6
#define IO_SIGN_RECOVER 7
#define IO_VERIFY_RECOVER 8
#define IO_DIGEST_ENCRYPT_UPDATE 9
#define IO_DECRYPT_DIGEST_UPDATE 10
#define IO_SIGN_ENCRYPT_UPDATE 11
#define IO_DECRYPT_VERIFY_UPDATE 12
/* and those that only give it */
#define IO_ENCRYPT_FINAL 20
#define IO_DECRYPT_FINAL 21
#define IO_DIGEST_FINAL 22
#define IO_SIGN_FINAL 23
#define IO_GET_OPERATION_STATE 24

static uint64_t io_call(CK_FUNCTION_LIST *f, int64_t op, CK_ULONG s, CK_BYTE *in, CK_ULONG inlen, CK_BYTE *out,
                     CK_ULONG *outlen, int *known) {
    *known = 1;
    switch (op) {
    case IO_ENCRYPT: return f->C_Encrypt(s, in, inlen, out, outlen);
    case IO_ENCRYPT_UPDATE: return f->C_EncryptUpdate(s, in, inlen, out, outlen);
    case IO_DECRYPT: return f->C_Decrypt(s, in, inlen, out, outlen);
    case IO_DECRYPT_UPDATE: return f->C_DecryptUpdate(s, in, inlen, out, outlen);
    case IO_DIGEST: return f->C_Digest(s, in, inlen, out, outlen);
    case IO_SIGN: return f->C_Sign(s, in, inlen, out, outlen);
    case IO_SIGN_RECOVER: return f->C_SignRecover(s, in, inlen, out, outlen);
    case IO_VERIFY_RECOVER: return f->C_VerifyRecover(s, in, inlen, out, outlen);
    case IO_DIGEST_ENCRYPT_UPDATE: return f->C_DigestEncryptUpdate(s, in, inlen, out, outlen);
    case IO_DECRYPT_DIGEST_UPDATE: return f->C_DecryptDigestUpdate(s, in, inlen, out, outlen);
    case IO_SIGN_ENCRYPT_UPDATE: return f->C_SignEncryptUpdate(s, in, inlen, out, outlen);
    case IO_DECRYPT_VERIFY_UPDATE: return f->C_DecryptVerifyUpdate(s, in, inlen, out, outlen);
    case IO_ENCRYPT_FINAL: return f->C_EncryptFinal(s, out, outlen);
    case IO_DECRYPT_FINAL: return f->C_DecryptFinal(s, out, outlen);
    case IO_DIGEST_FINAL: return f->C_DigestFinal(s, out, outlen);
    case IO_SIGN_FINAL: return f->C_SignFinal(s, out, outlen);
    case IO_GET_OPERATION_STATE: return f->C_GetOperationState(s, out, outlen);
    }
    *known = 0;
    return P11_E_ENCODING;
}

uint64_t p11_io(uint64_t ctx, int64_t op, uint64_t sh, p11_slice in, gs_rref out) {
    FL(ctx);
    NEED(FITS(sh) && FITS(in.len));
    int known;
    CK_ULONG n = 0;
    uint64_t rv = io_call(f, op, (CK_ULONG)sh, (CK_BYTE *)in.data, (CK_ULONG)in.len, NULL, &n, &known);
    if (!known || rv != CKR_OK) return rv;
    for (int tries = 0; tries < 4; tries++) {
        CK_BYTE *buf = malloc(n ? n : 1);
        if (!buf) return P11_E_MEMORY;
        CK_ULONG m = n;
        rv = io_call(f, op, (CK_ULONG)sh, (CK_BYTE *)in.data, (CK_ULONG)in.len, buf, &m, &known);
        if (rv == CKR_BUFFER_TOO_SMALL && m > n) { n = m; free(buf); continue; }
        if (rv == CKR_OK && m > n) rv = P11_E_MODULE;
        if (rv == CKR_OK) gs_bld_append(out, buf, (int64_t)m);
        free(buf);
        return rv;
    }
    return rv;
}

/* The calls that only take data. */
#define IN_DIGEST_UPDATE 1
#define IN_SIGN_UPDATE 2
#define IN_VERIFY_UPDATE 3
#define IN_VERIFY_FINAL 4
#define IN_SEED_RANDOM 5

uint64_t p11_in(uint64_t ctx, int64_t op, uint64_t sh, p11_slice in) {
    FL(ctx);
    NEED(FITS(sh) && FITS(in.len));
    CK_ULONG s = (CK_ULONG)sh;
    CK_BYTE *d = (CK_BYTE *)in.data;
    CK_ULONG n = (CK_ULONG)in.len;
    switch (op) {
    case IN_DIGEST_UPDATE: return f->C_DigestUpdate(s, d, n);
    case IN_SIGN_UPDATE: return f->C_SignUpdate(s, d, n);
    case IN_VERIFY_UPDATE: return f->C_VerifyUpdate(s, d, n);
    case IN_VERIFY_FINAL: return f->C_VerifyFinal(s, d, n);
    case IN_SEED_RANDOM: return f->C_SeedRandom(s, d, n);
    }
    return P11_E_ENCODING;
}

uint64_t p11_verify(uint64_t ctx, uint64_t sh, p11_slice data, p11_slice sig) {
    FL(ctx);
    NEED(FITS(sh) && FITS(data.len) && FITS(sig.len));
    return f->C_Verify((CK_ULONG)sh, (CK_BYTE *)data.data, (CK_ULONG)data.len, (CK_BYTE *)sig.data,
                       (CK_ULONG)sig.len);
}

uint64_t p11_digest_key(uint64_t ctx, uint64_t sh, uint64_t key) { FL(ctx); NEED(FITS(sh) && FITS(key)); return f->C_DigestKey((CK_ULONG)sh, (CK_ULONG)key); }

/* --- Keys ----------------------------------------------------------------------------- */

uint64_t p11_generate_key(uint64_t ctx, uint64_t sh, p11_slice mech, p11_slice t, uint64_t *key) {
    FL(ctx);
    NEED(FITS(sh));
    p11_mech pm;
    CK_ATTRIBUTE *a;
    CK_ULONG n;
    if (!decode_mechanism(mech, &pm) || !decode_template(t, &a, &n)) return P11_E_ENCODING;
    CK_ULONG h = 0;
    CK_RV rv = f->C_GenerateKey((CK_ULONG)sh, &pm.m, a, n, &h);
    free(a);
    *key = h;
    return rv;
}

uint64_t p11_generate_key_pair(uint64_t ctx, uint64_t sh, p11_slice mech, p11_slice pubt, p11_slice privt,
                               uint64_t *pub, uint64_t *priv) {
    FL(ctx);
    NEED(FITS(sh));
    p11_mech pm;
    CK_ATTRIBUTE *a, *b;
    CK_ULONG na, nb;
    if (!decode_mechanism(mech, &pm) || !decode_template(pubt, &a, &na)) return P11_E_ENCODING;
    if (!decode_template(privt, &b, &nb)) { free(a); return P11_E_ENCODING; }
    CK_ULONG h1 = 0, h2 = 0;
    CK_RV rv = f->C_GenerateKeyPair((CK_ULONG)sh, &pm.m, a, na, b, nb, &h1, &h2);
    free(a);
    free(b);
    *pub = h1;
    *priv = h2;
    return rv;
}

uint64_t p11_wrap_key(uint64_t ctx, uint64_t sh, p11_slice mech, uint64_t wrapping, uint64_t key, gs_rref out) {
    FL(ctx);
    NEED(FITS(sh) && FITS(wrapping) && FITS(key));
    p11_mech pm;
    if (!decode_mechanism(mech, &pm)) return P11_E_ENCODING;
    CK_ULONG n = 0;
    CK_RV rv = f->C_WrapKey((CK_ULONG)sh, &pm.m, (CK_ULONG)wrapping, (CK_ULONG)key, NULL, &n);
    if (rv != CKR_OK) return rv;
    CK_BYTE *buf = malloc(n ? n : 1);
    if (!buf) return P11_E_MEMORY;
    CK_ULONG cap = n;
    rv = f->C_WrapKey((CK_ULONG)sh, &pm.m, (CK_ULONG)wrapping, (CK_ULONG)key, buf, &n);
    if (rv == CKR_OK && n > cap) { free(buf); return P11_E_MODULE; }
    if (rv == CKR_OK) gs_bld_append(out, buf, (int64_t)n);
    free(buf);
    return rv;
}

uint64_t p11_unwrap_key(uint64_t ctx, uint64_t sh, p11_slice mech, uint64_t unwrapping, p11_slice wrapped,
                        p11_slice t, uint64_t *key) {
    FL(ctx);
    NEED(FITS(sh) && FITS(unwrapping) && FITS(wrapped.len));
    p11_mech pm;
    CK_ATTRIBUTE *a;
    CK_ULONG n;
    if (!decode_mechanism(mech, &pm) || !decode_template(t, &a, &n)) return P11_E_ENCODING;
    CK_ULONG h = 0;
    CK_RV rv = f->C_UnwrapKey((CK_ULONG)sh, &pm.m, (CK_ULONG)unwrapping, (CK_BYTE *)wrapped.data,
                              (CK_ULONG)wrapped.len, a, n, &h);
    free(a);
    *key = h;
    return rv;
}

uint64_t p11_derive_key(uint64_t ctx, uint64_t sh, p11_slice mech, uint64_t base, p11_slice t, uint64_t *key) {
    FL(ctx);
    NEED(FITS(sh) && FITS(base));
    p11_mech pm;
    CK_ATTRIBUTE *a;
    CK_ULONG n;
    if (!decode_mechanism(mech, &pm) || !decode_template(t, &a, &n)) return P11_E_ENCODING;
    CK_ULONG h = 0;
    CK_RV rv = f->C_DeriveKey((CK_ULONG)sh, &pm.m, (CK_ULONG)base, a, n, &h);
    free(a);
    *key = h;
    return rv;
}

uint64_t p11_generate_random(uint64_t ctx, uint64_t sh, uint64_t len, gs_rref out) {
    FL(ctx);
    NEED(FITS(sh) && FITS(len));
    CK_BYTE *buf = malloc(len ? (size_t)len : 1);
    if (!buf) return P11_E_MEMORY;
    CK_RV rv = f->C_GenerateRandom((CK_ULONG)sh, buf, (CK_ULONG)len);
    if (rv == CKR_OK) gs_bld_append(out, buf, (int64_t)len);
    free(buf);
    return rv;
}

uint64_t p11_wait_for_slot_event(uint64_t ctx, uint64_t flags, uint64_t *slot) {
    FL(ctx);
    NEED(FITS(flags));
    CK_ULONG s = 0;
    CK_RV rv = f->C_WaitForSlotEvent((CK_ULONG)flags, &s, NULL);
    *slot = s;
    return rv;
}

uint64_t p11_get_function_status(uint64_t ctx, uint64_t sh) { FL(ctx); NEED(FITS(sh)); return f->C_GetFunctionStatus((CK_ULONG)sh); }
uint64_t p11_cancel_function(uint64_t ctx, uint64_t sh) { FL(ctx); NEED(FITS(sh)); return f->C_CancelFunction((CK_ULONG)sh); }
