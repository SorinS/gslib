// tpm2: a TPM 2.0 client, after go-tpm's tpm2 package and go-tpm-tools'
// attestation checks. The wire format of TPM Library Part 2 (commands,
// responses, the TPM2B/TPML/TPMS/TPMT structures the commands below
// need), response codes decoded to their names, and transports: raw TCP
// (swtpm's data channel), the Microsoft simulator's protocol (mssim, with
// its platform channel), Linux's /dev/tpmrm0 and a note for Windows' TBS.
// Sessions (tpm2.session): password, HMAC (bound, salted by RSA-OAEP or
// ECDH, AES-CFB parameter encryption both ways) and policy, with the
// policy assertions and a software policy calculator (tpm2.policy).
// Objects, keys, NV, PCRs and hashing (tpm2.commands); attestation: Quote,
// Certify, CertifyCreation, their verification in software, TCG event
// logs replayed to PCRs, and MakeCredential / ActivateCredential
// (tpm2.attest).
//
//   var t, err = tpm2::open("tcp:127.0.0.1:2321");   // or mssim:H:P, device:/dev/tpmrm0
//   tpm2::startup(t);
//   let srk, e = tpm2::create_primary(t, tpm2::owner(), tpm2::srk_rsa_template());
//   let ak, e2 = tpm2::create_key(t, srk, tpm2::ak_ecc_template());
//   ...
//   tpm2::close(t);
//
// This file: constants, the marshalling helpers, response codes, TPMT_PUBLIC
// and TPMT_SIGNATURE, Names, the TCG templates, KDFa and KDFe, and keys to
// and from SubjectPublicKeyInfo.
//
// Every structure from a TPM is read with its sizes checked against what
// is left and against the structure's own maximum: a size field that lies,
// a TPM2B larger than the buffer or its type, or bytes left over, refuse
// the whole response (ERR_MALFORMED). Nothing is cut to fit.

namespace tpm2;

import std;
import crypto.bignum;
import crypto.bignum.sha1;
import crypto.bignum.sha256;
import crypto.bignum.sha512;
import crypto.bignum.hmac;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import crypto.bignum.entropy;
import crypto.x509;
import encoding.asn1;

// --- Errors -------------------------------------------------------------------

let OK:              i64 = 0;
let ERR_ARG:         i64 = 1;   // an argument that cannot be used
let ERR_TRANSPORT:   i64 = 2;   // the connection or device failed (t.io says how)
let ERR_TPM:         i64 = 3;   // the TPM refused: its response code is t.rc (rc_text)
let ERR_MALFORMED:   i64 = 4;   // a response or structure that is not what Part 2 says
let ERR_INTEGRITY:   i64 = 5;   // a response HMAC (rpHash) that does not verify
let ERR_SIGNATURE:   i64 = 6;   // a signature that does not verify
let ERR_NONCE:       i64 = 7;   // extraData is not the nonce asked for
let ERR_PCR:         i64 = 8;   // the PCR digest is not that of the PCR values given
let ERR_UNSUPPORTED: i64 = 9;   // an algorithm, curve or key size this library does not do
let ERR_NAME:        i64 = 10;  // a Name the TPM gave is not the one computed here
let ERR_TYPE:        i64 = 11;  // a TPMS_ATTEST of another type than asked for
let ERR_EVENTLOG:    i64 = 12;  // an event log that cannot be read or replayed

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "bad argument"; }
    if e == ERR_TRANSPORT { return "transport failed"; }
    if e == ERR_TPM { return "the TPM refused"; }
    if e == ERR_MALFORMED { return "malformed response or structure"; }
    if e == ERR_INTEGRITY { return "response HMAC does not verify"; }
    if e == ERR_SIGNATURE { return "signature does not verify"; }
    if e == ERR_NONCE { return "nonce (extraData) mismatch"; }
    if e == ERR_PCR { return "PCR digest mismatch"; }
    if e == ERR_UNSUPPORTED { return "unsupported algorithm"; }
    if e == ERR_NAME { return "Name mismatch"; }
    if e == ERR_TYPE { return "wrong attestation type"; }
    if e == ERR_EVENTLOG { return "event log cannot be replayed"; }
    return "unknown error";
}

// --- Constants (Part 2) ---------------------------------------------------------

let ST_NO_SESSIONS:          u16 = 0x8001;
let ST_SESSIONS:             u16 = 0x8002;
let ST_ATTEST_NV:            u16 = 0x8014;
let ST_ATTEST_COMMAND_AUDIT: u16 = 0x8015;
let ST_ATTEST_SESSION_AUDIT: u16 = 0x8016;
let ST_ATTEST_CERTIFY:       u16 = 0x8017;
let ST_ATTEST_QUOTE:         u16 = 0x8018;
let ST_ATTEST_TIME:          u16 = 0x8019;
let ST_ATTEST_CREATION:      u16 = 0x801A;
let ST_CREATION:             u16 = 0x8021;
let ST_VERIFIED:             u16 = 0x8022;
let ST_AUTH_SECRET:          u16 = 0x8023;
let ST_HASHCHECK:            u16 = 0x8024;
let ST_AUTH_SIGNED:          u16 = 0x8025;

let GENERATED_VALUE: u32 = 0xff544347;   // TPM_GENERATED_VALUE, "\xffTCG"

let CC_NV_UndefineSpaceSpecial:   u32 = 0x11F;
let CC_EvictControl:              u32 = 0x120;
let CC_NV_UndefineSpace:          u32 = 0x122;
let CC_Clear:                     u32 = 0x126;
let CC_HierarchyChangeAuth:       u32 = 0x129;
let CC_NV_DefineSpace:            u32 = 0x12A;
let CC_CreatePrimary:             u32 = 0x131;
let CC_NV_Increment:              u32 = 0x134;
let CC_NV_SetBits:                u32 = 0x135;
let CC_NV_Extend:                 u32 = 0x136;
let CC_NV_Write:                  u32 = 0x137;
let CC_NV_WriteLock:              u32 = 0x138;
let CC_DictionaryAttackLockReset: u32 = 0x139;
let CC_PCR_Event:                 u32 = 0x13C;
let CC_PCR_Reset:                 u32 = 0x13D;
let CC_SelfTest:                  u32 = 0x143;
let CC_Startup:                   u32 = 0x144;
let CC_Shutdown:                  u32 = 0x145;
let CC_StirRandom:                u32 = 0x146;
let CC_ActivateCredential:        u32 = 0x147;
let CC_Certify:                   u32 = 0x148;
let CC_PolicyNV:                  u32 = 0x149;
let CC_CertifyCreation:           u32 = 0x14A;
let CC_Duplicate:                 u32 = 0x14B;
let CC_GetTime:                   u32 = 0x14C;
let CC_NV_Read:                   u32 = 0x14E;
let CC_NV_ReadLock:               u32 = 0x14F;
let CC_ObjectChangeAuth:          u32 = 0x150;
let CC_PolicySecret:              u32 = 0x151;
let CC_Create:                    u32 = 0x153;
let CC_ECDH_ZGen:                 u32 = 0x154;
let CC_HMAC:                      u32 = 0x155;
let CC_Import:                    u32 = 0x156;
let CC_Load:                      u32 = 0x157;
let CC_Quote:                     u32 = 0x158;
let CC_RSA_Decrypt:               u32 = 0x159;
let CC_Sign:                      u32 = 0x15D;
let CC_Unseal:                    u32 = 0x15E;
let CC_PolicySigned:              u32 = 0x160;
let CC_ContextLoad:               u32 = 0x161;
let CC_ContextSave:               u32 = 0x162;
let CC_ECDH_KeyGen:               u32 = 0x163;
let CC_EncryptDecrypt:            u32 = 0x164;
let CC_FlushContext:              u32 = 0x165;
let CC_LoadExternal:              u32 = 0x167;
let CC_MakeCredential:            u32 = 0x168;
let CC_NV_ReadPublic:             u32 = 0x169;
let CC_PolicyAuthorize:           u32 = 0x16A;
let CC_PolicyAuthValue:           u32 = 0x16B;
let CC_PolicyCommandCode:         u32 = 0x16C;
let CC_PolicyCounterTimer:        u32 = 0x16D;
let CC_PolicyCpHash:              u32 = 0x16E;
let CC_PolicyLocality:            u32 = 0x16F;
let CC_PolicyNameHash:            u32 = 0x170;
let CC_PolicyOR:                  u32 = 0x171;
let CC_PolicyTicket:              u32 = 0x172;
let CC_ReadPublic:                u32 = 0x173;
let CC_RSA_Encrypt:               u32 = 0x174;
let CC_StartAuthSession:          u32 = 0x176;
let CC_VerifySignature:           u32 = 0x177;
let CC_ECC_Parameters:            u32 = 0x178;
let CC_GetCapability:             u32 = 0x17A;
let CC_GetRandom:                 u32 = 0x17B;
let CC_GetTestResult:             u32 = 0x17C;
let CC_Hash:                      u32 = 0x17D;
let CC_PCR_Read:                  u32 = 0x17E;
let CC_PolicyPCR:                 u32 = 0x17F;
let CC_PolicyRestart:             u32 = 0x180;
let CC_ReadClock:                 u32 = 0x181;
let CC_PCR_Extend:                u32 = 0x182;
let CC_NV_Certify:                u32 = 0x184;
let CC_PolicyGetDigest:           u32 = 0x189;
let CC_PolicyPassword:            u32 = 0x18C;
let CC_CreateLoaded:              u32 = 0x191;

let ALG_ERROR:          u16 = 0x0000;
let ALG_RSA:            u16 = 0x0001;
let ALG_SHA1:           u16 = 0x0004;
let ALG_HMAC:           u16 = 0x0005;
let ALG_AES:            u16 = 0x0006;
let ALG_KEYEDHASH:      u16 = 0x0008;
let ALG_XOR:            u16 = 0x000A;
let ALG_SHA256:         u16 = 0x000B;
let ALG_SHA384:         u16 = 0x000C;
let ALG_SHA512:         u16 = 0x000D;
let ALG_NULL:           u16 = 0x0010;
let ALG_SM3_256:        u16 = 0x0012;
let ALG_RSASSA:         u16 = 0x0014;
let ALG_RSAES:          u16 = 0x0015;
let ALG_RSAPSS:         u16 = 0x0016;
let ALG_OAEP:           u16 = 0x0017;
let ALG_ECDSA:          u16 = 0x0018;
let ALG_ECDH:           u16 = 0x0019;
let ALG_ECDAA:          u16 = 0x001A;
let ALG_SM2:            u16 = 0x001B;
let ALG_ECSCHNORR:      u16 = 0x001C;
let ALG_ECMQV:          u16 = 0x001D;
let ALG_KDF1_SP800_56A: u16 = 0x0020;
let ALG_KDF2:           u16 = 0x0021;
let ALG_KDF1_SP800_108: u16 = 0x0022;
let ALG_ECC:            u16 = 0x0023;
let ALG_SYMCIPHER:      u16 = 0x0025;
let ALG_CTR:            u16 = 0x0040;
let ALG_OFB:            u16 = 0x0041;
let ALG_CBC:            u16 = 0x0042;
let ALG_CFB:            u16 = 0x0043;
let ALG_ECB:            u16 = 0x0044;

let ECC_NIST_P256: u16 = 0x0003;
let ECC_NIST_P384: u16 = 0x0004;
let ECC_NIST_P521: u16 = 0x0005;

// TPMA_OBJECT
let OBJ_FIXED_TPM:             u32 = 0x00000002;
let OBJ_ST_CLEAR:              u32 = 0x00000004;
let OBJ_FIXED_PARENT:          u32 = 0x00000010;
let OBJ_SENSITIVE_DATA_ORIGIN: u32 = 0x00000020;
let OBJ_USER_WITH_AUTH:        u32 = 0x00000040;
let OBJ_ADMIN_WITH_POLICY:     u32 = 0x00000080;
let OBJ_NO_DA:                 u32 = 0x00000400;
let OBJ_ENCRYPTED_DUPLICATION: u32 = 0x00000800;
let OBJ_RESTRICTED:            u32 = 0x00010000;
let OBJ_DECRYPT:               u32 = 0x00020000;
let OBJ_SIGN:                  u32 = 0x00040000;

// Handles
let RH_OWNER:          u32 = 0x40000001;
let RS_PW:             u32 = 0x40000009;
let RH_LOCKOUT:        u32 = 0x4000000A;
let RH_ENDORSEMENT:    u32 = 0x4000000B;
let RH_PLATFORM:       u32 = 0x4000000C;
let RH_NULL:           u32 = 0x40000007;
let HT_PCR:            u8  = 0x00;
let HT_NV_INDEX:       u8  = 0x01;
let HT_HMAC_SESSION:   u8  = 0x02;
let HT_POLICY_SESSION: u8  = 0x03;
let HT_PERMANENT:      u8  = 0x40;
let HT_TRANSIENT:      u8  = 0x80;
let HT_PERSISTENT:     u8  = 0x81;

// The EK certificate indices of the TCG EK Credential Profile (§2.2.1.4).
let EK_CERT_RSA_INDEX:      u32 = 0x01C00002;
let EK_NONCE_RSA_INDEX:     u32 = 0x01C00003;
let EK_TEMPLATE_RSA_INDEX:  u32 = 0x01C00004;
let EK_CERT_ECC_INDEX:      u32 = 0x01C0000A;
let EK_NONCE_ECC_INDEX:     u32 = 0x01C0000B;
let EK_TEMPLATE_ECC_INDEX:  u32 = 0x01C0000C;
let EK_CERT_ECC_P384_INDEX: u32 = 0x01C00016;   // the high range's NIST P-384 EK (template H-3)

// TPM_SU
let SU_CLEAR: u16 = 0x0000;
let SU_STATE: u16 = 0x0001;

// TPM_CAP and TPM_PT
let CAP_ALGS:              u32 = 0;
let CAP_HANDLES:           u32 = 1;
let CAP_COMMANDS:          u32 = 2;
let CAP_PCRS:              u32 = 5;
let CAP_TPM_PROPERTIES:    u32 = 6;
let CAP_ECC_CURVES:        u32 = 8;
let PT_FIXED:              u32 = 0x100;
let PT_FAMILY_INDICATOR:   u32 = 0x100;
let PT_MANUFACTURER:       u32 = 0x105;
let PT_VENDOR_STRING_1:    u32 = 0x106;
let PT_FIRMWARE_VERSION_1: u32 = 0x10B;
let PT_INPUT_BUFFER:       u32 = 0x10D;
let PT_MAX_DIGEST:         u32 = 0x120;
let PT_NV_BUFFER_MAX:      u32 = 0x12C;

// Response codes (Part 2 §6.6).
let RC_SUCCESS:     u32 = 0x000;
let RC_BAD_TAG:     u32 = 0x01E;
let RC_VER1:        u32 = 0x100;
let RC_INITIALIZE:  u32 = 0x100;
let RC_FMT1:        u32 = 0x080;
let RC_WARN:        u32 = 0x900;
let RC_HANDLE:      u32 = 0x08B;
let RC_POLICY_FAIL: u32 = 0x09D;
let RC_AUTH_FAIL:   u32 = 0x08E;
let RC_BAD_AUTH:    u32 = 0x0A2;
let RC_VALUE:       u32 = 0x084;
let RC_PCR_CHANGED: u32 = 0x128;
let RC_NV_DEFINED:  u32 = 0x14C;
let RC_INTEGRITY:   u32 = 0x09F;
let RC_RETRY:       u32 = 0x922;
let RC_TESTING:     u32 = 0x90A;
let RC_YIELDED:     u32 = 0x908;

// Largest sizes this library keeps (the reference implementation's).
let MAX_DIGEST:        i64 = 64;   // SHA-512
let MAX_NAME:          i64 = 66;   // nameAlg and a SHA-512 digest
let MAX_RSA_BYTES:     i64 = 512;  // RSA-4096
let MAX_ECC_BYTES:     i64 = 66;   // P-521
let MAX_RESPONSE:      i64 = 8192; // larger responses are refused
let MAX_PRIVATE:       i64 = 2048; // TPM2B_PRIVATE
let MAX_CONTEXT:       i64 = 5120; // TPMS_CONTEXT's blob
let MAX_NV:            i64 = 2048; // an NV index's data
let MAX_ATTEST:        i64 = 1024; // TPM2B_ATTEST
let MAX_CREATION_DATA: i64 = 1024; // TPMS_CREATION_DATA

// --- Hex ------------------------------------------------------------------------

fn hex(b: const u8[:]) -> u8[>..] {
    let digits = "0123456789abcdef";
    var out: u8[>..] = [];
    for c in b { out.push(digits[(c >> 4) as i64]); out.push(digits[(c & 15) as i64]); }
    return out;
}

fn hex_digit(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return (c - 'a') as i64 + 10; }
    if c >= 'A' && c <= 'F' { return (c - 'A') as i64 + 10; }
    return -1;
}

// Hex to bytes; false for an odd length or a character that is not hex.
fn unhex(s: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if s.len % 2 != 0 { return out, false; }
    var i = 0;
    while i < s.len {
        let a = hex_digit(s[i]);
        let b = hex_digit(s[i + 1]);
        if a < 0 || b < 0 { out.clear(); return out, false; }
        out.push((a * 16 + b) as u8);
        i += 2;
    }
    return out, true;
}

// --- Marshalling ------------------------------------------------------------------

fn put_u8(out: u8[>..]&, v: u8) { out.push(v); }
fn put_u16(out: u8[>..]&, v: u16) { out.push((v >> 8) as! u8); out.push(v as! u8); }
fn put_u32(out: u8[>..]&, v: u32) {
    out.push((v >> 24) as! u8); out.push((v >> 16) as! u8); out.push((v >> 8) as! u8); out.push(v as! u8);
}
fn put_u64(out: u8[>..]&, v: u64) { put_u32(out, (v >> 32) as! u32); put_u32(out, v as! u32); }
// A TPM2B: a u16 size and the bytes. The caller keeps data under 64 KiB.
fn put_2b(out: u8[>..]&, data: const u8[:]) {
    assert(data.len <= 0xffff);
    put_u16(out, data.len as u16);
    out.append(data);
}

fn be16(b: const u8[:], at: i64) -> u16 { ((b[at] as u16) << 8) | b[at + 1] }
fn be32(b: const u8[:], at: i64) -> u32 {
    ((b[at] as u32) << 24) | ((b[at + 1] as u32) << 16) | ((b[at + 2] as u32) << 8) | b[at + 3]
}

// A reader over a buffer. The first read past the end, or a size over a
// structure's maximum, clears ok; reads after that give zeros and empty
// slices, so a parser checks ok once at its end.
struct Reader { d: const u8[:], off: i64, ok: bool }

fn reader(d: const u8[:]) -> Reader { Reader { d: d, off: 0, ok: true } }

fn left(r: const Reader&) -> i64 { r.d.len - r.off }

fn get_u8(r: Reader&) -> u8 {
    if !r.ok || left(r) < 1 { r.ok = false; return 0; }
    let v = r.d[r.off];
    r.off += 1;
    return v;
}

fn get_u16(r: Reader&) -> u16 {
    if !r.ok || left(r) < 2 { r.ok = false; return 0; }
    let v = be16(r.d, r.off);
    r.off += 2;
    return v;
}

fn get_u32(r: Reader&) -> u32 {
    if !r.ok || left(r) < 4 { r.ok = false; return 0; }
    let v = be32(r.d, r.off);
    r.off += 4;
    return v;
}

fn get_u64(r: Reader&) -> u64 {
    let hi = get_u32(r);
    let lo = get_u32(r);
    return ((hi as u64) << 32) | lo;
}

// n raw bytes.
fn get_bytes(r: Reader&, n: i64) -> const u8[:] {
    if !r.ok || n < 0 || left(r) < n { r.ok = false; return r.d[0..0]; }
    let s = r.d[r.off..r.off + n];
    r.off += n;
    return s;
}

// A TPM2B of at most max bytes.
fn get_2b(r: Reader&, max: i64) -> const u8[:] {
    let n = get_u16(r) as i64;
    if n > max { r.ok = false; return r.d[0..0]; }
    return get_bytes(r, n);
}

// Copies b into a bounded array, refusing what does not fit.
fn set_bytes<A>(dst: A&, b: const u8[:]) -> bool {
    dst.clear();
    if b.len > dst.cap { return false; }
    dst.append(b);
    return true;
}

// --- Response codes ---------------------------------------------------------------

fn rc_base_name(code: u32) -> const u8[:] {
    if code == 0x000 { return "TPM_RC_SUCCESS"; }
    if code == 0x01E { return "TPM_RC_BAD_TAG"; }
    if code == 0x100 { return "TPM_RC_INITIALIZE"; }
    if code == 0x101 { return "TPM_RC_FAILURE"; }
    if code == 0x103 { return "TPM_RC_SEQUENCE"; }
    if code == 0x10B { return "TPM_RC_PRIVATE"; }
    if code == 0x119 { return "TPM_RC_HMAC"; }
    if code == 0x120 { return "TPM_RC_DISABLED"; }
    if code == 0x121 { return "TPM_RC_EXCLUSIVE"; }
    if code == 0x124 { return "TPM_RC_AUTH_TYPE"; }
    if code == 0x125 { return "TPM_RC_AUTH_MISSING"; }
    if code == 0x126 { return "TPM_RC_POLICY"; }
    if code == 0x127 { return "TPM_RC_PCR"; }
    if code == 0x128 { return "TPM_RC_PCR_CHANGED"; }
    if code == 0x12D { return "TPM_RC_UPGRADE"; }
    if code == 0x12E { return "TPM_RC_TOO_MANY_CONTEXTS"; }
    if code == 0x12F { return "TPM_RC_AUTH_UNAVAILABLE"; }
    if code == 0x130 { return "TPM_RC_REBOOT"; }
    if code == 0x131 { return "TPM_RC_UNBALANCED"; }
    if code == 0x142 { return "TPM_RC_COMMAND_SIZE"; }
    if code == 0x143 { return "TPM_RC_COMMAND_CODE"; }
    if code == 0x144 { return "TPM_RC_AUTHSIZE"; }
    if code == 0x145 { return "TPM_RC_AUTH_CONTEXT"; }
    if code == 0x146 { return "TPM_RC_NV_RANGE"; }
    if code == 0x147 { return "TPM_RC_NV_SIZE"; }
    if code == 0x148 { return "TPM_RC_NV_LOCKED"; }
    if code == 0x149 { return "TPM_RC_NV_AUTHORIZATION"; }
    if code == 0x14A { return "TPM_RC_NV_UNINITIALIZED"; }
    if code == 0x14B { return "TPM_RC_NV_SPACE"; }
    if code == 0x14C { return "TPM_RC_NV_DEFINED"; }
    if code == 0x150 { return "TPM_RC_BAD_CONTEXT"; }
    if code == 0x151 { return "TPM_RC_CPHASH"; }
    if code == 0x152 { return "TPM_RC_PARENT"; }
    if code == 0x153 { return "TPM_RC_NEEDS_TEST"; }
    if code == 0x154 { return "TPM_RC_NO_RESULT"; }
    if code == 0x155 { return "TPM_RC_SENSITIVE"; }
    if code == 0x156 { return "TPM_RC_READ_ONLY"; }
    if code == 0x081 { return "TPM_RC_ASYMMETRIC"; }
    if code == 0x082 { return "TPM_RC_ATTRIBUTES"; }
    if code == 0x083 { return "TPM_RC_HASH"; }
    if code == 0x084 { return "TPM_RC_VALUE"; }
    if code == 0x085 { return "TPM_RC_HIERARCHY"; }
    if code == 0x087 { return "TPM_RC_KEY_SIZE"; }
    if code == 0x088 { return "TPM_RC_MGF"; }
    if code == 0x089 { return "TPM_RC_MODE"; }
    if code == 0x08A { return "TPM_RC_TYPE"; }
    if code == 0x08B { return "TPM_RC_HANDLE"; }
    if code == 0x08C { return "TPM_RC_KDF"; }
    if code == 0x08D { return "TPM_RC_RANGE"; }
    if code == 0x08E { return "TPM_RC_AUTH_FAIL"; }
    if code == 0x08F { return "TPM_RC_NONCE"; }
    if code == 0x090 { return "TPM_RC_PP"; }
    if code == 0x092 { return "TPM_RC_SCHEME"; }
    if code == 0x095 { return "TPM_RC_SIZE"; }
    if code == 0x096 { return "TPM_RC_SYMMETRIC"; }
    if code == 0x097 { return "TPM_RC_TAG"; }
    if code == 0x098 { return "TPM_RC_SELECTOR"; }
    if code == 0x09A { return "TPM_RC_INSUFFICIENT"; }
    if code == 0x09B { return "TPM_RC_SIGNATURE"; }
    if code == 0x09C { return "TPM_RC_KEY"; }
    if code == 0x09D { return "TPM_RC_POLICY_FAIL"; }
    if code == 0x09F { return "TPM_RC_INTEGRITY"; }
    if code == 0x0A0 { return "TPM_RC_TICKET"; }
    if code == 0x0A1 { return "TPM_RC_RESERVED_BITS"; }
    if code == 0x0A2 { return "TPM_RC_BAD_AUTH"; }
    if code == 0x0A3 { return "TPM_RC_EXPIRED"; }
    if code == 0x0A4 { return "TPM_RC_POLICY_CC"; }
    if code == 0x0A5 { return "TPM_RC_BINDING"; }
    if code == 0x0A6 { return "TPM_RC_CURVE"; }
    if code == 0x0A7 { return "TPM_RC_ECC_POINT"; }
    if code == 0x0A8 { return "TPM_RC_FW_LIMITED"; }
    if code == 0x0A9 { return "TPM_RC_SVN_LIMITED"; }
    if code == 0x0AA { return "TPM_RC_PARMS"; }
    if code == 0x0AB { return "TPM_RC_EXT_MU"; }
    if code == 0x0AC { return "TPM_RC_ONE_SHOT_SIGNATURE"; }
    if code == 0x0AD { return "TPM_RC_SIGN_CONTEXT_KEY"; }
    if code == 0x0B0 { return "TPM_RC_CHANNEL"; }
    if code == 0x0B1 { return "TPM_RC_CHANNEL_KEY"; }
    if code == 0x901 { return "TPM_RC_CONTEXT_GAP"; }
    if code == 0x902 { return "TPM_RC_OBJECT_MEMORY"; }
    if code == 0x903 { return "TPM_RC_SESSION_MEMORY"; }
    if code == 0x904 { return "TPM_RC_MEMORY"; }
    if code == 0x905 { return "TPM_RC_SESSION_HANDLES"; }
    if code == 0x906 { return "TPM_RC_OBJECT_HANDLES"; }
    if code == 0x907 { return "TPM_RC_LOCALITY"; }
    if code == 0x908 { return "TPM_RC_YIELDED"; }
    if code == 0x909 { return "TPM_RC_CANCELED"; }
    if code == 0x90A { return "TPM_RC_TESTING"; }
    if code >= 0x910 && code <= 0x916 { return "TPM_RC_REFERENCE_H"; }
    if code >= 0x918 && code <= 0x91E { return "TPM_RC_REFERENCE_S"; }
    if code == 0x920 { return "TPM_RC_NV_RATE"; }
    if code == 0x921 { return "TPM_RC_LOCKOUT"; }
    if code == 0x922 { return "TPM_RC_RETRY"; }
    if code == 0x923 { return "TPM_RC_NV_UNAVAILABLE"; }
    if code == 0x97F { return "TPM_RC_NOT_USED"; }
    return "";
}

// A response code's parts (Part 2 §6.6.2): its base code (the format-1
// error with the number taken out, or the format-0 code), and for format 1
// what the number says: 'H' a handle, 'P' a parameter, 'S' a session, with
// its number (1-based; 0 for none).
fn rc_parts(rc: u32) -> u32, u8, i64 {
    if (rc & 0x080) != 0 {
        let base = 0x080 | (rc & 0x03F);
        if (rc & 0x040) != 0 { return base, 'P', ((rc >> 8) & 0xF); }
        if (rc & 0x800) != 0 { return base, 'S', ((rc >> 8) & 0x7); }
        return base, 'H', ((rc >> 8) & 0x7);
    }
    return rc, ' ', 0;
}

// The response code's base name: TPM_RC_HANDLE for 0x28B, say.
fn rc_name(rc: u32) -> const u8[:] {
    let base, kind, n = rc_parts(rc);
    return rc_base_name(base);
}

// The response code as text: "TPM_RC_HANDLE (handle 2, 0x28b)",
// "TPM_RC_BAD_AUTH (session 1, 0x9a2)", a vendor or TPM 1.2 code in hex.
fn rc_text(rc: u32) -> u8[>..] {
    var out: u8[>..] = [];
    let base, kind, n = rc_parts(rc);
    let name = rc_base_name(base);
    if (rc & 0x080) == 0 && (rc & 0x400) != 0 {
        out.append("vendor-defined response code");
    } else if (rc & 0x080) == 0 && (rc & 0x100) == 0 && rc != 0 {
        out.append("TPM 1.2 response code");
    } else if name.len == 0 {
        out.append("unknown response code");
    } else {
        out.append(name);
    }
    out.append(" (");
    if kind == 'H' && n != 0 { format(out, "handle ", n, ", "); }
    if kind == 'P' { format(out, "parameter ", n, ", "); }
    if kind == 'S' { format(out, "session ", n, ", "); }
    out.append("0x");
    out.append(hex_u32(rc));
    out.append(")");
    return out;
}

fn hex_u32(v: u32) -> u8[>..] {
    var out: u8[>..] = [];
    let digits = "0123456789abcdef";
    var started = false;
    var i = 7;
    while i >= 0 {
        let d = ((v >> ((i * 4) as! u32)) & 15) as i64;
        if d != 0 || started || i == 0 { out.push(digits[d]); started = true; }
        i -= 1;
    }
    return out;
}

// --- Hashes -------------------------------------------------------------------------

// bignum's hash id for a TPM hash algorithm, or 0.
fn hash_id(alg: u16) -> i64 {
    if alg == ALG_SHA1 { return 160; }
    if alg == ALG_SHA256 { return 256; }
    if alg == ALG_SHA384 { return 384; }
    if alg == ALG_SHA512 { return 512; }
    return 0;
}

// The digest size of a hash algorithm, or 0 for one not supported.
fn digest_size(alg: u16) -> i64 {
    let h = hash_id(alg);
    if h == 0 { return 0; }
    return bignum::hash_len(h);
}

fn hash_name(alg: u16) -> const u8[:] {
    if alg == ALG_SHA1 { return "sha1"; }
    if alg == ALG_SHA256 { return "sha256"; }
    if alg == ALG_SHA384 { return "sha384"; }
    if alg == ALG_SHA512 { return "sha512"; }
    return "";
}

// A hash algorithm by name (sha1, sha256, sha384, sha512), or ALG_ERROR.
fn hash_by_name(s: const u8[:]) -> u16 {
    if s == "sha1" { return ALG_SHA1; }
    if s == "sha256" { return ALG_SHA256; }
    if s == "sha384" { return ALG_SHA384; }
    if s == "sha512" { return ALG_SHA512; }
    return ALG_ERROR;
}

fn hash(alg: u16, data: const u8[:]) -> u8[>..] {
    assert(hash_id(alg) != 0);
    return bignum::hash_bits(hash_id(alg), data);
}

fn hmac(alg: u16, key: const u8[:], data: const u8[:]) -> u8[>..] {
    assert(hash_id(alg) != 0);
    return bignum::hmac(hash_id(alg), key, data);
}

// --- KDFa and KDFe (Part 1 §11.4.10) ---------------------------------------------

// KDFa(hashAlg, key, label, contextU, contextV, bits): SP 800-108 in counter
// mode with HMAC. The label is followed by a 0 octet unless it ends in one.
// bits need not be a multiple of 8: the first octet's extra bits are cleared.
fn kdfa(alg: u16, key: const u8[:], label: const u8[:], u: const u8[:], v: const u8[:], bits: i64) -> u8[>..] {
    var out: u8[>..] = [];
    let n = (bits + 7) / 8;
    var counter: u32 = 1;
    while out.len < n {
        var m: u8[>..] = [];
        put_u32(m, counter);
        m.append(label);
        if label.len == 0 || label[label.len - 1] != 0 { m.push(0); }
        m.append(u);
        m.append(v);
        put_u32(m, bits as u32);
        let h = hmac(alg, key, m);
        let take = min(h.len, n - out.len);
        out.append(h[..take]);
        counter += 1;
    }
    if bits % 8 != 0 { out[0] = out[0] & ((1 << ((bits % 8) as! u8)) - 1) as! u8; }
    return out;
}

// KDFe(hashAlg, Z, label, partyU, partyV, bits): the SP 800-56A
// concatenation KDF, Z being the x-coordinate of the shared point.
fn kdfe(alg: u16, z: const u8[:], label: const u8[:], u: const u8[:], v: const u8[:], bits: i64) -> u8[>..] {
    var out: u8[>..] = [];
    let n = (bits + 7) / 8;
    var counter: u32 = 1;
    while out.len < n {
        var m: u8[>..] = [];
        put_u32(m, counter);
        m.append(z);
        m.append(label);
        if label.len == 0 || label[label.len - 1] != 0 { m.push(0); }
        m.append(u);
        m.append(v);
        let h = hash(alg, m);
        let take = min(h.len, n - out.len);
        out.append(h[..take]);
        counter += 1;
    }
    if bits % 8 != 0 { out[0] = out[0] & ((1 << ((bits % 8) as! u8)) - 1) as! u8; }
    return out;
}

// --- TPMT_PUBLIC ---------------------------------------------------------------------

// A TPMT_PUBLIC: an RSA, ECC, keyed-hash or symmetric object's public area.
// sym_* is the symmetric definition of a storage key (or a SYMCIPHER's);
// scheme and scheme_hash the signing or decryption scheme (a keyed hash's
// HMAC or XOR scheme), scheme_extra ECDAA's count or XOR's KDF; unique the
// RSA modulus or a keyed hash's or symmetric object's unique digest, x and
// y an ECC point.
struct Public {
    kind:     u16       = ALG_RSA,
    name_alg: u16       = ALG_SHA256,
    attrs:    u32       = 0,
    policy:   u8[..64]  = [],
    sym_alg:  u16       = ALG_NULL, sym_bits: u16 = 0, sym_mode: u16 = 0,
    scheme:   u16       = ALG_NULL, scheme_hash: u16 = 0, scheme_extra: u16 = 0,
    rsa_bits: u16       = 0, exponent: u32 = 0,
    curve:    u16       = 0, kdf: u16 = ALG_NULL, kdf_hash: u16 = 0,
    unique:   u8[..512] = [],
    x:        u8[..66]  = [], y: u8[..66] = [],
}

fn put_sym_def(out: u8[>..]&, alg: u16, bits: u16, mode: u16) {
    put_u16(out, alg);
    if alg != ALG_NULL { put_u16(out, bits); put_u16(out, mode); }
}

// Whether a scheme carries a hash in TPMU_ASYM_SCHEME (and a count for ECDAA).
fn scheme_has_hash(s: u16) -> bool {
    s == ALG_RSASSA || s == ALG_RSAPSS || s == ALG_OAEP || s == ALG_ECDSA || s == ALG_ECDH || s == ALG_ECDAA
        || s == ALG_SM2 || s == ALG_ECSCHNORR || s == ALG_ECMQV
}

fn marshal_public(p: Public) -> u8[>..] {
    var out: u8[>..] = [];
    put_u16(out, p.kind);
    put_u16(out, p.name_alg);
    put_u32(out, p.attrs);
    put_2b(out, p.policy);
    if p.kind == ALG_KEYEDHASH {
        put_u16(out, p.scheme);
        if p.scheme == ALG_HMAC { put_u16(out, p.scheme_hash); }
        if p.scheme == ALG_XOR { put_u16(out, p.scheme_hash); put_u16(out, p.scheme_extra); }
        put_2b(out, p.unique);
    } else if p.kind == ALG_SYMCIPHER {
        put_sym_def(out, p.sym_alg, p.sym_bits, p.sym_mode);
        put_2b(out, p.unique);
    } else if p.kind == ALG_RSA {
        put_sym_def(out, p.sym_alg, p.sym_bits, p.sym_mode);
        put_u16(out, p.scheme);
        if scheme_has_hash(p.scheme) { put_u16(out, p.scheme_hash); }
        put_u16(out, p.rsa_bits);
        put_u32(out, p.exponent);
        put_2b(out, p.unique);
    } else {
        assert(p.kind == ALG_ECC);
        put_sym_def(out, p.sym_alg, p.sym_bits, p.sym_mode);
        put_u16(out, p.scheme);
        if scheme_has_hash(p.scheme) { put_u16(out, p.scheme_hash); }
        if p.scheme == ALG_ECDAA { put_u16(out, p.scheme_extra); }
        put_u16(out, p.curve);
        put_u16(out, p.kdf);
        if p.kdf != ALG_NULL { put_u16(out, p.kdf_hash); }
        put_2b(out, p.x);
        put_2b(out, p.y);
    }
    return out;
}

fn get_sym_def(r: Reader&, p: Public&) {
    p.sym_alg = get_u16(r);
    if p.sym_alg != ALG_NULL { p.sym_bits = get_u16(r); p.sym_mode = get_u16(r); }
}

fn read_into<A>(r: Reader&, dst: A&) {
    let s = get_2b(r, dst.cap);
    dst.clear();
    dst.append(s);
}

// A TPMT_PUBLIC from a reader. Types other than RSA, ECC, KEYEDHASH and
// SYMCIPHER, and schemes outside the TPM's set, fail the reader.
fn read_public(r: Reader&) -> Public {
    var p = Public { .. };
    p.kind = get_u16(r);
    p.name_alg = get_u16(r);
    p.attrs = get_u32(r);
    read_into(r, p.policy);
    if p.kind == ALG_KEYEDHASH {
        p.scheme = get_u16(r);
        if p.scheme == ALG_HMAC { p.scheme_hash = get_u16(r); }
        else if p.scheme == ALG_XOR { p.scheme_hash = get_u16(r); p.scheme_extra = get_u16(r); }
        else if p.scheme != ALG_NULL { r.ok = false; }
        read_into(r, p.unique);
    } else if p.kind == ALG_SYMCIPHER {
        get_sym_def(r, p);
        read_into(r, p.unique);
    } else if p.kind == ALG_RSA {
        get_sym_def(r, p);
        p.scheme = get_u16(r);
        if scheme_has_hash(p.scheme) { p.scheme_hash = get_u16(r); }
        else if p.scheme != ALG_NULL && p.scheme != ALG_RSAES { r.ok = false; }
        p.rsa_bits = get_u16(r);
        p.exponent = get_u32(r);
        read_into(r, p.unique);
    } else if p.kind == ALG_ECC {
        get_sym_def(r, p);
        p.scheme = get_u16(r);
        if scheme_has_hash(p.scheme) { p.scheme_hash = get_u16(r); }
        else if p.scheme != ALG_NULL { r.ok = false; }
        if p.scheme == ALG_ECDAA { p.scheme_extra = get_u16(r); }
        p.curve = get_u16(r);
        p.kdf = get_u16(r);
        if p.kdf != ALG_NULL { p.kdf_hash = get_u16(r); }
        read_into(r, p.x);
        read_into(r, p.y);
    } else {
        r.ok = false;
    }
    return p;
}

// A TPMT_PUBLIC from its bytes, which must be exactly one.
fn parse_public(b: const u8[:]) -> Public, bool {
    var r = reader(b);
    let p = read_public(r);
    return p, r.ok && left(r) == 0;
}

// A TPM2B_PUBLIC (a size and a TPMT_PUBLIC that fills it exactly) from a
// reader, and the TPMT_PUBLIC's bytes.
fn read_public_2b(r: Reader&) -> Public, const u8[:] {
    let b = get_2b(r, 1024);
    var inner = reader(b);
    let p = read_public(inner);
    if !inner.ok || left(inner) != 0 { r.ok = false; }
    return p, b;
}

// --- Names ----------------------------------------------------------------------------

// An object's Name: nameAlg || H_nameAlg(TPMT_PUBLIC).
fn public_name(p: Public) -> u8[..66] {
    var n: u8[..66] = [];
    if hash_id(p.name_alg) == 0 { return n; }
    var b: u8[>..] = [];
    put_u16(b, p.name_alg);
    b.append(hash(p.name_alg, marshal_public(p)));
    n.append(b);
    return n;
}

// The Name of a handle that is its own Name: a PCR, a session, a
// permanent handle (owner, endorsement, ...).
fn handle_name(h: u32) -> u8[..66] {
    var b: u8[>..] = [];
    put_u32(b, h);
    var n: u8[..66] = [];
    n.append(b);
    return n;
}

fn handle_type(h: u32) -> u8 { (h >> 24) as! u8 }

// --- Templates -------------------------------------------------------------------------

// The EK authPolicy of the TCG EK Credential Profile (B.3.3, B.3.4):
// PolicySecret(TPM_RH_ENDORSEMENT) under SHA-256.
let EK_POLICY_SHA256: const u8[:] = "\x83\x71\x97\x67\x44\x84\xb3\xf8\x1a\x90\xcc\x8d\x46\xa5\xd7\x24\xfd\x52\xd7\x6e\x06\x52\x0b\x64\xf2\xa1\xda\x1b\x33\x14\x69\xaa";

let EK_ATTRS:      u32 = 0x000300B2; // fixedTPM fixedParent sensitiveDataOrigin adminWithPolicy restricted decrypt
let SRK_ATTRS:     u32 = 0x00030472; // fixedTPM fixedParent sensitiveDataOrigin userWithAuth noDA restricted decrypt
let AK_ATTRS:      u32 = 0x00050072; // fixedTPM fixedParent sensitiveDataOrigin userWithAuth restricted sign
let SIGN_ATTRS:    u32 = 0x00040072; // fixedTPM fixedParent sensitiveDataOrigin userWithAuth sign
let DECRYPT_ATTRS: u32 = 0x00020072; // fixedTPM fixedParent sensitiveDataOrigin userWithAuth decrypt
let SEAL_ATTRS:    u32 = 0x00000012; // fixedTPM fixedParent: data from the caller, no userWithAuth

fn zeros(n: i64) -> u8[>..] {
    var z: u8[>..] = [];
    z.resize(n, 0);
    return z;
}

// The RSA-2048 EK template (EK Credential Profile, template L-1).
fn ek_rsa_template() -> Public {
    var p = Public { kind: ALG_RSA, name_alg: ALG_SHA256, attrs: EK_ATTRS, sym_alg: ALG_AES, sym_bits: 128,
                     sym_mode: ALG_CFB, rsa_bits: 2048, .. };
    p.policy.append(EK_POLICY_SHA256);
    p.unique.append(zeros(256));
    return p;
}

// The ECC NIST P-256 EK template (template L-2).
fn ek_ecc_template() -> Public {
    var p = Public { kind: ALG_ECC, name_alg: ALG_SHA256, attrs: EK_ATTRS, sym_alg: ALG_AES, sym_bits: 128,
                     sym_mode: ALG_CFB, curve: ECC_NIST_P256, .. };
    p.policy.append(EK_POLICY_SHA256);
    p.x.append(zeros(32));
    p.y.append(zeros(32));
    return p;
}

// The RSA-2048 SRK template (TCG TPM v2.0 Provisioning Guidance §7.5.1).
fn srk_rsa_template() -> Public {
    var p = Public { kind: ALG_RSA, name_alg: ALG_SHA256, attrs: SRK_ATTRS, sym_alg: ALG_AES, sym_bits: 128,
                     sym_mode: ALG_CFB, rsa_bits: 2048, .. };
    p.unique.append(zeros(256));
    return p;
}

// The ECC P-256 SRK template.
fn srk_ecc_template() -> Public {
    var p = Public { kind: ALG_ECC, name_alg: ALG_SHA256, attrs: SRK_ATTRS, sym_alg: ALG_AES, sym_bits: 128,
                     sym_mode: ALG_CFB, curve: ECC_NIST_P256, .. };
    p.x.append(zeros(32));
    p.y.append(zeros(32));
    return p;
}

// An attestation key: restricted signing, RSASSA-SHA256 with RSA-2048.
fn ak_rsa_template() -> Public {
    Public { kind: ALG_RSA, name_alg: ALG_SHA256, attrs: AK_ATTRS, scheme: ALG_RSASSA, scheme_hash: ALG_SHA256,
             rsa_bits: 2048, .. }
}

// An attestation key: restricted signing, ECDSA-SHA256 on P-256.
fn ak_ecc_template() -> Public {
    Public { kind: ALG_ECC, name_alg: ALG_SHA256, attrs: AK_ATTRS, scheme: ALG_ECDSA, scheme_hash: ALG_SHA256,
             curve: ECC_NIST_P256, .. }
}

// An unrestricted RSA-2048 signing key; the scheme is the Sign call's.
fn rsa_sign_template() -> Public {
    Public { kind: ALG_RSA, name_alg: ALG_SHA256, attrs: SIGN_ATTRS, rsa_bits: 2048, .. }
}

// An unrestricted ECC signing key on a curve (ECC_NIST_P256, P384, P521).
fn ecc_sign_template(curve: u16) -> Public {
    Public { kind: ALG_ECC, name_alg: ALG_SHA256, attrs: SIGN_ATTRS, curve: curve, .. }
}

// An unrestricted RSA-2048 decryption key (RSA_Decrypt, OAEP or RSAES).
fn rsa_decrypt_template() -> Public {
    Public { kind: ALG_RSA, name_alg: ALG_SHA256, attrs: DECRYPT_ATTRS, rsa_bits: 2048, .. }
}

// An unrestricted ECC decryption key, for ECDH_ZGen.
fn ecdh_template(curve: u16) -> Public {
    Public { kind: ALG_ECC, name_alg: ALG_SHA256, attrs: DECRYPT_ATTRS, scheme: ALG_ECDH, scheme_hash: ALG_SHA256,
             curve: curve, .. }
}

// A sealed data object: its data comes from the caller (Create's
// sensitive.data). With a policy, only the policy unseals it; with none,
// its authValue does (userWithAuth).
fn sealed_template(policy: const u8[:]) -> Public {
    var p = Public { kind: ALG_KEYEDHASH, name_alg: ALG_SHA256, attrs: SEAL_ATTRS, .. };
    if policy.len == 0 { p.attrs |= OBJ_USER_WITH_AUTH; }
    p.policy.append(policy);
    return p;
}

// An HMAC key (TPM2_HMAC) with the given hash.
fn hmac_key_template(alg: u16) -> Public {
    Public { kind: ALG_KEYEDHASH, name_alg: ALG_SHA256, attrs: SIGN_ATTRS, scheme: ALG_HMAC, scheme_hash: alg, .. }
}

// --- Curves ------------------------------------------------------------------------------

fn curve_supported(c: u16) -> bool { c == ECC_NIST_P256 || c == ECC_NIST_P384 || c == ECC_NIST_P521 }

fn curve_of(c: u16) -> bignum::Curve {
    if c == ECC_NIST_P384 { return bignum::p384(); }
    if c == ECC_NIST_P521 { return bignum::p521(); }
    return bignum::p256();
}

// A curve's coordinate size in bytes.
fn curve_len(c: u16) -> i64 {
    if c == ECC_NIST_P256 { return 32; }
    if c == ECC_NIST_P384 { return 48; }
    if c == ECC_NIST_P521 { return 66; }
    return 0;
}

fn x509_key_kind(c: u16) -> i64 {
    if c == ECC_NIST_P384 { return x509::KEY_EC_P384; }
    if c == ECC_NIST_P521 { return x509::KEY_EC_P521; }
    return x509::KEY_EC_P256;
}

// b left-padded with zeros to n bytes (a TPM may drop leading zeros of a
// coordinate); false when it is longer.
fn pad_left(b: const u8[:], n: i64) -> u8[>..], bool {
    var out: u8[>..] = [];
    var i = 0;
    while i < b.len && b.len - i > n && b[i] == 0 { i++; }
    if b.len - i > n { return out, false; }
    out.resize(n - (b.len - i), 0);
    out.append(b[i..]);
    return out, true;
}

// The uncompressed point 04 || x || y of an ECC public area.
fn ecc_point(p: Public) -> u8[>..], bool {
    var out: u8[>..] = [];
    let n = curve_len(p.curve);
    if n == 0 { return out, false; }
    let x, okx = pad_left(p.x, n);
    let y, oky = pad_left(p.y, n);
    if !okx || !oky { return out, false; }
    out.push(4);
    out.append(x);
    out.append(y);
    return out, true;
}

// The RSA public key of an RSA public area (exponent 0 meaning 65537).
fn rsa_public(p: Public) -> bignum::RsaPublicKey, bool {
    let e: u32 = if p.exponent == 0 { 65537 } else { p.exponent };
    var eb: u8[>..] = [];
    put_u32(eb, e);
    if p.kind != ALG_RSA || p.unique.len == 0 { return bignum::RsaPublicKey { n: [], e: [] }, false; }
    return bignum::rsa_public_from(bignum::from_bytes_be(p.unique), bignum::from_bytes_be(eb));
}

// --- SubjectPublicKeyInfo ----------------------------------------------------------------

// The public key of an RSA or ECC public area as a DER SubjectPublicKeyInfo,
// as x509 reads one (x509::spki_of) and openssl prints it.
fn public_to_spki(p: Public) -> u8[>..], bool {
    var out: u8[>..] = [];
    var alg: u8[>..] = [];
    var key: u8[>..] = [];
    if p.kind == ALG_RSA {
        if p.unique.len == 0 { return out, false; }
        asn1::put_oid(alg, "1.2.840.113549.1.1.1");
        asn1::put_null(alg);
        var rk: u8[>..] = [];
        asn1::put_uint(rk, p.unique);
        var eb: u8[>..] = [];
        put_u32(eb, if p.exponent == 0 { 65537 } else { p.exponent });
        asn1::put_uint(rk, eb);
        asn1::put(key, asn1::SEQUENCE, rk);
    } else if p.kind == ALG_ECC {
        if !curve_supported(p.curve) { return out, false; }
        asn1::put_oid(alg, "1.2.840.10045.2.1");
        asn1::put_oid(alg, if p.curve == ECC_NIST_P256 { "1.2.840.10045.3.1.7" }
                           else if p.curve == ECC_NIST_P384 { "1.3.132.0.34" } else { "1.3.132.0.35" });
        let pt, ok = ecc_point(p);
        if !ok { return out, false; }
        key.append(pt);
    } else {
        return out, false;
    }
    var body: u8[>..] = [];
    asn1::put(body, asn1::SEQUENCE, alg);
    asn1::put_bits(body, key);
    asn1::put(out, asn1::SEQUENCE, body);
    return out, true;
}

// A public area for a SubjectPublicKeyInfo's RSA or P-256/384/521 key, with
// the template's other fields (nameAlg, attributes, scheme, policy): for
// LoadExternal, PolicySigned and PolicyAuthorize's keys.
fn public_from_spki(spki: const u8[:], tmpl: Public) -> Public, i64 {
    var p = tmpl;
    let t, okt = asn1::parse(spki);
    if !okt || t.end != spki.len { return p, ERR_MALFORMED; }
    let kind, key, okk = x509::spki_of(spki, t);
    if !okk { return p, ERR_MALFORMED; }
    let kb, unused, okb = asn1::read_bits(spki, key);
    if !okb || unused != 0 { return p, ERR_MALFORMED; }
    if kind == x509::KEY_RSA {
        let rk, okr = asn1::parse(kb);
        let f, okf = asn1::children_of(kb, rk, asn1::SEQUENCE);
        if !okr || !okf || f.len != 2 { return p, ERR_MALFORMED; }
        let n, okn = asn1::read_uint(kb, f[0]);
        let e, oke = asn1::read_uint(kb, f[1]);
        if !okn || !oke || e.len > 4 || n.len > MAX_RSA_BYTES { return p, ERR_UNSUPPORTED; }
        p.kind = ALG_RSA;
        p.rsa_bits = (n.len * 8) as u16;
        var ev: u32 = 0;
        for c in e { ev = (ev << 8) | c; }
        p.exponent = if ev == 65537 { 0 } else { ev };
        p.unique.clear();
        p.unique.append(n);
        p.x.clear();
        p.y.clear();
        return p, OK;
    }
    var curve: u16 = 0;
    if kind == x509::KEY_EC_P256 { curve = ECC_NIST_P256; }
    if kind == x509::KEY_EC_P384 { curve = ECC_NIST_P384; }
    if kind == x509::KEY_EC_P521 { curve = ECC_NIST_P521; }
    if curve == 0 { return p, ERR_UNSUPPORTED; }
    let n = curve_len(curve);
    if kb.len != 1 + 2 * n || kb[0] != 4 { return p, ERR_UNSUPPORTED; }
    p.kind = ALG_ECC;
    p.curve = curve;
    p.unique.clear();
    p.x.clear();
    p.x.append(kb[1..1 + n]);
    p.y.clear();
    p.y.append(kb[1 + n..]);
    return p, OK;
}

// An x509::Cert holding only a key, made from a SubjectPublicKeyInfo, for
// x509's verify_digest and verify_with.
fn key_cert(spki: const u8[:]) -> x509::Cert, bool {
    var c = x509::empty_cert();
    c.der.append(spki);
    let d = c.der[..];
    let t, okt = asn1::parse(d);
    if !okt { return c, false; }
    let kind, key, okk = x509::spki_of(d, t);
    if !okk { return c, false; }
    c.spki = t;
    c.key_type = kind;
    c.key = key;
    return c, true;
}

// --- TPMT_SIGNATURE --------------------------------------------------------------------------

// A TPMT_SIGNATURE: RSASSA or RSAPSS (sig), ECDSA (r and s).
struct Signature { alg: u16 = ALG_NULL, hash: u16 = 0, sig: u8[..512] = [], r: u8[..66] = [], s: u8[..66] = [] }

fn marshal_signature(s: Signature) -> u8[>..] {
    var out: u8[>..] = [];
    put_u16(out, s.alg);
    if s.alg == ALG_NULL { return out; }
    put_u16(out, s.hash);
    if s.alg == ALG_RSASSA || s.alg == ALG_RSAPSS { put_2b(out, s.sig); }
    else { put_2b(out, s.r); put_2b(out, s.s); }
    return out;
}

fn read_signature(r: Reader&) -> Signature {
    var s = Signature { .. };
    s.alg = get_u16(r);
    if s.alg == ALG_NULL { return s; }
    s.hash = get_u16(r);
    if s.alg == ALG_RSASSA || s.alg == ALG_RSAPSS {
        read_into(r, s.sig);
    } else if s.alg == ALG_ECDSA || s.alg == ALG_ECSCHNORR || s.alg == ALG_SM2 {
        read_into(r, s.r);
        read_into(r, s.s);
    } else {
        r.ok = false;
    }
    return s;
}

fn parse_signature(b: const u8[:]) -> Signature, bool {
    var r = reader(b);
    let s = read_signature(r);
    return s, r.ok && left(r) == 0;
}

// The x509 form of a signature: RSA's bytes, ECDSA's DER SEQUENCE.
fn signature_der(s: Signature, p: Public) -> u8[>..], bool {
    var out: u8[>..] = [];
    if s.alg == ALG_RSASSA || s.alg == ALG_RSAPSS { out.append(s.sig); return out, true; }
    if s.alg != ALG_ECDSA { return out, false; }
    let n = curve_len(p.curve);
    let rr, okr = pad_left(s.r, n);
    let ss, oks = pad_left(s.s, n);
    if n == 0 || !okr || !oks { return out, false; }
    var raw: u8[>..] = [];
    raw.append(rr);
    raw.append(ss);
    return bignum::ecdsa_sig_to_der(raw), true;
}

// Verifies a TPM signature over a digest with a public area's key, through
// x509's verify_digest (the key as a SubjectPublicKeyInfo). RSASSA, RSAPSS
// (salted with the hash's length, as FIPS 186-5 and TPMs since rev 1.63
// make it, or with the most the key allows, as older ones do) and ECDSA;
// the signature's hash must be the digest's.
fn verify_signature(p: Public, digest: const u8[:], s: Signature) -> i64 {
    let h = hash_id(s.hash);
    if h == 0 { return ERR_UNSUPPORTED; }
    if digest.len != bignum::hash_len(h) { return ERR_SIGNATURE; }
    var alg = x509::SIG_UNKNOWN;
    if s.alg == ALG_RSASSA && p.kind == ALG_RSA { alg = x509::SIG_RSA_PKCS1; }
    if s.alg == ALG_RSAPSS && p.kind == ALG_RSA { alg = x509::SIG_RSA_PSS; }
    if s.alg == ALG_ECDSA && p.kind == ALG_ECC { alg = x509::SIG_ECDSA; }
    if alg == x509::SIG_UNKNOWN { return ERR_SIGNATURE; }
    let spki, oks = public_to_spki(p);
    if !oks { return ERR_UNSUPPORTED; }
    let c, okc = key_cert(spki);
    if !okc { return ERR_MALFORMED; }
    let der, okd = signature_der(s, p);
    if !okd { return ERR_SIGNATURE; }
    let e = x509::verify_digest(c, alg, h, bignum::hash_len(h), digest, der);
    if e == x509::OK { return OK; }
    // TPMs before FIPS 186-4's limit (Part 1 §43.7) salt PSS with all the
    // room the key leaves.
    if alg == x509::SIG_RSA_PSS {
        let em = (p.unique.len * 8 - 1 + 7) / 8;
        let e2 = x509::verify_digest(c, alg, h, em - bignum::hash_len(h) - 2, digest, der);
        if e2 == x509::OK { return OK; }
    }
    return ERR_SIGNATURE;
}

// --- TPML_PCR_SELECTION ------------------------------------------------------------------------

// One bank's selection: a hash and a mask of PCRs 0 to 23.
struct PcrSel { hash: u16, mask: u32 }

fn put_pcr_selection(out: u8[>..]&, sel: const PcrSel[:]) {
    put_u32(out, sel.len as u32);
    for s in sel {
        put_u16(out, s.hash);
        put_u8(out, 3);
        put_u8(out, s.mask as! u8);
        put_u8(out, (s.mask >> 8) as! u8);
        put_u8(out, (s.mask >> 16) as! u8);
    }
}

// A TPML_PCR_SELECTION of at most 4 banks with sizeofSelect up to 4 (PCRs
// beyond 23 are refused: no TPM this library meets has them).
fn read_pcr_selection(r: Reader&) -> PcrSel[..4] {
    var out: PcrSel[..4] = [];
    let n = get_u32(r);
    if n > 4 { r.ok = false; return out; }
    for i in n as i64 {
        let h = get_u16(r);
        let size = get_u8(r) as i64;
        if size > 4 { r.ok = false; return out; }
        var m: u32 = 0;
        for j in size {
            let b = get_u8(r) as u32;
            if j == 3 && b != 0 { r.ok = false; }
            m |= b << ((8 * j) as! u32);
        }
        if r.ok { out.push(PcrSel { hash: h, mask: m & 0xffffff }); }
    }
    return out;
}

// The PCR indices of a mask, in order.
fn pcr_list(mask: u32) -> i64[..24] {
    var out: i64[..24] = [];
    for i in 24 { if (mask >> (i as! u32)) & 1 != 0 { out.push(i); } }
    return out;
}

// A mask from a list such as "0,1,7" or "0-7,14"; false when a number is
// not 0-23.
fn parse_pcr_list(s: const u8[:]) -> u32, bool {
    var mask: u32 = 0;
    if s.len == 0 { return 0, false; }
    var ok = true;
    each_split(s, ',') {
        let dash = find(it, "-");
        var lo = -1;
        var hi = -1;
        if dash >= 0 {
            let a, oka = parse_int(it[..dash]);
            let b, okb = parse_int(it[dash + 1..]);
            if oka && okb { lo = a; hi = b; }
        } else {
            let a, oka = parse_int(it);
            if oka { lo = a; hi = a; }
        }
        if lo < 0 || hi > 23 || lo > hi { ok = false; }
        else { for i in lo..hi + 1 { mask |= (1 as u32) << (i as! u32); } }
    };
    return mask, ok;
}
