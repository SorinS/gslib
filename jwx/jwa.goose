// jwx.jwa: the identifiers of JSON Web Algorithms (RFC 7518, RFC 8037,
// RFC 9864's fully specified "Ed25519" and "Ed448" and RFC 9964's ML-DSA):
// signature, key management and content encryption algorithms, key types
// and curves, with their names and what each needs.

namespace jwa;

import std;
import crypto.bignum.hmac;

// --- Signature algorithms (RFC 7518 §3, RFC 8037 §3.1) -------------------------

let UNKNOWN: i64 = 0;
let HS256: i64 = 1;
let HS384: i64 = 2;
let HS512: i64 = 3;
let RS256: i64 = 4;
let RS384: i64 = 5;
let RS512: i64 = 6;
let PS256: i64 = 7;
let PS384: i64 = 8;
let PS512: i64 = 9;
let ES256: i64 = 10;
let ES384: i64 = 11;
let ES512: i64 = 12;
let EDDSA: i64 = 13;
let ED25519: i64 = 14;           // RFC 9864: EdDSA on Ed25519 by name
let NONE: i64 = 15;
// RFC 9964: ML-DSA (FIPS 204) with "AKP" keys, the empty context.
let ML_DSA_44: i64 = 16;
let ML_DSA_65: i64 = 17;
let ML_DSA_87: i64 = 18;
let ED448: i64 = 19;             // RFC 9864: EdDSA on Ed448 by name

// --- Key management algorithms (RFC 7518 §4) ----------------------------------

let RSA1_5: i64 = 20;
let RSA_OAEP: i64 = 21;
let RSA_OAEP_256: i64 = 22;
let RSA_OAEP_384: i64 = 23;
let RSA_OAEP_512: i64 = 24;
let A128KW: i64 = 25;
let A192KW: i64 = 26;
let A256KW: i64 = 27;
let DIRECT: i64 = 28;            // "dir"
let ECDH_ES: i64 = 29;
let ECDH_ES_A128KW: i64 = 30;
let ECDH_ES_A192KW: i64 = 31;
let ECDH_ES_A256KW: i64 = 32;
let A128GCMKW: i64 = 33;
let A192GCMKW: i64 = 34;
let A256GCMKW: i64 = 35;
let PBES2_HS256_A128KW: i64 = 36;
let PBES2_HS384_A192KW: i64 = 37;
let PBES2_HS512_A256KW: i64 = 38;

// --- Content encryption algorithms (RFC 7518 §5) --------------------------------

let A128CBC_HS256: i64 = 50;
let A192CBC_HS384: i64 = 51;
let A256CBC_HS512: i64 = 52;
let A128GCM: i64 = 53;
let A192GCM: i64 = 54;
let A256GCM: i64 = 55;

// --- Key types and curves (RFC 7518 §6, RFC 8037 §2) -----------------------------

let KTY_UNKNOWN: i64 = 0;
let KTY_EC: i64 = 1;
let KTY_RSA: i64 = 2;
let KTY_OKP: i64 = 3;
let KTY_OCT: i64 = 4;
let KTY_AKP: i64 = 5;           // RFC 9964: Algorithm Key Pair, whose "alg" says what it is

let CRV_UNKNOWN: i64 = 0;
let CRV_P256: i64 = 1;
let CRV_P384: i64 = 2;
let CRV_P521: i64 = 3;
let CRV_ED25519: i64 = 4;
let CRV_X25519: i64 = 5;
let CRV_ED448: i64 = 6;
let CRV_X448: i64 = 7;

// Every algorithm, for looking names up.
let ALL: i64[] = [HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512,
                  EDDSA, ED25519, ED448, NONE, ML_DSA_44, ML_DSA_65, ML_DSA_87,
                  RSA1_5, RSA_OAEP, RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512, A128KW, A192KW, A256KW,
                  DIRECT, ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW,
                  A128GCMKW, A192GCMKW, A256GCMKW, PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW,
                  A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM, A256GCM];

fn name(a: i64) -> const u8[:] {
    if a == HS256 { return "HS256"; }
    if a == HS384 { return "HS384"; }
    if a == HS512 { return "HS512"; }
    if a == RS256 { return "RS256"; }
    if a == RS384 { return "RS384"; }
    if a == RS512 { return "RS512"; }
    if a == PS256 { return "PS256"; }
    if a == PS384 { return "PS384"; }
    if a == PS512 { return "PS512"; }
    if a == ES256 { return "ES256"; }
    if a == ES384 { return "ES384"; }
    if a == ES512 { return "ES512"; }
    if a == EDDSA { return "EdDSA"; }
    if a == ED25519 { return "Ed25519"; }
    if a == ED448 { return "Ed448"; }
    if a == NONE { return "none"; }
    if a == ML_DSA_44 { return "ML-DSA-44"; }
    if a == ML_DSA_65 { return "ML-DSA-65"; }
    if a == ML_DSA_87 { return "ML-DSA-87"; }
    if a == RSA1_5 { return "RSA1_5"; }
    if a == RSA_OAEP { return "RSA-OAEP"; }
    if a == RSA_OAEP_256 { return "RSA-OAEP-256"; }
    if a == RSA_OAEP_384 { return "RSA-OAEP-384"; }
    if a == RSA_OAEP_512 { return "RSA-OAEP-512"; }
    if a == A128KW { return "A128KW"; }
    if a == A192KW { return "A192KW"; }
    if a == A256KW { return "A256KW"; }
    if a == DIRECT { return "dir"; }
    if a == ECDH_ES { return "ECDH-ES"; }
    if a == ECDH_ES_A128KW { return "ECDH-ES+A128KW"; }
    if a == ECDH_ES_A192KW { return "ECDH-ES+A192KW"; }
    if a == ECDH_ES_A256KW { return "ECDH-ES+A256KW"; }
    if a == A128GCMKW { return "A128GCMKW"; }
    if a == A192GCMKW { return "A192GCMKW"; }
    if a == A256GCMKW { return "A256GCMKW"; }
    if a == PBES2_HS256_A128KW { return "PBES2-HS256+A128KW"; }
    if a == PBES2_HS384_A192KW { return "PBES2-HS384+A192KW"; }
    if a == PBES2_HS512_A256KW { return "PBES2-HS512+A256KW"; }
    if a == A128CBC_HS256 { return "A128CBC-HS256"; }
    if a == A192CBC_HS384 { return "A192CBC-HS384"; }
    if a == A256CBC_HS512 { return "A256CBC-HS512"; }
    if a == A128GCM { return "A128GCM"; }
    if a == A192GCM { return "A192GCM"; }
    if a == A256GCM { return "A256GCM"; }
    return "";
}

// The algorithm named s, or UNKNOWN. Names are case-sensitive (RFC 7515
// §4.1.1).
fn lookup(s: const u8[:]) -> i64 {
    for a in ALL {
        if name(a) == s { return a; }
    }
    return UNKNOWN;
}

fn is_signature(a: i64) -> bool { a >= HS256 && a <= ED448 }
fn is_key_management(a: i64) -> bool { a >= RSA1_5 && a <= PBES2_HS512_A256KW }
fn is_content(a: i64) -> bool { a >= A128CBC_HS256 && a <= A256GCM }

fn is_hmac(a: i64) -> bool { a >= HS256 && a <= HS512 }
fn is_rsa_pkcs1(a: i64) -> bool { a >= RS256 && a <= RS512 }
fn is_rsa_pss(a: i64) -> bool { a >= PS256 && a <= PS512 }
fn is_ecdsa(a: i64) -> bool { a >= ES256 && a <= ES512 }
fn is_eddsa(a: i64) -> bool { a == EDDSA || a == ED25519 || a == ED448 }
fn is_mldsa(a: i64) -> bool { a >= ML_DSA_44 && a <= ML_DSA_87 }

// The FIPS 204 parameter set of an ML-DSA algorithm (44, 65 or 87), as
// crypto/bignum's mldsa_* take it; 0 for the others.
fn mldsa_set(a: i64) -> i64 {
    if a == ML_DSA_44 { return 44; }
    if a == ML_DSA_65 { return 65; }
    if a == ML_DSA_87 { return 87; }
    return 0;
}

// The ML-DSA algorithm of a parameter set.
fn mldsa_alg(set: i64) -> i64 {
    if set == 44 { return ML_DSA_44; }
    if set == 65 { return ML_DSA_65; }
    if set == 87 { return ML_DSA_87; }
    return UNKNOWN;
}

fn is_rsa_kw(a: i64) -> bool { a >= RSA1_5 && a <= RSA_OAEP_512 }
fn is_aes_kw(a: i64) -> bool { a >= A128KW && a <= A256KW }
fn is_ecdh(a: i64) -> bool { a >= ECDH_ES && a <= ECDH_ES_A256KW }
fn is_gcm_kw(a: i64) -> bool { a >= A128GCMKW && a <= A256GCMKW }
fn is_pbes2(a: i64) -> bool { a >= PBES2_HS256_A128KW && a <= PBES2_HS512_A256KW }
fn is_gcm(e: i64) -> bool { e >= A128GCM && e <= A256GCM }
fn is_cbc_hmac(e: i64) -> bool { e >= A128CBC_HS256 && e <= A256CBC_HS512 }

// The bignum.hmac hash id an algorithm uses: for signatures their SHA-2,
// for RSA-OAEP its OAEP hash (SHA-1 for RSA-OAEP), for PBES2 the PRF's,
// for A*CBC-HS* the HMAC's. 0 for the others.
fn hash_of(a: i64) -> i64 {
    if a == HS256 || a == RS256 || a == PS256 || a == ES256 { return bignum::HASH_SHA256; }
    if a == HS384 || a == RS384 || a == PS384 || a == ES384 { return bignum::HASH_SHA384; }
    if a == HS512 || a == RS512 || a == PS512 || a == ES512 { return bignum::HASH_SHA512; }
    if a == RSA_OAEP { return bignum::HASH_SHA1; }
    if a == RSA_OAEP_256 || a == PBES2_HS256_A128KW || a == A128CBC_HS256 { return bignum::HASH_SHA256; }
    if a == RSA_OAEP_384 || a == PBES2_HS384_A192KW || a == A192CBC_HS384 { return bignum::HASH_SHA384; }
    if a == RSA_OAEP_512 || a == PBES2_HS512_A256KW || a == A256CBC_HS512 { return bignum::HASH_SHA512; }
    return 0;
}

// The curve an ECDSA algorithm requires (RFC 7518 §3.4).
fn curve_of(a: i64) -> i64 {
    if a == ES256 { return CRV_P256; }
    if a == ES384 { return CRV_P384; }
    if a == ES512 { return CRV_P521; }
    return CRV_UNKNOWN;
}

// The length in bytes of the content encryption key `enc` takes: for
// A*CBC-HS*, the MAC key and the AES key together.
fn cek_len(enc: i64) -> i64 {
    if enc == A128CBC_HS256 { return 32; }
    if enc == A192CBC_HS384 { return 48; }
    if enc == A256CBC_HS512 { return 64; }
    if enc == A128GCM { return 16; }
    if enc == A192GCM { return 24; }
    if enc == A256GCM { return 32; }
    return 0;
}

// The AES key length of a key-wrapping algorithm (A*KW, A*GCMKW, the KW of
// ECDH-ES+A*KW and PBES2-*); 0 for the others.
fn kek_len(a: i64) -> i64 {
    if a == A128KW || a == A128GCMKW || a == ECDH_ES_A128KW || a == PBES2_HS256_A128KW { return 16; }
    if a == A192KW || a == A192GCMKW || a == ECDH_ES_A192KW || a == PBES2_HS384_A192KW { return 24; }
    if a == A256KW || a == A256GCMKW || a == ECDH_ES_A256KW || a == PBES2_HS512_A256KW { return 32; }
    return 0;
}

// --- key types and curves ------------------------------------------------------

fn kty_name(k: i64) -> const u8[:] {
    if k == KTY_EC { return "EC"; }
    if k == KTY_RSA { return "RSA"; }
    if k == KTY_OKP { return "OKP"; }
    if k == KTY_OCT { return "oct"; }
    if k == KTY_AKP { return "AKP"; }
    return "";
}

fn kty_lookup(s: const u8[:]) -> i64 {
    for k in [KTY_EC, KTY_RSA, KTY_OKP, KTY_OCT, KTY_AKP] {
        if kty_name(k) == s { return k; }
    }
    return KTY_UNKNOWN;
}

fn crv_name(c: i64) -> const u8[:] {
    if c == CRV_P256 { return "P-256"; }
    if c == CRV_P384 { return "P-384"; }
    if c == CRV_P521 { return "P-521"; }
    if c == CRV_ED25519 { return "Ed25519"; }
    if c == CRV_X25519 { return "X25519"; }
    if c == CRV_ED448 { return "Ed448"; }
    if c == CRV_X448 { return "X448"; }
    return "";
}

fn crv_lookup(s: const u8[:]) -> i64 {
    for c in [CRV_P256, CRV_P384, CRV_P521, CRV_ED25519, CRV_X25519, CRV_ED448, CRV_X448] {
        if crv_name(c) == s { return c; }
    }
    return CRV_UNKNOWN;
}

// The byte length of a curve's coordinates and private scalar.
fn crv_len(c: i64) -> i64 {
    if c == CRV_P256 { return 32; }
    if c == CRV_P384 { return 48; }
    if c == CRV_P521 { return 66; }
    if c == CRV_ED25519 || c == CRV_X25519 { return 32; }
    if c == CRV_ED448 { return 57; }
    if c == CRV_X448 { return 56; }
    return 0;
}

fn is_nist(c: i64) -> bool { c == CRV_P256 || c == CRV_P384 || c == CRV_P521 }

// The OKP curves (RFC 8037 §2): Ed25519 and Ed448 sign, X25519 and X448
// agree on keys.
fn is_okp(c: i64) -> bool { c == CRV_ED25519 || c == CRV_X25519 || c == CRV_ED448 || c == CRV_X448 }
fn is_edwards(c: i64) -> bool { c == CRV_ED25519 || c == CRV_ED448 }
fn is_montgomery(c: i64) -> bool { c == CRV_X25519 || c == CRV_X448 }

// The curves an EdDSA algorithm signs with: "EdDSA" (RFC 8037 §3.1) either
// Edwards curve, RFC 9864's "Ed25519" and "Ed448" their own only.
fn eddsa_fits(a: i64, c: i64) -> bool {
    if a == EDDSA { return is_edwards(c); }
    if a == ED25519 { return c == CRV_ED25519; }
    if a == ED448 { return c == CRV_ED448; }
    return false;
}

// The key type an algorithm works with: signing and verifying for
// signatures, the recipient's key for key management.
fn kty_of(a: i64) -> i64 {
    if is_hmac(a) || is_aes_kw(a) || is_gcm_kw(a) || is_pbes2(a) || a == DIRECT { return KTY_OCT; }
    if is_rsa_pkcs1(a) || is_rsa_pss(a) || is_rsa_kw(a) { return KTY_RSA; }
    if is_ecdsa(a) { return KTY_EC; }
    if is_eddsa(a) { return KTY_OKP; }
    if is_mldsa(a) { return KTY_AKP; }
    return KTY_UNKNOWN;     // ECDH-ES takes EC or OKP (X25519, X448); none takes none
}
