// jwx: JOSE, as Go's lestrrat-go/jwx has it: JSON Web Algorithms, Keys,
// Signatures, Encryption and Tokens (RFC 7515 to 7520, 7638, 7797, 8037).
//
//   jwx.jwa   algorithm, key type and curve identifiers (namespace jwa)
//   jwx.jwk   keys and key sets (namespace jwk)
//   jwx.jws   signatures (namespace jws)
//   jwx.jwe   encryption (namespace jwe)
//   jwx.jwt   tokens and their claims (namespace jwt)
//
// This module holds what they share: the error codes and base64url.

namespace jwx;

import std;

// --- Errors -------------------------------------------------------------------
//
// Every fallible function returns one of these (OK, 0, for success).

let OK: i64 = 0;
let ERR_MALFORMED: i64 = 1;          // not JSON, not base64url, missing or ill-typed members
let ERR_UNSUPPORTED: i64 = 2;        // an algorithm, key type or curve this package does not do
let ERR_ALG_MISMATCH: i64 = 3;       // the header's alg or enc is not the one asked for
let ERR_KEY: i64 = 4;                // a key unfit for the algorithm, or invalid
let ERR_BAD_SIGNATURE: i64 = 5;
let ERR_DECRYPT: i64 = 6;            // any failure to unwrap the key or open the ciphertext
let ERR_CRIT: i64 = 7;               // a "crit" header this package does not understand
let ERR_NONE: i64 = 8;               // "none" without asking for it
let ERR_NO_KEY: i64 = 9;             // no key of the set fits the message
let ERR_LIMIT: i64 = 10;             // a PBES2 count or an inflated payload over its limit
let ERR_EXPIRED: i64 = 11;           // jwt: exp is past
let ERR_NOT_YET_VALID: i64 = 12;     // jwt: nbf is ahead
let ERR_IAT: i64 = 13;               // jwt: iat is ahead, or older than allowed
let ERR_ISSUER: i64 = 14;
let ERR_SUBJECT: i64 = 15;
let ERR_AUDIENCE: i64 = 16;
let ERR_MISSING_CLAIM: i64 = 17;
let ERR_JTI: i64 = 18;

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_MALFORMED { return "jwx: malformed input"; }
    if e == ERR_UNSUPPORTED { return "jwx: unsupported algorithm, key type or curve"; }
    if e == ERR_ALG_MISMATCH { return "jwx: algorithm does not match the one expected"; }
    if e == ERR_KEY { return "jwx: invalid key, or a key of the wrong type for the algorithm"; }
    if e == ERR_BAD_SIGNATURE { return "jwx: signature verification failed"; }
    if e == ERR_DECRYPT { return "jwx: decryption failed"; }
    if e == ERR_CRIT { return "jwx: unsupported critical header parameter"; }
    if e == ERR_NONE { return "jwx: the none algorithm was not allowed"; }
    if e == ERR_NO_KEY { return "jwx: no key matches the message"; }
    if e == ERR_LIMIT { return "jwx: a limit was exceeded"; }
    if e == ERR_EXPIRED { return "jwt: \"exp\" not satisfied"; }
    if e == ERR_NOT_YET_VALID { return "jwt: \"nbf\" not satisfied"; }
    if e == ERR_IAT { return "jwt: \"iat\" not satisfied"; }
    if e == ERR_ISSUER { return "jwt: \"iss\" not satisfied"; }
    if e == ERR_SUBJECT { return "jwt: \"sub\" not satisfied"; }
    if e == ERR_AUDIENCE { return "jwt: \"aud\" not satisfied"; }
    if e == ERR_MISSING_CLAIM { return "jwt: a required claim is missing"; }
    if e == ERR_JTI { return "jwt: \"jti\" not satisfied"; }
    return "jwx: unknown error";
}

// --- base64url (RFC 4648 §5, without padding, as RFC 7515 §2 requires) -------

fn b64_symbol(v: u32) -> u8 {
    if v < 26 { return ('A' + v as! u8); }
    if v < 52 { return ('a' + (v - 26) as! u8); }
    if v < 62 { return ('0' + (v - 52) as! u8); }
    return if v == 62 { '-' } else { '_' };
}

// The 6-bit value of a base64url character, or 255.
fn b64_value(c: u8) -> u32 {
    if c >= 'A' && c <= 'Z' { return c - 'A'; }
    if c >= 'a' && c <= 'z' { return c - 'a' + 26; }
    if c >= '0' && c <= '9' { return c - '0' + 52; }
    if c == '-' { return 62; }
    if c == '_' { return 63; }
    return 255;
}

// data in base64url, appended to out.
fn b64_append(out: u8[>..]&, data: const u8[:]) {
    var i = 0;
    while i + 3 <= data.len {
        let v: u32 = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8 | data[i + 2];
        out.push(b64_symbol(v >> 18));
        out.push(b64_symbol(v >> 12 & 63));
        out.push(b64_symbol(v >> 6 & 63));
        out.push(b64_symbol(v & 63));
        i += 3;
    }
    let rest = data.len - i;
    if rest == 1 {
        let v: u32 = (data[i] as u32) << 16;
        out.push(b64_symbol(v >> 18));
        out.push(b64_symbol(v >> 12 & 63));
    } else if rest == 2 {
        let v: u32 = (data[i] as u32) << 16 | (data[i + 1] as u32) << 8;
        out.push(b64_symbol(v >> 18));
        out.push(b64_symbol(v >> 12 & 63));
        out.push(b64_symbol(v >> 6 & 63));
    }
}

fn b64_encode(data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    b64_append(out, data);
    return out;
}

// Decodes base64url text onto the end of out. Refuses padding, any byte
// outside the alphabet, a length that leaves one character over, and
// non-zero bits in the last character's unused low bits (so that every
// value has one encoding, as Go's RawURLEncoding.Strict has it).
fn b64_decode_append(out: u8[>..]&, s: const u8[:]) -> bool {
    if s.len % 4 == 1 { return false; }
    var acc: u32 = 0;
    var bits: u32 = 0;
    for c in s {
        let v = b64_value(c);
        if v == 255 { return false; }
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits & 255) as! u8);
        }
    }
    // What is left over must be zero bits.
    return (acc & ((1 << bits) - 1)) == 0;
}

fn b64_decode(s: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let ok = b64_decode_append(out, s);
    if !ok { out.resize(0); }
    return out, ok;
}

// --- JSON writing helpers ----------------------------------------------------------

// `"name":` then the string value, with a comma before it unless it is the
// first member written (out ends with '{').
fn put_comma(out: u8[>..]&) {
    if out.len > 0 && out[out.len - 1] != '{' && out[out.len - 1] != '[' { out.push(','); }
}
