// webauthn: WebAuthn Level 3 and passkeys for a relying party (the
// server): the options a browser's navigator.credentials.create() and
// .get() take, as the L3 JSON serialization has them (base64url for
// bytes), and the checks of what comes back. A registration is checked
// whole (§7.1): clientDataJSON (its type, the challenge exactly, an
// origin from the RP's list, crossOrigin and topOrigin by policy), the
// attestation object (CBOR, strictly), the authenticator data (the RP ID's
// hash, the flags UP, UV, BE, BS, AT and ED and their consistency, a
// credential ID of at most 1023 bytes, the COSE key, nothing after), the
// algorithm against the RP's list, and the attestation statement by its
// format (webauthn/register.goose: none, packed, fido-u2f, tpm,
// android-key, apple), its certificates checked against roots the caller
// trusts with crypto/x509. What comes out is the credential record the RP
// stores (Credential, which marshal_credential makes bytes of). An
// authentication is checked against that record (§7.2): the same client
// data checks, the RP ID's hash and flags, the signature over authData ||
// SHA-256(clientDataJSON) by the stored key, the user handle of a
// discoverable credential, a signature counter that did not go forward
// (reported; refused only when the policy says so), and the backup flags.
// FIDO Metadata Service (MDS3) BLOBs are verified and searched by
// webauthn/mds.goose.
//
//   var p = webauthn::Policy { .. };
//   webauthn::set_rp(p, "example.org");
//   webauthn::add_origin(p, "https://example.org");
//   var o = webauthn::RegistrationOptions { .. };          // rp, user, ...
//   let json, e = webauthn::registration_options(o, []);   // to the browser; keep o.challenge
//   var c = webauthn::Credential { .. };
//   let r = webauthn::verify_registration(p, o.challenge, response_json, roots, c);
//   let stored = webauthn::marshal_credential(c);           // the RP keeps this
//   ...
//   var a = webauthn::Assertion { .. };
//   let r2 = webauthn::verify_authentication(p, challenge, response_json, c, user_handle, false, a);
//
// Nothing is kept in part: a value that does not fit where it goes is an
// error, never cut.

namespace webauthn;

import std;
import json;
import encoding.cbor;
import encoding.cbor.cose;
import encoding.asn1;
import crypto.x509;
import crypto.x509.keys;
import crypto.x509.verify;
import crypto.x509.pool;
import crypto.bignum;
import crypto.bignum.sha256;
import crypto.bignum.ct;
import crypto.bignum.entropy;
import jwx;

// --- Names ----------------------------------------------------------------------

// Authenticator data flags (§6.1).
let FLAG_UP: u8 = 0x01;
let FLAG_UV: u8 = 0x04;
let FLAG_BE: u8 = 0x08;
let FLAG_BS: u8 = 0x10;
let FLAG_AT: u8 = 0x40;
let FLAG_ED: u8 = 0x80;

// Transports (§5.8.4), as bits.
let TRANSPORT_USB:        u32           = 1;
let TRANSPORT_NFC:        u32           = 2;
let TRANSPORT_BLE:        u32           = 4;
let TRANSPORT_INTERNAL:   u32           = 8;
let TRANSPORT_HYBRID:     u32           = 16;
let TRANSPORT_SMART_CARD: u32           = 32;
let TRANSPORT_NAMES:      const u8[:][] = ["usb", "nfc", "ble", "internal", "hybrid", "smart-card"];

// authenticatorAttachment (§5.4.5).
let ATTACH_ANY:            i64 = 0;
let ATTACH_PLATFORM:       i64 = 1;
let ATTACH_CROSS_PLATFORM: i64 = 2;

// residentKey and userVerification requirements (§5.4.6, §5.8.6).
let REQ_DISCOURAGED: i64 = 1;
let REQ_PREFERRED:   i64 = 2;
let REQ_REQUIRED:    i64 = 3;

// Attestation conveyance (§5.4.7).
let CONVEY_NONE:       i64 = 0;
let CONVEY_INDIRECT:   i64 = 1;
let CONVEY_DIRECT:     i64 = 2;
let CONVEY_ENTERPRISE: i64 = 3;

// Hints (§5.8.7).
let HINT_SECURITY_KEY:  i64 = 1;
let HINT_CLIENT_DEVICE: i64 = 2;
let HINT_HYBRID:        i64 = 3;

// Attestation statement formats (§8), as numbers and as bits of
// Policy.formats.
let FMT_NONE:        i64           = 1;
let FMT_PACKED:      i64           = 2;
let FMT_FIDO_U2F:    i64           = 3;
let FMT_TPM:         i64           = 4;
let FMT_ANDROID_KEY: i64           = 5;
let FMT_APPLE:       i64           = 6;
let FMT_NAMES:       const u8[:][] = ["", "none", "packed", "fido-u2f", "tpm", "android-key", "apple"];
let FORMATS_ALL:     u32           = 0x7e;

fn format_bit(fmt: i64) -> u32 { 1 << fmt as u32 }

fn format_name(fmt: i64) -> const u8[:] { if fmt >= 1 && fmt <= 6 { FMT_NAMES[fmt] } else { "unknown" } }

fn format_of(name: const u8[:]) -> i64 {
    for i in 1..7 { if FMT_NAMES[i] == name { return i; } }
    return 0;
}

// Attestation types (§6.5.4).
let ATT_NONE:   i64 = 0;
let ATT_SELF:   i64 = 1;
let ATT_BASIC:  i64 = 2;       // or AttCA: the two look the same to an RP
let ATT_ANONCA: i64 = 3;

fn attestation_type_name(t: i64) -> const u8[:] {
    if t == ATT_SELF { return "self"; }
    if t == ATT_BASIC { return "basic"; }
    if t == ATT_ANONCA { return "anonca"; }
    return "none";
}

// The algorithms asked for when the caller names none, in order:
// ES256, EdDSA, RS256 (as most RPs and authenticators have them).
let DEFAULT_ALGS: i64[] = [-7, -8, -257];

// --- Errors ---------------------------------------------------------------------

let OK:                     i64 = 0;
let ERR_ARG:                i64 = 1;  // an argument that cannot be used
let ERR_MALFORMED:          i64 = 2;  // JSON, base64url, CBOR or a structure that is not what it should be
let ERR_TYPE:               i64 = 3;  // clientDataJSON's type is not webauthn.create / webauthn.get, or the credential's type
let ERR_CHALLENGE:          i64 = 4;  // not the challenge sent
let ERR_ORIGIN:             i64 = 5;  // an origin not on the RP's list
let ERR_CROSS_ORIGIN:       i64 = 6;  // crossOrigin true, or a topOrigin, not allowed
let ERR_RP_ID:              i64 = 7;  // rpIdHash is not the hash of the RP ID
let ERR_USER_PRESENCE:      i64 = 8;  // UP not set
let ERR_USER_VERIFICATION:  i64 = 9;  // UV required and not set
let ERR_FLAGS:              i64 = 10; // flags that contradict each other or the data (BS without BE, AT or ED wrong)
let ERR_TRAILING:           i64 = 11; // bytes after the authenticator data's last part
let ERR_CREDENTIAL_ID:      i64 = 12; // a credential ID over 1023 bytes, or not the one in the response
let ERR_KEY:                i64 = 13; // a credential public key that is not a usable COSE key
let ERR_ALGORITHM:          i64 = 14; // an algorithm not asked for, unknown, forbidden, or not the key's
let ERR_FORMAT:             i64 = 15; // an attestation format unknown or not allowed
let ERR_ATTESTATION:        i64 = 16; // an attestation statement that does not hold
let ERR_TRUST:              i64 = 17; // attestation certificates that do not chain to a trusted root (or none, when required)
let ERR_SIGNATURE:          i64 = 18; // an assertion signature that does not verify
let ERR_USER_HANDLE:        i64 = 19; // userHandle not the account's, or missing when it must be there
let ERR_UNKNOWN_CREDENTIAL: i64 = 20; // the response is for another credential than the record
let ERR_SIGN_COUNT:         i64 = 21; // the signature counter did not go forward (only when the policy refuses that)
let ERR_BACKUP:             i64 = 22; // BE is not what it was at registration
let ERR_LIMIT:              i64 = 23; // larger than a limit
let ERR_METADATA:           i64 = 24; // an MDS BLOB that is malformed or does not verify
let ERR_STATUS:             i64 = 25; // the authenticator's MDS status refuses it (revoked, compromised)

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "an argument that cannot be used"; }
    if e == ERR_MALFORMED { return "malformed"; }
    if e == ERR_TYPE { return "wrong type"; }
    if e == ERR_CHALLENGE { return "wrong challenge"; }
    if e == ERR_ORIGIN { return "origin not allowed"; }
    if e == ERR_CROSS_ORIGIN { return "cross-origin not allowed"; }
    if e == ERR_RP_ID { return "wrong RP ID"; }
    if e == ERR_USER_PRESENCE { return "user not present"; }
    if e == ERR_USER_VERIFICATION { return "user not verified"; }
    if e == ERR_FLAGS { return "inconsistent flags"; }
    if e == ERR_TRAILING { return "trailing bytes in the authenticator data"; }
    if e == ERR_CREDENTIAL_ID { return "bad credential ID"; }
    if e == ERR_KEY { return "bad credential public key"; }
    if e == ERR_ALGORITHM { return "algorithm not allowed"; }
    if e == ERR_FORMAT { return "attestation format not allowed"; }
    if e == ERR_ATTESTATION { return "attestation statement does not verify"; }
    if e == ERR_TRUST { return "attestation not trusted"; }
    if e == ERR_SIGNATURE { return "bad signature"; }
    if e == ERR_USER_HANDLE { return "wrong user handle"; }
    if e == ERR_UNKNOWN_CREDENTIAL { return "not this credential"; }
    if e == ERR_SIGN_COUNT { return "signature counter did not increase"; }
    if e == ERR_BACKUP { return "backup eligibility changed"; }
    if e == ERR_LIMIT { return "over a limit"; }
    if e == ERR_METADATA { return "bad metadata"; }
    if e == ERR_STATUS { return "authenticator status not acceptable"; }
    return "unknown error";
}

// A message for a failure: s, and an explicit "..." when it does not fit.
fn note(m: u8[..256]&, s: const u8[:]) {
    m.clear();
    if s.len <= m.cap { m.append(s); return; }
    m.append(s[..m.cap - 3]);
    m.append("...");
}

// --- base64url ------------------------------------------------------------------

fn b64url(data: const u8[:]) -> u8[>..] { jwx::b64_encode(data) }

// base64url text (RFC 4648 §5, no padding, the unused bits zero). With
// `lenient`, the standard alphabet and '=' padding are taken too, as some
// old clients wrote them.
fn unb64url(s: const u8[:], lenient: bool, out: u8[>..]&) -> bool {
    if !lenient { return jwx::b64_decode_append(out, s); }
    var t: u8[>..] = [];
    for c in s {
        if c == '+' { t.push('-'); } else if c == '/' { t.push('_'); } else { t.push(c); }
    }
    var n = t.len;
    while n > 0 && t[n - 1] == '=' { n--; }
    if t.len - n > 2 { return false; }
    let at = out.len;
    var acc:  u32 = 0;
    var bits: u32 = 0;
    if n % 4 == 1 { return false; }
    for c in t[..n] {
        let v = jwx::b64_value(c);
        if v == 255 { out.resize(at); return false; }
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits & 255) as! u8);
        }
    }
    return true;
}

// --- The relying party's policy ----------------------------------------------------

// What the RP expects and allows. Origins and top origins are lists kept
// one per line: set them with add_origin and add_top_origin, which refuse
// a line break inside one and a list that would not fit.
struct Policy {
    rp_id:                 u8[..253]  = [],
    origins:               u8[..4096] = [],    // the RP's origins, and related origins (§5.11)
    top_origins:           u8[..4096] = [],    // the pages that may embed the RP, when allow_cross_origin
    allow_cross_origin:    bool       = false, // take crossOrigin true (an iframe)
    user_verification:     i64        = REQ_PREFERRED, // REQ_REQUIRED: UV must be set
    require_user_presence: bool       = true,        // false only for conditional create (§5.1.3, step 21)
    algs:                  i64[..16]  = [],          // the credential algorithms asked for (empty: DEFAULT_ALGS)
    formats:               u32        = FORMATS_ALL, // the attestation formats taken
    require_trusted:       bool       = false,       // the attestation must chain to a root given (refuses none and self)
    allow_rs1:             bool       = false,       // TPM attestation signed by RS1 (old TPMs; SHA-1)
    tpm_any_vendor:        bool       = false,       // TPM manufacturers not in TCG's registry (simulators, the spec's vectors)
    min_rsa_bits:          i64        = 2048,        // the smallest RSA credential key
    lenient_base64:        bool       = false,       // take standard base64 and padding in responses too
    android_tee_only:      bool       = false,       // android-key: the TEE's authorization list only
    refuse_sign_count:     bool       = false,       // a counter that did not go forward is ERR_SIGN_COUNT, not just reported
    max_response:          i64        = 262144,      // the response JSON, in bytes
    now:                   i64        = 0,           // seconds since 1970, for attestation certificates' validity
}

fn set_rp(p: Policy&, rp_id: const u8[:]) -> bool {
    if rp_id.len == 0 || rp_id.len > p.rp_id.cap { return false; }
    p.rp_id.clear();
    p.rp_id.append(rp_id);
    return true;
}

fn add_line(list: u8[..4096]&, s: const u8[:]) -> bool {
    if s.len == 0 || find(s, "\n") >= 0 || list.len + s.len + 1 > list.cap { return false; }
    list.append(s);
    list.push('\n');
    return true;
}

// An origin the RP takes, as clientDataJSON has it: "https://example.org",
// no trailing slash, the port when it is not the scheme's default.
fn add_origin(p: Policy&, origin: const u8[:]) -> bool { add_line(p.origins, origin) }
fn add_top_origin(p: Policy&, origin: const u8[:]) -> bool { add_line(p.top_origins, origin) }

fn in_list(list: const u8[:], s: const u8[:]) -> bool {
    if s.len == 0 { return false; }
    var found = false;
    each_split(list, '\n') { if it.len > 0 && it == s { found = true; } };
    return found;
}

// The related origins document the RP serves at
// https://RP-ID/.well-known/webauthn (§5.11.1): its origins.
fn related_origins_json(p: const Policy&) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("{\"origins\":[");
    var first = true;
    each_split(p.origins, '\n') {
        if it.len > 0 {
            if !first { out.push(','); }
            first = false;
            json::format_string(out, it);
        }
    };
    out.append("]}");
    return out;
}

// --- Credential records ------------------------------------------------------------

// What an RP keeps of a credential (§4, "credential record"): its ID, its
// public key as the authenticator encoded it (a COSE_Key) and algorithm,
// the signature counter, whether the user was verified at registration,
// the backup flags, transports, the authenticator's AAGUID, how it was
// attested and whether that chained to a root the RP trusts, and the
// attestation certificates (DER, concatenated: the trust path).
struct Credential {
    id:               u8[..1023] = [],
    public_key:       u8[..1200] = [],
    alg:              i64        = 0,
    sign_count:       i64        = 0,
    uv:               bool       = false,
    backup_eligible:  bool       = false,
    backed_up:        bool       = false,
    transports:       u32        = 0,
    aaguid:           u8[16]     = [0; 16],
    fmt:              i64        = 0,
    attestation_type: i64        = ATT_NONE,
    trusted:          bool       = false,
    attachment:       i64        = ATTACH_ANY,
    rk:               i64        = -1, // credProps.rk: 1, 0, or -1 when the client did not say
    message:          u8[..256]  = [], // why a check failed
    x5c:              u8[>..]    = [],
}

// The record as bytes to store: a CBOR map, deterministically encoded.
fn marshal_credential(c: const Credential&) -> u8[>..] {
    var out: u8[>..] = [];
    cbor::put_map(out, 14);
    cbor::put_int(out, 1); cbor::put_bytes(out, c.id);
    cbor::put_int(out, 2); cbor::put_bytes(out, c.public_key);
    cbor::put_int(out, 3); cbor::put_int(out, c.alg);
    cbor::put_int(out, 4); cbor::put_int(out, c.sign_count);
    cbor::put_int(out, 5); cbor::put_bool(out, c.uv);
    cbor::put_int(out, 6); cbor::put_bool(out, c.backup_eligible);
    cbor::put_int(out, 7); cbor::put_bool(out, c.backed_up);
    cbor::put_int(out, 8); cbor::put_int(out, c.transports);
    cbor::put_int(out, 9); cbor::put_bytes(out, c.aaguid);
    cbor::put_int(out, 10); cbor::put_int(out, c.fmt);
    cbor::put_int(out, 11); cbor::put_int(out, c.attestation_type);
    cbor::put_int(out, 12); cbor::put_bool(out, c.trusted);
    cbor::put_int(out, 13); cbor::put_int(out, c.rk);
    cbor::put_int(out, 14); cbor::put_bytes(out, c.x5c);
    let e = cbor::sort_map(out, 0);
    return out;
}

// A record from marshal_credential's bytes.
fn parse_credential(b: const u8[:], c: Credential&) -> i64 {
    var doc: cbor::Node[>..] = [];
    let root, e = cbor::decode(b, cbor::Options { max_bytes: 1 << 24, .. }, doc);
    if e != cbor::OK || !cbor::is_map(doc, root) { return ERR_MALFORMED; }
    let id, ok1 = cbor::as_bytes(b, doc, cbor::map_get_int(doc, root, 1));
    let pk, ok2 = cbor::as_bytes(b, doc, cbor::map_get_int(doc, root, 2));
    let alg, ok3 = cbor::as_i64(doc, cbor::map_get_int(doc, root, 3));
    let count, ok4 = cbor::as_i64(doc, cbor::map_get_int(doc, root, 4));
    let uv, ok5 = cbor::as_bool(doc, cbor::map_get_int(doc, root, 5));
    let be, ok6 = cbor::as_bool(doc, cbor::map_get_int(doc, root, 6));
    let bs, ok7 = cbor::as_bool(doc, cbor::map_get_int(doc, root, 7));
    let tr, ok8 = cbor::as_i64(doc, cbor::map_get_int(doc, root, 8));
    let aaguid, ok9 = cbor::as_bytes(b, doc, cbor::map_get_int(doc, root, 9));
    let fmt, ok10 = cbor::as_i64(doc, cbor::map_get_int(doc, root, 10));
    let att, ok11 = cbor::as_i64(doc, cbor::map_get_int(doc, root, 11));
    let trusted, ok12 = cbor::as_bool(doc, cbor::map_get_int(doc, root, 12));
    let rk, ok13 = cbor::as_i64(doc, cbor::map_get_int(doc, root, 13));
    let x5c, ok14 = cbor::as_bytes(b, doc, cbor::map_get_int(doc, root, 14));
    if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8 && ok9 && ok10 && ok11 && ok12 && ok13 && ok14) {
        return ERR_MALFORMED;
    }
    if id.len == 0 || id.len > c.id.cap || pk.len > c.public_key.cap || aaguid.len != 16 || tr < 0 || tr > 0xffffffff {
        return ERR_MALFORMED;
    }
    c.id.clear(); c.id.append(id);
    c.public_key.clear(); c.public_key.append(pk);
    c.alg = alg;
    c.sign_count = count;
    c.uv = uv;
    c.backup_eligible = be;
    c.backed_up = bs;
    c.transports = tr as u32;
    for i in 16 { c.aaguid[i] = aaguid[i]; }
    c.fmt = fmt;
    c.attestation_type = att;
    c.trusted = trusted;
    c.rk = rk;
    c.x5c.clear();
    c.x5c.append(x5c);
    return OK;
}

// The AAGUID as text: 8-4-4-4-12 hex digits.
fn aaguid_text(a: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for i in a.len {
        if i == 4 || i == 6 || i == 8 || i == 10 { out.push('-'); }
        cbor::put_hex(out, a[i..i + 1]);
    }
    return out;
}

// --- Options ------------------------------------------------------------------------

// A credential to exclude (registration) or allow (authentication):
// its ID and the transports it was registered with.
struct Descriptor { id: u8[..1023] = [], transports: u32 = 0 }

// What PublicKeyCredentialCreationOptions say. An empty challenge is
// filled with 32 random bytes by registration_options, which the RP keeps
// to check the response against.
struct RegistrationOptions {
    rp_id:               u8[..253] = [],
    rp_name:             u8[..256] = [],
    user_id:             u8[..64]  = [], // the user handle: random, no personal data (§14.6.1)
    user_name:           u8[..256] = [],
    user_display_name:   u8[..256] = [],
    challenge:           u8[..64]  = [],
    timeout_ms:          i64       = 300000,
    algs:                i64[..16] = [], // empty: DEFAULT_ALGS
    attachment:          i64       = ATTACH_ANY,
    resident_key:        i64       = REQ_PREFERRED,
    user_verification:   i64       = REQ_PREFERRED,
    attestation:         i64       = CONVEY_NONE,
    attestation_formats: i64[..6]  = [],   // FMT_*, most preferred first (L3); empty: not sent
    hints:               i64[..3]  = [],   // HINT_*, most preferred first
    cred_props:          bool      = true, // ask for the credProps extension
}

struct AuthenticationOptions {
    rp_id:             u8[..253] = [],
    challenge:         u8[..64]  = [],
    timeout_ms:        i64       = 300000,
    user_verification: i64       = REQ_PREFERRED,
    hints:             i64[..3]  = [],
}

fn requirement_name(r: i64) -> const u8[:] {
    if r == REQ_DISCOURAGED { return "discouraged"; }
    if r == REQ_REQUIRED { return "required"; }
    return "preferred";
}

fn hint_name(h: i64) -> const u8[:] {
    if h == HINT_SECURITY_KEY { return "security-key"; }
    if h == HINT_CLIENT_DEVICE { return "client-device"; }
    return "hybrid";
}

fn conveyance_name(c: i64) -> const u8[:] {
    if c == CONVEY_INDIRECT { return "indirect"; }
    if c == CONVEY_DIRECT { return "direct"; }
    if c == CONVEY_ENTERPRISE { return "enterprise"; }
    return "none";
}

// 32 random bytes, for a challenge or a user handle.
fn new_random(out: u8[..64]&) {
    var b: u8[32] = [0; 32];
    bignum::random_bytes(b);
    out.clear();
    out.append(b);
}

fn put_key_b64(out: u8[>..]&, key: const u8[:], v: const u8[:]) {
    json::format_key(out, key);
    out.push('"');
    jwx::b64_append(out, v);
    out.push('"');
}

fn put_key_string(out: u8[>..]&, key: const u8[:], v: const u8[:]) {
    json::format_key(out, key);
    json::format_string(out, v);
}

fn put_descriptors(out: u8[>..]&, key: const u8[:], ds: const Descriptor[:]) {
    json::format_key(out, key);
    out.push('[');
    for d, i in ds {
        if i > 0 { out.push(','); }
        out.append("{\"type\":\"public-key\",");
        put_key_b64(out, "id", d.id);
        if d.transports != 0 {
            out.append(",\"transports\":[");
            var n = 0;
            for t in TRANSPORT_NAMES.len {
                if d.transports & (1 << t as u32) != 0 {
                    if n > 0 { out.push(','); }
                    json::format_string(out, TRANSPORT_NAMES[t]);
                    n++;
                }
            }
            out.push(']');
        }
        out.push('}');
    }
    out.push(']');
}

fn put_hints(out: u8[>..]&, hints: const i64[:]) {
    if hints.len == 0 { return; }
    out.append(",\"hints\":[");
    for h, i in hints {
        if i > 0 { out.push(','); }
        json::format_string(out, hint_name(h));
    }
    out.push(']');
}

// PublicKeyCredentialCreationOptionsJSON (L3 §5.1.1) for
// PublicKeyCredential.parseCreationOptionsFromJSON(), and OK; the
// challenge is made when o.challenge is empty. ERR_ARG without an RP ID,
// an RP name or a user handle, or for an algorithm cose does not know.
fn registration_options(o: RegistrationOptions&, exclude: const Descriptor[:]) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if o.rp_id.len == 0 || o.rp_name.len == 0 || o.user_id.len == 0 { return out, ERR_ARG; }
    for a in o.algs { if !cose::known_alg(a) || a == cose::RS1 { return out, ERR_ARG; } }
    if o.challenge.len == 0 { new_random(o.challenge); }
    out.append("{\"rp\":{");
    put_key_string(out, "name", o.rp_name);
    out.push(',');
    put_key_string(out, "id", o.rp_id);
    out.append("},\"user\":{");
    put_key_b64(out, "id", o.user_id);
    out.push(',');
    put_key_string(out, "name", o.user_name);
    out.push(',');
    put_key_string(out, "displayName", o.user_display_name);
    out.append("},");
    put_key_b64(out, "challenge", o.challenge);
    out.append(",\"pubKeyCredParams\":[");
    if o.algs.len == 0 {
        for a, i in DEFAULT_ALGS { if i > 0 { out.push(','); } format(out, "{\"type\":\"public-key\",\"alg\":", a, "}"); }
    } else {
        for a, i in o.algs { if i > 0 { out.push(','); } format(out, "{\"type\":\"public-key\",\"alg\":", a, "}"); }
    }
    out.append("],");
    format(out, "\"timeout\":", o.timeout_ms, ",");
    put_descriptors(out, "excludeCredentials", exclude);
    out.append(",\"authenticatorSelection\":{");
    if o.attachment != ATTACH_ANY {
        put_key_string(out, "authenticatorAttachment", if o.attachment == ATTACH_PLATFORM { "platform" } else { "cross-platform" });
        out.push(',');
    }
    put_key_string(out, "residentKey", requirement_name(o.resident_key));
    format(out, ",\"requireResidentKey\":", o.resident_key == REQ_REQUIRED, ",");
    put_key_string(out, "userVerification", requirement_name(o.user_verification));
    out.push('}');
    put_hints(out, o.hints);
    out.push(',');
    put_key_string(out, "attestation", conveyance_name(o.attestation));
    if o.attestation_formats.len > 0 {
        out.append(",\"attestationFormats\":[");
        for f, i in o.attestation_formats {
            if i > 0 { out.push(','); }
            json::format_string(out, format_name(f));
        }
        out.push(']');
    }
    out.append(",\"extensions\":{");
    if o.cred_props { out.append("\"credProps\":true"); }
    out.append("}}");
    return out, OK;
}

// PublicKeyCredentialRequestOptionsJSON (L3 §5.5.1). An empty `allow`
// leaves the choice of credential to the authenticator: a discoverable
// credential (a passkey), whose response carries the user handle.
fn authentication_options(o: AuthenticationOptions&, allow: const Descriptor[:]) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if o.rp_id.len == 0 { return out, ERR_ARG; }
    if o.challenge.len == 0 { new_random(o.challenge); }
    out.push('{');
    put_key_b64(out, "challenge", o.challenge);
    format(out, ",\"timeout\":", o.timeout_ms, ",");
    put_key_string(out, "rpId", o.rp_id);
    out.push(',');
    put_descriptors(out, "allowCredentials", allow);
    out.push(',');
    put_key_string(out, "userVerification", requirement_name(o.user_verification));
    put_hints(out, o.hints);
    out.append(",\"extensions\":{}}");
    return out, OK;
}

// --- Responses --------------------------------------------------------------------

// A PublicKeyCredential as RegistrationResponseJSON or
// AuthenticationResponseJSON (L3 §5.1) has it, its bytes decoded.
root struct Response {
    id:                 u8[>..] = [],
    client_data:        u8[>..] = [],
    attestation_object: u8[>..] = [],
    authenticator_data: u8[>..] = [],
    signature:          u8[>..] = [],
    user_handle:        u8[>..] = [],
    has_user_handle:    bool    = false,
    transports:         u32     = 0,
    attachment:         i64     = ATTACH_ANY,
    rk:                 i64     = -1,
}

// The first member named key, or null; ERR_MALFORMED in dup when there
// are two.
fn only_member(n: json::Node?, key: const u8[:], dup: bool&) -> json::Node? {
    guard n else { return null; }
    var count = 0;
    var c = n.first;
    while c {
        if c.key == key { count++; }
        c .= c.next;
    }
    if count > 1 { dup = true; }
    return json::member(n, key);
}

fn take_b64(n: json::Node?, key: const u8[:], lenient: bool, out: u8[>..]&, dup: bool&) -> bool {
    let s, ok = json::as_string(only_member(n, key, dup));
    if !ok { return false; }
    return unb64url(s, lenient, out);
}

// Reads a response's JSON into r: id and rawId (which must be the same
// bytes), type "public-key", and the response's members for a
// registration (attestation) or an authentication (not).
fn parse_response(r: Response&, text: const u8[:], registration: bool, lenient: bool, max: i64, msg: u8[..256]&) -> i64 {
    if text.len > max { note(msg, "response JSON over the size limit"); return ERR_LIMIT; }
    if !cbor::valid_utf8(text) { note(msg, "response JSON is not UTF-8"); return ERR_MALFORMED; }
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, err = json::parse(text, doc, decoded);
    guard root else { note(msg, err); return ERR_MALFORMED; }
    var dup = false;
    let ty, okt = json::as_string(only_member(root, "type", dup));
    if !okt || ty != "public-key" { note(msg, "type is not public-key"); return ERR_TYPE; }
    var raw: u8[>..] = [];
    if !take_b64(root, "id", lenient, r.id, dup) || !take_b64(root, "rawId", lenient, raw, dup) {
        note(msg, "id or rawId missing or not base64url");
        return ERR_MALFORMED;
    }
    if r.id[..] != raw[..] { note(msg, "id is not rawId"); return ERR_CREDENTIAL_ID; }
    if r.id.len == 0 || r.id.len > 1023 { note(msg, "credential ID empty or over 1023 bytes"); return ERR_CREDENTIAL_ID; }
    let resp = only_member(root, "response", dup);
    if !take_b64(resp, "clientDataJSON", lenient, r.client_data, dup) { note(msg, "no clientDataJSON"); return ERR_MALFORMED; }
    if registration {
        if !take_b64(resp, "attestationObject", lenient, r.attestation_object, dup) { note(msg, "no attestationObject"); return ERR_MALFORMED; }
        let ts = only_member(resp, "transports", dup);
        if ts {
            var bad = false;
            json::each(ts) { t =>
                let s, ok = json::as_string(t);
                if !ok { bad = true; }
                for k in TRANSPORT_NAMES.len { if TRANSPORT_NAMES[k] == s { r.transports = r.transports | (1 << k as u32); } }
            };
            if bad { note(msg, "transports is not a list of strings"); return ERR_MALFORMED; }
        }
    } else {
        if !take_b64(resp, "authenticatorData", lenient, r.authenticator_data, dup)
            || !take_b64(resp, "signature", lenient, r.signature, dup) {
            note(msg, "no authenticatorData or signature");
            return ERR_MALFORMED;
        }
        let uh = only_member(resp, "userHandle", dup);
        if uh {
            match uh.val {
                Null => {},
                _ => {
                    let s, ok = json::as_string(uh);
                    if !ok || !unb64url(s, lenient, r.user_handle) { note(msg, "userHandle not base64url"); return ERR_MALFORMED; }
                    r.has_user_handle = r.user_handle.len > 0;
                },
            }
        }
    }
    let att, oka = json::as_string(only_member(root, "authenticatorAttachment", dup));
    if oka { r.attachment = if att == "platform" { ATTACH_PLATFORM } else if att == "cross-platform" { ATTACH_CROSS_PLATFORM } else { ATTACH_ANY }; }
    let ext = only_member(root, "clientExtensionResults", dup);
    let rk, okrk = json::as_bool(json::member(json::member(ext, "credProps"), "rk"));
    if okrk { r.rk = if rk { 1 } else { 0 }; }
    if dup { note(msg, "a member twice in the response JSON"); return ERR_MALFORMED; }
    return OK;
}

// The credential ID and user handle of an authentication response, to find
// the credential record (and, for a passkey, the account) before
// verify_authentication: OK, or why the JSON will not do.
fn response_ids(text: const u8[:], id: u8[>..]&, user_handle: u8[>..]&, lenient: bool = false) -> i64 {
    var r = Response { .. };
    var msg: u8[..256] = [];
    let e = parse_response(r, text, false, lenient, 1 << 20, msg);
    if e != OK { return e; }
    id.append(r.id);
    user_handle.append(r.user_handle);
    return OK;
}

// --- Client data ---------------------------------------------------------------------

// Checks clientDataJSON (§7.1 steps 5-11, §7.2 steps 9-14): UTF-8 JSON
// with no member twice, type `want_type`, the challenge exactly, an origin
// on the RP's list, crossOrigin and topOrigin by the policy, and a
// tokenBinding, when there, with a status WebAuthn Level 2 knows.
fn check_client_data(p: const Policy&, cd: const u8[:], want_type: const u8[:], challenge: const u8[:], msg: u8[..256]&) -> i64 {
    if !cbor::valid_utf8(cd) { note(msg, "clientDataJSON is not UTF-8"); return ERR_MALFORMED; }
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, err = json::parse(cd, doc, decoded);
    guard root else { note(msg, err); return ERR_MALFORMED; }
    match root.val {
        Obj => {},
        _ => { note(msg, "clientDataJSON is not an object"); return ERR_MALFORMED; },
    }
    var dup = false;
    let ty, okt = json::as_string(only_member(root, "type", dup));
    let ch, okc = json::as_string(only_member(root, "challenge", dup));
    let origin, oko = json::as_string(only_member(root, "origin", dup));
    let co = only_member(root, "crossOrigin", dup);
    let to = only_member(root, "topOrigin", dup);
    let tb = only_member(root, "tokenBinding", dup);
    if dup { note(msg, "a member twice in clientDataJSON"); return ERR_MALFORMED; }
    if !okt || ty != want_type { note(msg, str("type is not ", want_type)); return ERR_TYPE; }
    var got: u8[>..] = [];
    if !okc || !jwx::b64_decode_append(got, ch) { note(msg, "challenge missing or not base64url"); return ERR_CHALLENGE; }
    if got.len != challenge.len || bignum::ct_eq_bytes(got, challenge) == 0 { note(msg, "not the challenge sent"); return ERR_CHALLENGE; }
    if !oko || !in_list(p.origins, origin) { note(msg, str("origin not allowed: ", origin)); return ERR_ORIGIN; }
    var cross = false;
    if co {
        let v, ok = json::as_bool(co);
        if !ok { note(msg, "crossOrigin is not a boolean"); return ERR_MALFORMED; }
        cross = v;
    }
    if cross && !p.allow_cross_origin { note(msg, "crossOrigin true"); return ERR_CROSS_ORIGIN; }
    if to {
        let top, ok = json::as_string(to);
        if !ok { note(msg, "topOrigin is not a string"); return ERR_MALFORMED; }
        // A topOrigin is there only for a cross-origin call (§5.8.1).
        if !cross { note(msg, "topOrigin without crossOrigin"); return ERR_CROSS_ORIGIN; }
        if !in_list(p.top_origins, top) { note(msg, str("topOrigin not allowed: ", top)); return ERR_CROSS_ORIGIN; }
    }
    // Token binding (Level 2; reserved in Level 3): an object's status
    // must be one Level 2 knows. Anything else (old Edge wrote the string
    // "unused") is passed over, as other RPs do.
    if tb {
        match tb.val {
            Obj => {
                let status, oks = json::as_string(json::member(tb, "status"));
                if !oks || (status != "present" && status != "supported") { note(msg, "tokenBinding status unknown"); return ERR_MALFORMED; }
            },
            _ => {},
        }
    }
    return OK;
}

// --- Authenticator data -----------------------------------------------------------------

// Authenticator data (§6.1), parsed: offsets into it for the credential
// public key and the extensions, when there.
struct AuthData {
    rp_id_hash: u8[32]     = [0; 32],
    flags:      u8         = 0,
    sign_count: i64        = 0,
    aaguid:     u8[16]     = [0; 16],
    cred_id:    u8[..1023] = [],
    key_at:     i64        = 0,
    key_end:    i64        = 0,
    ext_at:     i64        = 0,
    ext_end:    i64        = 0,
}

// Parses authenticator data: the attested credential data when AT says so
// (a credential ID of at most 1023 bytes, a COSE key decoded strictly),
// the extensions (a CBOR map) when ED says so, and nothing after them.
// BS without BE is ERR_FLAGS.
fn parse_auth_data(b: const u8[:], a: AuthData&, msg: u8[..256]&) -> i64 {
    if b.len < 37 { note(msg, "authenticator data shorter than 37 bytes"); return ERR_MALFORMED; }
    for i in 32 { a.rp_id_hash[i] = b[i]; }
    a.flags = b[32];
    a.sign_count = (b[33] as i64) << 24 | (b[34] as i64) << 16 | (b[35] as i64) << 8 | b[36];
    if a.flags & FLAG_BS != 0 && a.flags & FLAG_BE == 0 { note(msg, "BS set without BE"); return ERR_FLAGS; }
    var pos = 37;
    if a.flags & FLAG_AT != 0 {
        if b.len < pos + 18 { note(msg, "attested credential data cut short"); return ERR_MALFORMED; }
        for i in 16 { a.aaguid[i] = b[pos + i]; }
        let n = (b[pos + 16] as i64) << 8 | b[pos + 17];
        pos += 18;
        if n > 1023 { note(msg, "credential ID over 1023 bytes"); return ERR_CREDENTIAL_ID; }
        if n == 0 { note(msg, "empty credential ID"); return ERR_CREDENTIAL_ID; }
        if b.len < pos + n { note(msg, "credential ID cut short"); return ERR_MALFORMED; }
        a.cred_id.clear();
        a.cred_id.append(b[pos..pos + n]);
        pos += n;
        var doc: cbor::Node[>..] = [];
        let root, end, e = cbor::decode_at(b, pos, cbor::Options { .. }, doc);
        if e != cbor::OK { note(msg, str("credential public key: ", cbor::error_text(e))); return if e == cbor::ERR_DUPLICATE_KEY { ERR_KEY } else { ERR_MALFORMED }; }
        a.key_at = pos;
        a.key_end = end;
        pos = end;
    }
    if a.flags & FLAG_ED != 0 {
        var doc: cbor::Node[>..] = [];
        let root, end, e = cbor::decode_at(b, pos, cbor::Options { .. }, doc);
        if e != cbor::OK || !cbor::is_map(doc, root) { note(msg, "extensions are not a CBOR map"); return ERR_MALFORMED; }
        a.ext_at = pos;
        a.ext_end = end;
        pos = end;
    }
    if pos != b.len {
        note(msg, if a.flags & FLAG_ED == 0 && pos < b.len { "bytes after the authenticator data (ED not set)" } else { "trailing bytes" });
        return ERR_TRAILING;
    }
    return OK;
}

// Checks the RP ID hash and the user presence and verification flags.
fn check_flags(p: const Policy&, a: const AuthData&, msg: u8[..256]&) -> i64 {
    let want = bignum::sha256(p.rp_id);
    if bignum::ct_eq_bytes(want, a.rp_id_hash) == 0 { note(msg, "rpIdHash is not the RP ID's"); return ERR_RP_ID; }
    if p.require_user_presence && a.flags & FLAG_UP == 0 { note(msg, "UP not set"); return ERR_USER_PRESENCE; }
    if p.user_verification == REQ_REQUIRED && a.flags & FLAG_UV == 0 { note(msg, "UV required, not set"); return ERR_USER_VERIFICATION; }
    return OK;
}

fn sha256_of(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(bignum::sha256(b));
    return out;
}

// --- Authentication -----------------------------------------------------------------------

// What an authentication found: the credential and user handle, the new
// signature counter (to store), and the flags.
struct Assertion {
    credential_id:     u8[..1023] = [],
    user_handle:       u8[..64]   = [],
    sign_count:        i64        = 0,
    up:                bool       = false,
    uv:                bool       = false,
    backed_up:         bool       = false,
    counter_regressed: bool       = false, // the counter did not go forward: a cloned authenticator, maybe
    backup_changed:    bool       = false, // BS is not what the record says: store the new one
    attachment:        i64        = ATTACH_ANY,
    message:           u8[..256]  = [],
}

// Verifies an authentication response (§7.2) against the challenge sent
// and the credential's record, and fills a with OK. `user_handle` is the
// handle of the account the record belongs to; a response that carries
// one must carry that one, and with `require_user_handle` (a passkey
// sign-in, when allowCredentials was empty and the user was not known
// beforehand) it must carry one. The signature counter is the record's:
// one that did not go forward is reported in a.counter_regressed, and
// refused when p.refuse_sign_count. Store a.sign_count and a.backed_up in
// the record afterwards.
fn verify_authentication(p: const Policy&, challenge: const u8[:], response_json: const u8[:], cred: const Credential&,
                         user_handle: const u8[:], require_user_handle: bool, a: Assertion&) -> i64 {
    if p.rp_id.len == 0 || p.origins.len == 0 || challenge.len == 0 { note(a.message, "no RP ID, origins or challenge"); return ERR_ARG; }
    var r = Response { .. };
    let e1 = parse_response(r, response_json, false, p.lenient_base64, p.max_response, a.message);
    if e1 != OK { return e1; }
    if r.id[..] != cred.id[..] { note(a.message, "the response is for another credential"); return ERR_UNKNOWN_CREDENTIAL; }
    if r.has_user_handle {
        if user_handle.len == 0 || r.user_handle[..] != user_handle { note(a.message, "userHandle is not the account's"); return ERR_USER_HANDLE; }
    } else if require_user_handle {
        note(a.message, "no userHandle from a discoverable credential");
        return ERR_USER_HANDLE;
    }
    let e2 = check_client_data(p, r.client_data, "webauthn.get", challenge, a.message);
    if e2 != OK { return e2; }
    var ad = AuthData { .. };
    let e3 = parse_auth_data(r.authenticator_data, ad, a.message);
    if e3 != OK { return e3; }
    let e4 = check_flags(p, ad, a.message);
    if e4 != OK { return e4; }
    if ad.flags & FLAG_AT != 0 { note(a.message, "AT set in an assertion"); return ERR_FLAGS; }
    let be = ad.flags & FLAG_BE != 0;
    if be != cred.backup_eligible { note(a.message, "BE is not what it was at registration"); return ERR_BACKUP; }
    // The signature, by the stored key and algorithm.
    let key, ek = cose::decode(cred.public_key, p.min_rsa_bits);
    if ek != cose::OK { note(a.message, str("stored public key: ", cose::error_text(ek))); return ERR_KEY; }
    var signed: u8[>..] = [];
    signed.append(r.authenticator_data);
    signed.append(bignum::sha256(r.client_data));
    let ev = cose::verify(key, cred.alg, signed, r.signature);
    if ev != cose::OK {
        note(a.message, str("signature: ", cose::error_text(ev)));
        return if ev == cose::ERR_SIGNATURE { ERR_SIGNATURE } else { ERR_ALGORITHM };
    }
    a.counter_regressed = (ad.sign_count != 0 || cred.sign_count != 0) && ad.sign_count <= cred.sign_count;
    if a.counter_regressed && p.refuse_sign_count {
        note(a.message, str("signature counter ", ad.sign_count, " is not above ", cred.sign_count));
        return ERR_SIGN_COUNT;
    }
    a.credential_id.clear();
    a.credential_id.append(r.id);
    a.user_handle.clear();
    if r.user_handle.len > a.user_handle.cap { note(a.message, "userHandle over 64 bytes"); return ERR_USER_HANDLE; }
    a.user_handle.append(r.user_handle);
    a.sign_count = ad.sign_count;
    a.up = ad.flags & FLAG_UP != 0;
    a.uv = ad.flags & FLAG_UV != 0;
    a.backed_up = ad.flags & FLAG_BS != 0;
    a.backup_changed = a.backed_up != cred.backed_up;
    a.attachment = r.attachment;
    a.message.clear();
    return OK;
}
