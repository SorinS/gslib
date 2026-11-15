// webauthn.mds: the FIDO Metadata Service's BLOB (MDS3, FIDO Metadata
// Service v3.0 §3.1): a JWT whose header's x5c chains to the FIDO root
// the caller gives (GlobalSign Root R3 for the real service), checked
// with crypto/x509 and jwx, and whose payload lists the authenticators by
// AAGUID: their metadata statements' attestation roots (what an RP trusts
// a registration's x5c to), and their status reports. A lookup refuses an
// authenticator whose reports hold REVOKED or a compromise
// (USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE,
// USER_KEY_REMOTE_COMPROMISE, USER_KEY_PHYSICAL_COMPROMISE), whatever
// came after it. The BLOB is read from bytes: fetching it from the FIDO
// Alliance's MDS3 endpoint is the caller's.
//
//   var m = webauthn::Mds { .. };
//   let e = webauthn::parse_mds(blob, globalsign_r3_der, now, m);
//   var entry = webauthn::MdsEntry { .. };
//   if webauthn::mds_lookup(m, credential.aaguid, entry) && webauthn::mds_status_ok(entry) == webauthn::OK {
//       // entry.roots: the roots to verify_registration with
//   }

namespace webauthn;

import std;
import json;
import base64;
import webauthn;
import webauthn.register;
import encoding.asn1;
import crypto.x509;
import jwx;
import jwx.jwa;
import jwx.jwk;
import jwx.jws;
import jwx.pem;

// Status reports' statuses (FIDO Metadata Service v3.0 §3.1.4).
let STATUS_UNKNOWN:                      i64 = 0;
let STATUS_NOT_FIDO_CERTIFIED:           i64 = 1;
let STATUS_FIDO_CERTIFIED:               i64 = 2;
let STATUS_USER_VERIFICATION_BYPASS:     i64 = 3;
let STATUS_ATTESTATION_KEY_COMPROMISE:   i64 = 4;
let STATUS_USER_KEY_REMOTE_COMPROMISE:   i64 = 5;
let STATUS_USER_KEY_PHYSICAL_COMPROMISE: i64 = 6;
let STATUS_UPDATE_AVAILABLE:             i64 = 7;
let STATUS_REVOKED:                      i64 = 8;
let STATUS_SELF_ASSERTION_SUBMITTED:     i64 = 9;
let STATUS_FIDO_CERTIFIED_L1:            i64 = 10;
let STATUS_FIDO_CERTIFIED_L1PLUS:        i64 = 11;
let STATUS_FIDO_CERTIFIED_L2:            i64 = 12;
let STATUS_FIDO_CERTIFIED_L2PLUS:        i64 = 13;
let STATUS_FIDO_CERTIFIED_L3:            i64 = 14;
let STATUS_FIDO_CERTIFIED_L3PLUS:        i64 = 15;
let STATUS_NAMES: const u8[:][] = ["", "NOT_FIDO_CERTIFIED", "FIDO_CERTIFIED", "USER_VERIFICATION_BYPASS",
    "ATTESTATION_KEY_COMPROMISE", "USER_KEY_REMOTE_COMPROMISE", "USER_KEY_PHYSICAL_COMPROMISE", "UPDATE_AVAILABLE",
    "REVOKED", "SELF_ASSERTION_SUBMITTED", "FIDO_CERTIFIED_L1", "FIDO_CERTIFIED_L1plus", "FIDO_CERTIFIED_L2",
    "FIDO_CERTIFIED_L2plus", "FIDO_CERTIFIED_L3", "FIDO_CERTIFIED_L3plus"];

fn status_of(name: const u8[:]) -> i64 {
    for i in 1..STATUS_NAMES.len { if STATUS_NAMES[i] == name { return i; } }
    return STATUS_UNKNOWN;
}

fn status_refused(s: i64) -> bool {
    s == STATUS_REVOKED || s == STATUS_USER_VERIFICATION_BYPASS || s == STATUS_ATTESTATION_KEY_COMPROMISE
        || s == STATUS_USER_KEY_REMOTE_COMPROMISE || s == STATUS_USER_KEY_PHYSICAL_COMPROMISE
}

// A verified BLOB: its serial number, its nextUpdate (seconds since 1970,
// midnight UTC), whether that has passed at the `now` it was read at, and
// the payload JSON, which lookups read.
struct Mds {
    no:          i64       = 0,
    next_update: i64       = 0,
    stale:       bool      = false,
    message:     u8[..256] = [],
    payload:     u8[>..]   = [],
}

// One authenticator's entry: its description, the latest of its status
// reports and whether any of them refuses it, and the attestation roots of
// its metadata statement (DER certificates, concatenated).
struct MdsEntry {
    aaguid:      u8[16]    = [0; 16],
    description: u8[..256] = [],
    status:      i64       = STATUS_UNKNOWN, // the last report's
    refused:     i64       = STATUS_UNKNOWN, // a report that refuses it, or STATUS_UNKNOWN
    reports:     i64       = 0,
    roots:       u8[>..]   = [],
}

// "YYYY-MM-DD" as seconds since 1970 at its midnight, UTC.
fn mds_date(s: const u8[:]) -> i64, bool {
    if s.len != 10 || s[4] != '-' || s[7] != '-' { return 0, false; }
    let y, oky = parse_int(s[0..4]);
    let mo, okm = parse_int(s[5..7]);
    let d, okd = parse_int(s[8..10]);
    if !oky || !okm || !okd || mo < 1 || mo > 12 || d < 1 || d > 31 { return 0, false; }
    return asn1::days_from_civil(y, mo, d) * 86400, true;
}

fn mds_fail(m: Mds&, s: const u8[:]) -> i64 {
    m.message.clear();
    if s.len <= m.message.cap { m.message.append(s); } else { m.message.append(s[..m.message.cap - 3]); m.message.append("..."); }
    return ERR_METADATA;
}

// Verifies a BLOB (the JWT as served) against the FIDO root (a DER
// certificate, or several concatenated) at `now`: its x5c chains to the
// root, the signature is the leaf's, by RS256, ES256 or PS256 (as MDS3
// allows), and the payload has a serial number, a nextUpdate and an array
// of entries. OK, or ERR_METADATA with m.message saying why.
fn parse_mds(blob: const u8[:], fido_root: const u8[:], now: i64, m: Mds&) -> i64 {
    if now <= 0 || fido_root.len == 0 { return mds_fail(m, "no root, or no time"); }
    var msg = jws::Message { .. };
    let ep = jws::parse(msg, trim(blob));
    if ep != jwx::OK || !msg.compact || msg.sigs.len != 1 { return mds_fail(m, str("not a compact JWS: ", jwx::error_text(ep))); }
    let alg = msg.sigs[0].header.alg;
    if alg != jwa::RS256 && alg != jwa::ES256 && alg != jwa::PS256 { return mds_fail(m, "the BLOB's alg is not RS256, ES256 or PS256"); }
    // The protected header's x5c: standard base64 DER, the leaf first.
    var hdr: u8[>..] = [];
    if !jwx::b64_decode_append(hdr, jws::protected_text(msg, 0)) { return mds_fail(m, "the header is not base64url"); }
    var doc: json::Node[>..] = [];
    var dec: u8[>..]         = [];
    let root, err = json::parse(hdr, doc, dec);
    let x5c = json::member(root, "x5c");
    guard x5c else { return mds_fail(m, "no x5c in the header"); }
    var chain: u8[>..] = [];
    var leaf_end = -1;
    var bad = false;
    json::each(x5c) { c =>
        let s, ok = json::as_string(c);
        if !ok || !base64::decode(chain, s) { bad = true; }
        if leaf_end < 0 { leaf_end = chain.len; }
    };
    if bad || leaf_end <= 0 { return mds_fail(m, "x5c is not a list of base64 certificates"); }
    var tmsg: u8[..256] = [];
    let et = check_trust(chain, fido_root, now, tmsg);
    if et != OK { return mds_fail(m, str("the BLOB's certificates: ", tmsg)); }
    let leaf, ec = x509::parse(chain[..leaf_end]);
    if ec != x509::OK { return mds_fail(m, "the signing certificate does not parse"); }
    let key, ek = jwk::from_cert(leaf);
    if ek != jwx::OK { return mds_fail(m, "the signing certificate's key"); }
    let ev = jws::verify_signature(msg, 0, alg, key);
    if ev != jwx::OK { return mds_fail(m, str("the BLOB's signature: ", jwx::error_text(ev))); }
    // The payload.
    var pdoc: json::Node[>..] = [];
    var pdec: u8[>..]         = [];
    let p, perr = json::parse(msg.payload, pdoc, pdec);
    guard p else { return mds_fail(m, str("the payload: ", perr)); }
    let no, okn = json::as_i64(json::member(p, "no"));
    let nu, oku = json::as_string(json::member(p, "nextUpdate"));
    let when, okw = mds_date(nu);
    let entries = json::member(p, "entries");
    var is_arr = false;
    if entries { match entries.val { Arr => { is_arr = true; }, _ => {}, } }
    if !okn || !oku || !okw || !is_arr { return mds_fail(m, "the payload lacks no, nextUpdate or entries"); }
    m.no = no;
    m.next_update = when;
    m.stale = now >= when;
    m.payload.clear();
    m.payload.append(msg.payload);
    m.message.clear();
    return OK;
}

// "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" as 16 bytes.
fn aaguid_of_text(s: const u8[:], out: u8[16]&) -> bool {
    if s.len != 36 { return false; }
    var n = 0;
    var i = 0;
    while i < s.len {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if s[i] != '-' { return false; }
            i++;
            continue;
        }
        let a = ascii::hex_value(s[i]);
        let b = ascii::hex_value(s[i + 1]);
        if a < 0 || b < 0 { return false; }
        out[n] = (a * 16 + b) as! u8;
        n++;
        i += 2;
    }
    return n == 16;
}

// The entry for an AAGUID, into e; false when the BLOB has none (or one
// whose roots do not decode). The payload is read again each time.
fn mds_lookup(m: const Mds&, aaguid: const u8[:], e: MdsEntry&) -> bool {
    if aaguid.len != 16 || m.payload.len == 0 { return false; }
    var doc: json::Node[>..] = [];
    var dec: u8[>..]         = [];
    let p, perr = json::parse(m.payload, doc, dec);
    let entries = json::member(p, "entries");
    guard entries else { return false; }
    var found = false;
    var bad = false;
    // Cleared first: read_entry only appends, while the walk is on.
    e.description.clear();
    e.roots.clear();
    json::each(entries) { en =>
        let t, ok = json::as_string(json::member(en, "aaguid"));
        var a: u8[16] = [0; 16];
        if !found && ok && aaguid_of_text(t, a) && a[..] == aaguid {
            found = true;
            bad = !read_entry(en, a, e);
        }
    };
    return found && !bad;
}

// An entry's fields into e (cleared already); false when its roots do not decode.
fn read_entry(en: json::Node&, a: const u8[16]&, e: MdsEntry&) -> bool {
    var bad = false;
    for i in 16 { e.aaguid[i] = a[i]; }
    let ms = json::member(en, "metadataStatement");
    let desc, okd = json::as_string(json::member(ms, "description"));
    if okd {
        // A description is for people: a long one is cut, and says so.
        if desc.len <= e.description.cap { e.description.append(desc); }
        else { e.description.append(desc[..e.description.cap - 3]); e.description.append("..."); }
    }
    let rs = json::member(ms, "attestationRootCertificates");
    if rs {
        json::each(rs) { r =>
            let s, oks = json::as_string(r);
            var der: u8[>..] = [];
            if !oks || !base64::decode(der, s) { bad = true; } else { e.roots.append(der); }
        };
    }
    e.status = STATUS_UNKNOWN;
    e.refused = STATUS_UNKNOWN;
    e.reports = 0;
    let reports = json::member(en, "statusReports");
    if reports {
        json::each(reports) { r =>
            let s, oks = json::as_string(json::member(r, "status"));
            let st = if oks { status_of(s) } else { STATUS_UNKNOWN };
            e.status = st;
            e.reports += 1;
            if status_refused(st) && e.refused == STATUS_UNKNOWN { e.refused = st; }
        };
    }
    return !bad;
}

// OK when the entry's status reports allow the authenticator, ERR_STATUS
// when one refuses it.
fn mds_status_ok(e: const MdsEntry&) -> i64 {
    if e.refused != STATUS_UNKNOWN { return ERR_STATUS; }
    return OK;
}

fn status_name(s: i64) -> const u8[:] { if s >= 1 && s < STATUS_NAMES.len { STATUS_NAMES[s] } else { "unknown" } }
