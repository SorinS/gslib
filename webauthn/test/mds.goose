// MDS3: a BLOB made here (a test root, a signing certificate under it in
// x5c, ES256) verified and searched: an entry's description, roots and
// status; a revoked authenticator, one whose user verification could be
// bypassed (and was updated since: still refused), one certified; an
// AAGUID not listed. Refused: another root, the payload changed, x5c in
// base64url instead of base64, no x5c, alg HS256 and none, a signing
// certificate not yet valid, a payload without entries; a BLOB past its
// nextUpdate is read and marked stale. And a registration whose
// attestation roots come from the BLOB.
import std;
import base64;
import gslib from "../..";
import gslib.webauthn;
import gslib.webauthn.register;
import gslib.webauthn.mds;
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.pem;
import gslib.crypto.bignum;
import gslib.crypto.bignum.sha256;
import tv;

let A1 = "11111111-2222-3333-4444-555555555555";
let A2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
let A3 = "01020304-0506-0708-090a-0b0c0d0e0f10";

fn std64(der: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    base64::encode(out, der);
    return out;
}

fn payload(att_root: const u8[:], next: const u8[:], entries: bool) -> u8[>..] {
    var out: u8[>..] = [];
    format(out, "{\"legalHeader\":\"test\",\"no\":42,\"nextUpdate\":\"", next, "\"");
    if entries {
        format(out, ",\"entries\":[",
               "{\"attestationCertificateKeyIdentifiers\":[\"00\"],\"statusReports\":[{\"status\":\"FIDO_CERTIFIED\"}]},",
               "{\"aaguid\":\"", A1, "\",\"metadataStatement\":{\"description\":\"Test Key\",\"attestationRootCertificates\":[\"", std64(att_root), "\"]},",
               "\"statusReports\":[{\"status\":\"FIDO_CERTIFIED\",\"effectiveDate\":\"2024-01-01\"},{\"status\":\"FIDO_CERTIFIED_L2\",\"effectiveDate\":\"2025-01-01\"}]},",
               "{\"aaguid\":\"", A2, "\",\"metadataStatement\":{\"description\":\"Revoked Key\"},\"statusReports\":[{\"status\":\"FIDO_CERTIFIED\"},{\"status\":\"REVOKED\"}]},",
               "{\"aaguid\":\"", A3, "\",\"metadataStatement\":{\"description\":\"Bypassed Key\"},\"statusReports\":[{\"status\":\"USER_VERIFICATION_BYPASS\"},{\"status\":\"UPDATE_AVAILABLE\"}]}",
               "]");
    }
    out.push('}');
    return out;
}

fn blob(text: const u8[:], key: const x509::PrivateKey&, alg: i64, x5c_json: const u8[:]) -> u8[>..] {
    let k, ek = jwk::from_private(key);
    var h = jws::Header { .. };
    h.alg = alg;
    h.typ.append("JWT");
    let out, e = jws::sign_with(text, k, h, x5c_json);
    tv::check(str("sign blob: ", jwx::error_text(e)), e == jwx::OK);
    return out;
}

fn x5c_member(certs: const u8[:][:], url: bool) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("\"x5c\":[");
    for c, i in certs {
        if i > 0 { out.push(','); }
        out.push('"');
        out.append(if url { jwx::b64_encode(c) } else { std64(c) });
        out.push('"');
    }
    out.push(']');
    return out;
}

fn expect(what: const u8[:], b: const u8[:], root: const u8[:], now: i64, want: i64) {
    var m = webauthn::Mds { .. };
    let e = webauthn::parse_mds(b, root, now, m);
    tv::check_code(what, e, want, m.message);
}

fn main() {
    let now = tv::NOW;
    let root_key = x509::generate_key(x509::KEY_EC_P256);
    let root = tv::ca_cert(root_key);
    // The signing certificate, under the root.
    let sk = x509::generate_key(x509::KEY_EC_P256);
    let signer = tv::att_cert("CN=Test MDS Signer,O=Example,C=AA", sk, root, root_key, "");
    // An attestation root the BLOB lists for A1.
    let att_key = x509::generate_key(x509::KEY_EC_P256);
    let att_root = tv::ca_cert(att_key);
    let certs: const u8[:][] = [signer];
    let good = blob(payload(att_root, "2026-02-01", true), sk, jwa::ES256, x5c_member(certs, false));

    var m = webauthn::Mds { .. };
    let e = webauthn::parse_mds(good, root, now, m);
    tv::check_code("good blob", e, webauthn::OK, m.message);
    tv::check("no and nextUpdate", m.no == 42 && m.next_update == 1769904000 && !m.stale);
    var en = webauthn::MdsEntry { .. };
    var a1: u8[16] = [0; 16];
    tv::check("aaguid text", webauthn::aaguid_of_text(A1, a1));
    tv::check("lookup A1", webauthn::mds_lookup(m, a1, en));
    tv::check(str("A1 fields: ", en.description), en.description[..] == "Test Key" && en.roots[..] == att_root[..]
              && en.status == webauthn::STATUS_FIDO_CERTIFIED_L2 && en.reports == 2);
    tv::check("A1 allowed", webauthn::mds_status_ok(en) == webauthn::OK);
    var a2: u8[16] = [0; 16];
    let ok2 = webauthn::aaguid_of_text(A2, a2);
    var en2 = webauthn::MdsEntry { .. };
    tv::check("lookup A2", webauthn::mds_lookup(m, a2, en2) && en2.status == webauthn::STATUS_REVOKED);
    tv::check("A2 revoked", webauthn::mds_status_ok(en2) == webauthn::ERR_STATUS);
    var a3: u8[16] = [0; 16];
    let ok3 = webauthn::aaguid_of_text(A3, a3);
    var en3 = webauthn::MdsEntry { .. };
    tv::check("lookup A3", webauthn::mds_lookup(m, a3, en3) && en3.status == webauthn::STATUS_UPDATE_AVAILABLE);
    tv::check("A3 bypass, updated since: still refused", webauthn::mds_status_ok(en3) == webauthn::ERR_STATUS
              && en3.refused == webauthn::STATUS_USER_VERIFICATION_BYPASS);
    var en4 = webauthn::MdsEntry { .. };
    tv::check("not listed", !webauthn::mds_lookup(m, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09", en4));
    tv::check("bad aaguid text", !webauthn::aaguid_of_text("11111111-2222-3333-4444-55555555555", a1));

    // Refused.
    let other_key = x509::generate_key(x509::KEY_EC_P256);
    let other = tv::ca_cert(other_key);
    expect("another root", good, other, now, webauthn::ERR_METADATA);
    expect("no root", good, "", now, webauthn::ERR_METADATA);
    expect("no time", good, root, 0, webauthn::ERR_METADATA);
    expect("before the signer was valid", good, root, now - 10 * 86400, webauthn::ERR_METADATA);
    // The payload changed after signing.
    let dot1 = find(good, ".");
    let dot2 = dot1 + 1 + find(good[dot1 + 1..], ".");
    var changed: u8[>..] = [];
    changed.append(good[..dot1 + 1]);
    changed.append(jwx::b64_encode(payload(other, "2026-02-01", true)));
    changed.append(good[dot2..]);
    expect("payload changed", changed, root, now, webauthn::ERR_METADATA);
    expect("x5c in base64url", blob(payload(att_root, "2026-02-01", true), sk, jwa::ES256, x5c_member(certs, true)), root, now, webauthn::ERR_METADATA);
    expect("no x5c", blob(payload(att_root, "2026-02-01", true), sk, jwa::ES256, ""), root, now, webauthn::ERR_METADATA);
    expect("signed by another key", blob(payload(att_root, "2026-02-01", true), other_key, jwa::ES256, x5c_member(certs, false)), root, now, webauthn::ERR_METADATA);
    expect("no entries", blob(payload(att_root, "2026-02-01", false), sk, jwa::ES256, x5c_member(certs, false)), root, now, webauthn::ERR_METADATA);
    expect("bad nextUpdate", blob(payload(att_root, "2026-2-1", true), sk, jwa::ES256, x5c_member(certs, false)), root, now, webauthn::ERR_METADATA);
    // An HS256 BLOB: a JWT, but not one MDS signs.
    let hk = jwk::from_oct("0123456789abcdef0123456789abcdef");
    var hh = jws::Header { .. };
    hh.alg = jwa::HS256;
    let hb, ehb = jws::sign_with(payload(att_root, "2026-02-01", true), hk, hh, x5c_member(certs, false));
    expect("HS256", hb, root, now, webauthn::ERR_METADATA);
    // alg none: header {"alg":"none"} and no signature.
    var nb: u8[>..] = [];
    nb.append(jwx::b64_encode("{\"alg\":\"none\"}"));
    nb.push('.');
    nb.append(jwx::b64_encode(payload(att_root, "2026-02-01", true)));
    nb.push('.');
    expect("alg none", nb, root, now, webauthn::ERR_METADATA);
    expect("not a JWT", "hello", root, now, webauthn::ERR_METADATA);
    // Past nextUpdate: read, and stale.
    var ms = webauthn::Mds { .. };
    tv::check("stale", webauthn::parse_mds(blob(payload(att_root, "2025-12-01", true), sk, jwa::ES256, x5c_member(certs, false)), root, now, ms) == webauthn::OK && ms.stale);

    // A registration attested under A1's root, trusted through the BLOB.
    let akey = x509::generate_key(x509::KEY_EC_P256);
    let leaf = tv::att_cert("CN=Test Key,OU=Authenticator Attestation,O=Example,C=AA", akey, att_root, att_key, tv::aaguid_ext(a1));
    let ckey = x509::generate_key(x509::KEY_EC_P256);
    let chal = "mds-registration-challenge";
    let cdj = tv::client_data("webauthn.create", chal, tv::ORIGIN);
    let ad = tv::auth_data(tv::RP, 0x45, 0, a1, "cred-mds", tv::cose_key(ckey, cose::ES256));
    var signed = copy(ad);
    signed.append(bignum::sha256(cdj));
    let lcerts: const u8[:][] = [leaf];
    let ao = tv::att_obj("packed", tv::packed_stmt(cose::ES256, tv::sign(akey, cose::ES256, signed), lcerts), ad);
    var p = tv::policy(tv::RP, tv::ORIGIN);
    p.require_trusted = true;
    var c = webauthn::Credential { .. };
    var entry = webauthn::MdsEntry { .. };
    let found = webauthn::mds_lookup(m, a1, entry);
    let r = webauthn::verify_registration(p, chal, tv::reg_json("cred-mds", cdj, ao), entry.roots, c);
    tv::check_code("registration trusted through MDS", r, webauthn::OK, c.message);
    tv::check("its record", found && c.trusted && c.aaguid[..] == a1[..]);
    tv::done("mds");
}
