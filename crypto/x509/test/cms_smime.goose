// x509.cms and x509.cms_env for S/MIME, against cms_smime/vectors.txt
// (mail/scripts/interop_smime.py --write-vectors): SignedData over id-data
// made by `openssl cms -sign`, detached and not, by RSA (PKCS #1 v1.5 and
// PSS), P-256 by key identifier, P-384 with SHA-384, Ed25519, without
// signed attributes, in BER, must verify, with the content and the
// signing time, and refuse a changed content; EnvelopedData and
// AuthEnvelopedData made by `openssl cms -encrypt` (RSA PKCS #1 v1.5 and
// OAEP with SHA-1 and SHA-256, by key identifier, AES-192; ECDH with the
// SHA-1 and SHA-256 KDFs, P-384; GCM; several recipients; BER) must
// decrypt for each recipient, and not for others. Then what is made here
// (every signer, every cipher, every way of naming a recipient) must read
// back here, and refuse changed bytes and wrong keys. (The interop script
// has openssl read what is made here.)
import std;
import gslib from "../../..";
import gslib.crypto.x509;
import gslib.encoding.asn1;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.cms;
import gslib.crypto.x509.cms_env;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 20 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

let VECTORS = embed_file("cms_smime/vectors.txt");

// The certificate (DER) and private key (PKCS #8) of a key line.
fn key_of(name: const u8[:]) -> u8[>..], u8[>..] {
    for line in split(VECTORS, '\n') {
        let w = words(line);
        if w.len == 4 && w[0] == "key" && w[1] == name { return unhex(w[2]), unhex(w[3]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none, unhex("");
}

fn content() -> u8[>..] {
    for line in split(VECTORS, '\n') {
        let w = words(line);
        if w.len == 2 && w[0] == "content" { return unhex(w[1]); }
    }
    assert(false);
    return unhex("");
}

fn has_name(list: const u8[:], name: const u8[:]) -> bool {
    for n in split(list, ',') { if n == name { return true; } }
    return false;
}

fn signed_vector(label: const u8[:], who: const u8[:], detached: bool, der: const u8[:], data: const u8[:]) {
    let cd, kd = key_of(who);
    let sd, ep = x509::cms_parse_signed_ber(der);
    check(label, ep == x509::OK && sd.has_content != detached);
    if ep != x509::OK { return; }
    var e = 0;
    if detached {
        let s, ev = x509::cms_verify_detached(sd, data);
        e = ev;
        check(label, ev == x509::OK && s.der == cd);
        // The content changed: refused.
        var bad: u8[>..] = [];
        bad.append(data);
        bad[bad.len - 3] ^= 1;
        let s2, ev2 = x509::cms_verify_detached(sd, bad);
        check(label, ev2 == x509::ERR_BAD_SIGNATURE);
        // A detached signature is not one with content, nor the other way.
        let s3, ev3 = x509::cms_verify(sd);
        check(label, ev3 == x509::ERR_MALFORMED);
    } else {
        let s, ev = x509::cms_verify(sd);
        e = ev;
        check(label, ev == x509::OK && s.der == cd && x509::cms_content(sd) == data);
        let s3, ev3 = x509::cms_verify_detached(sd, data);
        check(label, ev3 == x509::ERR_MALFORMED);
    }
    if e != x509::OK { print("  ", label, ": ", x509::error_text(e)); }
    let t, okt = x509::cms_signing_time(sd);
    let noattr = find(label, "noattr") >= 0;
    check(label, okt != noattr && (noattr || t > 1700000000));
}

fn enveloped_vector(label: const u8[:], whos: const u8[:], der: const u8[:], data: const u8[:]) {
    for who in ["alice", "bob", "carol", "dave"] {
        let cd, kd = key_of(who);
        let c, e = x509::parse(cd);
        let k, ok = x509::parse_private_key(kd);
        let pt, ct, ed = x509::cms_decrypt(der, k, c);
        if has_name(whos, who) {
            check(label, ed == x509::OK && pt == data && ct == "1.2.840.113549.1.7.1");
            if ed != x509::OK { print("  ", label, " ", who, ": ", x509::cms_error_text(ed)); }
        } else {
            check(label, ed == x509::ERR_CMS_NOT_RECIPIENT);
        }
    }
    check(label, x509::cms_content_type(der) == (if find(label, "gcm") >= 0 { x509::OID_CMS_AUTH_ENVELOPED_DATA }
                                                 else { x509::OID_CMS_ENVELOPED_DATA }));
}

// Signs with a key each way it can, verifies, refuses changes.
fn sign_round_trip(who: const u8[:]) {
    let cd, kd = key_of(who);
    let c, e = x509::parse(cd);
    let k, ok = x509::parse_private_key(kd);
    let data = "Content-Type: text/plain\r\n\r\nsigned here\r\n";
    var algs: i64[>..] = [];
    var hs:   i64[>..] = [];
    if k.kind == x509::KEY_RSA { algs.push(x509::SIG_RSA_PKCS1); hs.push(256); algs.push(x509::SIG_RSA_PSS); hs.push(384); }
    else if k.kind == x509::KEY_ED25519 { algs.push(x509::SIG_ED25519); hs.push(0); }
    else { algs.push(x509::SIG_ECDSA); hs.push(256); algs.push(x509::SIG_ECDSA); hs.push(512); }
    for i in algs.len {
        for detached in [true, false] {
            let o = x509::CmsSignOptions { detached: detached, signing_time: 1893456000, capabilities: true,
                                           by_key_id: i == 1 || k.kind == x509::KEY_ED25519 };
            let der, oks = x509::cms_sign_with(x509::OID_CMS_DATA, data, k, c, "", algs[i], hs[i], o);
            check(who, oks);
            let sd, ep = x509::cms_parse_signed(der);
            check(who, ep == x509::OK && sd.has_content != detached);
            let s0, ev0 = x509::cms_verify_detached(sd, data);
            let s1, ev1 = x509::cms_verify(sd);
            let ev = if detached { ev0 } else { ev1 };
            check(who, ev == x509::OK && (if detached { s0.der == cd } else { s1.der == cd }));
            if ev != x509::OK { print("  ", who, " ", algs[i], ": ", x509::error_text(ev)); }
            let t, okt = x509::cms_signing_time(sd);
            check(who, okt && t == 1893456000);
            // The version: 1 by issuer and serial, 3 by key identifier.
            let d = sd.der[..];
            let top, okp = asn1::parse(d);
            let ci, okc = asn1::children(d, top);
            let inner, oki = asn1::explicit(d, ci[1]);
            let f, okf = asn1::children(d, inner);
            let v, okv = asn1::read_i64(d, f[0]);
            check(who, v == (if o.by_key_id { 3 } else { 1 }));
            // A byte of the signature changed: refused.
            var bad: u8[>..] = [];
            bad.append(der);
            bad[bad.len - 3] ^= 0x10;
            let sd2, ep2 = x509::cms_parse_signed(bad);
            let s2, ev2a = x509::cms_verify_detached(sd2, data);
            let s3, ev2b = x509::cms_verify(sd2);
            let ev2 = if detached { ev2a } else { ev2b };
            check(who, ep2 != x509::OK || ev2 == x509::ERR_BAD_SIGNATURE);
        }
    }
    // Detached over other content: refused.
    let o = x509::CmsSignOptions { detached: true, .. };
    let der, oks = x509::cms_sign_with(x509::OID_CMS_DATA, data, k, c, "", algs[0], hs[0], o);
    let sd, ep = x509::cms_parse_signed(der);
    let s, ev = x509::cms_verify_detached(sd, "Content-Type: text/plain\r\n\r\nsigned there\r\n");
    check(who, ev == x509::ERR_BAD_SIGNATURE);
}

fn recipients(names: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for n in split(names, ',') {
        let cd, kd = key_of(n);
        out.append(cd);
    }
    return out;
}

// Encrypts every way, decrypts for each recipient, refuses the rest.
fn encrypt_round_trip() {
    let data = content();
    let ciphers = [x509::CMS_AES128_CBC, x509::CMS_AES256_CBC, x509::CMS_AES128_GCM, x509::CMS_AES256_GCM];
    var n = 0;
    for cipher in ciphers {
        n++;
        // Each cipher once with every key type; key identifiers and PKCS #1 v1.5 on alternate ones.
        let o = x509::CmsEncryptOptions { cipher: cipher, rsa_pkcs1: n == 2, by_key_id: n % 2 == 1 };
        let der, e = x509::cms_encrypt(x509::OID_CMS_DATA, data, recipients("alice,bob,carol"), o);
        check("encrypt", e == x509::OK);
        let gcm = cipher == x509::CMS_AES128_GCM || cipher == x509::CMS_AES256_GCM;
        check("encrypt", x509::cms_content_type(der) == (if gcm { x509::OID_CMS_AUTH_ENVELOPED_DATA } else { x509::OID_CMS_ENVELOPED_DATA }));
        for who in ["alice", "bob", "carol"] {
            // RSA once per cipher is enough; it is the slow one.
            if who == "alice" && n > 2 { continue; }
            let cd, kd = key_of(who);
            let c, ec = x509::parse(cd);
            let k, ok = x509::parse_private_key(kd);
            let pt, ct, ed = x509::cms_decrypt(der, k, c);
            check("decrypt", ed == x509::OK && pt == data);
            if ed != x509::OK { print("  ", who, " cipher ", cipher, ": ", x509::cms_error_text(ed)); }
        }
        // Dave is not a recipient (and his key cannot be one).
        let dd, dk = key_of("dave");
        let dc, edc = x509::parse(dd);
        let dkey, okd = x509::parse_private_key(dk);
        let p0, c0, e0 = x509::cms_decrypt(der, dkey, dc);
        check("not a recipient", e0 == x509::ERR_CMS_NOT_RECIPIENT);
        // Bob's certificate with Carol's key: does not decrypt.
        let bd, bk = key_of("bob");
        let cd2, ck = key_of("carol");
        let bc, ebc = x509::parse(bd);
        let ckey, okc = x509::parse_private_key(ck);
        let p1, c1, e1 = x509::cms_decrypt(der, ckey, bc);
        check("wrong key", e1 == x509::ERR_CMS_DECRYPT);
        // A byte of the ciphertext changed (the last block, or GCM's tag).
        var bad: u8[>..] = [];
        bad.append(der);
        bad[bad.len - (if gcm { 3 } else { 20 })] ^= 1;
        let bkey, okb = x509::parse_private_key(bk);
        let p2, c2, e2 = x509::cms_decrypt(bad, bkey, bc);
        check("changed ciphertext", e2 == x509::ERR_CMS_DECRYPT);
    }
    // Alice's encrypted key changed: OAEP refuses it, PKCS #1 v1.5 gives a
    // random key and the content fails to decrypt.
    for pkcs1 in [false, true] {
        let o = x509::CmsEncryptOptions { cipher: x509::CMS_AES128_CBC, rsa_pkcs1: pkcs1, .. };
        let der, e = x509::cms_encrypt(x509::OID_CMS_DATA, data, recipients("alice"), o);
        let ad, ak = key_of("alice");
        let ac, eac = x509::parse(ad);
        let akey, oka = x509::parse_private_key(ak);
        var bad: u8[>..] = [];
        bad.append(der);
        // The encrypted key is the OCTET STRING of 256 bytes, 04 82 01 00.
        let at = find(bad, "\x04\x82\x01\x00");
        check("encrypted key found", at > 0);
        bad[at + 40] ^= 1;
        let p, ct, ed = x509::cms_decrypt(bad, akey, ac);
        check(if pkcs1 { "pkcs1 changed key" } else { "oaep changed key" }, ed == x509::ERR_CMS_DECRYPT);
    }
    // Recipients that cannot be: an Ed25519 key, and none.
    let o = x509::CmsEncryptOptions { .. };
    let d1, e1 = x509::cms_encrypt(x509::OID_CMS_DATA, data, recipients("dave"), o);
    check("ed25519 recipient", e1 == x509::ERR_UNSUPPORTED_ALGORITHM);
    let d2, e2 = x509::cms_encrypt(x509::OID_CMS_DATA, data, "", o);
    check("no recipient", e2 == x509::ERR_MALFORMED);
}

// BER: indefinite lengths, a constructed OCTET STRING, long-form lengths.
fn ber() {
    // SEQUENCE (indefinite) { OID 1.2.3, [0] (indefinite) { OCTET STRING (constructed) { "ab", "cd" } } }
    let b = unhex("308006022a03a08024800402616204026364000000000000");
    let d, ok = x509::cms_der(b);
    check("ber", ok && d == unhex("300c06022a03a006040461626364"));
    // Long-form lengths made short; DER as it was.
    let l, okl = x509::cms_der(unhex("3081030201ff"));
    check("ber long", okl && l == unhex("30030201ff"));
    let s, oks = x509::cms_der(unhex("30030201ff"));
    check("der", oks && s == unhex("30030201ff"));
    // Truncated, unterminated, trailing bytes: refused.
    for bad in ["3080020101", "30800201010000ff", "3005020101", "2480040161"] {
        let x, okx = x509::cms_der(unhex(bad));
        check("ber bad", !okx);
    }
}

fn main() {
    let data = content();
    var nsigned = 0;
    var nenv = 0;
    for line in split(VECTORS, '\n') {
        let w = words(line);
        if w.len == 5 && w[0] == "signed" {
            signed_vector(w[1], w[2], w[3] == "1", unhex(w[4]), data);
            nsigned++;
        } else if w.len == 4 && w[0] == "enveloped" {
            enveloped_vector(w[1], w[2], unhex(w[3]), data);
            nenv++;
        }
    }
    check("vectors read", nsigned == 9 && nenv == 12);
    for who in ["alice", "bob", "carol", "dave"] { sign_round_trip(who); }
    encrypt_round_trip();
    ber();
    print("cms smime: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
