// Fuzz target: x509_cms. By the first byte (data[0] % 3):
//   0  SignedData: cms_parse_signed (DER), and cms_der then
//      cms_parse_signed_ber (BER); each parsed one walked: the content,
//      its certificates (each parsed) and CRLs, the signing time, the
//      signed attributes, and the signature checked (cms_verify, SHA-1
//      allowed; detached; with a fixed extra certificate).
//   1  EnvelopedData / AuthEnvelopedData decrypted (cms_decrypt and
//      cms_decrypt_legacy) by bob's P-256 key (ECDH key agreement).
//   2  the same by grace-kem's ML-KEM-512 key (KEMRecipientInfo).
// Keys and certificates from crypto/x509/test/cms_smime. RSA recipients
// are not tried: a bad PKCS #1 v1.5 block decrypts to a random key, which
// would make the target nondeterministic.

import std;
import gslib from "../..";
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.cms;
import gslib.crypto.x509.cms_env;
import gslib.encoding.asn1;

var bob_cert = x509::empty_cert();
var bob_key = x509::empty_key();
var kem_cert = x509::empty_cert();
var kem_key = x509::empty_key();

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((ascii::hex_value(s[i]) * 16 + ascii::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn walk(sd: const x509::SignedData&) {
    let _ = x509::cms_content(sd);
    let _ = x509::cms_signed(sd);
    let certs = x509::cms_certs(sd);
    var off = 0;
    var n = 0;
    while off < certs.len && n < 16 {
        let t, ok = asn1::read(certs, off, certs.len);
        if !ok { break; }
        let _ = x509::parse(certs[t.start..t.end]);
        off = t.end;
        n++;
    }
    let _ = x509::cms_crls(sd);
    let _ = x509::cms_signing_time(sd);
    let _ = x509::cms_signed_attr(sd, x509::OID_CMS_CONTENT_TYPE);
    let _ = x509::cms_signed_attr(sd, x509::OID_CMS_MESSAGE_DIGEST);
    let _ = x509::cms_verify(sd, true);
    let _ = x509::cms_verify_detached(sd, "detached content", true);
    let _ = x509::cms_verify_with_certs(sd, bob_cert.der, false);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let rest = data[1..];
    let mode = data[0] % 3;
    if mode == 0 {
        let sd, e = x509::cms_parse_signed(rest);
        if e == x509::OK { walk(sd); }
        let der, ok = x509::cms_der(rest);
        if ok && der[..] != rest {
            let sd2, e2 = x509::cms_parse_signed_ber(rest);
            if e2 == x509::OK { walk(sd2); }
        }
    } else if mode == 1 {
        let _ = x509::cms_decrypt(rest, bob_key, bob_cert);
        let _ = x509::cms_decrypt_legacy(rest, bob_key, bob_cert);
    } else {
        let _ = x509::cms_decrypt(rest, kem_key, kem_cert);
    }
    return 0;
}

fn main() {
    for path in [0, 1] {
        let text = if path == 0 { embed_file("../../crypto/x509/test/cms_smime/vectors.txt") }
                   else { embed_file("../../crypto/x509/test/cms_smime/pq_vectors.txt") };
        for line in split(text, '\n') {
            let w = split(line, ' ');
            if w.len < 4 || w[0] != "key" { continue; }
            if w[1] != "bob" && w[1] != "grace-kem" { continue; }
            let c, e = x509::parse(unhex(w[2]));
            let k, ok = x509::parse_private_key(unhex(w[3]));
            assert(e == x509::OK && ok);
            if w[1] == "bob" { bob_cert = copy(c); bob_key = copy(k); }
            else { kem_cert = copy(c); kem_key = copy(k); }
        }
    }
    assert(bob_cert.der.len > 0 && kem_cert.der.len > 0);
}
