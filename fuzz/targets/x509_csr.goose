// Fuzz target: x509_csr. A PKCS #10 request parsed, then its subject as
// text, its attributes (extensionRequest, challengePassword,
// unstructuredName, a made-up one) by csr_attribute, the SAN's DNS names,
// and the signature by the key it carries (check_csr).

import std;
import gslib from "../..";
import gslib.crypto.x509;
import gslib.crypto.x509.create;
import gslib.encoding.asn1;

export fn fuzz_one(data: const u8[:]) -> i32 {
    let r, e = x509::parse_csr(data);
    if e != x509::OK { return 0; }
    let d = r.der[..];
    let _ = x509::name_text(d, r.subject);
    let _ = x509::name_values(d, r.subject, "2.5.4.3");
    for oid in ["1.2.840.113549.1.9.14", "1.2.840.113549.1.9.7", "1.2.840.113549.1.9.2", "1.2.3.4"] {
        let t, n = x509::csr_attribute(r, oid);
        if n == 1 {
            let _ = asn1::read_string(d, t);
            let _ = asn1::children(d, t);
        }
    }
    let _ = x509::csr_dns_names(r);
    let _ = x509::check_csr(r);
    return 0;
}

fn main() {}
