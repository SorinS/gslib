// Fuzz target: x509_pkcs12. A PKCS #12 file decoded with the password ""
// (data[0] even) or "goose" (odd: the password of the test vectors), then
// the private key it yields parsed and the certificates each parsed.
// Iteration counts come from the input (up to the library's 10,000,000),
// so a slow input here is a slow file, not a hang.

import std;
import gslib from "../..";
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.pkcs12;
import gslib.encoding.asn1;

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let password: const u8[:] = if data[0] % 2 == 0 { "" } else { "goose" };
    let key, certs, e = x509::pkcs12_decode(data[1..], password);
    if key.len > 0 {
        let _ = x509::parse_private_key(key);
    }
    var off = 0;
    var n = 0;
    while off < certs.len && n < 16 {
        let t, ok = asn1::read(certs, off, certs.len);
        if !ok { break; }
        let _ = x509::parse(certs[t.start..t.end]);
        off = t.end;
        n++;
    }
    return 0;
}

fn main() {}
