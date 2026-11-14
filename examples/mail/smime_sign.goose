// smime_sign: a message signed with S/MIME (mail.smime), as
// multipart/signed, then read back: the signature verified, the signer's
// certificate checked against itself as the root, and its address against
// From. The key and certificate below are a P-256 test pair made for this
// example and nothing else (zoe@example.com). The Date, Message-ID,
// boundary and signing time are fixed and ECDSA's nonces are RFC 6979's,
// so the output is the same each run. No network.
//
//   goose examples/mail/smime_sign.goose

import std;
import gslib from "../..";
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.pool;
import gslib.mail;
import gslib.mail.message;
import gslib.mail.smime;

// Test only: never use this key for anything but this example.
let CERT_PEM = """
    -----BEGIN CERTIFICATE-----
    MIIBxzCCAWygAwIBAgIBBzAKBggqhkjOPQQDAjA0MRUwEwYDVQQKDAxFeGFtcGxl
    IFRlc3QxGzAZBgNVBAMMElpvZSAoZXhhbXBsZSBvbmx5KTAgFw0yNjExMTQwMzIw
    MDZaGA8yMTI2MTAyMTAzMjAwNlowNDEVMBMGA1UECgwMRXhhbXBsZSBUZXN0MRsw
    GQYDVQQDDBJab2UgKGV4YW1wbGUgb25seSkwWTATBgcqhkjOPQIBBggqhkjOPQMB
    BwNCAATzYIPsoPkFRHjNsLMGncmTDKx6UfIYKibmDXpwq82oP+1tXEfNDUgfGhRy
    RgO0cD+rnAHrSvfVUwK6P0eKZMM+o20wazAJBgNVHRMEAjAAMA4GA1UdDwEB/wQE
    AwIDiDATBgNVHSUEDDAKBggrBgEFBQcDBDAaBgNVHREEEzARgQ96b2VAZXhhbXBs
    ZS5jb20wHQYDVR0OBBYEFHmWiKiUSSnJJdOnn/5TBvIyJO4WMAoGCCqGSM49BAMC
    A0kAMEYCIQDMTLybfemyhPJwEpYO0FInrQBcblQkbiM5oj98dBzDggIhAMEzMJwK
    yXvYT1zvoSJGwmfbC1tyhhxHHMN9oZCCF947
    -----END CERTIFICATE-----
    """;

let KEY_PEM = """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrpizwuDAbB+YbxhE
    LHEDMDU6O5+A2h2D7uVVjNN/Y4ehRANCAATzYIPsoPkFRHjNsLMGncmTDKx6UfIY
    KibmDXpwq82oP+1tXEfNDUgfGhRyRgO0cD+rnAHrSvfVUwK6P0eKZMM+
    -----END PRIVATE KEY-----
    """;

fn must(what: const u8[:], rc: i64) {
    if rc != mail::OK {
        print("smime_sign: ", what, ": ", mail::error_text(rc));
        exit(1);
    }
}

fn main() {
    let cert, e = x509::parse_pem(CERT_PEM);
    let key, ok = x509::parse_private_key_pem(KEY_PEM);
    if e != x509::OK || !ok { print("smime_sign: the test key does not parse"); exit(1); }

    var m = mail::Msg { .. };
    must("from", mail::set_from(m, "Zoë <zoe@example.com>"));
    must("to", mail::add_to(m, "bob@example.org"));
    must("subject", mail::set_subject(m, "Signed minutes"));
    mail::set_date(m, 1798761600);                              // 2027-01-01 00:00:00 UTC
    must("id", mail::set_message_id(m, "minutes-2027-01@example.com"));
    must("boundary", mail::set_boundary(m, "example"));
    must("text", mail::set_body(m, mail::TEXT_PLAIN, "The minutes of the meeting are attached.\n"));
    must("attach", mail::attach(m, "minutes.txt", "1. Opening.\n2. Budget: approved.\n3. Close.\n"));

    var o = smime::Options { signing_time: 1798761600, .. };
    o.boundary.append("smime-example");
    var out: u8[>..] = [];
    must("sign", smime::sign(m, key, cert, "", o, out));     // no intermediates: the certificate is its own root
    print(out);

    // Back: verify the signature, then decide whether to trust the signer.
    var r = smime::Opened { .. };
    must("verify", smime::verify(out, r));
    print("signed by: ", x509::subject_text(r.signer));
    var roots = x509::new_pool();
    let added = x509::pool_add_cert(roots, cert);
    must("signer", smime::check_signer(r, roots, 1798761600, smime::from_address(out)));
    print("the signer is ", smime::from_address(out), ", as From says");
}
