// challenges: what an ACME client makes before it talks to a server, and
// what it publishes for each challenge. An account key (P-256), the
// request that registers it (a flattened JWS carrying the key, a nonce and
// the URL, as RFC 8555 §6.2 has it), verified here as a server would; the
// http-01 response and the dns-01 TXT record for a token; and the CSR
// that finalizes an order, for a name and its wildcard. No network.
//
//   goose examples/acme/challenges.goose

import std;
import gslib from "../..";
import gslib.acme;
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

fn main() {
    var a = acme::Client { .. };
    let key = jwk::generate_ec(jwa::CRV_P256);
    assert(acme::set_key(a, key) == acme::OK);
    print("account key thumbprint: ", jwk::thumbprint_b64(key));

    // The newAccount request, with the nonce a server would have handed out.
    a.nonce.append("oFvnlFP1wIhRlYS2jTaXbA");
    let body, err = acme::sign_request(a, "https://acme.example.org/new-account",
                                       "{\"termsOfServiceAgreed\":true}", true);
    assert(err == acme::OK);
    var m = jws::Message { .. };
    assert(jws::parse(m, body) == jwx::OK);
    // A server checks the signature by the key in the header.
    assert(jws::verify_signature(m, 0, jwa::ES256, m.sigs[0].header.jwk) == jwx::OK);
    let url, has_url = jws::header_string(m, 0, "url");
    assert(has_url && url == "https://acme.example.org/new-account");
    print("newAccount request: ", body.len, " bytes, signed by the key it carries");

    // A challenge's token, as an authorization would give it.
    let token = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    print("http-01: serve at ", acme::http01_path(token));
    print("         the text ", acme::key_authorization(a, token));
    print("dns-01:  TXT at ", acme::dns01_name("*.example.org"));
    print("         the value ", acme::dns01_value(a, token));
    assert(acme::dns01_value(a, token).len == 43);

    // The CSR: a key of its own (never the account's), the names in the SAN.
    let ck = x509::generate_key(x509::KEY_EC_P256);
    var san: u8[..4096] = [];
    x509::add_dns(san, "example.org");
    x509::add_dns(san, "*.example.org");
    let subject, ok = x509::name_der("CN=example.org");
    assert(ok);
    let csr, cerr = x509::create_csr(subject, san, ck);
    assert(cerr == x509::OK);
    let r, perr = x509::parse_csr(csr);
    assert(perr == x509::OK && x509::check_csr(r) == x509::OK);
    let names = x509::csr_dns_names(r);
    var n = 0;
    for name in names { n++; }
    assert(n == 2);
    print("CSR for example.org and *.example.org: ", csr.len, " bytes");
}
