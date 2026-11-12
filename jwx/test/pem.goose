// jwx.pem against OpenSSL's keys (test/vectors/pem, scripts/gen_pem.sh):
// each key type's private key, public key and self-signed certificate
// give the same JWK (by RFC 7638 thumbprint), the certificate's x5t and
// x5t#S256 are OpenSSL's fingerprints, PKCS #1 and SEC 1 read as PKCS #8
// does, a private key signs what its PEM public key verifies, and every
// key written to PEM reads back the same.
import std;
import os;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.pem;
import tv;

fn load(name: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(str("vectors/pem/", name), text) { abort(str("cannot read ", name)); }
    return text;
}

fn key(name: const u8[:]) -> jwk::Key {
    let k, e = jwk::from_pem(load(name));
    tv::check_int(str(name, " read"), e, jwx::OK);
    return k;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let digits = "0123456789abcdef";
    for c in b { out.push(digits[c >> 4]); out.push(digits[c & 15]); }
    return out;
}

fn main() {
    let names = ["rsa", "p256", "p384", "p521", "ed25519"];
    let algs = [jwa::RS256, jwa::ES256, jwa::ES384, jwa::ES512, jwa::EDDSA];
    for i in names.len {
        let n = names[i];
        let priv = key(str(n, ".key"));
        let pub = key(str(n, ".pub"));
        let cert = key(str(n, ".crt"));
        tv::check(str(n, " private"), priv.private && !pub.private && !cert.private);
        let tp = jwk::thumbprint(priv);
        tv::check(str(n, " public key is the private key's"), jwk::thumbprint(pub) == tp);
        tv::check(str(n, " certificate key is the private key's"), jwk::thumbprint(cert) == tp);
        tv::check_eq(str(n, " x5t"), hex(cert.x5t), trim(load(str(n, ".sha1"))));
        tv::check_eq(str(n, " x5t#S256"), hex(cert.x5t256), trim(load(str(n, ".sha256"))));
        tv::check_int(str(n, " valid"), jwk::validate(priv), jwx::OK);

        let token, e = jws::sign("pem", algs[i], priv);
        let got, ev = jws::verify(token, algs[i], cert);
        tv::check(str(n, " signs for its certificate"), e == jwx::OK && ev == jwx::OK && got == "pem");

        // Written to PEM and read back.
        let p1, e1 = jwk::to_pem(priv);
        let back, eb = jwk::from_pem(p1);
        tv::check(str(n, " private PEM round trip"), e1 == jwx::OK && eb == jwx::OK
                  && jwk::marshal(back) == jwk::marshal(priv));
        let p2, e2 = jwk::to_pem(pub);
        let back2, eb2 = jwk::from_pem(p2);
        tv::check(str(n, " public PEM round trip"), e2 == jwx::OK && eb2 == jwx::OK
                  && jwk::marshal(back2) == jwk::marshal(pub));
        tv::check_eq(str(n, " public PEM is OpenSSL's"), p2, load(str(n, ".pub")));
    }
    let rsa1 = key("rsa-pkcs1.key");
    let rsa8 = key("rsa.key");
    tv::check_eq("PKCS #1 reads as PKCS #8", jwk::marshal(rsa1), jwk::marshal(rsa8));
    let ec1 = key("p256-sec1.key");
    let ec8 = key("p256.key");
    tv::check_eq("SEC 1 reads as PKCS #8", jwk::marshal(ec1), jwk::marshal(ec8));
    let oct = jwk::from_oct("secret");
    let none, en = jwk::to_pem(oct);
    tv::check_int("oct has no PEM", en, jwx::ERR_KEY);
    let junk, ej = jwk::from_pem("-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n");
    tv::check_int("unknown PEM refused", ej, jwx::ERR_MALFORMED);
    tv::done("pem");
}
