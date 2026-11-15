// jwx.pem against OpenSSL's keys (test/vectors/pem, scripts/gen_pem.sh):
// each key type's private key, public key and self-signed certificate
// give the same JWK (by RFC 7638 thumbprint), the certificate's x5t and
// x5t#S256 are OpenSSL's fingerprints, PKCS #1 and SEC 1 read as PKCS #8
// does, a private key signs what its PEM public key verifies, and every
// key written to PEM reads back the same. ML-DSA keys (RFC 9881) become
// AKP JWKs (RFC 9964), from OpenSSL's seed-and-expanded PKCS #8 and its
// seed-only one, which is also what this package writes. Ed448 and X448
// keys (RFC 8410) become OKP JWKs (RFC 8037), X448's without a
// certificate; brainpool keys, which JOSE has no curve for, are refused.
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
    let names = ["rsa", "p256", "p384", "p521", "ed25519", "mldsa44", "mldsa65", "mldsa87", "ed448"];
    let algs = [jwa::RS256, jwa::ES256, jwa::ES384, jwa::ES512, jwa::EDDSA, jwa::ML_DSA_44, jwa::ML_DSA_65,
                jwa::ML_DSA_87, jwa::EDDSA];
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
    let ed = key("ed448.key");
    tv::check("Ed448 key is OKP Ed448", ed.kty == jwa::KTY_OKP && ed.crv == jwa::CRV_ED448 && ed.d.len == 57 &&
              ed.x.len == 57);
    let ed_pem, eep = jwk::to_pem(ed);
    tv::check_eq("Ed448 private PEM is OpenSSL's", ed_pem, load("ed448.key"));
    // X448: no certificate; the private and public keys agree, and both go
    // back to PEM as OpenSSL wrote them.
    let xp = key("x448.key");
    let xq = key("x448.pub");
    tv::check("X448 key is OKP X448", xp.kty == jwa::KTY_OKP && xp.crv == jwa::CRV_X448 && xp.private && xp.d.len == 56 &&
              !xq.private && xq.x.len == 56);
    tv::check("X448 public key is the private key's", jwk::thumbprint(xq) == jwk::thumbprint(xp));
    tv::check_int("X448 valid", jwk::validate(xp), jwx::OK);
    let xp_pem, exp = jwk::to_pem(xp);
    tv::check_eq("X448 private PEM is OpenSSL's", xp_pem, load("x448.key"));
    let xq_pem, exq = jwk::to_pem(xp, true);
    tv::check_eq("X448 public PEM is OpenSSL's", xq_pem, load("x448.pub"));
    let xb, exb = jwk::from_pem(xp_pem);
    tv::check("X448 private PEM round trip", exp == jwx::OK && exb == jwx::OK && jwk::marshal(xb) == jwk::marshal(xp));
    // A generated pair, both curves, through PEM.
    let g448 = jwk::generate_okp(jwa::CRV_ED448);
    let gp, egp = jwk::to_pem(g448);
    let gb, egb = jwk::from_pem(gp);
    tv::check("generated Ed448 through PEM", egp == jwx::OK && egb == jwx::OK && jwk::marshal(gb) == jwk::marshal(g448));
    let gx = jwk::generate_okp(jwa::CRV_X448);
    let gxp, egx = jwk::to_pem(gx, true);
    let gxb, egxb = jwk::from_pem(gxp);
    tv::check("generated X448 public through PEM", egx == jwx::OK && egxb == jwx::OK && !gxb.private &&
              gxb.x == gx.x && gxb.crv == jwa::CRV_X448);
    // brainpoolP256r1: no JOSE curve, so none of its forms reads.
    for f in ["bp256.key", "bp256.pub", "bp256.crt"] {
        let kb, eb = jwk::from_pem(load(f));
        tv::check_int(str(f, " refused"), eb, jwx::ERR_UNSUPPORTED);
    }
    let rsa1 = key("rsa-pkcs1.key");
    let rsa8 = key("rsa.key");
    tv::check_eq("PKCS #1 reads as PKCS #8", jwk::marshal(rsa1), jwk::marshal(rsa8));
    let ec1 = key("p256-sec1.key");
    let ec8 = key("p256.key");
    tv::check_eq("SEC 1 reads as PKCS #8", jwk::marshal(ec1), jwk::marshal(ec8));
    let ml_both = key("mldsa65.key");
    let ml_seed = key("mldsa65-seed.key");
    tv::check("ML-DSA key is AKP with its alg", ml_both.kty == jwa::KTY_AKP && ml_both.alg == jwa::ML_DSA_65);
    tv::check_eq("ML-DSA seed-only reads as seed and expanded", jwk::marshal(ml_seed), jwk::marshal(ml_both));
    let ml_pem, eml = jwk::to_pem(ml_both);
    tv::check_int("ML-DSA private PEM", eml, jwx::OK);
    tv::check_eq("ML-DSA private PEM is OpenSSL's seed-only", ml_pem, load("mldsa65-seed.key"));
    let oct = jwk::from_oct("secret");
    let none, en = jwk::to_pem(oct);
    tv::check_int("oct has no PEM", en, jwx::ERR_KEY);
    let junk, ej = jwk::from_pem("-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n");
    tv::check_int("unknown PEM refused", ej, jwx::ERR_MALFORMED);
    tv::done("pem");
}
