// signer: a key pair on the token used by the rest of gslib, its private
// key never leaving the token. Its public key stands for it
// (p11::x509_key), and p11::sign_data is the signer given to the calls
// that sign: a self-signed certificate (x509::create_certificate), a CSR
// for a CA to sign, and a JWT (jwt::sign). The certificate's and the CSR's
// signatures are checked, and the JWT verified with the public key, as a
// peer holding only the public key would.
//
//   goose examples/pkcs11/signer.goose -- [MODULE [PIN]]
//
// MODULE and PIN default to $P11_MODULE and $P11_PIN; the token is the
// one labelled $P11_LABEL, else the first initialized one. The key pair is
// made as session objects: it goes when the session closes. The same
// signer serves TLS (tls::server_feed), SSH (ssh::server_feed) and HTTP
// (http::get) as a block: { k, alg, h, data => p11::sign_data(key, alg, h, data) }.

import std;
import os;
import gslib from "../..";
import gslib.pkcs11;
import gslib.pkcs11.p11;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jwt;
import gslib.jwx.pem;

fn arg_or_env(i: i64, name: const u8[:]) -> u8[>..] {
    var v: u8[>..] = [];
    let a = args();
    if a.len > i { v.append(a[i]); } else { env(name, v); }
    return v;
}

fn die(what: const u8[:]) { print("signer: ", what); exit(1); }

fn token_slot(c: pkcs11::Ctx) -> u64 {
    var want: u8[>..] = [];
    env("P11_LABEL", want);
    let slots, rv = pkcs11::get_slot_list(c, true);
    for s in slots {
        let t, rt = pkcs11::get_token_info(c, s);
        if rt != pkcs11::CKR_OK || t.flags & pkcs11::CKF_TOKEN_INITIALIZED == 0 { continue; }
        if want.len == 0 || t.label[..] == want[..] { return s; }
    }
    die("no initialized token");
    return 0;
}

fn main() {
    let path = arg_or_env(1, "P11_MODULE");
    let pin = arg_or_env(2, "P11_PIN");
    guard path.len > 0 && pin.len > 0 else { print("usage: signer MODULE PIN (or set P11_MODULE, P11_PIN)"); exit(2); }
    var err: u8[>..] = [];
    var c, ok = pkcs11::new(path, err);
    guard ok else { die(err); }
    if pkcs11::initialize(c) != pkcs11::CKR_OK { die("C_Initialize"); }
    let sh, rs = pkcs11::open_session(c, token_slot(c), pkcs11::CKF_SERIAL_SESSION | pkcs11::CKF_RW_SESSION);
    if rs != pkcs11::CKR_OK || pkcs11::login(c, sh, pkcs11::CKU_USER, pin) != pkcs11::CKR_OK { die("cannot log in"); }

    // A P-256 key pair on the token; the private key sensitive (never
    // readable).
    var pubt: u8[>..] = [];
    pkcs11::attr(pubt, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(pubt, pkcs11::CKA_VERIFY, true);
    pkcs11::attr(pubt, pkcs11::CKA_EC_PARAMS, pkcs11::EC_PARAMS_P256[..]);
    var privt: u8[>..] = [];
    pkcs11::attr(privt, pkcs11::CKA_TOKEN, false);
    pkcs11::attr(privt, pkcs11::CKA_SIGN, true);
    pkcs11::attr(privt, pkcs11::CKA_SENSITIVE, true);
    pkcs11::attr(privt, pkcs11::CKA_PRIVATE, true);
    let pubh, privh, rg = pkcs11::generate_key_pair(c, sh, pkcs11::mechanism(pkcs11::CKM_EC_KEY_PAIR_GEN), pubt, privt);
    if rg != pkcs11::CKR_OK { die(str("C_GenerateKeyPair: ", pkcs11::error_text(rg))); }
    let key = p11::PrivateKey { object: p11::Object { ctx: c, session: sh, handle: privh } };
    let pub, okx = p11::x509_key(p11::PublicKey { object: p11::Object { ctx: c, session: sh, handle: pubh } });
    if !okx { die("cannot read the public key"); }

    // A self-signed certificate, signed on the token.
    let now = time_ns() / 1000000000;
    var t, okt = x509::template("CN=token.example.com", now - 60, now + 86400);
    t.is_ca = true;
    t.key_usage = x509::KU_DIGITAL_SIGNATURE | x509::KU_KEY_CERT_SIGN;
    let cert, ec = x509::create_certificate(t, x509::marshal_public_key(pub), "", pub) { k, alg, h, data => p11::sign_data(key, alg, h, data) };
    let cc, ep = x509::parse(cert);
    guard okt && ec == x509::OK && ep == x509::OK && x509::check_signature(cc, cc) == x509::OK else { die("certificate"); }
    print("certificate: ", cert.len, " bytes, signed on the token, signature checked");

    // A CSR for a CA to sign.
    let subj, oks = x509::name_der("CN=device.example.com");
    let csr, ecsr = x509::create_csr(subj, "", pub) { k, alg, h, data => p11::sign_data(key, alg, h, data) };
    let cr, ecr = x509::parse_csr(csr);
    guard oks && ecsr == x509::OK && ecr == x509::OK && x509::check_csr(cr) == x509::OK else { die("CSR"); }
    print("CSR: ", csr.len, " bytes, signed on the token, signature checked");

    // A JWT, verified with the public key alone.
    let jpub, ej = jwk::from_spki(x509::marshal_public_key(pub));
    var claims = jwt::new_claims();
    claims.sub.append("device-42");
    claims.has |= jwt::CLAIM_SUB;
    let token, et = jwt::sign(claims, jwa::ES256, jpub) { k, alg, h, data => p11::sign_data(key, alg, h, data) };
    var got = jwt::new_claims();
    let v = jwt::Validator { validate: false };
    guard ej == jwx::OK && et == jwx::OK && jwt::parse(token, jwa::ES256, jpub, got, v) == jwx::OK else { die("JWT"); }
    print("JWT for ", got.sub, ": signed on the token, verified");
    pkcs11::logout(c, sh);
    pkcs11::close_session(c, sh);
    pkcs11::finalize(c);
}
