// Messages made by gslib's jwx for Go's lestrrat-go/jwx to verify and
// decrypt (scripts/differential: go run . check): every signature
// algorithm (ML-DSA-44, -65 and -87 too), compact and JSON, and every key
// management algorithm with every content algorithm, some compressed,
// some as JSON. One per line,
// tab-separated: kind, algorithm, content encryption ("-"), zip (0 or 1),
// the private JWK, the payload, the message.
//
//   goose tools/tokens.goose -- [rounds]
import std;
import os;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwe;

fn emit(kind: const u8[:], alg: i64, enc: i64, zip: bool, key: const jwk::Key&, payload: const u8[:], msg: const u8[:]) {
    print(kind, "\t", jwa::name(alg), "\t", if enc == jwa::UNKNOWN { "-" } else { jwa::name(enc) }, "\t",
          if zip { "1" } else { "0" }, "\t", jwk::marshal(key), "\t", payload, "\t", msg);
}

fn main() {
    var rounds = 1;
    var i = 0;
    for a in args() {
        let n, ok = parse_int(a);
        if ok && i > 0 { rounds = n; }     // args()[0] is the program
        i++;
    }
    let rsa = jwk::generate_rsa(2048);
    let sigs = [jwa::HS256, jwa::HS384, jwa::HS512, jwa::RS256, jwa::RS384, jwa::RS512, jwa::PS256, jwa::PS384,
                jwa::PS512, jwa::ES256, jwa::ES384, jwa::ES512, jwa::EDDSA, jwa::ML_DSA_44, jwa::ML_DSA_65,
                jwa::ML_DSA_87];
    let algs = [jwa::RSA1_5, jwa::RSA_OAEP, jwa::RSA_OAEP_256, jwa::RSA_OAEP_384, jwa::RSA_OAEP_512,
                jwa::A128KW, jwa::A192KW, jwa::A256KW, jwa::DIRECT, jwa::ECDH_ES, jwa::ECDH_ES_A128KW,
                jwa::ECDH_ES_A192KW, jwa::ECDH_ES_A256KW, jwa::A128GCMKW, jwa::A192GCMKW, jwa::A256GCMKW,
                jwa::PBES2_HS256_A128KW, jwa::PBES2_HS384_A192KW, jwa::PBES2_HS512_A256KW];
    let encs = [jwa::A128CBC_HS256, jwa::A192CBC_HS384, jwa::A256CBC_HS512, jwa::A128GCM, jwa::A192GCM, jwa::A256GCM];
    let curves = [jwa::CRV_P256, jwa::CRV_P384, jwa::CRV_P521, jwa::CRV_X25519];
    for r in rounds {
        var i = 0;
        for alg in sigs {
            let key = if jwa::is_hmac(alg) { jwk::generate_oct(64) }
                      else if jwa::kty_of(alg) == jwa::KTY_RSA { rsa }
                      else if jwa::is_eddsa(alg) { jwk::generate_okp(jwa::CRV_ED25519) }
                      else if jwa::is_mldsa(alg) { jwk::generate_akp(alg) }
                      else { jwk::generate_ec(jwa::curve_of(alg)) };
            let payload = str("{\"iss\":\"goose\",\"n\":", r * 100 + i, "}");
            let t, e = jws::sign(payload, alg, key);
            assert(e == jwx::OK);
            emit("jws", alg, jwa::UNKNOWN, false, key, payload, t);
            var signers: jws::Signer[>..] = [];
            signers.push(jws::Signer { key: key, .. });
            signers[0].header.alg = alg;
            let j, ej = jws::sign_json(payload, signers, i % 2 == 0);
            assert(ej == jwx::OK);
            emit("jws-json", alg, jwa::UNKNOWN, false, key, payload, j);
            i++;
        }
        var n = 0;
        for alg in algs {
            for enc in encs {
                n++;
                let crv = curves[(n + r) % 4];
                let key = if jwa::is_rsa_kw(alg) { rsa }
                          else if alg == jwa::DIRECT { jwk::generate_oct(jwa::cek_len(enc)) }
                          else if jwa::is_ecdh(alg) {
                              if crv == jwa::CRV_X25519 { jwk::generate_okp(crv) } else { jwk::generate_ec(crv) }
                          }
                          else if jwa::is_pbes2(alg) { jwk::from_oct(str("password ", n)) }
                          else { jwk::generate_oct(jwa::kek_len(alg)) };
                let pub = jwk::public_key(key);
                let zip = (n + r) % 3 == 0;
                let payload = str("{\"iss\":\"goose\",\"n\":", r * 1000 + n, "}");
                let t, e = jwe::encrypt(payload, alg, enc, pub, zip);
                assert(e == jwx::OK);
                emit("jwe", alg, enc, zip, key, payload, t);
                if n % 4 == 0 {
                    var h = jwe::Header { .. };
                    h.enc = enc;
                    h.zip = zip;
                    var rs: jwe::Recipient[>..] = [];
                    rs.push(jwe::Recipient { alg: alg, key: pub, .. });
                    let j, ej = jwe::encrypt_json(payload, h, rs, "", n % 8 == 0);
                    assert(ej == jwx::OK);
                    emit("jwe-json", alg, enc, zip, key, payload, j);
                }
            }
        }
    }
}
