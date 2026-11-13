// encrypt_decrypt: JSON Web Encryption. Encrypts a message in the compact
// form to an RSA key (RSA-OAEP-256), to EC and X25519 keys (ECDH-ES and
// ECDH-ES+A256KW), under a shared key-wrapping key (A256KW) and a shared
// content key (dir), and with a password (PBES2); compresses one (zip:
// DEF); then encrypts once as JSON for three recipients, each of whom opens
// it with their own key, with additional authenticated data.
//
//   goose examples/jwx/encrypt_decrypt.goose
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jwe;

fn fail(what: const u8[:], e: i64) {
    if e == jwx::OK { print("encrypt_decrypt: ", what); } else { print("encrypt_decrypt: ", what, ": ", jwx::error_text(e)); }
    exit(1);
}

fn main() {
    var plaintext: u8[>..] = [];
    for i in 20 { plaintext.append("The true sign of intelligence is not knowledge but imagination. "); }

    // Compact: the sender has the recipient's public key (or shares a
    // secret with them); the recipient decrypts with the private key and
    // the algorithm they expect.
    let algs = [jwa::RSA_OAEP_256, jwa::ECDH_ES, jwa::ECDH_ES_A256KW, jwa::A256KW, jwa::DIRECT, jwa::PBES2_HS256_A128KW];
    let encs = [jwa::A256GCM, jwa::A128CBC_HS256, jwa::A256GCM, jwa::A256CBC_HS512, jwa::A256GCM, jwa::A128GCM];
    let keys = [jwk::generate_rsa(2048), jwk::generate_ec(jwa::CRV_P256), jwk::generate_okp(jwa::CRV_X25519),
                jwk::generate_oct(32), jwk::generate_oct(32), jwk::from_oct("correct horse battery staple")];
    for i in algs.len {
        let pub = jwk::public_key(keys[i]);     // for a shared key, the key itself
        let zip = i == 0;
        let token, e = jwe::encrypt(plaintext, algs[i], encs[i], pub, zip);
        if e != jwx::OK { fail(str("encrypt ", jwa::name(algs[i])), e); }
        let got, ed = jwe::decrypt(token, algs[i], keys[i]);
        if ed != jwx::OK || got != plaintext { fail(str("decrypt ", jwa::name(algs[i])), ed); }
        print(jwa::name(algs[i]), " + ", jwa::name(encs[i]), if zip { ", zip" } else { "" }, ": ", plaintext.len,
              " bytes in ", token.len, " bytes of JWE (", split(token, '.').len, " parts)");

        // Any other key, or a key for another algorithm, cannot open it.
        let x, ex = jwe::decrypt(token, algs[i], keys[(i + 1) % keys.len]);
        guard ex != jwx::OK && x.len == 0 else { fail("opened with another key", jwx::OK); }
    }

    // A ciphertext with one byte changed is refused, whatever the cause
    // (no padding or tag oracle: every failure is ERR_DECRYPT).
    let t, e = jwe::encrypt("attack at dawn", jwa::A256KW, jwa::A256GCM, keys[3]);
    var bad: u8[>..] = [];
    bad.append(t);
    let at = bad.len - 30;
    bad[at] = if bad[at] == 'A' { 'B' } else { 'A' };
    let y, ey = jwe::decrypt(bad, jwa::A256KW, keys[3]);
    guard ey == jwx::ERR_DECRYPT else { fail("a changed ciphertext was not refused", ey); }
    print("changed ciphertext: ", jwx::error_text(ey));

    // JSON: one ciphertext, the content key wrapped once per recipient,
    // each with its own algorithm and kid. AAD is authenticated, not
    // encrypted.
    var people: jwk::Key[>..] = [];
    people.push(keys[0]);
    people.push(jwk::generate_ec(jwa::CRV_P384));
    people.push(jwk::generate_oct(32));
    let kids = ["alice", "bob", "carol"];
    let kw = [jwa::RSA_OAEP_256, jwa::ECDH_ES_A256KW, jwa::A256GCMKW];
    var rs: jwe::Recipient[>..] = [];
    for i in 3 {
        people[i].kid.append(kids[i]);
        rs.push(jwe::Recipient { alg: kw[i], key: jwk::public_key(people[i]), .. });
        rs[i].header.kid.append(kids[i]);
    }
    var shared = jwe::Header { .. };
    shared.enc = jwa::A256GCM;
    shared.zip = true;
    let json, ej = jwe::encrypt_json(plaintext, shared, rs, "for the board only");
    if ej != jwx::OK { fail("encrypt_json", ej); }
    var m = jwe::Message { .. };
    if jwe::parse(m, json) != jwx::OK || m.recipients.len != 3 { fail("parse", jwx::ERR_MALFORMED); }
    for i in 3 {
        let got, ed = jwe::decrypt(json, kw[i], people[i]);
        if ed != jwx::OK || got != plaintext { fail(str("recipient ", kids[i]), ed); }
    }
    // A recipient with several keys picks theirs by kid.
    let got, es = jwe::decrypt_set(json, people, true);
    if es != jwx::OK || got != plaintext { fail("decrypt_set", es); }
    print("JSON for ", m.recipients.len, " recipients (", m.recipients[0].header.kid, ", ", m.recipients[1].header.kid,
          ", ", m.recipients[2].header.kid, "), ", json.len, " bytes with AAD; each opened it");
}
