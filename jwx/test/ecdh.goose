// ECDH-ES against RFC 7518 Appendix C: Alice's ephemeral key and Bob's key
// agree on the appendix's Z both ways, the Concat KDF with apu "Alice" and
// apv "Bob" gives its key, and a message made with them (the appendix's
// header) decrypts with Bob's key. Then apu and apv in a recipient's
// unprotected header, which the AAD does not cover: changing either makes
// the KDF give another key, and the message is refused.
import std;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jwe;
import tv;

let ALICE = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0\",\"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\",\"d\":\"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo\"}";
let BOB = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"}";
let Z: u8[] = [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163,
               218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196];

fn main() {
    let alice, ea = jwk::parse(ALICE);
    let bob, eb = jwk::parse(BOB);
    tv::check("keys", ea == jwx::OK && eb == jwx::OK);
    let alice_pub = jwk::public_key(alice);
    let bob_pub = jwk::public_key(bob);
    let z1, ok1 = jwe::agree(bob_pub, alice);
    let z2, ok2 = jwe::agree(alice_pub, bob);
    tv::check("Z from Alice's side", ok1 && z1[..] == Z[..]);
    tv::check("Z from Bob's side", ok2 && z2[..] == Z[..]);
    let derived = jwe::concat_kdf(Z, "A128GCM", "Alice", "Bob", 16);
    tv::check_eq("Concat KDF", jwx::b64_encode(derived), "VqqN6vgjbSBcIijNcacQGg");

    // The appendix's message: ECDH-ES to Bob with Alice's ephemeral key.
    var h = jwe::Header { .. };
    h.alg = jwa::ECDH_ES;
    h.enc = jwa::A128GCM;
    h.apu.append("Alice");
    h.apv.append("Bob");
    var o = jwe::Options { .. };
    o.epk = alice;
    o.has_epk = true;
    var h2 = h;
    let cek, ek, ek_err = jwe::key_encrypt(h2, jwa::ECDH_ES, jwa::A128GCM, bob_pub, o);
    tv::check("the CEK is the derived key", ek_err == jwx::OK && cek == derived && ek.len == 0);
    let token, e = jwe::encrypt_with_options("Hello, Bob", bob_pub, h, "", o);
    tv::check_int("encrypted", e, jwx::OK);
    var m = jwe::Message { .. };
    tv::check_int("parsed", jwe::parse(m, token), jwx::OK);
    let hd = m.recipients[0].header;
    tv::check("apu and apv sent", hd.apu[..] == "Alice" && hd.apv[..] == "Bob" && hd.has_epk);
    let pt, ed = jwe::decrypt(token, jwa::ECDH_ES, bob);
    tv::check("decrypted by Bob", ed == jwx::OK && pt == "Hello, Bob");

    // apu and apv per recipient, unprotected: two recipients of
    // ECDH-ES+A128KW, the first with apu "Alice".
    var rs: jwe::Recipient[>..] = [];
    rs.push(jwe::Recipient { alg: jwa::ECDH_ES_A128KW, key: bob_pub, .. });
    rs[0].header.apu.append("Alice");
    rs[0].header.apv.append("Bob");
    rs.push(jwe::Recipient { alg: jwa::A128KW, key: jwk::generate_oct(16), .. });
    var shared = jwe::Header { .. };
    shared.enc = jwa::A128GCM;
    let j, ej = jwe::encrypt_json("for two", shared, rs);
    tv::check_int("two recipients", ej, jwx::OK);
    let pj, epj = jwe::decrypt(j, jwa::ECDH_ES_A128KW, bob);
    tv::check("Bob reads it", epj == jwx::OK && pj == "for two");
    // "QWxpY2U" is base64url "Alice"; "Qm9i" is "Bob".
    for change in [["QWxpY2U", "QWxpY2Y"], ["Qm9i", "Qm9j"]] {
        let at = find(j, change[0]);
        tv::check(str(change[0], " sent unprotected"), at > 0);
        var forged: u8[>..] = [];
        forged.append(j[..at]);
        forged.append(change[1]);
        forged.append(j[at + change[0].len..]);
        let x, ex = jwe::decrypt(forged, jwa::ECDH_ES_A128KW, bob);
        tv::check_int(str(change[0], " changed: another key"), ex, jwx::ERR_DECRYPT);
    }
    tv::done("ecdh");
}
