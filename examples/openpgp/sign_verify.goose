// sign_verify: OpenPGP signatures and encryption, with a test key made
// by gpg (test_key.asc: Ed25519 with a Curve25519 subkey; test only, not
// protected).
// Signs a document detached, inline and as a cleartext message, verifies
// each, and shows a changed document refused; then encrypts to the key,
// signed, and reads it back. The signature time is fixed and Ed25519 is
// deterministic, so the signatures printed are the same on every run.
//
//   goose examples/openpgp/sign_verify.goose
import std;
import gslib from "../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.armor;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;

// Test only: user ID "Test <test@example.com>", made by gpg, unprotected.
let KEY = embed_file("test_key.asc");

let SIGNED_AT: i64 = 1795000000;     // 2026-11-18, after the key was made

fn fail(what: const u8[:], e: i64) {
    print("sign_verify: ", what, ": ", openpgp::error_text(e));
    exit(1);
}

fn main() {
    var kr = openpgp::Keyring { .. };
    let e = openpgp::add_keys(kr, KEY);
    if e != openpgp::OK { fail("key", e); }
    let me = openpgp::find_key(kr, "test@example.com");
    print("key ", openpgp::hex(kr.keys[me].fpr), " \"", openpgp::primary_uid(kr, me), "\"");

    let doc = "The quick brown fox\njumps over the lazy dog.\n";
    var w = openpgp::WriteOptions { .. };
    w.created = SIGNED_AT;

    // Detached, armored.
    var sig: u8[>..] = [];
    let e1 = openpgp::sign_detached(kr, me, doc, sig, w);
    if e1 != openpgp::OK { fail("sign", e1); }
    print(sig);
    var m = openpgp::Message { .. };
    let v = openpgp::verify_detached(kr, doc, sig, m);
    print("detached: ", openpgp::error_text(v), ", by ", openpgp::hex(kr.keys[m.sigs[0].key].keyid),
          ", ", openpgp::hash_name(m.sigs[0].hash), ", at ", m.sigs[0].created);
    var m2 = openpgp::Message { .. };
    let v2 = openpgp::verify_detached(kr, "The quick brown cat\njumps over the lazy dog.\n", sig, m2);
    print("changed document: ", openpgp::error_text(v2));

    // Inline: the document inside the signed message.
    var inl: u8[>..] = [];
    let e2 = openpgp::sign(kr, me, doc, inl, w);
    if e2 != openpgp::OK { fail("sign inline", e2); }
    var m3 = openpgp::Message { .. };
    let v3 = openpgp::verify(kr, inl, m3, openpgp::ReadOptions { .. });
    print("inline: ", openpgp::error_text(v3), ", ", m3.data.len, " bytes");

    // Cleartext: readable as it is.
    var clear: u8[>..] = [];
    let e3 = openpgp::sign_cleartext(kr, me, doc, clear, w);
    if e3 != openpgp::OK { fail("sign cleartext", e3); }
    print(clear);
    var m4 = openpgp::Message { .. };
    print("cleartext: ", openpgp::error_text(openpgp::verify_cleartext(kr, clear, m4)));

    // Encrypted to the key and signed by it (the ciphertext differs each
    // run: the session key is random).
    var enc: u8[>..] = [];
    let e4 = openpgp::encrypt(kr, [me], "", doc, enc, w, me);
    if e4 != openpgp::OK { fail("encrypt", e4); }
    var m5 = openpgp::Message { .. };
    let v5 = openpgp::read_message(kr, enc, m5, openpgp::ReadOptions { .. });
    print("decrypted: ", openpgp::error_text(v5), ", integrity ", if m5.integrity == openpgp::INTEGRITY_MDC { "MDC" } else { "?" },
          ", signature ", openpgp::error_text(openpgp::signature_status(m5)), ", same text ", m5.data[..] == doc);
}
