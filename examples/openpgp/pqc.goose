// pqc: post-quantum OpenPGP, both kinds, made here for this run only.
//
// First a key as gpg 2.5 makes them (Ed25519 with a v5 Kyber subkey,
// LibrePGP's ML-KEM-768+X25519, "ky768_cv25519"): its armored public key
// is what gpg imports (gpg --import) and encrypts to; a message encrypted
// to that public key alone is decrypted with the secret key, which is
// exported protected by a passphrase and read back first. Then an RFC
// 9980 key (ML-DSA-65+Ed25519 with ML-KEM-768+X25519, v6): a detached
// composite signature verified with its public key, and refused over a
// changed document; a message signed and encrypted by it, read back.
// Every result is checked; the keys are random, so the output's
// fingerprints differ on each run. No network, no files.
//
//   goose examples/openpgp/pqc.goose
import std;
import gslib from "../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import gslib.crypto.openpgp.keygen;

fn must(what: const u8[:], e: i64) {
    if e != openpgp::OK {
        print("pqc: ", what, ": ", openpgp::error_text(e));
        exit(1);
    }
}

fn expect(what: const u8[:], ok: bool) {
    if !ok {
        print("pqc: ", what, ": unexpected result");
        exit(1);
    }
}

fn show(kr: const openpgp::Keyring&, primary: i64) {
    for i in kr.keys.len {
        let k = kr.keys[i];
        if k.primary != primary { continue; }
        print(if k.subkey { "  sub " } else { "  key " }, openpgp::key_type_name(k), " v", k.version, " ",
              openpgp::hex(k.fpr));
    }
}

fn main() {
    let doc = "Harvest now, decrypt later? Not this one.\n";
    let made: i64 = 1794000000;      // 2026-11-07: keys must not be from the future

    // 1. gpg's kind.
    var mine = openpgp::Keyring { .. };
    must("generate", openpgp::generate_pqc_key(mine, "Alice PQ <alice@example.com>", made));
    print("gpg 2.5's kind (LibrePGP):");
    show(mine, 0);
    var armored: u8[>..] = [];
    must("export public", openpgp::export_public(mine, 0, armored, true));
    expect("armored", starts_with(armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    print("  public key: ", armored.len, " bytes armored (gpg --import takes it)");
    var secret: u8[>..] = [];
    // A small S2K count (65536 octets, coded 96) to keep the example quick;
    // the default is gpg's 65 million.
    must("export secret", openpgp::export_secret(mine, 0, secret, true, "correct horse", 96));

    // A sender with the public key only.
    var theirs = openpgp::Keyring { .. };
    must("import public", openpgp::add_keys(theirs, armored));
    let alice = openpgp::find_key(theirs, "alice@example.com");
    expect("found", alice == 0 && openpgp::encryption_key(theirs, alice) == 1);
    var enc: u8[>..] = [];
    must("encrypt", openpgp::encrypt(theirs, [alice], "", doc, enc, openpgp::WriteOptions { .. }));
    var nokey = openpgp::Message { .. };
    expect("no secret, no plaintext", openpgp::read_message(theirs, enc, nokey, openpgp::ReadOptions { .. }) == openpgp::ERR_NO_KEY);

    // The recipient, from the protected export.
    var back = openpgp::Keyring { .. };
    must("import secret", openpgp::add_keys(back, secret));
    expect("wrong passphrase", openpgp::unlock(back, 0, "battery staple") == openpgp::ERR_PASSPHRASE);
    must("unlock", openpgp::unlock(back, 0, "correct horse"));
    var m = openpgp::Message { .. };
    must("decrypt", openpgp::decrypt(back, enc, m, openpgp::ReadOptions { .. }));
    expect("same text", m.data[..] == doc && m.decrypted_with == 1);
    print("  decrypted with the Kyber subkey: ", m.data.len, " bytes, ",
          if m.integrity == openpgp::INTEGRITY_MDC { "SEIPD v1 with the MDC" } else { "AEAD" });

    // 2. RFC 9980's.
    var rk = openpgp::Keyring { .. };
    must("generate RFC 9980", openpgp::generate_rfc9980_key(rk, "Bob PQ <bob@example.com>", made));
    print("RFC 9980:");
    show(rk, 0);
    var sig: u8[>..] = [];
    must("sign", openpgp::sign_detached(rk, 0, doc, sig, openpgp::WriteOptions { .. }));
    var pub: u8[>..] = [];
    must("export RFC 9980 public", openpgp::export_public(rk, 0, pub));
    var verifier = openpgp::Keyring { .. };
    must("import RFC 9980 public", openpgp::add_keys(verifier, pub));
    var mv = openpgp::Message { .. };
    must("verify", openpgp::verify_detached(verifier, doc, sig, mv));
    print("  signature: ", openpgp::algo_name(mv.sigs[0].pk_algo), ", ", sig.len, " bytes armored, good");
    var mb = openpgp::Message { .. };
    expect("changed document refused",
           openpgp::verify_detached(verifier, "Harvest now, decrypt later? Yes.\n", sig, mb) == openpgp::ERR_BAD_SIGNATURE);
    var enc2: u8[>..] = [];
    must("sign and encrypt", openpgp::encrypt(rk, [0], "", doc, enc2, openpgp::WriteOptions { .. }, 0));
    var m2 = openpgp::Message { .. };
    must("read", openpgp::read_message(rk, enc2, m2, openpgp::ReadOptions { .. }));
    expect("signed and same text", m2.data[..] == doc && openpgp::signature_status(m2) == openpgp::OK);
    print("  signed and encrypted to itself: read back, signature good");
}
