// new_curves: OpenPGP keys on the newer curves, made here for this run only.
//
// Four kinds, as gpg 2.5 makes them unless said otherwise:
//   brainpoolP384r1   ECDSA primary with an ECDH subkey on the same curve
//   ed448             Ed448 (EdDSALegacy) with a cv448 ECDH subkey: gpg
//                     makes the 448 curves as v5 keys, signing v5
//                     signatures, and so does this
//   ed448-v6          RFC 9580's own Ed448 (28) and X448 (26), on v6 keys
//                     (gpg 2.5 does not read them)
//   pqc               gpg's default post-quantum key: brainpoolP384r1 with
//                     a v5 Kyber subkey, ML-KEM-768+brainpoolP256r1
//                     ("ky768_bp256")
// For each: a detached signature verified with the armored public key
// alone (what gpg --import takes) and refused over a changed document; a
// cleartext signature verified; a message encrypted to the public key
// decrypted with the secret key, which is exported protected by a
// passphrase and read back first. Every result is checked; the keys are
// random, so the fingerprints differ on each run. No network, no files.
//
//   goose examples/openpgp/new_curves.goose
import std;
import gslib from "../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import gslib.crypto.openpgp.keygen;

fn must(what: const u8[:], e: i64) {
    if e != openpgp::OK {
        print("new_curves: ", what, ": ", openpgp::error_text(e));
        exit(1);
    }
}

fn expect(what: const u8[:], ok: bool) {
    if !ok {
        print("new_curves: ", what, ": unexpected result");
        exit(1);
    }
}

fn generate(kr: openpgp::Keyring&, kind: const u8[:], uid: const u8[:], made: i64) -> i64 {
    if kind == "brainpoolP384r1" { return openpgp::generate_brainpool_key(kr, uid, 384, made); }
    if kind == "ed448" { return openpgp::generate_ed448_key(kr, uid, made); }
    if kind == "ed448-v6" { return openpgp::generate_ed448_v6_key(kr, uid, made); }
    return openpgp::generate_pqc_bp_key(kr, uid, made);
}

fn main() {
    let doc = "Curves other than 25519.\n";
    let made: i64 = 1794000000;      // 2026-11-07: keys must not be from the future
    for kind in ["brainpoolP384r1", "ed448", "ed448-v6", "pqc"] {
        var mine = openpgp::Keyring { .. };
        must(str(kind, ": generate"), generate(mine, kind, "Alice <alice@example.com>", made));
        print(kind, ":");
        for k in mine.keys {
            print(if k.subkey { "  sub " } else { "  key " }, openpgp::key_type_name(k), " (", openpgp::algo_name(k.algo),
                  ") v", k.version, " ", openpgp::hex(k.fpr));
        }
        var pub: u8[>..] = [];
        must("export public", openpgp::export_public(mine, 0, pub, true));
        // A small S2K count (65536 octets, coded 96) to keep the example
        // quick; the default is gpg's 65 million.
        var secret: u8[>..] = [];
        must("export secret", openpgp::export_secret(mine, 0, secret, true, "correct horse", 96));

        // Signatures, checked by someone with the public key only.
        var sig: u8[>..] = [];
        must("sign", openpgp::sign_detached(mine, 0, doc, sig, openpgp::WriteOptions { .. }));
        var clear: u8[>..] = [];
        must("sign cleartext", openpgp::sign_cleartext(mine, 0, doc, clear, openpgp::WriteOptions { .. }));
        var theirs = openpgp::Keyring { .. };
        must("import public", openpgp::add_keys(theirs, pub));
        var mv = openpgp::Message { .. };
        must("verify", openpgp::verify_detached(theirs, doc, sig, mv));
        var mb = openpgp::Message { .. };
        expect("changed document refused",
               openpgp::verify_detached(theirs, "Curves other than 448.\n", sig, mb) == openpgp::ERR_BAD_SIGNATURE);
        var mc = openpgp::Message { .. };
        must("verify cleartext", openpgp::verify_cleartext(theirs, clear, mc));
        print("  signature: ", openpgp::hash_name(mv.sigs[0].hash), ", good; changed document refused; cleartext good");

        // A message to the public key, read with the protected secret.
        var enc: u8[>..] = [];
        must("encrypt", openpgp::encrypt(theirs, [0], "", doc, enc, openpgp::WriteOptions { .. }));
        var back = openpgp::Keyring { .. };
        must("import secret", openpgp::add_keys(back, secret));
        expect("wrong passphrase", openpgp::unlock(back, 0, "battery staple") == openpgp::ERR_PASSPHRASE);
        must("unlock", openpgp::unlock(back, 0, "correct horse"));
        var m = openpgp::Message { .. };
        must("decrypt", openpgp::decrypt(back, enc, m, openpgp::ReadOptions { .. }));
        expect("same text", m.data[..] == doc && m.decrypted_with == 1);
        print("  decrypted with the ", openpgp::key_type_name(back.keys[1]), " subkey: ", m.data.len, " bytes");
    }
}
