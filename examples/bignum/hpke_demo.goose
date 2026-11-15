// HPKE (RFC 9180), public-key encryption to a recipient's key: base mode
// with X25519, HKDF-SHA256 and AES-128-GCM, a context sealing several
// messages in order and exporting a secret; single-shot seal and open
// with the post-quantum hybrid ML-KEM-768 + X25519 (X-Wing); and the
// authenticated mode, where the recipient also learns who sent it.
//
//   goose examples/bignum/hpke_demo.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.hpke;
import gslib.crypto.bignum.ct;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn fail(what: const u8[:]) { print("hpke_demo: ", what); exit(1); }

fn main() {
    let kem = bignum::HPKE_DHKEM_X25519;
    let kdf = bignum::HPKE_HKDF_SHA256;
    let aead = bignum::HPKE_AES128GCM;
    let info = "example.com chat v1";        // binds both sides to one application

    // The recipient publishes pk and keeps sk.
    let sk, pk = bignum::hpke_keygen(kem);

    // The sender sets up a context: enc goes to the recipient once, then
    // each seal uses the next nonce.
    var enc, sender, ok = bignum::hpke_sender(kem, kdf, aead, pk, info);
    guard ok else { fail("sender setup"); }
    let c1, ok1 = bignum::hpke_seal(sender, "msg 1", "hello");
    let c2, ok2 = bignum::hpke_seal(sender, "msg 2", "how are you?");
    guard ok1 && ok2 else { fail("seal"); }
    print("enc ", enc.len, " bytes: ", hex(enc));

    // The recipient opens them in the same order.
    var recipient, okr = bignum::hpke_recipient(kem, kdf, aead, sk, enc, info);
    guard okr else { fail("recipient setup"); }
    let p1, okp1 = bignum::hpke_open(recipient, "msg 1", c1);
    let p2, okp2 = bignum::hpke_open(recipient, "msg 2", c2);
    guard okp1 && okp2 && p1 == "hello" && p2 == "how are you?" else { fail("open"); }
    print("opened in order: \"", p1, "\", \"", p2, "\"");

    // Both sides can export the same secret, for keys beyond the messages.
    let xs, oks = bignum::hpke_export(sender, "resumption key", 32);
    let xr, okr = bignum::hpke_export(recipient, "resumption key", 32);
    guard oks && okr && bignum::ct_eq_bytes(xs, xr) == 1 else { fail("export"); }
    print("exported secret ", hex(xs));

    // Another info string (another application) cannot open the messages.
    var wrong, okw = bignum::hpke_recipient(kem, kdf, aead, sk, enc, "other app");
    let pw, okpw = bignum::hpke_open(wrong, "msg 1", c1);
    guard !okpw else { fail("opened under the wrong info"); }

    // Single shot, post-quantum: enc and ciphertext in one buffer.
    let pq = bignum::HPKE_MLKEM768_X25519;
    let pq_sk, pq_pk = bignum::hpke_keygen(pq);
    let sealed, oks = bignum::hpke_seal_once(pq, kdf, bignum::HPKE_CHACHA20POLY1305, pq_pk, info, "quantum-safe note");
    let opened, oko = bignum::hpke_open_once(pq, kdf, bignum::HPKE_CHACHA20POLY1305, pq_sk, info, sealed);
    guard oks && oko && opened == "quantum-safe note" else { fail("ML-KEM-768 + X25519 single shot"); }
    print("X-Wing single shot: ", sealed.len, " bytes, opened");

    // Auth mode (DHKEM only): the sender's key pair goes in, and only its
    // public key opens it, so the recipient knows who sealed it.
    let ssk, spk = bignum::hpke_keygen(kem);
    var enca, sa, oka = bignum::hpke_sender(kem, kdf, aead, pk, info, "", "", ssk);
    let ca, okca = bignum::hpke_seal(sa, "", "signed, so to speak");
    var ra, okra = bignum::hpke_recipient(kem, kdf, aead, sk, enca, info, "", "", spk);
    let pa, okpa = bignum::hpke_open(ra, "", ca);
    let osk, opk = bignum::hpke_keygen(kem);
    var rb, okrb = bignum::hpke_recipient(kem, kdf, aead, sk, enca, info, "", "", opk);
    let pb, okpb = bignum::hpke_open(rb, "", ca);
    guard oka && okca && okra && okpa && pa == "signed, so to speak" && !okpb else { fail("auth mode"); }
    print("auth mode: opens with the sender's key, not with another");
}
