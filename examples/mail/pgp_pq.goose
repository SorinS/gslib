// pgp_pq: a PGP/MIME message (RFC 3156, through mail.pgp) signed by Alice
// and encrypted to Bob's post-quantum OpenPGP key, then opened by Bob:
// decrypted, the signature checked. Bob's key is of gpg 2.5's kind
// (Ed25519 with a Kyber subkey: LibrePGP's ML-KEM-768+X25519), so gpg
// 2.5 reads the same message; Alice's is a plain Ed25519 key. mail.pgp's
// API is the same as for any other key: the post-quantum part is in the
// recipient's key alone. Both keys are made here, for this run only. No
// network, no files.
//
//   goose examples/mail/pgp_pq.goose

import std;
import gslib from "../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.keygen;
import gslib.mail;
import gslib.mail.message;
import gslib.mail.pgp;

fn must(what: const u8[:], rc: i64) {
    if rc != mail::OK {
        print("pgp_pq: ", what, ": ", mail::error_text(rc));
        exit(1);
    }
}

fn expect(what: const u8[:], ok: bool) {
    if !ok {
        print("pgp_pq: ", what, ": unexpected result");
        exit(1);
    }
}

fn main() {
    let made: i64 = 1794000000;      // 2026-11-07: keys must not be from the future
    var kr = openpgp::Keyring { .. };
    expect("alice's key", openpgp::generate_key(kr, "Alice <alice@example.com>", made) == openpgp::OK);
    expect("bob's key", openpgp::generate_pqc_key(kr, "Bob <bob@example.com>", made) == openpgp::OK);
    let alice = openpgp::find_key(kr, "alice@example.com");
    let bob = openpgp::find_key(kr, "bob@example.com");
    let sub = openpgp::encryption_key(kr, bob);
    print("bob encrypts with ", openpgp::key_type_name(kr.keys[sub]), " ", openpgp::hex(kr.keys[sub].fpr));

    var m = mail::Msg { .. };
    must("from", mail::set_from(m, "Alice <alice@example.com>"));
    must("to", mail::add_to(m, "Bob <bob@example.com>"));
    must("subject", mail::set_subject(m, "Quarterly numbers"));
    must("body", mail::set_body(m, mail::TEXT_PLAIN, "Bob,\n\nthe numbers are attached. Keep them for ten years.\n\nAlice\n"));
    must("attachment", mail::attach(m, "numbers.csv", "quarter,revenue\nQ3,1234\n"));

    var out: u8[>..] = [];
    must("sign and encrypt", pgp::sign_encrypt(m, kr, alice, [bob], pgp::Options { .. }, out));
    let ct = find(out, "Content-Type: multipart/encrypted;");
    expect("multipart/encrypted", ct > 0 && find(out, "-----BEGIN PGP MESSAGE-----") > ct && find(out, "ten years") < 0);
    print("sent: ", out.len, " bytes, multipart/encrypted, nothing readable inside");

    var r = pgp::Opened { .. };
    must("open", pgp::open(out, kr, "", r));
    expect("layers", r.encrypted && r.signed && kr.keys[r.signer].primary == alice);
    expect("entity", starts_with(r.entity, "Content-Type: multipart/mixed;") && find(r.entity, "ten years") > 0
           && find(r.entity, "numbers.csv") > 0);
    print("opened: decrypted, signed by ", openpgp::primary_uid(kr, alice), ", ", r.entity.len, " bytes of MIME entity");

    // Someone without Bob's secret key cannot open it.
    var stranger = openpgp::Keyring { .. };
    expect("stranger's key", openpgp::generate_pqc_key(stranger, "Eve <eve@example.com>", made) == openpgp::OK);
    var r2 = pgp::Opened { .. };
    expect("not for eve", pgp::open(out, stranger, "", r2) == mail::ERR_DECRYPT);
    print("eve's post-quantum key does not open it");
}
