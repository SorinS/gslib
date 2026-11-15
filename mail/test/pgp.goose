// PGP/MIME (mail.pgp) with the test keys of pgp/ (Alice, Ed25519 +
// Curve25519, and Bob, RSA-3072; made by gpg through
// scripts/interop_pgp.py --write-vectors, test keys only):
//
//   - a mail::Msg signed by each key as multipart/signed: the header
//     outside, micalg and protocol, the entity signed exactly as sent;
//     back through verify with the signer and the entity; a changed byte
//     refused, and a message with LF line ends read as well;
//   - encryption, signed and not, to each key, read back; not for any
//     key here, a changed ciphertext, 8bit bodies for multipart/signed,
//     messages that are not PGP/MIME, refused;
//   - messages gpg made (pgp/gpg-*.eml): multipart/signed, multipart/
//     encrypted, signed and encrypted in one message (RFC 3156 §6.2) and
//     multipart/signed inside multipart/encrypted (§6.1);
//   - post-quantum recipients, with no change to the API: a key of gpg
//     2.5's kind (Ed25519 with a v5 ML-KEM-768+X25519 Kyber subkey) and an
//     RFC 9980 one (ML-DSA-65+Ed25519 with ML-KEM-768+X25519), made here,
//     encrypted to (alone and with Bob), signed by Alice or by the RFC
//     9980 key itself, opened by each recipient.
import std;
import gslib from "../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import gslib.crypto.openpgp.keygen;
import gslib.mail;
import gslib.mail.message;
import gslib.mail.pgp;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { print("FAIL ", what); failures++; }
}

fn check_rc(what: const u8[:], got: i64, want: i64) {
    checks++;
    if got != want { print("FAIL ", what, ": ", mail::error_text(got), ", want ", mail::error_text(want)); failures++; }
}

fn contains(s: const u8[:], sub: const u8[:]) -> bool { find(s, sub) >= 0 }

let TIME: i64 = 1795000000;      // the signature time written, after the keys were made

let KEYS_SEC = embed_file("pgp/keys.sec");
let KEYS_PUB = embed_file("pgp/keys.pub");
let ENTITY = embed_file("pgp/entity.txt");

fn message(m: mail::Msg&) {
    let r1 = mail::set_from(m, "Alice <alice@example.com>");
    let r2 = mail::add_to(m, "Bob <bob@example.com>");
    let r3 = mail::set_subject(m, "PGP/MIME, Café");
    let r4 = mail::set_body(m, mail::TEXT_PLAIN, "Hello Bob,\n\nsee you at the café.\n");
    mail::set_date(m, TIME);
    let r5 = mail::set_message_id(m, "pgp-test@example.com");
    let r6 = mail::set_boundary(m, "msg-boundary");
}

fn opts() -> pgp::Options {
    var o = pgp::Options { .. };
    o.created = TIME;
    o.boundary.append("pgp-boundary");
    return o;
}

fn signing(kr: const openpgp::Keyring&, alice: i64, bob: i64) {
    for signer in [alice, bob] {
        let who = if signer == alice { "alice" } else { "bob" };
        var m = mail::Msg { .. };
        message(m);
        var plain: u8[>..] = [];
        let rw = mail::write(m, plain);
        var out: u8[>..] = [];
        let o = opts();
        let rc = pgp::sign(m, kr, signer, o, out);
        check_rc(str(who, " sign"), rc, mail::OK);
        let ct = find(out, "Content-Type: multipart/signed;");
        let from = find(out, "From: \"Alice\" <alice@example.com>");
        let subj = find(out, "Subject:");
        let mv = find(out, "MIME-Version: 1.0");
        check(str(who, " header outside"), ct > 0 && from >= 0 && from < ct && subj >= 0 && subj < ct && mv >= 0 && mv < ct);
        check(str(who, " micalg and protocol"), contains(out, "micalg=pgp-sha256") && contains(out, "protocol=\"application/pgp-signature\""));
        check(str(who, " signature part"), contains(out, "Content-Type: application/pgp-signature") && contains(out, "-----BEGIN PGP SIGNATURE-----\r\n"));
        // The entity signed is the Msg's Content-* fields and body, as sent.
        let body_at = find(plain, "\r\n\r\n");
        let first = find(out, "--pgp-boundary\r\n") + 16;
        check(str(who, " entity as sent"), find(out[first..], "Content-Transfer-Encoding: quoted-printable\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n") == 0
              && contains(out, plain[body_at + 4..]));
        var r = pgp::Opened { .. };
        let label_93 = str(who, " verify");
        check_rc(label_93, pgp::verify(out, kr, r), mail::OK);
        check(str(who, " signer"), r.signed && !r.encrypted && kr.keys[r.signer].primary == signer && r.signed_at == TIME);
        check(str(who, " entity"), starts_with(r.entity, "Content-Transfer-Encoding: quoted-printable\r\nContent-Type: text/plain")
              && ends_with(r.entity, plain[body_at + 4..]));
        check(str(who, " message"), starts_with(r.message, "Date: ") && contains(r.message, "Subject:") && !contains(r.message, "multipart/signed"));
        // LF line ends, as a message saved to a file may have.
        var lf: u8[>..] = [];
        for c in out { if c != '\r' { lf.push(c); } }
        var r2 = pgp::Opened { .. };
        let label_103 = str(who, " verify LF");
        check_rc(label_103, pgp::verify(lf, kr, r2), mail::OK);
        // A changed byte of the signed entity.
        var bad = copy(out);
        let at = find(bad, "Hello Bob");
        bad[at] = 'J';
        var r3 = pgp::Opened { .. };
        let label_110 = str(who, " changed");
        check_rc(label_110, pgp::verify(bad, kr, r3), mail::ERR_SIGNATURE);
    }
    // micalg follows the hash.
    var m = mail::Msg { .. };
    message(m);
    var o = opts();
    o.hash = openpgp::HASH_SHA512;
    var out: u8[>..] = [];
    check_rc("sha512 sign", pgp::sign(m, kr, alice, o, out), mail::OK);
    check("pgp-sha512", contains(out, "micalg=pgp-sha512"));
    var r = pgp::Opened { .. };
    check_rc("sha512 verify", pgp::verify(out, kr, r), mail::OK);
    // With attachments: multipart/mixed signed whole.
    var ma = mail::Msg { .. };
    message(ma);
    let ra = mail::attach(ma, "data.bin", "\x00\x01\x02 binary \xff");
    var outa: u8[>..] = [];
    check_rc("attachment sign", pgp::sign(ma, kr, bob, opts(), outa), mail::OK);
    var rr = pgp::Opened { .. };
    check_rc("attachment verify", pgp::verify(outa, kr, rr), mail::OK);
    check("attachment entity", starts_with(rr.entity, "Content-Type: multipart/mixed;"));
    // 8bit cannot go into multipart/signed.
    var m8 = mail::Msg { .. };
    message(m8);
    let r8 = mail::set_encoding(m8, mail::ENC_8BIT);
    var out8: u8[>..] = [];
    check_rc("8bit refused", pgp::sign(m8, kr, alice, opts(), out8), mail::ERR_ARG);
    // Verified without the signer's key.
    var nokey = openpgp::Keyring { .. };
    var r4 = pgp::Opened { .. };
    check_rc("unknown signer", pgp::verify(out, nokey, r4), mail::ERR_KEY);
}

fn encryption(kr: const openpgp::Keyring&, alice: i64, bob: i64) {
    for rcpt in [alice, bob] {
        for signer in [-1, alice, bob] {
            let what = str("to ", if rcpt == alice { "alice" } else { "bob" }, if signer < 0 { "" } else if signer == alice { " by alice" } else { " by bob" });
            var m = mail::Msg { .. };
            message(m);
            var out: u8[>..] = [];
            let rc = if signer < 0 { pgp::encrypt(m, kr, [rcpt], opts(), out) } else { pgp::sign_encrypt(m, kr, signer, [rcpt], opts(), out) };
            check_rc(str(what, " encrypt"), rc, mail::OK);
            let ct = find(out, "Content-Type: multipart/encrypted;");
            let subj = find(out, "Subject:");
            check(str(what, " header outside"), ct > 0 && subj >= 0 && subj < ct && contains(out, "protocol=\"application/pgp-encrypted\"")
                  && contains(out, "\r\nVersion: 1\r\n") && contains(out, "-----BEGIN PGP MESSAGE-----\r\n") && !contains(out, "Hello Bob"));
            var r = pgp::Opened { .. };
            let label_155 = str(what, " open");
            check_rc(label_155, pgp::open(out, kr, "", r), mail::OK);
            check(str(what, " layers"), r.encrypted && r.signed == (signer >= 0) && (signer < 0 || kr.keys[r.signer].primary == signer));
            check(str(what, " entity"), starts_with(r.entity, "Content-Transfer-Encoding: quoted-printable\r\nContent-Type: text/plain")
                  && contains(r.entity, "Hello Bob,"));
            var rd = pgp::Opened { .. };
            let label_162 = str(what, " decrypt");
            check_rc(label_162, pgp::decrypt(out, kr, "", rd), mail::OK);
            var rv = pgp::Opened { .. };
            let label_166 = str(what, " verify");
            check_rc(label_166, pgp::verify(out, kr, rv), if signer < 0 { mail::ERR_SIGNATURE } else { mail::OK });
        }
    }
    // To a key not here; a changed ciphertext.
    var other = openpgp::Keyring { .. };
    let eg = openpgp::generate_key(other, "Carol <carol@example.org>", TIME - 1000000);
    var m = mail::Msg { .. };
    message(m);
    var out: u8[>..] = [];
    check_rc("to carol", pgp::encrypt(m, other, [0], opts(), out), mail::OK);
    var r = pgp::Opened { .. };
    check_rc("not for us", pgp::open(out, kr, "", r), mail::ERR_DECRYPT);
    var out2: u8[>..] = [];
    let e2 = pgp::encrypt(m, kr, [bob], opts(), out2);
    let at = find(out2, "-----END PGP MESSAGE-----") - 12;
    out2[at] = if out2[at] == 'A' { 'B' } else { 'A' };
    var r2 = pgp::Opened { .. };
    check("changed ciphertext", pgp::open(out2, kr, "", r2) != mail::OK);
    // Not PGP/MIME.
    var plain: u8[>..] = [];
    let ep = mail::write(m, plain);
    var r3 = pgp::Opened { .. };
    check_rc("not pgp/mime", pgp::open(plain, kr, "", r3), mail::ERR_FORMAT);
    var r4 = pgp::Opened { .. };
    check_rc("broken multipart", pgp::open("Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=x\r\n\r\n--x\r\nno end", kr, "", r4), mail::ERR_FORMAT);
    check_rc("no recipients", pgp::encrypt(m, kr, [], opts(), out), mail::ERR_ARG);
}

fn from_gpg(kr: const openpgp::Keyring&, alice: i64) {
    for name in ["gpg-signed.eml", "gpg-encrypted.eml", "gpg-signed-encrypted.eml", "gpg-nested.eml"] {
        var data: u8[>..] = [];
        if !read_file(str("pgp/", name), data) { check(str("read ", name), false); continue; }
        var r = pgp::Opened { .. };
        let label_195 = str(name, " opens");
        check_rc(label_195, pgp::open(data, kr, "", r), mail::OK);
        check(str(name, " entity"), r.entity[..] == ENTITY);
        let enc = name != "gpg-signed.eml";
        let sig = name != "gpg-encrypted.eml";
        check(str(name, " layers"), r.encrypted == enc && r.signed == sig && (!sig || kr.keys[r.signer].primary == alice));
        check(str(name, " message"), starts_with(r.message, "Date: Sat, 14 Nov 2026") && ends_with(r.message, ENTITY));
    }
}

fn pqc(kr: const openpgp::Keyring&, alice: i64, bob: i64) {
    for kind in 2 {
        let what = if kind == 0 { "kyber" } else { "rfc9980" };
        var pk = openpgp::Keyring { .. };
        let eg = openpgp::add_keys(pk, KEYS_SEC);
        let carol = pk.keys.len;
        let e = if kind == 0 { openpgp::generate_pqc_key(pk, "Carol <carol@example.com>", TIME - 1000000) }
                else { openpgp::generate_rfc9980_key(pk, "Carol <carol@example.com>", TIME - 1000000) };
        check(str(what, " key"), e == openpgp::OK && pk.keys[carol].valid);
        let pa = openpgp::find_key(pk, "alice@example.com");
        let pb = openpgp::find_key(pk, "bob@example.com");
        // The RFC 9980 key signs too (ML-DSA-65+Ed25519).
        let signer = if kind == 0 { pa } else { carol };
        var m = mail::Msg { .. };
        message(m);
        var out: u8[>..] = [];
        check_rc(str(what, " encrypt"), pgp::encrypt(m, pk, [carol], opts(), out), mail::OK);
        var r = pgp::Opened { .. };
        let label_222 = str(what, " open");
        check_rc(label_222, pgp::open(out, pk, "", r), mail::OK);
        check(str(what, " entity"), r.encrypted && !r.signed && contains(r.entity, "Hello Bob,"));
        var out2: u8[>..] = [];
        check_rc(str(what, " sign and encrypt, with bob"), pgp::sign_encrypt(m, pk, signer, [carol, pb], opts(), out2), mail::OK);
        var r2 = pgp::Opened { .. };
        let label_231 = str(what, " open signed");
        check_rc(label_231, pgp::open(out2, pk, "", r2), mail::OK);
        check(str(what, " signed"), r2.encrypted && r2.signed && pk.keys[r2.signer].primary == signer);
        // Bob alone (the keyring without Carol's secret) opens it too.
        var r3 = pgp::Opened { .. };
        let label_238 = str(what, " bob opens it");
        check_rc(label_238, pgp::open(out2, kr, "", r3), if kind == 0 { mail::OK } else { mail::ERR_KEY });
        // The multipart/signed form, by the RFC 9980 key.
        if kind == 1 {
            var out3: u8[>..] = [];
            check_rc("rfc9980 sign", pgp::sign(m, pk, carol, opts(), out3), mail::OK);
            var r4 = pgp::Opened { .. };
            check_rc("rfc9980 verify", pgp::verify(out3, pk, r4), mail::OK);
            check("rfc9980 micalg", contains(out3, "micalg=pgp-sha256"));
        }
    }
}

// What the review found: an Opened used again holds nothing of the
// message before; a line the boundary only starts is not a delimiter.
fn review(kr: const openpgp::Keyring&, alice: i64, bob: i64) {
    var m1 = mail::Msg { .. };
    message(m1);
    var s1: u8[>..] = [];
    check_rc("review sign", pgp::sign(m1, kr, alice, opts(), s1), mail::OK);
    var m2 = mail::Msg { .. };
    message(m2);
    var s2: u8[>..] = [];
    check_rc("review encrypt", pgp::encrypt(m2, kr, [bob], opts(), s2), mail::OK);
    var r = pgp::Opened { .. };
    check_rc("reuse: signed", pgp::verify(s1, kr, r), mail::OK);
    check_rc("reuse: not signed", pgp::verify(s2, kr, r), mail::ERR_SIGNATURE);
    check("reuse: fresh", !r.signed && r.encrypted && r.signer == -1 && r.signer_fpr.len == 0
          && find(r.entity, "Hello Bob") >= 0 && find(r.entity, "Hello Bob") == rfind(r.entity, "Hello Bob"));

    var spans: i64[>..] = [];
    let body = "--b\r\none\r\n--bx\r\nstill one\r\n--b \r\ntwo\r\n--b--\r\n";
    check("delimiter whole", pgp::parts_of(body, "b", spans) && spans.len == 4
          && body[spans[0]..spans[1]] == "one\r\n--bx\r\nstill one" && body[spans[2]..spans[3]] == "two");
    var sp2: i64[>..] = [];
    check("close delimiter whole", !pgp::parts_of("--b\r\none\r\n--b--x\r\n", "b", sp2));
}

fn main() {
    var kr = openpgp::Keyring { .. };
    check_rc("keys", openpgp::add_keys(kr, KEYS_SEC), openpgp::OK);
    let alice = openpgp::find_key(kr, "alice@example.com");
    let bob = openpgp::find_key(kr, "bob@example.com");
    check("both keys", alice >= 0 && bob >= 0 && kr.keys[alice].has_secret && kr.keys[bob].has_secret);
    signing(kr, alice, bob);
    encryption(kr, alice, bob);
    from_gpg(kr, alice);
    pqc(kr, alice, bob);
    review(kr, alice, bob);
    print("pgp: ", checks - failures, "/", checks, " checks passed");
    if failures > 0 { exit(1); }
}
