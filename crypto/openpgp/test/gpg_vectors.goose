// What gpg 2.5 writes (test/vectors, made by scripts/gen_vectors.py) and
// RFC 9580's Appendix A samples.
//
// gpg's keys: fingerprints as gpg lists them (keys.txt), self-signatures
// and bindings valid, the protected ones locked until the passphrase (and
// not the wrong one) opens them, public and secret exports read back.
// gpg's messages: encrypted to Curve25519 and RSA (in gpg's OCB packet),
// to a passphrase (SEIPD v1), signed inline, detached (binary and text
// mode) and in cleartext, compressed with ZIP, ZLIB and BZip2 or not:
// each gives msg.txt or text.txt back, with a good signature where there
// is one. RFC 9580: the v4 Ed25519Legacy key's fingerprint and its
// signature over "OpenPGP", the v6 certificate and secret key, and the v6
// cleartext and inline-signed messages. And gpg's ECDSA and ECDH on P-384.
import std;
import gslib from "../../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.armor;
import gslib.crypto.openpgp.packet;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.sig;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import tv;

let V = "vectors/";

fn vec(name: const u8[:]) -> u8[>..] { tv::read(str(V, name)) }

fn passphrase() -> u8[>..] {
    var p = vec("passphrase.txt");
    while p.len > 0 && p[p.len - 1] == '\n' { p.resize(p.len - 1); }
    return p;
}

// gpg's fingerprints in keys.txt's order: ed, its subkey, prot, its
// subkey, rsa, its subkey.
fn fingerprints() -> u8[>..] {
    var out: u8[>..] = [];
    for line in split(vec("keys.txt"), '\n') {
        if !starts_with(line, "fpr:") { continue; }
        let f = split(line, ':');
        out.append(f[9]);
        out.push(' ');
    }
    return out;
}

fn keys(kr: openpgp::Keyring&) {
    let all = fingerprints();
    let fprs = split(all, ' ');
    for name in ["ed.pub", "prot.pub", "rsa.pub"] {
        tv::check_int(str("add ", name), openpgp::add_keys(kr, vec(name)), openpgp::OK);
    }
    tv::check_int("public keys", kr.keys.len, 6);
    for i in 6 {
        tv::check(str("fingerprint ", i), openpgp::hex(kr.keys[i].fpr)[..] == fprs[i]);
        tv::check(str("valid ", i), kr.keys[i].valid && !kr.keys[i].revoked);
    }
    tv::check("ed25519 primary", kr.keys[0].algo == openpgp::PK_EDDSA && kr.keys[0].curve == openpgp::CURVE_ED25519);
    tv::check("cv25519 subkey", kr.keys[1].algo == openpgp::PK_ECDH && kr.keys[1].curve == openpgp::CURVE_X25519
              && kr.keys[1].subkey && kr.keys[1].primary == 0);
    tv::check("rsa3072", openpgp::key_type_name(kr.keys[4])[..] == "rsa3072");
    tv::check("flags", kr.keys[0].flags == openpgp::FLAG_CERTIFY | openpgp::FLAG_SIGN && kr.keys[1].flags == openpgp::FLAG_ENCRYPT);
    tv::check("user IDs", kr.uids.len == 3 && kr.uids[0].text[..] == "Test <test@example.com>" && kr.uids[0].valid);
    tv::check_int("find by email", openpgp::find_key(kr, "rsa@example.com"), 4);
    tv::check_int("find by key ID", openpgp::find_key(kr, openpgp::hex(kr.keys[3].keyid)), 2);
    tv::check_int("find by fingerprint", openpgp::find_key(kr, str("0x", fprs[0])), 0);
    tv::check_int("find nothing", openpgp::find_key(kr, "nobody@example.org"), -1);
    tv::check_int("signing key", openpgp::signing_key(kr, 0), -1);   // no secret yet
    tv::check_int("encryption key", openpgp::encryption_key(kr, 4), 5);

    // The secrets: ed unprotected, prot and rsa protected.
    for name in ["ed.sec", "prot.sec", "rsa.sec"] {
        tv::check_int(str("add ", name), openpgp::add_keys(kr, vec(name)), openpgp::OK);
    }
    tv::check_int("all keys", kr.keys.len, 12);
    tv::check("ed secret open", kr.keys[6].has_secret && !kr.keys[6].locked && !kr.keys[7].locked);
    tv::check("prot locked", kr.keys[8].locked && kr.keys[9].locked && kr.keys[10].locked);
    tv::check_int("find prefers secret", openpgp::find_key(kr, "test@example.com"), 6);
    tv::check_int("signing key", openpgp::signing_key(kr, 6), 6);
    tv::check_int("wrong passphrase", openpgp::unlock(kr, 8, "not the passphrase"), openpgp::ERR_PASSPHRASE);
    tv::check("still locked", kr.keys[8].locked);
    let pass = passphrase();
    tv::check_int("unlock prot", openpgp::unlock(kr, 8, pass), openpgp::OK);
    tv::check_int("unlock rsa", openpgp::unlock(kr, 10, pass), openpgp::OK);
    tv::check("unlocked", !kr.keys[8].locked && !kr.keys[9].locked && !kr.keys[10].locked && !kr.keys[11].locked);
    tv::check_int("unlock no secret", openpgp::unlock(kr, 0, pass), openpgp::ERR_KEY);

    // Exports read back to the same keys; gpg's own public export is
    // what export_public gives of the secret key.
    var pub: u8[>..] = [];
    tv::check_int("export public", openpgp::export_public(kr, 6, pub), openpgp::OK);
    tv::check_eq("export public is gpg's", pub, vec("ed.pub"));
    var sec: u8[>..] = [];
    tv::check_int("export secret", openpgp::export_secret(kr, 10, sec, true, "another test passphrase", 96), openpgp::OK);
    var kr2 = openpgp::Keyring { .. };
    tv::check_int("re-read", openpgp::add_keys(kr2, sec), openpgp::OK);
    tv::check("re-read locked", kr2.keys.len == 2 && kr2.keys[0].locked && kr2.keys[0].fpr[..] == kr.keys[10].fpr[..]);
    tv::check_int("re-read unlock", openpgp::unlock(kr2, 0, "another test passphrase"), openpgp::OK);
    tv::check("re-read same secret", kr2.keys[0].d[..] == kr.keys[10].d[..] && kr2.keys[1].p[..] == kr.keys[11].p[..]);
}

fn read(kr: const openpgp::Keyring&, name: const u8[:], want: const u8[:], encrypted: bool, signed: bool) {
    var m = openpgp::Message { .. };
    var o = openpgp::ReadOptions { .. };
    o.passphrase.append(passphrase());
    let e = openpgp::read_message(kr, vec(name), m, o);
    tv::check_int(str(name, " reads"), e, openpgp::OK);
    tv::check_eq(str(name, " data"), m.data, want);
    tv::check(str(name, " encrypted"), m.encrypted == encrypted);
    if encrypted { tv::check(str(name, " integrity"), m.integrity != openpgp::INTEGRITY_NONE); }
    let st = openpgp::signature_status(m);
    tv::check_int(str(name, " signature"), st, if signed { openpgp::OK } else { openpgp::ERR_NO_SIGNATURE });
}

fn messages(kr: const openpgp::Keyring&) {
    let msg = vec("msg.txt");
    read(kr, "enc_ed.gpg", msg, true, false);
    read(kr, "enc_rsa.asc", msg, true, false);
    read(kr, "enc_signed.gpg", msg, true, true);
    read(kr, "enc_bzip2.gpg", msg, true, false);
    read(kr, "enc_nocomp.gpg", msg, true, false);
    read(kr, "sym.gpg", msg, true, false);
    read(kr, "sym_aes128_zlib.asc", msg, true, false);
    read(kr, "sig_inline.gpg", msg, false, true);
    read(kr, "sig_inline_rsa.asc", msg, false, true);

    var m = openpgp::Message { .. };
    var o = openpgp::ReadOptions { .. };
    o.passphrase.append(passphrase());
    let e = openpgp::read_message(kr, vec("enc_ed.gpg"), m, o);
    tv::check("gpg's OCB packet", e == openpgp::OK && m.integrity == openpgp::INTEGRITY_AEAD && m.aead == openpgp::AEAD_OCB
              && m.cipher == openpgp::CIPHER_AES256 && m.decrypted_with == 7);
    var m1 = openpgp::Message { .. };
    let e1 = openpgp::read_message(kr, vec("sym.gpg"), m1, o);
    tv::check("SEIPD v1", e1 == openpgp::OK && m1.integrity == openpgp::INTEGRITY_MDC && m1.decrypted_with == -1);
    var m2 = openpgp::Message { .. };
    let e2 = openpgp::read_message(kr, vec("enc_bzip2.gpg"), m2, o);
    tv::check("bzip2", e2 == openpgp::OK && m2.compression == openpgp::COMP_BZIP2);
    var m3 = openpgp::Message { .. };
    let e3 = openpgp::read_message(kr, vec("enc_signed.gpg"), m3, o);
    tv::check("signed by", e3 == openpgp::OK && m3.sigs.len == 1 && m3.sigs[0].key == 0 && m3.sigs[0].hash == openpgp::HASH_SHA512);
    var w = openpgp::ReadOptions { .. };
    w.passphrase.append("wrong");
    var m4 = openpgp::Message { .. };
    tv::check_int("sym wrong passphrase", openpgp::read_message(kr, vec("sym.gpg"), m4, w), openpgp::ERR_PASSPHRASE);
    var m5 = openpgp::Message { .. };
    tv::check_int("sym no passphrase", openpgp::read_message(kr, vec("sym.gpg"), m5, openpgp::ReadOptions { .. }),
                  openpgp::ERR_PASSPHRASE);

    var md = openpgp::Message { .. };
    tv::check_int("detached", openpgp::verify_detached(kr, msg, vec("det.sig"), md), openpgp::OK);
    var mr = openpgp::Message { .. };
    tv::check_int("detached rsa", openpgp::verify_detached(kr, msg, vec("det_rsa.asc"), mr), openpgp::OK);
    tv::check("detached rsa by its subkey", mr.sigs[0].key == 5 && mr.sigs[0].pk_algo == openpgp::PK_RSA);
    var mt = openpgp::Message { .. };
    tv::check_int("detached text", openpgp::verify_detached(kr, vec("text.txt"), vec("det_text.asc"), mt), openpgp::OK);
    tv::check("detached text type", mt.sigs[0].sigtype == openpgp::SIG_TEXT);
    // A text signature holds over CRLF line ends too, a binary one does not.
    var crlf: u8[>..] = [];
    openpgp::canonical_text(crlf, vec("text.txt"));
    var mt2 = openpgp::Message { .. };
    tv::check_int("detached text crlf", openpgp::verify_detached(kr, crlf, vec("det_text.asc"), mt2), openpgp::OK);
    var changed = copy(msg);
    changed[0] = 'J';
    var mx = openpgp::Message { .. };
    tv::check_int("detached changed", openpgp::verify_detached(kr, changed, vec("det.sig"), mx), openpgp::ERR_BAD_SIGNATURE);

    var mc = openpgp::Message { .. };
    tv::check_int("cleartext", openpgp::verify_cleartext(kr, vec("clear.asc"), mc), openpgp::OK);
    tv::check_eq("cleartext data", mc.data, msg);
    var mc2 = openpgp::Message { .. };
    tv::check_int("cleartext rsa", openpgp::verify_cleartext(kr, vec("clear_rsa.asc"), mc2), openpgp::OK);
    // gpg strips the trailing white space the text has; the rest is the text.
    tv::check("cleartext rsa data", starts_with(mc2.data, "- a line that starts with a dash\nFrom the start\n"));
    var ctext = vec("clear.asc");
    let at = find(ctext, "Second");
    ctext[at] = 's';
    var mc3 = openpgp::Message { .. };
    tv::check_int("cleartext changed", openpgp::verify_cleartext(kr, ctext, mc3), openpgp::ERR_BAD_SIGNATURE);
}

fn rfc9580() {
    // A.1 and A.2: a bare v4 Ed25519Legacy key and its signature.
    var kr = openpgp::Keyring { .. };
    tv::check_int("A.1 key", openpgp::add_keys(kr, vec("rfc9580_a1_key.asc")), openpgp::OK);
    tv::check("A.1 fingerprint", openpgp::hex(kr.keys[0].fpr)[..] == "C959BDBAFA32A2F89A153B678CFDE12197965A9A");
    var bin: u8[>..] = [];
    let label, e = openpgp::dearmor(vec("rfc9580_a2_sig.asc"), bin);
    let p, ep = openpgp::next_packet(bin, 0);
    let s, es = openpgp::parse_signature(bin[p.body..p.body_end]);
    tv::check("A.2 parses", e == openpgp::OK && es == openpgp::OK && s.created == 1442406293 && s.hash == openpgp::HASH_SHA256);
    tv::check_int("A.2 verifies", openpgp::verify_signature(kr.keys[0], s, "OpenPGP"), openpgp::OK);
    tv::check_int("A.2 other data", openpgp::verify_signature(kr.keys[0], s, "OpenPGQ"), openpgp::ERR_BAD_SIGNATURE);
    // The key has no self-signature, so a message check refuses it.
    var m = openpgp::Message { .. };
    tv::check_int("A.2 key not bound", openpgp::verify_detached(kr, "OpenPGP", vec("rfc9580_a2_sig.asc"), m), openpgp::ERR_KEY);

    // A.3 and A.4: v6.
    var k6 = openpgp::Keyring { .. };
    tv::check_int("A.3 certificate", openpgp::add_keys(k6, vec("rfc9580_a3_cert.asc")), openpgp::OK);
    tv::check("A.3 fingerprints", k6.keys.len == 2
              && openpgp::hex(k6.keys[0].fpr)[..] == "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"
              && openpgp::hex(k6.keys[1].fpr)[..] == "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885");
    tv::check("A.3 v6 Ed25519 and X25519", k6.keys[0].version == 6 && k6.keys[0].algo == openpgp::PK_ED25519
              && k6.keys[1].algo == openpgp::PK_X25519 && k6.keys[0].valid && k6.keys[1].valid);
    tv::check_int("A.4 secret", openpgp::add_keys(k6, vec("rfc9580_a4_secret.asc")), openpgp::OK);
    tv::check("A.4 open", k6.keys[2].has_secret && !k6.keys[2].locked && !k6.keys[3].locked);
    // A.6 and A.7: v6 signatures, cleartext and inline.
    var mc = openpgp::Message { .. };
    tv::check_int("A.6 cleartext", openpgp::verify_cleartext(k6, vec("rfc9580_a6_cleartext.asc"), mc), openpgp::OK);
    tv::check("A.6 text", mc.data[..] == "What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n\n");
    var mi = openpgp::Message { .. };
    tv::check_int("A.7 inline", openpgp::verify(k6, vec("rfc9580_a7_inline.asc"), mi, openpgp::ReadOptions { .. }), openpgp::OK);
    tv::check("A.7 text", mi.data[..] == "What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n");
    // v6 signing and encryption to the v6 key, read back.
    var out: u8[>..] = [];
    var w = openpgp::WriteOptions { .. };
    tv::check_int("v6 sign", openpgp::sign_detached(k6, 2, "v6 data", out, w), openpgp::OK);
    var mv = openpgp::Message { .. };
    tv::check_int("v6 verify", openpgp::verify_detached(k6, "v6 data", out, mv), openpgp::OK);
    out.clear();
    tv::check_int("X25519 encrypt", openpgp::encrypt(k6, [0], "", "to X25519", out, w, 2), openpgp::OK);
    var me = openpgp::Message { .. };
    tv::check_int("X25519 decrypt", openpgp::read_message(k6, out, me, openpgp::ReadOptions { .. }), openpgp::OK);
    tv::check("X25519 data", me.data[..] == "to X25519" && openpgp::signature_status(me) == openpgp::OK && me.decrypted_with == 3);
}

// gpg's P-384 key: its ECDSA signature and ECDH message read, and ours
// (SHA-256 asked for, SHA-384 used, as the curve needs) read back.
fn nist() {
    var kr = openpgp::Keyring { .. };
    tv::check_int("nist key", openpgp::add_keys(kr, vec("nist.sec")), openpgp::OK);
    tv::check("nist keys", kr.keys.len == 2 && kr.keys[0].algo == openpgp::PK_ECDSA && kr.keys[0].curve == openpgp::CURVE_P384
              && kr.keys[1].algo == openpgp::PK_ECDH && kr.keys[1].curve == openpgp::CURVE_P384 && kr.keys[0].valid && kr.keys[1].valid);
    let msg = vec("msg.txt");
    var m = openpgp::Message { .. };
    tv::check_int("nist gpg's ECDSA", openpgp::verify_detached(kr, msg, vec("det_nist.sig"), m), openpgp::OK);
    var me = openpgp::Message { .. };
    let e = openpgp::read_message(kr, vec("enc_nist.gpg"), me, openpgp::ReadOptions { .. });
    tv::check("nist gpg's ECDH", e == openpgp::OK && me.data[..] == msg[..]);
    var sig: u8[>..] = [];
    let w = openpgp::WriteOptions { .. };
    tv::check_int("nist sign", openpgp::sign_detached(kr, 0, msg, sig, w), openpgp::OK);
    var mv = openpgp::Message { .. };
    tv::check_int("nist verify", openpgp::verify_detached(kr, msg, sig, mv), openpgp::OK);
    tv::check("nist hash raised", mv.sigs[0].hash == openpgp::HASH_SHA384);
    var enc: u8[>..] = [];
    tv::check_int("nist encrypt", openpgp::encrypt(kr, [0], "", msg, enc, w, 0), openpgp::OK);
    var md = openpgp::Message { .. };
    let ed = openpgp::read_message(kr, enc, md, openpgp::ReadOptions { .. });
    tv::check("nist decrypt", ed == openpgp::OK && md.data[..] == msg[..] && openpgp::signature_status(md) == openpgp::OK);
}

fn main() {
    var kr = openpgp::Keyring { .. };
    keys(kr);
    messages(kr);
    rfc9580();
    nist();
    tv::done("gpg_vectors");
}
