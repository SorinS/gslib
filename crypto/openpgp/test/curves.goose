// The newer curves: Brainpool (ECDSA and ECDH on brainpoolP256r1, P384r1
// and P512r1), Ed448 and X448 (gpg's v5 EdDSALegacy and cv448 keys with
// their v5 signatures; RFC 9580's native Ed448 and X448 on v6 keys), and
// gpg's default post-quantum key (brainpoolP384r1 with ky768_bp256) with
// its ky1024_cv448 and ky1024_bp384 kinds.
//
// gpg's (test/vectors, from scripts/gen_curve_vectors.py): fingerprints as
// gpg lists them, key names, every signature kind verified (and refused
// over changed data), every message decrypted (protected keys unlocked
// first), the public exports identical to gpg's, the secrets exported and
// read back. RFC 9580 has no 448 samples in its Appendix A, so the native
// Ed448 and X448 keys are checked by what they do here: keys of every kind
// are made, exported, read back and used both ways. A v5 signature's
// trailer is checked octet by octet.
import std;
import gslib from "../../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.armor;
import gslib.crypto.openpgp.packet;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.sig;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import gslib.crypto.openpgp.keygen;
import tv;

let V = "vectors/";

fn vec(name: const u8[:]) -> u8[>..] { tv::read(str(V, name)) }

fn passphrase() -> u8[>..] {
    var p = vec("passphrase.txt");
    while p.len > 0 && p[p.len - 1] == '\n' { p.resize(p.len - 1); }
    return p;
}

// gpg's fingerprints, in keys_curves.txt's order.
fn gpg_fingerprints() -> u8[>..] {
    var out: u8[>..] = [];
    for line in split(vec("keys_curves.txt"), '\n') {
        if !starts_with(line, "fpr:") { continue; }
        out.append(split(line, ':')[9]);
        out.push(' ');
    }
    return out;
}

fn load(kr: openpgp::Keyring&, file: const u8[:]) {
    let e = openpgp::add_keys(kr, vec(file));
    tv::check_int(str("add ", file), e, openpgp::OK);
}

fn read_ok(what: const u8[:], kr: const openpgp::Keyring&, msg: const u8[:], want: const u8[:], signed: bool) {
    var m = openpgp::Message { .. };
    let e = openpgp::read_message(kr, msg, m, openpgp::ReadOptions { .. });
    tv::check_int(str(what, ": read"), e, openpgp::OK);
    tv::check(str(what, ": data"), m.data[..] == want && m.encrypted);
    if signed { tv::check_int(str(what, ": signature"), openpgp::signature_status(m), openpgp::OK); }
}

// Each of gpg's keys: (file, its key count, the names gpg gives them, versions).
fn gpg_keys() {
    let all = gpg_fingerprints();
    let fprs = split(all, ' ');
    let files = ["bp256", "bp384", "bp512", "ed448", "ed448_prot", "pqcbp", "pqcbp_prot", "ky1024cv", "ky1024bp"];
    let names = ["brainpoolP256r1 brainpoolP256r1", "brainpoolP384r1 brainpoolP384r1",
                 "brainpoolP512r1 brainpoolP512r1", "ed448 cv448", "ed448 cv448", "brainpoolP384r1 ky768_bp256",
                 "brainpoolP384r1 ky768_bp256", "ed448 ky1024_cv448", "brainpoolP384r1 ky1024_bp384"];
    let versions = ["4 4", "4 4", "4 4", "5 5", "5 5", "4 5", "4 5", "5 5", "4 5"];
    var at = 0;
    for i in files.len {
        let f = files[i];
        var kr = openpgp::Keyring { .. };
        load(kr, str(f, ".pub"));
        tv::check_int(str(f, ": keys"), kr.keys.len, 2);
        if kr.keys.len != 2 { continue; }
        var got: u8[>..] = [];
        var ver: u8[>..] = [];
        for j in 2 {
            let k = kr.keys[j];
            tv::check(str(f, ": fingerprint ", j), openpgp::hex(k.fpr)[..] == fprs[at + j]);
            tv::check(str(f, ": valid ", j), k.valid);
            if j > 0 { got.push(' '); ver.push(' '); }
            got.append(openpgp::key_type_name(k));
            ver.append(str(k.version));
        }
        at += 2;
        tv::check(str(f, ": names ", got), got[..] == names[i]);
        tv::check(str(f, ": versions ", ver), ver[..] == versions[i]);
        tv::check(str(f, ": flags"), kr.keys[0].flags & openpgp::FLAG_SIGN != 0
                  && kr.keys[1].flags == openpgp::FLAG_ENCRYPT);
        let r1 = openpgp::encryption_key(kr, 0);
        tv::check_int(str(f, ": encryption key"), r1, 1);
        // The secret export: unlocked unless protected; the public part is gpg's.
        var ks = openpgp::Keyring { .. };
        load(ks, str(f, ".sec"));
        let prot = ends_with(f, "_prot");
        tv::check(str(f, ": secrets"), ks.keys.len == 2 && ks.keys[0].has_secret && ks.keys[1].has_secret
                  && ks.keys[0].locked == prot && ks.keys[1].locked == prot);
        if prot {
            let r2 = openpgp::unlock(ks, 0, "wrong");
            tv::check_int(str(f, ": wrong passphrase"), r2, openpgp::ERR_PASSPHRASE);
            let r3 = openpgp::unlock(ks, 0, passphrase());
            tv::check_int(str(f, ": unlock"), r3, openpgp::OK);
        }
        var pub: u8[>..] = [];
        let r4 = openpgp::export_public(ks, 0, pub);
        tv::check_int(str(f, ": export public"), r4, openpgp::OK);
        tv::check(str(f, ": export public is gpg's"), pub[..] == vec(str(f, ".pub"))[..]);
        // Exported again, protected, read back and unlocked.
        var sec: u8[>..] = [];
        let r5 = openpgp::export_secret(ks, 0, sec, false, "pw", 96);
        tv::check_int(str(f, ": export secret"), r5, openpgp::OK);
        var k2 = openpgp::Keyring { .. };
        let r6 = openpgp::add_keys(k2, sec);
        tv::check_int(str(f, ": re-read"), r6, openpgp::OK);
        let r7 = openpgp::unlock(k2, 0, "pw");
        tv::check_int(str(f, ": re-read: unlock"), r7, openpgp::OK);
        tv::check(str(f, ": re-read: secrets"), k2.keys.len == 2 && !k2.keys[0].locked && !k2.keys[1].locked
                  && k2.keys[0].scalar[..] == ks.keys[0].scalar[..] && k2.keys[1].scalar[..] == ks.keys[1].scalar[..]);
    }
}

fn gpg_signatures() {
    let msg = vec("msg.txt");
    var changed: u8[>..] = [];
    changed.append(msg);
    changed[0] ^= 1;
    var kr = openpgp::Keyring { .. };
    for f in ["bp256", "bp384", "bp512", "ed448", "pqcbp"] {
        let r8 = openpgp::add_keys(kr, vec(str(f, ".pub")));
        tv::check_int(str("add ", f), r8, openpgp::OK);
    }
    for f in ["bp256", "bp384", "bp512", "ed448", "pqcbp"] {
        var m = openpgp::Message { .. };
        let r9 = openpgp::verify_detached(kr, msg, vec(str("det_", f, ".sig")), m);
        tv::check_int(str(f, ": detached"), r9, openpgp::OK);
        var mc = openpgp::Message { .. };
        let label_139 = str(f, ": detached, changed data");
        tv::check_int(label_139, openpgp::verify_detached(kr, changed, vec(str("det_", f, ".sig")), mc),
                      openpgp::ERR_BAD_SIGNATURE);
        var mi = openpgp::Message { .. };
        let ei = openpgp::verify(kr, vec(str("sig_", f, ".gpg")), mi, openpgp::ReadOptions { .. });
        tv::check_int(str(f, ": inline"), ei, openpgp::OK);
        tv::check(str(f, ": inline data"), mi.data[..] == msg[..]);
        let want_v: i64 = if f == "ed448" { 5 } else { 4 };
        var bin: u8[>..] = [];
        let ed = openpgp::decode_input(vec(str("det_", f, ".sig")), bin);
        let p, ep = openpgp::next_packet(bin, 0);
        let s, es = openpgp::parse_signature(bin[p.body..p.body_end]);
        tv::check(str(f, ": signature version ", s.version), es == openpgp::OK && s.version == want_v);
        // What gpg hashes with: as long as the curve (SHA-512 for Ed448).
        let want_h = if f == "bp256" { openpgp::HASH_SHA256 } else if f == "bp384" || f == "pqcbp" { openpgp::HASH_SHA384 }
                     else { openpgp::HASH_SHA512 };
        tv::check_int(str(f, ": hash"), s.hash, want_h);
    }
    // Ed448 (v5): text mode inline and detached, cleartext; Brainpool cleartext.
    var mt = openpgp::Message { .. };
    tv::check_int("ed448: text inline", openpgp::verify(kr, vec("sigt_ed448.gpg"), mt, openpgp::ReadOptions { .. }), openpgp::OK);
    var md = openpgp::Message { .. };
    tv::check_int("ed448: text detached", openpgp::verify_detached(kr, msg, vec("dett_ed448.asc"), md), openpgp::OK);
    for f in ["ed448", "bp256"] {
        var mc = openpgp::Message { .. };
        let r10 = openpgp::verify_cleartext(kr, vec(str("clear_", f, ".asc")), mc);
        tv::check_int(str(f, ": cleartext"), r10, openpgp::OK);
    }
}

fn gpg_messages() {
    let msg = vec("msg.txt");
    for f in ["bp256", "bp384", "bp512", "ed448", "pqcbp", "ky1024cv", "ky1024bp"] {
        var ks = openpgp::Keyring { .. };
        load(ks, str(f, ".sec"));
        let enc = str("enc_", f, ".gpg");
        read_ok(str("gpg's to ", f), ks, vec(enc), msg, false);
        var m = openpgp::Message { .. };
        let e = openpgp::read_message(ks, vec(enc), m, openpgp::ReadOptions { .. });
        tv::check(str("gpg's to ", f, ": by the subkey, OCB"), e == openpgp::OK && m.decrypted_with == 1
                  && m.aead == openpgp::AEAD_OCB);
        // A key of another kind does not open it.
        let other = if f == "bp256" { "bp384" } else { "bp256" };
        var ko = openpgp::Keyring { .. };
        load(ko, str(other, ".sec"));
        var mo = openpgp::Message { .. };
        let label_nw = str("gpg's to ", f, ": not with ", other);
        tv::check_int(label_nw, openpgp::read_message(ko, vec(enc), mo, openpgp::ReadOptions { .. }),
                      openpgp::ERR_NO_KEY);
    }
    for f in ["ed448_prot", "pqcbp_prot"] {
        var ks = openpgp::Keyring { .. };
        load(ks, str(f, ".sec"));
        var m = openpgp::Message { .. };
        let label_193 = str(f, ": locked");
        tv::check_int(label_193, openpgp::read_message(ks, vec(str("enc_", f, ".asc")), m, openpgp::ReadOptions { .. }),
                      openpgp::ERR_PASSPHRASE);
        let r11 = openpgp::unlock(ks, 0, passphrase());
        tv::check_int(str(f, ": unlock"), r11, openpgp::OK);
        read_ok(str("gpg's to ", f), ks, vec(str("enc_", f, ".asc")), msg, false);
    }
    // To three keys, signed by the Ed448 one: each opens it, the v5
    // signature verifies.
    for f in ["bp256", "ed448", "pqcbp"] {
        var ks = openpgp::Keyring { .. };
        load(ks, str(f, ".sec"));
        let r12 = openpgp::add_keys(ks, vec("ed448.pub"));
        tv::check_int(str("add ed448.pub with ", f), r12, openpgp::OK);
        read_ok(str("gpg's to three, signed, with ", f), ks, vec("enc_curves_signed.gpg"), msg, true);
    }
    // Changed PKESKs: the key wrap fails, or the KEM gives another key.
    var ks = openpgp::Keyring { .. };
    load(ks, "pqcbp.sec");
    var bin: u8[>..] = [];
    let ed = openpgp::decode_input(vec("enc_pqcbp.gpg"), bin);
    for at in [20, 40, 100, 600, 1200] {
        var bad: u8[>..] = [];
        bad.append(bin);
        bad[at] ^= 0x10;
        var mb = openpgp::Message { .. };
        let label_219 = str("ky768_bp256: changed PKESK at ", at);
        tv::check(label_219, openpgp::read_message(ks, bad, mb, openpgp::ReadOptions { .. }) != openpgp::OK);
    }
    var k4 = openpgp::Keyring { .. };
    load(k4, "ed448.sec");
    var b4: u8[>..] = [];
    let e4 = openpgp::decode_input(vec("enc_ed448.gpg"), b4);
    for at in [15, 40, 70] {
        var bad: u8[>..] = [];
        bad.append(b4);
        bad[at] ^= 0x10;
        var mb = openpgp::Message { .. };
        let label_231 = str("cv448: changed PKESK at ", at);
        tv::check(label_231, openpgp::read_message(k4, bad, mb, openpgp::ReadOptions { .. }) != openpgp::OK);
    }
}

// The trailer of a v5 signature, octet by octet: the hashed part, the
// literal packet's header (zeros when detached), 05 FF and an 8-octet
// length of the hashed part alone.
fn v5_trailer() {
    var s = openpgp::Signature { .. };
    s.version = 5;
    s.sigtype = openpgp::SIG_BINARY;
    s.pk_algo = openpgp::PK_EDDSA;
    s.hash = openpgp::HASH_SHA512;
    s.hashed.append("\x05\x02\x00\x00\x00\x01");
    tv::check_eq("v5 trailer, detached", openpgp::sig_trailer(s),
                 tv::unhex("05 00 16 0a 0006 050200000001 000000000000 05ff 000000000000000c"));
    tv::check_eq("v5 trailer, inline", openpgp::sig_trailer(s, openpgp::literal_meta('b', "a.txt", 0x01020304)),
                 tv::unhex("05 00 16 0a 0006 050200000001 62 05 612e747874 01020304 05ff 000000000000000c"));
    s.sigtype = openpgp::SIG_CERT_POSITIVE;
    tv::check_eq("v5 trailer, a certification", openpgp::sig_trailer(s, "ignored"),
                 tv::unhex("05 13 16 0a 0006 050200000001 05ff 000000000000000c"));
    s.version = 4;
    s.sigtype = openpgp::SIG_BINARY;
    tv::check_eq("v4 trailer", openpgp::sig_trailer(s, "ignored"),
                 tv::unhex("04 00 16 0a 0006 050200000001 04ff 0000000c"));
}

// Keys made here of each kind: their names and versions, signatures and
// messages both ways, exported (protected), read back, used again.
fn generated() {
    let msg = "New curves test message.\nA second line.\n";
    let kinds = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "ed448", "ed448-v6", "pqc"];
    let names = ["brainpoolP256r1 brainpoolP256r1", "brainpoolP384r1 brainpoolP384r1",
                 "brainpoolP512r1 brainpoolP512r1", "ed448 cv448", "ed448 cv448", "brainpoolP384r1 ky768_bp256"];
    let versions = ["4 4", "4 4", "4 4", "5 5", "6 6", "4 5"];
    for i in kinds.len {
        let what = kinds[i];
        var kr = openpgp::Keyring { .. };
        let uid = "Curves <curves@example.com>";
        var e = openpgp::OK;
        if i < 3 { e = openpgp::generate_brainpool_key(kr, uid, [256, 384, 512][i], 1794000000); }
        else if i == 3 { e = openpgp::generate_ed448_key(kr, uid, 1794000000); }
        else if i == 4 { e = openpgp::generate_ed448_v6_key(kr, uid, 1794000000); }
        else { e = openpgp::generate_pqc_bp_key(kr, uid, 1794000000); }
        tv::check_int(str(what, ": generate"), e, openpgp::OK);
        if e != openpgp::OK || kr.keys.len != 2 { continue; }
        tv::check(str(what, ": valid"), kr.keys[0].valid && kr.keys[1].valid);
        let got = str(openpgp::key_type_name(kr.keys[0]), " ", openpgp::key_type_name(kr.keys[1]));
        tv::check(str(what, ": names ", got), got[..] == names[i]);
        let ver = str(kr.keys[0].version, " ", kr.keys[1].version);
        tv::check(str(what, ": versions ", ver), ver[..] == versions[i]);
        if i == 4 {
            tv::check("ed448-v6: native algorithms", kr.keys[0].algo == openpgp::PK_ED448 && kr.keys[1].algo == openpgp::PK_X448);
        }
        var w = openpgp::WriteOptions { .. };
        w.hash = openpgp::HASH_SHA256;           // raised where the key needs more
        // Signatures of every kind, verified with the public key alone.
        var pub: u8[>..] = [];
        let r13 = openpgp::export_public(kr, 0, pub, true);
        tv::check_int(str(what, ": export public"), r13, openpgp::OK);
        var kp = openpgp::Keyring { .. };
        let r14 = openpgp::add_keys(kp, pub);
        tv::check_int(str(what, ": public read"), r14, openpgp::OK);
        tv::check(str(what, ": same fingerprints"), kp.keys.len == 2 && kp.keys[0].fpr[..] == kr.keys[0].fpr[..]
                  && kp.keys[1].fpr[..] == kr.keys[1].fpr[..] && kp.keys[0].valid && kp.keys[1].valid);
        var det: u8[>..] = [];
        let r15 = openpgp::sign_detached(kr, 0, msg, det, w);
        tv::check_int(str(what, ": sign detached"), r15, openpgp::OK);
        var m1 = openpgp::Message { .. };
        let r16 = openpgp::verify_detached(kp, msg, det, m1);
        tv::check_int(str(what, ": verify detached"), r16, openpgp::OK);
        let need = if i == 0 { 32 } else if i == 1 || i == 5 { 48 } else { 64 };
        tv::check(str(what, ": hash long enough"), m1.sigs.len == 1 && openpgp::hash_size(m1.sigs[0].hash) >= need);
        var m1b = openpgp::Message { .. };
        let label_301 = str(what, ": changed data refused");
        tv::check_int(label_301, openpgp::verify_detached(kp, "New curves", det, m1b),
                      openpgp::ERR_BAD_SIGNATURE);
        for text in [false, true] {
            var wi = w;
            wi.text = text;
            wi.filename.append("name.txt");
            wi.mtime = 1794000001;
            var inl: u8[>..] = [];
            let r17 = openpgp::sign(kr, 0, msg, inl, wi);
            tv::check_int(str(what, ": sign inline ", text), r17, openpgp::OK);
            var m2 = openpgp::Message { .. };
            let r18 = openpgp::verify(kp, inl, m2, openpgp::ReadOptions { .. });
            tv::check_int(str(what, ": verify inline ", text), r18, openpgp::OK);
            // A v5 signature hashes the literal packet's header too: another
            // name there is another signature (v4 and v6 do not).
            var bin: u8[>..] = [];
            let ed = openpgp::decode_input(inl, bin);
            let at = find(bin[..], "name.txt");
            if at >= 0 { bin[at] = 'N'; }
            var m5 = openpgp::Message { .. };
            let e5 = openpgp::verify(kp, bin, m5, openpgp::ReadOptions { .. });
            tv::check(str(what, ": literal name changed ", text), at >= 0
                      && (if kr.keys[0].version == 5 { e5 == openpgp::ERR_BAD_SIGNATURE } else { e5 == openpgp::OK }));
        }
        var clr: u8[>..] = [];
        let r19 = openpgp::sign_cleartext(kr, 0, msg, clr, w);
        tv::check_int(str(what, ": sign cleartext"), r19, openpgp::OK);
        var m3 = openpgp::Message { .. };
        let r20 = openpgp::verify_cleartext(kp, clr, m3);
        tv::check_int(str(what, ": verify cleartext"), r20, openpgp::OK);
        // Encrypted to the public key (signed), read with the secret.
        var enc: u8[>..] = [];
        let r21 = openpgp::encrypt(kp, [0], "", msg, enc, w);
        tv::check_int(str(what, ": encrypt"), r21, openpgp::OK);
        var enc2: u8[>..] = [];
        let r22 = openpgp::encrypt(kr, [0], "", msg, enc2, w, 0);
        tv::check_int(str(what, ": encrypt, signed"), r22, openpgp::OK);
        read_ok(str(what, ": decrypt"), kr, enc, msg, false);
        read_ok(str(what, ": decrypt, signed"), kr, enc2, msg, true);
        // The secret exported protected, read back, unlocked.
        var sec: u8[>..] = [];
        let r23 = openpgp::export_secret(kr, 0, sec, false, "pw", 96);
        tv::check_int(str(what, ": export secret"), r23, openpgp::OK);
        var ks = openpgp::Keyring { .. };
        let r24 = openpgp::add_keys(ks, sec);
        tv::check_int(str(what, ": secret read"), r24, openpgp::OK);
        tv::check(str(what, ": locked"), ks.keys.len == 2 && ks.keys[0].locked && ks.keys[1].locked);
        let r25 = openpgp::unlock(ks, 0, "nope");
        tv::check_int(str(what, ": wrong passphrase"), r25, openpgp::ERR_PASSPHRASE);
        let r26 = openpgp::unlock(ks, 0, "pw");
        tv::check_int(str(what, ": unlock"), r26, openpgp::OK);
        read_ok(str(what, ": decrypt with the re-read key"), ks, enc, msg, false);
        // Another key of the same kind does not open it.
        var other = openpgp::Keyring { .. };
        var eo = openpgp::OK;
        if i < 3 { eo = openpgp::generate_brainpool_key(other, uid, [256, 384, 512][i]); }
        else if i == 3 { eo = openpgp::generate_ed448_key(other, uid); }
        else if i == 4 { eo = openpgp::generate_ed448_v6_key(other, uid); }
        else { eo = openpgp::generate_pqc_bp_key(other, uid); }
        var mo = openpgp::Message { .. };
        let label_ak = str(what, ": another key");
        tv::check(label_ak, eo == openpgp::OK
                  && openpgp::read_message(other, enc, mo, openpgp::ReadOptions { .. }) != openpgp::OK);
        // gpg's keys verify ours and the other way round only with the right key.
        var m4 = openpgp::Message { .. };
        let label_nb = str(what, ": not by another key");
        tv::check(label_nb, openpgp::verify_detached(other, msg, det, m4) != openpgp::OK);
    }
}

fn main() {
    gpg_keys();
    gpg_signatures();
    gpg_messages();
    v5_trailer();
    generated();
    tv::done("curves");
}
