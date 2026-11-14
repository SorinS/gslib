// Messages made here and read back: signatures (inline, detached,
// cleartext; binary and text) by Ed25519 and RSA keys, encryption to
// Curve25519 and RSA keys and to a passphrase, with each compression and
// without, armored and binary, signed and not. Then tampering: a changed
// literal fails its signature, a changed ciphertext its MDC, a changed
// key its self-signature; the wrong key, a locked key and unprotected
// data are refused. And a key made by keygen, exported and read back.
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
let MSG = "Round trip.\nLine two, with trailing spaces   \n- a dash line\n";
let T0: i64 = 1795000000;            // a fixed time for signatures, after the vectors' keys were made

fn vec(name: const u8[:]) -> u8[>..] { tv::read(str(V, name)) }

fn passphrase() -> u8[>..] {
    var p = vec("passphrase.txt");
    while p.len > 0 && p[p.len - 1] == '\n' { p.resize(p.len - 1); }
    return p;
}

fn opts(compression: i64, armored: bool) -> openpgp::WriteOptions {
    var w = openpgp::WriteOptions { .. };
    w.compression = compression;
    w.armored = armored;
    w.created = T0;
    w.filename.append("msg.txt");
    w.mtime = T0;
    w.s2k_coded = 96;                // 65536 octets: quick, for tests
    return w;
}

fn read_back(kr: const openpgp::Keyring&, what: const u8[:], data: const u8[:], want: const u8[:], signed: bool,
             pass: const u8[:] = "") {
    var m = openpgp::Message { .. };
    var o = openpgp::ReadOptions { .. };
    o.passphrase.append(pass);
    let e = openpgp::read_message(kr, data, m, o);
    tv::check_int(str(what, " reads"), e, openpgp::OK);
    tv::check(str(what, " data"), m.data[..] == want);
    tv::check(str(what, " name"), m.filename[..] == "msg.txt" && m.mtime == T0);
    let rc1 = openpgp::signature_status(m);
    tv::check_int(str(what, " signature"), rc1, if signed { openpgp::OK } else { openpgp::ERR_NO_SIGNATURE });
}

fn signing(kr: const openpgp::Keyring&, ed: i64, rsa: i64) {
    for signer in [ed, rsa] {
        let who = if signer == ed { "ed25519" } else { "rsa" };
        for comp in [openpgp::COMP_NONE, openpgp::COMP_ZIP, openpgp::COMP_ZLIB, openpgp::COMP_BZIP2] {
            // RSA is slow: the compressions are the Ed25519 key's to cover.
            if signer == rsa && comp != openpgp::COMP_NONE && comp != openpgp::COMP_ZLIB { continue; }
            for armored in [true, false] {
                var out: u8[>..] = [];
                let w = opts(comp, armored);
                let rc2 = openpgp::sign(kr, signer, MSG, out, w);
                tv::check_int(str(who, " sign ", comp, " ", armored), rc2, openpgp::OK);
                tv::check(str(who, " armored ", armored), openpgp::is_armored(out) == armored);
                read_back(kr, str(who, " inline ", comp, " ", armored), out, MSG, true);
            }
        }
        var w = opts(openpgp::COMP_NONE, true);
        for hash in [openpgp::HASH_SHA256, openpgp::HASH_SHA384, openpgp::HASH_SHA512] {
            if signer == rsa && hash == openpgp::HASH_SHA384 { continue; }
            w.hash = hash;
            var det: u8[>..] = [];
            let rc3 = openpgp::sign_detached(kr, signer, MSG, det, w);
            tv::check_int(str(who, " detached ", hash), rc3, openpgp::OK);
            var m = openpgp::Message { .. };
            let rc4 = openpgp::verify_detached(kr, MSG, det, m);
            tv::check_int(str(who, " detached verifies ", hash), rc4, openpgp::OK);
            tv::check(str(who, " detached hash ", hash), m.sigs[0].hash == hash && m.sigs[0].created == T0);
        }
        w.hash = openpgp::HASH_SHA256;
        w.text = true;
        var tdet: u8[>..] = [];
        let rc5 = openpgp::sign_detached(kr, signer, MSG, tdet, w);
        tv::check_int(str(who, " text detached"), rc5, openpgp::OK);
        var crlf: u8[>..] = [];
        openpgp::canonical_text(crlf, MSG);
        var mt = openpgp::Message { .. };
        let rc6 = openpgp::verify_detached(kr, crlf, tdet, mt);
        tv::check_int(str(who, " text detached over CRLF"), rc6, openpgp::OK);
        var clear: u8[>..] = [];
        let rc7 = openpgp::sign_cleartext(kr, signer, MSG, clear, w);
        tv::check_int(str(who, " cleartext"), rc7, openpgp::OK);
        tv::check(str(who, " cleartext escaped"), find(clear, "\n- - a dash line\n") >= 0);
        var mc = openpgp::Message { .. };
        let rc8 = openpgp::verify_cleartext(kr, clear, mc);
        tv::check_int(str(who, " cleartext verifies"), rc8, openpgp::OK);
        tv::check(str(who, " cleartext text"), mc.data[..] == "Round trip.\nLine two, with trailing spaces\n- a dash line\n");

        // Tampering with the signed literal.
        var inl: u8[>..] = [];
        let wb = opts(openpgp::COMP_NONE, false);
        let e = openpgp::sign(kr, signer, MSG, inl, wb);
        let at = find(inl, "Round trip.");
        inl[at] = 'r';
        var mx = openpgp::Message { .. };
        tv::check_int(str(who, " changed literal"), openpgp::verify(kr, inl, mx, openpgp::ReadOptions { .. }),
                      openpgp::ERR_BAD_SIGNATURE);
        var md = openpgp::Message { .. };
        var det2: u8[>..] = [];
        let e2 = openpgp::sign_detached(kr, signer, MSG, det2, wb);
        tv::check_int(str(who, " detached other data"), openpgp::verify_detached(kr, "Round trip!", det2, md),
                      openpgp::ERR_BAD_SIGNATURE);
    }
}

fn encryption(kr: const openpgp::Keyring&, ed: i64, rsa: i64) {
    let pass = passphrase();
    for comp in [openpgp::COMP_NONE, openpgp::COMP_ZIP, openpgp::COMP_ZLIB, openpgp::COMP_BZIP2] {
        for armored in [true, false] {
            let w = opts(comp, armored);
            var out: u8[>..] = [];
            let rc9 = openpgp::encrypt(kr, [ed], "", MSG, out, w);
            tv::check_int(str("encrypt ", comp, " ", armored), rc9, openpgp::OK);
            read_back(kr, str("cv25519 ", comp, " ", armored), out, MSG, false);
        }
    }
    let w = opts(openpgp::COMP_ZLIB, true);
    var out: u8[>..] = [];
    tv::check_int("encrypt rsa", openpgp::encrypt(kr, [rsa], "", MSG, out, w), openpgp::OK);
    read_back(kr, "rsa", out, MSG, false);
    out.clear();
    tv::check_int("encrypt both, signed", openpgp::encrypt(kr, [ed, rsa], "", MSG, out, w, ed), openpgp::OK);
    read_back(kr, "both signed", out, MSG, true);
    out.clear();
    tv::check_int("encrypt passphrase", openpgp::encrypt(kr, [], pass, MSG, out, w), openpgp::OK);
    var empty = openpgp::Keyring { .. };
    read_back(empty, "passphrase", out, MSG, false, pass);
    out.clear();
    for cipher in [openpgp::CIPHER_AES128, openpgp::CIPHER_AES192, openpgp::CIPHER_CAST5, openpgp::CIPHER_TWOFISH] {
        var wc = opts(openpgp::COMP_NONE, false);
        wc.cipher = cipher;
        out.clear();
        let rc10 = openpgp::encrypt(kr, [ed], pass, MSG, out, wc, rsa);
        tv::check_int(str("cipher ", cipher), rc10, openpgp::OK);
        read_back(kr, str("cipher ", cipher), out, MSG, true);
        var m = openpgp::Message { .. };
        let e = openpgp::read_message(empty, out, m, openpgp::ReadOptions { passphrase: pass });
        tv::check(str("cipher ", cipher, " by passphrase"), e == openpgp::OK && m.data[..] == MSG && m.cipher == cipher);
    }

    // A changed ciphertext: the MDC fails, and nothing is returned.
    var bin: u8[>..] = [];
    let wb = opts(openpgp::COMP_NONE, false);
    let e = openpgp::encrypt(kr, [ed], "", MSG, bin, wb);
    for off in [bin.len - 1, bin.len - 25, bin.len - 40] {
        var bad = copy(bin);
        bad[off] ^= 0x01;
        var m = openpgp::Message { .. };
        tv::check_int(str("changed ciphertext at ", off), openpgp::read_message(kr, bad, m, openpgp::ReadOptions { .. }),
                      openpgp::ERR_INTEGRITY);
        tv::check(str("nothing returned ", off), m.data.len == 0);
    }
    // gpg's OCB packet, changed in its last chunk and its final tag.
    for off in [10, 1] {
        var g = vec("enc_ed.gpg");
        g[g.len - off] ^= 0x80;
        var m = openpgp::Message { .. };
        let rc11 = openpgp::read_message(kr, g, m, openpgp::ReadOptions { .. });
        tv::check_int(str("OCB changed ", off), rc11, openpgp::ERR_INTEGRITY);
    }
    // Truncated: the MDC is gone.
    var m2 = openpgp::Message { .. };
    tv::check("truncated", openpgp::read_message(kr, bin[..bin.len - 10], m2, openpgp::ReadOptions { .. }) != openpgp::OK);

    // To a key not here; to the passphrase without one.
    var only_rsa = openpgp::Keyring { .. };
    let er = openpgp::add_keys(only_rsa, vec("rsa.pub"));
    var m3 = openpgp::Message { .. };
    tv::check_int("no secret key", openpgp::read_message(only_rsa, bin, m3, openpgp::ReadOptions { .. }), openpgp::ERR_NO_KEY);
    var locked = openpgp::Keyring { .. };
    let el = openpgp::add_keys(locked, vec("prot.sec"));
    out.clear();
    let ep = openpgp::encrypt(locked, [0], "", MSG, out, wb);
    var m4 = openpgp::Message { .. };
    tv::check_int("locked key", openpgp::read_message(locked, out, m4, openpgp::ReadOptions { .. }), openpgp::ERR_PASSPHRASE);
    let rn = openpgp::encrypt(kr, [], "", MSG, out, wb);
    tv::check_int("encrypt to nobody", rn, openpgp::ERR_KEY);
    var m7 = openpgp::Message { .. };
    tv::check_int("not encrypted", openpgp::decrypt(kr, vec("sig_inline.gpg"), m7, openpgp::ReadOptions { .. }),
                  openpgp::ERR_NOT_ENCRYPTED);

    // Packet 9 (no MDC): refused unless allowed. Made by hand: an SKESK
    // without an encrypted session key, then OpenPGP CFB with the resync.
    let s2k = openpgp::new_s2k(96);
    let key, ek = openpgp::s2k_key(s2k, pass, 16);
    var sk: u8[>..] = [];
    sk.push(4);
    sk.push(openpgp::CIPHER_AES128 as! u8);
    openpgp::put_s2k(sk, s2k);
    var lit: u8[>..] = [];
    openpgp::put_packet(lit, openpgp::TAG_LITERAL, "b\x00\x00\x00\x00\x00old style");
    var pre = openpgp::random(16);
    pre.push(pre[14]);
    pre.push(pre[15]);
    var zero: u8[16] = [0; 16];
    let ok1 = openpgp::cfb(openpgp::CIPHER_AES128, key, zero, pre, false);
    var rest = copy(lit);
    let ok2 = openpgp::cfb(openpgp::CIPHER_AES128, key, pre[2..18], rest, false);
    var sed: u8[>..] = [];
    openpgp::put_packet(sed, openpgp::TAG_SKESK, sk);
    var body = copy(pre);
    body.append(rest);
    openpgp::put_packet(sed, openpgp::TAG_SED, body);
    var m5 = openpgp::Message { .. };
    tv::check_int("SED refused", openpgp::read_message(empty, sed, m5, openpgp::ReadOptions { passphrase: pass }),
                  openpgp::ERR_UNPROTECTED);
    var m6 = openpgp::Message { .. };
    var allow = openpgp::ReadOptions { allow_unprotected: true };
    allow.passphrase.append(pass);
    let e6 = openpgp::read_message(empty, sed, m6, allow);
    tv::check("SED allowed", e6 == openpgp::OK && m6.data[..] == "old style" && m6.integrity == openpgp::INTEGRITY_NONE);
}

fn generated() {
    var kr = openpgp::Keyring { .. };
    tv::check_int("generate", openpgp::generate_key(kr, "Generated <gen@example.com>", T0 - 1000000), openpgp::OK);
    tv::check("generated keys", kr.keys.len == 2 && kr.keys[0].valid && kr.keys[1].valid && kr.keys[0].created == T0 - 1000000
              && kr.keys[1].flags == openpgp::FLAG_ENCRYPT && kr.uids[0].valid);
    var pub: u8[>..] = [];
    var sec: u8[>..] = [];
    tv::check_int("export public", openpgp::export_public(kr, 0, pub, true), openpgp::OK);
    tv::check_int("export secret", openpgp::export_secret(kr, 0, sec, true, "gen test passphrase", 96), openpgp::OK);
    var kp = openpgp::Keyring { .. };
    tv::check_int("public back", openpgp::add_keys(kp, pub), openpgp::OK);
    tv::check("public same", kp.keys.len == 2 && kp.keys[0].fpr[..] == kr.keys[0].fpr[..] && kp.keys[1].valid && !kp.keys[0].has_secret);
    var ks = openpgp::Keyring { .. };
    tv::check_int("secret back", openpgp::add_keys(ks, sec), openpgp::OK);
    tv::check("secret locked", ks.keys[0].locked && ks.keys[1].locked);
    tv::check_int("secret unlock", openpgp::unlock(ks, 0, "gen test passphrase"), openpgp::OK);
    var out: u8[>..] = [];
    let w = opts(openpgp::COMP_NONE, true);
    tv::check_int("generated encrypt", openpgp::encrypt(kp, [0], "", "for the new key", out, w), openpgp::OK);
    var m = openpgp::Message { .. };
    let e = openpgp::read_message(ks, out, m, openpgp::ReadOptions { .. });
    tv::check("generated decrypt", e == openpgp::OK && m.data[..] == "for the new key");
    out.clear();
    tv::check_int("generated sign", openpgp::sign_detached(ks, 0, "signed", out, w), openpgp::OK);
    var mv = openpgp::Message { .. };
    tv::check_int("generated verify", openpgp::verify_detached(kp, "signed", out, mv), openpgp::OK);

    // A changed user ID no longer has a valid self-signature.
    var bin: u8[>..] = [];
    let ex = openpgp::export_public(kr, 0, bin, false);
    let at = find(bin, "Generated");
    bin[at] = 'g';
    var kc = openpgp::Keyring { .. };
    let ec = openpgp::add_keys(kc, bin);
    tv::check("changed user ID", ec == openpgp::OK && !kc.uids[0].valid && !kc.keys[0].valid);
    var mc = openpgp::Message { .. };
    tv::check_int("changed key refused", openpgp::verify_detached(kc, "signed", out, mc), openpgp::ERR_KEY);
}

fn main() {
    var kr = openpgp::Keyring { .. };
    let e1 = openpgp::add_keys(kr, vec("ed.sec"));
    let e2 = openpgp::add_keys(kr, vec("rsa.sec"));
    tv::check("keys", e1 == openpgp::OK && e2 == openpgp::OK);
    let ed = openpgp::find_key(kr, "test@example.com");
    let rsa = openpgp::find_key(kr, "rsa@example.com");
    tv::check_int("unlock rsa", openpgp::unlock(kr, rsa, passphrase()), openpgp::OK);
    signing(kr, ed, rsa);
    encryption(kr, ed, rsa);
    generated();
    tv::done("roundtrip");
}
