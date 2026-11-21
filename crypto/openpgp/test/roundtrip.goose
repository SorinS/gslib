// Messages made here and read back: signatures (inline, detached,
// cleartext; binary and text) by Ed25519 and RSA keys, encryption to
// Curve25519 and RSA keys and to a passphrase, with each compression and
// without, armored and binary, signed and not. Then tampering: a changed
// literal fails its signature, a changed ciphertext its MDC, a changed
// key its self-signature; the wrong key, a locked key and unprotected
// data are refused. And a key made by keygen, exported and read back,
// and decompression bombs refused.
import std;
import os;
import gslib from "../../..";
import gslib.compress;
import gslib.compress.deflate;
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
        let label_109 = str(who, " changed literal");
        tv::check_int(label_109, openpgp::verify(kr, inl, mx, openpgp::ReadOptions { .. }),
                      openpgp::ERR_BAD_SIGNATURE);
        var md = openpgp::Message { .. };
        var det2: u8[>..] = [];
        let e2 = openpgp::sign_detached(kr, signer, MSG, det2, wb);
        let label_115 = str(who, " detached other data");
        tv::check_int(label_115, openpgp::verify_detached(kr, "Round trip!", det2, md),
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
        let label_162 = str("changed ciphertext at ", off);
        tv::check_int(label_162, openpgp::read_message(kr, bad, m, openpgp::ReadOptions { .. }),
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

// What the review found, kept found.
fn review() {
    var kr = openpgp::Keyring { .. };
    tv::check_int("review key", openpgp::generate_key(kr, "Gen <gen@example.com>", T0 - 1000000), openpgp::OK);
    var pub: u8[>..] = [];
    let ep = openpgp::export_public(kr, 0, pub, false);
    var sig: u8[>..] = [];
    let w = opts(openpgp::COMP_NONE, false);
    let es = openpgp::sign_detached(kr, 0, "doc", sig, w);
    // A key revocation certificate (as gpg --gen-revoke makes one).
    var hd: u8[>..] = [];
    openpgp::put_key_hash(hd, kr.keys[0]);
    var rev: u8[>..] = [];
    let er = openpgp::make_signature(kr.keys[0], openpgp::SigParams { sigtype: openpgp::SIG_KEY_REVOCATION, created: T0 + 10, .. }, hd, rev);
    tv::check("review setup", ep == openpgp::OK && es == openpgp::OK && er == openpgp::OK);

    // The key again with its revocation merges into the copy there.
    var ka = openpgp::Keyring { .. };
    let ea = openpgp::add_keys(ka, pub);
    var m = openpgp::Message { .. };
    tv::check_int("verify before revocation", openpgp::verify_detached(ka, "doc", sig, m), openpgp::OK);
    // The revocation goes after the key packet, as gpg exports it.
    let pk0, epk = openpgp::next_packet(pub, 0);
    var again: u8[>..] = [];
    again.append(pub[..pk0.end]);
    again.append(rev);
    again.append(pub[pk0.end..]);
    tv::check_int("re-import revoked", openpgp::add_keys(ka, again), openpgp::OK);
    tv::check("merged, revoked", ka.keys.len == 2 && ka.uids.len == 1 && ka.keys[0].revoked);
    tv::check_int("verify after revocation", openpgp::verify_detached(ka, "doc", sig, m), openpgp::ERR_REVOKED);
    var out: u8[>..] = [];
    let ex = openpgp::export_public(ka, 0, out, false);
    var kb = openpgp::Keyring { .. };
    tv::check("revocation exported", ex == openpgp::OK && openpgp::add_keys(kb, out) == openpgp::OK && kb.keys[0].revoked);
    tv::check("exported once", out.len == pub.len + rev.len);
    tv::check("exported as gpg orders it", out[..pk0.end + rev.len] == again[..pk0.end + rev.len]);
    // A revocation certificate on its own.
    var kc = openpgp::Keyring { .. };
    let ec = openpgp::add_keys(kc, pub);
    tv::check_int("revocation alone", openpgp::add_keys(kc, rev), openpgp::OK);
    tv::check_int("verify, revoked alone", openpgp::verify_detached(kc, "doc", sig, m), openpgp::ERR_REVOKED);
    var kd = openpgp::Keyring { .. };
    tv::check_int("revocation, no key", openpgp::add_keys(kd, rev), openpgp::ERR_NO_KEY);
    // The secret merges into the public copy.
    var sec: u8[>..] = [];
    let ex2 = openpgp::export_secret(kr, 0, sec, false);
    var ke = openpgp::Keyring { .. };
    let ee1 = openpgp::add_keys(ke, pub);
    let ee2 = openpgp::add_keys(ke, sec);
    tv::check("secret merged", ex2 == openpgp::OK && ee2 == openpgp::OK && ke.keys.len == 2 && ke.keys[0].has_secret
              && ke.keys[1].has_secret && !ke.keys[1].locked);

    // A Message used again holds nothing of the one before.
    var enc: u8[>..] = [];
    let ee = openpgp::encrypt(kr, [0], "", "not signed", enc, w);
    var signed: u8[>..] = [];
    let es2 = openpgp::sign(kr, 0, "signed", signed, w);
    var mm = openpgp::Message { .. };
    tv::check_int("reuse: signed", openpgp::verify(kr, signed, mm, openpgp::ReadOptions { .. }), openpgp::OK);
    tv::check_int("reuse: not signed", openpgp::verify(kr, enc, mm, openpgp::ReadOptions { .. }), openpgp::ERR_NO_SIGNATURE);
    tv::check("reuse: fresh", mm.sigs.len == 0 && mm.data[..] == "not signed" && mm.encrypted);
    tv::check_int("reuse: detached", openpgp::verify_detached(kr, "doc", sig, mm), openpgp::OK);
    tv::check("reuse: detached fresh", mm.sigs.len == 1 && mm.data[..] == "doc" && !mm.encrypted);

    // A signature's own expiry counts by the clock when now is 0.
    let idx, eidx = openpgp::resolve_signer(kr, 0);
    var xs: u8[>..] = [];
    let ex3 = openpgp::make_signature(kr.keys[idx], openpgp::SigParams { created: T0 - 900000, expires: 60, .. }, "data", xs);
    tv::check_int("expired signature", openpgp::verify_detached(kr, "data", xs, m), openpgp::ERR_EXPIRED);
    tv::check_int("expired, before", openpgp::verify_detached(kr, "data", xs, m, T0 - 900000 + 30), openpgp::OK);

    // find_key: user IDs without a self-signature do not count; an email
    // address is matched whole.
    var bin: u8[>..] = [];
    bin.append(pub[..pk0.end]);
    openpgp::put_packet(bin, openpgp::TAG_USER_ID, "Bob <bob@example.com>");
    bin.append(pub[pk0.end..]);
    var kf = openpgp::Keyring { .. };
    let ef = openpgp::add_keys(kf, bin);
    tv::check("unsigned user ID read", ef == openpgp::OK && kf.uids.len == 2 && !kf.uids[0].valid && kf.uids[1].valid);
    tv::check_int("unsigned user ID not found", openpgp::find_key(kf, "bob@example.com"), -1);
    tv::check_int("email found", openpgp::find_key(kf, "GEN@example.com"), 0);
    tv::check_int("email part not found", openpgp::find_key(kf, "en@example.com"), -1);
    tv::check_int("name found", openpgp::find_key(kf, "gen <"), 0);

    // Session key packets: stopped at the first that opens the data, and
    // no more than MAX_KEY_TRIES key operations for one message.
    var plain: u8[>..] = [];
    let ep2 = openpgp::encrypt(kr, [0], "", "hidden", plain, w);
    let p0, e0 = openpgp::next_packet(plain, 0);
    for i in 1..9 { plain[p0.body + i] = 0; }      // a wildcard key ID
    var junk: u8[>..] = [];
    junk.push(3);
    for i in 8 { junk.push(0); }
    junk.push(kr.keys[1].algo as! u8);
    junk.append("\x00\x08\x01\x01");
    var many: u8[>..] = [];
    many.append(plain[..p0.end]);
    for i in 20 { openpgp::put_packet(many, openpgp::TAG_PKESK, junk); }
    many.append(plain[p0.end..]);
    var mw = openpgp::Message { .. };
    tv::check_int("wildcard first", openpgp::read_message(kr, many, mw, openpgp::ReadOptions { .. }), openpgp::OK);
    tv::check("wildcard data", mw.data[..] == "hidden");
    var flood: u8[>..] = [];
    for i in 20 { openpgp::put_packet(flood, openpgp::TAG_PKESK, junk); }
    flood.append(plain);
    tv::check_int("wildcards capped", openpgp::read_message(kr, flood, mw, openpgp::ReadOptions { .. }), openpgp::ERR_LIMIT);
    // RFC 9580 §5.1: a v3 PKESK does not open SEIPD v2.
    var v2: u8[>..] = [];
    v2.append(plain);
    let p1, e1 = openpgp::next_packet(v2, p0.end);
    v2[p1.body] = 2;
    tv::check_int("v3 PKESK, SEIPD v2", openpgp::read_message(kr, v2, mw, openpgp::ReadOptions { .. }), openpgp::ERR_MALFORMED);

    // A v6 signature by SHA-1 is refused.
    var b6: u8[>..] = [];
    b6.append("\x06\x00\x1b\x02\x00\x00\x00\x06\x05\x02\x6a\xfd\x5b\x00\x00\x00\x00\x00\x12\x34\x00");
    for i in 64 { b6.push(0); }
    let s6, e6 = openpgp::parse_signature(b6);
    tv::check_int("v6 SHA-1 signature", e6, openpgp::ERR_UNSUPPORTED);

    // Argon2: no more work than the RFC's first choice.
    var a2: u8[>..] = [];
    a2.push(4);
    for i in 16 { a2.push(7); }
    a2.append("\x01\x04\x15");
    let sa, na, ea2 = openpgp::read_s2k(a2, 0);
    a2[17] = 3;
    a2[19] = 16;
    let sb, nb, eb = openpgp::read_s2k(a2, 0);
    a2[17] = 64;
    a2[19] = 21;
    let sc, nc, ecc = openpgp::read_s2k(a2, 0);
    a2[17] = 1;
    a2[18] = 64;
    let sd, nd, ed = openpgp::read_s2k(a2, 0);
    tv::check("argon2 limits", ea2 == openpgp::OK && eb == openpgp::OK && ecc == openpgp::ERR_LIMIT && ed != openpgp::OK);

    // Cleartext: a CR within a line, and a last empty line, read as signed.
    var ct: u8[>..] = [];
    let ecs = openpgp::sign_cleartext(kr, 0, "a\rb  \nc\n\n", ct, w);
    var mc = openpgp::Message { .. };
    tv::check_int("cleartext CR", openpgp::verify_cleartext(kr, ct, mc), openpgp::OK);
    tv::check("cleartext CR text", ecs == openpgp::OK && mc.data[..] == "a\rb\nc\n\n");
}

// A Compressed Data packet of the given algorithm around inner.
fn compressed(algo: i64, inner: const u8[:]) -> u8[>..] {
    var body: u8[>..] = [];
    body.push(algo as! u8);
    if algo == openpgp::COMP_NONE { body.append(inner); } else { compress::deflate_encode(inner, body); }
    var out: u8[>..] = [];
    openpgp::put_packet(out, openpgp::TAG_COMPRESSED, body);
    return out;
}

// Decompression bombs (scripts/gen_bombs.py): 1000 MiB of zeros in two
// ZIP layers and in one BZip2 layer stop at ReadOptions.max_size's
// default with ERR_LIMIT and nothing read. The limit is one for all the
// layers together; a literal not compressed is not held to it.
fn bombs() {
    var kr = openpgp::Keyring { .. };
    let t0 = clock_ns();
    var m = openpgp::Message { .. };
    tv::check_int("zip bomb", openpgp::read_message(kr, vec("bomb_zip.gpg"), m, openpgp::ReadOptions { .. }), openpgp::ERR_LIMIT);
    tv::check_int("zip bomb data", m.data.len, 0);
    var mb = openpgp::Message { .. };
    tv::check_int("bzip2 bomb", openpgp::read_message(kr, vec("bomb_bzip2.gpg"), mb, openpgp::ReadOptions { .. }), openpgp::ERR_LIMIT);
    // 32 MiB of each, not 1000: well under a second built, a few with --debug.
    tv::check("bombs stop early", clock_ns() - t0 < 30 * 1000000000);

    // A literal of 400 KiB inside two Compressed Data packets that only
    // store (algorithm 0) inside one that deflates: each layer is under
    // 1 MiB, the three together over it.
    var zeros: u8[>..] = [];
    zeros.resize(400 << 10, 0);
    var lit: u8[>..] = [];
    lit.push('b');                   // binary, no name, date 0
    for i in 5 { lit.push(0); }
    lit.append(zeros);
    var msg: u8[>..] = [];
    openpgp::put_packet(msg, openpgp::TAG_LITERAL, lit);
    let nested = compressed(openpgp::COMP_ZIP, compressed(openpgp::COMP_NONE, compressed(openpgp::COMP_NONE, msg)));
    var o = openpgp::ReadOptions { .. };
    o.max_size = 1 << 20;
    var m1 = openpgp::Message { .. };
    tv::check_int("one budget for the layers", openpgp::read_message(kr, nested, m1, o), openpgp::ERR_LIMIT);
    o.max_size = 2 << 20;
    var m2 = openpgp::Message { .. };
    tv::check_int("layers within the budget", openpgp::read_message(kr, nested, m2, o), openpgp::OK);
    tv::check("layers within the budget data", m2.data[..] == zeros[..]);
    // The literal alone, over the limit but not compressed.
    o.max_size = 100 << 10;
    var m3 = openpgp::Message { .. };
    tv::check_int("literal over max_size", openpgp::read_message(kr, msg, m3, o), openpgp::OK);
    tv::check_int("literal over max_size data", m3.data.len, zeros.len);
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
    review();
    bombs();
    tv::done("roundtrip");
}
