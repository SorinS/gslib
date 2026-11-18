// Microsoft's SMB 3 vectors (vectors/ms.txt, from the Open Specifications
// blog): the 3.1.1 preauth integrity hash over real NEGOTIATE and
// SESSION_SETUP messages, the 3.0 and 3.1.1 keys, the signatures of final
// SESSION_SETUP responses (AES-128-CMAC), and WRITE and READ messages
// encrypted and decrypted with AES-128-CCM (3.0 and 3.1.1) and
// AES-128-GCM (3.1.1). Then what has no published vector, checked
// against itself and its definition: HMAC-SHA256 and AES-128-GMAC
// signing, AES-256 keys and the 256-bit ciphers, tampering refused.
import std;
import gslib from "../..";
import gslib.smb;
import gslib.smb.crypto;
import gslib.crypto.bignum;
import gslib.crypto.bignum.hmac;
import gslib.crypto.bignum.gcm;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn ms_vectors() {
    var counts: i64[5] = [0; 5];
    for line in split(embed_file("vectors/ms.txt"), '\n') {
        if line.len == 0 || line[0] == '#' { continue; }
        let w = words(line);
        if w[0] == "preauth" {
            var h: u8[64] = [0; 64];
            let prev = unhex(w[1]);
            for i in 64 { h[i] = prev[i]; }
            let msg = unhex(w[2]);
            smb::preauth_update(h, msg);
            check("preauth hash", h[..] == unhex(w[3])[..]);
            counts[0]++;
        } else if w[0] == "kdf30" {
            let k = smb::derive_keys(smb::SMB30, unhex(w[1]), "", smb::AES128_CCM);
            check("3.0 signing key", k.signing[..] == unhex(w[2])[..]);
            if w[3] != "-" {
                check("3.0 encryption key", k.enc[..16] == unhex(w[3])[..] && k.enc_len == 16);
                check("3.0 decryption key", k.dec[..16] == unhex(w[4])[..]);
                check("3.0 application key", k.application[..] == unhex(w[5])[..]);
            }
            counts[1]++;
        } else if w[0] == "kdf311" {
            let k = smb::derive_keys(smb::SMB311, unhex(w[1]), unhex(w[2]), smb::AES128_GCM);
            check("3.1.1 signing key", k.signing[..] == unhex(w[3])[..]);
            if w[4] != "-" {
                check("3.1.1 encryption key", k.enc[..16] == unhex(w[4])[..]);
                check("3.1.1 decryption key", k.dec[..16] == unhex(w[5])[..]);
                check("3.1.1 application key", k.application[..] == unhex(w[6])[..]);
            }
            counts[2]++;
        } else if w[0] == "sign" {
            let key = unhex(w[2]);
            var msg = unhex(w[3]);
            check("CMAC signature", smb::verify(smb::AES_CMAC, key, msg));
            var again = copy(msg);
            for i in 16 { again[48 + i] = 0; }
            smb::sign(smb::AES_CMAC, key, again);
            check("CMAC signed again", again == msg);
            msg[msg.len - 1] ^= 1;
            check("CMAC tampered", !smb::verify(smb::AES_CMAC, key, msg));
            counts[3]++;
        } else if w[0] == "transform" {
            let cipher: u16 = if w[1] == "2" { smb::AES128_GCM } else { smb::AES128_CCM };
            let key = unhex(w[2]);
            let tm = unhex(w[3]);
            let plain = unhex(w[4]);
            let got, ok = smb::decrypt_message(cipher, key, tm);
            check("decrypted", ok && got == plain);
            let again = smb::encrypt_message(cipher, key, tm[20..36], smb::transform_session(tm), plain);
            check("encrypted", again == tm);
            var bad = copy(tm);
            bad[bad.len - 1] ^= 0x40;
            let g2, ok2 = smb::decrypt_message(cipher, key, bad);
            check("tampered ciphertext refused", !ok2 && g2.len == 0);
            var bad2 = copy(tm);
            bad2[44] ^= 1;                                  // the session id is in the AAD
            let g3, ok3 = smb::decrypt_message(cipher, key, bad2);
            check("tampered header refused", !ok3);
            var bad3 = copy(tm);
            bad3[36] ^= 1;                                  // OriginalMessageSize
            let g4, ok4 = smb::decrypt_message(cipher, key, bad3);
            check("wrong size refused", !ok4);
            counts[4]++;
        } else {
            check(line, false);
        }
    }
    print("ms.txt: ", counts[0], " preauth, ", counts[1], " kdf30, ", counts[2], " kdf311, ", counts[3], " sign, ",
          counts[4], " transform");
}

// A NEGOTIATE request header to sign (the vectors' first one).
fn a_message() -> u8[>..] {
    var m: u8[>..] = [];
    var h = smb::header(smb::ECHO);
    h.message_id = 0x0102030405060708;
    h.session_id = 0x100000000025;
    smb::put_header(m, h);
    smb::put16(m, 4);
    smb::put16(m, 0);
    return m;
}

fn hmac_and_gmac() {
    let key = unhex("8765949dfeaee105ce9118b45be988f0");
    // HMAC-SHA256: the first 16 bytes of the HMAC of the message with a
    // zero signature.
    var m = a_message();
    smb::sign(smb::HMAC_SHA256, key, m);
    var z = copy(m);
    for i in 16 { z[48 + i] = 0; }
    let h = bignum::hmac_sha256(key, z);
    check("HMAC-SHA256 signature", m[48..64] == h[..16] && smb::get32(m, 16) & smb::FLAGS_SIGNED != 0);
    check("HMAC-SHA256 verifies", smb::verify(smb::HMAC_SHA256, key, m));
    check("HMAC-SHA256 is not CMAC", !smb::verify(smb::AES_CMAC, key, m));

    // GMAC: GCM's tag over the message with the nonce MessageId || role.
    var g = a_message();
    smb::sign(smb::AES_GMAC, key, g);
    var zg = copy(g);
    for i in 16 { zg[48 + i] = 0; }
    var nonce: u8[12] = [0; 12];
    for i in 8 { nonce[i] = zg[24 + i]; }
    let gc = bignum::gcm_init(key);
    var none: u8[0] = [];
    let t = bignum::gcm_encrypt(gc, nonce, zg, none);
    check("GMAC signature", g[48..64] == t[..]);
    check("GMAC verifies", smb::verify(smb::AES_GMAC, key, g));
    // The same message from the server has another nonce, and so another
    // signature: a request cannot be reflected as a response.
    var r = a_message();
    smb::set32(r, 16, smb::FLAGS_SERVER_TO_REDIR);
    smb::sign(smb::AES_GMAC, key, r);
    check("GMAC: the direction is in the nonce", r[48..64] != g[48..64]);
    var rr = copy(g);
    smb::set32(rr, 16, smb::get32(rr, 16) | smb::FLAGS_SERVER_TO_REDIR);
    check("GMAC: a reflected request fails", !smb::verify(smb::AES_GMAC, key, rr));
    var c = a_message();
    smb::set16(c, 12, smb::CANCEL);
    smb::sign(smb::AES_GMAC, key, c);
    var c2 = copy(c);
    for i in 16 { c2[48 + i] = 0; }
    var n2: u8[12] = [0; 12];
    for i in 8 { n2[i] = c2[24 + i]; }
    n2[8] = 2;
    let t2 = bignum::gcm_encrypt(gc, n2, c2, none);
    check("GMAC: CANCEL's nonce", c[48..64] == t2[..]);
    var unsigned = a_message();
    check("no SIGNED flag: refused", !smb::verify(smb::AES_GMAC, key, unsigned));
}

fn aes256() {
    // A 32-byte session key (Kerberos with AES-256): 3.1.1's AES-256
    // ciphers take 256-bit keys from all of it, the rest from its first 16
    // bytes.
    let gss = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var pre: u8[64] = [0x5a; 64];
    let k = smb::derive_keys(smb::SMB311, gss, pre, smb::AES256_GCM);
    let want_e = smb::kdf(gss, "SMBC2SCipherKey\0", pre, 256);
    let want_d = smb::kdf(gss, "SMBS2CCipherKey\0", pre, 256);
    let want_s = smb::kdf(gss[..16], "SMBSigningKey\0", pre, 128);
    check("AES-256 encryption key", k.enc_len == 32 && k.enc[..] == want_e[..] && k.dec[..] == want_d[..]);
    check("AES-256: the signing key from 16 bytes", k.signing[..] == want_s[..] && k.session[..] == gss[..16]);
    let k128 = smb::derive_keys(smb::SMB311, gss, pre, smb::AES128_GCM);
    let e128 = smb::kdf(gss[..16], "SMBC2SCipherKey\0", pre, 128);
    check("AES-128: 16 bytes of the key", k128.enc_len == 16 && k128.enc[..16] == e128[..]);
    // L is part of the input: a 256-bit key does not begin with the 128-bit one.
    check("L in the KDF", want_e[..16] != e128[..]);
    // A 2.x session signs with the session key itself.
    let k2 = smb::derive_keys(smb::SMB21, gss, "", 0);
    check("2.1: signing key is the session key", k2.signing[..] == gss[..16] && k2.enc_len == 0);

    // Each cipher round-trips, and the other direction's key does not open it.
    let plain = a_message();
    let ciphers: u16[4] = [smb::AES128_CCM, smb::AES128_GCM, smb::AES256_CCM, smb::AES256_GCM];
    for cipher in ciphers {
        let kc = smb::derive_keys(smb::SMB311, gss, pre, cipher);
        let nonce: u8[12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let tm = smb::encrypt_message(cipher, kc.enc[..kc.enc_len], nonce[..smb::nonce_len(cipher)], 0x1234, plain);
        let back, ok = smb::decrypt_message(cipher, kc.enc[..kc.enc_len], tm);
        check(smb::cipher_name(cipher), ok && back == plain && tm.len == plain.len + 52);
        let no, nok = smb::decrypt_message(cipher, kc.dec[..kc.enc_len], tm);
        check("the other direction's key fails", !nok);
        // CCM's nonce is 11 bytes: the 12th is not part of it.
        let n_len = smb::nonce_len(cipher);
        check("nonce length", n_len == (if smb::cipher_is_gcm(cipher) { 12 } else { 11 }));
        var zero = true;
        for x in tm[20 + n_len..36] { if x != 0 { zero = false; } }
        check("nonce zero-padded", zero);
    }
}

fn main() {
    ms_vectors();
    hmac_and_gmac();
    aes256();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
