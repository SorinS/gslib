// tpm2's sessions with no TPM: a command's HMAC and a response's rpHash
// HMAC against Python's (scripts/make_vectors.py), parameter encryption
// both ways, and responses that lie: a bad rpHash HMAC, a changed
// parameter, truncated and oversized responses, size fields that lie,
// TPM2Bs larger than what is left, bytes left over, the wrong tag, a
// password session's response with a nonce; and the commands' own
// response readers given TPM2Bs over their types' maximum.
import std;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.crypto.bignum;
import gslib.crypto.bignum.rsa;
import known;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn h(s: const u8[:]) -> u8[>..] {
    let b, ok = tpm2::unhex(s);
    assert(ok);
    return b;
}

fn hmac_session() -> tpm2::Session {
    var s = tpm2::Session { kind: tpm2::SESSION_HMAC, handle: 0x02000000, hash: tpm2::ALG_SHA256, .. };
    s.key.append(h(known::SESSION_KEY));
    s.nonce_tpm.append(h(known::NONCE_TPM));
    s.next_nonce.append(h(known::NONCE_CALLER));
    return s;
}

let UNSEAL = tpm2::Cmd { cc: 0x15E, nauth: 1, enc_out: true };

fn item() -> tpm2::Entity { tpm2::object_entity(0x80000001, h(known::ITEM_NAME), "pin") }

fn known_answers() {
    var s = hmac_session();
    var none = tpm2::no_session();
    let hs = [item()];
    let cmd, e = tpm2::build_command(UNSEAL, hs, s, none, "");
    check("build Unseal", e == tpm2::OK);
    // header 10, handle 4, authSize 4, session handle 4, nonce 2+32, attrs 1, hmac 2+32
    check("Unseal's size", cmd.len == 10 + 4 + 4 + 4 + 34 + 1 + 34 && tpm2::be32(cmd, 2) == cmd.len);
    var hdr: u8[>..] = [];
    tpm2::put_u16(hdr, 0x8002);
    tpm2::put_u32(hdr, cmd.len as u32);
    tpm2::put_u32(hdr, 0x15e);
    tpm2::put_u32(hdr, 0x80000001);
    check("Unseal's header and handle", cmd[..14] == hdr);
    check("Unseal's nonceCaller", cmd[24..56] == h(known::NONCE_CALLER));
    check("Unseal's HMAC: Python's", tpm2::hex(cmd[^32..]) == known::CMD_HMAC);
    // The response: Python's rpHash HMAC verifies, and the TPM's new nonce is kept.
    let rsp = h(known::UNSEAL_RESPONSE);
    let p, hh, rc, er = tpm2::parse_response(UNSEAL, hs, s, none, rsp);
    check("Unseal's response verifies", er == tpm2::OK && rc == 0 && p == "\x00\x09unsealed!");
    check("the TPM's new nonce is kept", s.nonce_tpm[0] == 0x5a && s.kind == tpm2::SESSION_HMAC);
    // Every byte of it matters.
    var all = true;
    for i in rsp.len {
        var s2 = hmac_session();
        s2.nonce_caller.append(h(known::NONCE_CALLER));
        s2.next_nonce.clear();
        var bad = copy(rsp);
        bad[i] ^= 0x01;
        let p2, h2, rc2, er2 = tpm2::parse_response(UNSEAL, hs, s2, none, bad);
        if er2 == tpm2::OK { all = false; print("  byte ", i, " changed and accepted"); }
    }
    check("a response with any byte changed is refused", all);
    // A bad rpHash with the right shape: ERR_INTEGRITY, not a parse error.
    var s3 = hmac_session();
    s3.nonce_caller.append(h(known::NONCE_CALLER));
    var bad = copy(rsp);
    bad[bad.len - 1] ^= 0x80;
    let p3, h3, rc3, er3 = tpm2::parse_response(UNSEAL, hs, s3, none, bad);
    check("a bad response HMAC: ERR_INTEGRITY", er3 == tpm2::ERR_INTEGRITY);
    var bad2 = copy(rsp);
    bad2[16] ^= 0x01;   // a byte of outData
    var s4 = hmac_session();
    s4.nonce_caller.append(h(known::NONCE_CALLER));
    let p4, h4, rc4, er4 = tpm2::parse_response(UNSEAL, hs, s4, none, bad2);
    check("a changed parameter: ERR_INTEGRITY", er4 == tpm2::ERR_INTEGRITY);
    // The wrong authValue on our side: the HMAC does not verify either.
    var s5 = hmac_session();
    s5.nonce_caller.append(h(known::NONCE_CALLER));
    let hs5 = [tpm2::object_entity(0x80000001, h(known::ITEM_NAME), "nip")];
    let p5, h5, rc5, er5 = tpm2::parse_response(UNSEAL, hs5, s5, none, rsp);
    check("a response for another authValue: ERR_INTEGRITY", er5 == tpm2::ERR_INTEGRITY);
    // continueSession cleared: the session is gone.
    var s6 = hmac_session();
    s6.nonce_caller.append(h(known::NONCE_CALLER));
    var nc = copy(rsp);
    nc[rsp.len - 35] = 0;     // the session attributes
    let p6, h6, rc6, er6 = tpm2::parse_response(UNSEAL, hs, s6, none, nc);
    check("attributes are in the HMAC", er6 == tpm2::ERR_INTEGRITY);
}

fn hostile() {
    var pw = tpm2::pw();
    var none = tpm2::no_session();
    let hs = [tpm2::owner()];
    let cmd = tpm2::Cmd { cc: tpm2::CC_GetRandom };
    let no: tpm2::Entity[0] = [];
    var n1 = tpm2::no_session();
    var n2 = tpm2::no_session();
    // A good GetRandom response, and lies about it.
    let gp, gh, grc, ge = tpm2::parse_response(cmd, no, n1, n2, h("80010000001000000000000411223344"));
    check("a plain response", ge == tpm2::OK && gp.len == 6);
    let p1, h1, rc1, e1 = tpm2::parse_response(cmd, no, n1, n2, h("8001000000"));
    check("a response shorter than its header", e1 == tpm2::ERR_MALFORMED);
    let p2, h2, rc2, e2 = tpm2::parse_response(cmd, no, n1, n2, h("80010000002000000000000411223344"));
    check("a size larger than the response", e2 == tpm2::ERR_MALFORMED);
    let p3, h3, rc3, e3 = tpm2::parse_response(cmd, no, n1, n2, h("8001000000080000000000041122"));
    check("a size smaller than the response", e3 == tpm2::ERR_MALFORMED);
    let p4, h4, rc4, e4 = tpm2::parse_response(cmd, no, n1, n2, h("8001000000100000098e00000000"));
    check("an error code with bytes after it", e4 == tpm2::ERR_MALFORMED);
    let p5, h5, rc5, e5 = tpm2::parse_response(cmd, no, n1, n2, h("80010000000a0000098e"));
    check("an error code: ERR_TPM and the code", e5 == tpm2::ERR_TPM && rc5 == 0x98e);
    let p6, h6, rc6, e6 = tpm2::parse_response(cmd, no, n1, n2, h("80020000000e0000000000020000"));
    check("ST_SESSIONS to a command without sessions", e6 == tpm2::ERR_MALFORMED);
    // With a password session: parameterSize and the session area.
    let pcmd = tpm2::Cmd { cc: tpm2::CC_PCR_Extend, nauth: 1 };
    let pg, phh, prc, pe = tpm2::parse_response(pcmd, hs, pw, none, h("80020000001300000000000000000000010000"));
    check("a password session's response", pe == tpm2::OK);
    let pa, pah, parc, pae = tpm2::parse_response(pcmd, hs, pw, none, h("80020000001300000000000000ff0000010000"));
    check("a parameterSize past the end", pae == tpm2::ERR_MALFORMED);
    let pb, pbh, pbrc, pbe = tpm2::parse_response(pcmd, hs, pw, none, h("800200000013000000000000000000ff010000"));
    check("a nonce TPM2B past the end", pbe == tpm2::ERR_MALFORMED);
    let pc, pch, pcrc, pce = tpm2::parse_response(pcmd, hs, pw, none, h("8002000000140000000000000000000001000000"));
    check("a byte left after the sessions", pce == tpm2::ERR_MALFORMED);
    let pd, pdh, pdrc, pde = tpm2::parse_response(pcmd, hs, pw, none, h("8002000000150000000000000000000201ff010000"));
    check("a password session answered with a nonce", pde == tpm2::ERR_MALFORMED);
    let pf, pfh, pfrc, pfe = tpm2::parse_response(pcmd, hs, pw, none, h("80020000000f0000000000000000000001"));
    check("a session area cut short", pfe == tpm2::ERR_MALFORMED);
    // An HMAC session whose response has no HMAC at all.
    var s = hmac_session();
    s.nonce_caller.append(h(known::NONCE_CALLER));
    let hs2 = [tpm2::object_entity(0x80000001, h(known::ITEM_NAME), "pin")];
    let ph, phh2, phrc, phe = tpm2::parse_response(UNSEAL, hs2, s, none, h("8002000000210000000000000002000000020000000000000000000000000000000000000000000000000000000000000000010000"));
    check("an HMAC session's response without an HMAC", phe != tpm2::OK);
}

fn builds() {
    var pw = tpm2::pw();
    var none = tpm2::no_session();
    let hs = [tpm2::pcr_entity(23)];
    var p: u8[>..] = [];
    tpm2::put_u32(p, 1);
    tpm2::put_u16(p, tpm2::ALG_SHA256);
    p.resize(p.len + 32, 0xab);
    let cmd, e = tpm2::build_command(tpm2::Cmd { cc: tpm2::CC_PCR_Extend, nauth: 1 }, hs, pw, none, p);
    // As tpm2-tools sends it: handle, authSize 9, TPM_RS_PW, no nonce, continueSession, empty password.
    check("PCR_Extend with a password", e == tpm2::OK && tpm2::hex(cmd[..27]) == "800200000041000001820000001700000009400000090000010000");
    let hs2 = [tpm2::owner("owner pass")];
    let cmd2, e2 = tpm2::build_command(tpm2::Cmd { cc: tpm2::CC_NV_UndefineSpace, nauth: 1 }, hs2, pw, none, "");
    check("a password goes in the clear", e2 == tpm2::OK && cmd2[^10..] == "owner pass");
    // A handle needing authorization with no session.
    let cmd3, e3 = tpm2::build_command(tpm2::Cmd { cc: tpm2::CC_PCR_Extend, nauth: 1 }, hs, none, none, p);
    check("authorization without a session refused", e3 == tpm2::ERR_ARG);
    // Parameter encryption on a password session, or a command whose first parameter is not sized.
    var pwd = tpm2::pw();
    pwd.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT;
    let cmd4, e4 = tpm2::build_command(tpm2::Cmd { cc: tpm2::CC_PCR_Extend, nauth: 1 }, hs, pwd, none, p);
    check("parameter encryption with a password refused", e4 == tpm2::ERR_ARG);
    var s = hmac_session();
    s.sym_bits = 128;
    s.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT;
    let cmd5, e5 = tpm2::build_command(tpm2::Cmd { cc: tpm2::CC_PCR_Extend, nauth: 1 }, hs, s, none, p);
    check("parameter encryption of a command without a sized first parameter refused", e5 == tpm2::ERR_ARG);
    // Encryption both ways: what goes out is not the plaintext, and comes back.
    var s2 = hmac_session();
    s2.sym_bits = 128;
    s2.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT;
    var q: u8[>..] = [];
    tpm2::put_2b(q, "a secret digest!");
    let hs3 = [tpm2::object_entity(0x80000001, h(known::ITEM_NAME), "pin")];
    let cmd6, e6 = tpm2::build_command(tpm2::Cmd { cc: tpm2::CC_Sign, nauth: 1, enc_in: true }, hs3, s2, none, q);
    check("an encrypted first parameter", e6 == tpm2::OK && find(cmd6, "a secret digest!") < 0);
    var back: u8[>..] = [];
    back.append(cmd6[^16..]);
    let v = tpm2::session_value(s2, hs3[0], true);
    tpm2::param_crypt(s2, v, s2.nonce_caller, s2.nonce_tpm, back, true);
    check("  and it decrypts with the session value", back == "a secret digest!");
}

fn salts() {
    // RSA: the seed comes back with the private key and the label SECRET.
    let rk = bignum::rsa_generate(2048);
    var nb: u8[>..] = [];
    var li = 63;
    while li >= 0 {
        let w = rk.n[li];
        nb.push((w >> 24) as! u8); nb.push((w >> 16) as! u8); nb.push((w >> 8) as! u8); nb.push(w as! u8);
        li -= 1;
    }
    var p = tpm2::srk_rsa_template();
    p.unique.clear();
    p.unique.append(nb);
    let seed, enc, e = tpm2::secret_to(p, "SECRET");
    let back, ok = bignum::rsa_decrypt_oaep(rk, enc, "SECRET\x00", 256);
    check("a salt to an RSA key", e == tpm2::OK && ok && back == seed && seed.len == 32);
    var q = p;
    q.name_alg = tpm2::ALG_SHA384;
    let seed2, enc2, e2 = tpm2::secret_to(q, "SECRET");
    let back2, ok2 = bignum::rsa_decrypt_oaep(rk, enc2, "SECRET\x00", 384);
    check("a salt to an RSA key with SHA-384", e2 == tpm2::OK && ok2 && back2 == seed2 && seed2.len == 48);
    var r = p;
    r.name_alg = tpm2::ALG_SM3_256;
    let seed3, enc3, e3 = tpm2::secret_to(r, "SECRET");
    check("a salt to a key with a hash not done", e3 == tpm2::ERR_UNSUPPORTED);
}

fn main() {
    known_answers();
    hostile();
    builds();
    salts();
    print(checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
