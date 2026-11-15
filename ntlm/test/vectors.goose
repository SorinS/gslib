// The [MS-NLMP] §4.2.4 NTLMv2 example, byte for byte: NTOWFv2, LMv2,
// NTProofStr and the whole NTLMv2 response, the session base key, the
// encrypted session key, the CHALLENGE and AUTHENTICATE messages, and
// §4.2.4.4's GSS_WrapEx (sealing and signing keys, sealed data,
// signature). Then the same AUTHENTICATE message accepted by the
// acceptor given the spec's CHALLENGE, and the text and time helpers.
import std;
import os;
import gslib from "../..";
import gslib.ntlm;
import gslib.ntlm.crypto;
import gslib.ntlm.messages;
import gslib.ntlm.session;
import gslib.ntlm.server;
import tv;

let CHALLENGE_HEX = "4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00 38 00 00 00 33 82 8a e2 01 23 45 67 89 ab cd ef 00 00 00 00 00 00 00 00 24 00 24 00 44 00 00 00 06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00 65 00 72 00 02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00";

let AUTHENTICATE_HEX = "4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00 6c 00 00 00 54 00 54 00 84 00 00 00 0c 00 0c 00 48 00 00 00 08 00 08 00 54 00 00 00 10 00 10 00 5c 00 00 00 10 00 10 00 d8 00 00 00 35 82 88 e2 05 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 00 69 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00 00 00 00 00 c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e";

let SERVER_CHALLENGE = "0123456789abcdef";
let RANDOM_SESSION_KEY = "55555555555555555555555555555555";
let CLIENT_CHALLENGE = "aaaaaaaaaaaaaaaa";

fn utf16(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    ntlm::utf16le(out, s);
    return out;
}

fn crypto_values() {
    let nth, ok = ntlm::nt_hash(tv::PASSWORD);
    tv::check("nt hash", ok);
    tv::check_hex("NT hash (MD4)", nth, "a4f49c406510bdcab6824ee7c30fd852");
    let key, kok = ntlm::ntowfv2(nth, tv::USER, tv::DOMAIN);
    tv::check("ntowfv2 ok", kok);
    tv::check_hex("4.2.4.1.1 NTOWFv2", key, "0c868a403bfd7a93a3001ef22ef02e3f");
    // Lower-case user: the same key (Uppercase(User)); the domain is as given.
    let key2, k2ok = ntlm::ntowfv2(nth, "user", tv::DOMAIN);
    tv::check("ntowfv2 upper-cases the user", k2ok && key2 == key);
    let key3, k3ok = ntlm::ntowfv2(nth, tv::USER, "DOMAIN");
    tv::check("ntowfv2 keeps the domain's case", k3ok && key3 != key);

    let sc = tv::unhex(SERVER_CHALLENGE);
    let cc = tv::unhex(CLIENT_CHALLENGE);
    let lm = ntlm::lmv2_response(key, sc, cc);
    tv::check_hex("4.2.4.2.1 LMv2 response", lm, "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa");

    var ti: u8[>..] = [];
    ntlm::av_put_name(ti, ntlm::AV_NB_DOMAIN_NAME, "Domain");
    ntlm::av_put_name(ti, ntlm::AV_NB_COMPUTER_NAME, "Server");
    ntlm::av_end(ti);
    var blob: u8[>..] = [];
    ntlm::client_blob(blob, 0, cc, ti);
    let proof = ntlm::nt_proof(key, sc, blob);
    tv::check_hex("4.2.4.2.2 NTProofStr", proof, "68cd0ab851e51c96aabc927bebef6a1c");
    var resp: u8[>..] = [];
    resp.append(proof);
    resp.append(blob);
    tv::check_hex("4.2.4.2.2 NTLMv2 response", resp,
                  "68cd0ab851e51c96aabc927bebef6a1c01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000");
    let sbk = ntlm::session_base_key(key, proof);
    tv::check_hex("4.2.4.1.2 session base key", sbk, "8de40ccadbc14a82f15cb0ad0de95ca3");
    let rsk = tv::unhex(RANDOM_SESSION_KEY);
    let ek = ntlm::rc4k(sbk, rsk);
    tv::check_hex("4.2.4.2.3 encrypted session key", ek, "c5dad2544fc9799094ce1ce90bc9d03e");
    tv::check("RC4K undoes itself", ntlm::rc4k(sbk, ek)[..] == rsk[..]);
}

fn messages() {
    // The CHALLENGE message, read and written.
    let cm = tv::unhex(CHALLENGE_HEX);
    tv::check("challenge is 0x68 bytes", cm.len == 0x68);
    let c, ce = ntlm::parse_challenge(cm);
    tv::check_err("parse challenge", ce, ntlm::OK);
    tv::check("challenge flags", c.flags == 0xe28a8233);
    tv::check_hex("server challenge", c.server_challenge, SERVER_CHALLENGE);
    tv::check("challenge version", c.has_version && tv::hex(c.version)[..] == "060070170000000f");
    var name: u8[>..] = [];
    tv::check("target name", ntlm::utf8_of_utf16le(name, ntlm::field_bytes(cm, c.target_name)) && name[..] == "Server");
    let ti = ntlm::field_bytes(cm, c.target_info);
    let dn, has_dn = ntlm::av_get(ti, ntlm::AV_NB_DOMAIN_NAME);
    var dtext: u8[>..] = [];
    tv::check("MsvAvNbDomainName", has_dn && ntlm::utf8_of_utf16le(dtext, dn) && dtext[..] == "Domain");
    let ts, has_ts = ntlm::av_get(ti, ntlm::AV_TIMESTAMP);
    tv::check("no MsvAvTimestamp in the example", !has_ts);

    var built: u8[>..] = [];
    // The example's version (6.0.6000, revision 15), not ours: written
    // with ours, then the 8 bytes put back to compare.
    ntlm::challenge_message(built, 0xe28a8233, tv::unhex(SERVER_CHALLENGE), utf16("Server"), ti);
    for i in 8 { built[48 + i] = c.version[i]; }
    tv::check_hex("4.2.4.3 CHALLENGE_MESSAGE written", built, tv::hex(cm));

    // The AUTHENTICATE message, written without a MIC as the example is.
    let nth, ok = ntlm::nt_hash(tv::PASSWORD);
    let key, kok = ntlm::ntowfv2(nth, tv::USER, tv::DOMAIN);
    let cc = tv::unhex(CLIENT_CHALLENGE);
    var blob: u8[>..] = [];
    ntlm::client_blob(blob, 0, cc, ti);
    let proof = ntlm::nt_proof(key, c.server_challenge, blob);
    var nt: u8[>..] = [];
    nt.append(proof);
    nt.append(blob);
    let lm = ntlm::lmv2_response(key, c.server_challenge, cc);
    let ek = ntlm::rc4k(ntlm::session_base_key(key, proof), tv::unhex(RANDOM_SESSION_KEY));
    var am: u8[>..] = [];
    ntlm::authenticate_message(am, 0xe2888235, lm, nt, utf16("Domain"), utf16("User"), utf16("COMPUTER"), ek, false);
    let want = tv::unhex(AUTHENTICATE_HEX);
    // Again the example's version in place of ours.
    for i in 8 { am[64 + i] = want[64 + i]; }
    tv::check_hex("4.2.4.3 AUTHENTICATE_MESSAGE written", am, tv::hex(want));

    let a, ae = ntlm::parse_authenticate(want);
    tv::check_err("parse authenticate", ae, ntlm::OK);
    tv::check("authenticate: no MIC field, a version", !a.has_mic && a.has_version);
    tv::check("authenticate flags", a.flags == 0xe2888235);
    var u: u8[>..] = [];
    tv::check("authenticate user", ntlm::utf8_of_utf16le(u, ntlm::field_bytes(want, a.user)) && u[..] == "User");
    tv::check_hex("authenticate key field", ntlm::field_bytes(want, a.key), "c5dad2544fc9799094ce1ce90bc9d03e");
}

// §4.2.4.4: GSS_WrapEx of "Plaintext" (UTF-16LE), sequence 0.
fn wrap_example() {
    let flags: u32 = 0xe28a8233;
    let rsk = tv::unhex(RANDOM_SESSION_KEY);
    tv::check_hex("4.2.4.4 sealing key", ntlm::seal_key(flags, rsk, true), "59f600973cc4960a25480a7c196e4c58");
    tv::check_hex("4.2.4.4 signing key", ntlm::sign_key(rsk, true), "4788dc861b4782f35d43fd98fe1a2d39");
    var s = ntlm::new_session(flags, rsk, true);
    var w: u8[>..] = [];
    let e = ntlm::wrap(s, utf16("Plaintext"), w);
    tv::check_err("wrap", e, ntlm::OK);
    tv::check_hex("4.2.4.4 signature", w[..16], "010000007fb38ec5c55d497600000000");
    tv::check_hex("4.2.4.4 sealed data", w[16..], "54e50165bf1936dc996020c1811b0f06fb5f");
    // The server's side of the same context unwraps it.
    var r = ntlm::new_session(flags, rsk, false);
    var plain: u8[>..] = [];
    tv::check_err("unwrap", ntlm::unwrap(r, w, plain), ntlm::OK);
    tv::check("unwrapped", plain[..] == utf16("Plaintext")[..]);
}

// The acceptor, given the spec's CHALLENGE as its own, takes the spec's
// AUTHENTICATE (a real LMv2, no MIC, time 0: so a skew of 0 is turned
// off for it).
fn accept_example() {
    let cm = tv::unhex(CHALLENGE_HEX);
    let am = tv::unhex(AUTHENTICATE_HEX);
    var a = ntlm::acceptor("Server", "Domain", "", "");
    a.skew = -1;
    tv::check_err("adopt the spec's challenge", ntlm::adopt_challenge(a, "", cm), ntlm::OK);
    var asked: u8[>..] = [];
    let e = ntlm::accept_authenticate(a, am, tv::NOW) { user, domain, h =>
        asked.append(user); asked.push('|'); asked.append(domain);
        let nth, ok = ntlm::nt_hash(tv::PASSWORD);
        for i in 16 { h[i] = nth[i]; }
        user == "User"
    };
    tv::check_err("accept the spec's AUTHENTICATE", e, ntlm::OK);
    tv::check("looked up User|Domain", asked[..] == "User|Domain");
    tv::check("authenticated user", a.user[..] == "User" && a.domain[..] == "Domain" && a.workstation[..] == "COMPUTER");
    tv::check_hex("exported session key", a.session.exported, RANDOM_SESSION_KEY);

    // A wrong password.
    var b = ntlm::acceptor("Server", "Domain", "", "");
    b.skew = -1;
    ntlm::adopt_challenge(b, "", cm);
    let e2 = ntlm::accept_authenticate(b, am, tv::NOW) { user, domain, h =>
        let nth, ok = ntlm::nt_hash("password");
        for i in 16 { h[i] = nth[i]; }
        true
    };
    tv::check_err("wrong password", e2, ntlm::ERR_LOGON);
    // An unknown user: the same error.
    var d = ntlm::acceptor("Server", "Domain", "", "");
    d.skew = -1;
    ntlm::adopt_challenge(d, "", cm);
    let e3 = ntlm::accept_authenticate(d, am, tv::NOW) { user, domain, h => false };
    tv::check_err("unknown user", e3, ntlm::ERR_LOGON);
    // With the clock checked, time 0 (1601) is far outside the skew.
    var t = ntlm::acceptor("Server", "Domain", "", "");
    ntlm::adopt_challenge(t, "", cm);
    let e4 = ntlm::accept_authenticate(t, am, tv::NOW) { user, domain, h =>
        let nth, ok = ntlm::nt_hash(tv::PASSWORD);
        for i in 16 { h[i] = nth[i]; }
        true
    };
    tv::check_err("time 1601 refused", e4, ntlm::ERR_TIMESTAMP);
}

fn text_and_time() {
    var u: u8[>..] = [];
    tv::check("utf16 ascii", ntlm::utf16le(u, "Ab") && tv::hex(u)[..] == "41006200");
    u.clear();
    // U+00E9, U+20AC, U+1F600 (a surrogate pair).
    tv::check("utf16 multi", ntlm::utf16le(u, "\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80") && tv::hex(u)[..] == "e900ac203dd800de");
    var back: u8[>..] = [];
    tv::check("utf16 round trip", ntlm::utf8_of_utf16le(back, u) && back[..] == "\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80");
    var x: u8[>..] = [];
    tv::check("bad utf8 refused", !ntlm::utf16le(x, "\xff"));
    tv::check("overlong refused", !ntlm::utf16le(x, "\xc0\xaf"));
    tv::check("utf8 surrogate refused", !ntlm::utf16le(x, "\xed\xa0\x80"));
    tv::check("truncated refused", !ntlm::utf16le(x, "\xe2\x82"));
    tv::check("lone surrogate refused", !ntlm::utf8_of_utf16le(x, "\x00\xd8"));
    tv::check("odd utf16 refused", !ntlm::utf8_of_utf16le(x, "A"));
    tv::check("filetime", ntlm::filetime(0) == 116444736000000000 && ntlm::filetime_unix(ntlm::filetime(tv::NOW)) == tv::NOW);
    let h, ok = ntlm::parse_nt_hash("A4F49C406510BDCAB6824EE7C30FD852");
    tv::check("parse NT hash", ok && tv::hex(h)[..] == "a4f49c406510bdcab6824ee7c30fd852");
    let h2, ok2 = ntlm::parse_nt_hash("a4f49c406510bdcab6824ee7c30fd85");
    tv::check("short NT hash refused", !ok2);
    let c, ce = ntlm::credentials("EXAMPLE\\alice", "", "pw");
    tv::check("DOMAIN\\user split", ce == ntlm::OK && c.user[..] == "alice" && c.domain[..] == "EXAMPLE");
    let c2, ce2 = ntlm::credentials("alice@example.test", "", "pw");
    tv::check("UPN kept whole", ce2 == ntlm::OK && c2.user[..] == "alice@example.test" && c2.domain.len == 0);
    let c3, ce3 = ntlm::credentials("\xff", "", "pw");
    tv::check_err("user not UTF-8", ce3, ntlm::ERR_ARG);
    var long: u8[>..] = [];
    for i in 300 { long.push('a'); }
    let c4, ce4 = ntlm::credentials(long, "", "pw");
    tv::check_err("user too long: refused, not cut", ce4, ntlm::ERR_ARG);
    // gss_channel_bindings_struct's MD5 (as pyspnego's GssChannelBindings packs it).
    tv::check_hex("bindings hash", ntlm::bindings_hash("tls-server-end-point:abc"), "feb0fffbc725957540b287e8c838dfd9");
}

fn main() {
    crypto_values();
    messages();
    wrap_example();
    accept_example();
    text_and_time();
    tv::done("vectors");
}
