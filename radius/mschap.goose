// radius.mschap: MS-CHAPv2 (RFC 2759): the challenge hash, the NT
// response with DES under three keys from the NT hash, the authenticator
// response ("S=" and 40 hex digits) and its check; its MPPE keys (RFC
// 3079: the master key and the asymmetric start keys); and its RADIUS
// attributes (RFC 2548: MS-CHAP-Challenge, MS-CHAP2-Response,
// MS-CHAP2-Success), both sides.
//
// MS-CHAPv2 rests on the NT hash, an unsalted MD4 of the password, and on
// single DES: a captured exchange gives the NT hash to anyone who breaks
// one DES key. Run it inside a tunnel (PEAP, TTLS), never in the clear.

namespace radius;

import std;
import crypto.bignum;
import crypto.bignum.md4;
import crypto.bignum.sha1;
import crypto.bignum.des;
import crypto.bignum.ct;
import entropy;
import ntlm;

// The NT hash: MD4 of the password in UTF-16LE; false if not UTF-8.
fn nt_password_hash(pw: const u8[:]) -> u8[16], bool {
    let h, ok = ntlm::nt_hash(pw);
    return h, ok;
}

// ChallengeHash: the first 8 bytes of SHA-1(peer challenge, authenticator
// challenge, user name), the name without a domain (RFC 2759 §8.2).
fn challenge_hash(peer: const u8[:], auth: const u8[:], user: const u8[:]) -> u8[8] {
    var b: u8[>..] = [];
    b.append(peer);
    b.append(auth);
    b.append(user);
    let h = bignum::sha1(b);
    var out: u8[8] = [0; 8];
    for i in 8 { out[i] = h[i]; }
    return out;
}

// A DES key from 7 bytes: 8 groups of 7 bits, each in a byte's top bits.
fn des_key7(k: const u8[:]) -> u8[8] {
    var x: u64 = 0;
    for i in 7 { x = (x << 8) | k[i]; }
    var out: u8[8] = [0; 8];
    for i in 8 { out[i] = (((x >> (49 - 7 * i)) & 0x7f) << 1) as! u8; }
    return out;
}

// ChallengeResponse (§8.5): the challenge hash under DES with the NT hash,
// zero-padded to 21 bytes, as three 7-byte keys.
fn challenge_response(ch: const u8[:], hash: const u8[:]) -> u8[24] {
    var z: u8[21] = [0; 21];
    for i in 16 { z[i] = hash[i]; }
    var out: u8[24] = [0; 24];
    for k in 3 {
        let key = des_key7(z[7 * k..7 * k + 7]);
        let d = bignum::des_init(key);
        let c = bignum::des_encrypt_block(d, ch);
        for i in 8 { out[8 * k + i] = c[i]; }
    }
    return out;
}

// GenerateNTResponse (§8.1) from the NT hash.
fn nt_response(auth_ch: const u8[:], peer_ch: const u8[:], user: const u8[:], hash: const u8[:]) -> u8[24] {
    let ch = challenge_hash(peer_ch, auth_ch, user);
    return challenge_response(ch, hash);
}

let MAGIC_SERVER_SIGNING: const u8[:] = "Magic server to client signing constant";
let MAGIC_PAD: const u8[:] = "Pad to make it do more than one iteration";

fn hex_upper(out: u8[>..]&, b: const u8[:]) {
    let digits = "0123456789ABCDEF";
    for x in b { out.push(digits[(x >> 4) as i64]); out.push(digits[(x & 15) as i64]); }
}

// GenerateAuthenticatorResponse (§8.7): "S=" and 40 upper-case hex digits.
fn authenticator_response(hash: const u8[:], nt_resp: const u8[:], peer_ch: const u8[:], auth_ch: const u8[:],
                          user: const u8[:]) -> u8[42] {
    let hh = bignum::md4(hash);
    var b: u8[>..] = [];
    b.append(hh);
    b.append(nt_resp);
    b.append(MAGIC_SERVER_SIGNING);
    let d1 = bignum::sha1(b);
    let ch = challenge_hash(peer_ch, auth_ch, user);
    b.clear();
    b.append(d1);
    b.append(ch);
    b.append(MAGIC_PAD);
    let d2 = bignum::sha1(b);
    var s: u8[>..] = [];
    s.append("S=");
    hex_upper(s, d2);
    var out: u8[42] = [0; 42];
    for i in 42 { out[i] = s[i]; }
    return out;
}

// CheckAuthenticatorResponse (§8.8): the "S=..." a server sent, in its
// first 42 bytes (a message may follow), against the one it should be.
fn authenticator_response_ok(got: const u8[:], hash: const u8[:], nt_resp: const u8[:], peer_ch: const u8[:],
                             auth_ch: const u8[:], user: const u8[:]) -> bool {
    if got.len < 42 { return false; }
    let want = authenticator_response(hash, nt_resp, peer_ch, auth_ch, user);
    // Hex digits either case.
    var g: u8[42] = [0; 42];
    for i in 42 { g[i] = if got[i] >= 'a' && got[i] <= 'f' { got[i] - 32 } else { got[i] }; }
    return bignum::ct_eq_bytes(want, g) == 1;
}

// --- MPPE keys (RFC 3079 §3) -----------------------------------------------------

let MAGIC_MASTER: const u8[:] = "This is the MPPE Master Key";
let MAGIC_CLIENT_SEND: const u8[:] = "On the client side, this is the send key; on the server side, it is the receive key.";
let MAGIC_CLIENT_RECV: const u8[:] = "On the client side, this is the receive key; on the server side, it is the send key.";

// GetMasterKey: 16 bytes of SHA-1(MD4(NT hash), NT response, magic).
fn master_key(hash: const u8[:], nt_resp: const u8[:]) -> u8[16] {
    var b: u8[>..] = [];
    b.append(bignum::md4(hash));
    b.append(nt_resp);
    b.append(MAGIC_MASTER);
    let d = bignum::sha1(b);
    var out: u8[16] = [0; 16];
    for i in 16 { out[i] = d[i]; }
    return out;
}

// GetAsymmetricStartKey: the 16-byte send or receive key of the client or
// the server.
fn start_key(master: const u8[:], is_send: bool, is_server: bool) -> u8[16] {
    let s = if is_send == is_server { MAGIC_CLIENT_RECV } else { MAGIC_CLIENT_SEND };
    var b: u8[>..] = [];
    b.append(master[..16]);
    for i in 40 { b.push(0); }
    b.append(s);
    for i in 40 { b.push(0xf2); }
    let d = bignum::sha1(b);
    var out: u8[16] = [0; 16];
    for i in 16 { out[i] = d[i]; }
    return out;
}

// --- The RADIUS attributes (RFC 2548 §2.3) -----------------------------------------

// An Access-Request's MS-CHAP-Challenge and MS-CHAP2-Response for a
// password: a random authenticator challenge (the NAS's), a random peer
// challenge, and the NT response; the challenge and the response's
// 50 bytes are kept for checking the MS-CHAP2-Success that comes back.
struct Mschap2 { auth_ch: u8[16], peer_ch: u8[16], nt_resp: u8[24], hash: u8[16], ident: u8 }

fn add_mschap2(p: Packet&, user: const u8[:], pw: const u8[:]) -> Mschap2, bool {
    var m = Mschap2 { auth_ch: [0; 16], peer_ch: [0; 16], nt_resp: [0; 24], hash: [0; 16], ident: 0 };
    let h, ok = nt_password_hash(pw);
    if !ok { return m, false; }
    m.hash = h;
    entropy::random_bytes(m.auth_ch);
    entropy::random_bytes(m.peer_ch);
    var idb: u8[1] = [0];
    entropy::random_bytes(idb);
    m.ident = idb[0];
    m.nt_resp = nt_response(m.auth_ch, m.peer_ch, user, h);
    var r: u8[>..] = [];
    r.push(m.ident);
    r.push(0);                       // flags
    r.append(m.peer_ch);
    for i in 8 { r.push(0); }        // reserved
    r.append(m.nt_resp);
    let ok2 = add(p, USER_NAME, user) && add_vsa(p, VENDOR_MICROSOFT, MS_CHAP_CHALLENGE, m.auth_ch) &&
        add_vsa(p, VENDOR_MICROSOFT, MS_CHAP2_RESPONSE, r);
    return m, ok2;
}

// Whether an Access-Accept's MS-CHAP2-Success proves the server knew the
// password.
fn mschap2_success_ok(p: const Packet&, m: const Mschap2&, user: const u8[:]) -> bool {
    let v, ok = vsa(p, VENDOR_MICROSOFT, MS_CHAP2_SUCCESS);
    return ok && v.len >= 43 && v[0] == m.ident &&
        authenticator_response_ok(v[1..], m.hash, m.nt_resp, m.peer_ch, m.auth_ch, user);
}

// The server's side: whether a request's MS-CHAP2-Response is right for
// the NT hash; if so, MS-CHAP2-Success goes in the answer, and the MPPE
// keys (16 bytes each, as FreeRADIUS sends them) with mppe set.
fn check_mschap2(req: const Packet&, user: const u8[:], hash: const u8[:]) -> bool {
    let ch, okc = vsa(req, VENDOR_MICROSOFT, MS_CHAP_CHALLENGE);
    let r, okr = vsa(req, VENDOR_MICROSOFT, MS_CHAP2_RESPONSE);
    if !okc || !okr || ch.len != 16 || r.len != 50 { return false; }
    let want = nt_response(ch, r[2..18], user, hash);
    return bignum::ct_eq_bytes(want, r[26..50]) == 1;
}

fn add_mschap2_success(resp: Packet&, req: const Packet&, user: const u8[:], hash: const u8[:], secret: const u8[:],
                       mppe: bool) -> bool {
    let ch, okc = vsa(req, VENDOR_MICROSOFT, MS_CHAP_CHALLENGE);
    let r, okr = vsa(req, VENDOR_MICROSOFT, MS_CHAP2_RESPONSE);
    if !okc || !okr || ch.len != 16 || r.len != 50 { return false; }
    let a = authenticator_response(hash, r[26..50], r[2..18], ch, user);
    var v: u8[>..] = [];
    v.push(r[0]);
    v.append(a);
    if !add_vsa(resp, VENDOR_MICROSOFT, MS_CHAP2_SUCCESS, v) { return false; }
    if !mppe { return true; }
    let mk = master_key(hash, r[26..50]);
    let send = start_key(mk, true, true);
    let recv = start_key(mk, false, true);
    let se, oks = salt_encrypt(send, secret, req.auth);
    let re, okr2 = salt_encrypt(recv, secret, req.auth);
    return oks && okr2 && add_vsa(resp, VENDOR_MICROSOFT, MS_MPPE_SEND_KEY, se) &&
        add_vsa(resp, VENDOR_MICROSOFT, MS_MPPE_RECV_KEY, re);
}
