// ntlm.crypto: NTLMv2's computations ([MS-NLMP] §3.3.2, §3.4.4, §3.4.5):
// NTOWFv2, the NTLMv2_CLIENT_CHALLENGE blob, NTProofStr, LMv2, the session
// base key, the MIC, the keys of session security, and the MD5 of
// gss_channel_bindings_struct.
//
// There is no NTOWFv1, LMOWFv1, DESL or NTLMv1 response here, on purpose.

namespace ntlm;

import std;
import crypto.bignum;
import crypto.bignum.md4;
import crypto.bignum.md5;
import crypto.bignum.hmac;
import crypto.bignum.rc4;

fn hmac_md5(key: const u8[:], msg: const u8[:]) -> u8[16] {
    let h = bignum::hmac(128, key, msg);
    var out: u8[16] = [0; 16];
    for i in 16 { out[i] = h[i]; }
    return out;
}

fn md5_16(data: const u8[:]) -> u8[16] { bignum::md5(data) }

// NTOWFv2 = HMAC_MD5(NT hash, UTF-16LE(Uppercase(User) || UserDom)), the
// response key (LMOWFv2 is the same). false if a name is not UTF-8.
fn ntowfv2(hash: const u8[:], user: const u8[:], domain: const u8[:]) -> u8[16], bool {
    var t: u8[>..] = [];
    let up = upper_ascii(user);
    if !utf16le(t, up) || !utf16le(t, domain) { return [0; 16], false; }
    return hmac_md5(hash, t), true;
}

// The NTLMv2_CLIENT_CHALLENGE ("temp", §3.3.2) with the trailing Z(4):
// versions 1 and 1, Z(6), the time, the client challenge, Z(4), the AV
// pairs (ending in MsvAvEOL), Z(4).
fn client_blob(out: u8[>..]&, time: u64, client_challenge: const u8[:], av_pairs: const u8[:]) {
    out.push(1);
    out.push(1);
    for i in 6 { out.push(0); }
    put64(out, time);
    out.append(client_challenge);
    put32(out, 0);
    out.append(av_pairs);
    put32(out, 0);
}

// NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp).
fn nt_proof(key: const u8[:], server_challenge: const u8[:], blob: const u8[:]) -> u8[16] {
    var m: u8[>..] = [];
    m.append(server_challenge);
    m.append(blob);
    return hmac_md5(key, m);
}

// The LMv2 response: HMAC_MD5(ResponseKeyLM, ServerChallenge ||
// ClientChallenge) || ClientChallenge.
fn lmv2_response(key: const u8[:], server_challenge: const u8[:], client_challenge: const u8[:]) -> u8[24] {
    var m: u8[>..] = [];
    m.append(server_challenge);
    m.append(client_challenge);
    let h = hmac_md5(key, m);
    var out: u8[24] = [0; 24];
    for i in 16 { out[i] = h[i]; }
    for i in 8 { out[16 + i] = client_challenge[i]; }
    return out;
}

// SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr); NTLMv2's
// KeyExchangeKey is the same.
fn session_base_key(key: const u8[:], proof: const u8[:]) -> u8[16] { hmac_md5(key, proof) }

// RC4K(key, data): the KEY_EXCH encryption of the exported session key
// (and its decryption, the same).
fn rc4k(key: const u8[:], data: const u8[:]) -> u8[16] {
    var r = bignum::rc4_init(key);
    var out: u8[16] = [0; 16];
    for i in 16 { out[i] = data[i]; }
    bignum::rc4_xor(r, out);
    return out;
}

// MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE ||
// AUTHENTICATE), the last with its MIC field zeros.
fn compute_mic(exported: const u8[:], negotiate: const u8[:], challenge: const u8[:], authenticate: const u8[:]) -> u8[16] {
    var m: u8[>..] = [];
    m.append(negotiate);
    m.append(challenge);
    m.append(authenticate);
    return hmac_md5(exported, m);
}

// The MD5 of a gss_channel_bindings_struct (RFC 2744 §3.11) with no
// addresses and the application data, as MsvAvChannelBindings carries it
// (TLS: "tls-server-end-point:" and the certificate's hash, RFC 5929).
fn bindings_hash(application_data: const u8[:]) -> u8[16] {
    var b: u8[>..] = [];
    for i in 4 { put32(b, 0); }
    put32(b, application_data.len as! u32);
    b.append(application_data);
    return md5_16(b);
}

// --- Session security keys (§3.4.5.2, §3.4.5.3) -------------------------------------------

let MAGIC_SIGN_C2S: const u8[:] = "session key to client-to-server signing key magic constant\x00";
let MAGIC_SIGN_S2C: const u8[:] = "session key to server-to-client signing key magic constant\x00";
let MAGIC_SEAL_C2S: const u8[:] = "session key to client-to-server sealing key magic constant\x00";
let MAGIC_SEAL_S2C: const u8[:] = "session key to server-to-client sealing key magic constant\x00";

// SIGNKEY with extended session security, for messages the client
// sends (c2s) or the server sends.
fn sign_key(exported: const u8[:], c2s: bool) -> u8[16] {
    var m: u8[>..] = [];
    m.append(exported);
    m.append(if c2s { MAGIC_SIGN_C2S } else { MAGIC_SIGN_S2C });
    return md5_16(m);
}

// SEALKEY with extended session security: the exported key cut to 16, 7
// or 5 bytes by NEGOTIATE_128 and NEGOTIATE_56, then hashed with the
// direction's constant.
fn seal_key(flags: u32, exported: const u8[:], c2s: bool) -> u8[16] {
    let n = if flags & NEGOTIATE_128 != 0 { 16 } else if flags & NEGOTIATE_56 != 0 { 7 } else { 5 };
    var m: u8[>..] = [];
    m.append(exported[..n]);
    m.append(if c2s { MAGIC_SEAL_C2S } else { MAGIC_SEAL_S2C });
    return md5_16(m);
}
