// ntlm.session: session security after authentication ([MS-NLMP] §3.4)
// with extended session security, the only kind here: each direction has
// its signing key, its sealing key and RC4 state, and its sequence
// number. A signature (NTLMSSP_MESSAGE_SIGNATURE, 16 bytes) is version 1,
// the first 8 bytes of HMAC_MD5(SigningKey, SeqNum || message) (RC4'd
// with the direction's sealing state when KEY_EXCH was negotiated), and
// the sequence number. Sealing RC4s the message with the same state,
// then signs it.
//
// GSS-API's calls on it: get_mic and verify_mic (a signature alone), wrap
// and unwrap (the signature, then the message, sealed when SEAL was
// negotiated: as SSPI, gss-ntlmssp and pyspnego lay it out). Messages are
// taken in order: the RC4 state and sequence numbers run on.

namespace ntlm;

import std;
import crypto.bignum;
import crypto.bignum.hmac;
import crypto.bignum.rc4;

struct Session {
    flags:        u32,          // the negotiated flags
    exported:     u8[16],       // ExportedSessionKey
    keys:         bool,         // keys were derived (not anonymous)
    initiator:    bool,
    sign_out:     u8[16],
    sign_in:      u8[16],
    seal_key_out: u8[16],
    seal_key_in:  u8[16],
    seal_out:     bignum::Rc4,
    seal_in:      bignum::Rc4,
    seq_out:      u32,
    seq_in:       u32,
}

fn no_session() -> Session {
    let z: u8[16] = [0; 16];
    return Session { flags: 0, exported: z, keys: false, initiator: false, sign_out: z, sign_in: z, seal_key_out: z, seal_key_in: z,
                     seal_out: bignum::rc4_init(z), seal_in: bignum::rc4_init(z), seq_out: 0, seq_in: 0 };
}

// The session of an established context: the negotiated flags, the
// exported session key, and which side this is.
fn new_session(flags: u32, exported: const u8[:], initiator: bool) -> Session {
    var s = no_session();
    s.flags = flags;
    s.initiator = initiator;
    for i in 16 { s.exported[i] = exported[i]; }
    s.sign_out = sign_key(exported, initiator);
    s.sign_in = sign_key(exported, !initiator);
    s.seal_key_out = seal_key(flags, exported, initiator);
    s.seal_key_in = seal_key(flags, exported, !initiator);
    s.seal_out = bignum::rc4_init(s.seal_key_out);
    s.seal_in = bignum::rc4_init(s.seal_key_in);
    s.keys = true;
    return s;
}

// The RC4 state of one direction back to its start, the sequence number
// kept: what SPNEGO does after the NTLM mechListMIC (MS-SPNG, as Windows
// and pyspnego do it).
fn reset_rc4(s: Session&, outgoing: bool) {
    if outgoing { s.seal_out = bignum::rc4_init(s.seal_key_out); } else { s.seal_in = bignum::rc4_init(s.seal_key_in); }
}

// MAC(Handle, SigningKey, SeqNum, Message) with extended session security.
fn mac_of(s: Session&, outgoing: bool, msg: const u8[:]) -> u8[16] {
    let seq = if outgoing { s.seq_out } else { s.seq_in };
    var m: u8[>..] = [];
    put32(m, seq);
    m.append(msg);
    let h = hmac_md5(if outgoing { s.sign_out[..] } else { s.sign_in[..] }, m);
    var ck: u8[8] = [0; 8];
    for i in 8 { ck[i] = h[i]; }
    if s.flags & NEGOTIATE_KEY_EXCH != 0 {
        if outgoing { bignum::rc4_xor(s.seal_out, ck); } else { bignum::rc4_xor(s.seal_in, ck); }
    }
    var sig: u8[16] = [0; 16];
    sig[0] = 1;
    for i in 8 { sig[4 + i] = ck[i]; }
    for i in 4 { sig[12 + i] = (seq >> (8 * i)) as! u8; }
    if outgoing { s.seq_out += 1; } else { s.seq_in += 1; }
    return sig;
}

// A signature of msg (GSS_GetMIC).
fn get_mic(s: Session&, msg: const u8[:], out: u8[>..]&) -> i64 {
    if !s.keys { return ERR_NO_SESSION; }
    out.append(mac_of(s, true, msg));
    return OK;
}

// Whether sig is the peer's next signature of msg (GSS_VerifyMIC).
fn verify_mic(s: Session&, msg: const u8[:], sig: const u8[:]) -> i64 {
    if !s.keys { return ERR_NO_SESSION; }
    if sig.len != 16 { return ERR_SIGNATURE; }
    let want = mac_of(s, false, msg);
    return if same(want, sig) { OK } else { ERR_SIGNATURE };
}

// GSS_Wrap: the signature and the message, sealed when SEAL was
// negotiated, else signed only (SIGN); ERR_NO_SESSION with neither.
fn wrap(s: Session&, msg: const u8[:], out: u8[>..]&) -> i64 {
    if !s.keys || s.flags & (NEGOTIATE_SEAL | NEGOTIATE_SIGN) == 0 { return ERR_NO_SESSION; }
    if s.flags & NEGOTIATE_SEAL != 0 {
        var c: u8[>..] = [];
        c.append(msg);
        bignum::rc4_xor(s.seal_out, c);
        out.append(mac_of(s, true, msg));
        out.append(c);
    } else {
        out.append(mac_of(s, true, msg));
        out.append(msg);
    }
    return OK;
}

// GSS_Unwrap: the message of a wrap token from the peer, its signature
// checked (and its sealing undone). Nothing goes to `out` on failure.
fn unwrap(s: Session&, token: const u8[:], out: u8[>..]&) -> i64 {
    if !s.keys || s.flags & (NEGOTIATE_SEAL | NEGOTIATE_SIGN) == 0 { return ERR_NO_SESSION; }
    if token.len < 16 { return ERR_SIGNATURE; }
    var m: u8[>..] = [];
    m.append(token[16..]);
    if s.flags & NEGOTIATE_SEAL != 0 { bignum::rc4_xor(s.seal_in, m); }
    let want = mac_of(s, false, m);
    if !same(want, token[..16]) { return ERR_SIGNATURE; }
    out.append(m);
    return OK;
}
