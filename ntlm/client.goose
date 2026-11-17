// ntlm.client: the initiator (client) side of NTLM ([MS-NLMP] §3.1),
// NTLMv2 only. negotiate() makes the NEGOTIATE message; authenticate()
// reads the server's CHALLENGE and makes the AUTHENTICATE message:
//
//   - flags offered: UNICODE, NTLM, extended session security, 128-bit,
//     KEY_EXCH, SIGN (and SEAL with WANT_SEAL), ALWAYS_SIGN,
//     REQUEST_TARGET, VERSION; never LM_KEY, OEM, DATAGRAM or 56;
//   - a CHALLENGE without UNICODE or extended session security, without
//     128 when signing, or without SEAL when WANT_SEAL asked for it, is a
//     downgrade: ERR_FLAGS;
//   - the server's target info is sent back with MsvAvFlags (MIC
//     present), MsvAvChannelBindings (set_channel_bindings), and
//     MsvAvTargetName (the SPN) added, in the NTLMv2 blob whose time is the
//     server's MsvAvTimestamp when it sent one (then the LM response is
//     Z(24), as §3.1.5.1.2 says; else LMv2);
//   - the exported session key is random and goes RC4-encrypted
//     (KEY_EXCH); the MIC covers the three messages.
//
// Anonymous credentials (ntlm::anonymous_credentials) send no response
// and get no session keys.

namespace ntlm;

import std;
import entropy;
import ntlm.crypto;
import ntlm.messages;
import ntlm.session;

let INIT_NEW: i64 = 0;
let INIT_NEGOTIATED: i64 = 1;
let INIT_DONE: i64 = 2;
let INIT_FAILED: i64 = 3;

struct Initiator {
    cred:      Credentials,
    want:      u32,              // WANT_SIGN, WANT_SEAL
    spn:       u8[..512],        // the target name, "HTTP/web.example.test"; empty: none sent
    has_cb:    bool,
    cb_hash:   u8[16],
    state:     i64,
    flags:     u32,              // offered, then negotiated
    negotiate: u8[..256],        // the NEGOTIATE sent, for the MIC
    session:   Session,
}

fn initiator(cred: Credentials, spn: const u8[:], want: u32) -> Initiator {
    var c = Initiator { cred: cred, want: want, spn: [], has_cb: false, cb_hash: [0; 16], state: INIT_NEW, flags: 0,
                        negotiate: [], session: no_session() };
    if spn.len > c.spn.cap { c.state = INIT_FAILED; } else { c.spn.append(spn); }
    return c;
}

// Channel bindings: the application data of gss_channel_bindings_struct
// (TLS: "tls-server-end-point:" and the server certificate's hash).
fn set_channel_bindings(c: Initiator&, application_data: const u8[:]) {
    c.cb_hash = bindings_hash(application_data);
    c.has_cb = true;
}

fn offered_flags(c: const Initiator&) -> u32 {
    var f = NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY |
            NEGOTIATE_VERSION;
    if c.cred.anonymous { return f | NEGOTIATE_ANONYMOUS; }
    f |= NEGOTIATE_128 | NEGOTIATE_KEY_EXCH | NEGOTIATE_SIGN;
    if c.want & WANT_SEAL != 0 { f |= NEGOTIATE_SEAL; }
    return f;
}

// The NEGOTIATE message.
fn negotiate(c: Initiator&, out: u8[>..]&) -> i64 {
    if c.state != INIT_NEW { c.state = INIT_FAILED; return ERR_STATE; }
    c.flags = offered_flags(c);
    var m: u8[>..] = [];
    negotiate_message(m, c.flags);
    c.negotiate.clear();
    c.negotiate.append(m);
    c.state = INIT_NEGOTIATED;
    out.append(m);
    return OK;
}

// The AUTHENTICATE message for the server's CHALLENGE, with a random
// client challenge and session key; `now` (seconds since 1970) is the
// blob's time when the server sent none.
fn authenticate(c: Initiator&, challenge: const u8[:], now: i64, out: u8[>..]&) -> i64 {
    var cc: u8[8] = [0; 8];
    entropy::random_bytes(cc);
    var key: u8[16] = [0; 16];
    entropy::random_bytes(key);
    return authenticate_with(c, challenge, filetime(now), cc, key, true, out);
}

// authenticate with the FILETIME, client challenge and exported session
// key given, and the MIC only when `mic` (tests, and the spec's example
// that has none).
fn authenticate_with(c: Initiator&, challenge: const u8[:], time: u64, client_challenge: const u8[:], random_key: const u8[:],
                     mic: bool, out: u8[>..]&) -> i64 {
    if c.state != INIT_NEGOTIATED { c.state = INIT_FAILED; return ERR_STATE; }
    c.state = INIT_FAILED;
    if client_challenge.len != 8 || random_key.len != 16 { return ERR_ARG; }
    let ch, e = parse_challenge(challenge);
    if e != OK { return e; }
    let cf = ch.flags;
    // Downgrades.
    if cf & NEGOTIATE_UNICODE == 0 || cf & NEGOTIATE_EXTENDED_SESSIONSECURITY == 0 { return ERR_FLAGS; }
    if c.want & WANT_SEAL != 0 && cf & NEGOTIATE_SEAL == 0 { return ERR_FLAGS; }
    if cf & (NEGOTIATE_SIGN | NEGOTIATE_SEAL) != 0 && cf & NEGOTIATE_128 == 0 { return ERR_FLAGS; }
    let nf = cf & (c.flags | TARGET_TYPE_DOMAIN | TARGET_TYPE_SERVER | NEGOTIATE_TARGET_INFO);
    let start = out.len;
    var d16: u8[>..] = [];
    var n16: u8[>..] = [];
    var w16: u8[>..] = [];
    if !utf16le(d16, c.cred.domain) || !utf16le(n16, c.cred.user) || !utf16le(w16, c.cred.workstation) { return ERR_ARG; }
    if c.cred.anonymous {
        authenticate_message(out, nf | NEGOTIATE_ANONYMOUS, "\x00", "", "", "", w16, "", false);
        c.flags = nf | NEGOTIATE_ANONYMOUS;
        c.session = no_session();
        c.state = INIT_DONE;
        return OK;
    }
    let ti = field_bytes(challenge, ch.target_info);
    let ts, has_ts = av_get(ti, AV_TIMESTAMP);
    let t = if has_ts { get64(ts, 0) } else { time };
    // The target info, ours added.
    var av: u8[>..] = [];
    av_copy_without(av, ti, (1 << AV_FLAGS) | (1 << AV_CHANNEL_BINDINGS) | (1 << AV_TARGET_NAME));
    let fl, has_fl = av_get(ti, AV_FLAGS);
    var avflags: u32 = if has_fl { get32(fl, 0) } else { 0 };
    if mic { avflags |= AVF_MIC; }
    if mic || has_fl {
        var f4: u8[>..] = [];
        put32(f4, avflags);
        av_put(av, AV_FLAGS, f4);
    }
    if c.has_cb { av_put(av, AV_CHANNEL_BINDINGS, c.cb_hash); }
    if c.spn.len > 0 && !av_put_name(av, AV_TARGET_NAME, c.spn) { return ERR_ARG; }
    av_end(av);
    if av.len > 0xffff { return ERR_LIMIT; }
    let key, kok = ntowfv2(c.cred.nt_hash, c.cred.user, c.cred.domain);
    if !kok { return ERR_ARG; }
    var blob: u8[>..] = [];
    client_blob(blob, t, client_challenge, av);
    let proof = nt_proof(key, ch.server_challenge, blob);
    var nt: u8[>..] = [];
    nt.append(proof);
    nt.append(blob);
    if nt.len > 0xffff { return ERR_LIMIT; }
    var lm: u8[24] = [0; 24];
    if !has_ts { lm = lmv2_response(key, ch.server_challenge, client_challenge); }
    let sbk = session_base_key(key, proof);
    var exported: u8[16] = sbk;
    var enc: u8[>..] = [];
    if nf & NEGOTIATE_KEY_EXCH != 0 && nf & (NEGOTIATE_SIGN | NEGOTIATE_SEAL) != 0 {
        for i in 16 { exported[i] = random_key[i]; }
        enc.append(rc4k(sbk, exported));
    }
    authenticate_message(out, nf, lm, nt, d16, n16, w16, enc, mic);
    if mic {
        let m = compute_mic(exported, c.negotiate, challenge, out[start..]);
        for i in 16 { out[start + MIC_OFFSET + i] = m[i]; }
    }
    c.flags = nf;
    c.session = new_session(nf, exported, true);
    c.state = INIT_DONE;
    return OK;
}

fn established(c: const Initiator&) -> bool { c.state == INIT_DONE }
