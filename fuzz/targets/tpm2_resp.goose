// Fuzz target: tpm2_resp. TPM responses as tpm2's commands read them,
// with no TPM. data[0] picks how the bytes arrive, data[1] which command's
// response parameters they are, the rest is the input:
//   data[0] % 4 == 0: the input is a whole response, read by
//      parse_response for a command with no sessions (nrh = data[0] / 4 % 2).
//   1: the same with a password session.
//   2: the same with an HMAC session (fixed key and nonces; the response
//      HMAC will not verify, so this is the header and session area).
//   3: the input is the response parameters, wrapped here into a response
//      a TPM would send for an HMAC session with parameter encryption: the
//      first parameter encrypted, rpHash and the HMAC computed with the
//      session's key. parse_response then checks and decrypts it, so the
//      parameters reach the command's reader.
// The parameters (parse_response's, or the raw input when it refuses the
// response) then go to the reader of one command, data[1] % 12, copied
// from tpm2/commands.goose and tpm2/session.goose where the reader is inline:
// GetCapability (properties, handles), CreatePrimary, Create, Load,
// ReadPublic, Quote/Certify (read_attested, parse_attest), PCR_Read,
// NV_ReadPublic, ContextSave, StartAuthSession, Sign/Hash/ECDH_ZGen/Unseal.

import std;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.tpm2.attest;

let KEY:          const u8[:] = "0123456789abcdef0123456789abcdef";
let NONCE_CALLER: const u8[:] = "caller nonce caller nonce 012345";
let NONCE_TPM:    const u8[:] = "tpm nonce tpm nonce tpm nonce 01";

fn hmac_session(encrypt: bool) -> tpm2::Session {
    var s = tpm2::Session { kind: tpm2::SESSION_HMAC, handle: 0x02000000, .. };
    s.key.append(KEY);
    s.nonce_caller.append(NONCE_CALLER);
    if encrypt { s.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_ENCRYPT; s.sym_bits = 128; }
    return s;
}

// The response a TPM would send for params, with an HMAC session.
fn wrap(cc: u32, nrh: i64, params: const u8[:], e: tpm2::Entity, s: const tpm2::Session&) -> u8[>..] {
    var p: u8[>..] = [];
    p.append(params);
    if (s.attrs & tpm2::ATTR_ENCRYPT) != 0 && p.len >= 2 && tpm2::be16(p, 0) as i64 + 2 <= p.len {
        let n = tpm2::be16(p, 0) as i64;
        let v = tpm2::session_value(s, e, true);
        tpm2::param_crypt(s, v, NONCE_TPM, s.nonce_caller, p[2..2 + n], false);
    }
    var rp: u8[>..] = [];
    tpm2::put_u32(rp, 0);
    tpm2::put_u32(rp, cc);
    rp.append(p);
    var m: u8[>..] = [];
    m.append(tpm2::hash(s.hash, rp));
    m.append(NONCE_TPM);
    m.append(s.nonce_caller);
    m.push(s.attrs);
    let mac = tpm2::hmac(s.hash, tpm2::hmac_key(s, e, true), m);
    var body: u8[>..] = [];
    for i in nrh { tpm2::put_u32(body, 0x80000001); }
    tpm2::put_u32(body, p.len as u32);
    body.append(p);
    tpm2::put_2b(body, NONCE_TPM);
    tpm2::put_u8(body, s.attrs);
    tpm2::put_2b(body, mac);
    var out: u8[>..] = [];
    tpm2::put_u16(out, tpm2::ST_SESSIONS);
    tpm2::put_u32(out, (10 + body.len) as u32);
    tpm2::put_u32(out, 0);
    out.append(body);
    return out;
}

fn readers(which: u8, rp: const u8[:]) {
    var r = tpm2::reader(rp);
    if which == 0 {
        // GetCapability, then tpm_property's and get_handles' reads of its data.
        let more = tpm2::get_u8(r);
        let c = tpm2::get_u32(r);
        let data = tpm2::get_bytes(r, tpm2::left(r));
        var d = tpm2::reader(data);
        let n = tpm2::get_u32(d);
        let p = tpm2::get_u32(d);
        let v = tpm2::get_u32(d);
        var h = tpm2::reader(data);
        let hn = tpm2::get_u32(h);
        if hn <= 256 {
            var out: u32[>..] = [];
            for i in hn as i64 {
                let x = tpm2::get_u32(h);
                if h.ok && tpm2::handle_type(x) == 0x81 { out.push(x); }
            }
        }
    } else if which == 1 || which == 2 {
        // CreatePrimary (read_creation, name), Create (private, read_creation).
        var o = tpm2::Object { .. };
        if which == 2 { tpm2::read_into(r, o.private); }
        tpm2::read_creation(r, o);
        if which == 1 { tpm2::read_into(r, o.name); }
        if r.ok {
            let nm = tpm2::public_name(o.public);
            let _ = tpm2::matches_template(o.public, tpm2::ak_ecc_template());
            let spki, ok = tpm2::public_to_spki(o.public);
            let cd = tpm2::reader(o.creation_data);
        }
    } else if which == 3 {
        // CreateLoaded: private, public, name.
        var o = tpm2::Object { .. };
        tpm2::read_into(r, o.private);
        let pub, pb = tpm2::read_public_2b(r);
        o.public = pub;
        tpm2::read_into(r, o.name);
        if r.ok { let _ = tpm2::public_name(o.public); let _ = tpm2::rsa_public(o.public); let _ = tpm2::ecc_point(o.public); }
    } else if which == 4 {
        // ReadPublic: public, name, qualified name.
        var qn: u8[..66] = [];
        let pub, pb = tpm2::read_public_2b(r);
        var name: u8[..66] = [];
        tpm2::read_into(r, name);
        tpm2::read_into(r, qn);
        if r.ok {
            let spki, ok = tpm2::public_to_spki(pub);
            if ok { let back, be = tpm2::public_from_spki(spki, pub); }
            let _ = tpm2::marshal_public(pub);
        }
    } else if which == 5 {
        // Quote, Certify, CertifyCreation: TPMS_ATTEST and the signature.
        let q, e = tpm2::read_attested(rp);
        if e == tpm2::OK {
            let a, ae = tpm2::parse_attest(q.attest);
            let _ = tpm2::marshal_signature(q.sig);
        }
    } else if which == 6 {
        // PCR_Read for SHA-256 0-7 and SHA-1 0-1.
        let req = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0xff }, tpm2::PcrSel { hash: tpm2::ALG_SHA1, mask: 0x3 }];
        let counter = tpm2::get_u32(r);
        let out_sel = tpm2::read_pcr_selection(r);
        let n = tpm2::get_u32(r);
        if !r.ok || n > 8 { return; }
        var digests: u8[..64][..8] = [];
        for i in n as i64 {
            var d: u8[..64] = [];
            tpm2::read_into(r, d);
            digests.push(d);
        }
        if !r.ok || tpm2::left(r) != 0 { return; }
        var di = 0;
        for os in out_sel {
            var bank = -1;
            for b in req.len { if req[b].hash == os.hash { bank = b; } }
            if bank < 0 || (os.mask & ~req[bank].mask) != 0 { return; }
            for i in tpm2::pcr_list(os.mask) {
                if di >= digests.len || digests[di].len != tpm2::digest_size(os.hash) { return; }
                di++;
            }
        }
        var vals: u8[..64][>..] = [];
        for d in digests { vals.push(d); }
        let _ = tpm2::pcr_digest(tpm2::ALG_SHA256, vals);
    } else if which == 7 {
        // NV_ReadPublic.
        let b = tpm2::get_2b(r, 256);
        var name: u8[..66] = [];
        tpm2::read_into(r, name);
        var inner = tpm2::reader(b);
        let n = tpm2::read_nv_public(inner);
        if r.ok && inner.ok { let _ = tpm2::nv_name(n); let _ = tpm2::marshal_nv_public(n); }
    } else if which == 8 {
        // ContextSave.
        var c = tpm2::Context { .. };
        c.sequence = tpm2::get_u64(r);
        c.saved_handle = tpm2::get_u32(r);
        c.hierarchy = tpm2::get_u32(r);
        tpm2::read_into(r, c.blob);
    } else if which == 9 {
        // Sign and VerifySignature.
        let sig = tpm2::read_signature(r);
        let k = tpm2::read_ticket(r);
        if r.ok {
            let der, ok = tpm2::signature_der(sig, tpm2::ak_ecc_template());
            let _ = tpm2::marshal_signature(sig);
        }
    } else if which == 10 {
        // Hash (digest, ticket), ECDH_ZGen (a point), Unseal (data).
        var d: u8[..64] = [];
        tpm2::read_into(r, d);
        let k = tpm2::read_ticket(r);
        var r2 = tpm2::reader(rp);
        let x, y = tpm2::read_ecc_point_2b(r2);
        var r3 = tpm2::reader(rp);
        let u = tpm2::get_2b(r3, 128);
    } else {
        // StartAuthSession's nonce, and the response code's text.
        let nonce = tpm2::get_2b(r, 64);
        if rp.len >= 4 { let _ = tpm2::rc_text(tpm2::be32(rp, 0)); }
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 2 { return 0; }
    let mode = data[0] % 4;
    let nrh = (data[0] / 4 % 2) as i64;
    let which = data[1] % 12;
    let input = data[2..];
    var none = tpm2::no_session();
    var none2 = tpm2::no_session();
    let e = tpm2::Entity { handle: 0x81000001, .. };
    let hs = [e];
    let c = tpm2::Cmd { cc: tpm2::CC_Create, nauth: 1, nrh: nrh, enc_in: true, enc_out: true };
    var params: u8[>..] = [];
    var pe:     i64     = tpm2::ERR_MALFORMED;
    if mode == 0 {
        let p, h, rc, err = tpm2::parse_response(c, hs, none, none2, input);
        params.append(p);
        pe = err;
    } else if mode == 1 {
        var pw = tpm2::pw();
        let p, h, rc, err = tpm2::parse_response(c, hs, pw, none2, input);
        params.append(p);
        pe = err;
    } else if mode == 2 {
        var s = hmac_session(data[0] & 8 != 0);
        let p, h, rc, err = tpm2::parse_response(c, hs, s, none2, input);
        params.append(p);
        pe = err;
        if rc != 0 { let _ = tpm2::rc_text(rc); }
    } else {
        var s = hmac_session(data[0] & 8 == 0);
        let rsp = wrap(c.cc, nrh, input, e, s);
        let p, h, rc, err = tpm2::parse_response(c, hs, s, none2, rsp);
        params.append(p);
        pe = err;
    }
    if pe == tpm2::OK { readers(which, params); } else { readers(which, input); }
    return 0;
}

fn main() {}
