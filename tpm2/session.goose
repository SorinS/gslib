// tpm2.session: authorization sessions and running a command through them
// (Part 1 §16-§21, Part 3 §11).
//
// A command's handles are Entities: a handle, its Name (for cpHash) and its
// authValue. The ones that need authorization each take a Session:
//
//   pw()                         a password: the entity's authValue in the clear
//   start_session(t, SESSION_HMAC, opts)
//                                an HMAC session: cpHash and rpHash under
//                                HMAC(sessionKey || authValue), new nonces
//                                each command; bound to an entity (its
//                                authValue goes into the sessionKey and out
//                                of the HMAC key when it authorizes that
//                                entity), salted to a TPM key (RSA-OAEP with
//                                the label "SECRET", or ECDH and KDFe), and
//                                with AES-CFB parameter encryption of a
//                                command's first parameter (ATTR_DECRYPT) or a
//                                response's (ATTR_ENCRYPT)
//   start_session(t, SESSION_POLICY, opts)
//                                a policy session, satisfied by the policy
//                                commands of tpm2.policy before the command
//
// execute() builds the command (build_command), sends it, and checks the
// response (parse_response): each session's response HMAC must verify
// (ERR_INTEGRITY otherwise) before an encrypted response parameter is
// decrypted. A session whose continueSession the TPM cleared is closed
// (kind SESSION_NONE).

namespace tpm2;

import std;
import tpm2;
import tpm2.transport;
import crypto.bignum;
import crypto.bignum.aes;
import crypto.bignum.modes;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import entropy;

let SESSION_NONE:   i64 = 0;
let SESSION_PW:     i64 = 1;
let SESSION_HMAC:   i64 = 2;
let SESSION_POLICY: i64 = 3;
let SESSION_TRIAL:  i64 = 4;

// TPMA_SESSION
let ATTR_CONTINUE:        u8 = 0x01;
let ATTR_AUDIT_EXCLUSIVE: u8 = 0x02;
let ATTR_AUDIT_RESET:     u8 = 0x04;
let ATTR_DECRYPT:         u8 = 0x20; // the command's first parameter is encrypted
let ATTR_ENCRYPT:         u8 = 0x40; // the response's first parameter is encrypted
let ATTR_AUDIT:           u8 = 0x80;

struct Session {
    kind:              i64      = SESSION_NONE,
    handle:            u32      = 0,
    hash:              u16      = ALG_SHA256,
    key:               u8[..64] = [], // sessionKey
    nonce_caller:      u8[..64] = [],
    nonce_tpm:         u8[..64] = [],
    attrs:             u8       = ATTR_CONTINUE,
    sym_bits:          u16      = 0, // AES-CFB key bits for parameter encryption; 0 for none
    bound:             bool     = false,
    bind_name:         u8[..66] = [],
    bind_auth:         u8[..64] = [],
    auth_value_needed: bool     = false, // PolicyAuthValue was run
    password_needed:   bool     = false, // PolicyPassword was run
    next_nonce:        u8[..64] = [],    // the next nonceCaller instead of a random one (known-answer tests)
}

// A handle of a command: the handle, its Name and its authValue.
struct Entity { handle: u32 = RH_NULL, name: u8[..66] = [], auth: u8[..64] = [] }

// What execute needs to know of a command: its code, how many of its
// handles need authorization, how many handles its response has, and
// whether its first parameter and its response's are sized buffers that
// a session may encrypt.
struct Cmd { cc: u32, nauth: i64 = 0, nrh: i64 = 0, enc_in: bool = false, enc_out: bool = false }

// A permanent handle (or PCR, or session) as an Entity: its Name is the handle.
fn entity(handle: u32, auth: const u8[:] = "") -> Entity {
    var e = Entity { handle: handle, name: handle_name(handle), .. };
    e.auth.append(auth);
    return e;
}

fn owner(auth: const u8[:] = "") -> Entity { entity(RH_OWNER, auth) }
fn endorsement(auth: const u8[:] = "") -> Entity { entity(RH_ENDORSEMENT, auth) }
fn platform(auth: const u8[:] = "") -> Entity { entity(RH_PLATFORM, auth) }
fn lockout(auth: const u8[:] = "") -> Entity { entity(RH_LOCKOUT, auth) }
fn pcr_entity(i: i64) -> Entity { entity(i as u32) }

// An object or NV index: its handle, its Name and its authValue.
fn object_entity(handle: u32, name: const u8[:], auth: const u8[:] = "") -> Entity {
    var e = Entity { handle: handle, .. };
    e.name.append(name);
    e.auth.append(auth);
    return e;
}

fn pw() -> Session { Session { kind: SESSION_PW, handle: RS_PW, .. } }
fn no_session() -> Session { Session { .. } }

// --- Session values ------------------------------------------------------------

// Whether entity e's authValue goes into the HMAC key of session s when s
// authorizes it (Part 1 §19.6.8-9).
fn auth_in_hmac(s: const Session&, e: Entity) -> bool {
    if s.kind == SESSION_POLICY { return s.auth_value_needed; }
    if s.kind != SESSION_HMAC { return false; }
    return !(s.bound && s.bind_name == e.name && s.bind_auth == e.auth);
}

fn hmac_key(s: const Session&, e: Entity, authorizes: bool) -> u8[>..] {
    var k: u8[>..] = [];
    k.append(s.key);
    if authorizes && auth_in_hmac(s, e) { k.append(e.auth); }
    return k;
}

// sessionValue for parameter encryption (Part 1 §21.1): sessionKey ||
// authValue when the session authorizes the entity, binding or not.
fn session_value(s: const Session&, e: Entity, authorizes: bool) -> u8[>..] {
    var k: u8[>..] = [];
    k.append(s.key);
    if authorizes { k.append(e.auth); }
    return k;
}

// AES-CFB over data in place with KDFa(hash, value, "CFB", newer, older).
fn param_crypt(s: const Session&, value: const u8[:], newer: const u8[:], older: const u8[:], data: u8[:], decrypt: bool) {
    let kb = s.sym_bits as i64;
    let k = kdfa(s.hash, value, "CFB", newer, older, kb + 128);
    let aes = bignum::aes_init(k[..kb / 8]);
    if decrypt { bignum::cfb_decrypt(aes, k[kb / 8..], data); }
    else { bignum::cfb_encrypt(aes, k[kb / 8..], data); }
}

fn new_nonce(s: Session&) {
    if s.next_nonce.len > 0 {
        s.nonce_caller = s.next_nonce;
        s.next_nonce.clear();
        return;
    }
    var n: u8[>..] = [];
    n.resize(digest_size(s.hash), 0);
    entropy::random_bytes(n);
    s.nonce_caller.clear();
    s.nonce_caller.append(n);
}

fn active(s: const Session&) -> bool { s.kind != SESSION_NONE }

// --- Building commands and reading responses ------------------------------------

// The command's bytes; the sessions get new caller nonces. ERR_ARG when a
// handle needing authorization has no session, or a session asks for
// parameter encryption the command cannot have.
fn build_command(c: Cmd, hs: const Entity[:], s1: Session&, s2: Session&, params: const u8[:]) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let ns = if active(s2) { 2 } else if active(s1) { 1 } else { 0 };
    if active(s2) && !active(s1) { return out, ERR_ARG; }
    if c.nauth > ns || hs.len < c.nauth { return out, ERR_ARG; }
    var p: u8[>..] = [];
    p.append(params);
    // Roll the nonces, then encrypt the first parameter.
    fn prep(s: Session&, i: i64) -> i64 {
        if s.kind == SESSION_HMAC || s.kind == SESSION_POLICY || s.kind == SESSION_TRIAL { new_nonce(s); }
        if (s.attrs & (ATTR_DECRYPT | ATTR_ENCRYPT)) != 0 && (s.kind == SESSION_PW || s.sym_bits == 0) { return ERR_ARG; }
        if (s.attrs & ATTR_DECRYPT) != 0 {
            if !c.enc_in || p.len < 2 || be16(p, 0) as i64 + 2 > p.len { return ERR_ARG; }
            let e = if i < hs.len { hs[i] } else { Entity { .. } };
            let v = session_value(s, e, i < c.nauth);
            let n = be16(p, 0) as i64;
            param_crypt(s, v, s.nonce_caller, s.nonce_tpm, p[2..2 + n], false);
        }
        if (s.attrs & ATTR_ENCRYPT) != 0 && !c.enc_out { return ERR_ARG; }
        return OK;
    }
    var auth: u8[>..] = [];
    fn put_auth(s: Session&, i: i64) {
        let authorizes = i < c.nauth;
        let e = if i < hs.len { hs[i] } else { Entity { .. } };
        put_u32(auth, s.handle);
        put_2b(auth, s.nonce_caller);
        put_u8(auth, s.attrs);
        if s.kind == SESSION_PW {
            if authorizes { put_2b(auth, e.auth); } else { put_2b(auth, ""); }
        } else if s.kind == SESSION_POLICY && s.password_needed && authorizes {
            put_2b(auth, e.auth);
        } else {
            var cp: u8[>..] = [];
            put_u32(cp, c.cc);
            for h in hs { cp.append(h.name); }
            cp.append(p);
            let cphash = hash(s.hash, cp);
            var m: u8[>..] = [];
            m.append(cphash);
            m.append(s.nonce_caller);
            m.append(s.nonce_tpm);
            m.push(s.attrs);
            put_2b(auth, hmac(s.hash, hmac_key(s, e, authorizes), m));
        }
    }
    if ns >= 1 { let e1 = prep(s1, 0); if e1 != OK { return out, e1; } }
    if ns >= 2 { let e2 = prep(s2, 1); if e2 != OK { return out, e2; } }
    if ns >= 1 { put_auth(s1, 0); }
    if ns >= 2 { put_auth(s2, 1); }
    put_u16(out, if ns > 0 { ST_SESSIONS } else { ST_NO_SESSIONS });
    put_u32(out, 0);
    put_u32(out, c.cc);
    for h in hs { put_u32(out, h.handle); }
    if ns > 0 {
        put_u32(out, auth.len as u32);
        out.append(auth);
    }
    out.append(p);
    let size = out.len as u32;
    out[2] = (size >> 24) as! u8;
    out[3] = (size >> 16) as! u8;
    out[4] = (size >> 8) as! u8;
    out[5] = size as! u8;
    return out, OK;
}

// A response's parameters (decrypted) and handle, checked against the
// command and its sessions; the sessions take the TPM's new nonces. The
// response code is the third result: ERR_TPM when it is not 0.
fn parse_response(c: Cmd, hs: const Entity[:], s1: Session&, s2: Session&, rsp: const u8[:]) -> u8[>..], u32, u32, i64 {
    var params: u8[>..] = [];
    if rsp.len < 10 { return params, 0, 0, ERR_MALFORMED; }
    var r = reader(rsp);
    let tag = get_u16(r);
    let size = get_u32(r);
    let rc = get_u32(r);
    if size != rsp.len { return params, 0, rc, ERR_MALFORMED; }
    if rc != RC_SUCCESS {
        if left(r) != 0 || tag != ST_NO_SESSIONS { return params, 0, rc, ERR_MALFORMED; }
        return params, 0, rc, ERR_TPM;
    }
    let ns = if active(s2) { 2 } else if active(s1) { 1 } else { 0 };
    if tag != (if ns > 0 { ST_SESSIONS } else { ST_NO_SESSIONS }) { return params, 0, rc, ERR_MALFORMED; }
    var handle: u32 = 0;
    for i in c.nrh { handle = get_u32(r); }
    var pbytes = r.d[0..0];
    if ns > 0 {
        let psize = get_u32(r) as i64;
        pbytes = get_bytes(r, psize);
    } else {
        pbytes = get_bytes(r, left(r));
    }
    if !r.ok { return params, 0, rc, ERR_MALFORMED; }
    params.append(pbytes);
    var rphash_in: u8[>..] = [];
    put_u32(rphash_in, 0);
    put_u32(rphash_in, c.cc);
    rphash_in.append(pbytes);
    fn check(s: Session&, i: i64) -> i64 {
        let nonce = get_2b(r, 64);
        let attrs = get_u8(r);
        let mac = get_2b(r, 64);
        if !r.ok { return ERR_MALFORMED; }
        let authorizes = i < c.nauth;
        let e = if i < hs.len { hs[i] } else { Entity { .. } };
        if s.kind == SESSION_PW {
            if nonce.len != 0 || mac.len != 0 { return ERR_MALFORMED; }
            return OK;
        }
        s.nonce_tpm.clear();
        if nonce.len > s.nonce_tpm.cap { return ERR_MALFORMED; }
        s.nonce_tpm.append(nonce);
        let policy_pw = s.kind == SESSION_POLICY && s.password_needed && authorizes;
        let need_mac = s.kind == SESSION_HMAC || (s.kind == SESSION_POLICY && !policy_pw && (s.key.len > 0 || (authorizes && s.auth_value_needed)));
        if mac.len > 0 || need_mac {
            var m: u8[>..] = [];
            m.append(hash(s.hash, rphash_in));
            m.append(s.nonce_tpm);
            m.append(s.nonce_caller);
            m.push(attrs);
            let want = hmac(s.hash, hmac_key(s, e, authorizes), m);
            if mac != want { return ERR_INTEGRITY; }
        }
        if (attrs & ATTR_CONTINUE) == 0 { s.kind = SESSION_NONE; }
        if s.kind == SESSION_POLICY && authorizes {
            s.auth_value_needed = false;
            s.password_needed = false;
        }
        return OK;
    }
    // Decrypt the first response parameter.
    fn decrypt(s: Session&, i: i64) -> i64 {
        if (s.attrs & ATTR_ENCRYPT) != 0 && s.sym_bits != 0 {
            if params.len < 2 || be16(params, 0) as i64 + 2 > params.len { return ERR_MALFORMED; }
            let e = if i < hs.len { hs[i] } else { Entity { .. } };
            let v = session_value(s, e, i < c.nauth);
            let n = be16(params, 0) as i64;
            param_crypt(s, v, s.nonce_tpm, s.nonce_caller, params[2..2 + n], true);
        }
        return OK;
    }
    if ns >= 1 { let e1 = check(s1, 0); if e1 != OK { return params, 0, rc, e1; } }
    if ns >= 2 { let e2 = check(s2, 1); if e2 != OK { return params, 0, rc, e2; } }
    if left(r) != 0 { return params, 0, rc, ERR_MALFORMED; }
    if ns >= 1 { decrypt(s1, 0); }
    if ns >= 2 { decrypt(s2, 1); }
    return params, handle, rc, OK;
}

// Runs a command: its response parameters and handle, and OK or an error
// (ERR_TPM with the response code in t.rc).
fn execute(t: Tpm&, c: Cmd, hs: const Entity[:], s1: Session&, s2: Session&, params: const u8[:]) -> u8[>..], u32, i64 {
    t.rc = 0;
    var none: u8[>..] = [];
    let cmd, e = build_command(c, hs, s1, s2, params);
    if e != OK { return none, 0, e; }
    let rsp, et = transmit(t, cmd);
    if et != OK { return none, 0, et; }
    let p, h, rc, ep = parse_response(c, hs, s1, s2, rsp);
    t.rc = rc;
    return p, h, ep;
}

// A command without sessions.
fn execute0(t: Tpm&, cc: u32, hs: const Entity[:], params: const u8[:], nrh: i64 = 0) -> u8[>..], u32, i64 {
    var a = no_session();
    var b = no_session();
    return execute(t, Cmd { cc: cc, nrh: nrh }, hs, a, b, params);
}

// --- Salts and seeds -----------------------------------------------------------------

// A secret for a TPM key and its encryption to that key (Part 1 §11.4.10.2,
// §B.10.3, §C.6.4): for an RSA key a random nameAlg-sized seed, encrypted
// by RSA-OAEP with the nameAlg and the label; for an ECC key, KDFe over an
// ephemeral ECDH, the encryption being the ephemeral point (a TPMS_ECC_POINT).
// label is "SECRET" for salts, "IDENTITY" for credentials, "DUPLICATE" for
// duplication. eph (ECC) fixes the ephemeral private key, rnd (RSA) the
// seed and OAEP's seed (twice the digest size), for known-answer tests;
// empty, they are random.
fn secret_to(pub: Public, label: const u8[:], eph: const u8[:] = "", rnd: const u8[:] = "") -> u8[>..], u8[>..], i64 {
    var seed: u8[>..] = [];
    var enc:  u8[>..] = [];
    let hl = digest_size(pub.name_alg);
    if hl == 0 { return seed, enc, ERR_UNSUPPORTED; }
    var lbl: u8[>..] = [];
    lbl.append(label);
    if label.len == 0 || label[label.len - 1] != 0 { lbl.push(0); }
    if pub.kind == ALG_RSA {
        let key, ok = rsa_public(pub);
        if !ok { return seed, enc, ERR_UNSUPPORTED; }
        if rnd.len == 2 * hl {
            seed.append(rnd[..hl]);
            enc = bignum::rsa_encrypt_oaep_with_seed(key, seed, lbl, rnd[hl..], hash_id(pub.name_alg));
        } else {
            seed.resize(hl, 0);
            entropy::random_bytes(seed);
            enc = bignum::rsa_encrypt_oaep(key, seed, lbl, hash_id(pub.name_alg));
        }
        return seed, enc, OK;
    }
    if pub.kind != ALG_ECC || !curve_supported(pub.curve) { return seed, enc, ERR_UNSUPPORTED; }
    let curve = curve_of(pub.curve);
    let n = curve_len(pub.curve);
    let peer, okp = ecc_point(pub);
    if !okp { return seed, enc, ERR_MALFORMED; }
    var sk: u8[>..] = [];
    var pk: u8[>..] = [];
    if eph.len > 0 {
        let k, okk = bignum::ec_scalar(curve, eph);
        if !okk { return seed, enc, ERR_ARG; }
        sk.append(eph);
        pk = bignum::ec_public_key(curve, eph);
    } else {
        let a, b = bignum::ec_keypair(curve);
        sk.append(a);
        pk.append(b);
    }
    let z, okz = bignum::ecdh_shared(curve, sk, peer);
    if !okz { return seed, enc, ERR_MALFORMED; }
    seed = kdfe(pub.name_alg, z, label, pk[1..1 + n], peer[1..1 + n], 8 * hl);
    put_2b(enc, pk[1..1 + n]);
    put_2b(enc, pk[1 + n..]);
    return seed, enc, OK;
}

// --- StartAuthSession ----------------------------------------------------------------

// How to start a session: its hash, the AES key size for parameter
// encryption (0: none), a salt to a loaded TPM key (its handle and public
// area), and an entity to bind to.
struct SessionOpts {
    hash:        u16    = ALG_SHA256,
    sym_bits:    u16    = 128,
    salt:        bool   = false,
    salt_key:    Entity = Entity { .. },
    salt_pub:    Public = Public { .. },
    bind:        bool   = false,
    bind_entity: Entity = Entity { .. },
    attrs:       u8     = ATTR_CONTINUE,
}

fn put_sym(out: u8[>..]&, bits: u16) {
    if bits == 0 { put_u16(out, ALG_NULL); }
    else { put_u16(out, ALG_AES); put_u16(out, bits); put_u16(out, ALG_CFB); }
}

// TPM2_StartAuthSession: an unbound, unsalted HMAC, policy or trial session.
fn start_session(t: Tpm&, kind: i64, hash: u16 = ALG_SHA256, sym_bits: u16 = 128) -> Session, i64 {
    let o = SessionOpts { hash: hash, sym_bits: sym_bits, .. };
    return start_session_with(t, kind, o);
}

// TPM2_StartAuthSession with the options: salted, bound, its hash and symmetric.
fn start_session_with(t: Tpm&, kind: i64, o: const SessionOpts&) -> Session, i64 {
    var s = Session { kind: kind, hash: o.hash, sym_bits: o.sym_bits, attrs: o.attrs, .. };
    if digest_size(o.hash) == 0 || (kind != SESSION_HMAC && kind != SESSION_POLICY && kind != SESSION_TRIAL) {
        return s, ERR_ARG;
    }
    new_nonce(s);
    var salt: u8[>..] = [];
    var enc:  u8[>..] = [];
    if o.salt {
        let a, b, e = secret_to(o.salt_pub, "SECRET");
        if e != OK { return s, e; }
        salt.append(a);
        enc.append(b);
    }
    var hs: Entity[2] = [Entity { .. }, Entity { .. }];
    hs[0] = if o.salt { o.salt_key } else { entity(RH_NULL) };
    hs[1] = if o.bind { o.bind_entity } else { entity(RH_NULL) };
    var p: u8[>..] = [];
    put_2b(p, s.nonce_caller);
    put_2b(p, enc);
    put_u8(p, if kind == SESSION_HMAC { 0 } else if kind == SESSION_POLICY { 1 } else { 3 });
    put_sym(p, o.sym_bits);
    put_u16(p, o.hash);
    let rp, h, err = execute0(t, CC_StartAuthSession, hs, p, 1);
    if err != OK { return s, err; }
    var r = reader(rp);
    let nonce = get_2b(r, 64);
    if !r.ok || left(r) != 0 { return s, ERR_MALFORMED; }
    s.handle = h;
    s.nonce_tpm.append(nonce);
    if o.bind || o.salt {
        var k: u8[>..] = [];
        if o.bind { k.append(o.bind_entity.auth); }
        k.append(salt);
        let key = kdfa(o.hash, k, "ATH", s.nonce_tpm, s.nonce_caller, 8 * digest_size(o.hash));
        s.key.append(key);
    }
    if o.bind {
        s.bound = true;
        s.bind_name = o.bind_entity.name;
        s.bind_auth = o.bind_entity.auth;
    }
    return s, OK;
}
