// tpm2.commands: the TPM's commands for start-up, randomness and
// capabilities, objects (CreatePrimary, Create, Load, CreateLoaded,
// LoadExternal, ReadPublic, EvictControl, FlushContext, ContextSave and
// ContextLoad), keys (Sign, VerifySignature, RSA_Encrypt, RSA_Decrypt,
// ECDH_ZGen, ECDH_KeyGen, Hash, HMAC, Unseal), PCRs (PCR_Read, PCR_Extend,
// PCR_Event, PCR_Reset) and NV indices (NV_DefineSpace, NV_Write, NV_Read,
// NV_ReadPublic, NV_UndefineSpace, NV_Increment, NV_Extend), reading EK
// certificates from their standard indices.
//
// Every Name the TPM returns for an object or NV index is checked against
// the one computed here from its public area (ERR_NAME when they differ).
// A command that needs authorization takes the Session to authorize with:
// pw() for a password, or one from start_session.

namespace tpm2;

import std;
import tpm2;
import tpm2.transport;
import tpm2.session;
import crypto.bignum;
import crypto.bignum.ec;
import crypto.x509;
import crypto.x509.keys;

// --- Structures ---------------------------------------------------------------------

// A TPMT_TK_CREATION, TPMT_TK_VERIFIED, TPMT_TK_AUTH or TPMT_TK_HASHCHECK.
struct Ticket { tag: u16 = ST_HASHCHECK, hierarchy: u32 = RH_NULL, digest: u8[..64] = [] }

fn put_ticket(out: u8[>..]&, k: Ticket) {
    put_u16(out, k.tag);
    put_u32(out, k.hierarchy);
    put_2b(out, k.digest);
}

fn read_ticket(r: Reader&) -> Ticket {
    var k = Ticket { .. };
    k.tag = get_u16(r);
    k.hierarchy = get_u32(r);
    read_into(r, k.digest);
    return k;
}

// An object made or loaded: its handle (0 for Create's, not loaded), its
// public area and Name, and from Create and CreatePrimary its private
// blob, creation data, creation hash and ticket (for CertifyCreation).
struct Object {
    handle:        u32        = 0,
    public:        Public     = Public { .. },
    name:          u8[..66]   = [],
    private:       u8[..2048] = [],
    creation_data: u8[..1024] = [],
    creation_hash: u8[..64]   = [],
    ticket:        Ticket     = Ticket { .. },
}

// The Entity of a loaded object, with the authValue it was made with.
fn object_of(o: const Object&, auth: const u8[:] = "") -> Entity {
    return object_entity(o.handle, o.name, auth);
}

fn no_handles() -> Entity[0] { [] }

// --- Start-up, randomness, capabilities -----------------------------------------------

// TPM2_Startup(CLEAR or STATE). A TPM already started (TPM_RC_INITIALIZE,
// as swtpm answers when it was started with startup-clear) is OK.
fn startup(t: Tpm&, su: u16 = SU_CLEAR) -> i64 {
    var p: u8[>..] = [];
    put_u16(p, su);
    let hs = no_handles();
    let rp, h, e = execute0(t, CC_Startup, hs, p);
    if e == ERR_TPM && t.rc == RC_INITIALIZE { return OK; }
    return e;
}

fn shutdown(t: Tpm&, su: u16 = SU_CLEAR) -> i64 {
    var p: u8[>..] = [];
    put_u16(p, su);
    let hs = no_handles();
    let rp, h, e = execute0(t, CC_Shutdown, hs, p);
    return e;
}

fn self_test(t: Tpm&, full: bool = true) -> i64 {
    var p: u8[>..] = [];
    put_u8(p, if full { 1 } else { 0 });
    let hs = no_handles();
    let rp, h, e = execute0(t, CC_SelfTest, hs, p);
    return e;
}

// n random bytes, asked for in pieces as large as the TPM gives.
fn get_random(t: Tpm&, n: i64) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let hs = no_handles();
    while out.len < n {
        var p: u8[>..] = [];
        put_u16(p, min(n - out.len, 64) as u16);
        let rp, h, e = execute0(t, CC_GetRandom, hs, p);
        if e != OK { return out, e; }
        var r = reader(rp);
        let b = get_2b(r, 64);
        if !r.ok || left(r) != 0 || b.len == 0 || b.len > n - out.len { out.clear(); return out, ERR_MALFORMED; }
        out.append(b);
    }
    return out, OK;
}

fn stir_random(t: Tpm&, data: const u8[:]) -> i64 {
    var p: u8[>..] = [];
    put_2b(p, data);
    let hs = no_handles();
    let rp, h, e = execute0(t, CC_StirRandom, hs, p);
    return e;
}

// TPM2_GetCapability: moreData, and the TPMS_CAPABILITY_DATA's bytes after
// the capability (its TPML_*).
fn get_capability(t: Tpm&, cap: u32, prop: u32, count: u32) -> bool, u8[>..], i64 {
    var data: u8[>..] = [];
    var p:    u8[>..] = [];
    put_u32(p, cap);
    put_u32(p, prop);
    put_u32(p, count);
    let hs = no_handles();
    let rp, h, e = execute0(t, CC_GetCapability, hs, p);
    if e != OK { return false, data, e; }
    var r = reader(rp);
    let more = get_u8(r);
    let c = get_u32(r);
    if !r.ok || c != cap || more > 1 { return false, data, ERR_MALFORMED; }
    data.append(get_bytes(r, left(r)));
    return more == 1, data, OK;
}

// One TPM property (TPM_PT_*), from CAP_TPM_PROPERTIES.
fn tpm_property(t: Tpm&, pt: u32) -> u32, i64 {
    let more, data, e = get_capability(t, CAP_TPM_PROPERTIES, pt, 1);
    if e != OK { return 0, e; }
    var r = reader(data);
    let n = get_u32(r);
    if !r.ok || n < 1 { return 0, ERR_MALFORMED; }
    let p = get_u32(r);
    let v = get_u32(r);
    if !r.ok || p != pt { return 0, ERR_MALFORMED; }
    return v, OK;
}

// The manufacturer's four letters (TPM_PT_MANUFACTURER).
fn manufacturer(t: Tpm&) -> u8[..4], i64 {
    var out: u8[..4] = [];
    let v, e = tpm_property(t, PT_MANUFACTURER);
    if e != OK { return out, e; }
    for i in 4 {
        let c = (v >> ((24 - 8 * i) as! u32)) as! u8;
        if c != 0 && c != ' ' { out.push(c); }
    }
    return out, OK;
}

// The handles in use from first on (CAP_HANDLES): persistent ones from
// 0x81000000, NV indices from 0x01000000, ...
fn get_handles(t: Tpm&, first: u32) -> u32[>..], i64 {
    var out: u32[>..] = [];
    var next = first;
    loop {
        let more, data, e = get_capability(t, CAP_HANDLES, next, 64);
        if e != OK { return out, e; }
        var r = reader(data);
        let n = get_u32(r);
        if n > 256 { return out, ERR_MALFORMED; }
        for i in n as i64 {
            let h = get_u32(r);
            if r.ok && handle_type(h) == handle_type(first) { out.push(h); }
        }
        if !r.ok || left(r) != 0 { return out, ERR_MALFORMED; }
        if !more || n == 0 || out.len == 0 { break; }
        next = out[out.len - 1] + 1;
    }
    return out, OK;
}

// TPM2_DictionaryAttackLockReset with the lockout hierarchy's authorization:
// the failed-authorization count back to zero.
fn da_lock_reset(t: Tpm&, lockout_auth: Entity, s: Session&) -> i64 {
    var none = no_session();
    let hs = [lockout_auth];
    let rp, h, e = execute(t, Cmd { cc: CC_DictionaryAttackLockReset, nauth: 1 }, hs, s, none, "");
    return e;
}

// TPM2_FlushContext: an object or session out of the TPM. t.rc keeps the
// response code of the command before, so cleaning up after a failure
// does not hide why it failed.
fn flush(t: Tpm&, handle: u32) -> i64 {
    var p: u8[>..] = [];
    put_u32(p, handle);
    let hs = no_handles();
    let rc = t.rc;
    let rp, h, e = execute0(t, CC_FlushContext, hs, p);
    t.rc = rc;
    return e;
}

// --- Objects -------------------------------------------------------------------------------

fn put_sensitive_create(p: u8[>..]&, auth: const u8[:], data: const u8[:]) {
    var sc: u8[>..] = [];
    put_2b(sc, auth);
    put_2b(sc, data);
    put_2b(p, sc);
}

fn put_public_2b(p: u8[>..]&, pub: Public) {
    put_2b(p, marshal_public(pub));
}

// Reads outPublic, creationData, creationHash and creationTicket into o.
fn read_creation(r: Reader&, o: Object&) {
    let pub, pb = read_public_2b(r);
    o.public = pub;
    read_into(r, o.creation_data);
    read_into(r, o.creation_hash);
    o.ticket = read_ticket(r);
}

// Whether the TPM made what the template asked for: same type, nameAlg,
// attributes, policy and parameters.
fn matches_template(p: Public, tmpl: Public) -> bool {
    p.kind == tmpl.kind && p.name_alg == tmpl.name_alg && p.attrs == tmpl.attrs && p.policy == tmpl.policy
        && p.sym_alg == tmpl.sym_alg && p.scheme == tmpl.scheme && p.curve == tmpl.curve
        && (p.kind != ALG_RSA || p.rsa_bits == tmpl.rsa_bits)
}

// TPM2_CreatePrimary under a hierarchy (owner(), endorsement(), ...): the
// key's handle, public area and Name (checked), and its creation data.
// auth is the new key's authValue, data a sealed object's data; creation_pcrs
// the PCRs whose digest goes into the creation data.
fn create_primary(t: Tpm&, hierarchy: Entity, s: Session&, tmpl: Public, auth: const u8[:] = "",
                  data: const u8[:] = "", outside: const u8[:] = "", creation_pcrs: const PcrSel[:] = []) -> Object, i64 {
    var o = Object { .. };
    var p: u8[>..] = [];
    put_sensitive_create(p, auth, data);
    put_public_2b(p, tmpl);
    put_2b(p, outside);
    put_pcr_selection(p, creation_pcrs);
    var none = no_session();
    let hs = [hierarchy];
    let rp, h, e = execute(t, Cmd { cc: CC_CreatePrimary, nauth: 1, nrh: 1, enc_in: true, enc_out: true }, hs, s, none, p);
    if e != OK { return o, e; }
    var r = reader(rp);
    read_creation(r, o);
    read_into(r, o.name);
    if !r.ok || left(r) != 0 { return o, ERR_MALFORMED; }
    o.handle = h;
    if public_name(o.public) != o.name { return o, ERR_NAME; }
    if !matches_template(o.public, tmpl) { return o, ERR_MALFORMED; }
    return o, OK;
}

// TPM2_Create under a loaded parent: the new object's private and public
// parts (not loaded: load() them) and its creation data.
fn create(t: Tpm&, parent: Entity, s: Session&, tmpl: Public, auth: const u8[:] = "",
          data: const u8[:] = "", outside: const u8[:] = "", creation_pcrs: const PcrSel[:] = []) -> Object, i64 {
    var o = Object { .. };
    var p: u8[>..] = [];
    put_sensitive_create(p, auth, data);
    put_public_2b(p, tmpl);
    put_2b(p, outside);
    put_pcr_selection(p, creation_pcrs);
    var none = no_session();
    let hs = [parent];
    let rp, h, e = execute(t, Cmd { cc: CC_Create, nauth: 1, enc_in: true, enc_out: true }, hs, s, none, p);
    if e != OK { return o, e; }
    var r = reader(rp);
    read_into(r, o.private);
    read_creation(r, o);
    if !r.ok || left(r) != 0 { return o, ERR_MALFORMED; }
    if !matches_template(o.public, tmpl) { return o, ERR_MALFORMED; }
    o.name = public_name(o.public);
    return o, OK;
}

// TPM2_Load: o (from create) into the TPM under its parent; o.handle is set
// and the TPM's Name checked against o's.
fn load(t: Tpm&, parent: Entity, s: Session&, o: Object&) -> i64 {
    var p: u8[>..] = [];
    put_2b(p, o.private);
    put_public_2b(p, o.public);
    var none = no_session();
    let hs = [parent];
    let rp, h, e = execute(t, Cmd { cc: CC_Load, nauth: 1, nrh: 1, enc_in: true, enc_out: true }, hs, s, none, p);
    if e != OK { return e; }
    var r = reader(rp);
    let name = get_2b(r, MAX_NAME);
    if !r.ok || left(r) != 0 { return ERR_MALFORMED; }
    o.handle = h;
    if name != public_name(o.public) { return ERR_NAME; }
    o.name = public_name(o.public);
    return OK;
}

// TPM2_CreateLoaded under a parent (an ordinary key here): Create and Load
// in one.
fn create_loaded(t: Tpm&, parent: Entity, s: Session&, tmpl: Public, auth: const u8[:] = "",
                 data: const u8[:] = "") -> Object, i64 {
    var o = Object { .. };
    var p: u8[>..] = [];
    put_sensitive_create(p, auth, data);
    put_public_2b(p, tmpl);
    var none = no_session();
    let hs = [parent];
    let rp, h, e = execute(t, Cmd { cc: CC_CreateLoaded, nauth: 1, nrh: 1, enc_in: true, enc_out: true }, hs, s, none, p);
    if e != OK { return o, e; }
    var r = reader(rp);
    read_into(r, o.private);
    let pub, pb = read_public_2b(r);
    o.public = pub;
    read_into(r, o.name);
    if !r.ok || left(r) != 0 { return o, ERR_MALFORMED; }
    o.handle = h;
    if public_name(o.public) != o.name { return o, ERR_NAME; }
    if !matches_template(o.public, tmpl) { return o, ERR_MALFORMED; }
    return o, OK;
}

// TPM2_LoadExternal of a public key alone, in a hierarchy (RH_NULL by
// default): for VerifySignature, PolicySigned and PolicyAuthorize.
fn load_external(t: Tpm&, pub: Public, hierarchy: u32 = RH_NULL) -> Object, i64 {
    var o = Object { public: pub, .. };
    var p: u8[>..] = [];
    put_u16(p, 0);                 // no TPM2B_SENSITIVE
    put_public_2b(p, pub);
    put_u32(p, hierarchy);
    let hs = no_handles();
    let rp, h, e = execute0(t, CC_LoadExternal, hs, p, 1);
    if e != OK { return o, e; }
    var r = reader(rp);
    read_into(r, o.name);
    if !r.ok || left(r) != 0 { return o, ERR_MALFORMED; }
    o.handle = h;
    if public_name(pub) != o.name { return o, ERR_NAME; }
    return o, OK;
}

// TPM2_ReadPublic: a loaded object's public area, Name and qualified Name;
// the Name is checked.
fn read_public_tpm(t: Tpm&, handle: u32) -> Object, u8[..66], i64 {
    var o = Object { handle: handle, .. };
    var qn: u8[..66] = [];
    let hs = [entity(handle)];
    let rp, h, e = execute0(t, CC_ReadPublic, hs, "");
    if e != OK { return o, qn, e; }
    var r = reader(rp);
    let pub, pb = read_public_2b(r);
    o.public = pub;
    read_into(r, o.name);
    read_into(r, qn);
    if !r.ok || left(r) != 0 { return o, qn, ERR_MALFORMED; }
    if public_name(o.public) != o.name { return o, qn, ERR_NAME; }
    return o, qn, OK;
}

// TPM2_EvictControl: a loaded object made persistent at `persistent`
// (0x81xxxxxx), or, given a persistent object, removed.
fn evict_control(t: Tpm&, auth: Entity, s: Session&, object: Entity, persistent: u32) -> i64 {
    var p: u8[>..] = [];
    put_u32(p, persistent);
    var none = no_session();
    let hs = [auth, object];
    let rp, h, e = execute(t, Cmd { cc: CC_EvictControl, nauth: 1 }, hs, s, none, p);
    return e;
}

// A TPMS_CONTEXT from ContextSave, for ContextLoad.
struct Context { sequence: u64 = 0, saved_handle: u32 = 0, hierarchy: u32 = 0, blob: u8[..5120] = [] }

fn context_save(t: Tpm&, handle: u32) -> Context, i64 {
    var c = Context { .. };
    let hs = [entity(handle)];
    let rp, h, e = execute0(t, CC_ContextSave, hs, "");
    if e != OK { return c, e; }
    var r = reader(rp);
    c.sequence = get_u64(r);
    c.saved_handle = get_u32(r);
    c.hierarchy = get_u32(r);
    read_into(r, c.blob);
    if !r.ok || left(r) != 0 { return c, ERR_MALFORMED; }
    return c, OK;
}

fn context_load(t: Tpm&, c: const Context&) -> u32, i64 {
    var p: u8[>..] = [];
    put_u64(p, c.sequence);
    put_u32(p, c.saved_handle);
    put_u32(p, c.hierarchy);
    put_2b(p, c.blob);
    let hs = no_handles();
    let rp, h, e = execute0(t, CC_ContextLoad, hs, p, 1);
    if e != OK { return 0, e; }
    if rp.len != 0 { return 0, ERR_MALFORMED; }
    return h, OK;
}

// --- Keys --------------------------------------------------------------------------------

fn put_sig_scheme(p: u8[>..]&, scheme: u16, h: u16) {
    put_u16(p, scheme);
    if scheme != ALG_NULL { put_u16(p, h); }
}

// TPM2_Sign of a digest by a loaded key, by scheme (ALG_RSASSA, ALG_RSAPSS,
// ALG_ECDSA; ALG_NULL for the key's own) with hash h. An unrestricted key
// signs with the null ticket; a restricted one needs the ticket from Hash.
fn sign(t: Tpm&, key: Entity, s: Session&, digest: const u8[:], scheme: u16, h: u16,
        ticket: Ticket = Ticket { .. }) -> Signature, i64 {
    var p: u8[>..] = [];
    put_2b(p, digest);
    put_sig_scheme(p, scheme, h);
    put_ticket(p, ticket);
    var none = no_session();
    let hs = [key];
    let rp, hh, e = execute(t, Cmd { cc: CC_Sign, nauth: 1, enc_in: true }, hs, s, none, p);
    if e != OK { return Signature { .. }, e; }
    var r = reader(rp);
    let sig = read_signature(r);
    if !r.ok || left(r) != 0 { return sig, ERR_MALFORMED; }
    return sig, OK;
}

// --- Keys held in the TPM, for TLS, SSH, x509 and JWS -------------------------------------

// The x509 key standing for a TPM signing key in a configuration (a TLS
// server's, an SSH host's, an issuer's): its public area as an
// x509::external_key. The signing is then done by sign_data, passed as the
// signer to the call that signs.
fn x509_key(p: Public) -> x509::PrivateKey, bool {
    let spki, ok = public_to_spki(p);
    if !ok { return x509::empty_key(), false; }
    let k, okk = x509::external_key(spki);
    return k, okk;
}

// A signer for a loaded, unrestricted TPM signing key (x509::sign_data
// describes signers): x509's algorithm and hash as TPM2_Sign's scheme
// (SIG_ECDSA as ALG_ECDSA, SIG_RSA_PKCS1 as ALG_RSASSA, SIG_RSA_PSS as
// ALG_RSAPSS; SHA-256, SHA-384, SHA-512), data the digest, and the answer
// as x509 signs (ECDSA as DER). Empty when the TPM refuses, or for what a
// TPM does not sign (Ed25519, ML-DSA). The key's authorization is in key
// (object_of) and s; t and s are the caller's, which a block names:
//
//   tls::feed(c, cfg, input, out, app) { k, alg, h, data => tpm2::sign_data(t, key, s, alg, h, data) }
//
// A TPM's RSA-PSS salt may be as long as the key allows, not the hash's
// length that TLS 1.3 requires; such a TPM's RSA keys suit TLS 1.2 and
// PKCS #1 signatures, and its ECDSA keys TLS 1.3.
fn sign_data(t: Tpm&, key: Entity, s: Session&, alg: i64, h: i64, data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let scheme = if alg == x509::SIG_ECDSA { ALG_ECDSA } else if alg == x509::SIG_RSA_PKCS1 { ALG_RSASSA }
                 else if alg == x509::SIG_RSA_PSS { ALG_RSAPSS } else { ALG_NULL };
    let th = if h == 256 { ALG_SHA256 } else if h == 384 { ALG_SHA384 } else if h == 512 { ALG_SHA512 } else { ALG_NULL };
    if scheme == ALG_NULL || th == ALG_NULL || data.len != bignum::hash_len(h) { return out; }
    let sig, e = sign(t, key, s, data, scheme, th);
    if e != OK { return out; }
    if scheme == ALG_ECDSA {
        let n = ::max(sig.r.len, sig.s.len);
        if n == 0 || n > 66 { return out; }
        var raw: u8[>..] = [];
        for _ in n - sig.r.len { raw.push(0); }
        raw.append(sig.r);
        for _ in n - sig.s.len { raw.push(0); }
        raw.append(sig.s);
        out.append(bignum::ecdsa_sig_to_der(raw));
    } else {
        out.append(sig.sig);
    }
    return out;
}

// TPM2_VerifySignature: the TPM checks a signature with a loaded key and
// gives a TPMT_TK_VERIFIED ticket (for PolicyAuthorize).
fn verify_signature_tpm(t: Tpm&, key: Entity, digest: const u8[:], sig: Signature) -> Ticket, i64 {
    var p: u8[>..] = [];
    put_2b(p, digest);
    p.append(marshal_signature(sig));
    let hs = [key];
    let rp, h, e = execute0(t, CC_VerifySignature, hs, p);
    if e != OK { return Ticket { .. }, e; }
    var r = reader(rp);
    let k = read_ticket(r);
    if !r.ok || left(r) != 0 { return k, ERR_MALFORMED; }
    return k, OK;
}

fn put_rsa_decrypt_scheme(p: u8[>..]&, scheme: u16, h: u16) {
    put_u16(p, scheme);
    if scheme == ALG_OAEP { put_u16(p, h); }
}

// TPM2_RSA_Encrypt with a loaded key's public part: scheme ALG_OAEP (with
// hash h), ALG_RSAES, or ALG_NULL for the key's. A non-empty label gets its
// terminating 0 here when it has none.
fn rsa_encrypt(t: Tpm&, key: Entity, msg: const u8[:], scheme: u16 = ALG_OAEP, h: u16 = ALG_SHA256,
               label: const u8[:] = "") -> u8[>..], i64 {
    var out: u8[>..] = [];
    var p:   u8[>..] = [];
    put_2b(p, msg);
    put_rsa_decrypt_scheme(p, scheme, h);
    var lbl: u8[>..] = [];
    lbl.append(label);
    if label.len > 0 && label[label.len - 1] != 0 { lbl.push(0); }
    put_2b(p, lbl);
    let hs = [key];
    let rp, hh, e = execute0(t, CC_RSA_Encrypt, hs, p);
    if e != OK { return out, e; }
    var r = reader(rp);
    out.append(get_2b(r, MAX_RSA_BYTES));
    if !r.ok || left(r) != 0 { out.clear(); return out, ERR_MALFORMED; }
    return out, OK;
}

// TPM2_RSA_Decrypt with a loaded key.
fn rsa_decrypt(t: Tpm&, key: Entity, s: Session&, ct: const u8[:], scheme: u16 = ALG_OAEP, h: u16 = ALG_SHA256,
               label: const u8[:] = "") -> u8[>..], i64 {
    var out: u8[>..] = [];
    var p:   u8[>..] = [];
    put_2b(p, ct);
    put_rsa_decrypt_scheme(p, scheme, h);
    var lbl: u8[>..] = [];
    lbl.append(label);
    if label.len > 0 && label[label.len - 1] != 0 { lbl.push(0); }
    put_2b(p, lbl);
    var none = no_session();
    let hs = [key];
    let rp, hh, e = execute(t, Cmd { cc: CC_RSA_Decrypt, nauth: 1, enc_in: true, enc_out: true }, hs, s, none, p);
    if e != OK { return out, e; }
    var r = reader(rp);
    out.append(get_2b(r, MAX_RSA_BYTES));
    if !r.ok || left(r) != 0 { out.clear(); return out, ERR_MALFORMED; }
    return out, OK;
}

fn put_ecc_point_2b(p: u8[>..]&, x: const u8[:], y: const u8[:]) {
    var pt: u8[>..] = [];
    put_2b(pt, x);
    put_2b(pt, y);
    put_2b(p, pt);
}

// A TPM2B_ECC_POINT: x and y, the inner size checked.
fn read_ecc_point_2b(r: Reader&) -> u8[..66], u8[..66] {
    var x: u8[..66] = [];
    var y: u8[..66] = [];
    let b = get_2b(r, 4 + 2 * MAX_ECC_BYTES);
    var inner = reader(b);
    read_into(inner, x);
    read_into(inner, y);
    if !inner.ok || left(inner) != 0 { r.ok = false; }
    return x, y;
}

// TPM2_ECDH_ZGen: the shared point d * (x, y) with a loaded ECC decryption key.
fn ecdh_zgen(t: Tpm&, key: Entity, s: Session&, x: const u8[:], y: const u8[:]) -> u8[..66], u8[..66], i64 {
    var p: u8[>..] = [];
    put_ecc_point_2b(p, x, y);
    var none = no_session();
    let hs = [key];
    let rp, h, e = execute(t, Cmd { cc: CC_ECDH_ZGen, nauth: 1, enc_in: true, enc_out: true }, hs, s, none, p);
    var zx: u8[..66] = [];
    var zy: u8[..66] = [];
    if e != OK { return zx, zy, e; }
    var r = reader(rp);
    let a, b = read_ecc_point_2b(r);
    if !r.ok || left(r) != 0 { return zx, zy, ERR_MALFORMED; }
    return a, b, OK;
}

// TPM2_Hash in a hierarchy: the digest and its TPMT_TK_HASHCHECK (for a
// restricted key's Sign; a null ticket when the data begins with
// TPM_GENERATED_VALUE).
fn hash_tpm(t: Tpm&, data: const u8[:], alg: u16, hierarchy: u32 = RH_OWNER) -> u8[..64], Ticket, i64 {
    var d: u8[..64] = [];
    var p: u8[>..]  = [];
    put_2b(p, data);
    put_u16(p, alg);
    put_u32(p, hierarchy);
    let hs = no_handles();
    let rp, h, e = execute0(t, CC_Hash, hs, p);
    if e != OK { return d, Ticket { .. }, e; }
    var r = reader(rp);
    read_into(r, d);
    let k = read_ticket(r);
    if !r.ok || left(r) != 0 { return d, k, ERR_MALFORMED; }
    return d, k, OK;
}

// TPM2_HMAC with a loaded HMAC key.
fn hmac_tpm(t: Tpm&, key: Entity, s: Session&, data: const u8[:], alg: u16) -> u8[..64], i64 {
    var d: u8[..64] = [];
    var p: u8[>..]  = [];
    put_2b(p, data);
    put_u16(p, alg);
    var none = no_session();
    let hs = [key];
    let rp, h, e = execute(t, Cmd { cc: CC_HMAC, nauth: 1, enc_in: true, enc_out: true }, hs, s, none, p);
    if e != OK { return d, e; }
    var r = reader(rp);
    read_into(r, d);
    if !r.ok || left(r) != 0 { return d, ERR_MALFORMED; }
    return d, OK;
}

// TPM2_Unseal: a sealed object's data.
fn unseal(t: Tpm&, item: Entity, s: Session&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    var none = no_session();
    let hs = [item];
    let rp, h, e = execute(t, Cmd { cc: CC_Unseal, nauth: 1, enc_out: true }, hs, s, none, "");
    if e != OK { return out, e; }
    var r = reader(rp);
    out.append(get_2b(r, 128));
    if !r.ok || left(r) != 0 { out.clear(); return out, ERR_MALFORMED; }
    return out, OK;
}

// --- PCRs ------------------------------------------------------------------------------------

// PCR values from PCR_Read: for each bank of the selection, each selected
// PCR in order, and the update counter. A TPML_DIGEST holds at most 8
// digests, so at most 8 PCRs are asked for at a time, and again for what
// the TPM left out. ERR_UNSUPPORTED when the TPM returns none of what is
// asked: a bank it has not allocated.
fn pcr_read(t: Tpm&, sel: const PcrSel[:]) -> u8[..64][>..], u32, i64 {
    var vals: u8[..64][>..] = [];
    var want: PcrSel[..4]   = [];
    if sel.len > 4 { return vals, 0, ERR_ARG; }
    for s in sel { want.push(s); }
    // Per bank, what came: one u8[..64] per PCR index, kept until the end.
    var got: u8[..64][>..] = [];
    for i in want.len * 24 { got.push([]); }
    var counter: u32 = 0;
    let hs = no_handles();
    loop {
        var rest = 0;
        for s in want { if s.mask != 0 { rest++; } }
        if rest == 0 { break; }
        // At most 8 PCRs a request: a TPML_DIGEST holds no more.
        var req: PcrSel[..4] = [];
        var budget = 8;
        for s in want {
            var m: u32 = 0;
            for i in pcr_list(s.mask) { if budget > 0 { m |= (1 as u32) << (i as! u32); budget--; } }
            req.push(PcrSel { hash: s.hash, mask: m });
        }
        var p: u8[>..] = [];
        put_pcr_selection(p, req);
        let rp, h, e = execute0(t, CC_PCR_Read, hs, p);
        if e != OK { return vals, 0, e; }
        var r = reader(rp);
        counter = get_u32(r);
        let out_sel = read_pcr_selection(r);
        let n = get_u32(r);
        if !r.ok || n > 8 { return vals, 0, ERR_MALFORMED; }
        var count = 0;
        var di = 0;
        var digests: u8[..64][..8] = [];
        for i in n as i64 {
            var d: u8[..64] = [];
            read_into(r, d);
            digests.push(d);
        }
        if !r.ok || left(r) != 0 { return vals, 0, ERR_MALFORMED; }
        for os in out_sel {
            var bank = -1;
            for b in want.len { if want[b].hash == os.hash { bank = b; } }
            if bank < 0 || (os.mask & ~req[bank].mask) != 0 { return vals, 0, ERR_MALFORMED; }
            for i in pcr_list(os.mask) {
                if di >= digests.len || digests[di].len != digest_size(os.hash) { return vals, 0, ERR_MALFORMED; }
                got[bank * 24 + i] = digests[di];
                di++;
            }
            want[bank].mask &= ~os.mask;
            count += pcr_list(os.mask).len;
        }
        if di != digests.len { return vals, 0, ERR_MALFORMED; }
        // Nothing of what is left came back: a bank (or PCR) the TPM has not
        // allocated, which it answers with no bits selected.
        if count == 0 { return vals, 0, ERR_UNSUPPORTED; }
    }
    for b in sel.len {
        for i in pcr_list(sel[b].mask) { vals.push(got[b * 24 + i]); }
    }
    return vals, counter, OK;
}

// The values of one bank's PCRs, by mask.
fn pcr_read_bank(t: Tpm&, alg: u16, mask: u32) -> u8[..64][>..], i64 {
    let sel = [PcrSel { hash: alg, mask: mask }];
    let v, c, e = pcr_read(t, sel);
    return v, e;
}

// TPM2_PCR_Extend of one PCR in one bank by a digest.
fn pcr_extend(t: Tpm&, pcr: i64, s: Session&, alg: u16, digest: const u8[:]) -> i64 {
    if digest.len != digest_size(alg) { return ERR_ARG; }
    var p: u8[>..] = [];
    put_u32(p, 1);
    put_u16(p, alg);
    p.append(digest);
    var none = no_session();
    let hs = [pcr_entity(pcr)];
    let rp, h, e = execute(t, Cmd { cc: CC_PCR_Extend, nauth: 1 }, hs, s, none, p);
    return e;
}

// TPM2_PCR_Event: the TPM hashes data in every bank and extends the PCR.
fn pcr_event(t: Tpm&, pcr: i64, s: Session&, data: const u8[:]) -> i64 {
    var p: u8[>..] = [];
    put_2b(p, data);
    var none = no_session();
    let hs = [pcr_entity(pcr)];
    let rp, h, e = execute(t, Cmd { cc: CC_PCR_Event, nauth: 1, enc_in: true }, hs, s, none, p);
    return e;
}

fn pcr_reset(t: Tpm&, pcr: i64, s: Session&) -> i64 {
    var none = no_session();
    let hs = [pcr_entity(pcr)];
    let rp, h, e = execute(t, Cmd { cc: CC_PCR_Reset, nauth: 1 }, hs, s, none, "");
    return e;
}

// A PCR's value after extending it by digest, in software.
fn extend_value(alg: u16, old: const u8[:], digest: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    m.append(old);
    m.append(digest);
    return hash(alg, m);
}

// The digest of PCR values (concatenated in selection order), as a quote
// and PolicyPCR take it.
fn pcr_digest(alg: u16, vals: const u8[..64][:]) -> u8[>..] {
    var m: u8[>..] = [];
    for v in vals { m.append(v); }
    return hash(alg, m);
}

// --- NV ---------------------------------------------------------------------------------------

// TPMA_NV
let NV_PPWRITE:        u32 = 0x00000001;
let NV_OWNERWRITE:     u32 = 0x00000002;
let NV_AUTHWRITE:      u32 = 0x00000004;
let NV_POLICYWRITE:    u32 = 0x00000008;
let NV_TYPE_ORDINARY:  u32 = 0x00000000;
let NV_TYPE_COUNTER:   u32 = 0x00000010;
let NV_TYPE_BITS:      u32 = 0x00000020;
let NV_TYPE_EXTEND:    u32 = 0x00000040;
let NV_POLICY_DELETE:  u32 = 0x00000400;
let NV_WRITELOCKED:    u32 = 0x00000800;
let NV_WRITEALL:       u32 = 0x00001000;
let NV_WRITEDEFINE:    u32 = 0x00002000;
let NV_WRITE_STCLEAR:  u32 = 0x00004000;
let NV_GLOBALLOCK:     u32 = 0x00008000;
let NV_PPREAD:         u32 = 0x00010000;
let NV_OWNERREAD:      u32 = 0x00020000;
let NV_AUTHREAD:       u32 = 0x00040000;
let NV_POLICYREAD:     u32 = 0x00080000;
let NV_NO_DA:          u32 = 0x02000000;
let NV_ORDERLY:        u32 = 0x04000000;
let NV_CLEAR_STCLEAR:  u32 = 0x08000000;
let NV_READLOCKED:     u32 = 0x10000000;
let NV_WRITTEN:        u32 = 0x20000000;
let NV_PLATFORMCREATE: u32 = 0x40000000;
let NV_READ_STCLEAR:   u32 = 0x80000000;

// A TPMS_NV_PUBLIC.
struct NvPublic { index: u32 = 0, name_alg: u16 = ALG_SHA256, attrs: u32 = 0, policy: u8[..64] = [], size: u16 = 0 }

fn marshal_nv_public(n: NvPublic) -> u8[>..] {
    var out: u8[>..] = [];
    put_u32(out, n.index);
    put_u16(out, n.name_alg);
    put_u32(out, n.attrs);
    put_2b(out, n.policy);
    put_u16(out, n.size);
    return out;
}

fn read_nv_public(r: Reader&) -> NvPublic {
    var n = NvPublic { .. };
    n.index = get_u32(r);
    n.name_alg = get_u16(r);
    n.attrs = get_u32(r);
    read_into(r, n.policy);
    n.size = get_u16(r);
    return n;
}

// An NV index's Name: nameAlg || H(TPMS_NV_PUBLIC). It changes when the
// index is first written (TPMA_NV_WRITTEN).
fn nv_name(n: NvPublic) -> u8[..66] {
    var out: u8[..66] = [];
    if hash_id(n.name_alg) == 0 { return out; }
    var b: u8[>..] = [];
    put_u16(b, n.name_alg);
    b.append(hash(n.name_alg, marshal_nv_public(n)));
    out.append(b);
    return out;
}

// TPM2_NV_DefineSpace by a hierarchy (owner() or platform()).
fn nv_define(t: Tpm&, hierarchy: Entity, s: Session&, pub: NvPublic, auth: const u8[:] = "") -> i64 {
    var p: u8[>..] = [];
    put_2b(p, auth);
    put_2b(p, marshal_nv_public(pub));
    var none = no_session();
    let hs = [hierarchy];
    let rp, h, e = execute(t, Cmd { cc: CC_NV_DefineSpace, nauth: 1, enc_in: true }, hs, s, none, p);
    return e;
}

// TPM2_NV_UndefineSpace.
fn nv_undefine(t: Tpm&, hierarchy: Entity, s: Session&, index: u32) -> i64 {
    var none = no_session();
    let hs = [hierarchy, entity(index)];
    let rp, h, e = execute(t, Cmd { cc: CC_NV_UndefineSpace, nauth: 1 }, hs, s, none, "");
    return e;
}

// TPM2_NV_ReadPublic: the index's public area and Name (checked).
fn nv_read_public(t: Tpm&, index: u32) -> NvPublic, u8[..66], i64 {
    var name: u8[..66] = [];
    let hs = [entity(index)];
    let rp, h, e = execute0(t, CC_NV_ReadPublic, hs, "");
    if e != OK { return NvPublic { .. }, name, e; }
    var r = reader(rp);
    let b = get_2b(r, 256);
    read_into(r, name);
    var inner = reader(b);
    let n = read_nv_public(inner);
    if !r.ok || left(r) != 0 || !inner.ok || left(inner) != 0 { return n, name, ERR_MALFORMED; }
    if nv_name(n) != name || n.index != index { return n, name, ERR_NAME; }
    return n, name, OK;
}

// An NV index as an Entity, with its current Name read from the TPM.
fn nv_entity(t: Tpm&, index: u32, auth: const u8[:] = "") -> Entity, i64 {
    let n, name, e = nv_read_public(t, index);
    return object_entity(index, name, auth), e;
}

// The largest NV_Read/NV_Write the TPM takes (TPM_PT_NV_BUFFER_MAX), at
// most 1024.
fn nv_chunk(t: Tpm&) -> i64 {
    let v, e = tpm_property(t, PT_NV_BUFFER_MAX);
    if e != OK || v == 0 { return 512; }
    return min(v as i64, 1024);
}

// TPM2_NV_Write of data at offset, in pieces the TPM takes. auth is the
// entity authorizing (the index itself, or owner() / platform()).
fn nv_write(t: Tpm&, auth: Entity, index: Entity, s: Session&, data: const u8[:], offset: i64 = 0) -> i64 {
    let chunk = nv_chunk(t);
    var at = 0;
    var none = no_session();
    let hs = [auth, index];
    while at < data.len || (data.len == 0 && at == 0) {
        let n = min(chunk, data.len - at);
        var p: u8[>..] = [];
        put_2b(p, data[at..at + n]);
        put_u16(p, (offset + at) as u16);
        let rp, h, e = execute(t, Cmd { cc: CC_NV_Write, nauth: 1, enc_in: true }, hs, s, none, p);
        if e != OK { return e; }
        at += n;
        if data.len == 0 { break; }
    }
    return OK;
}

// TPM2_NV_Read of size bytes from offset, in pieces.
fn nv_read(t: Tpm&, auth: Entity, index: Entity, s: Session&, size: i64, offset: i64 = 0) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if size < 0 || size > MAX_NV { return out, ERR_ARG; }
    let chunk = nv_chunk(t);
    var none = no_session();
    let hs = [auth, index];
    while out.len < size {
        let n = min(chunk, size - out.len);
        var p: u8[>..] = [];
        put_u16(p, n as u16);
        put_u16(p, (offset + out.len) as u16);
        let rp, h, e = execute(t, Cmd { cc: CC_NV_Read, nauth: 1, enc_out: true }, hs, s, none, p);
        if e != OK { return out, e; }
        var r = reader(rp);
        let b = get_2b(r, n);
        if !r.ok || left(r) != 0 || b.len != n { out.clear(); return out, ERR_MALFORMED; }
        out.append(b);
    }
    return out, OK;
}

// TPM2_NV_Increment of a counter index.
fn nv_increment(t: Tpm&, auth: Entity, index: Entity, s: Session&) -> i64 {
    var none = no_session();
    let hs = [auth, index];
    let rp, h, e = execute(t, Cmd { cc: CC_NV_Increment, nauth: 1 }, hs, s, none, "");
    return e;
}

// TPM2_NV_Extend of an extend index by data (the TPM hashes it).
fn nv_extend(t: Tpm&, auth: Entity, index: Entity, s: Session&, data: const u8[:]) -> i64 {
    var p: u8[>..] = [];
    put_2b(p, data);
    var none = no_session();
    let hs = [auth, index];
    let rp, h, e = execute(t, Cmd { cc: CC_NV_Extend, nauth: 1, enc_in: true }, hs, s, none, p);
    return e;
}

// A counter index's value.
fn nv_read_counter(t: Tpm&, auth: Entity, index: Entity, s: Session&) -> u64, i64 {
    let b, e = nv_read(t, auth, index, s, 8);
    if e != OK { return 0, e; }
    var r = reader(b);
    return get_u64(r), OK;
}

// An EK certificate's DER from its NV index (EK_CERT_RSA_INDEX or
// EK_CERT_ECC_INDEX), read with the index's own (empty) authValue, or the
// owner's when the index is not AUTHREAD. ERR_TPM with TPM_RC_HANDLE when
// the TPM has none.
fn read_ek_cert(t: Tpm&, index: u32) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let n, name, e = nv_read_public(t, index);
    if e != OK { return out, e; }
    let ix = object_entity(index, name);
    var s = pw();
    let auth = if (n.attrs & NV_AUTHREAD) != 0 { ix } else { owner() };
    let b, er = nv_read(t, auth, ix, s, n.size);
    if er != OK { return out, er; }
    // The index is sized for the largest certificate; the DER says how long it is.
    if b.len < 4 || b[0] != 0x30 { out.append(b); return out, OK; }
    var len = 0;
    var hl = 2;
    if b[1] < 0x80 { len = b[1]; }
    else if b[1] == 0x81 { len = b[2]; hl = 3; }
    else if b[1] == 0x82 { len = (b[2] as i64) * 256 + b[3]; hl = 4; }
    else { out.append(b); return out, OK; }
    if hl + len > b.len { return out, ERR_MALFORMED; }
    out.append(b[..hl + len]);
    return out, OK;
}
