// tpm2.policy: enhanced authorization (Part 1 §19.7, Part 3 §23). A
// Policy computes a policy digest in software, as a trial session would,
// for an object's or NV index's authPolicy; the policy_* commands assert
// the same things to a policy session on the TPM, and policy_get_digest
// reads what the session has. The two agree when the assertions do:
//
//   var p = tpm2::policy(tpm2::ALG_SHA256);
//   tpm2::policy_pcr(p, sel, tpm2::pcr_digest(tpm2::ALG_SHA256, values));
//   tpm2::policy_auth_value(p);
//   // p.digest is the sealed object's authPolicy
//
//   var s, e = tpm2::start_session(t, tpm2::SESSION_POLICY);
//   tpm2::policy_pcr_tpm(t, s, sel);
//   tpm2::policy_auth_value_tpm(t, s);
//   let data, e2 = tpm2::unseal(t, item, s);
//
// Assertions: PolicyPCR, PolicySecret, PolicySigned, PolicyOR,
// PolicyAuthValue, PolicyPassword, PolicyCommandCode, PolicyAuthorize.

namespace tpm2;

import std;
import tpm2;
import tpm2.transport;
import tpm2.session;
import tpm2.commands;

// A policy digest under a hash, being computed.
struct Policy { hash: u16 = ALG_SHA256, digest: u8[..64] = [] }

// A fresh policy: the digest all zeros.
fn policy(alg: u16 = ALG_SHA256) -> Policy {
    var p = Policy { hash: alg, .. };
    p.digest.append(zeros(digest_size(alg)));
    return p;
}

// PolicyUpdate's first step: digest = H(digest || cc || arg).
fn policy_extend(p: Policy&, cc: u32, arg: const u8[:]) {
    var m: u8[>..] = [];
    m.append(p.digest);
    put_u32(m, cc);
    m.append(arg);
    let d = hash(p.hash, m);
    p.digest.clear();
    p.digest.append(d);
}

// PolicyUpdate (Part 3 §23.2.3): the Name, then the policyRef.
fn policy_update(p: Policy&, cc: u32, name: const u8[:], ref: const u8[:]) {
    policy_extend(p, cc, name);
    var m: u8[>..] = [];
    m.append(p.digest);
    m.append(ref);
    let d = hash(p.hash, m);
    p.digest.clear();
    p.digest.append(d);
}

// TPM2_PolicyPCR: the selection and the digest of the PCR values it
// selects (pcr_digest).
fn policy_pcr(p: Policy&, sel: const PcrSel[:], digest: const u8[:]) {
    var a: u8[>..] = [];
    put_pcr_selection(a, sel);
    a.append(digest);
    policy_extend(p, CC_PolicyPCR, a);
}

// TPM2_PolicySecret: the authorizing entity's Name (a hierarchy's is its
// handle) and the policyRef.
fn policy_secret(p: Policy&, auth_name: const u8[:], ref: const u8[:] = "") {
    policy_update(p, CC_PolicySecret, auth_name, ref);
}

// TPM2_PolicySigned: the signing key's Name and the policyRef.
fn policy_signed(p: Policy&, key_name: const u8[:], ref: const u8[:] = "") {
    policy_update(p, CC_PolicySigned, key_name, ref);
}

// TPM2_PolicyAuthorize: the digest restarts from zeros, then the
// authorizing key's Name and the policyRef.
fn policy_authorize(p: Policy&, key_name: const u8[:], ref: const u8[:] = "") {
    p.digest.clear();
    p.digest.append(zeros(digest_size(p.hash)));
    policy_update(p, CC_PolicyAuthorize, key_name, ref);
}

// TPM2_PolicyOR of 2 to 8 branch digests: the digest restarts from zeros,
// then the branches concatenated. false for fewer than 2 or more than 8.
fn policy_or(p: Policy&, branches: const u8[..64][:]) -> bool {
    if branches.len < 2 || branches.len > 8 { return false; }
    var a: u8[>..] = [];
    for b in branches { a.append(b); }
    p.digest.clear();
    p.digest.append(zeros(digest_size(p.hash)));
    policy_extend(p, CC_PolicyOR, a);
    return true;
}

// TPM2_PolicyAuthValue; TPM2_PolicyPassword makes the same digest.
fn policy_auth_value(p: Policy&) { policy_extend(p, CC_PolicyAuthValue, ""); }
fn policy_password(p: Policy&) { policy_extend(p, CC_PolicyAuthValue, ""); }

// TPM2_PolicyCommandCode.
fn policy_command_code(p: Policy&, cc: u32) {
    var a: u8[>..] = [];
    put_u32(a, cc);
    policy_extend(p, CC_PolicyCommandCode, a);
}

// The digest PolicySigned's signer signs (Part 3 §23.3): aHash =
// H(nonceTPM || expiration || cpHashA || policyRef).
fn policy_signed_hash(alg: u16, nonce_tpm: const u8[:], expiration: i32, cp_hash: const u8[:], ref: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    m.append(nonce_tpm);
    put_u32(m, expiration as! u32);
    m.append(cp_hash);
    m.append(ref);
    return hash(alg, m);
}

// The digest PolicyAuthorize's key signs: aHash = H(approvedPolicy || policyRef).
fn policy_authorize_hash(alg: u16, approved: const u8[:], ref: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    m.append(approved);
    m.append(ref);
    return hash(alg, m);
}

// --- On the TPM -------------------------------------------------------------------------------

fn policy_cmd(t: Tpm&, cc: u32, s: const Session&, params: const u8[:]) -> u8[>..], i64 {
    let hs = [entity(s.handle)];
    let rp, h, e = execute0(t, cc, hs, params);
    return rp, e;
}

fn no_params(rp: const u8[:], e: i64) -> i64 {
    if e != OK { return e; }
    return if rp.len == 0 { OK } else { ERR_MALFORMED };
}

// TPM2_PolicyPCR: the session's PCRs must be the selection's now. With a
// digest, they must also have that digest when the policy is used.
fn policy_pcr_tpm(t: Tpm&, s: const Session&, sel: const PcrSel[:], digest: const u8[:] = "") -> i64 {
    var p: u8[>..] = [];
    put_2b(p, digest);
    put_pcr_selection(p, sel);
    let rp, e = policy_cmd(t, CC_PolicyPCR, s, p);
    return no_params(rp, e);
}

// TPM2_PolicySecret: auth's authValue (by auth_session, a password or an
// HMAC session) satisfies the policy session s. nonce_tpm (s.nonce_tpm, or
// empty), cp_hash, the policyRef and an expiration (0 for none) are what
// the TPM checks and binds.
fn policy_secret_tpm(t: Tpm&, auth: Entity, auth_session: Session&, s: const Session&, ref: const u8[:] = "",
                     nonce_tpm: const u8[:] = "", cp_hash: const u8[:] = "", expiration: i32 = 0) -> i64 {
    var p: u8[>..] = [];
    put_2b(p, nonce_tpm);
    put_2b(p, cp_hash);
    put_2b(p, ref);
    put_u32(p, expiration as! u32);
    var none = no_session();
    let hs = [auth, entity(s.handle)];
    let rp, h, e = execute(t, Cmd { cc: CC_PolicySecret, nauth: 1, enc_in: true, enc_out: true }, hs, auth_session, none, p);
    if e != OK { return e; }
    var r = reader(rp);
    let timeout = get_2b(r, 64);
    let ticket = read_ticket(r);
    if !r.ok || left(r) != 0 { return ERR_MALFORMED; }
    return OK;
}

// TPM2_PolicySigned: a signature by a loaded key (key: its handle and Name)
// over policy_signed_hash(nonce_tpm, expiration, cp_hash, ref).
fn policy_signed_tpm(t: Tpm&, key: Entity, s: const Session&, sig: Signature, ref: const u8[:] = "",
                     nonce_tpm: const u8[:] = "", cp_hash: const u8[:] = "", expiration: i32 = 0) -> i64 {
    var p: u8[>..] = [];
    put_2b(p, nonce_tpm);
    put_2b(p, cp_hash);
    put_2b(p, ref);
    put_u32(p, expiration as! u32);
    p.append(marshal_signature(sig));
    let hs = [key, entity(s.handle)];
    let rp, h, e = execute0(t, CC_PolicySigned, hs, p);
    if e != OK { return e; }
    var r = reader(rp);
    let timeout = get_2b(r, 64);
    let ticket = read_ticket(r);
    if !r.ok || left(r) != 0 { return ERR_MALFORMED; }
    return OK;
}

// TPM2_PolicyOR: the session's digest must be one of the branches.
fn policy_or_tpm(t: Tpm&, s: const Session&, branches: const u8[..64][:]) -> i64 {
    if branches.len < 2 || branches.len > 8 { return ERR_ARG; }
    var p: u8[>..] = [];
    put_u32(p, branches.len as u32);
    for b in branches { put_2b(p, b); }
    let rp, e = policy_cmd(t, CC_PolicyOR, s, p);
    return no_params(rp, e);
}

// TPM2_PolicyAuthValue: the entity's authValue goes into the session's HMAC.
fn policy_auth_value_tpm(t: Tpm&, s: Session&) -> i64 {
    let rp, e = policy_cmd(t, CC_PolicyAuthValue, s, "");
    let r = no_params(rp, e);
    if r == OK { s.auth_value_needed = true; s.password_needed = false; }
    return r;
}

// TPM2_PolicyPassword: the entity's authValue goes in the clear.
fn policy_password_tpm(t: Tpm&, s: Session&) -> i64 {
    let rp, e = policy_cmd(t, CC_PolicyPassword, s, "");
    let r = no_params(rp, e);
    if r == OK { s.password_needed = true; s.auth_value_needed = false; }
    return r;
}

// TPM2_PolicyCommandCode: the session authorizes only this command.
fn policy_command_code_tpm(t: Tpm&, s: const Session&, cc: u32) -> i64 {
    var p: u8[>..] = [];
    put_u32(p, cc);
    let rp, e = policy_cmd(t, CC_PolicyCommandCode, s, p);
    return no_params(rp, e);
}

// TPM2_PolicyAuthorize: the session's digest, which must be `approved`,
// becomes PolicyAuthorize's of the key, given the TPMT_TK_VERIFIED ticket
// from VerifySignature of policy_authorize_hash(approved, ref).
fn policy_authorize_tpm(t: Tpm&, s: const Session&, approved: const u8[:], ref: const u8[:], key_name: const u8[:],
                        ticket: Ticket) -> i64 {
    var p: u8[>..] = [];
    put_2b(p, approved);
    put_2b(p, ref);
    put_2b(p, key_name);
    put_ticket(p, ticket);
    let rp, e = policy_cmd(t, CC_PolicyAuthorize, s, p);
    return no_params(rp, e);
}

// TPM2_PolicyGetDigest: the session's policy digest now.
fn policy_get_digest(t: Tpm&, s: const Session&) -> u8[..64], i64 {
    var d: u8[..64] = [];
    let rp, e = policy_cmd(t, CC_PolicyGetDigest, s, "");
    if e != OK { return d, e; }
    var r = reader(rp);
    read_into(r, d);
    if !r.ok || left(r) != 0 { return d, ERR_MALFORMED; }
    return d, OK;
}

// TPM2_PolicyRestart: the session's digest back to zeros.
fn policy_restart(t: Tpm&, s: Session&) -> i64 {
    let rp, e = policy_cmd(t, CC_PolicyRestart, s, "");
    s.auth_value_needed = false;
    s.password_needed = false;
    return no_params(rp, e);
}

// A policy session satisfying the TCG EK policy, PolicySecret(TPM_RH_ENDORSEMENT)
// with the endorsement hierarchy's authValue: what an EK made from the TCG
// templates needs to decrypt (ActivateCredential, a salted session's tpmKey
// does not need it).
fn ek_policy_session(t: Tpm&, endorsement_auth: const u8[:] = "") -> Session, i64 {
    var s, e = start_session(t, SESSION_POLICY);
    if e != OK { return s, e; }
    var a = pw();
    let e2 = policy_secret_tpm(t, endorsement(endorsement_auth), a, s);
    return s, e2;
}
