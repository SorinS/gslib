// The live scenarios against a TPM (scripts/interop.py runs this against
// tpmemu and swtpm): every command of tpm2, each result checked in
// software. Objects are flushed as soon as a scenario is done with them,
// since a TPM holds only a few (swtpm three).
//
//   goose scripts/live.goose -- --tpm tcp:127.0.0.1:2321 [--only NAME] [--ek-cert]
//
// Prints "ok NAME", "FAIL NAME: why" or "skip NAME: why" a line, and
// "N passed, M failed"; exit status 1 if any failed.
import std;
import os;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.transport;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.tpm2.policy;
import gslib.tpm2.attest;
import gslib.crypto.bignum;
import gslib.crypto.bignum.ec;
import gslib.crypto.bignum.rsa;
import gslib.crypto.bignum.hmac;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.encoding.asn1;

var passed = 0;
var failed = 0;
var only: u8[..64] = [];
var want_ek_cert = false;

fn ok(name: const u8[:]) { passed++; print("ok    ", name); }
fn fail(name: const u8[:], why: const u8[:]) { failed++; print("FAIL  ", name, ": ", why); }
fn skip(name: const u8[:], why: const u8[:]) { print("skip  ", name, ": ", why); }

fn check(t: const tpm2::Tpm&, name: const u8[:], e: i64) -> bool {
    if e == tpm2::OK { ok(name); return true; }
    fail(name, tpm2::describe(t, e));
    return false;
}

fn expect(name: const u8[:], cond: bool, why: const u8[:] = "") -> bool {
    if cond { ok(name); } else { fail(name, why); }
    return cond;
}

fn want(name: const u8[:]) -> bool { only.len == 0 || find(name, only) >= 0 }

fn flush(t: tpm2::Tpm&, h: u32) {
    if h != 0 { tpm2::flush(t, h); }
}

fn srk(t: tpm2::Tpm&, ecc: bool) -> tpm2::Object, i64 {
    var s = tpm2::pw();
    let tmpl = if ecc { tpm2::srk_ecc_template() } else { tpm2::srk_rsa_template() };
    return tpm2::create_primary(t, tpm2::owner(), s, tmpl);
}

fn basics(t: tpm2::Tpm&) {
    let r, e = tpm2::get_random(t, 100);
    if check(t, "GetRandom", e) { expect("GetRandom: 100 bytes", r.len == 100); }
    let m, em = tpm2::manufacturer(t);
    if check(t, "GetCapability manufacturer", em) { print("      manufacturer ", m); }
    let v, ev = tpm2::tpm_property(t, tpm2::PT_FAMILY_INDICATOR);
    if check(t, "GetCapability family", ev) { expect("family is 2.0", v == 0x322e3000, tpm2::hex_u32(v)); }
    let d, k, eh = tpm2::hash_tpm(t, "abc", tpm2::ALG_SHA256);
    if check(t, "Hash", eh) { expect("Hash = SHA-256(abc)", d == tpm2::hash(tpm2::ALG_SHA256, "abc")); }
    let d1, k1, eh1 = tpm2::hash_tpm(t, "abc", tpm2::ALG_SHA384, tpm2::RH_NULL);
    if check(t, "Hash SHA-384", eh1) { expect("Hash = SHA-384(abc)", d1 == tpm2::hash(tpm2::ALG_SHA384, "abc")); }
    // The PCR banks the TPM has.
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0xffffff }, tpm2::PcrSel { hash: tpm2::ALG_SHA1, mask: 0x0000ff }];
    let vals, c, ep = tpm2::pcr_read(t, sel);
    if check(t, "PCR_Read 32 PCRs in two banks", ep) { expect("PCR_Read: 32 values", vals.len == 32, str(vals.len)); }
}

fn primaries(t: tpm2::Tpm&) {
    var s = tpm2::pw();
    for which in 4 {
        let name = if which == 0 { "EK RSA" } else if which == 1 { "EK ECC" } else if which == 2 { "SRK RSA" } else { "SRK ECC" };
        let tmpl = if which == 0 { tpm2::ek_rsa_template() } else if which == 1 { tpm2::ek_ecc_template() }
                   else if which == 2 { tpm2::srk_rsa_template() } else { tpm2::srk_ecc_template() };
        let hier = if which < 2 { tpm2::endorsement() } else { tpm2::owner() };
        let o, e = tpm2::create_primary(t, hier, s, tmpl);
        if !check(t, str("CreatePrimary ", name, " (Name checked)"), e) { continue; }
        let rp, qn, er = tpm2::read_public_tpm(t, o.handle);
        if check(t, str("ReadPublic ", name), er) {
            expect(str("ReadPublic ", name, ": same public area"), tpm2::marshal_public(rp.public) == tpm2::marshal_public(o.public));
        }
        let spki, oks = tpm2::public_to_spki(o.public);
        let back, eb = tpm2::public_from_spki(spki, tmpl);
        expect(str(name, " to SubjectPublicKeyInfo and back"), oks && eb == tpm2::OK && tpm2::public_name(back) == o.name);
        // Same template, same key: a primary comes from the hierarchy's seed.
        let o2, e2 = tpm2::create_primary(t, hier, s, tmpl);
        if e2 == tpm2::OK {
            expect(str("CreatePrimary ", name, " again: the same key"), o2.name == o.name, "a different key from the same template and seed");
            flush(t, o2.handle);
        }
        flush(t, o.handle);
    }
}

fn signing(t: tpm2::Tpm&) {
    let parent, ep = srk(t, true);
    if !check(t, "SRK for signing keys", ep) { return; }
    var s = tpm2::pw();
    let pe = tpm2::object_of(parent);
    let digest = tpm2::hash(tpm2::ALG_SHA256, "message to sign");
    // RSA: RSASSA and RSAPSS.
    var rk, e = tpm2::create(t, pe, s, no_da(tpm2::rsa_sign_template()), "rsa key auth");
    if check(t, "Create RSA signing key", e) {
        let el = tpm2::load(t, pe, s, rk);
        if check(t, "Load RSA signing key (Name checked)", el) {
            let ke = tpm2::object_of(rk, "rsa key auth");
            for scheme in [tpm2::ALG_RSASSA, tpm2::ALG_RSAPSS] {
                let sig, es = tpm2::sign(t, ke, s, digest, scheme, tpm2::ALG_SHA256);
                let nm = if scheme == tpm2::ALG_RSASSA { "RSASSA" } else { "RSAPSS" };
                if check(t, str("Sign ", nm), es) {
                    check(t, str("Sign ", nm, " verified by x509"), tpm2::verify_signature(rk.public, digest, sig));
                    var bad = copy(digest);
                    bad[0] ^= 1;
                    expect(str("Sign ", nm, ": another digest does not verify"), tpm2::verify_signature(rk.public, bad, sig) == tpm2::ERR_SIGNATURE);
                }
            }
            // A wrong password.
            let kbad = tpm2::object_of(rk, "wrong");
            let sb, esb = tpm2::sign(t, kbad, s, digest, tpm2::ALG_RSASSA, tpm2::ALG_SHA256);
            expect("Sign with a wrong password (noDA key): TPM_RC_BAD_AUTH", esb == tpm2::ERR_TPM && tpm2::rc_name(t.rc) == "TPM_RC_BAD_AUTH",
                   tpm2::describe(t, esb));
            flush(t, rk.handle);
        }
    }
    // ECDSA on each curve.
    for curve in [tpm2::ECC_NIST_P256, tpm2::ECC_NIST_P384, tpm2::ECC_NIST_P521] {
        let h = if curve == tpm2::ECC_NIST_P256 { tpm2::ALG_SHA256 } else if curve == tpm2::ECC_NIST_P384 { tpm2::ALG_SHA384 } else { tpm2::ALG_SHA512 };
        let nm = if curve == tpm2::ECC_NIST_P256 { "P-256" } else if curve == tpm2::ECC_NIST_P384 { "P-384" } else { "P-521" };
        let ko, ec = tpm2::create_loaded(t, pe, s, tpm2::ecc_sign_template(curve));
        if ec == tpm2::ERR_TPM && (tpm2::rc_name(t.rc) == "TPM_RC_CURVE" || tpm2::rc_name(t.rc) == "TPM_RC_VALUE") {
            skip(str("ECDSA ", nm), tpm2::rc_text(t.rc));
            continue;
        }
        if !check(t, str("CreateLoaded ECC ", nm, " signing key"), ec) { continue; }
        let d = tpm2::hash(h, "message to sign");
        let sig, es = tpm2::sign(t, tpm2::object_of(ko), s, d, tpm2::ALG_ECDSA, h);
        if check(t, str("Sign ECDSA ", nm), es) {
            check(t, str("Sign ECDSA ", nm, " verified by x509"), tpm2::verify_signature(ko.public, d, sig));
        }
        flush(t, ko.handle);
    }
    flush(t, parent.handle);
}

fn encryption(t: tpm2::Tpm&) {
    let parent, ep = srk(t, true);
    if !check(t, "SRK for decryption keys", ep) { return; }
    var s = tpm2::pw();
    let pe = tpm2::object_of(parent);
    let rk, e = tpm2::create_loaded(t, pe, s, tpm2::rsa_decrypt_template());
    if check(t, "CreateLoaded RSA decryption key", e) {
        let ke = tpm2::object_of(rk);
        let ct, ee = tpm2::rsa_encrypt(t, ke, "secret message", tpm2::ALG_OAEP, tpm2::ALG_SHA256, "label");
        if check(t, "RSA_Encrypt OAEP", ee) {
            let pt, ed = tpm2::rsa_decrypt(t, ke, s, ct, tpm2::ALG_OAEP, tpm2::ALG_SHA256, "label");
            if check(t, "RSA_Decrypt OAEP", ed) { expect("RSA_Decrypt: the message", pt == "secret message"); }
        }
        // Encrypted here, by the public key alone.
        let pub, okp = tpm2::rsa_public(rk.public);
        let ct2 = bignum::rsa_encrypt_oaep(pub, "from software", "label\x00", 256);
        let pt2, ed2 = tpm2::rsa_decrypt(t, ke, s, ct2, tpm2::ALG_OAEP, tpm2::ALG_SHA256, "label");
        if check(t, "RSA_Decrypt of software RSA-OAEP", ed2) { expect("RSA_Decrypt: software's message", pt2 == "from software"); }
        flush(t, rk.handle);
    }
    let ek, e2 = tpm2::create_loaded(t, pe, s, tpm2::ecdh_template(tpm2::ECC_NIST_P256));
    if check(t, "CreateLoaded ECDH key", e2) {
        let curve = bignum::p256();
        let sk, pk = bignum::ec_keypair(curve);
        let zx, zy, ez = tpm2::ecdh_zgen(t, tpm2::object_of(ek), s, pk[1..33], pk[33..]);
        if check(t, "ECDH_ZGen", ez) {
            let peer, okp = tpm2::ecc_point(ek.public);
            let z, okz = bignum::ecdh_shared(curve, sk, peer);
            expect("ECDH_ZGen: the software's shared x", okz && zx == z);
        }
        flush(t, ek.handle);
    }
    // HMAC with a keyed-hash key of our own.
    let hk, e3 = tpm2::create_loaded(t, pe, s, hmac_template(), "", "0123456789abcdef0123456789abcdef");
    if check(t, "CreateLoaded HMAC key", e3) {
        let mac, em = tpm2::hmac_tpm(t, tpm2::object_of(hk), s, "data", tpm2::ALG_SHA256);
        if check(t, "HMAC", em) { expect("HMAC: the software's", mac == tpm2::hmac(tpm2::ALG_SHA256, "0123456789abcdef0123456789abcdef", "data")); }
        flush(t, hk.handle);
    }
    flush(t, parent.handle);
}

// A template with noDA, so that wrong passwords do not lock the TPM out.
fn no_da(p: tpm2::Public) -> tpm2::Public {
    var q = p;
    q.attrs |= tpm2::OBJ_NO_DA;
    return q;
}

// An HMAC key with caller-given key bits (no sensitiveDataOrigin).
fn hmac_template() -> tpm2::Public {
    var p = tpm2::hmac_key_template(tpm2::ALG_SHA256);
    p.attrs &= ~tpm2::OBJ_SENSITIVE_DATA_ORIGIN;
    return p;
}

fn sessions(t: tpm2::Tpm&) {
    let parent, ep = srk(t, false);
    if !check(t, "SRK RSA for sessions", ep) { return; }
    var pws = tpm2::pw();
    let pe = tpm2::object_of(parent);
    let digest = tpm2::hash(tpm2::ALG_SHA256, "session test");
    let k, ek = tpm2::create_loaded(t, pe, pws, no_da(tpm2::ecc_sign_template(tpm2::ECC_NIST_P256)), "key auth");
    if !check(t, "CreateLoaded key with an authValue", ek) { flush(t, parent.handle); return; }
    let ke = tpm2::object_of(k, "key auth");
    for hashalg in [tpm2::ALG_SHA256, tpm2::ALG_SHA1, tpm2::ALG_SHA384] {
        var s, es = tpm2::start_session(t, tpm2::SESSION_HMAC, hashalg);
        if !check(t, str("StartAuthSession HMAC ", tpm2::hash_name(hashalg)), es) { continue; }
        for i in 2 {
            let sig, e = tpm2::sign(t, ke, s, digest, tpm2::ALG_ECDSA, tpm2::ALG_SHA256);
            if check(t, str("Sign in an HMAC session (", tpm2::hash_name(hashalg), ", command ", i + 1, ")"), e) {
                check(t, "  and verified", tpm2::verify_signature(k.public, digest, sig));
            }
        }
        let bad = tpm2::object_of(k, "wrong");
        let sb, eb = tpm2::sign(t, bad, s, digest, tpm2::ALG_ECDSA, tpm2::ALG_SHA256);
        expect(str("HMAC session, wrong authValue: TPM_RC_BAD_AUTH (", tpm2::hash_name(hashalg), ")"),
               eb == tpm2::ERR_TPM && tpm2::rc_name(t.rc) == "TPM_RC_BAD_AUTH", tpm2::describe(t, eb));
        flush(t, s.handle);
    }
    // Salted to the SRK (RSA-OAEP), and to an ECC SRK (ECDH).
    for ecc in [false, true] {
        let nm = if ecc { "ECC (ECDH, KDFe)" } else { "RSA (OAEP)" };
        var saltkey = parent;
        var extra: u32 = 0;
        if ecc {
            let es, ee = srk(t, true);
            if !check(t, "SRK ECC for a salt", ee) { continue; }
            flush(t, k.handle);
            saltkey = es;
            extra = es.handle;
        }
        let o = tpm2::SessionOpts { salt: true, salt_key: tpm2::object_of(saltkey), salt_pub: saltkey.public, .. };
        var s, e = tpm2::start_session_with(t, tpm2::SESSION_HMAC, o);
        if check(t, str("StartAuthSession salted, ", nm), e) {
            expect("  session key made", s.key.len == 32);
            // Seal and unseal through it, the data encrypted both ways.
            s.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT;
            let so, ec = tpm2::create(t, pe, s, tpm2::sealed_template(""), "seal auth", "the sealed secret");
            if check(t, str("Create sealed object, salted session, data encrypted (", nm, ")"), ec) {
                var so2 = so;
                s.attrs = tpm2::ATTR_CONTINUE;
                let el = tpm2::load(t, pe, s, so2);
                if check(t, "  Load it in the same session", el) {
                    s.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_ENCRYPT;
                    let data, eu = tpm2::unseal(t, tpm2::object_of(so2, "seal auth"), s);
                    if check(t, str("  Unseal, response encrypted (", nm, ")"), eu) { expect("  the data", data == "the sealed secret"); }
                    flush(t, so2.handle);
                }
            }
            flush(t, s.handle);
        }
        if ecc { flush(t, extra); }
    }
    // Bound to the key: its authValue in the session key, out of the HMAC.
    let k2, ek2 = tpm2::create_loaded(t, pe, pws, tpm2::ecc_sign_template(tpm2::ECC_NIST_P256), "bound auth");
    if check(t, "CreateLoaded key to bind to", ek2) {
        let ke2 = tpm2::object_of(k2, "bound auth");
        let o = tpm2::SessionOpts { bind: true, bind_entity: ke2, .. };
        var s, e = tpm2::start_session_with(t, tpm2::SESSION_HMAC, o);
        if check(t, "StartAuthSession bound", e) {
            let sig, es = tpm2::sign(t, ke2, s, digest, tpm2::ALG_ECDSA, tpm2::ALG_SHA256);
            check(t, "Sign in a session bound to the key", es);
            // The same session for another entity: the parent, with its own (empty) auth.
            let c2, ec2 = tpm2::create(t, pe, s, tpm2::sealed_template(""), "", "x");
            check(t, "Create under another entity in the bound session", ec2);
            // Parameter encryption in a bound session (sessionValue includes the authValue).
            s.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT;
            let sig2, es2 = tpm2::sign(t, ke2, s, digest, tpm2::ALG_ECDSA, tpm2::ALG_SHA256);
            if check(t, "Sign, digest encrypted, bound session for its entity", es2) {
                check(t, "Sign, digest encrypted, bound session: the signature verifies", tpm2::verify_signature(k2.public, digest, sig2));
            }
            flush(t, s.handle);
        }
        flush(t, k2.handle);
    }
    // Parameter encryption, unbound, unsalted: the key from the authValue alone.
    let k3, ek3 = tpm2::create_loaded(t, pe, pws, tpm2::rsa_decrypt_template(), "dec auth");
    if check(t, "CreateLoaded RSA decryption key", ek3) {
        let ke3 = tpm2::object_of(k3, "dec auth");
        var s, e = tpm2::start_session(t, tpm2::SESSION_HMAC, tpm2::ALG_SHA256, 128);
        let ct, ee = tpm2::rsa_encrypt(t, ke3, "both ways");
        if check(t, "StartAuthSession for parameter encryption", e) && ee == tpm2::OK {
            s.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT | tpm2::ATTR_ENCRYPT;
            let pt, ed = tpm2::rsa_decrypt(t, ke3, s, ct, tpm2::ALG_OAEP, tpm2::ALG_SHA256);
            if check(t, "RSA_Decrypt, AES-CFB both ways", ed) { expect("  the message", pt == "both ways"); }
            flush(t, s.handle);
        }
        // AES-256.
        var s2, e2 = tpm2::start_session(t, tpm2::SESSION_HMAC, tpm2::ALG_SHA256, 256);
        if e2 == tpm2::OK {
            s2.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT | tpm2::ATTR_ENCRYPT;
            let pt, ed = tpm2::rsa_decrypt(t, ke3, s2, ct, tpm2::ALG_OAEP, tpm2::ALG_SHA256);
            if check(t, "RSA_Decrypt, AES-256-CFB both ways", ed) { expect("  the message", pt == "both ways"); }
            flush(t, s2.handle);
        } else {
            skip("AES-256 parameter encryption", tpm2::describe(t, e2));
        }
        flush(t, k3.handle);
    }
    flush(t, k.handle);
    flush(t, parent.handle);
}

fn policies(t: tpm2::Tpm&) {
    var pws = tpm2::pw();
    // Each assertion: the TPM's digest against the software's.
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: (1 << 23) | 1 }];
    let vals, c, ev = tpm2::pcr_read(t, sel);
    if !check(t, "PCR_Read for policies", ev) { return; }
    // A trial session computes a policy digest without checking anything;
    // a policy session gives the same digests (its assertions all hold here).
    var trial = tpm2::SESSION_TRIAL;
    var ts, et0 = tpm2::start_session(t, tpm2::SESSION_TRIAL);
    if check(t, "StartAuthSession trial", et0) { flush(t, ts.handle); } else { trial = tpm2::SESSION_POLICY; }
    for step in 6 {
        var s, e = tpm2::start_session(t, trial);
        if e != tpm2::OK { check(t, "StartAuthSession for policy digests", e); return; }
        var p = tpm2::policy();
        var nm: u8[>..] = [];
        var et = tpm2::OK;
        if step == 0 {
            nm.append("PolicyPCR");
            et = tpm2::policy_pcr_tpm(t, s, sel);
            tpm2::policy_pcr(p, sel, tpm2::pcr_digest(tpm2::ALG_SHA256, vals));
        } else if step == 1 {
            nm.append("PolicyAuthValue");
            et = tpm2::policy_auth_value_tpm(t, s);
            tpm2::policy_auth_value(p);
        } else if step == 2 {
            nm.append("PolicyPassword");
            et = tpm2::policy_password_tpm(t, s);
            tpm2::policy_password(p);
        } else if step == 3 {
            nm.append("PolicyCommandCode(Unseal)");
            et = tpm2::policy_command_code_tpm(t, s, tpm2::CC_Unseal);
            tpm2::policy_command_code(p, tpm2::CC_Unseal);
        } else if step == 4 {
            nm.append("PolicySecret(endorsement), the EK policy");
            var a = tpm2::pw();
            et = tpm2::policy_secret_tpm(t, tpm2::endorsement(), a, s);
            tpm2::policy_secret(p, tpm2::handle_name(tpm2::RH_ENDORSEMENT));
            expect("  the EK Credential Profile's authPolicy", p.digest == tpm2::EK_POLICY_SHA256);
        } else {
            nm.append("PolicyOR");
            var b1 = tpm2::policy();
            tpm2::policy_auth_value(b1);
            var b2 = tpm2::policy();
            tpm2::policy_command_code(b2, tpm2::CC_Unseal);
            let branches = [b1.digest, b2.digest];
            et = tpm2::policy_auth_value_tpm(t, s);
            if et == tpm2::OK { et = tpm2::policy_or_tpm(t, s, branches); }
            tpm2::policy_auth_value(p);
            tpm2::policy_or(p, branches);
        }
        if check(t, nm, et) {
            let d, eg = tpm2::policy_get_digest(t, s);
            if check(t, str(nm, ": PolicyGetDigest"), eg) { expect(str(nm, ": the software's digest"), d == p.digest, tpm2::hex(d)); }
        }
        flush(t, s.handle);
    }
    seal_pcr(t);
    signed_and_authorized(t);
}

// Seal to PCR 23, unseal, extend PCR 23, fail to unseal.
fn seal_pcr(t: tpm2::Tpm&) {
    var pws = tpm2::pw();
    let er = tpm2::pcr_reset(t, 23, pws);
    if !check(t, "PCR_Reset 23", er) { return; }
    let parent, ep = srk(t, true);
    if !check(t, "SRK for sealing", ep) { return; }
    let pe = tpm2::object_of(parent);
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 1 << 23 }];
    let vals, c, ev = tpm2::pcr_read(t, sel);
    var p = tpm2::policy();
    tpm2::policy_pcr(p, sel, tpm2::pcr_digest(tpm2::ALG_SHA256, vals));
    tpm2::policy_auth_value(p);
    var so, ec = tpm2::create(t, pe, pws, no_da(tpm2::sealed_template(p.digest)), "pin", "sealed to PCR 23");
    if check(t, "Create sealed object under PolicyPCR + PolicyAuthValue", ec) {
        let el = tpm2::load(t, pe, pws, so);
        if check(t, "Load sealed object", el) {
            let item = tpm2::object_of(so, "pin");
            var s, e = tpm2::start_session(t, tpm2::SESSION_POLICY);
            tpm2::policy_pcr_tpm(t, s, sel);
            tpm2::policy_auth_value_tpm(t, s);
            let data, eu = tpm2::unseal(t, item, s);
            if check(t, "Unseal with the PCRs as sealed", eu) { expect("  the data", data == "sealed to PCR 23"); }
            // A wrong PIN.
            tpm2::policy_pcr_tpm(t, s, sel);
            tpm2::policy_auth_value_tpm(t, s);
            let bad = tpm2::object_of(so, "nip");
            let d2, eu2 = tpm2::unseal(t, bad, s);
            expect("Unseal with a wrong authValue (noDA): TPM_RC_BAD_AUTH", eu2 == tpm2::ERR_TPM && tpm2::rc_name(t.rc) == "TPM_RC_BAD_AUTH", tpm2::describe(t, eu2));
            flush(t, s.handle);
            let ex = tpm2::pcr_extend(t, 23, pws, tpm2::ALG_SHA256, tpm2::hash(tpm2::ALG_SHA256, "measurement"));
            check(t, "PCR_Extend 23", ex);
            let v2, c2, ev2 = tpm2::pcr_read(t, sel);
            expect("PCR_Extend: the software's value", ev2 == tpm2::OK && v2[0] == tpm2::extend_value(tpm2::ALG_SHA256, vals[0], tpm2::hash(tpm2::ALG_SHA256, "measurement")));
            var s2, e2 = tpm2::start_session(t, tpm2::SESSION_POLICY);
            let ep2 = tpm2::policy_pcr_tpm(t, s2, sel);
            tpm2::policy_auth_value_tpm(t, s2);
            let d3, eu3 = tpm2::unseal(t, item, s2);
            expect("Unseal after PCR_Extend fails (TPM_RC_POLICY_FAIL)", eu3 == tpm2::ERR_TPM && tpm2::rc_name(t.rc) == "TPM_RC_POLICY_FAIL",
                   tpm2::describe(t, eu3));
            flush(t, s2.handle);
            flush(t, so.handle);
        }
    }
    tpm2::pcr_reset(t, 23, pws);
    flush(t, parent.handle);
}

// PolicySecret, PolicySigned (a software key) and PolicyAuthorize.
fn signed_and_authorized(t: tpm2::Tpm&) {
    var pws = tpm2::pw();
    let parent, ep = srk(t, true);
    if !check(t, "SRK for PolicySigned", ep) { return; }
    let pe = tpm2::object_of(parent);
    // A software P-256 key, loaded as a public key alone.
    let sk = x509::generate_key(x509::KEY_EC_P256);
    let spki = x509::marshal_public_key(sk);
    var tmpl = tpm2::Public { kind: tpm2::ALG_ECC, attrs: tpm2::OBJ_SIGN | tpm2::OBJ_USER_WITH_AUTH, scheme: tpm2::ALG_ECDSA,
                              scheme_hash: tpm2::ALG_SHA256, curve: tpm2::ECC_NIST_P256, .. };
    let pub, epub = tpm2::public_from_spki(spki, tmpl);
    if !check(t, "public_from_spki of a software key", epub) { flush(t, parent.handle); return; }
    let ext, ee = tpm2::load_external(t, pub, tpm2::RH_OWNER);
    if !check(t, "LoadExternal of the software key", ee) { flush(t, parent.handle); return; }
    // PolicySigned: sign aHash over the session's nonce.
    var p = tpm2::policy();
    tpm2::policy_signed(p, ext.name, "ref");
    var so, ec = tpm2::create(t, pe, pws, tpm2::sealed_template(p.digest), "", "by PolicySigned");
    var s, es = tpm2::start_session(t, tpm2::SESSION_POLICY);
    if check(t, "Create sealed object under PolicySigned", ec) && es == tpm2::OK {
        let ah = tpm2::policy_signed_hash(tpm2::ALG_SHA256, s.nonce_tpm, 0, "", "ref");
        let raw, oks = x509::sign_digest(sk, x509::SIG_ECDSA, 256, ah);
        let sig = ecdsa_from_der(raw);
        let e1 = tpm2::policy_signed_tpm(t, tpm2::object_of(ext), s, sig, "ref", s.nonce_tpm);
        if check(t, "PolicySigned with a software ECDSA signature", e1) {
            let d, eg = tpm2::policy_get_digest(t, s);
            expect("PolicySigned: the software's digest", d == p.digest);
            let el = tpm2::load(t, pe, pws, so);
            if el == tpm2::OK {
                let data, eu = tpm2::unseal(t, tpm2::object_of(so), s);
                if check(t, "Unseal under PolicySigned", eu) { expect("  the data", data == "by PolicySigned"); }
                flush(t, so.handle);
            }
        }
        flush(t, s.handle);
    }
    // PolicyAuthorize: the object's policy is "whatever the key approves";
    // the key approves PolicyAuthValue.
    var pa = tpm2::policy();
    tpm2::policy_authorize(pa, ext.name, "");
    var approved = tpm2::policy();
    tpm2::policy_auth_value(approved);
    var so2, ec2 = tpm2::create(t, pe, pws, tpm2::sealed_template(pa.digest), "apin", "by PolicyAuthorize");
    if check(t, "Create sealed object under PolicyAuthorize", ec2) {
        let ah = tpm2::policy_authorize_hash(tpm2::ALG_SHA256, approved.digest, "");
        let raw, oks = x509::sign_digest(sk, x509::SIG_ECDSA, 256, ah);
        let sig = ecdsa_from_der(raw);
        let ticket, ev = tpm2::verify_signature_tpm(t, tpm2::object_of(ext), ah, sig);
        if check(t, "VerifySignature: a ticket for the approved policy", ev) {
            var s2, e2 = tpm2::start_session(t, tpm2::SESSION_POLICY);
            tpm2::policy_auth_value_tpm(t, s2);
            let ea = tpm2::policy_authorize_tpm(t, s2, approved.digest, "", ext.name, ticket);
            if check(t, "PolicyAuthorize", ea) {
                let d, eg = tpm2::policy_get_digest(t, s2);
                expect("PolicyAuthorize: the software's digest", d == pa.digest, tpm2::hex(d));
                let el = tpm2::load(t, pe, pws, so2);
                if el == tpm2::OK {
                    let data, eu = tpm2::unseal(t, tpm2::object_of(so2, "apin"), s2);
                    if check(t, "Unseal under PolicyAuthorize(PolicyAuthValue)", eu) { expect("  the data", data == "by PolicyAuthorize"); }
                    flush(t, so2.handle);
                }
            }
            flush(t, s2.handle);
        }
    }
    // PolicySecret with the owner's authValue, in an HMAC session.
    var p3 = tpm2::policy();
    tpm2::policy_secret(p3, tpm2::handle_name(tpm2::RH_OWNER));
    var s3, e3 = tpm2::start_session(t, tpm2::SESSION_POLICY);
    var hs, eh = tpm2::start_session(t, tpm2::SESSION_HMAC);
    if e3 == tpm2::OK && eh == tpm2::OK {
        let e4 = tpm2::policy_secret_tpm(t, tpm2::owner(), hs, s3);
        if check(t, "PolicySecret(owner) authorized by an HMAC session", e4) {
            let d, eg = tpm2::policy_get_digest(t, s3);
            expect("PolicySecret(owner): the software's digest", d == p3.digest);
        }
    }
    flush(t, s3.handle);
    flush(t, hs.handle);
    flush(t, ext.handle);
    flush(t, parent.handle);
}

// A TPMT_SIGNATURE from x509's DER ECDSA signature.
fn ecdsa_from_der(der: const u8[:]) -> tpm2::Signature {
    var sig = tpm2::Signature { alg: tpm2::ALG_ECDSA, hash: tpm2::ALG_SHA256, .. };
    let curve = bignum::p256();
    let raw, ok = bignum::ecdsa_sig_from_der(curve, der);
    if ok { sig.r.append(raw[..32]); sig.s.append(raw[32..]); }
    return sig;
}

fn nv(t: tpm2::Tpm&) {
    var pws = tpm2::pw();
    let index: u32 = 0x01500020;
    tpm2::nv_undefine(t, tpm2::owner(), pws, index);
    let np = tpm2::NvPublic { index: index, attrs: tpm2::NV_AUTHWRITE | tpm2::NV_AUTHREAD | tpm2::NV_OWNERREAD | tpm2::NV_NO_DA, size: 64 };
    if !check(t, "NV_DefineSpace ordinary, 64 bytes", tpm2::nv_define(t, tpm2::owner(), pws, np, "nv pass")) { return; }
    let n0, name0, er0 = tpm2::nv_read_public(t, index);
    if check(t, "NV_ReadPublic (Name checked)", er0) { expect("  not yet written", (n0.attrs & tpm2::NV_WRITTEN) == 0); }
    let ix = tpm2::object_entity(index, name0, "nv pass");
    var hs, eh = tpm2::start_session(t, tpm2::SESSION_HMAC);
    hs.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT;
    let ew = tpm2::nv_write(t, ix, ix, hs, "hello, NV", 3);
    check(t, "NV_Write at offset 3, HMAC session, data encrypted", ew);
    let ix2, en = tpm2::nv_entity(t, index, "nv pass");   // the Name now has WRITTEN
    expect("NV Name changes on the first write", ix2.name != ix.name);
    hs.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_ENCRYPT;
    let data, erd = tpm2::nv_read(t, ix2, ix2, hs, 9, 3);
    if check(t, "NV_Read, response encrypted", erd) { expect("  the data", data == "hello, NV"); }
    var p2 = tpm2::pw();
    let data2, erd2 = tpm2::nv_read(t, tpm2::owner(), ix2, p2, 12, 0);
    if check(t, "NV_Read by the owner", erd2) { expect("  the data", data2[3..] == "hello, NV"); }
    let big = zeros_of(65);
    let eb = tpm2::nv_write(t, ix2, ix2, p2, big);
    expect("NV_Write past the end: TPM_RC_NV_RANGE", eb == tpm2::ERR_TPM && tpm2::rc_name(t.rc) == "TPM_RC_NV_RANGE", tpm2::describe(t, eb));
    flush(t, hs.handle);
    check(t, "NV_UndefineSpace", tpm2::nv_undefine(t, tpm2::owner(), p2, index));
    // A counter.
    let ci: u32 = 0x01500021;
    tpm2::nv_undefine(t, tpm2::owner(), p2, ci);
    let cp = tpm2::NvPublic { index: ci, attrs: tpm2::NV_TYPE_COUNTER | tpm2::NV_AUTHWRITE | tpm2::NV_AUTHREAD | tpm2::NV_NO_DA, size: 8 };
    if check(t, "NV_DefineSpace counter", tpm2::nv_define(t, tpm2::owner(), p2, cp)) {
        let ce, e1 = tpm2::nv_entity(t, ci);
        check(t, "NV_Increment", tpm2::nv_increment(t, ce, ce, p2));
        let ce2, e2 = tpm2::nv_entity(t, ci);
        let v1, ec1 = tpm2::nv_read_counter(t, ce2, ce2, p2);
        check(t, "NV_Increment again", tpm2::nv_increment(t, ce2, ce2, p2));
        let v2, ec2 = tpm2::nv_read_counter(t, ce2, ce2, p2);
        expect("counter: +1", ec1 == tpm2::OK && ec2 == tpm2::OK && v2 == v1 + 1, str(v1, " ", v2));
        tpm2::nv_undefine(t, tpm2::owner(), p2, ci);
    }
    // An extend index.
    let xi: u32 = 0x01500022;
    tpm2::nv_undefine(t, tpm2::owner(), p2, xi);
    let xp = tpm2::NvPublic { index: xi, attrs: tpm2::NV_TYPE_EXTEND | tpm2::NV_AUTHWRITE | tpm2::NV_AUTHREAD | tpm2::NV_NO_DA, size: 32 };
    if check(t, "NV_DefineSpace extend", tpm2::nv_define(t, tpm2::owner(), p2, xp)) {
        let xe, e1 = tpm2::nv_entity(t, xi);
        check(t, "NV_Extend", tpm2::nv_extend(t, xe, xe, p2, "event one"));
        let xe2, e2 = tpm2::nv_entity(t, xi);
        check(t, "NV_Extend again", tpm2::nv_extend(t, xe2, xe2, p2, "event two"));
        let v, ev = tpm2::nv_read(t, xe2, xe2, p2, 32);
        var want = zeros_of(32);
        let w1 = tpm2::extend_value(tpm2::ALG_SHA256, want, "event one");
        let w2 = tpm2::extend_value(tpm2::ALG_SHA256, w1, "event two");
        expect("extend index: the software's value", ev == tpm2::OK && v == w2, tpm2::hex(v));
        tpm2::nv_undefine(t, tpm2::owner(), p2, xi);
    }
}

fn zeros_of(n: i64) -> u8[>..] {
    var z: u8[>..] = [];
    z.resize(n, 0);
    return z;
}

// The EK certificates in NV (swtpm_setup --create-ek-cert writes an RSA-2048
// one at 0x01C00002 and a P-384 one at 0x01C00016, the EKs persistent at
// 0x81010001 and 0x81010016): each parses, and its key is the EK's.
fn ek_cert(t: tpm2::Tpm&) {
    var pws = tpm2::pw();
    for which in 3 {
        let index = if which == 0 { tpm2::EK_CERT_RSA_INDEX } else if which == 1 { tpm2::EK_CERT_ECC_INDEX } else { tpm2::EK_CERT_ECC_P384_INDEX };
        let nm = if which == 0 { "RSA" } else if which == 1 { "ECC P-256" } else { "ECC P-384" };
        let der, e = tpm2::read_ek_cert(t, index);
        if e == tpm2::ERR_TPM && tpm2::rc_name(t.rc) == "TPM_RC_HANDLE" && (!want_ek_cert || which != 0) {
            skip(str("EK certificate ", nm), str("no index 0x", tpm2::hex_u32(index), ": ", tpm2::rc_text(t.rc)));
            continue;
        }
        if !check(t, str("EK certificate ", nm, " read from NV"), e) { continue; }
        let c, ec = x509::parse(der);
        if !expect(str("EK certificate ", nm, " parses"), ec == x509::OK) { continue; }
        let cert_spki = c.der[c.spki.start..c.spki.end];
        if which < 2 {
            let ek, ee = tpm2::create_primary(t, tpm2::endorsement(), pws, if which == 1 { tpm2::ek_ecc_template() } else { tpm2::ek_rsa_template() });
            if check(t, str("EK ", nm, " from the TCG template"), ee) {
                let spki, oks = tpm2::public_to_spki(ek.public);
                expect(str("EK certificate ", nm, ": the template EK's key"), oks && cert_spki == spki);
                flush(t, ek.handle);
            }
        }
        // The persistent EK swtpm_setup leaves.
        let ph: u32 = if which == 2 { 0x81010016 } else if which == 1 { 0x8101000a } else { 0x81010001 };
        let rp, qn, er = tpm2::read_public_tpm(t, ph);
        if er == tpm2::OK {
            let spki, oks = tpm2::public_to_spki(rp.public);
            expect(str("EK certificate ", nm, ": the persistent EK's key (0x", tpm2::hex_u32(ph), ")"), oks && cert_spki == spki);
        }
    }
}

fn attestation(t: tpm2::Tpm&) {
    var pws = tpm2::pw();
    for ecc in [false, true] {
        let nm = if ecc { "ECC" } else { "RSA" };
        let parent, ep = srk(t, ecc);
        if !check(t, str("SRK for an ", nm, " AK"), ep) { continue; }
        let pe = tpm2::object_of(parent);
        let ak, ea = tpm2::create_loaded(t, pe, pws, if ecc { tpm2::ak_ecc_template() } else { tpm2::ak_rsa_template() }, "ak auth");
        if !check(t, str("CreateLoaded ", nm, " AK"), ea) { flush(t, parent.handle); continue; }
        let ake = tpm2::object_of(ak, "ak auth");
        let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0x8000ff }, tpm2::PcrSel { hash: tpm2::ALG_SHA1, mask: 0x3 }];
        let nonce = "fresh nonce 1234";
        let q, eq = tpm2::quote(t, ake, pws, nonce, tpm2::ALG_NULL, tpm2::ALG_SHA256, sel);
        if check(t, str("Quote by the ", nm, " AK"), eq) {
            let vals, c, ev = tpm2::pcr_read(t, sel);
            let a, evq = tpm2::verify_quote(ak.public, q.attest, q.sig, nonce, sel, vals);
            if check(t, str("Quote ", nm, " verified (signature, nonce, PCR digest)"), evq) {
                expect("  qualifiedSigner is a Name", a.signer.len == 34);
            }
            let a2, ebad = tpm2::verify_quote(ak.public, q.attest, q.sig, "another nonce", sel, vals);
            expect(str("Quote ", nm, ": another nonce refused"), ebad == tpm2::ERR_NONCE);
            var vals2 = copy(vals);
            if vals2.len > 0 && vals2[0].len > 0 { vals2[0][0] ^= 1; }
            let a3, ebad2 = tpm2::verify_quote(ak.public, q.attest, q.sig, nonce, sel, vals2);
            expect(str("Quote ", nm, ": other PCR values refused"), ebad2 == tpm2::ERR_PCR);
        }
        // Certify a key, and its creation.
        var ko, ek = tpm2::create(t, pe, pws, tpm2::ecc_sign_template(tpm2::ECC_NIST_P256), "obj auth");
        if check(t, "Create a key to certify", ek) {
            let el = tpm2::load(t, pe, pws, ko);
            if el == tpm2::OK {
                var pws2 = tpm2::pw();
                let cq, ec = tpm2::certify(t, tpm2::object_of(ko, "obj auth"), ake, pws, pws2, "certify nonce", tpm2::ALG_NULL, tpm2::ALG_SHA256);
                if check(t, str("Certify by the ", nm, " AK"), ec) {
                    let a, ev = tpm2::verify_certify(ak.public, cq.attest, cq.sig, "certify nonce", ko.public);
                    check(t, str("Certify ", nm, " verified (signature, nonce, Name)"), ev);
                }
                let cc, ecc2 = tpm2::certify_creation(t, ake, tpm2::object_of(ko), pws, "creation nonce", ko.creation_hash,
                                                       tpm2::ALG_NULL, tpm2::ALG_SHA256, ko.ticket);
                if check(t, str("CertifyCreation by the ", nm, " AK"), ecc2) {
                    let a, ev = tpm2::verify_creation(ak.public, cc.attest, cc.sig, "creation nonce", ko.public, ko.creation_hash);
                    check(t, str("CertifyCreation ", nm, " verified (signature, nonce, Name, creation hash)"), ev);
                }
                flush(t, ko.handle);
            }
        }
        flush(t, ak.handle);
        flush(t, parent.handle);
    }
}

// MakeCredential in software (and on the TPM), ActivateCredential on the TPM.
fn credentials(t: tpm2::Tpm&) {
    var pws = tpm2::pw();
    for ecc in [false, true] {
        let nm = if ecc { "ECC" } else { "RSA" };
        let ek, ee = tpm2::create_primary(t, tpm2::endorsement(), pws, if ecc { tpm2::ek_ecc_template() } else { tpm2::ek_rsa_template() });
        if !check(t, str("EK ", nm, " for credentials"), ee) { continue; }
        // The AK under the EK's sibling, the SRK.
        let parent, ep = srk(t, true);
        let ak, ea = tpm2::create_loaded(t, tpm2::object_of(parent), pws, tpm2::ak_ecc_template(), "ak auth");
        flush(t, parent.handle);
        if !check(t, "AK for credentials", ea) { flush(t, ek.handle); continue; }
        let secret = "credential secret 0123456789abcd";
        let cred, ec = tpm2::make_credential(ek.public, ak.name, secret);
        if check(t, str("MakeCredential in software to the ", nm, " EK"), ec) {
            var es, eps = tpm2::ek_policy_session(t);
            if check(t, "  EK policy session (PolicySecret endorsement)", eps) {
                var akpw = tpm2::pw();
                let got, eact = tpm2::activate_credential(t, tpm2::object_of(ak, "ak auth"), tpm2::object_of(ek), akpw, es, cred);
                if check(t, str("ActivateCredential (", nm, " EK)"), eact) { expect("  the credential", got == secret); }
                flush(t, es.handle);
            }
            // The credential made for another Name is refused.
            var other = copy(ak.name);
            other[5] ^= 1;
            let cred2, ec2 = tpm2::make_credential(ek.public, other, secret);
            var es2, eps2 = tpm2::ek_policy_session(t);
            var akpw2 = tpm2::pw();
            let got2, eact2 = tpm2::activate_credential(t, tpm2::object_of(ak, "ak auth"), tpm2::object_of(ek), akpw2, es2, cred2);
            expect(str("ActivateCredential for another AK's Name refused (", nm, ")"), eact2 == tpm2::ERR_TPM, tpm2::describe(t, eact2));
            flush(t, es2.handle);
        }
        // The TPM's own MakeCredential with the EK's public key loaded.
        let ext, ex = tpm2::load_external(t, ek.public);
        if check(t, str("LoadExternal of the ", nm, " EK public"), ex) {
            let tc, etc = tpm2::make_credential_tpm(t, tpm2::object_of(ext), ak.name, secret);
            flush(t, ext.handle);
            if check(t, "MakeCredential on the TPM", etc) {
                var es3, eps3 = tpm2::ek_policy_session(t);
                var akpw3 = tpm2::pw();
                let got3, eact3 = tpm2::activate_credential(t, tpm2::object_of(ak, "ak auth"), tpm2::object_of(ek), akpw3, es3, tc);
                if check(t, str("  ActivateCredential of the TPM's (", nm, ")"), eact3) { expect("  the credential", got3 == secret); }
                flush(t, es3.handle);
            }
        }
        flush(t, ak.handle);
        flush(t, ek.handle);
    }
}

fn contexts(t: tpm2::Tpm&) {
    var pws = tpm2::pw();
    let parent, ep = srk(t, true);
    if !check(t, "SRK for contexts", ep) { return; }
    let k, ek = tpm2::create_loaded(t, tpm2::object_of(parent), pws, tpm2::ecc_sign_template(tpm2::ECC_NIST_P256));
    if check(t, "CreateLoaded key", ek) {
        let c, ec = tpm2::context_save(t, k.handle);
        if check(t, "ContextSave", ec) {
            flush(t, k.handle);
            let h, el = tpm2::context_load(t, c);
            if check(t, "ContextLoad", el) {
                let rp, qn, er = tpm2::read_public_tpm(t, h);
                expect("ContextLoad: the same key", er == tpm2::OK && rp.name == k.name);
                flush(t, h);
            }
        } else {
            flush(t, k.handle);
        }
    }
    // EvictControl: persist the SRK, read it, remove it.
    let ph: u32 = 0x81000100;
    tpm2::evict_control(t, tpm2::owner(), pws, tpm2::entity(ph), ph);
    if check(t, "EvictControl: persist the SRK", tpm2::evict_control(t, tpm2::owner(), pws, tpm2::object_of(parent), ph)) {
        let rp, qn, er = tpm2::read_public_tpm(t, ph);
        expect("ReadPublic of the persistent SRK", er == tpm2::OK && rp.name == parent.name);
        let hs, eh = tpm2::get_handles(t, 0x81000000);
        var found = false;
        for h in hs { if h == ph { found = true; } }
        expect("GetCapability(handles) lists it", eh == tpm2::OK && found);
        check(t, "EvictControl: remove it", tpm2::evict_control(t, tpm2::owner(), pws, tpm2::entity(ph), ph));
    }
    flush(t, parent.handle);
}

fn main() {
    var spec: u8[>..] = [];
    let args = args();
    var i = 1;
    while i < args.len {
        let a = args[i];
        if a == "--tpm" && i + 1 < args.len { spec.clear(); spec.append(args[i + 1]); i++; }
        else if a == "--only" && i + 1 < args.len { only.clear(); only.append(args[i + 1]); i++; }
        else if a == "--ek-cert" { want_ek_cert = true; }
        i++;
    }
    if spec.len == 0 { print("usage: live.goose -- --tpm tcp:HOST:PORT [--only NAME] [--ek-cert]"); exit(2); }
    var t, e = tpm2::open(spec);
    if e != tpm2::OK { print("cannot open ", spec, ": ", tpm2::describe(t, e)); exit(1); }
    if !check(t, "Startup", tpm2::startup(t)) { exit(1); }
    var lp = tpm2::pw();
    check(t, "DictionaryAttackLockReset", tpm2::da_lock_reset(t, tpm2::lockout(), lp));
    if want("basics") { basics(t); }
    if want("primaries") { primaries(t); }
    if want("signing") { signing(t); }
    if want("encryption") { encryption(t); }
    if want("sessions") { sessions(t); }
    if want("policies") { policies(t); }
    if want("nv") { nv(t); }
    if want("ekcert") { ek_cert(t); }
    if want("attestation") { attestation(t); }
    if want("credentials") { credentials(t); }
    if want("contexts") { contexts(t); }
    tpm2::close(t);
    print("\n", passed, " passed, ", failed, " failed");
    if failed > 0 { exit(1); }
}
