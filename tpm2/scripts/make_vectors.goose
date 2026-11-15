// Captures test/vectors.goose's TPM-made values from a TPM (swtpm, which
// follows the specification where tpmemu does not): public areas with the
// TPM's Names, quotes, Certify and CertifyCreation attestations with the
// PCR values and nonces, an NV index's public area and Name, and policy
// digests from PolicyGetDigest. The unit tests check tpm2's parsing,
// Names, signatures and policy calculator against them with no TPM.
//
//   goose scripts/make_vectors.goose -- --tpm tcp:127.0.0.1:2321 > test/vectors.goose
import std;
import os;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.transport;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.tpm2.policy;
import gslib.tpm2.attest;

fn out(name: const u8[:], b: const u8[:]) { print("let ", name, " = \"", tpm2::hex(b), "\";"); }

fn die(t: const tpm2::Tpm&, what: const u8[:], e: i64) {
    if e != tpm2::OK { write_stderr(str(what, ": ", tpm2::describe(t, e), "\n")); exit(1); }
}

fn main() {
    let a = args();
    if a.len != 3 || a[1] != "--tpm" { write_stderr("usage: make_vectors.goose -- --tpm SPEC\n"); exit(2); }
    var t, e = tpm2::open(a[2]);
    die(t, "open", e);
    die(t, "startup", tpm2::startup(t));
    var s = tpm2::pw();
    print("// Made by scripts/make_vectors.goose from swtpm: TPM-made public areas with");
    print("// their Names, attestations with what they attest, policy digests. Hex.");
    print("");
    print("namespace vectors;");
    print("");
    let ek, e1 = tpm2::create_primary(t, tpm2::endorsement(), s, tpm2::ek_rsa_template());
    die(t, "EK RSA", e1);
    out("EK_RSA_PUBLIC", tpm2::marshal_public(ek.public));
    out("EK_RSA_NAME", ek.name);
    tpm2::flush(t, ek.handle);
    let eke, e2 = tpm2::create_primary(t, tpm2::endorsement(), s, tpm2::ek_ecc_template());
    die(t, "EK ECC", e2);
    out("EK_ECC_PUBLIC", tpm2::marshal_public(eke.public));
    out("EK_ECC_NAME", eke.name);
    tpm2::flush(t, eke.handle);
    let srk, e3 = tpm2::create_primary(t, tpm2::owner(), s, tpm2::srk_ecc_template());
    die(t, "SRK", e3);
    let pe = tpm2::object_of(srk);
    tpm2::pcr_reset(t, 23, s);
    tpm2::pcr_extend(t, 23, s, tpm2::ALG_SHA256, tpm2::hash(tpm2::ALG_SHA256, "vector"));
    for ecc in [false, true] {
        let pre = if ecc { "ECC" } else { "RSA" };
        let ak, ea = tpm2::create_loaded(t, pe, s, if ecc { tpm2::ak_ecc_template() } else { tpm2::ak_rsa_template() });
        die(t, "AK", ea);
        out(str("AK_", pre, "_PUBLIC"), tpm2::marshal_public(ak.public));
        out(str("AK_", pre, "_NAME"), ak.name);
        let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0x8000ff }, tpm2::PcrSel { hash: tpm2::ALG_SHA1, mask: 0x3 }];
        let q, eq = tpm2::quote(t, tpm2::object_of(ak), s, "quote nonce", tpm2::ALG_NULL, tpm2::ALG_SHA256, sel);
        die(t, "quote", eq);
        let vals, c, ev = tpm2::pcr_read(t, sel);
        die(t, "pcr_read", ev);
        out(str("QUOTE_", pre, "_ATTEST"), q.attest);
        out(str("QUOTE_", pre, "_SIG"), tpm2::marshal_signature(q.sig));
        var all: u8[>..] = [];
        for v in vals { all.append(v); }
        out(str("QUOTE_", pre, "_PCRS"), all);
        if ecc {
            var ko, ek2 = tpm2::create(t, pe, s, tpm2::ecc_sign_template(tpm2::ECC_NIST_P256));
            die(t, "create", ek2);
            die(t, "load", tpm2::load(t, pe, s, ko));
            out("CERTIFIED_PUBLIC", tpm2::marshal_public(ko.public));
            out("CERTIFIED_CREATION_HASH", ko.creation_hash);
            var s2 = tpm2::pw();
            let cq, ec = tpm2::certify(t, tpm2::object_of(ko), tpm2::object_of(ak), s, s2, "certify nonce", tpm2::ALG_NULL, tpm2::ALG_SHA256);
            die(t, "certify", ec);
            out("CERTIFY_ATTEST", cq.attest);
            out("CERTIFY_SIG", tpm2::marshal_signature(cq.sig));
            let cc, ecc2 = tpm2::certify_creation(t, tpm2::object_of(ak), tpm2::object_of(ko), s, "creation nonce", ko.creation_hash,
                                                  tpm2::ALG_NULL, tpm2::ALG_SHA256, ko.ticket);
            die(t, "certify_creation", ecc2);
            out("CREATION_ATTEST", cc.attest);
            out("CREATION_SIG", tpm2::marshal_signature(cc.sig));
            tpm2::flush(t, ko.handle);
        }
        tpm2::flush(t, ak.handle);
    }
    tpm2::flush(t, srk.handle);
    // An NV index's public area and Name, written and not.
    let index: u32 = 0x01500030;
    tpm2::nv_undefine(t, tpm2::owner(), s, index);
    let np = tpm2::NvPublic { index: index, attrs: tpm2::NV_AUTHWRITE | tpm2::NV_AUTHREAD, size: 16 };
    die(t, "nv_define", tpm2::nv_define(t, tpm2::owner(), s, np, ""));
    let n1, name1, er1 = tpm2::nv_read_public(t, index);
    die(t, "nv_read_public", er1);
    out("NV_PUBLIC", tpm2::marshal_nv_public(n1));
    out("NV_NAME", name1);
    tpm2::nv_undefine(t, tpm2::owner(), s, index);
    // Policy digests, from a trial session each.
    tpm2::pcr_reset(t, 23, s);
    for step in 4 {
        var ps, ep = tpm2::start_session(t, tpm2::SESSION_TRIAL);
        die(t, "trial", ep);
        var nm: u8[>..] = [];
        if step == 0 {
            nm.append("POLICY_PCR23_ZERO");
            let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 1 << 23 }];
            die(t, "PolicyPCR", tpm2::policy_pcr_tpm(t, ps, sel));
        } else if step == 1 {
            nm.append("POLICY_COMMAND_CODE_UNSEAL_AUTH_VALUE");
            die(t, "PolicyCommandCode", tpm2::policy_command_code_tpm(t, ps, tpm2::CC_Unseal));
            die(t, "PolicyAuthValue", tpm2::policy_auth_value_tpm(t, ps));
        } else if step == 2 {
            nm.append("POLICY_SECRET_OWNER_REF");
            var a2 = tpm2::pw();
            die(t, "PolicySecret", tpm2::policy_secret_tpm(t, tpm2::owner(), a2, ps, "a policy ref"));
        } else {
            nm.append("POLICY_OR_AUTHVALUE_PASSWORD_CC");
            var b1 = tpm2::policy();
            tpm2::policy_auth_value(b1);
            var b2 = tpm2::policy();
            tpm2::policy_command_code(b2, tpm2::CC_NV_Read);
            let br = [b1.digest, b2.digest];
            die(t, "PolicyAuthValue", tpm2::policy_auth_value_tpm(t, ps));
            die(t, "PolicyOR", tpm2::policy_or_tpm(t, ps, br));
        }
        let d, eg = tpm2::policy_get_digest(t, ps);
        die(t, "PolicyGetDigest", eg);
        out(nm, d);
        tpm2::flush(t, ps.handle);
    }
    tpm2::close(t);
}
