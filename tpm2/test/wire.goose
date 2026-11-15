// tpm2's wire format with no TPM: TPMT_PUBLIC, TPMT_SIGNATURE, TPMS_NV_PUBLIC
// and TPML_PCR_SELECTION round trips; public areas a TPM (swtpm) made, read
// and given the Names the TPM gave them; keys to SubjectPublicKeyInfo and
// back; response codes by name; KDFa and KDFe against Python's hashlib
// (scripts/make_vectors.py); the policy calculator against well-known
// digests (the EK policy, PolicyAuthValue) and swtpm's PolicyGetDigest;
// structures that lie about their sizes.
import std;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.tpm2.policy;
import gslib.crypto.x509;
import gslib.encoding.asn1;
import vectors;
import known;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn h(s: const u8[:]) -> u8[>..] {
    let b, ok = tpm2::unhex(s);
    assert(ok);
    return b;
}

fn templates() {
    let ts = [tpm2::ek_rsa_template(), tpm2::ek_ecc_template(), tpm2::srk_rsa_template(), tpm2::srk_ecc_template(),
              tpm2::ak_rsa_template(), tpm2::ak_ecc_template(), tpm2::rsa_sign_template(),
              tpm2::ecc_sign_template(tpm2::ECC_NIST_P384), tpm2::rsa_decrypt_template(),
              tpm2::ecdh_template(tpm2::ECC_NIST_P256), tpm2::sealed_template(h(known::POLICY_AUTH_VALUE)),
              tpm2::sealed_template(""), tpm2::hmac_key_template(tpm2::ALG_SHA384)];
    for p in ts {
        let b = tpm2::marshal_public(p);
        let q, ok = tpm2::parse_public(b);
        check(str("template round trip, type ", p.kind), ok && tpm2::marshal_public(q) == b && q.attrs == p.attrs);
        // Each byte short is refused, and so is one byte more.
        var all_short = true;
        for n in b.len {
            let r, okr = tpm2::parse_public(b[..n]);
            if okr { all_short = false; }
        }
        check("truncated public areas refused", all_short);
        var longer = copy(b);
        longer.push(0);
        let r2, ok2 = tpm2::parse_public(longer);
        check("a public area with a byte left over refused", !ok2);
    }
    // The TCG EK templates, byte for byte (EK Credential Profile B.3.3, B.3.4).
    let ek = tpm2::marshal_public(tpm2::ek_rsa_template());
    check("EK RSA template L-1", tpm2::hex(ek[..48]) ==
          "0001000b000300b20020837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa000600800043");
    check("EK RSA template: 2048 bits, exponent 0, 256 zero bytes", tpm2::hex(ek[48..58]) == "00100800000000000100" && ek.len == 58 + 256);
    let eke = tpm2::marshal_public(tpm2::ek_ecc_template());
    check("EK ECC template L-2", tpm2::hex(eke[..56]) ==
          "0023000b000300b20020837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa0006008000430010000300100020"
          && eke.len == 56 + 32 + 2 + 32);
}

fn tpm_made() {
    let pubs = [vectors::EK_RSA_PUBLIC, vectors::EK_ECC_PUBLIC, vectors::AK_RSA_PUBLIC, vectors::AK_ECC_PUBLIC];
    let names = [vectors::EK_RSA_NAME, vectors::EK_ECC_NAME, vectors::AK_RSA_NAME, vectors::AK_ECC_NAME];
    for i in pubs.len {
        let b = h(pubs[i]);
        let p, ok = tpm2::parse_public(b);
        check(str("swtpm's public area ", i, " parses"), ok);
        check(str("swtpm's public area ", i, " marshals back"), tpm2::marshal_public(p) == b);
        check(str("swtpm's public area ", i, ": its Name"), tpm2::hex(tpm2::public_name(p)) == names[i]);
        // To SubjectPublicKeyInfo, read by x509, and back.
        let spki, oks = tpm2::public_to_spki(p);
        let t, okt = asn1::parse(spki);
        let kind, key, okk = x509::spki_of(spki, t);
        check(str("SubjectPublicKeyInfo ", i, " read by x509"), oks && okt && okk
              && kind == (if p.kind == tpm2::ALG_RSA { x509::KEY_RSA } else { x509::KEY_EC_P256 }));
        let q, eq = tpm2::public_from_spki(spki, p);
        check(str("SubjectPublicKeyInfo ", i, " back to the same Name"), eq == tpm2::OK && tpm2::public_name(q) == tpm2::public_name(p));
    }
    let ek, ok = tpm2::parse_public(h(vectors::EK_RSA_PUBLIC));
    check("swtpm's EK has the EK policy", ek.policy == h(known::POLICY_EK) && ek.attrs == tpm2::EK_ATTRS);
    check("swtpm's EK: what the template asked", tpm2::matches_template(ek, tpm2::ek_rsa_template()));
    // NV.
    let r_b = h(vectors::NV_PUBLIC);
    var r = tpm2::reader(r_b);
    let n = tpm2::read_nv_public(r);
    check("NV public parses", r.ok && tpm2::left(r) == 0 && n.index == 0x01500030 && n.size == 16);
    check("NV public marshals back", tpm2::marshal_nv_public(n) == h(vectors::NV_PUBLIC));
    check("NV Name", tpm2::hex(tpm2::nv_name(n)) == vectors::NV_NAME);
    // Handles' own Names.
    check("owner's Name", tpm2::hex(tpm2::handle_name(tpm2::RH_OWNER)) == "40000001");
}

fn signatures() {
    for s in [vectors::QUOTE_RSA_SIG, vectors::QUOTE_ECC_SIG, vectors::CERTIFY_SIG] {
        let b = h(s);
        let sig, ok = tpm2::parse_signature(b);
        check("signature round trip", ok && tpm2::marshal_signature(sig) == b);
        let short, oks = tpm2::parse_signature(b[..b.len - 1]);
        check("truncated signature refused", !oks);
    }
    let sig, ok = tpm2::parse_signature(h("0014000b0300aabbcc"));
    check("an RSA signature longer than the buffer refused", !ok);
    let sig2, ok2 = tpm2::parse_signature(h("00990000"));
    check("a signature of an unknown scheme refused", !ok2);
}

fn pcrs() {
    var b: u8[>..] = [];
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0x8000ff }, tpm2::PcrSel { hash: tpm2::ALG_SHA1, mask: 0x3 }];
    tpm2::put_pcr_selection(b, sel);
    check("TPML_PCR_SELECTION bytes", tpm2::hex(b) == "00000002000b03ff0080000403030000");
    var r = tpm2::reader(b);
    let back = tpm2::read_pcr_selection(r);
    check("TPML_PCR_SELECTION round trip", r.ok && back.len == 2 && back[0].mask == 0x8000ff && back[1].hash == tpm2::ALG_SHA1);
    let r2_b = h("00000005000b03ff0000");
    var r2 = tpm2::reader(r2_b);
    let x = tpm2::read_pcr_selection(r2);
    check("more than 4 banks refused", !r2.ok);
    let r3_b = h("00000001000b09ffffffffffffffffff");
    var r3 = tpm2::reader(r3_b);
    let y = tpm2::read_pcr_selection(r3);
    check("a sizeofSelect over 4 refused", !r3.ok);
    let m, ok = tpm2::parse_pcr_list("0-3,7,23");
    check("PCR list", ok && m == 0x80008f);
    let m2, ok2 = tpm2::parse_pcr_list("24");
    check("PCR 24 refused", !ok2);
    let l = tpm2::pcr_list(0x800003);
    check("pcr_list", l.len == 3 && l[2] == 23);
    // PCR_Extend in software.
    let z: u8[32] = [0; 32];
    check("extend of zeros by zeros", tpm2::hex(tpm2::extend_value(tpm2::ALG_SHA256, z, z))
          == "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
}

fn rcs() {
    check("rc 0x28b", tpm2::rc_text(0x28b) == "TPM_RC_HANDLE (handle 2, 0x28b)");
    check("rc 0x98e", tpm2::rc_text(0x98e) == "TPM_RC_AUTH_FAIL (session 1, 0x98e)");
    check("rc 0x1c4", tpm2::rc_text(0x1c4) == "TPM_RC_VALUE (parameter 1, 0x1c4)");
    check("rc 0x2d5", tpm2::rc_text(0x2d5) == "TPM_RC_SIZE (parameter 2, 0x2d5)");
    check("rc 0x9a2", tpm2::rc_text(0x9a2) == "TPM_RC_BAD_AUTH (session 1, 0x9a2)");
    check("rc 0x100", tpm2::rc_text(0x100) == "TPM_RC_INITIALIZE (0x100)");
    check("rc 0x921", tpm2::rc_name(0x921) == "TPM_RC_LOCKOUT");
    check("rc 0x922", tpm2::rc_name(0x922) == "TPM_RC_RETRY");
    check("rc 0x14c", tpm2::rc_name(0x14c) == "TPM_RC_NV_DEFINED");
    check("rc 0x99d", tpm2::rc_text(0x99d) == "TPM_RC_POLICY_FAIL (session 1, 0x99d)");
    check("rc 0x84", tpm2::rc_text(0x84) == "TPM_RC_VALUE (0x84)");
    check("rc vendor", starts_with(tpm2::rc_text(0x501), "vendor-defined"));
    check("rc TPM 1.2", starts_with(tpm2::rc_text(0x00b), "TPM 1.2"));
    check("rc unknown", starts_with(tpm2::rc_text(0x13f), "unknown"));
}

fn kdfs() {
    check("KDFa SHA-256 256 bits", tpm2::hex(tpm2::kdfa(tpm2::ALG_SHA256, "a key", "LABEL", "context u", "context v", 256)) == known::KDFA_SHA256_256);
    check("KDFa SHA-256 600 bits", tpm2::hex(tpm2::kdfa(tpm2::ALG_SHA256, "a key", "LABEL", "context u", "context v", 600)) == known::KDFA_SHA256_600);
    check("KDFa SHA-256 100 bits", tpm2::hex(tpm2::kdfa(tpm2::ALG_SHA256, "a key", "LABEL", "context u", "context v", 100)) == known::KDFA_SHA256_100);
    check("KDFa: a label with its 0", tpm2::kdfa(tpm2::ALG_SHA256, "a key", "LABEL\x00", "context u", "context v", 256)
          == tpm2::kdfa(tpm2::ALG_SHA256, "a key", "LABEL", "context u", "context v", 256));
    check("KDFa SHA-1", tpm2::hex(tpm2::kdfa(tpm2::ALG_SHA1, "a key", "STORAGE", "\x00\x0bname", "", 160)) == known::KDFA_SHA1_160);
    check("KDFa SHA-384", tpm2::hex(tpm2::kdfa(tpm2::ALG_SHA384, "", "CFB", "newer", "older", 128)) == known::KDFA_SHA384_128);
    var z: u8[>..] = [];
    var u: u8[>..] = [];
    var v: u8[>..] = [];
    z.resize(32, 0x11); u.resize(32, 0x22); v.resize(32, 0x33);
    check("KDFe SHA-256", tpm2::hex(tpm2::kdfe(tpm2::ALG_SHA256, z, "IDENTITY", u, v, 256)) == known::KDFE_SHA256_256);
    z.resize(48, 0x11); u.resize(48, 0x22); v.resize(48, 0x33);
    check("KDFe SHA-384", tpm2::hex(tpm2::kdfe(tpm2::ALG_SHA384, z, "SECRET", u, v, 512)) == known::KDFE_SHA384_512);
}

fn policies() {
    var p = tpm2::policy();
    tpm2::policy_auth_value(p);
    check("PolicyAuthValue", tpm2::hex(p.digest) == known::POLICY_AUTH_VALUE);
    var pp = tpm2::policy();
    tpm2::policy_password(pp);
    check("PolicyPassword is PolicyAuthValue's", pp.digest == p.digest);
    var ek = tpm2::policy();
    tpm2::policy_secret(ek, tpm2::handle_name(tpm2::RH_ENDORSEMENT));
    check("PolicySecret(endorsement): the EK policy", tpm2::hex(ek.digest) == known::POLICY_EK && ek.digest == tpm2::EK_POLICY_SHA256);
    var cc = tpm2::policy();
    tpm2::policy_command_code(cc, tpm2::CC_Unseal);
    check("PolicyCommandCode(Unseal)", tpm2::hex(cc.digest) == known::POLICY_CC_UNSEAL);
    var pcr = tpm2::policy();
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 1 << 23 }];
    var z: u8[..64][>..] = [];
    z.push([]);
    for i in 32 { z[0].push(0); }
    tpm2::policy_pcr(pcr, sel, tpm2::pcr_digest(tpm2::ALG_SHA256, z));
    check("PolicyPCR(sha256:23 zero)", tpm2::hex(pcr.digest) == known::POLICY_PCR23_ZERO);
    check("PolicyPCR: swtpm's PolicyGetDigest", tpm2::hex(pcr.digest) == vectors::POLICY_PCR23_ZERO);
    var or = tpm2::policy();
    let br = [p.digest, cc.digest];
    check("PolicyOR", tpm2::policy_or(or, br) && tpm2::hex(or.digest) == known::POLICY_OR);
    let one = [p.digest];
    var bad = tpm2::policy();
    check("PolicyOR of one branch refused", !tpm2::policy_or(bad, one));
    var au = tpm2::policy();
    tpm2::policy_auth_value(au);    // PolicyAuthorize resets it
    tpm2::policy_authorize(au, h(known::AUTHORIZE_NAME), "ref");
    check("PolicyAuthorize", tpm2::hex(au.digest) == known::POLICY_AUTHORIZE);
    // swtpm's.
    var c2 = tpm2::policy();
    tpm2::policy_command_code(c2, tpm2::CC_Unseal);
    tpm2::policy_auth_value(c2);
    check("PolicyCommandCode + PolicyAuthValue: swtpm's", tpm2::hex(c2.digest) == vectors::POLICY_COMMAND_CODE_UNSEAL_AUTH_VALUE);
    var s2 = tpm2::policy();
    tpm2::policy_secret(s2, tpm2::handle_name(tpm2::RH_OWNER), "a policy ref");
    check("PolicySecret(owner, ref): swtpm's", tpm2::hex(s2.digest) == vectors::POLICY_SECRET_OWNER_REF);
    var o2 = tpm2::policy();
    var b1 = tpm2::policy();
    tpm2::policy_auth_value(b1);
    var b2 = tpm2::policy();
    tpm2::policy_command_code(b2, tpm2::CC_NV_Read);
    tpm2::policy_auth_value(o2);
    let br2 = [b1.digest, b2.digest];
    tpm2::policy_or(o2, br2);
    check("PolicyOR: swtpm's", tpm2::hex(o2.digest) == vectors::POLICY_OR_AUTHVALUE_PASSWORD_CC);
    // SHA-384 policies are 48 bytes.
    var p384 = tpm2::policy(tpm2::ALG_SHA384);
    tpm2::policy_auth_value(p384);
    check("SHA-384 policy", p384.digest.len == 48);
}

fn readers() {
    // A TPM2B whose size is past the buffer, or past its type's maximum.
    let r_b = h("0005aabb");
    var r = tpm2::reader(r_b);
    let b = tpm2::get_2b(r, 64);
    check("TPM2B past the end refused", !r.ok && b.len == 0);
    var r2b = h("0041");
    r2b.append(zeros65());
    var r2 = tpm2::reader(r2b);
    let b2 = tpm2::get_2b(r2, 64);
    check("TPM2B over its maximum refused", !r2.ok);
    // Once failed, a reader stays failed.
    let x = tpm2::get_u32(r);
    check("a failed reader stays failed", !r.ok && x == 0);
    // An RSA public area whose modulus is over 512 bytes.
    var big: u8[>..] = [];
    tpm2::put_u16(big, tpm2::ALG_RSA);
    tpm2::put_u16(big, tpm2::ALG_SHA256);
    tpm2::put_u32(big, tpm2::SIGN_ATTRS);
    tpm2::put_u16(big, 0);
    tpm2::put_u16(big, tpm2::ALG_NULL);
    tpm2::put_u16(big, tpm2::ALG_NULL);
    tpm2::put_u16(big, 8192);
    tpm2::put_u32(big, 0);
    tpm2::put_u16(big, 1024);
    big.resize(big.len + 1024, 0xff);
    let p, ok = tpm2::parse_public(big);
    check("an RSA modulus over 512 bytes refused", !ok);
    // A TPM2B_PUBLIC whose size is not its TPMT_PUBLIC's.
    var b3: u8[>..] = [];
    let inner = tpm2::marshal_public(tpm2::ak_ecc_template());
    tpm2::put_u16(b3, (inner.len + 1) as u16);
    b3.append(inner);
    b3.push(0);
    var r4 = tpm2::reader(b3);
    let q, qb = tpm2::read_public_2b(r4);
    check("TPM2B_PUBLIC with a byte to spare refused", !r4.ok);
}

fn zeros65() -> u8[>..] {
    var z: u8[>..] = [];
    z.resize(65, 0);
    return z;
}

fn hexes() {
    let b, ok = tpm2::unhex("00ff10Ab");
    check("unhex", ok && b.len == 4 && b[3] == 0xab);
    let b2, ok2 = tpm2::unhex("0g");
    check("unhex refuses non-hex", !ok2);
    let b3, ok3 = tpm2::unhex("abc");
    check("unhex refuses an odd length", !ok3);
    check("hex", tpm2::hex(b) == "00ff10ab");
}

fn main() {
    templates();
    tpm_made();
    signatures();
    pcrs();
    rcs();
    kdfs();
    policies();
    readers();
    hexes();
    print(checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
