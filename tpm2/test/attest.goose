// tpm2's attestation checks with no TPM: swtpm's quotes (RSA and ECC AKs),
// Certify and CertifyCreation verified, and each fault they look for (a
// wrong nonce, other PCR values, another selection, a changed byte,
// another key, a key that is not an AK, another type); TPMS_ATTEST
// structures that lie; a crypto-agile event log (scripts/make_vectors.py)
// replayed to the PCRs Python computed, and broken logs; MakeCredential
// to software EKs (RSA and ECC) whose private keys recover it here as
// ActivateCredential would, the integrity HMAC and the Name binding included.
import std;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.tpm2.attest;
import gslib.crypto.bignum;
import gslib.crypto.bignum.rsa;
import gslib.crypto.bignum.ec;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.modes;
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

fn pub_of(s: const u8[:]) -> tpm2::Public {
    let b = h(s);
    let p, ok = tpm2::parse_public(b);
    assert(ok);
    return p;
}

fn sig_of(s: const u8[:]) -> tpm2::Signature {
    let b = h(s);
    let g, ok = tpm2::parse_signature(b);
    assert(ok);
    return g;
}

// The PCR values a vector holds, 32 or 20 bytes each by the selection.
fn values_of(s: const u8[:], sel: const tpm2::PcrSel[:]) -> u8[..64][>..] {
    let b = h(s);
    var out: u8[..64][>..] = [];
    var at = 0;
    for x in sel {
        let n = tpm2::digest_size(x.hash);
        for i in tpm2::pcr_list(x.mask) {
            var v: u8[..64] = [];
            v.append(b[at..at + n]);
            out.push(v);
            at += n;
        }
    }
    assert(at == b.len);
    return out;
}

fn quotes() {
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0x8000ff }, tpm2::PcrSel { hash: tpm2::ALG_SHA1, mask: 0x3 }];
    for ecc in [false, true] {
        let nm = if ecc { "ECC" } else { "RSA" };
        let ak = pub_of(if ecc { vectors::AK_ECC_PUBLIC } else { vectors::AK_RSA_PUBLIC });
        let other = pub_of(if ecc { vectors::AK_RSA_PUBLIC } else { vectors::AK_ECC_PUBLIC });
        let attest = h(if ecc { vectors::QUOTE_ECC_ATTEST } else { vectors::QUOTE_RSA_ATTEST });
        let sig = sig_of(if ecc { vectors::QUOTE_ECC_SIG } else { vectors::QUOTE_RSA_SIG });
        let vals = values_of(if ecc { vectors::QUOTE_ECC_PCRS } else { vectors::QUOTE_RSA_PCRS }, sel);
        let a, e = tpm2::verify_quote(ak, attest, sig, "quote nonce", sel, vals);
        check(str("swtpm's ", nm, " quote verifies"), e == tpm2::OK);
        check(str(nm, " quote: its fields"), a.kind == tpm2::ST_ATTEST_QUOTE && a.extra == "quote nonce" && a.sel.len == 2
              && a.signer.len == 34 && a.magic == tpm2::GENERATED_VALUE);
        let a1, e1 = tpm2::verify_quote(ak, attest, sig, "quote nonce!", sel, vals);
        check(str(nm, " quote: another nonce"), e1 == tpm2::ERR_NONCE);
        var v2 = copy(vals);
        v2[8][3] ^= 0x40;
        let a2, e2 = tpm2::verify_quote(ak, attest, sig, "quote nonce", sel, v2);
        check(str(nm, " quote: another PCR value"), e2 == tpm2::ERR_PCR);
        let sel2 = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0x8000ff }];
        let a3, e3 = tpm2::verify_quote(ak, attest, sig, "quote nonce", sel2, vals);
        check(str(nm, " quote: another selection"), e3 == tpm2::ERR_PCR);
        let a3b, e3b = tpm2::verify_quote(ak, attest, sig, "quote nonce", sel, vals[..9]);
        check(str(nm, " quote: a value missing"), e3b == tpm2::ERR_PCR);
        for i in attest.len {
            var bad = copy(attest);
            bad[i] ^= 1;
            let a4, e4 = tpm2::verify_quote(ak, bad, sig, "quote nonce", sel, vals);
            if e4 != tpm2::ERR_SIGNATURE { check(str(nm, " quote: byte ", i, " changed"), false); }
        }
        check(str(nm, " quote: every byte is signed"), true);
        let a5, e5 = tpm2::verify_quote(other, attest, sig, "quote nonce", sel, vals);
        check(str(nm, " quote: another AK"), e5 == tpm2::ERR_SIGNATURE);
        var sig2 = sig;
        if ecc { sig2.s[5] ^= 1; } else { sig2.sig[5] ^= 1; }
        let a6, e6 = tpm2::verify_quote(ak, attest, sig2, "quote nonce", sel, vals);
        check(str(nm, " quote: a changed signature"), e6 == tpm2::ERR_SIGNATURE);
        var notak = ak;
        notak.attrs &= ~tpm2::OBJ_RESTRICTED;
        let a7, e7 = tpm2::verify_quote(notak, attest, sig, "quote nonce", sel, vals);
        check(str(nm, " quote: a key that is not restricted is not an AK"), e7 == tpm2::ERR_ARG);
        var sig3 = sig;
        sig3.hash = tpm2::ALG_SHA384;
        let a8, e8 = tpm2::verify_quote(ak, attest, sig3, "quote nonce", sel, vals);
        check(str(nm, " quote: the signature's hash changed"), e8 == tpm2::ERR_SIGNATURE);
    }
    // A Certify given as a quote: signed, but of another type.
    let ak = pub_of(vectors::AK_ECC_PUBLIC);
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 1 }];
    var one: u8[..64][>..] = [];
    one.push([]);
    let cert_attest = h(vectors::CERTIFY_ATTEST);
    let a9, e9 = tpm2::verify_quote(ak, cert_attest, sig_of(vectors::CERTIFY_SIG), "certify nonce", sel, one);
    check("a Certify is not a quote", e9 == tpm2::ERR_TYPE);
}

fn certifies() {
    let ak = pub_of(vectors::AK_ECC_PUBLIC);
    let obj = pub_of(vectors::CERTIFIED_PUBLIC);
    let attest = h(vectors::CERTIFY_ATTEST);
    let a, e = tpm2::verify_certify(ak, attest, sig_of(vectors::CERTIFY_SIG), "certify nonce", obj);
    check("swtpm's Certify verifies", e == tpm2::OK && a.name == tpm2::public_name(obj) && a.qname.len == 34);
    let other = pub_of(vectors::AK_RSA_PUBLIC);
    let a1, e1 = tpm2::verify_certify(ak, attest, sig_of(vectors::CERTIFY_SIG), "certify nonce", other);
    check("Certify: another object", e1 == tpm2::ERR_NAME);
    let a2, e2 = tpm2::verify_certify(ak, attest, sig_of(vectors::CERTIFY_SIG), "", obj);
    check("Certify: another nonce", e2 == tpm2::ERR_NONCE);
    let cattest = h(vectors::CREATION_ATTEST);
    let ch = h(vectors::CERTIFIED_CREATION_HASH);
    let c, ec = tpm2::verify_creation(ak, cattest, sig_of(vectors::CREATION_SIG), "creation nonce", obj, ch);
    check("swtpm's CertifyCreation verifies", ec == tpm2::OK && c.creation_hash == ch);
    var ch2 = copy(ch);
    ch2[0] ^= 1;
    let c2, ec2 = tpm2::verify_creation(ak, cattest, sig_of(vectors::CREATION_SIG), "creation nonce", obj, ch2);
    check("CertifyCreation: another creation hash", ec2 == tpm2::ERR_INTEGRITY);
    // TPMS_ATTEST that lie.
    let short, es = tpm2::parse_attest(attest[..attest.len - 1]);
    check("TPMS_ATTEST truncated", es == tpm2::ERR_MALFORMED);
    var longer = copy(attest);
    longer.push(0);
    let l, el = tpm2::parse_attest(longer);
    check("TPMS_ATTEST with a byte left over", el == tpm2::ERR_MALFORMED);
    var magic = copy(attest);
    magic[0] = 0;
    let m, em = tpm2::parse_attest(magic);
    check("TPMS_ATTEST not TPM-generated", em == tpm2::ERR_MALFORMED);
    var big = copy(attest);
    big[6] = 0xff;     // qualifiedSigner's size
    let b, eb = tpm2::parse_attest(big);
    check("TPMS_ATTEST: a Name past the end", eb == tpm2::ERR_MALFORMED);
    var kind = copy(attest);
    kind[5] = 0x19;    // TPM_ST_ATTEST_TIME
    let k, ek = tpm2::parse_attest(kind);
    check("TPMS_ATTEST of a type not read", ek == tpm2::ERR_UNSUPPORTED);
}

fn event_logs() {
    let log = h(known::EVENT_LOG);
    let r, e = tpm2::replay_event_log(log, tpm2::ALG_SHA256);
    check("event log replays (SHA-256)", e == tpm2::OK && r.events == 8);
    var all: u8[>..] = [];
    for v in r.pcrs { all.append(v); }
    check("event log: Python's SHA-256 PCRs", tpm2::hex(all) == known::EVENT_LOG_PCRS_SHA256);
    let r1, e1 = tpm2::replay_event_log(log, tpm2::ALG_SHA1);
    var all1: u8[>..] = [];
    for v in r1.pcrs { all1.append(v); }
    check("event log: Python's SHA-1 PCRs", e1 == tpm2::OK && tpm2::hex(all1) == known::EVENT_LOG_PCRS_SHA1);
    check("event log: PCR 0 started at locality 3", r.pcrs[0] != r.pcrs[2]);
    let r2, e2 = tpm2::replay_event_log(log, tpm2::ALG_SHA384);
    check("event log: a bank it does not have", e2 == tpm2::ERR_EVENTLOG);
    // Against PCR values, as from a quote.
    var vals: u8[..64][>..] = [];
    for i in [0, 1, 4, 7] { vals.push(r.pcrs[i]); }
    check("event log matches PCRs 0, 1, 4, 7", tpm2::check_event_log(log, tpm2::ALG_SHA256, 0x93, vals) == tpm2::OK);
    vals[2][0] ^= 1;
    check("event log against another PCR 4", tpm2::check_event_log(log, tpm2::ALG_SHA256, 0x93, vals) == tpm2::ERR_PCR);
    // Every truncation is refused, or (at an event's boundary) replays fewer events.
    var ok = true;
    for n in log.len {
        let rt, et = tpm2::replay_event_log(log[..n], tpm2::ALG_SHA256);
        if et == tpm2::OK && rt.events >= 8 { ok = false; }
    }
    check("truncated event logs", ok);
    var bad = copy(log);
    bad[4] = 1;        // the first event is not EV_NO_ACTION
    let r3, e3 = tpm2::replay_event_log(bad, tpm2::ALG_SHA256);
    check("event log without the Spec ID header", e3 == tpm2::ERR_EVENTLOG);
    // An event naming PCR 24: the first TCG_PCR_EVENT2 starts after the header.
    let start = 32 + 37;
    var bad3 = copy(log);    // past the StartupLocality event: 12 + 2 + 20 + 2 + 32 + 4 + 17 = 89
    bad3[start + 89] = 24;
    let r4, e4 = tpm2::replay_event_log(bad3, tpm2::ALG_SHA256);
    check("event log naming PCR 24", e4 == tpm2::ERR_EVENTLOG);
    var bad4 = copy(log);
    bad4[start + 89 + 8] = 0xff;    // digest count
    let r5, e5 = tpm2::replay_event_log(bad4, tpm2::ALG_SHA256);
    check("event log with 255 digests in an event", e5 == tpm2::ERR_EVENTLOG);
    // StartupLocality only before PCR 0's first extend, and once: else events
    // put before it would be thrown away and the real PCR 0 still match.
    let loc = log[start..start + 89];
    var twice: u8[>..] = [];
    twice.append(log[..start + 89]);
    twice.append(loc);
    twice.append(log[start + 89..]);
    let r6, e6 = tpm2::replay_event_log(twice, tpm2::ALG_SHA256);
    check("event log with two StartupLocality events", e6 == tpm2::ERR_EVENTLOG);
    var late: u8[>..] = [];
    late.append(log[..start]);
    late.append(log[start + 89..]);
    late.append(loc);
    let r7, e7 = tpm2::replay_event_log(late, tpm2::ALG_SHA256);
    check("event log with StartupLocality after PCR 0 was extended", e7 == tpm2::ERR_EVENTLOG);
}

// ActivateCredential in software, with the EK's private key: what the TPM
// does (Part 3 §12.5), to check make_credential.
fn activate(ek: tpm2::Public, seed: const u8[:], name: const u8[:], c: const tpm2::Credential&) -> u8[>..], bool {
    var out: u8[>..] = [];
    var r = tpm2::reader(c.blob);
    let mac = tpm2::get_2b(r, 64);
    let enc = tpm2::get_bytes(r, tpm2::left(r));
    if !r.ok { return out, false; }
    let hkey = tpm2::kdfa(ek.name_alg, seed, "INTEGRITY", "", "", 8 * tpm2::digest_size(ek.name_alg));
    var m: u8[>..] = [];
    m.append(enc);
    m.append(name);
    if tpm2::hmac(ek.name_alg, hkey, m) != mac { return out, false; }
    let sym = tpm2::kdfa(ek.name_alg, seed, "STORAGE", name, "", ek.sym_bits);
    var cv: u8[>..] = [];
    cv.append(enc);
    let aes = bignum::aes_init(sym);
    let iv = tpm2::zeros(16);
    bignum::cfb_decrypt(aes, iv, cv);
    if cv.len < 2 || tpm2::be16(cv, 0) != cv.len - 2 { return out, false; }
    out.append(cv[2..]);
    return out, true;
}

fn credentials() {
    let name = h(vectors::AK_ECC_NAME);
    let secret = "0123456789abcdef0123456789abcdef";
    // RSA: a software key in the EK template's shape.
    let rk = bignum::rsa_generate(2048);
    var nb: u8[>..] = [];
    var li = 63;
    while li >= 0 {
        let w = rk.n[li];
        nb.push((w >> 24) as! u8); nb.push((w >> 16) as! u8); nb.push((w >> 8) as! u8); nb.push(w as! u8);
        li -= 1;
    }
    var ek = tpm2::ek_rsa_template();
    ek.unique.clear();
    ek.unique.append(nb);
    let c, e = tpm2::make_credential(ek, name, secret);
    check("MakeCredential to an RSA EK", e == tpm2::OK && c.secret.len == 256);
    let seed, okd = bignum::rsa_decrypt_oaep(rk, c.secret, "IDENTITY\x00", 256);
    check("  the seed by RSA-OAEP with the label IDENTITY", okd && seed.len == 32);
    let got, ok = activate(ek, seed, name, c);
    check("  activated with the EK's private key", ok && got == secret);
    var other = copy(name);
    other[2] ^= 1;
    let got2, ok2 = activate(ek, seed, other, c);
    check("  not for another Name", !ok2);
    var cbad = c;
    cbad.blob[40] ^= 1;
    let got3, ok3 = activate(ek, seed, name, cbad);
    check("  not with encIdentity changed", !ok3);
    // Fixed randomness: the same credential each time.
    var rnd: u8[>..] = [];
    rnd.resize(64, 0x5c);
    let cf1, ef1 = tpm2::make_credential(ek, name, secret, "", rnd);
    let cf2, ef2 = tpm2::make_credential(ek, name, secret, "", rnd);
    check("  fixed randomness, fixed credential", ef1 == tpm2::OK && cf1.blob == cf2.blob && cf1.secret == cf2.secret);
    // ECC: a software P-256 key.
    let curve = bignum::p256();
    let sk, pk = bignum::ec_keypair(curve);
    var eke = tpm2::ek_ecc_template();
    eke.x.clear();
    eke.x.append(pk[1..33]);
    eke.y.clear();
    eke.y.append(pk[33..]);
    let ce, ee = tpm2::make_credential(eke, name, secret);
    check("MakeCredential to an ECC EK", ee == tpm2::OK && ce.secret.len == 68);
    // The seed: KDFe over ECDH of the EK's key and the ephemeral point.
    var r = tpm2::reader(ce.secret);
    let x = tpm2::get_2b(r, 32);
    let y = tpm2::get_2b(r, 32);
    var pt: u8[>..] = [];
    pt.push(4);
    pt.append(x);
    pt.append(y);
    let z, okz = bignum::ecdh_shared(curve, sk, pt);
    let seed2 = tpm2::kdfe(tpm2::ALG_SHA256, z, "IDENTITY", x, pk[1..33], 256);
    let got4, ok4 = activate(eke, seed2, name, ce);
    check("  activated with the EK's private key", okz && ok4 && got4 == secret);
    // A fixed ephemeral key gives a fixed credential.
    var eph: u8[>..] = [];
    eph.resize(32, 0x42);
    let cx1, ex1 = tpm2::make_credential(eke, name, secret, eph);
    let cx2, ex2 = tpm2::make_credential(eke, name, secret, eph);
    check("  fixed ephemeral key, fixed credential", ex1 == tpm2::OK && cx1.blob == cx2.blob && cx1.secret == cx2.secret);
    // What is refused.
    var long: u8[>..] = [];
    long.resize(33, 1);
    let cl, el = tpm2::make_credential(ek, name, long);
    check("a credential longer than the digest", el == tpm2::ERR_ARG);
    var nosym = ek;
    nosym.sym_alg = tpm2::ALG_NULL;
    let cn, en = tpm2::make_credential(nosym, name, secret);
    check("an EK without AES-CFB", en == tpm2::ERR_UNSUPPORTED);
    var badpt = eke;
    badpt.y[0] ^= 1;
    let cb, eb = tpm2::make_credential(badpt, name, secret);
    check("an ECC EK that is not on the curve", eb == tpm2::ERR_MALFORMED);
}

fn main() {
    quotes();
    certifies();
    event_logs();
    credentials();
    print(checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
