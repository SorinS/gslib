// Fuzz target: tpm2_attest. TPMS_ATTEST and the structures around it,
// data[0] % 5 picking the path, the rest the input:
//   0: parse_attest.
//   1: verify_quote, verify_certify or verify_creation (data[0] / 5 % 3) of the input as a
//      TPMS_ATTEST signed here (ECDSA P-256, RFC 6979, a fixed key made an
//      AK), so the checks after the signature (parse, type, nonce, PCR
//      selection and digest, names, creation hash) are reached.
//   2: read_attested (a Quote's response parameters), then verify_quote
//      with swtpm's ECC AK (tpm2/test/vectors.goose).
//   3: parse_public, then the public area used: its Name, SPKI (and back),
//      RSA key or ECC point, is_attestation_key, and verify_signature of
//      swtpm's quote with it.
//   4: parse_signature, signature_der and verify_signature of swtpm's
//      quote with its AK.

import std;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.tpm2.attest;
import gslib.crypto.bignum;
import gslib.crypto.bignum.ec;

// From tpm2/test/vectors.goose (swtpm).
let AK_ECC_PUBLIC:    const u8[:] = "0023000b00050072000000100018000b000300100020c43898373f057b5ddc024232809bae93eb55fb216a162840ad005c6b4944d2f90020bbeb4bc8e273b731c4d0802a3e2ddf3d78bbc5543edc036d464795611368cda9";
let AK_RSA_PUBLIC:    const u8[:] = "0001000b00050072000000100014000b0800000000000100c880676d53b85928bee3a2e43f6cd428ecccda3151da9bc3c4485fe33b02395e3a0afac0e363fb933f5c951900dc72d8d97ba32785ba30ef41ab837a2c8f67dc1e1c7974fe8989f49d6052dd89ec17a5cd3944a694648b80c6d53c5a019c5efb143aa7a5bc3a1b38641b77ac68976a61bb3ba070b4c39327380b5ef82db880f816ba1c7aa5c3c523d160a5702ff0dc15cbc0f785991f691b63260a43f825eced4e013a3491d47c56b7d8d928b2001556a166a4e323f836b3a17e9b2597700e962218caba278b1f085c06d3f1749265545cc1aa7bc4db064167d100667a1660c003b1c1d8f515cb93c065d81e668bffd045fd3738d43d61cd27b5b5a6fd4bafe7";
let QUOTE_ECC_ATTEST: const u8[:] = "ff54434780180022000b6a0ca6692ff20afce74d1eb74681abe97155bf0d95f3a5973a4d319cfa4958ac000b71756f7465206e6f6e636500000000000566e9b9a335850578195101caeea127b2bbf54e00000002000b03ff00800004030300000020ab426cdf75ba8942445d4347d817a7689544817a02b70cce2705903ba603bfc2";
let QUOTE_ECC_SIG:    const u8[:] = "0018000b00207b11fb91201bf60666ab19ee43ef194fae9ef7a3812650d162351d58f4544c6c00205435d68c7cc0cdcf421d7e0daeae053e22d547d904899b08ecca95c9b72e6ec2";
let CERTIFIED_PUBLIC: const u8[:] = "0023000b000400720000001000100003001000208c38195ec5ec1d13f7b3e2976cb4be89e1d04381a5b63c7d9fd2a3eeca99445a0020e065b87d899e2253c54ef0eb82a4fb1986a2d3277aaa172911514243cc220e30";

let SK: const u8[:] = "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01";

var OUR_AK:  tpm2::Public    = tpm2::Public { .. };
var VEC_AK:  tpm2::Public    = tpm2::Public { .. };
var OBJ:     tpm2::Public    = tpm2::Public { .. };
var QATTEST: u8[>..]         = [];
var QSIG:    tpm2::Signature = tpm2::Signature { .. };

fn h(s: const u8[:]) -> u8[>..] {
    let b, ok = tpm2::unhex(s);
    assert(ok);
    return b;
}

fn signed_by_us(attest: const u8[:], which: u8) {
    let c = bignum::p256();
    let d = tpm2::hash(tpm2::ALG_SHA256, attest);
    let raw = bignum::ecdsa_sign_digest(c, SK, d, tpm2::hash_id(tpm2::ALG_SHA256));
    var sig = tpm2::Signature { alg: tpm2::ALG_ECDSA, hash: tpm2::ALG_SHA256, .. };
    sig.r.append(raw[..32]);
    sig.s.append(raw[32..]);
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0x8000ff }, tpm2::PcrSel { hash: tpm2::ALG_SHA1, mask: 0x3 }];
    var vals: u8[..64][>..] = [];
    for i in 8 { var v: u8[..64] = []; v.resize(32, 0); vals.push(v); }
    var v23: u8[..64] = []; v23.resize(32, 0xff); vals.push(v23);
    for i in 2 { var v: u8[..64] = []; v.resize(20, 0); vals.push(v); }
    // One check a run (each verifies the signature again, slow under ASan).
    if which % 3 == 0 { let a, e = tpm2::verify_quote(OUR_AK, attest, sig, "quote nonce", sel, vals); }
    else if which % 3 == 1 { let b, eb = tpm2::verify_certify(OUR_AK, attest, sig, "certify nonce", OBJ); }
    else {
        let ch = tpm2::hash(tpm2::ALG_SHA256, "creation");
        let cc, ec = tpm2::verify_creation(OUR_AK, attest, sig, "creation nonce", OBJ, ch);
    }
}

fn public_area(b: const u8[:]) {
    let p, ok = tpm2::parse_public(b);
    if !ok { return; }
    let _ = tpm2::public_name(p);
    let _ = tpm2::is_attestation_key(p);
    let m = tpm2::marshal_public(p);
    let spki, sok = tpm2::public_to_spki(p);
    if sok { let back, be = tpm2::public_from_spki(spki, p); }
    let k, kok = tpm2::rsa_public(p);
    let pt, pok = tpm2::ecc_point(p);
    let _ = tpm2::verify_signature(p, tpm2::hash(tpm2::ALG_SHA256, QATTEST), QSIG);
}

fn signature(b: const u8[:]) {
    let s, ok = tpm2::parse_signature(b);
    if !ok { return; }
    let der, dok = tpm2::signature_der(s, VEC_AK);
    let _ = tpm2::marshal_signature(s);
    let _ = tpm2::verify_signature(VEC_AK, tpm2::hash(tpm2::ALG_SHA256, QATTEST), s);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let m = data[1..];
    let sel = data[0] % 5;
    if sel == 0 {
        let a, e = tpm2::parse_attest(m);
    } else if sel == 1 {
        signed_by_us(m, data[0] / 5);
    } else if sel == 2 {
        let q, e = tpm2::read_attested(m);
        if e == tpm2::OK {
            let a, ea = tpm2::parse_attest(q.attest);
            let s2 = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 1 }];
            var one: u8[..64][>..] = [];
            one.push([]);
            let b, eb = tpm2::verify_quote(VEC_AK, q.attest, q.sig, "quote nonce", s2, one);
        }
    } else if sel == 3 {
        public_area(m);
    } else {
        signature(m);
    }
    return 0;
}

fn main() {
    let c = bignum::p256();
    let pk = bignum::ec_public_key(c, SK);
    OUR_AK = tpm2::ak_ecc_template();
    OUR_AK.x.append(pk[1..33]);
    OUR_AK.y.append(pk[33..65]);
    let va, vok = tpm2::parse_public(h(AK_ECC_PUBLIC));
    assert(vok);
    VEC_AK = va;
    let ob, ook = tpm2::parse_public(h(CERTIFIED_PUBLIC));
    assert(ook);
    OBJ = ob;
    QATTEST.append(h(QUOTE_ECC_ATTEST));
    let qs, qok = tpm2::parse_signature(h(QUOTE_ECC_SIG));
    assert(qok);
    QSIG = qs;
}
