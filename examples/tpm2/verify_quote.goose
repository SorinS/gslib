// verify_quote: what a verifier does with a quote, with no TPM. A quote
// swtpm made (an ECC P-256 attestation key, SHA-256 PCRs 0-7 and 23 and
// SHA-1 PCRs 0 and 1, the nonce "quote nonce"), checked as tpm2 checks one:
// the AK's signature over the TPMS_ATTEST, the nonce in extraData, the PCR
// selection, and the PCR digest against the values the attester sent.
// Then the same with a changed PCR value, which is refused.
//
//   goose examples/tpm2/verify_quote.goose
//
// In practice the AK's public area comes with a credential: the verifier
// made one with tpm2::make_credential to the TPM's EK and the attester
// recovered it with ActivateCredential (examples/tpm2/attest.goose).

import std;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.commands;
import gslib.tpm2.attest;

let AK_PUBLIC = "0023000b00050072000000100018000b000300100020c43898373f057b5ddc024232809bae93eb55fb216a162840ad005c6b4944d2f90020bbeb4bc8e273b731c4d0802a3e2ddf3d78bbc5543edc036d464795611368cda9";
let ATTEST = "ff54434780180022000b6a0ca6692ff20afce74d1eb74681abe97155bf0d95f3a5973a4d319cfa4958ac000b71756f7465206e6f6e636500000000000566e9b9a335850578195101caeea127b2bbf54e00000002000b03ff00800004030300000020ab426cdf75ba8942445d4347d817a7689544817a02b70cce2705903ba603bfc2";
let SIGNATURE = "0018000b00207b11fb91201bf60666ab19ee43ef194fae9ef7a3812650d162351d58f4544c6c00205435d68c7cc0cdcf421d7e0daeae053e22d547d904899b08ecca95c9b72e6ec2";
let PCR_VALUES = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000716493a30fc57a0211b07425e22b7dcff0526e70dc613cc68bcdf57b616d3d4000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn unhex(s: const u8[:]) -> u8[>..] {
    let b, ok = tpm2::unhex(s);
    assert(ok);
    return b;
}

fn main() {
    let pb = unhex(AK_PUBLIC);
    let ak, okp = tpm2::parse_public(pb);
    let sb = unhex(SIGNATURE);
    let sig, oks = tpm2::parse_signature(sb);
    assert(okp && oks);
    print("attestation key ", tpm2::hex(tpm2::public_name(ak)));
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0x8000ff }, tpm2::PcrSel { hash: tpm2::ALG_SHA1, mask: 0x3 }];
    // The PCR values, in selection order: each bank's PCRs from the lowest.
    let raw = unhex(PCR_VALUES);
    var values: u8[..64][>..] = [];
    var at = 0;
    for s in sel {
        let n = tpm2::digest_size(s.hash);
        for i in tpm2::pcr_list(s.mask) {
            var v: u8[..64] = [];
            v.append(raw[at..at + n]);
            values.push(v);
            at += n;
        }
    }
    let attest = unhex(ATTEST);
    let a, e = tpm2::verify_quote(ak, attest, sig, "quote nonce", sel, values);
    print("quote: ", tpm2::error_text(e));
    assert(e == tpm2::OK);
    print("  signer ", tpm2::hex(a.signer), ", PCR digest ", tpm2::hex(a.pcr_digest));
    // A PCR the attester says is something else.
    values[8][0] ^= 1;
    let a2, e2 = tpm2::verify_quote(ak, attest, sig, "quote nonce", sel, values);
    print("with PCR 23 changed: ", tpm2::error_text(e2));
    assert(e2 == tpm2::ERR_PCR);
    // A replayed quote, for another nonce.
    values[8][0] ^= 1;
    let a3, e3 = tpm2::verify_quote(ak, attest, sig, "a fresh nonce", sel, values);
    print("for another nonce: ", tpm2::error_text(e3));
    assert(e3 == tpm2::ERR_NONCE);
}
