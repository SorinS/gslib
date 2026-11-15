// attest: remote attestation against a TPM, both sides in one program.
// The attester makes its EK and an attestation key (AK); the verifier
// makes a credential for the AK's Name, encrypted to the EK
// (tpm2::make_credential, in software), which only that TPM can recover,
// and only for that AK (ActivateCredential): now the verifier knows the AK
// lives on the TPM whose EK it has. Then the verifier sends a nonce, the
// attester quotes its PCRs with the AK, and the verifier checks the quote.
//
//   swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
//         --tpmstate dir=/tmp/tpm --flags not-need-init,startup-clear &
//   goose examples/tpm2/attest.goose -- tcp:127.0.0.1:2321
//
// Against a real TPM: device:/dev/tpmrm0 (Linux). The verifier would also
// check the EK's certificate (tpm2::read_ek_cert) against the
// manufacturer's CA.

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
import gslib.crypto.bignum.entropy;

fn die(t: const tpm2::Tpm&, what: const u8[:], e: i64) {
    if e != tpm2::OK { print(what, ": ", tpm2::describe(t, e)); exit(1); }
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: attest.goose -- tcp:HOST:PORT | mssim:HOST:PORT | device:/dev/tpmrm0"); exit(2); }
    var t, e = tpm2::open(a[1]);
    die(t, "open", e);
    die(t, "Startup", tpm2::startup(t));
    var pw = tpm2::pw();

    // Attester: the EK (TCG template) and an AK under the SRK.
    let ek, e1 = tpm2::create_primary(t, tpm2::endorsement(), pw, tpm2::ek_rsa_template());
    die(t, "EK", e1);
    let srk, e2 = tpm2::create_primary(t, tpm2::owner(), pw, tpm2::srk_ecc_template());
    die(t, "SRK", e2);
    let ak, e3 = tpm2::create_loaded(t, tpm2::object_of(srk), pw, tpm2::ak_ecc_template());
    die(t, "AK", e3);
    tpm2::flush(t, srk.handle);
    print("EK ", tpm2::hex(ek.name), "\nAK ", tpm2::hex(ak.name));

    // Verifier: a secret for the AK's Name, to the EK.
    var secret: u8[32] = [0; 32];
    bignum::random_bytes(secret);
    let cred, ec = tpm2::make_credential(ek.public, ak.name, secret);
    die(t, "MakeCredential", ec);

    // Attester: the EK's policy, then ActivateCredential.
    var ekp, ep = tpm2::ek_policy_session(t);
    die(t, "EK policy session", ep);
    var akauth = tpm2::pw();
    let got, ea = tpm2::activate_credential(t, tpm2::object_of(ak), tpm2::object_of(ek), akauth, ekp, cred);
    die(t, "ActivateCredential", ea);
    tpm2::flush(t, ekp.handle);
    print("credential recovered: ", if got == secret[..] { "yes, the AK is on this TPM" } else { "NO" });

    // Verifier: a nonce. Attester: a quote of PCRs 0-7 and its PCR values.
    var nonce: u8[16] = [0; 16];
    bignum::random_bytes(nonce);
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 0xff }];
    let q, eq = tpm2::quote(t, tpm2::object_of(ak), pw, nonce, tpm2::ALG_NULL, tpm2::ALG_SHA256, sel);
    die(t, "Quote", eq);
    let vals, c, ev = tpm2::pcr_read(t, sel);
    die(t, "PCR_Read", ev);

    // Verifier: the quote, with the AK it now trusts.
    let at, ek2 = tpm2::verify_quote(ak.public, q.attest, q.sig, nonce, sel, vals);
    print("quote: ", tpm2::error_text(ek2));
    tpm2::flush(t, ak.handle);
    tpm2::flush(t, ek.handle);
    tpm2::close(t);
    if ek2 != tpm2::OK || got != secret[..] { exit(1); }
}
