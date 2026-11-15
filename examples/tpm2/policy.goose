// policy: policy digests computed in software, with no TPM, as a trial
// session would compute them: what goes in an object's authPolicy before
// the object exists. The TCG EK policy (PolicySecret of the endorsement
// hierarchy), a seal to PCR values with a PIN (PolicyPCR and
// PolicyAuthValue), a choice of two (PolicyOR), and a policy a key may
// later approve (PolicyAuthorize).
//
//   goose examples/tpm2/policy.goose
//
// On a TPM the same assertions, made to a policy session
// (tpm2::policy_pcr_tpm, policy_auth_value_tpm, ...), give the same digest,
// and only then does the object accept that session (examples/tpm2/seal.goose).

import std;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.commands;
import gslib.tpm2.policy;

fn main() {
    // The EK's policy: whoever knows the endorsement hierarchy's authValue.
    var ek = tpm2::policy(tpm2::ALG_SHA256);
    tpm2::policy_secret(ek, tpm2::handle_name(tpm2::RH_ENDORSEMENT));
    print("EK policy:            ", tpm2::hex(ek.digest));
    assert(ek.digest == tpm2::EK_POLICY_SHA256);

    // Sealed to PCR 7 (Secure Boot's) as it is now, and a PIN.
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 1 << 7 }];
    var pcr7: u8[..64][>..] = [];
    pcr7.push([]);
    for i in 32 { pcr7[0].push(0x07); }     // the value a TPM would report
    var seal = tpm2::policy();
    tpm2::policy_pcr(seal, sel, tpm2::pcr_digest(tpm2::ALG_SHA256, pcr7));
    tpm2::policy_auth_value(seal);
    print("PCR 7 and a PIN:      ", tpm2::hex(seal.digest));

    // Either the PIN alone for Unseal, or the PCR policy above.
    var pin = tpm2::policy();
    tpm2::policy_command_code(pin, tpm2::CC_Unseal);
    tpm2::policy_auth_value(pin);
    var either = tpm2::policy();
    let branches = [seal.digest, pin.digest];
    assert(tpm2::policy_or(either, branches));
    print("one or the other:     ", tpm2::hex(either.digest));

    // Whatever a signing key approves: the key's Name and a policyRef.
    var key_name: u8[>..] = [];
    tpm2::put_u16(key_name, tpm2::ALG_SHA256);
    key_name.append(tpm2::hash(tpm2::ALG_SHA256, "an authorizing key's public area"));
    var authorized = tpm2::policy();
    tpm2::policy_authorize(authorized, key_name, "firmware-updates");
    print("approved by the key:  ", tpm2::hex(authorized.digest));
    // The key signs H(approvedPolicy || policyRef) to approve a policy.
    print("it signs, for PCR 7:  ", tpm2::hex(tpm2::policy_authorize_hash(tpm2::ALG_SHA256, seal.digest, "firmware-updates")));
}
