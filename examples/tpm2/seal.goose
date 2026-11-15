// seal: a secret sealed to a PCR and a PIN, through a salted session that
// encrypts it on its way to the TPM. It unseals while the PCR is what it
// was; after a PCR_Extend (a different boot, say) the TPM refuses.
//
//   goose examples/tpm2/seal.goose -- tcp:127.0.0.1:2321
//
// PCR 16 is the debug PCR: resettable, so the example can start it from zero.

import std;
import os;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.transport;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.tpm2.policy;

fn die(t: const tpm2::Tpm&, what: const u8[:], e: i64) {
    if e != tpm2::OK { print(what, ": ", tpm2::describe(t, e)); exit(1); }
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: seal.goose -- tcp:HOST:PORT | mssim:HOST:PORT | device:/dev/tpmrm0"); exit(2); }
    var t, e = tpm2::open(a[1]);
    die(t, "open", e);
    die(t, "Startup", tpm2::startup(t));
    var pw = tpm2::pw();
    die(t, "PCR_Reset", tpm2::pcr_reset(t, 16, pw));
    let srk, es = tpm2::create_primary(t, tpm2::owner(), pw, tpm2::srk_ecc_template());
    die(t, "SRK", es);

    // The policy: PCR 16 as it is now, and the PIN.
    let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 1 << 16 }];
    let vals, c, ev = tpm2::pcr_read(t, sel);
    die(t, "PCR_Read", ev);
    var p = tpm2::policy();
    tpm2::policy_pcr(p, sel, tpm2::pcr_digest(tpm2::ALG_SHA256, vals));
    tpm2::policy_auth_value(p);

    // Create it in a session salted to the SRK, the secret encrypted.
    let o = tpm2::SessionOpts { salt: true, salt_key: tpm2::object_of(srk), salt_pub: srk.public, .. };
    var s, e1 = tpm2::start_session_with(t, tpm2::SESSION_HMAC, o);
    die(t, "StartAuthSession", e1);
    s.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT;
    var sealed, e2 = tpm2::create(t, tpm2::object_of(srk), s, tpm2::sealed_template(p.digest), "1234", "the disk key");
    die(t, "Create", e2);
    tpm2::flush(t, s.handle);
    die(t, "Load", tpm2::load(t, tpm2::object_of(srk), pw, sealed));

    // Unseal: the same assertions in a policy session.
    var ps, e3 = tpm2::start_session(t, tpm2::SESSION_POLICY);
    die(t, "StartAuthSession", e3);
    die(t, "PolicyPCR", tpm2::policy_pcr_tpm(t, ps, sel));
    die(t, "PolicyAuthValue", tpm2::policy_auth_value_tpm(t, ps));
    let data, e4 = tpm2::unseal(t, tpm2::object_of(sealed, "1234"), ps);
    die(t, "Unseal", e4);
    print("unsealed: ", data);

    // Measure something else into PCR 16: the policy no longer holds.
    die(t, "PCR_Extend", tpm2::pcr_extend(t, 16, pw, tpm2::ALG_SHA256, tpm2::hash(tpm2::ALG_SHA256, "another kernel")));
    die(t, "PolicyPCR", tpm2::policy_pcr_tpm(t, ps, sel));
    die(t, "PolicyAuthValue", tpm2::policy_auth_value_tpm(t, ps));
    let data2, e5 = tpm2::unseal(t, tpm2::object_of(sealed, "1234"), ps);
    print("after PCR_Extend: ", tpm2::describe(t, e5));
    tpm2::flush(t, ps.handle);
    tpm2::flush(t, sealed.handle);
    tpm2::flush(t, srk.handle);
    tpm2::close(t);
    if e5 == tpm2::OK { exit(1); }
}
