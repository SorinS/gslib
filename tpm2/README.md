# tpm2

A TPM 2.0 client for Goose, after go-tpm's `tpm2` package with go-tpm-tools'
attestation checks: commands to a TPM (a chip through Linux's resource
manager, swtpm, the Microsoft simulator's protocol) and everything a
verifier does without one. Six modules, all in namespace `tpm2`:
`tpm2.goose` at gslib's top, `tpm2/transport.goose`, `tpm2/session.goose`,
`tpm2/commands.goose`, `tpm2/policy.goose`, `tpm2/attest.goose`; the C of
the device transport in `tpm2/src/tpmdev.c`; and a tool, `goose-tpm`.

Hashes, HMAC, AES-CFB, RSA-OAEP and ECDH are gslib's `crypto/bignum`;
signatures are checked by `crypto/x509` (`verify_digest`, the key turned
into a SubjectPublicKeyInfo); TCP is gslib's `net`.

| What | Functions |
|---|---|
| transports (tpm2.transport) | `open("tcp:HOST:PORT")` (raw commands, swtpm's data channel), `open("mssim:HOST:PORT")` (TPM_SEND_COMMAND framing, TPM_SIGNAL_POWER_ON and NV_ON on the platform channel at PORT+1), `open("device:/dev/tpmrm0")` (Linux), `close`, `transmit`, `describe` |
| the wire (tpm2) | `marshal_public`/`parse_public` (TPMT_PUBLIC: RSA, ECC, keyed-hash, symmetric), `marshal_signature`/`parse_signature`, `put_pcr_selection`/`read_pcr_selection`, `Reader` (sizes checked), `rc_text`, `rc_name`, `rc_parts` (format-0 and format-1 codes: handle, parameter or session number) |
| Names and keys (tpm2) | `public_name` (nameAlg ‖ H(TPMT_PUBLIC)), `handle_name`, `nv_name`, `public_to_spki`, `public_from_spki`, `key_cert` (an x509::Cert of a key alone), `rsa_public`, `ecc_point`, `verify_signature` (RSASSA, RSAPSS, ECDSA through x509), `signature_der` |
| templates (tpm2) | `ek_rsa_template`, `ek_ecc_template` (TCG EK Credential Profile L-1 and L-2), `srk_rsa_template`, `srk_ecc_template` (Provisioning Guidance), `ak_rsa_template`, `ak_ecc_template`, `rsa_sign_template`, `ecc_sign_template`, `rsa_decrypt_template`, `ecdh_template`, `sealed_template`, `hmac_key_template` |
| KDFs (tpm2) | `kdfa`, `kdfe` (Part 1 §11.4.10) |
| sessions (tpm2.session) | `pw()`, `start_session(t, SESSION_HMAC / SESSION_POLICY / SESSION_TRIAL, hash, aes_bits)`, `start_session_with(t, kind, SessionOpts { salt, salt_key, salt_pub, bind, bind_entity, .. })`, `ATTR_DECRYPT`/`ATTR_ENCRYPT` for parameter encryption, `execute`, `build_command`, `parse_response`, `secret_to` (a seed for a TPM key: RSA-OAEP or ECDH with KDFe) |
| entities | `owner()`, `endorsement()`, `platform()`, `lockout()`, `pcr_entity(i)`, `object_of(o, auth)`, `object_entity(handle, name, auth)`, `nv_entity(t, index, auth)` |
| start-up and capabilities | `startup` (TPM_RC_INITIALIZE is fine), `shutdown`, `self_test`, `get_random`, `stir_random`, `get_capability`, `tpm_property`, `manufacturer`, `get_handles`, `da_lock_reset`, `flush` |
| objects | `create_primary`, `create`, `load`, `create_loaded`, `load_external`, `read_public_tpm`, `evict_control`, `context_save`, `context_load`; each Name the TPM gives is checked against `public_name` |
| keys | `sign` (RSASSA, RSAPSS, ECDSA; a restricted key's ticket from `hash_tpm`), `verify_signature_tpm` (a TPMT_TK_VERIFIED), `rsa_encrypt`, `rsa_decrypt` (OAEP or RSAES, labels), `ecdh_zgen`, `hash_tpm`, `hmac_tpm`, `unseal` |
| PCRs | `pcr_read` (any banks, 8 PCRs a request; a bank the TPM has not allocated is `ERR_UNSUPPORTED`), `pcr_read_bank`, `pcr_extend`, `pcr_event`, `pcr_reset`, `extend_value`, `pcr_digest` |
| NV | `nv_define`, `nv_undefine`, `nv_read_public`, `nv_write`, `nv_read` (both in pieces of TPM_PT_NV_BUFFER_MAX), `nv_increment`, `nv_read_counter`, `nv_extend`; `read_ek_cert` (`EK_CERT_RSA_INDEX` 0x01C00002, `EK_CERT_ECC_INDEX` 0x01C0000A, `EK_CERT_ECC_P384_INDEX` 0x01C00016) |
| policies (tpm2.policy) | in software: `policy(hash)`, `policy_pcr`, `policy_secret`, `policy_signed`, `policy_or`, `policy_auth_value`, `policy_password`, `policy_command_code`, `policy_authorize`, `policy_signed_hash`, `policy_authorize_hash`; on the TPM: the same with `_tpm`, `policy_get_digest`, `policy_restart`, `ek_policy_session` |
| attestation (tpm2.attest) | on the TPM: `quote`, `certify`, `certify_creation`, `make_credential_tpm`, `activate_credential`; in software: `parse_attest`, `verify_quote`, `verify_certify`, `verify_creation`, `is_attestation_key`, `make_credential`, `replay_event_log`, `check_event_log` |

Errors are `i64` codes (`ERR_TPM` with the response code in `t.rc`,
`ERR_TRANSPORT`, `ERR_MALFORMED`, `ERR_INTEGRITY`, `ERR_SIGNATURE`,
`ERR_NONCE`, `ERR_PCR`, `ERR_NAME`, `ERR_TYPE`, `ERR_EVENTLOG`,
`ERR_UNSUPPORTED`, `ERR_ARG`); `describe(t, e)` says what went wrong,
"the TPM refused: TPM_RC_POLICY_FAIL (session 1, 0x99d)" for instance.
`flush` keeps `t.rc`, so cleaning up after a failure does not hide it.

Nothing a TPM sends is believed in part. Every structure is read with
its sizes checked against what is left and against the structure's own
maximum (a TPM2B_PUBLIC_KEY_RSA of 512 bytes, a digest of 64, a
TPML_DIGEST of 8 entries, 4 PCR banks of 24 PCRs); a size that lies, a
TPM2B past the end or over its type, bytes left over, a response over
8 KiB, the wrong tag, a password session answered with a nonce, an
error code with parameters after it: the response is refused whole
(`ERR_MALFORMED`). A response HMAC that does not verify is
`ERR_INTEGRITY`, checked before an encrypted parameter is decrypted.
The fields that hold values are bounded arrays (`u8[..64]`), and a value
that does not fit is refused, never cut.

## Using it

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.tpm2;
import gslib.tpm2.transport;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.tpm2.policy;
import gslib.tpm2.attest;

var t, e = tpm2::open("device:/dev/tpmrm0");       // or tcp:127.0.0.1:2321
tpm2::startup(t);
var pw = tpm2::pw();
let srk, e1 = tpm2::create_primary(t, tpm2::owner(), pw, tpm2::srk_ecc_template());

// A key under the SRK, made and used through a session salted to the SRK.
let so = tpm2::SessionOpts { salt: true, salt_key: tpm2::object_of(srk), salt_pub: srk.public, .. };
var s, e2 = tpm2::start_session_with(t, tpm2::SESSION_HMAC, so);
let key, e3 = tpm2::create_loaded(t, tpm2::object_of(srk), s, tpm2::ecc_sign_template(tpm2::ECC_NIST_P256), "key pin");
let digest = tpm2::hash(tpm2::ALG_SHA256, "message");
s.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT;          // the digest encrypted on its way
let sig, e4 = tpm2::sign(t, tpm2::object_of(key, "key pin"), s, digest, tpm2::ALG_ECDSA, tpm2::ALG_SHA256);
tpm2::verify_signature(key.public, digest, sig);              // OK
tpm2::flush(t, s.handle);
```

A command's handles are `Entity`s: a handle, its Name (for cpHash) and
its authValue. Those that need authorization take a `Session`: `pw()`
sends the authValue in the clear; an HMAC session (`start_session`)
sends HMAC(sessionKey ‖ authValue, cpHash ‖ nonceCaller ‖ nonceTPM ‖
attributes) with a new nonce each command and checks the response's
rpHash HMAC. Bound to an entity, its authValue goes into the sessionKey
and out of the HMAC key when the session authorizes that entity; salted,
the salt goes to a loaded key by RSA-OAEP ("SECRET", the key's nameAlg)
or an ephemeral ECDH and KDFe. With `ATTR_DECRYPT` the command's first
parameter is encrypted, with `ATTR_ENCRYPT` the response's: AES-CFB keyed
by KDFa(hash, sessionValue, "CFB", nonceNewer, nonceOlder), sessionValue
being sessionKey ‖ authValue when the session authorizes (binding or not,
Part 1 §21.1), sessionKey otherwise. A policy session is satisfied by the
`policy_*_tpm` assertions before the command; `policy_auth_value_tpm`
and `policy_password_tpm` mark it, so the HMAC or the password goes with
it. A session the TPM closes (continueSession cleared) becomes
`SESSION_NONE`.

Policies are computed in software first, for an object's authPolicy:

```goose
var p = tpm2::policy();                                     // SHA-256, all zeros
let sel = [tpm2::PcrSel { hash: tpm2::ALG_SHA256, mask: 1 << 7 }];
let vals, e5 = tpm2::pcr_read_bank(t, tpm2::ALG_SHA256, 1 << 7);
tpm2::policy_pcr(p, sel, tpm2::pcr_digest(tpm2::ALG_SHA256, vals));
tpm2::policy_auth_value(p);
var sealed, e6 = tpm2::create(t, tpm2::object_of(srk), pw, tpm2::sealed_template(p.digest), "1234", "the disk key");
tpm2::load(t, tpm2::object_of(srk), pw, sealed);
var ps, e7 = tpm2::start_session(t, tpm2::SESSION_POLICY);
tpm2::policy_pcr_tpm(t, ps, sel);
tpm2::policy_auth_value_tpm(t, ps);
let data, e8 = tpm2::unseal(t, tpm2::object_of(sealed, "1234"), ps);
```

The policy calculator agrees with `PolicyGetDigest` of a trial session,
assertion by assertion, and with go-tpm's PolicyCalculator; the EK
policy (`EK_POLICY_SHA256`) is `policy_secret` of the endorsement
hierarchy's Name. PolicyAuthorize restarts the digest from zeros as the
TPM does (Part 3 §23.16); PolicyOR takes 2 to 8 branches.

Attestation, the verifier's half needing no TPM:

```goose
// Verifier: a credential for the AK's Name, to the EK (certified by the manufacturer).
let cred, ec = tpm2::make_credential(ek_public, ak_name, secret);
// Attester: ActivateCredential, the EK under its policy.
var ekp, ep = tpm2::ek_policy_session(t);
let got, ea = tpm2::activate_credential(t, ak, ek, pw, ekp, cred);   // got == secret
// Attester: a quote of the verifier's nonce. Verifier: the quote.
let q, eq = tpm2::quote(t, ak, pw, nonce, tpm2::ALG_NULL, tpm2::ALG_SHA256, sel);
let a, ev = tpm2::verify_quote(ak_public, q.attest, q.sig, nonce, sel, values);
let el = tpm2::check_event_log(log, tpm2::ALG_SHA256, mask, values);
```

`verify_quote` checks the signature over the TPMS_ATTEST first (so
nothing unsigned is read), then that it is a quote, generated by a TPM,
with the nonce as extraData, the selection asked for, and the PCR digest
of the values given (by the signature's hash), and that the key is an AK
(restricted, signing, fixedTPM, made by the TPM). `verify_certify`
checks the certified object's Name, `verify_creation` its creation hash
too. `replay_event_log` reads the TCG PC Client crypto-agile log (the
TCG_PCR_EVENT with "Spec ID Event03" and its digest sizes, then
TCG_PCR_EVENT2s), skips EV_NO_ACTION, starts PCR 0 at the
StartupLocality event's locality (refusing one after PCR 0's first
extend, or a second), and refuses a log it cannot read whole.
`make_credential` follows Part 1 §24: the seed by RSA-OAEP with the label "IDENTITY\0" or by ECDH and KDFe, symKey = KDFa("STORAGE",
Name), encIdentity = AES-CFB of the TPM2B credential, the integrity HMAC
over encIdentity ‖ Name.

## goose-tpm

```
goose-tpm [--tpm SPEC] getrandom N | info | pcrread [--bank B] [--pcrs L]
goose-tpm [--tpm SPEC] pcrextend --pcrs N (--data S | --digest HEX)
goose-tpm [--tpm SPEC] createprimary [--template ek-rsa|ek-ecc|srk-rsa|srk-ecc] [--persist 0x81000001]
goose-tpm [--tpm SPEC] ekpub [--ecc] | ekcert [--ecc] [--out FILE]
goose-tpm [--tpm SPEC] quote --nonce HEX [--pcrs L] [--ecc] --out PREFIX
goose-tpm verify-quote --in PREFIX --nonce HEX [--pcrs L] [--eventlog FILE]
goose-tpm [--tpm SPEC] seal (--data S | --in FILE) [--pcrs L] [--auth-file F] --out FILE
goose-tpm [--tpm SPEC] unseal --in FILE [--pcrs L] [--auth-file F]
goose-tpm [--tpm SPEC] createkey [--ecc] --out FILE
goose-tpm [--tpm SPEC] sign --key FILE --in FILE [--out FILE]
goose-tpm [--tpm SPEC] nvdefine --index I --size N [--counter|--extend] | nvwrite | nvread | nvundefine | nvlist
goose-tpm eventlog --in FILE [--bank B]
```

SPEC is `tcp:HOST:PORT`, `mssim:HOST:PORT` or `device:/dev/tpmrm0`
(`$TPM2_TPM`, else the device). Keys and sealed objects live under the
ECC P-256 SRK made again from the owner's seed each time, and are saved
as TPM2B_PUBLIC ‖ TPM2B_PRIVATE. `seal` goes through a session salted to
the SRK, the data encrypted on its way; `unseal` replays the policy
(PolicyPCR of `--pcrs`, PolicyAuthValue with an auth file) and has the
data encrypted on its way back. `quote` makes a fresh AK, quotes, reads
the PCRs, checks the quote itself and writes `PREFIX.pub` (the AK's
TPMT_PUBLIC), `.attest`, `.sig` and `.pcrs`, which `verify-quote` checks
with no TPM (and an event log against them). `sign` checks the TPM's
signature before printing it. Authorization values come from files,
never arguments.

```bash
swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
      --tpmstate dir=/tmp/tpm --flags not-need-init,startup-clear &
goose-tpm --tpm tcp:127.0.0.1:2321 seal --data "disk key" --pcrs 7 --auth-file pin --out sealed
goose-tpm --tpm tcp:127.0.0.1:2321 unseal --in sealed --pcrs 7 --auth-file pin
```

## Examples

`examples/tpm2/`:

- `verify_quote.goose`: a quote swtpm made, verified with no TPM; then
  refused with a PCR value changed and for another nonce.
- `policy.goose`: policy digests in software: the EK policy, PCR 7 and a
  PIN, PolicyOR, PolicyAuthorize.
- `attest.goose` (needs a TPM): EK, AK, MakeCredential in software,
  ActivateCredential on the TPM, a quote and its verification.
- `seal.goose` (needs a TPM): seal to PCR 16 and a PIN through a salted,
  encrypting session; unseal; extend PCR 16; refused.

The first two run with the tests; the others are type-checked there and
run by hand: `goose examples/tpm2/attest.goose -- tcp:127.0.0.1:2321`.

## Tests

`make test-tpm2` (`python3 tpm2/scripts/run_tests.py`) runs three
programs at -O0, -O2 and with `--debug` (220 checks), the examples, and
type-checks the live programs in `scripts/`. With no TPM:

- `test/wire.goose` (128): every template marshalled and read back, each
  truncation and a byte over refused, the EK templates byte for byte
  against the EK Credential Profile; public areas swtpm made
  (`test/vectors.goose`, from `scripts/make_vectors.goose`) read, written
  back to the same bytes, given the Names swtpm gave them, turned into
  SubjectPublicKeyInfo (read by x509) and back; an NV index's Name;
  signatures and PCR selections round trip, oversized ones refused;
  response codes by name with their handle, parameter or session; KDFa
  and KDFe against Python's hashlib and hmac (`test/known.goose`, from
  `scripts/make_vectors.py`; SHA-1/256/384, 100/600 bits); the policy
  calculator against the well-known PolicyAuthValue and EK policy
  digests, Python's PolicyPCR, PolicyOR and PolicyAuthorize, and swtpm's
  PolicyGetDigest; TPM2Bs past the end or over their maximum, an RSA
  modulus over 512 bytes, a TPM2B_PUBLIC a byte too long.
- `test/session.goose` (36): an Unseal's command HMAC (cpHash with the
  item's Name) and its response's rpHash HMAC against Python's; every
  byte of that response changed, refused; a bad response HMAC, a changed
  parameter, the wrong authValue and changed attributes all
  `ERR_INTEGRITY`; responses shorter than their header, sizes larger and
  smaller than the bytes, an error code with parameters, ST_SESSIONS to a
  command without, a parameterSize or nonce past the end, a byte after
  the sessions, a password session answered with a nonce, a session area
  cut short, an HMAC session's response without an HMAC; a password
  command as tpm2-tools sends it; parameter encryption refused where it
  cannot be, and an encrypted parameter decrypting back; salts to an RSA
  key (SHA-256 and SHA-384) recovered with its private key.
- `test/attest.goose` (56): swtpm's RSA and ECC quotes verified, then
  refused for another nonce, another PCR value, another selection, a
  value missing, every byte of the TPMS_ATTEST changed, another AK, a
  changed signature, a key that is not restricted, the signature's hash
  changed; a Certify refused as a quote (ERR_TYPE); swtpm's Certify and
  CertifyCreation verified, and refused for another object, nonce and
  creation hash; TPMS_ATTEST truncated, with a byte over, not
  TPM-generated, a Name past the end, of a type not read; a crypto-agile
  event log (StartupLocality 3, events on PCRs 0, 1, 4, 7, separators)
  replayed to Python's SHA-256 and SHA-1 PCRs, checked against PCR
  values, refused truncated, without its header, naming PCR 24, with 255
  digests in an event; MakeCredential to software RSA and ECC EKs
  recovered with their private keys as ActivateCredential does (and not
  for another Name or a changed encIdentity), fixed randomness giving
  fixed credentials, too long a credential, an EK without AES-CFB and a
  point off the curve refused.

`make interop-tpm2` (`python3 tpm2/scripts/interop.py`, 720 checks)
starts each TPM on 127.0.0.1 with fresh state, stops it by its PID, and
runs `scripts/live.goose` (about 230 checks a TPM: every command above,
each result checked in software) and goose-tpm's commands against:

- [tpmemu](#quirks), the TPM 2.0 written in Sail (`TPMEMU`, else `tpmemu`
  on PATH), over raw TCP (TPM_PORT) and over mssim (TPM_MSSIM_PORT, its
  platform channel powering it on);
- swtpm 0.10.2 (libtpms), and a second swtpm provisioned by
  `swtpm_setup --create-ek-cert` (its configuration in the run's
  temporary directory), whose RSA and P-384 EK certificates are read from
  NV, parsed by x509 and matched to the EKs' keys;
- a fake TPM whose responses lie (larger than any TPM's, smaller than
  their header, cut short, a wrong tag, a TPM2B past the end, more random
  bytes than asked for, bytes after the parameters, an error code with
  parameters, a session area to a command without): goose-tpm must refuse
  each and exit 1.

The live checks: Startup and the DA reset; GetRandom, GetCapability,
Hash in two banks, PCR_Read of 32 PCRs; the four TCG primaries with their
Names checked, ReadPublic, to SubjectPublicKeyInfo and back, and made
again (the same key from the same seed); Create and Load, CreateLoaded,
signing with RSASSA, RSAPSS and ECDSA on P-256, P-384 and P-521, each
verified by x509; RSA-OAEP both ways and from software, ECDH_ZGen against
software ECDH, HMAC against software; HMAC sessions in SHA-1, SHA-256 and
SHA-384 over several commands, a wrong authValue (TPM_RC_BAD_AUTH);
sessions salted by RSA-OAEP and by ECDH, with sealed data encrypted in and
out; bound sessions, for their entity and another; parameter encryption
with AES-128 and AES-256 both ways; each policy assertion's digest
against PolicyGetDigest; a seal to PCR 23 and a PIN, unsealed, refused
with a wrong PIN and after PCR_Extend (TPM_RC_POLICY_FAIL); PolicySigned
with a software key loaded by LoadExternal, PolicyAuthorize with the
ticket from VerifySignature, PolicySecret by an HMAC session; NV ordinary
(an encrypted write at an offset, the Name changing with WRITTEN, an
encrypted read, a write past the end), counter and extend indices; EK
certificates; quotes by RSA and ECC AKs over two banks, verified and
refused for another nonce or PCR value; Certify and CertifyCreation;
MakeCredential in software to the RSA and ECC EKs, ActivateCredential,
refused for another Name, and the TPM's own MakeCredential activated;
ContextSave and ContextLoad, EvictControl and the persistent handle
listed. swtpm passes every one.

`make differential-tpm2` (`python3 tpm2/scripts/differential.py`)
compares tpm2 with [go-tpm](https://github.com/google/go-tpm) v0.9.8's
`tpm2` package (`scripts/gotpm`, pinned by its go.mod) on 3000 random
cases: KDFa and KDFe in every hash and odd bit counts, the Names of
random TPMT_PUBLIC areas of every type, scheme, symmetric definition
and KDF and their bytes written back, NV Names, and policy digests of
random sequences of seven assertions. All agree. (go-tpm cannot read
ECSchnorr or SM2 schemes in a public area, so the cases leave them out;
tpm2 reads them.)

`scripts/make_vectors.goose` (against swtpm) and `scripts/make_vectors.py`
remake `test/vectors.goose` and `test/known.goose`.

## Quirks

tpmemu (the Sail TPM's v1.0 release) and swtpm disagree in these, and
in each the TCG Library v1.85 sides with swtpm; `interop.py` reports
them as "known" with the reason instead of failing:

- Policies are not enforced when used: an object sealed under a policy
  unseals with an empty policy session, so a PCR_Extend does not stop it;
  PolicyAuthValue's HMAC is not checked (a wrong PIN unseals; the
  response then fails tpm2's rpHash check); an object without
  userWithAuth unseals with a password.
- Parameter encryption in a bound session that authorizes its own bind
  entity leaves the authValue out of the AES key (Part 1 §21.1 keeps it),
  so a Sign of an encrypted digest signs garbage.
- RSA_Encrypt and RSA_Decrypt ignore the OAEP label and hash.
- Trial sessions are refused (TPM_RC_VALUE), and policy sessions get
  handles in the HMAC range (0x02xxxxxx).
- PCR_Read answers with more than 8 digests (TPML_DIGEST holds 8): tpm2
  asks for 8 PCRs at a time, so it works with both.
- CertifyCreation takes its handles the other way round (the object signs,
  the AK is attested), and creation data and hashes are empty.
- ActivateCredential with an ECC EK fails (TPM_RC_VALUE), even for
  tpmemu's own MakeCredential; RSA works.
- Keyed-hash (HMAC) keys cannot be created (TPM_RC_AUTH_TYPE).
- Primary keys are random, not derived from the hierarchy's seed: an EK
  differs each time, and goose-tpm's key and sealed-object files, kept
  under a SRK made again, do not load in another process.
- RSAPSS is salted with the most the key allows (222 bytes), which v1.85
  allows only of TPMs before revision 1.63; swtpm uses the hash's length.
  `verify_signature` accepts both.
- A missing NV index is TPM_RC_HANDLE of handle 2, not 1; clockInfo in
  attestations is zero.

Others: swtpm started with `startup-clear` answers Startup with
TPM_RC_INITIALIZE, which `startup` takes as success. swtpm holds three
transient objects, so the live scenarios flush each as soon as they are
done; a TPM chip may hold as few. A TPM obfuscates resetCount,
restartCount and the firmware version in attestations signed by keys
outside the endorsement and platform hierarchies. mssim's power-on
resets the TPM (PCRs too), as tpm2-tss's TCTI does. Opening the device
needs Linux; elsewhere it is ERR_TRANSPORT.

## Not done

- TPM keys as `x509::PrivateKey`s for TLS, SSH and CMS: a separate design,
  shared with pkcs11's tokens. For now `sign` and `rsa_decrypt` take a
  handle and a session, and the caller wires them in.
- Windows' TBS (`tbs:` is ERR_UNSUPPORTED; Tbsi_Context_Create and
  Tbsip_Submit_Command would go in tpm2/src/tpmdev.c). The device
  transport is type-checked here, not run: no Linux machine with a TPM was
  at hand.
- Duplicate, Import, Rewrap, ObjectChangeAuth, HierarchyChangeAuth,
  NV_Certify, GetTime, audit sessions, PolicyNV, PolicyCpHash,
  PolicyNameHash, PolicyCounterTimer, PolicyTicket, PolicyLocality, XOR
  parameter obfuscation, ECDAA, a separate session only for encryption
  next to an authorizing one.
- Event logs in the old SHA-1 format (TCG_PCR_EVENT throughout), and
  reading the events' meaning (UEFI variables, boot entries): only the
  replay to PCRs is done.
- Checking an EK certificate's chain to its manufacturer's CA (x509's
  verification can; the manufacturers' roots are not bundled).
- The high-range EK templates (H-1 to H-7) beyond reading their
  certificates; an NV index's authValue with trailing zeros is not
  trimmed (Part 1 §19.6.4 says the TPM trims it, so such a value fails).
