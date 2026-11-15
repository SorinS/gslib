# webauthn

WebAuthn Level 3 and passkeys for Goose, the relying party's side (the
server): the options a browser's `navigator.credentials.create()` and
`.get()` take, in the L3 JSON serialization, and the checks of what
comes back, registrations with their attestation statements and
authentications with the stored credential; and the FIDO Metadata
Service's BLOB (MDS3), verified and searched. Three modules in namespace
`webauthn`, and a tool, `goose-webauthn`, with a small RP to try a real
browser and passkey with.

CBOR and COSE keys are gslib's `cbor` (`encoding/cbor`, strict: definite
lengths, no duplicate keys, limits); certificates and chains are
`crypto/x509`'s; signatures `crypto/bignum`'s through `cose`; JSON is the
standard library's; MDS3's JWT is `jwx`'s.

| Module | What |
|---|---|
| `webauthn.goose` | names and errors; `Policy` (`set_rp`, `add_origin`, `add_top_origin`, `related_origins_json`); `RegistrationOptions`, `registration_options`; `AuthenticationOptions`, `authentication_options`; `Descriptor`; `Credential` (the record), `marshal_credential`, `parse_credential`, `aaguid_text`; `Response`, `parse_response`, `response_ids`; `check_client_data`; `AuthData`, `parse_auth_data`; `Assertion`, `verify_authentication` |
| `webauthn/register.goose` | `verify_registration`; the attestation statement formats (`verify_statement`: none, packed, fido-u2f, tpm, android-key, apple); `check_trust` |
| `webauthn/mds.goose` | `Mds`, `parse_mds`; `MdsEntry`, `mds_lookup`, `mds_status_ok`; the statuses |

### What a registration is checked for

`verify_registration(p, challenge, response_json, roots, c)` (§7.1), in
this order, each failure its own error with `c.message` saying more:

- the response JSON (at most `max_response`, 256 KiB): UTF-8, no member
  twice; `type` "public-key"; `id` and `rawId` the same bytes, 1 to 1023
  of them; base64url without padding (standard base64 too with
  `lenient_base64`, for old clients);
- clientDataJSON: UTF-8 JSON, no member twice (a second `challenge`
  would be an attacker's); `type` "webauthn.create"; the challenge, its
  base64url canonical, equal to the one sent (in constant time); the
  origin exactly one of the policy's (the RP's own and its related
  origins: no prefix or suffix matching, no normalization); `crossOrigin`
  true only when `allow_cross_origin`; a `topOrigin` only with
  `crossOrigin` and on the policy's `top_origins`; a `tokenBinding`
  object's status "present" or "supported" (anything else in it is
  refused; a non-object, as old Edge sent, is passed over);
- the attestation object: CBOR decoded strictly (`fmt`, `attStmt` a map,
  `authData` bytes; nothing after it);
- the authenticator data: at least 37 bytes; the RP ID's SHA-256;
  UP (unless `require_user_presence` is off, for conditional create);
  UV when `user_verification` is `REQ_REQUIRED`; BS never without BE;
  AT set, and the attested credential data: an AAGUID, a credential ID
  of 1 to 1023 bytes that is the response's, a COSE key decoded strictly;
  extensions, when ED says so, a CBOR map; and nothing after that, nor
  anything after the key without ED;
- the key: a usable COSE key (cbor's checks: on its curve, no private
  parts, RSA of `min_rsa_bits`), with an alg, one the policy asked for
  (`algs`, else ES256, EdDSA, RS256), never RS1, and that fits the key
  (an EC2 P-256 key that says RS256 is `ERR_KEY`);
- the format, one this package does and the policy takes (`formats`),
  and its statement (below); then trust: the statement's certificates
  checked against `roots` with crypto/x509 at `p.now` (the leaf first,
  the rest as intermediates, any extended key usage) set `c.trusted`.
  None and self attestation are never trusted; `require_trusted` makes
  untrusted an error (`ERR_TRUST`). `roots` without `p.now` is `ERR_ARG`.

The formats (§8):

- **none**: an empty statement.
- **packed**: alg and sig; without x5c, self attestation by the
  credential's own key and alg; with x5c, the signature by the
  certificate's key and alg (which must fit it), the certificate v3 with
  C (two letters), O, OU "Authenticator Attestation" and CN, not a CA,
  and its FIDO AAGUID extension (1.3.6.1.4.1.45724.1.1.4), when there,
  not critical and the authenticator data's AAGUID.
- **fido-u2f**: one P-256 certificate, a P-256 credential key, and the
  signature over 0x00 || rpIdHash || clientDataHash || credentialId ||
  the uncompressed point.
- **tpm**: ver "2.0"; pubArea (TPMT_PUBLIC, RSA or ECC, parsed to its
  end) whose key is the credential's (an exponent of 0 being 65537);
  certInfo (TPMS_ATTEST, parsed to its end): magic TPM_GENERATED_VALUE,
  type ATTEST_CERTIFY, extraData the hash (by the statement's alg) of
  authData || clientDataHash, the certified name nameAlg || H(pubArea);
  the AIK certificate's signature over certInfo (RS1 only with
  `allow_rs1`), v3, an empty subject, a subjectAltName with the TPM's
  manufacturer (a registered TCG vendor ID unless `tpm_any_vendor`),
  model and version, the tcg-kp-AIKCertificate extended key usage, not a
  CA, and the AAGUID extension as packed's. ECDAA is not taken.
- **android-key**: the signature by the leaf's key; the leaf's key the
  credential's; the key description extension's attestationChallenge the
  clientDataHash, no allApplications in either authorization list, and
  origin GENERATED and purpose SIGN (in teeEnforced, or in either list
  unless `android_tee_only`).
- **apple**: the leaf's nonce extension (1.2.840.113635.100.8.2) the
  SHA-256 of authData || clientDataHash, and its key the credential's.

What comes out is the `Credential` record: ID, the COSE key as the
authenticator encoded it, alg, signature counter, UV at registration,
BE and BS, transports, AAGUID, format, attestation type (none, self,
basic, anonca), whether it was trusted, authenticatorAttachment, credProps'
rk, and the attestation certificates (the trust path). The caller stores
it: `marshal_credential` makes deterministic CBOR of it,
`parse_credential` reads it back.

### What an authentication is checked for

`verify_authentication(p, challenge, response_json, record, user_handle,
require_user_handle, a)` (§7.2): the response is for the record's
credential (`ERR_UNKNOWN_CREDENTIAL`); a userHandle, when there, is the
account's, and is required with `require_user_handle` (a passkey sign-in
where the user was not known beforehand); clientDataJSON as above with
type "webauthn.get"; the authenticator data's RP ID hash, UP, UV, BS
never without BE, no AT, extensions only with ED, nothing after; BE what
it was at registration (`ERR_BACKUP`); the signature over authData ||
SHA-256(clientDataJSON) by the stored key and alg; and the counter: one
that did not go forward (both 0 is fine: passkeys send 0) is reported in
`a.counter_regressed`, and refused only when `refuse_sign_count`. A BS
that changed is reported (`a.backup_changed`); store `a.sign_count` and
`a.backed_up` in the record afterwards.

To find the record first, `response_ids(json, id, user_handle)` reads
the credential ID and user handle.

### MDS3

`parse_mds(blob, fido_root, now, m)` verifies the BLOB (the JWT as
served, from a file or wherever the caller got it): a compact JWS by
RS256, ES256 or PS256 whose protected header's x5c (standard base64)
chains to `fido_root` (GlobalSign Root R3 for the FIDO Alliance's
service) at `now`, signed by the leaf; its payload's `no`, `nextUpdate`
(`m.stale` once it has passed) and `entries`. `mds_lookup(m, aaguid, e)`
finds an entry: its description, its metadata statement's
attestationRootCertificates (DER, concatenated: the `roots` to give
`verify_registration`), its status reports. `mds_status_ok(e)` refuses
(`ERR_STATUS`) an authenticator any of whose reports is REVOKED,
USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE,
USER_KEY_REMOTE_COMPROMISE or USER_KEY_PHYSICAL_COMPROMISE, whatever
came after.

## Using it

```goose
import gslib from "SorinS/gslib@v0.1";
import gslib.webauthn;
import gslib.webauthn.register;

var p = webauthn::Policy { now: now_seconds, .. };
webauthn::set_rp(p, "example.org");
webauthn::add_origin(p, "https://example.org");

// Registration: options to the browser, the challenge kept in the session.
var o = webauthn::RegistrationOptions { .. };
o.rp_id.append("example.org");
o.rp_name.append("Example");
o.user_id.append(user_handle);              // random, up to 64 bytes
o.user_name.append("alice@example.org");
o.resident_key = webauthn::REQ_REQUIRED;     // a passkey
let options_json, e = webauthn::registration_options(o, existing_credentials);
// ... the browser answers with PublicKeyCredential.toJSON():
var c = webauthn::Credential { .. };
let r = webauthn::verify_registration(p, o.challenge, response_json, mds_roots, c);
if r != webauthn::OK { print(webauthn::error_text(r), ": ", c.message); return; }
store(user, webauthn::marshal_credential(c));

// Sign-in (a passkey: no allowCredentials).
var ao = webauthn::AuthenticationOptions { .. };
ao.rp_id.append("example.org");
let request_json, e2 = webauthn::authentication_options(ao, []);
var id: u8[>..] = [];
var handle: u8[>..] = [];
webauthn::response_ids(response_json, id, handle);   // find the record and the account
var rec = webauthn::Credential { .. };
webauthn::parse_credential(stored_bytes, rec);
var a = webauthn::Assertion { .. };
let r2 = webauthn::verify_authentication(p, ao.challenge, response_json, rec, account_handle, true, a);
if r2 == webauthn::OK { rec.sign_count = a.sign_count; rec.backed_up = a.backed_up; /* store rec */ }
```

`Credential` holds a growable field (the certificates), so `var x = c;`
names the same record: `copy(c)` for another.

## goose-webauthn

```
goose-webauthn registration-options --rp-id ID --rp-name NAME --user-name NAME [--user-id B64URL] [--challenge B64URL]
               [--alg N ...] [--attestation none|indirect|direct|enterprise] [--resident-key R] [--uv R]
               [--attachment platform|cross-platform] [--exclude B64URL ...]
goose-webauthn authentication-options --rp-id ID [--challenge B64URL] [--allow B64URL ...] [--uv R]
goose-webauthn verify-registration --rp-id ID --origin O [--origin O ...] --challenge B64URL [--roots PEM] [--now S]
               [--uv required] [--require-trusted] [--alg N ...] [--cross-origin] [--top-origin O] [--lenient]
               [--allow-rs1] [--tpm-any-vendor] [--record-out FILE] RESPONSE.json
goose-webauthn verify-authentication --rp-id ID --origin O --challenge B64URL --record FILE [--user-handle B64URL]
               [--require-user-handle] [--uv required] [--refuse-sign-count] [--record-out FILE] RESPONSE.json
goose-webauthn mds BLOB --root PEM [--now S] [--aaguid HEX]
goose-webauthn serve [--port 8080] [--rp-id localhost] [--origin http://localhost:8080] [--uv required]
```

`verify-registration` prints the record's fields a line each and writes
the record (`marshal_credential`) to `--record-out`;
`verify-authentication` reads such a record and writes it back with the
new counter. Without `--alg`, a registration may use any algorithm
`cose` knows but RS1. `--now` defaults to the clock.

### Trying it with a browser and a passkey

```bash
make build        # or: goose build -o goose-webauthn webauthn/tools/webauthn.goose
goose-webauthn serve --port 8080
# open http://localhost:8080/ (localhost, not 127.0.0.1: the RP ID is "localhost")
```

The page has a user name field and three buttons: **Register** (a
passkey for that name: residentKey required, attestation direct, the
user's existing credentials excluded), **Sign in as this user**
(allowCredentials: the name's credentials) and **Sign in with a passkey**
(no name: the authenticator offers the passkeys it has for localhost,
and the user handle in the answer names the account). Each prints what
the server found: the format and attestation, the algorithm, the
AAGUID, whether the credential is discoverable and backup eligible, the
counter. http://localhost is a secure context, so no certificate is
needed; Chrome, Safari and Firefox take it. The credentials live in the
server's memory until it stops. A platform authenticator (Touch ID,
Windows Hello, Android), a phone over hybrid (the QR code), or a USB/NFC
security key all work; a security key with a PIN asks for it, since the
options prefer user verification. `examples/webauthn/rp_server.goose` is
the same server, smaller.

This is the part no test here does: a real browser and real
authenticators. The interop below plays both with software.

## Examples

In gslib's `examples/webauthn/`, run from gslib's top as `goose examples/webauthn/<name>.goose`:

- `offline.goose`: a registration and a passkey sign-in from end to end
  in one program, the browser and the authenticator played by it (a
  P-256 key, packed self attestation): options, response, the record
  kept, the assertion verified, and the same assertion replayed for a
  new challenge refused.
- `rp_server.goose`: the smallest useful RP on http://localhost:8080,
  with the page; needs a browser, so `make test` only type-checks it.

## Tests

`make test-webauthn` (`python3 webauthn/scripts/run_tests.py`) runs each
`webauthn/test/*.goose` at -O0, -O2 and with `--debug`, and the example:

- `vectors.goose` (594 checks): every registration and authentication of
  the WebAuthn L3 specification's §16 (none, self, crossOrigin,
  topOrigin, a 1023-byte credential ID; packed with ES256, ES384, ES512,
  RS256, Ed25519 and Ed448 credentials; TPM, Android Key, Apple and FIDO
  U2F), the attestation chains trusted under §16.1's root and not under
  another (and refused then when trust is required, and untrusted in
  2000), each record written, read back, and used for its authentication,
  which is then tried with another challenge, origin and RP ID, a counter
  behind (reported, refused when asked), BE changed and UV required; and
  py_webauthn's vectors from real authenticators: packed (YubiKeys, an
  Ed25519 key), fido-u2f (a YubiKey, FIDO's conformance tool), tpm
  (a Surface Pro 4, a Dell XPS 13, a Lenovo X1, an ECC TPM: standard
  base64 and RS1, taken only when allowed), android-key (under Google's
  roots, at the dates py_webauthn's tests use), apple (under Apple's
  WebAuthn root), none (over caBLE, several origins), authentications by
  EC2, RSA and OKP keys, and the ones py_webauthn refuses (a wrong key,
  UV required, bad authenticator data, a tokenBinding status Level 2 does
  not know), each with the outcome py_webauthn's tests expect. Made by
  `scripts/make_vectors.py` from the spec's HTML and a py_webauthn
  checkout; only public values are kept (not the spec's private keys).
- `hostile.goose` (252 checks): a software authenticator in Goose
  (`test/tv.goose`) and each thing changed: the challenge (another, a
  shorter one, one with its unused base64url bits set), the origin
  (another, a trailing slash, http), the type, members twice in
  clientDataJSON, crossOrigin and topOrigin both ways, clientDataJSON
  that is not JSON, an array, not UTF-8, tokenBinding; UP missing (and
  taken for conditional create), UV required, BS without BE, AT missing,
  bytes after the key and after the extensions, ED with nothing or not a
  map; credential IDs of 1023 bytes (taken) and 1024 (refused), the
  authenticator data's ID not the response's, another RP ID, authData
  of 3 bytes; `fmt` twice in the attestation object, a label twice in the
  COSE key, an indefinite map, trailing bytes; an ES256 key that says
  RS256, alg -260, RS1, EdDSA not asked for, a key without alg, packed
  self by another alg, a signature changed, none with a statement,
  android-safetynet and an unknown format, none not allowed, none and
  self when trust is required; packed certificates with another AAGUID, a
  critical AAGUID extension, no AAGUID (taken), the wrong OU, no CN, a
  CA, another key; trust under another CA, roots without a time;
  fido-u2f good, with two certificates, over another credential ID; x5c
  that is not a certificate; id and rawId apart, type "password", a member
  twice in the response, padded base64 (and taken when lenient), the size
  limit, origins with a newline and filling up; assertions with the
  userHandle missing, another, for another credential, of type create,
  without UP, with AT, trailing bytes, ED and an empty map, BE now set,
  BS without BE, another key, a record that says RS256 for an ES256 key,
  counters equal, forward and both 0, UV required, BS changed.
- `options.goose` (44 checks): both kinds of options read back as JSON
  (challenges made, default and given algorithms, exclusions with
  transports, authenticatorSelection, hints, attestation formats,
  credProps), the arguments refused, the related origins document,
  AAGUID text, records from junk.
- `mds.goose` (44 checks): a BLOB made in the test (a root, a signing
  certificate under it in x5c, ES256): its entries looked up (a certified
  one, a revoked one, one whose user verification could be bypassed and
  was updated since, still refused), and the BLOB refused under another
  root, without a root or a time, before the signer was valid, with its
  payload changed, x5c in base64url, no x5c, signed by another key, no
  entries, a bad nextUpdate, HS256, alg none, not a JWT; a stale one
  read and marked; a registration trusted through the BLOB's roots.

### Against other implementations

`make interop-webauthn` (`webauthn/scripts/interop.py`, 353 checks, all
on 127.0.0.1 or in-process), run by a Python with `fido2` (python-fido2
2.x), `webauthn` (py_webauthn), `cbor2` and `cryptography` in a venv
(nothing system-wide), and Go for go-webauthn, built from
`scripts/gowebauthn` (go.mod pins go-webauthn v0.18.2) into the work
directory:

```bash
python3 -m venv /tmp/webauthnvenv && /tmp/webauthnvenv/bin/pip install 'fido2>=2' webauthn cbor2 cryptography
WEBAUTHN_PYTHON=/tmp/webauthnvenv/bin/python make interop-webauthn
```

The Go modules go to a GOPATH in the work directory (a temporary one
unless `--work DIR`); `WEBAUTHN_GOPATH=DIR` keeps them between runs. The
software authenticator builds its answers with python-fido2's own
classes (CollectedClientData, AuthenticatorData, AttestedCredentialData,
AttestationObject, CoseKey) and signs with `cryptography`:

- ES256, ES384, EdDSA, RS256 and PS256 credentials, attested none,
  packed self, packed with a certificate under a throwaway CA (trusted
  by goose-webauthn with `--require-trusted`) and fido-u2f: each
  registration taken by goose-webauthn, py_webauthn 3.0, python-fido2's
  Fido2Server 2.2 and go-webauthn; two sign-ins each taken by all four
  (goose-webauthn with the record it wrote); and another challenge, a
  signature changed, another origin, another RP ID, another credential
  ID, and UV required but absent refused by every one of them.
- Their options answered: Fido2Server's register_begin and
  authenticate_begin, py_webauthn's generate_registration_options,
  go-webauthn's BeginRegistration and BeginLogin; each answer taken by
  them and by goose-webauthn with their challenge.
- goose-webauthn's registration and authentication options read by
  py_webauthn's parse_*_options_json, python-fido2's
  PublicKeyCredential*Options.from_dict and go-webauthn's protocol
  types: the RP, user handle, challenge, algorithms in order,
  exclusions, residentKey, userVerification and attestation as asked.
- `goose-webauthn serve` driven over HTTP: two users register, one signs
  in by name, the other as a passkey; a passkey sign-in without a user
  handle, one user's credential for the other's sign-in, and another
  origin refused.

What the others do that a peer must allow for:

- py_webauthn has no ES384 (-35): it refuses such credentials, so that
  part is skipped for it. Its default algorithms leave out PS256 and
  ES512 unless given.
- go-webauthn checks a registration's alg against the session's
  `credParams`, and refuses client extension outputs not asked for
  unless `ExtensionsUnsolicitedOutputPolicyIgnore`.
- python-fido2's Fido2Server checks attestation statements but trusts
  none without a verifier; goose-webauthn likewise keeps "verified" and
  "trusted" apart.
- The real FIDO MDS3 BLOB (11 MB, 537 entries, signed RS256 under
  GlobalSign Root R3) verified with `goose-webauthn mds` in 0.15 s;
  a YubiKey 5 and Windows Hello found and allowed, an authenticator
  REVOKED and later NOT_FIDO_CERTIFIED refused. It is not part of the
  interop: fetching it is left to the caller.

## Quirks

- The spec's TPM vector (§16.13) names the manufacturer `id:00000000`,
  which TCG has not registered: refused unless `tpm_any_vendor`. Its
  Android Key vector encodes the security levels as INTEGER rather than
  ENUMERATED; they are not read, so it passes.
- py_webauthn's TPM vectors (2019, Windows) carry standard base64 with
  padding and attest with RS1 (SHA-1): taken only with `lenient_base64`
  and `allow_rs1`, both off by default.
- AT in an assertion is refused (`ERR_FLAGS`); no authenticator tried
  sets it.
- Origins are compared exactly as clientDataJSON has them; an RP behind
  several hosts lists each, and related origins (§5.11) are on the same
  list (`related_origins_json` writes the .well-known document).
- A counter that did not go forward is reported, not refused, by default
  (synced passkeys keep 0; some security keys share a counter).
- An MDS entry is refused when any of its reports is a revocation or a
  compromise, even when a later one says an update fixed it: the
  attestation does not say which firmware made it.

## Not done

- android-safetynet (deprecated by Google), ECDAA, and compound
  attestation; the AppID extensions (`appid`, `appidExclude`: a U2F
  credential's rpIdHash under its AppID).
- Extensions processed: credProps' rk is read from the client's
  results; prf, largeBlob, credProtect, minPinLength and the rest are
  passed over (their outputs are in the authenticator data's extensions,
  which are checked to be a CBOR map).
- CRLs for attestation and MDS chains; MDS's metadata statements beyond
  the description, roots and status (attestation types, key protection,
  icons); fetching the BLOB; AAID and U2F key identifier entries.
- Credential storage: the caller keeps records (`marshal_credential`)
  and challenges (single use, with an expiry: the policy has no clock
  for them).
- The Level 3 signal API and the "limited verification" of
  clientDataJSON by a fixed prefix; ML-DSA credentials (no COSE AKP keys
  yet).
