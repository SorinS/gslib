# kmip

KMIP for Goose, both sides: the Key Management Interoperability Protocol,
OASIS's protocol between a program and a key manager (HSM appliances,
Thales CipherTrust, Fortanix, Vault's KMIP engine, VMware and NetApp's
storage encryption, MongoDB and MySQL's encrypted storage), in versions
1.0 to 1.4, 2.0 and 2.1. TTLV, its binary encoding, and the XML and JSON
encodings of KMIP's Profiles; the request and response messages with
their batches; attributes, written once and sent in 1.x's or 2.0's form;
the managed objects in every key format; wrapped keys; a client over TLS
or HTTPS; and a key manager with an in-memory store that does every
operation of KMIP 2.1 but a few (see Not done). Twenty-four modules in
namespace `kmip`, and two tools, `goose-kmip` and `goose-kmipd`.

**One list of attributes, two protocols.** KMIP 1.x names attributes
by text in Attribute structures (`Attribute Name` "Cryptographic
Algorithm", `Attribute Value` AES) inside a Template-Attribute; 2.0
writes each attribute as the item itself, under its own tag, inside an
Attributes structure, and names them in requests by their tag
(Attribute Reference). `Attrs` keeps the 2.0 items, and every operation
writes the form of the version spoken; what comes back, in either
form, reads into the same `Attrs`. A vendor's attribute is 2.0's
Attribute structure (Vendor Identification, Attribute Name, Attribute
Value) and 1.x's `x-name`, one mapped to the other. The version is
settled once, `negotiate` (Discover Versions, from 1.1), or set; a 1.0
server is spoken to in 1.0.

**The decoder is strict.** A length that does not fit its type, padding
that is not zero, a Boolean that is not 0 or 1, a Structure whose
children do not fill it exactly, a Text String that is not UTF-8, or
nesting, items or bytes past the limits (32, 1 << 20, 16 MiB) are
refused, never mended. The XML and JSON readers are as strict.

**TLS as KMIP's profiles want it.** Key managers know their clients by
their TLS certificates; `tls_config` is `tls::client_config` with the
suites KMIP's TLS 1.2 authentication suites name (CBC with SHA-256)
after Go's defaults, since servers built on them (PyKMIP) may take
nothing else; TLS 1.3 when the server has it. A username and password
(`password_credential`) or a ticket (`ticket_credential`, from Login)
go in each request's Authentication when a server wants one.

| Module | What |
|---|---|
| `kmip.goose` | errors (`error_text`); the item types (`type_name`); `decode` into `Node`s (offsets into the buffer, no copies; `Options`: `max_depth`, `max_items`, `max_bytes`, `check_utf8`), `message_length` (a stream's framing); reading: `child`, `next_same`, `count`, `each`, `raw`, `value`, `as_int`, `as_long`, `as_enum`, `as_bool`, `as_text`, `as_bytes`, `as_datetime`, `as_interval`, `as_bigint`, `as_biguint`, `child_text` and the other `child_*`; writing: `put_int`, `put_long`, `put_enum`, `put_bool`, `put_text`, `put_bytes`, `put_datetime`, `put_datetime_ext`, `put_interval`, `put_bigint`, `put_biguint`, `begin` and `end` (a Structure's length put in last), `put_raw`, `put_retagged`; `tag_name`, `enum_name`, `attribute_tag`, `attribute_name`; `dump` (a message as indented text) |
| `kmip/tables.goose` | generated from KMIP 2.1's specification (with 1.4's values 2.x dropped, and PyKMIP's names): every tag (`TAG_*`), every enumeration (`OBJ_`, `OP_`, `STATUS_`, `REASON_`, `ALG_`, `MODE_`, `PAD_`, `HASH_`, `SIG_`, `FMT_`, `STATE_`, `LINK_`, `REVOKE_`, `QUERY_`, `CURVE_`, `USAGE_`, `DERIVE_`, `WRAP_`, `KEY_WRAP_`, `SPLIT_`, `ROLE_`, `PSM_`, ...), their names as KMIP 1.x's text and the encodings write them, which enumeration each tag holds, the masks' bits, KMIP 1.x's attribute names |
| `kmip/messages.goose` | `Version` (`V1_0` to `V2_1`, `is_v2`, `version_eq`, `version_lt`, `put_version`, `read_version`); `Credential` (`no_credential`, `password_credential`, `ticket_credential`); a request: `begin_request`, `begin_request_with` (`HeaderOptions`: Asynchronous Indicator, Maximum Response Size, Batch Error Continuation), `begin_item`, `end_item`; a response: `parse_response` into `Response` and its `Item`s (`item_id`, `result_message`, `item_async`); the server's side: `parse_request` into `Request` and `RequestItem`s (`request_item_id`, `request_username`, `request_password`), `begin_response`, `begin_result`, `end_result` |
| `kmip/attributes.goose` | `Attrs` (`attrs`): `attr_text`, `attr_int`, `attr_long`, `attr_enum`, `attr_bool`, `attr_bytes`, `attr_datetime`, `attr_interval`, `attr_usage`, `attr_name`, `attr_link`, `attr_curve`, `attr_crypto_params`, `attr_raw`; `each_attr`, `attr_count`, `find_attr`, `has_attr`, `has_item`, `get_text`, `get_bytes`, `get_enum`, `get_int`, `get_long`, `get_bool`, `get_datetime`, `get_interval`, `get_name`, `get_curve`; `remove_attr`, `replace_attr`, `set_single`; `CryptoParams` (every field of Cryptographic Parameters: mode, padding, hash, signature, algorithm, IV and tag lengths, counter, salt, MGF1's hash, P Source...), `put_crypto_params`, `read_crypto_params`; rendering: `put_template`, `put_attributes`, `put_attribute_items`, `put_attribute_1x` (`_at`, with its Attribute Index); reading: `read_attrs` (1.x or 2.0); vendors' attributes: `put_custom`, `custom_key`; `reference_tag`, `reference_custom` |
| `kmip/objects.goose` | `Object` (type, key format, algorithm, length, sub-type, the Key Wrapping Data of a wrapped key, a Split Key's fields, material): `symmetric_key`, `private_key`, `public_key`, `certificate`, `secret_data`, `opaque_data`; `put_object`, `read_object`, `object_tag` |
| `kmip/formats.goose` | `convert_key`: a key in the Key Format Type asked for: private keys between PKCS #1, PKCS #8, ECPrivateKey and the Transparent RSA, EC (and 1.x's ECDSA, ECDH, ECMQV) and DSA Private Key structures; public keys between X.509, PKCS #1 and the transparent ones; Raw and Transparent Symmetric Key; `private_of` (an x509 key of any of them), `spki_of_object`, `curve_of_kind`, `kind_of_curve` |
| `kmip/crypto.goose` | the cryptography KMIP names, on gslib's: `hash_id`, `hmac_bits`; `sym_crypt` (AES, Triple DES, ChaCha20, ChaCha20-Poly1305; ECB, CBC, CFB, OFB, CTR, GCM with short tags, CCM, XTS with a 16-byte tweak, NIST Key Wrap, AES Key Wrap with Padding; PKCS #5, ANSI X9.23, ISO 10126, zeros or no padding), `sym_mac` (HMAC, CMAC), `rsa_crypt` (OAEP with its hash, MGF1's and label, PKCS #1 v1.5), `sign_with` and `verify_with` (on data or a digest of any length; PSS with the hash's salt or the longest) |
| `kmip/wrap.goose` | `Wrapping` (`wrapping`, `wrap_encrypt_key`, `wrap_mac_key`, `wrap_attribute`), `read_wrapping`, `put_wrapping_spec`, `put_wrapping_data`; `wrap_object` (Encrypt, MAC/sign, Encrypt then MAC/sign, MAC/sign then Encrypt; the Key Value TTLV-encoded with the attributes asked for, or No Encoding), `unwrap_object`, `unwrap_with` (a client's own copy of the wrapping key) |
| `kmip/split.goose` | Split Key objects, and `split_secret`, `join_secret` (XOR; polynomial sharing in GF(2^8), GF(2^16) and a prime field, on `bignum.shamir`) |
| `kmip/client.goose` | `Client`: `tls_config`, `dial`, `close`, `exchange`, `call` (one operation, its payload written by a block), `describe` (an error with the server's Result Reason and Message); `discover_versions`, `negotiate`, `query`; `create`, `create_key_pair`, `register`, `get`, `get_attributes`, `get_attribute_list`, `add_attribute`, `set_attribute`, `modify_attribute`, `delete_attribute`, `locate`, `activate`, `revoke`, `destroy`, `encrypt` and `decrypt` (`Sealed`: data, IV, AEAD tag), `sign`, `verify`, `mac`, `rng_retrieve`. The operations take any client type with `exchange`, `version` and the `last_*` fields: `Client`, `HttpClient`, or `Local` |
| `kmip/client_ops.goose` | `get_as` (a format, a Key Wrap Type, a Key Wrapping Specification), `get_wrapped`, `export_object`, `import_object`; `rekey`, `rekey_key_pair`, `derive_key` (`Derivation`); `check`, `obtain_lease`, `get_usage_allocation`, `archive`, `recover`, `adjust_attribute`, `interop`; `mac_verify`, `hash`, `rng_seed`, `sign_digest`, `verify_digest`; `part` (any cryptographic operation in parts: `Part`, its Correlation Value) |
| `kmip/client_pki.goose` | `certify`, `recertify`, `validate`, `create_split_key`, `join_split_key` |
| `kmip/client_session.goose` | asynchronous items (`submit`, `poll`, `process_async`, `cancel`, `query_async`); tickets (`login`, `delegated_login` with Rights, `logout`); `log_message`, `ping`, `set_endpoint_role`, `reprovision`, `pkcs11`; `set_defaults`, `set_constraints`, `get_constraints`; the Query functions past 1.2's (`query_capabilities`, `query_profiles`, `query_enums`, `query_registration_methods`, `query_defaults`); `take_server_request` (a server's Notify or Put, answered) |
| `kmip/https.goose` | KMIP over HTTPS: `HttpClient` (`https_dial`, `exchange`, `close`), `MSG_TTLV`, `MSG_XML`, `MSG_JSON`, `content_type`, `encoding_of`, `encode_as`, `decode_as`; the server's side: `HttpConn` (`http_conn`), `http_serve` |
| `kmip/text.goose` | what the XML and JSON encodings share: `tag_by_name`, `tag_from_text`, `tag_text`, `type_from_text`, `enum_by_name`, `enum_from_text`, `enum_text`, `is_mask`, `mask_text`, `mask_from_text`, `names_tag`, `put_from_text`, `value_text`, `datetime_text`, `datetime_from_text` |
| `kmip/xml.goose` | KMIP's XML encoding: `to_xml`, `ttlv_to_xml`, `from_xml`, `xml_element_to_ttlv` |
| `kmip/json.goose` | KMIP's JSON encoding: `to_json`, `ttlv_to_json`, `from_json` |
| `kmip/server.goose` | `Server` (`server`; `now`, `max_objects`, `lease_time`, `vendor`, `ca_cert` and `ca_key` for Certify): `handle` (a request's bytes and the client's identity to the response's), `peer_identity` (a client certificate's commonName), `object_count`; the request's handling: batches (Stop, Continue, Undo), the ID Placeholder, Maximum Response Size, each version's Result Reasons (`reason_for`); the store: `add_object`, `add_object_with`, `set_state`, `settle` (the state an object's dates put it in) |
| `kmip/server_manage.goose` | Discover Versions, Query, Create, Create Key Pair, Register, Get and Export, the attribute operations, Locate, Activate, Revoke, Destroy |
| `kmip/server_crypto.goose` | Encrypt, Decrypt, Sign, Signature Verify, MAC, MAC Verify, Hash (each in parts too), RNG Retrieve, RNG Seed |
| `kmip/server_lifecycle.goose` | Re-key, Re-key Key Pair, Derive Key, Check, Obtain Lease, Get Usage Allocation, Archive, Recover, Import, Adjust Attribute, Interop |
| `kmip/server_pki.goose` | Certify, Re-certify, Validate, Create Split Key, Join Split Key |
| `kmip/server_session.goose` | Poll, Cancel, Process, Query Asynchronous Requests; Login, Logout, Delegated Login (`add_user`); Log, Ping, Set Endpoint Role, Re-Provision, PKCS#11; Set Defaults, Set Constraints, Get Constraints (`add_group`); 2.1's Rotate attributes; the server-to-client Notify and Put (`put_request`, `notify_request`) |
| `kmip/local.goose` | `Local` (`local`): a client whose server is in the program, for tests and for KMIP's model without a key manager |

## The server

`handle` answers every operation of KMIP 2.1 but Set Endpoint Role to
Client, each from the version that brought it (Query lists them): the
basic ones of 1.0; Discover Versions and Re-key Key Pair (1.1); the
cryptographic services and split keys (1.2); Import and Export (1.4);
Log, Login, Logout, Delegated Login, Adjust Attribute, Set Attribute,
Set Endpoint Role, PKCS#11 (C_Initialize, C_GetInfo, C_Finalize),
Interop and Re-Provision (2.0); Set Defaults, Set and Get Constraints,
Query Asynchronous Requests, Process and Ping (2.1). What it makes and
takes:

- **Keys and objects.** Create makes AES, Triple DES (with parity),
  ChaCha20, ChaCha20-Poly1305 and HMAC keys and secret data (a
  Password, as long as asked); Create Key Pair RSA (2048 to 4096, kept in
  PKCS #1) and EC on P-224, P-256, P-384, P-521, secp256k1 and
  brainpoolP256r1, P384r1, P512r1. Register takes keys in any format
  (and without their value, kept elsewhere), certificates, secret data,
  opaque data, split keys, wrapped keys as they are. Get gives a key in
  any format it converts to, and Import and Export carry an object with
  its attributes.
- **Wrapped keys.** A key registered wrapped is given as registered, or
  unwrapped with the key its Key Wrapping Data names (Key Wrap Type Not
  Wrapped). Get and Export wrap a key as a Key Wrapping Specification
  says, with keys the server holds, which must have Wrap Key (or MAC
  Generate, Sign) in their usage and the parameters asked among theirs.
  A Sensitive key leaves wrapped only; an unextractable one not at all.
- **Cryptography.** Encrypt and Decrypt with symmetric keys in every
  mode of `kmip.crypto`, or RSA (OAEP, PKCS #1 v1.5) with a key pair;
  Sign and Signature Verify on data or a digest; MAC and MAC Verify
  (HMAC, CMAC); Hash; each also in parts, ECB and CBC giving whole
  blocks as they come. A key protects (encrypts, signs, wraps) only when
  Active and before its Protect Stop Date, and processes (decrypts,
  verifies) after its Process Start Date; Usage Limits are counted in
  bytes or objects.
- **Derived and replacement keys.** Derive Key with PBKDF2, HASH, HMAC,
  ENCRYPT, SP 800-108's counter, feedback and double-pipeline modes,
  HKDF, and ECDH (AsymmetricKey); Re-key and Re-key Key Pair, the dates
  moved by the Offset, the Names handed on, the two keys linked; 2.1's
  Rotate attributes counted on.
- **Certificates and split keys.** Certify and Re-certify from a
  PKCS #10 request or a public key, with the server's CA; Validate;
  Create and Join Split Key.
- **The life cycle.** Pre-Active, Active once activated or once its
  Activation Date has come, Deactivated when revoked or at its
  Deactivation Date, Compromised, Destroyed: Destroy drops the key
  material and keeps the object, its attributes and its Destroy Date for
  Get Attributes and Locate (Get says Object Destroyed). Archive keeps an
  object out of use until Recover. Check, Obtain Lease and Get Usage
  Allocation answer from the usage mask, the Lease Time and the Usage
  Limits.
- **Attributes the server keeps.** Unique Identifier, Object Type,
  State, the dates, Digest (SHA-256 of the Key Material, and of a
  transparent one's TTLV), Short Unique Identifier, Fresh, Lease Time,
  Sensitive, Extractable, Always Sensitive, Never Extractable, Protection
  Storage Mask, Random Number Generator and Original Creation Date for
  what it makes, a certificate's own attributes; a client that gives one
  of them is refused (Read Only Attribute). A Name belongs to one object
  only; Set Defaults' attributes fill in what a request leaves out and
  Set Constraints' are checked.
- **Requests.** Objects are the client's that made them, by the identity
  `handle` is given (`goose-kmipd` gives the CN of the client's
  certificate), or the user a ticket names; `add_user` and
  `require_auth` ask for a password. Batches stop at the first failure,
  go on, or undo what was done, as the request asks; the ID Placeholder
  carries an item's object to the next; an item asked for
  asynchronously is kept for Process and Poll. Before 2.0 the Result
  Reasons 1.x does not have are given as the 1.x one nearest them.

Each object is held in a fixed 32 KiB record; `max_objects` (100000)
bounds the store. Nothing outlives the program: it is a test server and
a reference, not a key manager to keep keys in.

## XML, JSON and HTTPS

**The encodings.** KMIP's Profiles (2.1, §5.4 and §5.5) write a message
as XML or JSON as well as TTLV: each item an element (or object) named
by its tag, with its type and value, a Structure's children inside it.
`kmip.xml` and `kmip.json` turn TTLV into either and back. The names are
the Profiles' normalized ones (`UniqueIdentifier`, `SymmetricKey`, `DES3`
for 3DES, `PKCS_1`, `OnLineStorage`); KMIP 1.x's Attribute Value takes
its names from the Attribute Name beside it, and Attribute Reference's
are tags'. Masks are their bits' names (`Encrypt Decrypt`,
`Encrypt|Decrypt` in JSON). What is read takes every form the Profiles
allow: hex for tags (`0x420094`, or `x540001` as an element), numbers,
enumerations, masks, Booleans and Date-Times; the general `<TTLV tag=...>`
form; the namespace `urn:oasis:tc:kmip:xmlns`; JSON numbers and hex
strings, `null` for an empty Structure. What is written is always one
form: decimal numbers, names where there are names, Byte Strings in
lower-case hex, Date-Times as xsd:dateTime in UTC (in hex outside the
years 1 to 9999), JSON's Long Integers past 2^52 in hex. The readers are
strict: an unknown tag, type, attribute or member, text inside an
element, a value that is no value of its type, nesting past
`max_depth`, are refused, and `why` says which element and what. XML
1.0 cannot carry most control characters even as references, so a Text
String holding one is refused by the XML writer (`ERR_UTF8`); JSON
carries them.

**HTTPS.** The Profiles' HTTPS binding (§5.3) sends each message as the
body of an HTTP/1.1 POST, by default to `/kmip`, in TTLV
(`application/octet-stream`), XML (`text/xml`) or JSON
(`application/json`), with `Cache-Control: no-cache`. `https_dial` gives
an `HttpClient` over the same TLS as `dial`, which every operation takes
as it takes a `Client`. `http_serve` is the server's side for a program
holding a connection's plaintext: it reads the requests in it with
net/http's HTTP/1.1, answers each with `handle` in the encoding it came
in, and refuses other methods (405), other targets (404), other content
types (415), bodies past 256 KiB (413) and bodies that are not a message
(400).

## Tools

```bash
goose-kmip --host kms.example.com --ca ca.pem --cert client.pem --key client.key query
goose-kmip ... create aes 256 --key-name backup-key       # prints the identifier
goose-kmip ... create-pair ec p256
goose-kmip ... locate backup-key
goose-kmip ... activate 7
goose-kmip ... encrypt 7 "attack at dawn"                  # AES-GCM: nonce, ciphertext, tag
goose-kmip ... sign 9 "a message"
goose-kmip --https [/kmip] --encoding json ...             # over HTTPS, the messages in JSON
goose-kmip dump message.ttlv [--xml|--json]                # TTLV, XML or JSON, decoded
goose-kmip convert message.xml ttlv message.ttlv           # between the three encodings

goose-kmipd --cert server.pem --key server.key --ca ca.pem [--port 5696] [--tls12] [--http [--path /kmip]]
```

`goose-kmipd` takes clients whose certificates its CA issued, over TLS
1.3 or 1.2 (KMIP's suites included), in TTLV or, with `--http`, in
KMIP's HTTPS binding.

## Tests

```bash
make test-kmip                                    # or: cd kmip && python3 scripts/run_tests.py
make interop-kmip                                 # Linux with Docker
python3 scripts/oasis.py                          # OASIS's test cases (fetched, not kept here)
```

Every test runs at -O0, -O2 and with `--debug`:

- `test/ttlv.goose`: the encodings of KMIP 1.2's §9.1.2, each type and
  a Structure, written and read back; negative numbers and Big Integers'
  sign; what the decoder refuses; the names; retagging: 60 checks.
- `test/corpus.goose`: the 245 TTLV encodings in PyKMIP's unit tests
  (`test/vectors/pykmip.txt`, from `scripts/gen_vectors.py`), each
  decoded and written again byte for byte; the six PyKMIP made malformed
  on purpose are refused.
- `test/encodings.goose`: each type's forms in XML and JSON, read and
  written, what is refused, and PyKMIP's 239 well-formed encodings
  written as XML and as JSON and read back to the same bytes: 70 checks.
- `test/local.goose`: `test/scenario.goose`'s checks (every basic
  operation, AES-CBC and GCM and HMAC checked against gslib's own)
  against the in-memory server, in KMIP 1.0 to 2.1 and negotiated: 266
  checks.
- `test/server.goose`: the server's rules: owners, the life cycle,
  attributes in 1.x, key formats, AES-CTR and ECB, ECDSA and RSA-PSS,
  Locate's limits, operations of later versions refused, batches, requests
  it cannot read: 51 checks.
- `test/ops.goose`: key formats both ways; wrapped keys (RFC 3394's
  vector registered wrapped; NIST Key Wrap, AES Key Wrap with Padding,
  RSA-OAEP and HMAC wrapping in both encodings, unwrapped by the client);
  Sensitive and Extractable; Export and Import; Re-key and Re-key Key
  Pair; Derive Key against published answers (the OASIS cases' HASH,
  HMAC and PBKDF2, RFC 6070, RFC 5869, SP 800-108 as Python computes it,
  ECDH on P-256 and secp256k1); Check, usage limits, leases, Archive and
  Recover, Adjust Attribute; MAC Verify, CMAC (SP 800-38B), Hash; RSA-OAEP
  with SHA-384 and MGF1 over SHA-256; ChaCha20 and ChaCha20-Poly1305
  (RFC 8439); Triple DES; operations in parts; a batch undone; the ID
  Placeholder; in 2.0 and 1.4: 147 checks.
- `test/pki.goose`: Certify, Re-certify, Validate, Create and Join
  Split Key in 1.0 to 2.0: 201 checks.
- `test/session.goose`: asynchronous items, tickets, users, the 2.x
  operations, the Query functions, Rotate, Notify and Put: 74 checks.

**OASIS's test cases.** OASIS publishes test cases for KMIP 1.4, 2.0
and 2.1: the Profiles' mandatory and optional ones and the Test Cases
notes', 541 files of requests each followed by the response a server
gives, in KMIP's XML. They are OASIS's ("All Rights Reserved"), so
`scripts/fetch_oasis.py` fetches them (each zip checked against its
SHA-256) into `test/oasis-cache` (ignored by git), and
`scripts/oasis.py` runs `test/oasis.goose` over them:

- `--roundtrip`: every message of every file read from XML into TTLV,
  written as XML and as JSON, and read back to the same bytes: 540 of
  the 541 (TC-ECDSA-SIGN-1-14 has an end tag too many and is not XML).
- `--replay`: each file's requests played against the in-memory server,
  placeholders bound from its answers, and its responses compared with
  the file's. What no two servers answer alike is not compared as a
  value: a response's Time Stamp, the dates the server records, Query's
  and RNG Retrieve's answers, the Random Number Generator attribute, the
  key material and Digest of what the server made, and what it encrypts,
  signs or MACs with a key it made (the file's value is bound to the
  server's and sent on in its place); output under an asymmetric key is
  decrypted or verified instead. Attribute lists may come in any order;
  a Result Message, Located Items, a Server Correlation Value and an
  Attribute Index of 0 may be on one side only.

438 of the 541 pass: 58 of 68 of 1.4's mandatory profile cases, 75 of
86 of 2.0's, 76 of 86 of 2.1's, 3, 4 and 4 of 7 optional ones, and 88 of
110, 49 of 60 and 81 of 110 of the 1.4, 2.0 and 2.1 Test Cases. The
others, by what they need:

- **A server set up otherwise** (12): objects that are there before the
  case starts (TL-M-3, SASED-M-3, TC-OTP, TC-CREG), or a policy other
  than this server's (RNG Seed taken, CS-RNG-O-1 and -2, or refused,
  -O-4; this server takes it and uses none of it, -O-3, as KMIP allows).
- **OASIS's files** (4 and more): one is not XML, one answers a 1.4
  request in 1.3, CS-AC-M-6 checks a `$MAC_DATA` no answer gives, and
  the Locate of TC-OFFSET and BL-M-4 expects objects of the run they
  were recorded on.
- **What this server does otherwise**: Certify refuses a request signed
  with SHA-1 (TC-REKEY-9 to 12; as Go does); PGP keys (TC-PGP), PKCS #12
  (TC-PKCS12), the Re-encrypt flows of 2.1 (TC-REENCRYPT), streaming GCM
  giving data before the Final part (CS-BC-M-GCM-3), the server-to-client
  Put received by the server (TC-NP), and a few Delegated Login rights
  (TC-DLOGIN) and certificate attributes (TC-CERTATTR, TC-ECC-3, BL-M-10).

`python3 scripts/oasis.py --replay -v` prints every file's first
difference.

**Live interop.** `scripts/interop.py` (`make interop-kmip`) runs in
Docker on loopback, against PyKMIP built from its master
(`scripts/interop/pykmip.Dockerfile`; the 0.10.0 release cannot load
public keys for Signature Verify under the cryptography it installs
with): gslib's client (`test/interop_client.goose`, the scenario)
against PyKMIP's server in KMIP 1.0 to 2.0 and negotiated; `goose-kmipd`
against gslib's client in the same versions and against PyKMIP's own
client (`scripts/interop/pykmip_client.py`) in 1.2, 1.4 and 2.0, its AES
and HMAC checked with Python's cryptography; and `goose-kmipd --http`
against `test/interop_https.goose` in TTLV, XML and JSON, and against
curl posting XML and JSON (`--local` runs this part without Docker).
PyKMIP's client names every object it registers "Symmetric Key",
"Secret Data" and the like unless told otherwise; a Name belongs to one
object (KMIP 2.1 §4.38), so give each object PyKMIP registers here a
name of its own.

**Fuzzing.** `fuzz/targets/kmip.goose` fuzzes the decoder and
everything that reads a decoded message, the server's `handle` from the
owner of keys of every kind (seeded with requests of every operation),
and the attribute list; `fuzz/targets/kmip_text.goose` the XML and JSON
readers, whose output must come back the same through both writers.

`scripts/gen_tables.py` makes `tables.goose` from KMIP 2.1's and 1.4's
specifications and PyKMIP's `kmip/core/enums.py` (parsed, not run).

## Not done

- Set Endpoint Role to Client (the server turning round on a connection
  to send requests), PKCS#11 functions past C_Initialize, C_GetInfo and
  C_Finalize, Attestation credentials, and Re-Provision invalidating the
  client's old certificate.
- PGP keys, PKCS #12 containers, Certificate Request objects kept as
  such, and Templates (deprecated in 1.3) are not kept; DSA, DH and ECMQV
  keys are converted between formats but not made.
- Streaming GCM, CCM, CTR, CFB and OFB give their data at the Final part
  (ECB and CBC give whole blocks as they come); streams buffer at most 64
  KiB, four at a time.
- Certify does not take requests signed with SHA-1, and Derive Key's
  PBKDF2 at most 200000 rounds in all (iterations times blocks of
  output, so that no request holds the server for long).
- KMIP's HTTPS binding is one request at a time on a connection (no
  pipelining), and the client does not reconnect when the server closes.
- The server keeps nothing on disk; it is not for production keys.
