# saml

SAML 2.0 for Goose, both sides of Web Browser SSO and Single Logout: a
service provider that sends AuthnRequests and checks the Responses that
come back, and an identity provider that answers AuthnRequests with
signed, optionally encrypted assertions; the HTTP-Redirect and HTTP-POST
bindings; metadata read, verified and written. Five modules in namespace
`saml`, and a tool, `goose-saml`.

XML, signatures and encryption are gslib's `xml` (`encoding/xml`): no
DTDs, every limit an error, signatures verified against wrapping and
returning the nodes they cover. Keys and certificates are `x509`'s; the
Redirect binding's DEFLATE is `compress`'s; the query and form encodings
are `net/http`'s.

| Module | What |
|---|---|
| `saml.goose` | names and errors; xs:dateTime; IDs; the bindings: `read_redirect`, `read_post`, `read_xml` into a `Received`, `verify_redirect`, `redirect_query`/`redirect_url`, `post_form`, `post_body`; `Signer`, `sign_element`, `Outgoing`, `peek_issuer` |
| `saml/metadata.goose` | `Entity` (EntityDescriptor: IDPSSODescriptor and SPSSODescriptor, KeyDescriptors by use, SSO, ACS and SLO endpoints with their bindings, NameIDFormat, EncryptionMethod, the signing flags); `parse_metadata`, `parse_metadata_signed`, `write_metadata`, `write_metadata_signed`; endpoint lookup |
| `saml/sp.goose` | `Sp`; `authn_request` (Redirect or POST, signed when asked); `process_response` and `process_response_replay`, into an `Assertion`; the SP's logout; `sp_metadata` |
| `saml/idp.goose` | `Idp`; `idp_read_authn_request`; `idp_response` (assertion signed, Response signed, both; encrypted), `idp_unsolicited_response`, `idp_error_response`; a `Login` says what to assert; the IdP's logout; `idp_metadata` |
| `saml/logout.goose` | what both share: `check_message` (version, ID, IssueInstant, Issuer, Destination, signature by either binding), the `Message` read; `LogoutRequest` and `LogoutResponse` made and read |

### What a service provider checks

`process_response(sp, idp, m, request_id, a)`, in this order:

- the Response came by POST (saml-profiles §4.1.2 rules the Redirect
  binding out), at most `max_message` bytes (1 MiB), no DOCTYPE, IDs
  unique in the document; it is a samlp:Response;
- **the Response's signature**, when it has one, verified with the IdP's
  signing certificates from its metadata (never KeyInfo's); from there on
  the Response is the node the signature covers, `v.refs[0]`;
- Version 2.0, an ID, an IssueInstant not ahead of the clock; Issuer (if
  any) the IdP's entityID; Destination (if any) our ACS URL, and there
  must be one on a signed Response (saml-bindings §3.5.5.2); InResponseTo
  the ID of the request the caller kept, or absent, which is an
  IdP-initiated Response and needs `allow_idp_initiated`;
- StatusCode Success, else `ERR_STATUS` with the top and second-level
  codes and the StatusMessage in the Assertion;
- **exactly one Assertion or EncryptedAssertion, a direct child of the
  Response**. Nothing else in the document is looked at: an assertion in
  Extensions, under Status, inside another assertion, in a ds:Object or in
  Advice is never read;
- an EncryptedAssertion decrypted in place with our key (the wrapper must
  hold one EncryptedData and nothing else but EncryptedKeys);
  `require_encrypted` refuses a plain one;
- **the assertion's own signature**, when it has one, and the assertion
  read from the node it covers; the Response or the assertion must be
  signed (`ERR_NOT_SIGNED`), `want_assertions_signed` and
  `want_response_signed` ask for each. An assertion that came encrypted
  inside a signed Response counts as covered: it was ciphertext under the
  signature;
- the assertion's Version, ID, IssueInstant, and its Issuer, the IdP's;
- Subject: one NameID (an EncryptedID decrypted; a BaseID refused) with
  no elements in it, read as **its whole text**: a comment cannot cut it
  short (the 2018 bug: `alice@example.test<!---->.evil.test` is
  `alice@example.test.evil.test`, as signed); a bearer
  SubjectConfirmation whose SubjectConfirmationData has Recipient our ACS
  URL, NotOnOrAfter not passed, NotBefore (if any) not ahead, and
  InResponseTo the request's (absent for an IdP-initiated one). Any one
  of several confirmations may hold;
- Conditions: NotBefore and NotOnOrAfter with `clock_skew` (120 s); at
  least one AudienceRestriction, each naming our entityID; OneTimeUse at
  most once (reported in `a.one_time_use`, for the caller); ProxyRestriction
  let through; any other condition refused (saml-core §2.5.1);
- an AuthnStatement, its SessionNotOnOrAfter not passed;
- the attributes, every value of each (EncryptedAttributes decrypted);
- replay: the assertion's ID and the time until which it could still be
  taken (`a.replay_until`, the earliest NotOnOrAfter plus the skew) are
  returned; `process_response_replay` hands them to the caller's block,
  which says whether the ID is new (and remembers it): `ERR_REPLAY` when
  not. Goose has no stored function values, so the cache is the
  caller's, in the block.

Each refusal is its own code (`ERR_SIGNATURE`, `ERR_NOT_SIGNED`,
`ERR_ALGORITHM`, `ERR_DESTINATION`, `ERR_ISSUER`, `ERR_STATUS`,
`ERR_IN_RESPONSE_TO`, `ERR_ASSERTION`, `ERR_DECRYPT`, `ERR_SUBJECT`,
`ERR_CONFIRMATION`, `ERR_RECIPIENT`, `ERR_EXPIRED`, `ERR_NOT_YET_VALID`,
`ERR_AUDIENCE`, `ERR_CONDITION`, `ERR_SESSION`, `ERR_REPLAY`,
`ERR_UNSOLICITED`, `ERR_NOT_ENCRYPTED`, `ERR_TIME`, ...; `error_text`
says each) with a message in `a.message` saying which check.

Algorithms are xml's: RSA PKCS #1 v1.5 and PSS, ECDSA, Ed25519 with
SHA-256/384/512; SHA-1 (signatures and digests, and the Redirect
binding's SigAlg) only with `allow_sha1`; RSA keys under 2048 bits
refused; AES-GCM content, AES-CBC only with `allow_cbc` (no integrity:
take it only from IdPs that send nothing else, and only signed), RSA-OAEP
key transport, RSA 1.5 only with `allow_rsa15`, ECDH-ES.

### The bindings

The Redirect binding's signature is checked over the parameters **as they
came**: `read_redirect` takes the raw query string (percent-encoding and
all), finds SAMLRequest or SAMLResponse, RelayState and SigAlg wherever
they are, and rebuilds the signed bytes from their raw values in the
binding's order (saml-bindings §3.4.4.1). A sender that encodes otherwise
(ADFS's lowercase hex) verifies; a value changed or dropped does not.
Each parameter at most once; the inflated message at most `max` bytes
(a DEFLATE bomb is `ERR_LIMIT`, nothing kept); RelayState at most 4096
bytes (the spec says 80; peers send more). ECDSA query signatures are
XML Signature's r || s, and DER is taken too. What we sign we escape as
Go's QueryEscape and Python's quote_plus do.

The POST binding's base64 may have line breaks; the form `post_form`
makes has its action and RelayState HTML-escaped and submits itself.

### Metadata

`parse_metadata(e, text, entity_id)` reads an EntityDescriptor, or picks
one by entityID out of an EntitiesDescriptor (the only one when none is
named). `parse_metadata_signed(e, text, entity_id, cert, now)` first
verifies the root's enveloped signature with a certificate the caller
trusts (a federation's, or one pinned for the peer) and reads only from
what it covers; validUntil, the root's or the entity's, must be ahead. A
KeyDescriptor without `use` is both; each X509Certificate is kept (DER),
so a key rollover works: every signing certificate is tried. Endpoints
of bindings this package does not speak are kept, marked `BINDING_OTHER`.
An entityID over 1024 bytes, a Location over 2048, a Binding over 256 are
`ERR_LIMIT`, never cut.

## Using it

```goose
import gslib from "SorinS/gslib@v0.1";
import gslib.saml;
import gslib.saml.metadata;
import gslib.saml.logout;
import gslib.saml.sp;

var sp = saml::Sp { .. };                        // a root struct: a local
sp.entity_id.append("https://app.example.test/saml/metadata");
sp.acs_url.append("https://app.example.test/saml/acs");
sp.slo_url.append("https://app.example.test/saml/slo");
saml::sp_set_key(sp, key, cert_der);             // signs requests; decrypts assertions
var idp = saml::Entity { .. };
let e = saml::parse_metadata_signed(idp, idp_metadata_xml, "", federation_cert, saml::now_or(0));

// /login: an AuthnRequest; keep o.id (in the user's session) until the Response.
var o = saml::Outgoing { .. };
saml::authn_request(sp, idp, saml::BINDING_REDIRECT, "/inbox", o);   // redirect the browser to o.url

// /acs: the form the IdP's page posted.
var m = saml::Received { .. };
saml::read_post(m, form_body, sp.max_message);
var a = saml::Assertion { .. };
let r = saml::process_response_replay(sp, idp, m, kept_request_id, a) { id, until =>
    replay_cache_add(id, until)                  // true if it was not there
};
if r != saml::OK { print(saml::error_text(r), ": ", a.message); return; }
print(a.name_id, " ", a.session_index);
let mail, has = saml::attribute(a, "urn:oid:0.9.2342.19200300.100.1.3");
saml::each_value(a, "groups") { v => print("group ", v); };
```

The identity provider's side:

```goose
import gslib.saml.idp;

var ip = saml::Idp { .. };
ip.entity_id.append("https://idp.example.test/metadata");
ip.sso_url.append("https://idp.example.test/sso");
saml::idp_set_key(ip, key, cert_der);
ip.sign_response = true;                         // and sign_assertion (the default)
ip.encrypt = true;                               // to the SP's encryption certificate

var m = saml::Received { .. };
saml::read_redirect(m, raw_query, ip.max_message);         // or read_post
var who: u8[>..] = [];
saml::peek_issuer(m, who);                       // find that SP's metadata, then:
var req = saml::Message { .. };
if saml::idp_read_authn_request(ip, sp_meta, m, req) != saml::OK { /* refuse */ }
// ... authenticate the user ...
var user = saml::Login { .. };
user.name_id.append("alice@example.test");
saml::add_value(user, "groups", "staff");
saml::add_value(user, "groups", "admins");
var out = saml::Outgoing { .. };
saml::idp_response(ip, sp_meta, req, user, out); // serve out.form
```

Logout either way: `sp_logout_request` / `idp_logout_request` (whom:
a `LogoutSubject`, `logout_subject_of(a)` from an assertion),
`sp_read_logout_request` / `idp_read_logout_request`,
`sp_logout_response` / `idp_logout_response`, `sp_read_logout_response`
/ `idp_read_logout_response` (for the request ID kept). Logout messages
are signed when the sender has a key, and must be signed to be taken
(saml-profiles §4.4.4.1 and §4.4.4.2), by either binding.

Nothing is kept in part: the structs the caller reads are root structs
of growable fields, and what has a fixed size (an endpoint's Location, a
`LogoutSubject`'s NameID, an attribute's NameFormat and FriendlyName, 256
bytes each) refuses what does not fit. Lists of strings that the Goose
compiler only lets be iterated (`u8[][>..]`) are read by `each_value`,
`each_attribute`, `each_signing`.

## goose-saml

```
goose-saml metadata sp|idp --base URL [--entity-id ID] [--cert FILE --key FILE] [--sign]
goose-saml sp   --base URL --idp-metadata FILE --cert FILE --key FILE [options] [--listen ADDR] --port N
goose-saml idp  --base URL --sp-metadata FILE [--sp-metadata FILE ...] --cert FILE --key FILE
                [--user NAME] [--attr NAME=VALUE ...] [options] [--listen ADDR] --port N
goose-saml verify --base URL --idp-metadata FILE --in FILE|- [--request-id ID] [--now TIME] [--key FILE --cert FILE]
```

`--base` is the server's own URL: its entityID is BASE/metadata unless
`--entity-id` says otherwise, and its endpoints BASE/acs and BASE/slo (an
SP's) or BASE/sso and BASE/slo (an IdP's). An SP's options:
`--binding redirect|post`, `--sign-requests`, `--want-assertions-signed`,
`--want-response-signed`, `--require-encrypted`, `--allow-idp-initiated`,
`--allow-sha1`, `--allow-cbc`, `--enc-key FILE --enc-cert FILE`, `--skew
S`; an IdP's: `--sign assertion|response|both`, `--encrypt`,
`--want-signed-requests`; both: `--metadata-cert FILE` (the peer's
metadata is signed; verify it with this).

`sp` serves GET /metadata, GET /login (an AuthnRequest, its ID kept), POST
/acs (the Response checked, a replayed assertion refused; on success the
verified assertion is printed on stdout as one line of JSON), GET
/logout (a LogoutRequest for the last user) and GET and POST /slo.
`idp` is a test IdP: it serves GET /metadata, GET and POST /sso (the
AuthnRequest checked and answered at once for `--user` with its `--attr`
values: no password is asked), GET /init?sp=ENTITYID (an IdP-initiated
Response), GET /logout?sp=ENTITYID[&binding=post] and GET and POST /slo.
Both print each SAML event as a JSON line on stdout and log requests to
stderr; nothing secret is printed. `verify` checks a Response from a file
(XML or the form body) and prints the assertion.

```bash
goose-saml metadata sp --base http://127.0.0.1:8001 --cert sp.crt --key sp.key > sp.xml
goose-saml metadata idp --base http://127.0.0.1:8002 --cert idp.crt --key idp.key > idp.xml
goose-saml idp --base http://127.0.0.1:8002 --port 8002 --cert idp.crt --key idp.key --sp-metadata sp.xml --encrypt &
goose-saml sp --base http://127.0.0.1:8001 --port 8001 --cert sp.crt --key sp.key --idp-metadata idp.xml
# open http://127.0.0.1:8001/login
```

`make build` puts it in `../bin` with the other tools.

## Examples

In gslib's `examples/saml/`, run from gslib's top as `goose examples/saml/<name>.goose`:

- `offline.goose`: a login from end to end in one program: an SP and an
  IdP with fresh P-256 keys exchange metadata (the IdP's signed and
  verified); the SP's AuthnRequest by Redirect, read by the IdP, answered
  with an assertion signed and encrypted (ECDH-ES); the SP checks it and
  prints the user and attributes; the same Response refused as a replay,
  and a forged assertion wrapped around the signed one refused. No network.
- `sp_server.goose`: the smallest useful SP, on 127.0.0.1:8001: /login
  and /acs, a replay cache in a block. Needs an IdP, so `make test` only
  type-checks it (it was run against `goose-saml idp`).

## Tests

`make test-saml` (`python3 saml/scripts/run_tests.py`) runs each
`saml/test/*.goose` at -O0, -O2 and with `--debug`, and the examples.
Nothing outside gslib is needed: the keys and self-signed certificates
(for the tests only) and two Responses signed by libxmlsec1 are in
`test/data`, made by `scripts/make_keys.py` and `scripts/make_vectors.py`.
The tests run at a fixed time (2026-01-01), set in `Sp.now` and `Idp.now`.

- `sp.goose` (162 checks): Responses with the assertion signed, the
  Response signed, both; encrypted with RSA-OAEP and with ECDH-ES (a
  separate decryption key), and to another key (refused); an
  EncryptedID; attributes, multi-valued, by Name and FriendlyName, a
  comment inside a value; IdP-initiated with and without the opt-in; and
  the hostile ones: **the eight wrapping attacks of "On Breaking SAML"**
  (XSW1 with the signed Response inside its Signature, and inside a
  ds:Object of it; XSW2 beside it; XSW3 an evil assertion before the
  signed one; XSW4 the signed one inside the evil one; XSW5 the signature
  moved to an evil copy, the original beside it or in Extensions; XSW6 the
  original inside that signature; XSW7 the original in Extensions, an
  evil one unsigned; XSW8 the original in a ds:Object), evil copies with
  the same ID (the parser refuses them), an assertion added to a signed
  Response, an unsigned assertion beside a signed one, the signed one
  hidden under Status, an assertion in Advice (never read), two
  signatures; **a comment in the NameID** (the signature holds, the NameID
  is its whole text), an element in it, the text changed after signing;
  expired and not yet valid (Conditions, the bearer confirmation, at the
  skew's edges), SessionNotOnOrAfter passed, IssueInstant ahead, times
  that are not times (February 30th); another audience, a second
  AudienceRestriction without us, none; OneTimeUse once and twice, an
  unknown condition; another Recipient, Destination, Issuer, Issuer
  Format; a signed Response without Destination; a Responder status;
  Version 1.1; no AuthnStatement; holder-of-key only, and a good
  confirmation after a bad one; InResponseTo another request, absent on
  the confirmation, a solicited Response taken as unsolicited;
  **replay**; a Response by the Redirect binding; signed by a key that is
  not the IdP's (a certificate with its name), the second of two
  certificates (a rollover), no certificate; unsigned; signed with P-256
  and Ed25519 keys; RSA 1024; **xmlsec's RSA-SHA1 signature refused** and
  then taken with `allow_sha1`, its RSA-SHA256 one taken; **a DOCTYPE**
  with an entity and an external DTD; over `max_message`, a POST over the
  limit, 1000 elements deep; not XML, not a Response, a SAMLRequest.
- `bindings.goose` (119): xs:dateTime (fractions, offsets, no zone, leap
  days, eleven that are not times), formatting; IDs; the Redirect binding
  unsigned and signed (RSA, and ECDSA as r || s and as DER), its parameters reordered and
  mixed with others, RelayState changed or dropped, the message or SigAlg
  changed, another certificate, a lowercase percent-encoding (verified,
  as received), RSA-SHA1 refused and allowed; duplicate and missing
  parameters, SigAlg without Signature and the reverse, bad base64 and
  percent-encoding, plain base64 that is not DEFLATE, **a DEFLATE bomb**
  (16 MiB of `<` in under 100 KB), RelayState over the limit; escaping as
  quote_plus; a URL with a query; the POST binding with line breaks in
  the base64, duplicates, the limit, the form escaped; metadata of both
  roles written and read back, the IdP's signed and verified, another
  certificate, a changed endpoint, unsigned when it must be, a signed
  entity in an unsigned aggregate with an evil entity beside it,
  aggregates by entityID, validUntil ahead and passed; malformed:
  an ACS without index, no ACS, a bad KeyDescriptor use, a certificate
  that is not one, a Location over 2048 bytes, SAML 1.1 only, a DOCTYPE;
  several ACS (the default, by index, another binding kept), a
  KeyDescriptor without use.
- `idp.goose` (106): AuthnRequests by both bindings, signed and not,
  their fields (ForceAuthn, NameIDPolicy, RequestedAuthnContext,
  RelayState), peek_issuer; unsigned when the IdP or the SP's metadata
  wants them signed; signed by another key, by Redirect and by POST;
  RelayState changed in a signed query; an ACS URL or index not in the
  metadata, the Artifact binding, index 0, the default ACS; another
  Destination, Issuer, IssueInstant ahead, Version 1.0, a SAMLResponse;
  the IdP's answer taken by the SP with its RelayState, an error Response
  read as ERR_STATUS with its codes and message, RSA-SHA512, no key, no
  NameID, encryption without the SP's certificate; Single Logout from the
  SP and from the IdP over each binding, a LogoutResponse for another
  request, a failure status; unsigned and expired LogoutRequests, one to
  another endpoint, a LogoutSubject from an assertion (a NameID too long
  refused, not cut), no SLO endpoint.

`make test-saml` passes at -O0, -O2 and `--debug`. `SAML_VERBOSE=1`
prints every check's code and reason.

### Against other implementations

`make interop-saml` (`saml/scripts/interop.py`, 107 checks), all on
127.0.0.1, run by a Python with `requests`, `python3-saml` (OneLogin's
toolkit) and `lxml` in a venv (python-xmlsec's wheel carries libxmlsec1;
nothing system-wide), and Go for crewjam/saml, built from
`saml/scripts/crewjam` (go.mod pins crewjam/saml v0.6.3) into the work
directory:

```bash
python3 -m venv /tmp/samlvenv && /tmp/samlvenv/bin/pip install python3-saml lxml requests cryptography
SAML_PYTHON=/tmp/samlvenv/bin/python make interop-saml
```

The Go modules go to a GOPATH in the work directory (a temporary one
unless `--work DIR`), fetched again each run; `SAML_GOPATH=DIR` keeps
them in one place between runs. Logs of every server are kept in the
work directory.

- goose-saml's SP and IdP over HTTP (26): logins by Redirect and POST,
  requests signed and not, the assertion signed, the Response, both,
  encrypted; SP- and IdP-initiated logout over both bindings;
  IdP-initiated logins; a Response posted twice (the second refused) and
  one with its NameID changed.
- python3-saml 1.16 (python-xmlsec 1.3.18) as an SP against goose-saml's IdP (26): its
  AuthnRequests unsigned and signed (RSA-SHA256 over the query) answered,
  its strict Response checks passed with the assertion signed, both
  signed, and encrypted (it decrypts our AES-256-GCM, RSA-OAEP);
  NameID, attributes, RelayState; its signed LogoutRequests read and
  answered, ours taken by it, its signed LogoutResponses taken, its
  unsigned ones refused.
- Responses built by the script and signed by python3-saml's `add_sign`
  and libxmlsec1 (the assertion, the Response, both; encrypted with
  AES-256-GCM and RSA-OAEP) taken by goose-saml's SP; signed with
  RSA-SHA1, tampered after signing, or unsigned, refused; AES-128-CBC
  refused, then taken with `--allow-cbc`; python3-saml's signed
  LogoutRequest (playing the IdP) read, our signed LogoutResponse taken
  by it, the same query with RelayState changed refused (12).
- crewjam/saml's SP (samlsp) against goose-saml's IdP (19): logins by
  Redirect (unsigned and signed requests) and by POST (signed), the
  assertion and the Response signed, encrypted; crewjam's attributes;
  crewjam's signed LogoutRequest read and our LogoutResponse taken (its
  session over), our LogoutRequest taken and its LogoutResponse read.
- crewjam/saml's IdP (samlidp) against goose-saml's SP (24): our metadata
  registered with it, its login form filled in, logins by Redirect and
  POST, signed requests, its assertions encrypted (AES-256-GCM, which it
  picks from our metadata's EncryptionMethods) and plain, signed
  Response and assertion; NameID, a multi-valued attribute, RelayState;
  our LogoutRequest taken and its LogoutResponse read, its LogoutRequest
  read.

What the others do that a peer must allow for:

- python3-saml signs no logout message by default (`logoutRequestSigned`
  and `logoutResponseSigned` are off); saml-profiles §4.4.4 wants them
  signed, and goose-saml refuses them unsigned (the interop checks the
  refusal). Its SLO speaks only the Redirect binding, and its
  AuthnRequests only Redirect.
- crewjam/saml's SP signs its logout messages only with `SignRequest`
  set; without it they are refused here likewise. After a logout it
  sends the browser to its default URI, `/`.
- crewjam/saml's IdP login form posts the SAMLRequest back to its /sso
  without the Redirect binding's query signature (its template,
  samlidp/session.go, has hidden inputs for SAMLRequest and RelayState
  only, no SigAlg or Signature), so a signed Redirect
  AuthnRequest fails there (400) unless the user is already logged in at
  the IdP; signed requests by POST carry their signature in the XML and
  work. It encrypts assertions whenever the SP's metadata has an
  encryption key, with AES-256-GCM if the SP lists it among its
  EncryptionMethods (we do) and AES-128-CBC otherwise: an SP that does
  not publish GCM gets CBC, which goose-saml takes only with
  `--allow-cbc`. It signs both the Response and the assertion.
- python3-saml re-encodes a Redirect query from its decoded parameters
  before checking its signature (unless `validate_signature_from_qs`, or
  `lowercase_urlencoding` for ADFS), so a query signed with another
  percent-encoding fails there; crewjam/saml v0.6.3 and goose-saml verify
  the bytes as they came.

## Not done

- The Artifact binding and SOAP (back-channel SLO, ArtifactResolve,
  AttributeQuery); the HTTP-POST-SimpleSign binding; ECP.
- BaseID; NameID mapping and management (ManageNameIDRequest).
- Decrypting with more than one key (a rollover of the SP's encryption
  key: one `enc_key` and the signing key only).
- Metadata: Organization, ContactPerson, Extensions (mdui, mdattr, shibmd
  scopes), AttributeConsumingService, RequestedAttribute; metadata
  aggregates as a whole (one entity is read at a time); fetching
  metadata over HTTP (read it with net/http and hand it over).
- AttributeValues are read as their text content (a complex value, an
  element inside, is flattened) and written as plain text (no
  xsi:type); EncryptedID and EncryptedAttribute are decrypted but never
  made; only the first AuthnStatement is read; the SP does not compare
  the AuthnContext it gets with one it asked for, nor the AuthnInstant's
  age (ForceAuthn is the IdP's to honour); the SP publishes one ACS.
- Logout propagation to other session participants (the IdP answers for
  itself); the tool keeps one session per SP and one user per IdP.
- `goose-saml idp` asks for no password: it is a test IdP.
- Keycloak and SimpleSAMLphp (no container runtime), Shibboleth and ADFS:
  not run.
