# tsp

The Time-Stamp Protocol (RFC 3161, with RFC 5816's ESSCertIDv2) for
Goose: asking a time-stamping authority (TSA) to sign the hash of some
data with the time, checking the token it answers with, and being a TSA.
One module, `tsp.goose` at gslib's top (namespace `tsp`), and a tool,
`goose-ts`, that does what `openssl ts` does (queries, replies, verifying)
and serves a TSA over HTTP.

Tokens are CMS SignedData made and read by gslib's `x509` (`cms_sign_with`,
`cms_parse_signed`, `cms_verify_with_certs`); the TSA's certificate is
checked by x509's path building; requests go over gslib's HTTP client
(`net/http`), and `goose-ts serve` answers with its HTTP/1.1 server
connection (`net/http/conn1`).

| What | Functions |
|---|---|
| requests | `new_request` (data hashed by SHA-256, -384 or -512, SHA-1 only when allowed; a 64-bit nonce; certReq), `request_for_digest`, `request_der`, `parse_request` |
| replies | `parse_response` (PKIStatusInfo: status, statusString, failInfo; a granted reply must have a token and a refusal must not), `error_response`, `fail_info_text`, `status_name` |
| tokens | `parse_token` (the SignedData and its TSTInfo), `parse_tst_info` (policy, imprint, serial, genTime with its fraction, accuracy, ordering, nonce, TSA name), `info_text` |
| checking | `verify_reply` (status, nonce, policy, certReq, then as `verify_token`), `verify_token` (imprint, signature, signingCertificate or signingCertificateV2, the TSA's certificate, its path to the roots at genTime, TSA name, policy, the clock) |
| over HTTP | `post` (application/timestamp-query, application/timestamp-reply back; replies past `max_body`, 1 MiB by default, refused rather than cut short) |
| a TSA | `Tsa`, `tsa_init`, `tsa_add_policy`, `respond` (a request's DER to a reply's DER) |
| CMS signatures | `signature_request`, `add_signature_token`, `signature_token`, `verify_signature_token` (RFC 3161 Appendix A) |

A token is checked as RFC 3161 §2.4.2 has it: its content type is
id-ct-TSTInfo, the CMS signature and signed attributes verify, the signer's
certificate (sent in the token, or given by the caller) is the one named
by the first ESSCertID of signingCertificateV2 (any of SHA-256, -384,
-512, SHA-256 when the hash is left out as DER leaves it; SHA-1 only with
`allow_sha1`) or of
signingCertificate (SHA-1, which RFC 2634 fixed; it identifies, it does
not sign), with its issuer and serial number when they are there; that
certificate has the extended key usage extension, critical, with
id-kp-timeStamping and nothing else (§2.3), and a path to the roots
(intermediates from the token and the caller) valid at genTime, with
timeStamping allowed all the way up; a TSA name in the token is the
certificate's subject (or one of its subjectAltName entries). Against a
request: the same hash and digest, the same nonce, the policy asked for,
and the TSA's certificate in the token if certReq asked for it. With
`VerifyOptions.now`, genTime must also be within `max_skew` (300 s) of the
clock, plus the token's accuracy. Every failure has its error (`ERR_NONCE`,
`ERR_IMPRINT`, `ERR_TSA_CERT`, `ERR_SIGNER`, `ERR_CHAIN`, ...), and for
`ERR_SIGNATURE` and `ERR_CHAIN` the x509 error behind it.

## Using it

```goose
import gslib from "SorinS/gslib@v0.9.4";
import gslib.tsp;
import gslib.net.http.client;
import gslib.crypto.x509;
import gslib.crypto.x509.pool;

let req, err = tsp::new_request(tsp::SHA256, data);       // a nonce, certReq true
let query, qerr = tsp::request_der(req);
var hc = http::Client { .. };
let reply, herr, status = tsp::post(hc, "http://tsa.example.org/", query);
let r, perr = tsp::parse_response(reply);
if r.status != tsp::GRANTED { print(tsp::status_name(r.status), " ", tsp::fail_info_text(r.fail_info), " ", r.status_text); }

var roots = x509::new_pool();
x509::pool_append_pem(roots, roots_pem);                  // the TSA's roots
let o = tsp::VerifyOptions { .. };
let info, verr, why = tsp::verify_reply(r, req, roots, "", o);
// info.gen_time (seconds since 1970), info.gen_frac, info.serial, info.policy, ...
// keep r.token: verify_token checks it again later against the data
```

A TSA:

```goose
var t = tsp::Tsa { .. };                                  // a root struct: a local
tsp::tsa_init(t, tsa_cert_der, tsa_key, chain_der, "1.3.6.1.4.1.99999.1");
t.acc_seconds = 1;                                        // accuracy; -1 parts are left out
t.precision = 3;                                          // genTime's fraction digits
t.tsa_name = true;                                        // its subject in the token
let reply, status = tsp::respond(t, request_der, tsp::now_ns());
```

`tsa_init` refuses a certificate that is not a TSA's (the critical
extended key usage of timeStamping alone) and a key that is not the
certificate's. The token is signed with the key's default algorithm
(ECDSA with the curve's hash, RSA PKCS #1 v1.5 with SHA-256, Ed25519, ...)
with contentType, messageDigest and signingCertificateV2 (ESSCertIDv2:
SHA-256 of the certificate, its issuer and serial number) as signed
attributes; the TSA's certificate and `chain` go in only when the request
asked (certReq). Serial numbers are random 128-bit ones, or counted from
`t.next_serial` when it is above 0. A request is refused, with the failInfo
saying why, when it does not parse (badDataFormat), its hash is not taken
(badAlg: anything but SHA-256, -384 and -512, unless `allow_sha1`), it asks
for a policy not taken (unacceptedPolicy: neither `policy` nor one added by
`tsa_add_policy`), it has extensions (unacceptedExtension), or signing fails
(systemFailure).

A CMS signature time-stamped, so that it can be trusted after its
certificate expires (RFC 3161 Appendix A):

```goose
let req, err = tsp::signature_request(cms_der, tsp::SHA256);   // over the signature value
// ... the token from a TSA, as above ...
let stamped, aerr = tsp::add_signature_token(cms_der, r.token);
let info, verr, why = tsp::verify_signature_token(stamped, roots, "", o);
```

The token goes into the SignerInfo's unsigned attributes as
id-aa-signatureTimeStampToken (1.2.840.113549.1.9.16.2.14), beside any
already there; the signature itself is not touched and still verifies
(`x509::cms_verify`). BER input (as mail clients send) is read; DER comes
out.

## goose-ts

```
goose-ts query   (--data FILE | --digest HEX) [--hash H] [--no-nonce] [--cert] [--policy OID] --out FILE
goose-ts request --url URL (--data FILE | --digest HEX | --queryfile FILE) [query options]
                 [--out FILE] [--token-out FILE] [--ca-file FILE [--untrusted FILE]]
goose-ts verify  (--in REPLY | --token FILE) (--queryfile FILE | --data FILE | --digest HEX [--hash H])
                 --ca-file FILE [--untrusted FILE] [--policy OID] [--sha1]
goose-ts reply   --queryfile FILE [TSA options] --out FILE
goose-ts serve   [--listen ADDR] --port N [--count N] [TSA options]
goose-ts show    (--in REPLY | --token FILE | --queryfile FILE)
goose-ts stamp   --in CMS --url URL --out FILE [--hash H] [--ca-file FILE [--untrusted FILE]]
goose-ts verify-stamp --in CMS --ca-file FILE [--untrusted FILE]
```

H is sha256 (the default), sha384, sha512, or sha1 with `--sha1`. The
files are the DER `openssl ts` reads and writes (.tsq, .tsr, a token with
`-token_out`); certificates and keys are PEM. `verify` checks a reply
against its query, or a reply or bare token against the data or a digest,
and prints what the token says; `--untrusted` gives the TSA's certificate
and intermediates when the token does not carry them.

The TSA options are `--signer FILE` (its certificate), `--key FILE` (its
key, unencrypted PEM), `--chain FILE`, `--policy OID`, `--other-policy
OID` (more it takes), `--accuracy SECONDS`, `--accuracy-ms N`,
`--precision DIGITS`, `--ordering`, `--tsa-name`, `--serial-file FILE`
(hex, as openssl's: the next serial number, written back after each
token) and `--sha1`. `serve` answers POSTs of
application/timestamp-query on ADDR (127.0.0.1 unless told otherwise),
one connection at a time, `--count` connections before it exits (0:
forever); a GET is 405, another Content-Type 415, and a request the TSA
refuses is a 200 with the refusal, as RFC 3161 §3.4 has it.

```bash
goose-ts query --data contract.pdf --cert --out contract.tsq
goose-ts request --url http://tsa.example.org/ --queryfile contract.tsq --out contract.tsr --ca-file tsa-roots.pem
goose-ts verify --in contract.tsr --data contract.pdf --ca-file tsa-roots.pem
goose-ts serve --port 3161 --signer tsa.pem --key tsa.key --chain ca.pem --policy 1.3.6.1.4.1.99999.1 --serial-file serial
```

`make build` puts it in `../bin` with the other tools. Nothing secret is
printed.

## Examples

In gslib's `examples/tsp/`, run from gslib's top as `goose examples/tsp/<name>.goose`:

- `local_tsa.goose`: a root, a TSA certificate with the critical
  timeStamping usage, a TSA, a request, its reply, and the reply checked
  as a client would. No network.
- `stamp_signature.goose`: a CMS signature time-stamped (Appendix A): the
  token added to its unsigned attributes, the signature still verified,
  the token checked. No network.
- `request.goose`: a time-stamp for a file from a TSA you name, checked
  against the roots you give. Needs a TSA, so `make test` only
  type-checks it.

## Tests

`make test-tsp` (`python3 tsp/scripts/run_tests.py`) runs
`tsp/test/tsp.goose` at -O0, -O2 and with `--debug`, and the examples:
requests made and read (versions, a certReq FALSE written out, unknown
hashes, extensions, nonces too long to keep); GeneralizedTime with and
without a fraction, trailing zeros refused; replies with every failInfo
bit, and refused when granted without a token, refusing with one, with a
line end in a status string or one too long to keep; a TSA made in the
test answering requests, its tokens checked for nonce, imprint, policy,
accuracy, ordering, its name and serial numbers (random, and counted), and
refused for another nonce, other data, another hash, other roots, a time
before the TSA's certificate and an hour off the clock; certReq both ways;
SHA-1 refused by the TSA and the client unless allowed; certificates that
are not a TSA's (the usage not critical, timeStamping with serverAuth, no
usage) refused by `tsa_init` and in tokens; signingCertificate missing,
naming another certificate or another serial number, and taken as
ESSCertID (SHA-1) and as ESSCertIDv2 with SHA-512 written out; a CMS
signature time-stamped, still verified, and refused with another
signature's token; and replies `openssl ts` made (`test/vectors`:
ESSCertIDv2 and ESSCertID, with and without the TSA's certificate) with
openssl's queries.

`make interop-tsp` (`python3 tsp/scripts/interop.py`) runs goose-ts
against `openssl ts` and a Go TSA, with a root and TSA certificates (P-256
and RSA-2048) openssl makes:

- openssl's queries, goose-ts's replies, `openssl ts -verify` against the
  query and the data: SHA-256, -384 (no certReq, no nonce) and -512 (another
  policy), an RSA TSA, the serial file counting on; a policy not taken and
  SHA-1 refused as openssl reads it, SHA-1 taken with `--sha1`.
- goose-ts's queries, openssl's replies (signingCertificateV2,
  signingCertificate with ESSCertID, an RSA TSA, a bare token), checked by
  goose-ts verify against the query and the data; other data, other roots
  and another policy refused; without certReq, refused until the TSA's
  certificate is given; openssl's refusal read.
- goose-ts serve: curl posting openssl's query (the reply checked by
  openssl), goose-ts request, a GET (405) and another Content-Type (415).
- Appendix A: a signature from `openssl cms -sign` time-stamped by goose-ts
  stamp against goose-ts serve; `openssl cms -verify` still verifies it and
  shows the unsigned attribute; goose-ts verify-stamp checks the token.
- With Go: `scripts/gotsa` (github.com/digitorus/timestamp, fetched by its
  go.mod) as a TSA over HTTP for goose-ts request, with and without
  certReq; and its client's query answered by goose-ts reply, the reply
  read back by it.

It needs openssl 3 or later; curl and Go are each skipped if absent.

What the others do differently, seen in these runs: openssl 4.1's
`ts -reply` still writes signingCertificate (ESSCertID, SHA-1) when its
configuration says `ess_cert_id_alg = sha1`; its ESSCertIDv2 for SHA-256
is the certificate's hash alone, hashAlgorithm left out as DER says and no
issuerSerial (goose's TSA sends issuerSerial, which openssl checks when it
is there). Its queries write the MessageImprint's parameters as NULL, and
its genTime has `clock_precision_digits` of fraction (three here).
digitorus/timestamp names the TSA (its subject) in every token whether
asked or not.

## Not done

- No CRLs or OCSP for the TSA's certificate: the path is checked at
  genTime, revocation is the caller's (x509's `revocation_status`,
  `ocsp_*`).
- A TSA certificate whose keyUsage is nonRepudiation alone (no
  digitalSignature) fails x509's check of a leaf, which wants
  digitalSignature, keyEncipherment or keyAgreement when keyUsage is there.
- A token whose request had no certReq may still carry certificates
  (RFC 3161 says it must not); it is taken, as openssl takes it.
- One SignerInfo per SignedData, as x509's CMS reads it: a token, or a
  signature to stamp, with several signers is refused.
- ESSCertIDv2's other certificates (the chain, `ess_cert_id_chain`) are
  not checked, only the first, the signer's; signingCertificateV2's
  policies are not read.
- TSTInfo extensions are noted (`info.extensions`), not read; the TSA
  takes none in requests.
- The TSA keeps no state but its serial file, takes one connection at a
  time, and has no TLS of its own (put it behind a TLS server, or use
  `respond` in one).
- Evidence records (RFC 4998) and long-term archive time-stamps, and the
  CAdES/PAdES forms built on Appendix A, are not here.
- Public TSAs (FreeTSA, DigiCert, Sectigo) were not run against, only
  local ones; `examples/tsp/request.goose` does it for a TSA you name.
