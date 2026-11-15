# scep

A SCEP client (RFC 8894) for Goose: certificates from the CAs that enrol
devices by the Simple Certificate Enrolment Protocol (Microsoft's NDES,
EJBCA, Dogtag, step-ca, micromdm and the MDM servers, network gear). One
module, `scep.goose` at gslib's top (namespace `scep`), a test CA in the
same module (`scep::serve`), and a tool, `goose-scep`, that enrols in one
command and runs the test CA.

A pkiMessage is a CMS SignedData over an EnvelopedData, both gslib's
`x509` (cms.goose and cms_env.goose); requests go over gslib's HTTP client
(`net/http`), by POST when the server's caps say POSTPKIOperation and by
GET with the message in base64 otherwise.

| What | Functions |
|---|---|
| the server | `set_url`, `get_caps` (GetCACaps: `c.caps`, `parse_caps`), `get_ca_cert` (GetCACert, the CA alone or certs-only with an RA: `c.ca_certs`) |
| enrolment | `enroll` (PKCSReq, or RenewalReq signed by the certificate being renewed; CertPoll every `poll_ms` while PENDING, until `poll_timeout_ms`), `poll` (one CertPoll) |
| other requests | `get_cert` (GetCert by issuer and serial), `get_crl` (GetCRL) |
| requests' parts | `make_csr` (with the challengePassword), `self_signed` (the signer of an initial request, §2.3), `transaction_id`, `issuer_and_subject`, `issuer_and_serial` |
| messages | `build_message`, `read_message`, `check_reply`, `open_envelope`, `read_certs_only`, `attrs_der`, `choose_algorithms` |
| a test CA | `Server`, `serve`: GetCACaps, GetCACert, PKCSReq with a challenge, RenewalReq by a certificate it issued, PENDING and CertPoll, GetCert, GetCRL |

A CertRep is checked before anything in it is used: it must be signed,
by the CA or RA certificate that GetCACert gave (byte for byte: a reply
that carries its own certificate under the CA's name, signed by another
key, is refused), the signature good, its transactionID the request's,
its recipientNonce the request's senderNonce, its messageType CertRep, each
authenticated attribute there once with one value; on SUCCESS the
envelope must decrypt with the request's key and hold certs-only, and the
issued certificate must carry the CSR's key. FAILURE leaves its failInfo
in `c.fail_info` (`fail_name` gives badRequest and the rest) and any
failInfoText in `c.fail_text` (a reply whose failInfoText is past 2048
bytes, or whose transactionID is not a PrintableString, is malformed:
refused, not cut short). Replies are read up to `c.max_body`
(1 MiB), past which the request fails rather than a body cut short being
read.

Algorithms: requests are encrypted with AES-128-CBC (AES-256-CBC with
`c.aes256`) and signed with SHA-256 when the caps list AES and SHA-256
(or SCEPStandard), SHA-512 if that is all; the content key goes by RSA
PKCS #1 v1.5 key transport, which every SCEP server decrypts, to the RA's
certificate if there is one, else the CA's (whose key usage need not list
keyEncipherment: micromdm's does not). DES-EDE3-CBC and SHA-1 go only to a
server whose caps have nothing newer, and only with `c.legacy`; replies
signed with SHA-1 or encrypted with DES-EDE3 or single DES are taken only
with `c.legacy` too (`ERR_ALGORITHM` says so otherwise). The client's key
must be RSA: the CA encrypts its reply to the signer's certificate.

x509 gained what this needed, kept small: `cms_signed_attr` (one signed
attribute's value), `cms_certs_only` and `cms_crls`, SHA-1 signing by RSA
in `cms_sign_with` (h 160), `CMS_DES3_CBC` to encrypt, `cms_decrypt_legacy`
for DES-EDE3 and single DES, `CmsEncryptOptions.any_usage`, and
`create_csr_attrs` and `csr_attribute` for the challengePassword.

## Using it

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.scep;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

var hc = http::Client { .. };
var c = scep::Client { .. };
scep::set_url(c, "http://ca.example.org/scep");
scep::get_caps(c, hc);
scep::get_ca_cert(c, hc);                      // check c.ca_certs' fingerprint out of band
let key = x509::generate_key(x509::KEY_RSA, 2048);
let subject, ok = x509::name_der("CN=device-0042,O=Example");
let csr, e = scep::make_csr(subject, "", key, challenge_password);
let signer, se = scep::self_signed(csr, key);
let certs, err = scep::enroll(c, hc, csr, key, signer, false);
if err == scep::ERR_FAILURE { print(scep::fail_name(c.fail_info)); }
let issued = scep::first_cert(certs);
```

Renewing: the CSR is for the new key; the message is signed by, and the
reply encrypted to, the certificate being renewed and its key:

```goose
let csr2, e2 = scep::make_csr(subject, "", new_key, "");
let renewed, rerr = scep::enroll(c, hc, csr2, old_key, old_cert_der, true);
```

## goose-scep

```
goose-scep --url URL [options] caps
goose-scep --url URL [options] getca [--out FILE]
goose-scep --url URL [options] enroll --key FILE --subject DN [--dns NAME ...] --out FILE
goose-scep --url URL [options] renew --key FILE --cert FILE --new-key FILE [--subject DN] --out FILE
goose-scep --url URL [options] getcert --key FILE --cert FILE [--out FILE]
goose-scep --url URL [options] getcrl --key FILE --cert FILE [--out FILE]
goose-scep serve --ca-cert FILE --ca-key FILE [--listen ADDR] [--port N] [--pending N] [--legacy]
```

The challenge password comes from the environment's `SCEP_CHALLENGE`,
never the command line, and is never printed. `enroll` makes the key when
`--key`'s file is not there (RSA 2048, PKCS #8 PEM, mode 0600), signs with
a self-signed certificate, and polls while PENDING (`--poll-interval`,
`--poll-timeout`, seconds). `renew` makes the CSR for `--new-key` (made if
missing) with `--cert`'s subject and SAN and signs a RenewalReq with
`--cert` and `--key`. `getcert` fetches `--cert` again by its issuer and
serial; `getcrl` the CA's CRL. `--label` is GetCACert's message,
`--ca-file` PEM roots for an https URL, `--legacy` allows DES and SHA-1,
`--aes256` sends AES-256-CBC, `--get` sends PKIOperation by GET.

`serve` is the test CA on 127.0.0.1 (plain HTTP, as SCEP is): the
challenge from `SCEP_CHALLENGE` (none asked when unset), each request held
through `--pending` CertPolls, DES and SHA-1 requests taken with
`--legacy`. It prints `listening on ADDR:PORT` first and a line a request
on stderr.

```bash
SCEP_CHALLENGE=... goose-scep --url http://ca.example.org/scep enroll \
    --key device.key --subject "CN=device-0042,O=Example" --out device.pem
```

`make build` puts it in `../bin` with the other tools.

## Examples

In gslib's `examples/scep/`, run from gslib's top as `goose examples/scep/<name>.goose`:

- `offline.goose`: a test CA with a challenge password; a device's key,
  CSR and self-signed signer, its PKCSReq and the CA's CertRep read as
  `enroll` reads it; a wrong password refused with badRequest. No network.
- `enroll_live.goose`: a certificate from a server you name. Needs a
  server, so `make test` only type-checks it.

## Tests

`make test-scep` (`python3 scep/scripts/run_tests.py`) runs
`scep/test/scep.goose` at -O0, -O2 and with `--debug` (54 checks each,
fixed RSA keys and certificates in `scep/test/vectors`), and the examples.
Without a network: GetCACaps' keywords (micromdm's list, case, SCEPStandard)
and the algorithms they choose, legacy or not; a CSR's challengePassword
as PrintableString and as UTF8String, none, and an EC key refused; the
transactionID; then requests through the test CA, the CertRep read back
as the client reads it: PKCSReq issued (the certificate's key, subject,
SAN and signature checked), the same by GET in base64, a wrong challenge
(badRequest), RenewalReq signed by the issued certificate for a new key,
and by a stranger (badRequest), GetCert and a serial not issued
(badCertId), GetCRL, PENDING through two CertPolls then issued, and a
CertPoll for nothing held (badCertId).

And what a hostile server might send: a CertRep signed by another key
under the CA's own name, carrying its own certificate; a signature
changed; unsigned; another transactionID; a recipientNonce not ours; a
request where a reply should be; a transactionID twice; SHA-1 and
DES-EDE3 without `legacy` (then taken with it); an envelope encrypted to
someone else; SUCCESS without an envelope; a certificate for another key;
garbage, truncated and empty; GetCACert answers that are not
certificates; a signed message where certs-only should be. Each refused
before anything in it is used.

`make interop-scep` (`python3 scep/scripts/interop.py`) runs goose-scep on
127.0.0.1, every certificate and CRL checked by openssl against its CA:

- against `goose-scep serve`: GetCACaps, GetCACert; PKCSReq (the key file
  0600), a wrong challenge (badRequest), PKIOperation by GET, RenewalReq,
  GetCert (the same certificate back), GetCRL; a CA holding requests
  (PENDING, CertPoll every second, issued) and one given up on after
  `--poll-timeout`.
- against hostile servers (Python): a GetCACert of 2 MiB refused as too
  large, junk refused.
- against micromdm's scepserver: PKCSReq refused without `--legacy` and
  saying why, issued with it, by POST and by GET; a wrong challenge
  (badRequest); RenewalReq with AES-256.
- micromdm's scepclient against `goose-scep serve --legacy`: PKCSReq, a
  wrong challenge (badRequest), RenewalReq signed by the issued
  certificate.

micromdm's tools are `go install github.com/micromdm/scep/v2/cmd/scepserver@latest`
and `.../cmd/scepclient@latest`, found by `$SCEPSERVER` and `$SCEPCLIENT`,
on the PATH or in `~/go/bin`; each part is skipped when its tool is not
there. openssl is needed.

What micromdm does, seen in these runs (it is built on smallstep's Go
pkcs7): its CertRep is signed with SHA-1 and encrypted with single DES
whatever its caps say (they list AES and SHA-256), so goose-scep needs
`--legacy` with it; its scepclient sends DES and SHA-1 too, so the test CA
runs with `--legacy` for it; its CA certificate has no keyEncipherment
though it is the recipient; it sets the CertRep's senderNonce to the
request's; it asks for the challenge password in RenewalReq too; it
answers GetCert, GetCRL and CertPoll with HTTP 500 ("not implemented"), so
those are tested against goose-scep serve; enrolling a subject again
revokes the certificate it issued before; and scepclient takes the first
certificate of the CertRep as its own, so the test CA sends the issued
certificate alone (a certs-only's SET is sorted, and the CA's could come
first). scepclient also reuses a `csr.pem` it finds in its directory.

## Not done

- GetNextCACert and CA rollover (§3.5.3, §4.7), and RA chains longer than
  an RA certificate beside the CA's.
- Requests signed or encrypted with an EC key: RFC 8894 allows them, but
  the servers built on Go's pkcs7 encrypt only to RSA.
- Sending single DES (it is read, with `legacy`, never sent), and RSA-OAEP
  key transport for requests (PKCS #1 v1.5 is what servers decrypt).
- The test CA answers with the CA's certificate alone (no RA), keeps
  what it issued in memory only, and its GetCRL is an empty CRL: it is for
  tests.
- NDES itself was not run against (it needs Windows Server and AD CS).
