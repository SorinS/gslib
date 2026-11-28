# est

An EST client (RFC 7030, with RFC 8951's clarifications) for Goose:
certificates over HTTPS from the CAs and RAs that speak Enrollment over
Secure Transport (EJBCA, Dogtag, Cisco's and the other network vendors'
CAs, GlobalSign's and DigiCert's EST services, IoT enrolment servers). One
module, `est.goose` at gslib's top (namespace `est`), a test CA in the same
module (`est::serve`), and a tool, `goose-est`, that enrols in one command
and runs the test CA over TLS.

Requests go over gslib's HTTP client (`net/http`, HTTP/2 or HTTP/1.1) and
its TLS, whose configuration is the caller's: the roots the EST server's
certificate must chain to (the explicit trust anchor of §3.6.1), a client
certificate when one authenticates the client, Basic credentials answered
to the server's 401. CSRs, certificates and certs-only CMS are gslib's
`x509`; /serverkeygen's multipart body is gslib's `mime`.

| What | Functions |
|---|---|
| the server | `set_server` (scheme and authority only), `set_label` (one path segment: §3.2.2's label, after `/.well-known/est/`), `op_url` |
| CA certificates | `cacerts` (§4.1): certs-only, base64 |
| enrolment | `simple_enroll` (one try: `/simpleenroll`, or `/simplereenroll` with `reenroll`), `enroll` (asks again while the CA answers 202, after its Retry-After, until `poll_timeout_ms`) |
| CSR attributes | `csrattrs` (§4.5; 204 and 404 are no attributes), `parse_csrattrs`, `csrattrs_has`, `csrattrs_values` |
| server-generated keys | `server_keygen` (§4.4): the PKCS #8 key and the certificate from multipart/mixed, `read_keygen` |
| underneath | `decode_base64` (white space taken out, RFC 8951 §3), `encode_base64`, `read_certs_only`, `issued_first`, `first_cert`, `retry_after_ms` |
| a test CA | `Server`, `serve`: every request above, Basic credentials or a client certificate the CA issued, 202s for a held key, under any label |

What comes back is checked before it is used: a certs-only CMS must have
no signers and only certificates that parse; the issued certificate must
carry the CSR's key (`ERR_KEY` otherwise), and /serverkeygen's the key
sent with it; replies are read up to `c.max_body` (1 MiB), past which the
request fails (`ERR_HTTP`, `http::ERR_TOO_LARGE`) rather than a body cut
short being read. An error response leaves its status in `c.status` and
its first 512 bytes, unprintable ones replaced, in `c.detail`.

## Using it

```goose
import gslib from "SorinS/gslib@v0.9.4";
import gslib.est;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.pool;

var hc = http::Client { .. };
hc.tlscfg = tls::client_config_pool("", roots);       // the EST server's CA: the explicit trust anchor
http::set_credentials(hc, "device-0042", password);   // Basic, sent when the server asks
var c = est::Client { .. };
est::set_server(c, "https://est.example.org");
let cas, err = est::cacerts(c, hc);                    // DER laid end to end
let attrs, aerr = est::csrattrs(c, hc);
if est::csrattrs_values(attrs, "1.2.840.10045.2.1") == "1.3.132.0.34" { /* the CA wants P-384 */ }
let certs, eerr = est::enroll(c, hc, csr, false);      // waits while the CA answers 202
if eerr != est::OK { print(est::error_text(eerr), " ", c.status, " ", c.detail); }
let leaf = est::first_cert(certs);                     // the issued certificate; the CA's may follow
```

Re-enrolment authenticates with the certificate being renewed, so it goes
on an `http::Client` whose TLS has it before its first request (a
connection already open without it would be reused):

```goose
var hc2 = http::Client { .. };
hc2.tlscfg = tls::client_config_pool("", roots);
tls::set_client_certificate(hc2.tlscfg, cert_chain_der, key_pkcs8_der);
let renewed, rerr = est::enroll(c, hc2, new_csr, true);   // the CSR's subject is the certificate's
```

## goose-est

```
goose-est --server URL [options] cacerts [--out FILE]
goose-est --server URL [options] csrattrs
goose-est --server URL [options] enroll --key FILE --subject DN [--dns NAME ...] --out FILE
goose-est --server URL [options] reenroll --cert FILE --key FILE [--new-key FILE] --out FILE
goose-est --server URL [options] serverkeygen --subject DN [--dns NAME ...] --out FILE --key-out FILE
goose-est serve --ca-cert FILE --ca-key FILE [--listen ADDR] [--port N] [--user NAME] [--pending N] [--csrattrs-example]
```

`--ca-file` trusts a PEM file of roots for the server instead of the
system's. `--user` sends HTTP Basic credentials when the server asks, the
password from the environment's `EST_PASSWORD` (never the command line);
`--tls-cert` and `--tls-key` authenticate by client certificate, which
`reenroll` takes from `--cert` and `--key`. `enroll` makes the key when
`--key`'s file is not there (P-256, or `--key-type rsa2048`; PKCS #8 PEM,
mode 0600) and waits while the CA answers 202, up to `--poll-timeout`
seconds; `serverkeygen` writes the key the CA made to `--key-out` (0600).
`--label` names a CA's path segment. Nothing secret is printed.

`serve` is the test CA over TLS on 127.0.0.1, its server certificate for
localhost and 127.0.0.1 issued from `--ca-cert` when it starts; client
certificates the CA issued are asked for and checked by the TLS layer.
`--user` (and `EST_PASSWORD`) requires Basic credentials of clients
without such a certificate, `--pending N` answers each new key's first N
tries with 202 and Retry-After, `--csrattrs-example` serves RFC 7030
§4.5.2's CsrAttrs. It prints `listening on ADDR:PORT` first and a line a
request on stderr.

```bash
EST_PASSWORD=... goose-est --server https://est.example.org --ca-file est-ca.pem --user device-0042 \
    enroll --key device.key --subject CN=device-0042 --dns device-0042.example.org --out device.pem
```

`make build` puts it in `../bin` with the other tools.

## Examples

In gslib's `examples/est/`, run from gslib's top as `goose examples/est/<name>.goose`:

- `offline.goose`: a test CA that wants Basic credentials and holds each
  key once; /cacerts, /csrattrs, /simpleenroll refused without
  credentials, held (202), then issued, and /serverkeygen, each answer read
  as the client reads it. No network.
- `enroll_live.goose`: a certificate from a server you name, checked
  against roots you give. Needs a server, so `make test` only
  type-checks it.

## Tests

`make test-est` (`python3 est/scripts/run_tests.py`) runs
`est/test/est.goose` at -O0, -O2 and with `--debug` (44 checks each), and
the examples. Without a network: RFC 7030 §4.5.2's CsrAttrs example read
item by item (bare OIDs, an attribute's OID values, a value that is not an
OID as hex); base64 with CRLF, LF and spaces, and not base64; server URLs
and labels (a label that would be another path, `..`, `%2f`, white space
or a line end refused); Retry-After as seconds, as a date, past or
unreadable. Then every request through the test CA, the answer read back
as the client reads it: /cacerts, /csrattrs and 204, /simpleenroll
without credentials (401 with a Basic challenge), with the wrong password,
with the right one, by a client certificate instead, and with the CA's own
certificate as the client's (refused), not application/pkcs10 (415), not a
CSR (400), held twice with Retry-After then issued, /simplereenroll for a
new key, without the certificate (403) and for another subject (400),
/serverkeygen under a label, two labels or `..` as one (404).

And what a hostile server might send: certs-only that is signed, empty or
junk; a certificate for another key; /serverkeygen's multipart without a
boundary, with two keys, without a certificate, with a key that is not the
certificate's, with the key encrypted, not base64, with no parts; CsrAttrs
with an attribute missing its SET or a stray INTEGER. Each refused.

`make interop-est` (`python3 est/scripts/interop.py`) runs goose-est over
TLS on 127.0.0.1, every certificate checked by openssl against its CA:

- against `goose-est serve`: /cacerts, and refused from a server not
  trusted; /csrattrs; /simpleenroll without credentials, with the wrong
  password (401 both), with Basic under a label; the key file 0600;
  /simplereenroll by client certificate for a new key; /serverkeygen, the
  key the certificate's; a CA holding the request twice (202, Retry-After)
  then issuing.
- against hostile servers (Python, TLS): a /cacerts of 2 MiB refused as
  too large, junk refused, a request held forever given up on after
  `--poll-timeout`.
- against GlobalSign's estserver (its mock CA an openssl CA): /cacerts,
  /csrattrs (none, and the RFC's example under the label `csrattrs`),
  /simpleenroll for EC and RSA keys, /simplereenroll by client
  certificate, /serverkeygen; under the label `triggererrors` a 403
  reported and a 202 with Retry-After 600 given up on; under `pkcs7` the
  encrypted key reported as unsupported.
- GlobalSign's estclient against `goose-est serve`: cacerts, csrattrs,
  enroll (refused without credentials, then with Basic), reenroll by client
  certificate, serverkeygen.

GlobalSign's tools are `go install github.com/globalsign/est/cmd/estserver@latest`
and `.../cmd/estclient@latest`, found by `$ESTSERVER` and `$ESTCLIENT`,
on the PATH or in `~/go/bin`; each part is skipped when its tool is not
there. openssl is needed.

What GlobalSign's server does, seen in these runs: it negotiates HTTP/2;
its HTTP Basic check guards only /healthcheck, so enrolment there needs no
credentials (the 401 path is tested against goose-est serve); labels are
test switches (`csrattrs` gives the RFC's example, `triggererrors` the
errors, `pkcs7` a PWRI-encrypted key); its 202 asks for 600 seconds.

## Not done

- Channel binding (§3.5): tls-unique, or RFC 9266's tls-exporter for TLS
  1.3, in the CSR's challengePassword. crypto/tls has the exporters
  (`export_keying_material`, `export12` in schedule.goose), but gslib's
  HTTP client does not give its caller the connection a request went on,
  nor its Finished messages for tls-unique.
- A server-generated key encrypted to the client (§4.4.2's
  application/pkcs7-mime; smime-type=server-generated-key, by key transport
  or a password: PWRI is not in x509's CMS): reported as `ERR_UNSUPPORTED`.
- /fullcmc (§4.3, CMC, RFC 5272) and the TPM enrolment GlobalSign adds.
- The test CA keeps nothing it issued, has no CRL, and issues for any
  subject a credentialed client asks for: it is for tests.
- Proof that the CSR came from the client authenticated by TLS beyond the
  subject check of /simplereenroll (§3.5's linking of identities).
