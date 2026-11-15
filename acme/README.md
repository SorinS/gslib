# acme

An ACME client (RFC 8555) for Goose: certificates from Let's Encrypt, from
an enterprise's own CA (Vault and OpenBao's PKI engine, step-ca, EJBCA,
Boulder) or from a commercial CA that ties ACME accounts to accounts of its
own (external account binding). One module, `acme.goose` at gslib's top
(namespace `acme`), and a tool, `goose-acme`, that gets a certificate in
one command and proves the names by http-01 (served by itself, or written
into a web root) or by dns-01 through RFC 2136 dynamic updates.

The requests are flattened JWS (RFC 7515) made by gslib's `jwx`, and go
over gslib's HTTP client (`net/http`), HTTP/2 or HTTP/1.1, with its TLS.
The CSR is gslib's `x509`; dns-01's updates are gslib's `dns`.

| What | Functions |
|---|---|
| the server | `open` (the directory: URLs, terms of service, `eab_required`, profiles) |
| the account | `set_key` (ES256, ES384, ES512, RS256 or EdDSA by the key), `new_account` (contacts, terms agreed, external account binding by HS256), `find_account` (onlyReturnExisting), `key_change` (rollover, §7.3.5), `deactivate_account` |
| orders | `new_order` (DNS names, wildcards, IP addresses (RFC 8738), a profile), `get_order`, `wait_order`, `finalize` (the CSR, then waits until issued), `certificate` (the PEM chain, leaf first) |
| authorizations | `get_authz`, `find_challenge`, `accept`, `wait_authz` (Retry-After honoured, as seconds or an HTTP-date), `deactivate_authz` |
| challenges | `key_authorization`, `http01_path`, `dns01_name`, `dns01_value` (§8.1, §8.3, §8.4) |
| revoking | `revoke` (by the account, with an RFC 5280 reason or none) |
| all of it | `obtain`: order, prove each name with a block that publishes the challenge, finalize, download |
| underneath | `post` (any signed request, POST-as-GET with an empty payload), `sign_request`, the JSON readers (`read_directory`, `read_order`, `read_authz`, `problem_of`) |

A request that the server turns down for its nonce (`badNonce`) is signed
again with the nonce that came with the refusal, up to `nonce_retries`
times (3). Every refusal leaves its problem document (RFC 9457) in
`a.problem`, its type tested by `is_problem(a, "rateLimited")` and the like.

## Using it

```goose
import gslib from "SorinS/gslib@v0.1";
import gslib.acme;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.net.http.client;
import gslib.net.http.fetch;

var hc = http::Client { .. };                   // the system's roots, or hc.tlscfg's
var a = acme::Client { .. };                    // a root struct: a local
let key = jwk::generate_ec(jwa::CRV_P256);      // keep it: jwk::marshal, in a file only you read
acme::set_key(a, key);
acme::open(a, hc, "https://acme-staging-v02.api.letsencrypt.org/directory");
acme::new_account(a, hc, "mailto:admin@example.org", true);

// csr: x509::create_csr with the names in the SAN, by a key that is not the account's.
let chain, err = acme::obtain(a, hc, "example.org\n*.example.org", csr, "dns-01") { z, ch, value =>
    // publish TXT `value` at acme::dns01_name(z.id_value); true once it is there
    my_dns_update(z.id_value, value)
};
if err != acme::OK { print(acme::error_text(err), ": ", a.problem.kind, " ", a.problem.detail); }
```

Step by step instead, as `obtain` does it:

```goose
var o, err = acme::new_order(a, hc, "example.org");
for url in split(o.authz, '\n') {
    let z, zerr = acme::get_authz(a, hc, url);
    let i = acme::find_challenge(z, "http-01");
    // serve acme::key_authorization(a, z.challenges[i].token) at acme::http01_path(...)
    acme::accept(a, hc, z.challenges[i]);
    let done, werr = acme::wait_authz(a, hc, url);
}
acme::get_order(a, hc, o);
acme::wait_order(a, hc, o);                     // pending to ready
acme::finalize(a, hc, o, csr);                  // ready to processing to valid
let chain, cerr = acme::certificate(a, hc, o);
```

With external account binding (ZeroSSL, Sectigo, DigiCert, Google Trust
Services, Vault or OpenBao with `eab_policy`), the CA gives a key id and a
MAC key in base64url; `new_account` takes the id and the decoded key:

```goose
let mac, ok = jwx::b64_decode(eab_hmac);
acme::new_account(a, hc, "mailto:admin@example.org", true, eab_kid, mac);
```

## goose-acme

```
goose-acme --server URL --account-key FILE [options] run -d NAME [-d NAME ...]
goose-acme --server URL --account-key FILE [options] register
goose-acme --server URL --account-key FILE [options] revoke --cert FILE [--reason N]
goose-acme --server URL --account-key FILE [options] rollover --new-account-key FILE
goose-acme --server URL --account-key FILE [options] deactivate
```

The account key is a JWK file, made (P-256, mode 0600) when it is not
there; every command registers the account first if the key has none.
`run` proves each name by one of:

- `--http PORT`: serves http-01 itself on PORT (80 for a real CA), on a
  thread that answers any token with the account key's thumbprint, so
  nothing is handed between threads;
- `--webroot DIR`: writes each token's file under
  `DIR/.well-known/acme-challenge/` for the web server already there, and
  removes it afterwards;
- `--dns SERVER[:PORT]`: dns-01 by RFC 2136 dynamic update, signed with
  `--tsig NAME:SECRET[:ALG]` (base64 secret, hmac-sha256 unless ALG), in
  `--dns-zone ZONE` or the zone whose SOA the server answers with, waiting
  `--dns-wait SECONDS` for secondaries; the records are removed afterwards.
  BIND, Knot, PowerDNS and Windows DNS take such updates.

It writes the chain (PEM, leaf first) to `--cert-out` (NAME.crt) and a new
key (PKCS #8 PEM, 0600) to `--key-out` (NAME.key), of `--key-type` ec256
(the default), ec384, rsa2048, rsa3072 or rsa4096, or keeps `--key FILE`'s.
`--ca-file` trusts a CA's own PEM roots for the ACME server instead of the
system's (Pebble's, an internal CA's, Let's Encrypt staging's);
`--email`, `--agree-tos`, `--eab-kid`, `--eab-hmac` and `--profile` go to
the server. Nothing secret is printed.

```bash
goose-acme --server https://acme-staging-v02.api.letsencrypt.org/directory \
    --account-key account.jwk --email admin@example.org --agree-tos \
    run -d example.org -d '*.example.org' --dns ns1.example.org --tsig acme-key:BASE64SECRET
```

`make build` puts it in `../bin` with the other tools.

## Examples

In gslib's `examples/acme/`, run from gslib's top as `goose examples/acme/<name>.goose`:

- `challenges.goose`: an account key, its newAccount request verified as
  a server would, the http-01 response and dns-01 record for a token, and
  the CSR for a name and its wildcard. No network.
- `obtain.goose`: a certificate from a server you name, proving the names
  by dns-01 records it asks you to publish. Needs a server, so `make test`
  only type-checks it.

## Tests

`make test-acme` (`python3 acme/scripts/run_tests.py`) runs
`acme/test/acme.goose` at -O0, -O2 and with `--debug`, and the examples.
Without a server: RFC 7638's thumbprint example for the key authorization
and dns-01's value; RFC 8555's directory, order, authorization and
problem examples (§7.1.1, §7.1.3, §7.1.4, §6.7.1), with a challenge's
error; Retry-After as seconds and as a date; IP identifiers; the JWS of a
request (flattened, verified by the account key, alg, nonce and url in its
protected header, `jwk` for newAccount and `kid` otherwise, never both,
POST-as-GET's empty payload) and of an external account binding (HS256
over the account's public key); no signing without a key or an account.
And what a hostile server might send: tokens that are not base64url
(`../../victim`, line ends, NUL) refused before anything is published, so
http-01 never writes outside the web root; directory, order and
authorization URLs too long to keep, or with a line end, refuse the whole
document rather than lose the URL, as do an expires or profile over 64
bytes, a challenge type over 32, more than 8 challenges and an embedded
problem whose type is over 256 bytes (a problem response with one keeps
its status, without the type). Only text for people is cut: a problem's
detail at 1024 bytes (`truncated` set); and the directory's profile
names, which the client decides nothing by, are left empty rather than
cut when over 1024 bytes or a name has a line end
(`profiles_truncated`). `obtain` publishes nothing for an
authorization whose identifier was not ordered (compared without regard to
case, wildcards by their base name).

`make interop-acme` (`python3 acme/scripts/interop.py`) runs goose-acme
against live servers on 127.0.0.1, with goose-dnsd as their DNS
(`*.example.test` at 127.0.0.1, TSIG-signed updates applied in memory):

- Pebble, Let's Encrypt's test server, in `-strict` mode and turning down a
  fifth of the nonces: http-01 served by goose-acme for two names; http-01
  from a web root that Python's http.server serves; dns-01 for
  `*.example.test` and `example.test` with an RSA key, the TXT records gone
  afterwards; an update with the wrong TSIG key refused by goose-dnsd and
  reported; revoking (superseded), then `alreadyRevoked`; a key rollover,
  the new key finding the same account; deactivating, and the account
  refused afterwards. Each chain verified by openssl against Pebble's root;
  the key files 0600.
- Pebble requiring external account binding: refused without one
  (`externalAccountRequired`) and with the wrong MAC key, registered with
  the right one.
- OpenBao's PKI engine (Vault's, from before the fork) as an ACME server in
  dev mode: dns-01 for two names, the chain verified against the engine's
  root, revoking, and external account binding with a key from
  `pki/acme/new-eab` (refused without it).

Pebble is `go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest`
(or `$PEBBLE`; its test certificates come from Go's module cache, or
`$PEBBLE_DIR`); OpenBao is `bao` (or Vault's `vault`) on the PATH or in
`~/go/bin`. Each is skipped when it is not there.

What the servers do differently, seen in these runs: OpenBao refuses any
revocation reason but none or 0, and lists `keyChange` in its directory
but answers it with 404, so key rollover works on Pebble (and Let's
Encrypt) but not on OpenBao.

## Not done

- tls-alpn-01 (RFC 8737): the certificate with the acmeIdentifier
  extension, and a TLS server that answers with it for the `acme-tls/1`
  protocol.
- ACME Renewal Information (RFC 9773): when to renew, from the CA.
- Revoking by the certificate's own key rather than the account's (§7.6),
  and alternate chains (`Link: rel="alternate"`).
- Orders with notBefore and notAfter, pre-authorization (newAuthz), and
  updating an account's contacts.
- The tool proves names only by http-01 and dns-01, and only DNS names (the
  library takes IP addresses too).
- Let's Encrypt itself was not run against: its staging server needs names
  in public DNS. `examples/acme/obtain.goose` does it for names you control.
