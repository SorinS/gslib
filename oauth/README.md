# oauth

An OAuth 2.0 and OpenID Connect client for Goose: tokens from
authorization servers and OpenID Providers (Keycloak, Entra ID, Okta,
Auth0, node-oidc-provider, ...) by every grant a client uses now, the
client authenticated by secret, signed JWT or TLS certificate, tokens
bound to a DPoP key or the certificate; and the checks on what comes
back: ID tokens, JWT access tokens and DPoP proofs, against the issuer's
keys. Two modules, `oauth.goose` at gslib's top and `oauth/oidc.goose`,
both in namespace `oauth`, and a tool, `goose-oauth`.

JWTs, JWKs and signatures are gslib's `jwx`; requests go over gslib's
HTTP client (`net/http`), HTTP/2 or HTTP/1.1, with its TLS (and its client
certificates, for mutual TLS); the loopback listener of logins is `dns`'s
listening socket.

| What | Functions |
|---|---|
| the server | `discover` (OpenID Connect discovery, then RFC 8414's well-known URL; the issuer must match exactly), `read_metadata`, `endpoint` (the mtls_endpoint_aliases when the client uses mutual TLS) |
| the client | `set_public`, `set_secret` (client_secret_basic, client_secret_post, client_secret_jwt), `set_private_key` (private_key_jwt, RFC 7523: ES256/384/512, RS256, PS*, EdDSA on Ed25519 or Ed448, by the key), `set_tls_client_auth` (RFC 8705 §2), `set_dpop_key` (RFC 9449) |
| logins | `new_auth_request` (state, nonce, PKCE verifier), `authorization_url`, `push_authorization_request` (PAR, RFC 9126), `parse_callback` (state, iss (RFC 9207), error), `exchange_code` |
| other grants | `client_credentials`, `refresh`, `device_authorize` + `device_wait` (or `device_token` per poll; RFC 8628, slow_down adds 5 s), `token_exchange` (RFC 8693), `jwt_bearer` (RFC 7523 §2.1), `grant` (any grant type) |
| tokens | `introspect` (RFC 7662), `revoke` (RFC 7009), `resource_request` (Bearer or DPoP with ath, a DPoP nonce answered), `userinfo` (JSON or signed, sub checked) |
| validation (oauth.oidc) | `validate_id_token` (OIDC Core §3.1.3.7), `validate_access_token` (RFC 9068), `verify_dpop_proof` (RFC 9449 §4.3), `check_dpop_binding`, `check_cert_binding` (cnf jkt, x5t#S256), `token_hash` (at_hash, c_hash), `claim_string`/`claim_int`/`claim_bool` |
| keys | `fetch_jwks`, `set_keys` (a JWKS of your own), `jwks_may_refetch`, `alg_allowed` |
| underneath | `post_form` (an authenticated POST to the server, DPoP and its nonce retry included), `add_client_auth`, `client_assertion`, `dpop_proof`, `pkce_challenge`, the JSON readers (`read_token`, `read_device`, `read_introspection`, `error_of`) |

Every refusal leaves the server's error response (RFC 6749 §5.2:
`error`, `error_description`, `error_uri`, and the HTTP status) in
`c.error`, tested by `is_error(c, "invalid_grant")`; a resource server's
comes from its WWW-Authenticate. Token validation returns its own code
for each fault (`ERR_ISSUER`, `ERR_AUDIENCE`, `ERR_AZP`, `ERR_NONCE`,
`ERR_EXPIRED`, `ERR_IAT`, `ERR_AT_HASH`, `ERR_C_HASH`, `ERR_ALG`,
`ERR_SIGNATURE`, `ERR_NO_KEY`, `ERR_TYP`, `ERR_SCOPE`, `ERR_CNF`,
`ERR_DPOP`, ...; `error_text` says each).

Nothing is kept in part. The structs have fixed-size fields (a redirect
URI 512 bytes, a scope 1024 in a request and 2048 in a response, a
client id 256, a cnf thumbprint 64, ...): an argument longer than its
field is `ERR_ARG` (`new_auth_request` returns its error with the
request), and a server's response with a member longer than its field,
of another JSON type than the RFC gives it, or holding the separator of
a list it goes in (a line end in an aud) is refused whole,
`ERR_MALFORMED` (metadata endpoints, issuer and flags; token, device and
introspection responses, ID and access tokens' claims, a DPoP-Nonce over 512 bytes;
a JWKS with a key it cannot read). So a cnf too long never leaves a bound
token looking unbound, an aud never goes missing from a check, an mTLS
alias never falls back to the plain endpoint. Only an error response's
text is cut: `error_description` at 1024 bytes, and an `error` over 128
or `error_uri` over 512 is left out, with `c.error.truncated` set.
The metadata's lists (`scopes` up to 8192 bytes, `grant_types`,
`response_types`, `auth_methods`, `pkce_methods`, `id_token_algs`,
`dpop_algs`) are the caller's to read: this package decides nothing by
them, so a list that does not fit, is not an array of strings or has a
name with a line end is left empty, never cut, with
`m.lists_truncated` set, and discovery goes on; members it does not keep
(claims_supported, ui_locales_supported, ...) are not read at all.

Signatures are checked with the algorithm the client allows, not the one
the token names: `c.algs`, or when it is empty RS*, PS*, ES* and EdDSA.
"none" is never allowed, and HMAC (with the client secret, OIDC Core
§10.1) only when listed. An ID token with typ at+jwt is refused, and an
access token must have it.

## Using it

```goose
import gslib from "SorinS/gslib@v0.1";
import gslib.oauth;
import gslib.oauth.oidc;
import gslib.net.http.client;
import gslib.net.http.fetch;

var hc = http::Client { .. };                   // the system's roots, or hc.tlscfg's
var c = oauth::Client { .. };                   // a root struct: a local
oauth::discover(c, hc, "https://login.example.test/realms/demo");

// A service: client credentials.
oauth::set_secret(c, "my-service", secret, oauth::AUTH_SECRET_BASIC);
let t, err = oauth::client_credentials(c, hc, "api:read");
if err != oauth::OK { print(oauth::error_text(err), ": ", c.error.code, " ", c.error.description); }
let r, rerr = oauth::resource_request(c, hc, "GET", "https://api.example.test/things", t);
```

A native app's login, with PKCE and a loopback redirect (goose-oauth's
`login` does this with its own listener):

```goose
oauth::set_public(c, "native-app");
let ar, aerr = oauth::new_auth_request(c, "http://127.0.0.1:8400/callback", "openid email");
let url = oauth::authorization_url(c, ar);      // or push_authorization_request(c, hc, ar)
// ... the browser comes back to the redirect URI; `query` is what follows "?"
let code, cerr = oauth::parse_callback(c, ar, query);
let t, terr = oauth::exchange_code(c, hc, ar, code);
let id, ierr = oauth::validate_id_token(c, hc, t.id_token, ar.nonce, t.access_token);
let info, uerr = oauth::userinfo(c, hc, t, id.sub);
```

DPoP: set a key and every request carries proofs; the token comes back
with token_type "DPoP", and `resource_request` sends it with a proof
bound to it:

```goose
oauth::set_dpop_key(c, jwk::generate_ec(jwa::CRV_P256));
```

A resource server checking a JWT access token, and its binding:

```goose
var rs = oauth::Client { .. };
oauth::discover(rs, hc, issuer);
let at, err = oauth::validate_access_token(rs, hc, token, "https://api.example.test", "read");
let p, perr = oauth::verify_dpop_proof(rs, dpop_header, "GET", request_url, token);
if oauth::check_dpop_binding(at.cnf_jkt, p) != oauth::OK { /* refuse */ }
```

## goose-oauth

```
goose-oauth --issuer URL --client-id ID [options] discover
goose-oauth --issuer URL --client-id ID [options] token          # client credentials
goose-oauth --issuer URL --client-id ID [options] login          # code + PKCE, a loopback redirect
goose-oauth --issuer URL --client-id ID [options] device
goose-oauth --issuer URL --client-id ID [options] refresh --saved FILE
goose-oauth --issuer URL --client-id ID [options] exchange --token-file FILE [--token-type T]
goose-oauth --issuer URL --client-id ID [options] introspect|revoke (--token-file FILE | --saved FILE [--refresh])
goose-oauth --issuer URL --client-id ID [options] userinfo --saved FILE
goose-oauth --issuer URL --client-id ID [options] validate-id-token (--saved FILE | --token-file FILE [--nonce N])
goose-oauth --issuer URL [options] validate-access-token --token-file FILE --audience A [--scope S]
```

The client authenticates by `--auth basic` (the default with a secret),
`post` or `secret-jwt`, the secret read from `--client-secret-file FILE`
or `$OAUTH_CLIENT_SECRET`; by `--auth private-key-jwt --key FILE` (a
private JWK); by `--auth tls --cert FILE --cert-key FILE` (PEM); or
`--auth none` (a public client, the default without a secret). Other
options: `--ca-file` (the server's CAs instead of the system's),
`--scope`, `--resource` (repeatable, RFC 8707), `--audience`,
`--dpop-key FILE` (a JWK, made P-256 and 0600 when it is not there),
`--par`, `--port N` (login's loopback port, 0 by default: any),
`--timeout S`, `--save FILE`, `--hint`.

`login` listens on 127.0.0.1, prints the URL to open on stderr, waits for
the browser's redirect to `/callback`, checks its state and issuer,
exchanges the code, and validates the ID token if one came. `device`
prints the verification URI and the user code and polls until the user
is done.

What it prints, by choice: the commands that get a token (`token`,
`login`, `device`, `refresh`, `exchange`) print the access token alone on
stdout, so that `TOKEN=$(goose-oauth ... token)` or a pipe takes it, and
say on stderr what came (type, lifetime, scope, whether a refresh token
or an ID token did). Refresh and ID tokens are never printed: `--save
FILE` writes the whole response (and login's nonce) to a 0600 file, which
`refresh`, `revoke --refresh`, `userinfo` and `validate-id-token` read.
`discover`, `introspect`, `userinfo` and the validate commands print
JSON on stdout. Client secrets and private keys are never printed, and
are never taken as arguments, which `ps` shows to everyone; tokens to
work on come from files (`-` for stdin) for the same reason.

```bash
TOKEN=$(goose-oauth --issuer https://login.example.test --client-id ci-job \
    --client-secret-file ~/.config/ci-job.secret --scope api:read token)
goose-oauth --issuer https://login.example.test --client-id cli --save ~/.cache/cli.json login
goose-oauth --issuer https://login.example.test --client-id cli --saved ~/.cache/cli.json userinfo
```

`make build` puts it in `../bin` with the other tools.

## Examples

In gslib's `examples/oauth/`, run from gslib's top as `goose examples/oauth/<name>.goose`:

- `offline.goose`: an authorization request with PKCE and its redirect
  (a forged state refused), a DPoP proof checked as a server would, and
  an ID token signed by a stand-in issuer key and validated (signature,
  iss, aud, nonce, exp, at_hash), then refused for another request's
  nonce. No network.
- `service.goose`: a backend's token by client credentials, introspected,
  used on an API and revoked; the secret from the environment. Needs a
  server, so `make test` only type-checks it.

## Tests

`make test-oauth` (`python3 oauth/scripts/run_tests.py`) runs
`oauth/test/oauth.goose` (210 checks) at -O0, -O2 and with `--debug`, and
the examples. Without a server:

- PKCE: RFC 7636 Appendix B's verifier and challenge; fresh verifiers of 43
  unreserved characters.
- DPoP: RFC 9449's proofs (§4.1 for the token request, §7.1 with an
  access token) verified with the keys they carry, §6.1's thumbprint and
  §7.1's ath; refused for another method, URL, token, a missing nonce,
  an old iat, a tampered signature; our own proofs (ES256, PS256) made and
  checked, their header holding only the public key, a fresh jti each;
  none by a public key or HMAC.
- at_hash and c_hash against OpenID Connect Core Appendix A.3 and A.4;
  EdDSA's by SHA-512 for Ed25519 and by SHAKE256 (114 bytes) for Ed448.
- ID tokens signed in the test (RS256, ES256, PS256, HS256, EdDSA and
  Ed448 on Ed448, at_hash checked): valid ones,
  and each fault refused with its own error: no or another iss, another
  audience, two audiences without azp, azp another's, no sub, exp or iat,
  another nonce, expired (and within the leeway, not), iat and nbf ahead,
  max_age passed, a tampered signature, another key with the same kid, an
  unknown kid, alg none, HS256 when not allowed (and with another secret
  when allowed), an alg outside the client's list, typ at+jwt, at_hash and
  c_hash mismatches.
- JWT access tokens (RFC 9068): typ at+jwt and application/at+jwt, typ
  JWT refused, another audience, a missing scope, no jti, expired; cnf
  x5t#S256 and jkt checked against a certificate and RFC 9449's proof.
- Documents: RFC 8414-style metadata with mtls_endpoint_aliases and the
  lists, the metadata URLs (RFC 8414 §3.1's example, OIDC's), RFC 6749
  §5.1's token response and §5.2's error, RFC 8628 §3.2's device
  response, RFC 7662 §2.2's introspection.
- The authorization URL's parameters and dpop_jkt; the callback refused
  for another state, a missing or another iss, an error; client
  authentication: client_secret_basic form-encoded before base64 (RFC
  6749 §2.3.1), _post, private_key_jwt's assertion verified (iss, sub, aud
  the issuer, exp, iat, a fresh jti, kid), client_secret_jwt by HS256.
- Nothing kept in part: `new_auth_request` with a 512-byte redirect URI
  and a 1024-byte scope (kept whole, in the URL) and one byte more
  (`ERR_ARG`); client ids of 256 and 257 bytes for every `set_*`;
  client_secret_jwt's secret at `jwk::MAX_OCT` and one over; a
  DPoP-Nonce of 512 and 513. Metadata, token, device and introspection
  responses with each member at its size and one over, or of another
  type, refused whole (an mTLS alias, an introspection aud or cnf
  thumbprint, a token response's scope or id_token); a line end in an
  aud refused; a 5 KB scopes_supported kept whole, and a metadata list
  over its size, not an array, with a non-string or a line end left
  empty and flagged while discovery goes on; ID and access tokens with at_hash,
  azp, nonce, c_hash, scope or cnf of the wrong type or size, or an
  audience holding a line end, refused; an error's description cut and
  its code and URI left out, marked `truncated`.

`make interop-oauth` (`python3 oauth/scripts/interop.py`, 45 checks) runs
goose-oauth against [node-oidc-provider](https://github.com/panva/node-oidc-provider)
9.15 (OpenID Certified), set up by `oauth/scripts/op/provider.mjs` on
https with a CA made for the run, asking for client certificates:

- discovery; client credentials by client_secret_basic, client_secret_post
  (secret from a file and from `$OAUTH_CLIENT_SECRET`), private_key_jwt
  and tls_client_auth; a wrong secret and another certificate refused
  (invalid_client); secrets and keys printed nowhere;
- JWT access tokens for a resource indicator, validated by
  `validate-access-token` (another audience and a missing scope refused);
  the tls_client_auth token bound to the certificate (cnf x5t#S256 equal
  to the certificate's thumbprint);
- introspection (active, then inactive after revocation, and for
  nonsense from stdin);
- DPoP with the provider demanding a nonce on every proof: the token after
  use_dpop_nonce, introspection showing cnf.jkt as the key's thumbprint,
  a DPoP-bound client refused without a proof;
- logins through goose-oauth's loopback listener, the provider's
  redirects followed by the script with interactions that sign "alice" in
  and consent: a public client with PKCE (the ID token validated, saved
  0600, nothing secret printed, refresh, the refresh token revoked and
  then refused), a confidential client by PAR with DPoP (UserInfo with the
  DPoP token after its nonce, refused with another key), client_secret_post
  with a signed UserInfo response, private_key_jwt with a resource (its
  JWT access token validated);
- the device grant, its verification pages filled in by the script;
- token exchange (a minimal RFC 8693 grant registered in provider.mjs:
  oidc-provider has none), and a bogus subject token refused.

It needs node and npm: the first run does `npm ci` in
`oauth/scripts/op` (package.json and package-lock.json are committed,
node_modules is not), and is skipped without them. Keycloak in Docker or
Podman was planned too; interop.py skips it when no container daemon is
running, and does not start one.

What node-oidc-provider does that a client must allow for: it takes no
`tls_client_auth` until `clientAuthMethods` lists it; it ignores a scope
it does not know in client credentials instead of refusing it; it rotates
refresh tokens (the old one is then dead, so keep the new one); its JWT
access tokens are only for resource indicators (others are opaque); with
DPoP nonces required, every first proof to the token endpoint and to
UserInfo is answered with use_dpop_nonce.

## Not done

- Keycloak: not run (no container runtime was up); the realm and its run
  in interop.py remain to be written.
- A differential against Go's golang.org/x/oauth2 and coreos/go-oidc.
- Encrypted ID tokens and UserInfo (JWE), request objects (JAR, RFC 9101),
  JARM, CIBA, dynamic client registration, RP-initiated logout.
- `validate_id_token` does not check acr values asked for, and the JWKS
  refetch for an unknown kid is tested offline (its rate limit) but not
  live, with keys rotated under it.
- The tool opens no browser itself: it prints the URL.
