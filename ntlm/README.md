# ntlm

NTLM authentication ([MS-NLMP]) for Goose, NTLMv2 only, both sides: an
initiator (client) and an acceptor (server) that trade the three
NTLMSSP messages, session security (signing and sealing) after them, and
NTLM as HTTP, SPNEGO and SASL carry it. Seven modules in namespace `ntlm`,
and a tool, `goose-ntlm`.

**NTLM is legacy.** Its keys come from the NT hash, an unsalted MD4 of
the password, so the hash is as good as the password (pass-the-hash), a
captured exchange can be brute-forced offline, and its only ciphers are
RC4 and HMAC-MD5. A server can relay a client's messages to another
server unless channel bindings, the target name and the MIC tie them to
one connection and one service. Use Kerberos (gslib's `krb5`) where
there is a KDC; use NTLM where a peer offers nothing else (an IIS site, an
Exchange server's SMTP, a workgroup machine).

**NTLMv1 and LM are not here at all.** There is no NTOWFv1, LMOWFv1, DESL
or NTLMv1 response in the code: the initiator only ever computes
NTLMv2, and the acceptor refuses an NTLMv1 response (24 bytes, the NTLM2
session response too), an LM response alone, and LM_KEY with
`ERR_NTLMV1`. An NTLMv1 response is DES under three pieces of the NT
hash, which a captured exchange (or a rainbow table for a fixed server
challenge) turns back into the hash outright; Windows has refused it by
default since Vista, and Microsoft is removing it.

Hashes are `crypto/bignum`'s MD4 (`bignum.md4`, legacy only), MD5 and
HMAC; RC4 is `bignum.rc4` (legacy only). The tls-server-end-point
binding uses `x509` and `asn1`.

| Module | What |
|---|---|
| `ntlm.goose` | flags, AV_PAIR ids, errors (`error_text`); UTF-8 to UTF-16LE and back; FILETIME; `Credentials`: `credentials` (from a password, the hash kept, not the password; `DOMAIN\user` split), `credentials_hash` (from an NT hash), `anonymous_credentials`, `nt_hash`, `parse_nt_hash` |
| `ntlm/messages.goose` | NEGOTIATE, CHALLENGE and AUTHENTICATE written and read (`negotiate_message`, `parse_negotiate`, `challenge_message`, `parse_challenge` into a `Challenge`, `authenticate_message`, `parse_authenticate` into an `Authenticate`), VERSION; AV_PAIRs: `av_check`, `av_get`, `av_put`, `av_put_name`, `av_end`; `is_ntlmssp` |
| `ntlm/crypto.goose` | `ntowfv2`, `client_blob` (NTLMv2_CLIENT_CHALLENGE), `nt_proof` (NTProofStr), `lmv2_response`, `session_base_key`, `rc4k`, `compute_mic`, `bindings_hash` (MD5 of gss_channel_bindings_struct), `sign_key`, `seal_key` |
| `ntlm/client.goose` | `Initiator`: `initiator`, `set_channel_bindings`, `negotiate`, `authenticate` (`authenticate_with` for given nonces and time), `established` |
| `ntlm/server.goose` | `Acceptor` (its policy as fields): `acceptor`, `set_acceptor_bindings`, `set_acceptor_spn`, `accept_negotiate`, `accept_authenticate` with the NT hash lookup as a block, `adopt_challenge`, `accepted` |
| `ntlm/session.goose` | `Session`: `get_mic`, `verify_mic`, `wrap`, `unwrap`, `sealed` (extended session security: HMAC-MD5 signatures, RC4 sealing, sequence numbers per direction), `reset_rc4` |
| `ntlm/http.goose` | `http_header`, `http_token` (NTLM and Negotiate header values), `leaf_certificate`, `tls_server_end_point` (RFC 5929's channel binding) |

And outside the package's own directory:

| Where | What |
|---|---|
| `krb5.spnego` | NTLM as SPNEGO's mechanism (1.3.6.1.4.1.311.2.2.10, [MS-SPNG]): `SpnegoNtlm`, `spnego_ntlm_initiator`, `spnego_ntlm_init`, `spnego_ntlm_init_continue`, `spnego_ntlm_acceptor`, `spnego_ntlm_accept` (a bare NTLMSSP token in place of SPNEGO taken too), `spnego_ntlm_session`; mechListMIC with the NTLM keys both ways (none for anonymous NTLM, which has no keys) |
| `net/http` (`http.fetch`) | `AUTH_NTLM` (and `AUTH_ANY`, which ranks NTLM after Digest and before Basic): a 401's `WWW-Authenticate: NTLM`, or `Negotiate` alone, answered with raw NTLMSSP over the same HTTP/1.1 connection, the server certificate's tls-server-end-point as the channel binding over https, `HTTP/host` as the target name; goose-http's `--ntlm` |
| `mail.sasl` | `AUTH_NTLM` for SMTP, POP3 and IMAP (Exchange's `AUTH NTLM`): the NEGOTIATE as the initial response, the AUTHENTICATE for the CHALLENGE; only when asked for |

### What the acceptor checks

`accept_authenticate(a, msg, now) { user, domain, hash => ... }`, in
this order:

- the message: at most 64 KiB, the signature and type, the fixed part
  whole, every field's offset and length inside the message and past the
  fixed part, no two payload fields overlapping;
- anonymous (no user, no NT response, LM empty or Z(1)): `ERR_ANONYMOUS`
  unless `allow_anonymous`, and then no session keys;
- no LM or NTLMv1: LM_KEY, a 24-byte NT response, an LM response alone
  (`ERR_NTLMV1`); an NT response too short to be NTLMv2;
- flags: UNICODE and extended session security; nothing of SIGN, SEAL,
  KEY_EXCH, 128 or 56 that the CHALLENGE did not offer; nothing of SIGN,
  SEAL, KEY_EXCH or 128 that the NEGOTIATE asked for and the
  AUTHENTICATE dropped (a downgrade); 128-bit keys whenever signing or
  sealing (`require_128`): `ERR_FLAGS`;
- the NTLMv2 response: the block gives the NT hash for the user and
  domain as sent (UTF-8); NTOWFv2, then NTProofStr over our server
  challenge and the client's blob, compared in constant time.
  `ERR_LOGON` for an unknown user and a wrong password alike, after the
  same work;
- the blob, now known to be the client's: version 1, its AV_PAIRs well
  formed; its time within `skew` seconds (300) of ours, and its
  MsvAvTimestamp, if any, the one we sent (`ERR_TIMESTAMP`);
- channel bindings (`ERR_BINDINGS`): with `CB_REQUIRED`, the client's
  MsvAvChannelBindings must be the MD5 of ours; with `CB_SUPPORTED` (the
  default), they are compared when we have bindings and the client sent
  some that are not zeros;
- the target name, when `spn` is set: MsvAvTargetName ours, any case
  (`ERR_TARGET`); with `spn_required` it must be there;
- the exported session key (KEY_EXCH: RC4K of the session base key), and
  the MIC over NEGOTIATE, CHALLENGE and AUTHENTICATE (its MIC field zero)
  whenever MsvAvFlags says there is one, or `require_mic` asks
  (`ERR_MIC`). A client that sets the flag but sends no MIC field, or
  changes a byte anywhere in the three messages, fails here.

The LM response is not read when there is an NT response (our client
sends Z(24) when the server sent a timestamp, as the spec says; curl
sends a real LMv2, which adds nothing). Any error spends the context.

### What the initiator sends

NEGOTIATE offers UNICODE, NTLM, extended session security, 128-bit,
KEY_EXCH, SIGN (and SEAL with `WANT_SEAL`), ALWAYS_SIGN, REQUEST_TARGET
and VERSION; never OEM, LM_KEY, DATAGRAM or 56. A CHALLENGE without
UNICODE or extended session security, without 128 while signing, or
without SEAL when it was asked for, is a downgrade: `ERR_FLAGS`. The
AUTHENTICATE carries the server's target info back with MsvAvFlags
(MIC present), MsvAvChannelBindings (`set_channel_bindings`) and
MsvAvTargetName (the SPN) added, the blob's time the server's
MsvAvTimestamp when it sent one, a random exported session key RC4'd
under the session base key, and the MIC.

## Using it

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.ntlm;
import gslib.ntlm.messages;
import gslib.ntlm.session;
import gslib.ntlm.client;
import gslib.ntlm.server;

// The client.
let cred, e = ntlm::credentials("EXAMPLE\\alice", "", password);
var cli = ntlm::initiator(cred, "HTTP/web.example.test", ntlm::WANT_SEAL);
ntlm::set_channel_bindings(cli, tls_end_point);      // over TLS: ntlm::tls_server_end_point(cert)
var t1: u8[>..] = [];
ntlm::negotiate(cli, t1);                            // send t1, get t2
var t3: u8[>..] = [];
let ce = ntlm::authenticate(cli, t2, now, t3);       // send t3

// The server.
var srv = ntlm::acceptor("WEB", "EXAMPLE", "web.example.test", "example.test");
ntlm::set_acceptor_bindings(srv, tls_end_point, ntlm::CB_REQUIRED);
ntlm::set_acceptor_spn(srv, "HTTP/web.example.test", true);
var t2: u8[>..] = [];
ntlm::accept_negotiate(srv, t1, now, t2);
let se = ntlm::accept_authenticate(srv, t3, now) { user, domain, hash =>
    lookup_nt_hash(user, domain, hash)               // write 16 bytes, yield true; false: no such user
};
if se == ntlm::OK { print(srv.domain, "\\", srv.user); }

// Then, both ways.
var w: u8[>..] = [];
ntlm::wrap(cli.session, "data", true, w);         // true: sealed, or ERR_NO_SESSION
var p: u8[>..] = [];
ntlm::unwrap(srv.session, w, p);
```

`now` is seconds since 1970 (`time_ns() / 1000000000`). Over HTTP:

```goose
var c = http::Client { .. };
c.opt.auth = http::AUTH_NTLM;          // or AUTH_ANY: Digest, then NTLM, then Basic
c.opt.http2 = false;                   // NTLM authenticates a connection: HTTP/1.1
http::set_credentials(c, "EXAMPLE\\alice", password);
var r = http::get(c, "https://web.example.test/");
```

Inside SPNEGO (HTTP Negotiate's tokens, SASL GSS-SPNEGO):

```goose
var cli = krb5::spnego_ntlm_initiator(cred, "HTTP/web.example.test", ntlm::WANT_SEAL);
krb5::spnego_ntlm_init(cli, tok);                                    // NegTokenInit [NTLM] + NEGOTIATE
let done, e = krb5::spnego_ntlm_init_continue(cli, reply, now, tok); // CHALLENGE in; AUTHENTICATE + mechListMIC out
var srv = krb5::spnego_ntlm_acceptor(ntlm::acceptor("WEB", "EXAMPLE", "", ""));
let sdone, se = krb5::spnego_ntlm_accept(srv, tok, now, reply) { user, domain, hash => lookup(user, domain, hash) };
```

## goose-ntlm

```bash
goose-ntlm hash < password-file                 # the NT hash, hex
goose-ntlm compute --user alice --domain EXAMPLE --password-env PW \
    --server-challenge 0123456789abcdef --client-challenge aaaaaaaaaaaaaaaa [--time FILETIME] [--target-info HEX]
goose-ntlm decode 'NTLM TlRMTVNTUAAB...'        # a message, field by field
goose-ntlm serve --users users.txt --port 8080  # HTTP, every path behind NTLM or Negotiate
goose-ntlm get --user 'EXAMPLE\alice' --password-env PW http://127.0.0.1:8080/
goose-ntlm initiate ... | goose-ntlm accept ... # one side each, tokens as "token BASE64" lines
```

Passwords come from an environment variable or a file, never the command
line; `--nt-hash-file` takes a hash instead (not for `get`). The users
file is pyspnego's `NTLM_USER_FILE` format, `DOMAIN:USER:PASSWORD`
lines. `serve` answers a request without credentials with 401 and both
`WWW-Authenticate: NTLM` and `WWW-Authenticate: Negotiate`, authenticates
each connection once (raw NTLMSSP under either scheme, SPNEGO under
Negotiate), says `hello DOMAIN\user` to its requests, and logs to stderr.
`initiate` and `accept` take `--spnego`, channel bindings (`--cb-data`,
`--cb-hex`, `--cb required`), `--spn`, `--seal`, and after the exchange
read `wrap`, `unwrap`, `mic` and `verify` lines. The source's header has
every option.

```bash
printf 'EXAMPLE:alice:%s\n' "$PW" > users.txt
goose-ntlm serve --users users.txt --port 8080 &
curl --ntlm -u "EXAMPLE\\alice:$PW" http://127.0.0.1:8080/      # hello EXAMPLE\alice
```

## Examples

In `examples/ntlm/`, each runnable from gslib's top:

- `exchange.goose`: a logon in memory with channel bindings, the target
  name and the MIC required; sealing both ways; a replayed AUTHENTICATE,
  a wrong password and an NTLMv1 response refused.
- `spnego.goose`: NTLM inside SPNEGO, each token as the `Negotiate`
  header that carries it, mechListMIC both ways, sealing after.
- `http_client.goose`: a GET with `AUTH_NTLM` against a server given on
  the command line (type-checked by the tests; `goose-ntlm serve` is a
  server to try it with).

## Tests

```bash
make test-ntlm                                   # or: cd ntlm && python3 scripts/run_tests.py
NTLM_PYTHON=VENV/bin/python make interop-ntlm
```

Every test runs at -O0, -O2 and with `--debug`:

- `test/vectors.goose`: [MS-NLMP] §4.2.4 byte for byte: NTOWFv2, LMv2,
  NTProofStr and the whole NTLMv2 response, the session base key, the
  encrypted session key, the CHALLENGE (0x68 bytes) read and written, the
  AUTHENTICATE (0xE8 bytes, no MIC) written and read, §4.2.4.4's sealing
  and signing keys, sealed data and signature, unwrapped again; the
  acceptor taking the spec's AUTHENTICATE against the spec's CHALLENGE,
  and refusing it with a wrong password, an unknown user, and its time
  (zero, 1601) outside the skew; UTF-8 and UTF-16 both ways with
  surrogate pairs and every malformed form; the channel bindings hash
  against pyspnego's.
- `test/exchange.goose`: initiator and acceptor in memory: sealing and
  signing both ways, replayed, changed and reflected signatures (the
  session still in step after each), sealing asked of a sign-only
  session refused; wrong
  password, unknown user, another domain; a changed MIC, a NEGOTIATE
  changed in transit (caught by the MIC), `require_mic`; an old
  timestamp, a wider skew, a replayed AUTHENTICATE (to a new context and
  to the finished one), a timestamp not the one sent; channel bindings
  matching, differing, missing when required; target names; NTLMv1, LM
  alone, LM_KEY and short responses refused; downgrades both ways (the
  client's CHALLENGE without ESS, UNICODE, 128 or SEAL; the acceptor's
  AUTHENTICATE flags changed, 56-bit); every prefix of every message, an
  oversized message, fields past the end, inside the fixed part,
  overlapping, of length 65535 or offset 2^32-1; every single byte of an
  AUTHENTICATE flipped (none accepted); AV_PAIR lists without MsvAvEOL,
  cut short, with a pair twice, of wrong sizes, with 300 empty pairs; a
  CHALLENGE with no target info; anonymous refused and allowed; steps out
  of order; curl's OEM-only NEGOTIATE.
- `test/spnego.goose`: krb5.spnego's NTLM: the exchange with mechListMIC
  both ways and sealing after it, a raw NTLMSSP token, Kerberos listed
  first (NTLM chosen in a second round), no NTLM offered, a mechListMIC
  changed or stripped, a wrong password.
- `test/http.goose`: the header values both ways and refused ones; the
  leaf of a chain; tls-server-end-point by SHA-256 and SHA-384
  certificates.
- `net/http/test/fetch.goose` checks which 401s fetch answers with NTLM,
  and `mail/test/sasl.goose` the SASL exchange against the acceptor.

### Against other implementations

`scripts/interop.py` (70 checks), all on 127.0.0.1 with made-up
passwords. It needs a Python with pyspnego (`python3 -m venv VENV &&
VENV/bin/pip install pyspnego impacket`; impacket is optional), and uses
curl and Go when found; nothing is installed system-wide.

- goose-ntlm's initiator against pyspnego's acceptor and pyspnego's
  initiator against goose-ntlm's acceptor, raw NTLMSSP and SPNEGO: the
  exchange, three sealed messages each way, MICs each way; channel
  bindings matching, differing, missing where required; a wrong password;
  an SPN checked and a wrong one; pyspnego as an NTLMv1 client
  (`LM_COMPAT_LEVEL=1`) refused; pyspnego's acceptor set to NTLMv2 only
  (`LM_COMPAT_LEVEL=5`) taking ours.
- `goose-ntlm compute` against impacket's NTOWFv2 and hashlib's HMAC-MD5
  for NTProofStr, the NT and LMv2 responses and the session base key.
- curl `--ntlm`, Azure/go-ntlmssp (pinned by `scripts/gontlm`'s go.mod)
  and pyspnego over http.client (NTLM, NTLMSSP under Negotiate, and
  SPNEGO) against `goose-ntlm serve`, right and wrong passwords.
- `goose-ntlm get` (net/http's fetch with `AUTH_NTLM`) against an HTTP
  server on pyspnego's acceptor offering `NTLM`, `Negotiate` alone, and
  `Basic` with `NTLM`; over https against the same server requiring the
  channel binding of its certificate (tls-server-end-point; with and
  without 401 bodies), and refused by one bound to another certificate;
  and against `goose-ntlm serve`.

### Against Windows

None of the above talks to Windows. To try it against a Windows host of
your own (an IIS site with Windows Authentication, Exchange's SMTP AUTH
or OWA, an http.sys service): `goose-ntlm get --user 'DOMAIN\user'
--password-env PW https://host/` (or goose-http `--ntlm`) for a client;
IIS's Extended Protection set to Required checks the channel binding that
fetch sends over https. For the server side, point a Windows client
(`Invoke-WebRequest -UseDefaultCredentials`, or a browser that allows
the host in its intranet zone) at `goose-ntlm serve`, with the user's
password in the users file; Windows sends its MIC, MsvAvChannelBindings
(zeros over plain HTTP) and the SPN. `goose-ntlm decode` prints any token
copied from a capture.

## Quirks

- Only Unicode: an OEM-only client (curl's NEGOTIATE) gets a Unicode
  CHALLENGE and answers in it; an AUTHENTICATE without UNICODE is
  refused.
- Extended session security is required, for authentication too (every
  NTLMv2 client sends it); there is no session security without it.
- NTOWFv2 upper-cases the user name in ASCII only; Windows upper-cases
  all of Unicode, so a user name with lower-case letters outside ASCII
  gets another key than Windows'. The domain is used as given, as the
  spec says.
- The acceptor computes the proof for an unknown user too (with a zero
  hash), so the two failures take the same path; the lookup block itself
  may still take its own time.
- With KEY_EXCH and neither SIGN nor SEAL, the exported key is the
  session base key and the encrypted key field is ignored (pyspnego's
  reading; Windows always signs).
- Inside SPNEGO the RC4 state of each direction is reset after the
  mechListMIC is signed or checked, sequence numbers kept, as Windows and
  pyspnego do. A client AUTHENTICATE with a MIC and no mechListMIC is
  refused (a stripped MIC).
- `http.fetch` answers NTLM only over HTTP/1.1 (a 401 that came over
  HTTP/2 is not answered: set `opt.http2 = false`), and not to a proxy's
  407. The AUTHENTICATE goes on the connection the CHALLENGE came on
  because each 401's body is read whole and the pool hands back the
  connection used last; it is not pinned otherwise. Over https, a 401
  whose connection's certificate cannot be found is not answered (no
  unbound AUTHENTICATE goes out).
- The client always signs (SIGN), as Windows does; `WANT_SIGN` asks for
  nothing more.
- `wrap`'s `conf` argument (GSS's conf_req) asks for sealing: with it,
  a session that did not negotiate SEAL gives `ERR_NO_SESSION` rather
  than sending the message signed only. Without it the message is sealed
  all the same when SEAL was negotiated (the token does not say which);
  `sealed(s)` tells.
- A wrap token or MIC that fails to verify leaves the session as it was
  (its incoming RC4 state and sequence number), unlike SSPI, which moves
  on: a forged or damaged token cannot put the direction out of step.
- `acceptor()` with a name longer than its field (64 bytes NetBIOS, 256
  DNS) gives an acceptor whose first step fails with `ERR_ARG`.
- `goose-ntlm serve` is a test server: one connection at a time,
  plain HTTP, and it trusts the users file.

## Not done

- NTLMv1, LM, NTLM2 session response, and session security without
  extended session security: refused by design, never to be added.
- Connectionless (datagram) NTLM; NEGOTIATE_IDENTIFY's semantics.
- MsvAvSingleHost is checked for size, not compared; MsvAvFlags'
  constrained-authentication and untrusted-SPN bits are not acted on.
- Upper-casing user names outside ASCII as Windows does.
- A domain controller: the acceptor checks against NT hashes it is
  given (no Netlogon pass-through, no NETLOGON_NETWORK_INFO).
- A combined Negotiate acceptor that takes Kerberos or NTLM in one
  context (krb5.spnego has one for each); NTLM in `http.fetch` through a
  proxy (407) or over HTTP/2.
- SASL GSS-SPNEGO in mail; LDAP's NTLM bind (MS-ADTS sicily).
- Interop with Windows itself (no hosts were contacted; see above).
