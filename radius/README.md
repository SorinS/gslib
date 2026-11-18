# radius

RADIUS for Goose, both sides, as FreeRADIUS and Go's layeh.com/radius
speak it: packets and their authenticators, a client over UDP and over
RadSec (RADIUS over TLS), a server's handling of each request, and EAP,
the protocol 802.1X carries inside RADIUS, with the methods Wi-Fi and
wired networks use: PEAP, TTLS and EAP-TLS, over TLS 1.2 and 1.3. Five
modules in namespace `radius`, and two tools, `goose-radtest` and
`goose-radiusd`.

**Message-Authenticator always, and first.** BlastRADIUS (CVE-2024-3596)
forges an Access-Accept from a captured Access-Reject through an MD5
collision on the Response Authenticator, unless the packets carry a
Message-Authenticator (HMAC-MD5 over the whole packet). Every
Access-Request and Status-Server the client sends has one, as the first
attribute, and every answer the server makes to them too; the client
requires one in every answer to an Access-Request (`require_ma`, true by
default), and the server in every Access-Request (`Server.require_ma`,
true by default; FreeRADIUS 3.2's `require_message_authenticator`).
Clear them only for old peers on networks nobody else can reach.

**RADIUS's own crypto is MD5.** The authenticators, User-Password hiding
and the salt-encryption of Tunnel-Password and the MPPE keys are MD5
with the shared secret; a long random secret is all that protects them.
RadSec puts the whole exchange in TLS (with certificates both ways) and
is the better choice across any network you do not own. MS-CHAPv2 is
DES under the NT hash: run it inside PEAP or TTLS, never in the clear.
MS-CHAP version 1 and EAP-LEAP are not here.

Hashes are `crypto/bignum`'s MD5, MD4 (legacy only), SHA-1, HMAC and DES;
the NT hash is `ntlm`'s; TLS is `crypto/tls`'s (its exporter,
`tls::export_keys`, gives the EAP methods their keys).

| Module | What |
|---|---|
| `radius.goose` | errors (`error_text`); codes (`code_name`) and attribute numbers (RFC 2865, 2866, 2868, 2869, 3162, 5176, 6911), Microsoft's vendor-specific ones (RFC 2548); `Packet`: `request` (an Access-Request's random authenticator made at once), `response` (Proxy-State copied), `add`, `add_u32`, `add_ipv4`, `add_vsa`, `remove`, `get`, `get_u32`, `get_text`, `get_all`, `vsa`, `count`, `attr_at`, `attr_count`; `set_eap` and `eap_message` (EAP-Message in 253-byte pieces); `encode`, `parse`, `packet_length` (RadSec's stream); `sign_request`, `sign_response`, `check_request`, `check_response`; `add_password` and `password` (User-Password), `add_chap` and `chap_ok`, `salt_encrypt` and `salt_decrypt`, `add_tunnel_password` and `tunnel_password`, `add_mppe_keys` and `mppe_keys` |
| `radius/mschap.goose` | MS-CHAPv2 (RFC 2759): `nt_password_hash`, `challenge_hash`, `nt_response`, `authenticator_response` and `authenticator_response_ok`; its MPPE keys (RFC 3079): `master_key`, `start_key`; the RADIUS attributes (RFC 2548): `add_mschap2` (a client's MS-CHAP-Challenge and MS-CHAP2-Response), `mschap2_success_ok`, `check_mschap2` and `add_mschap2_success` (the server's, with the MPPE keys) |
| `radius/eap.goose` | EAP (RFC 3748): `eap_packet`, `eap_header`, the codes and types; the peer: `PeerConfig` (`peer_config`; identity, outer identity, password, method, TTLS's inner method, fragment size, TLS), `Peer` (`peer`), `peer_step`, `peer_msk`, `peer_emsk`; the server: `EapConfig` (`eap_config`; methods in order, TLS, MS-CHAPv2's name, fragment size), `EapSession` (`eap_session`), `server_start`, `server_step` with the password lookup as a block, `session_msk`, `session_emsk`; EAP-TLS framing (`TlsLayer`, fragments both ways), TTLS's Diameter AVPs (`put_avp`, `find_avp`), the methods' keys (`tls_method_keys`) |
| `radius/client.goose` | `Client`: `dial` (UDP), `dial_radsec` (RFC 6614), `close`, `exchange` (numbered, signed, retransmitted, the answer checked); `authenticate_pap`, `authenticate_chap`, `authenticate_mschapv2` (the server's proof checked), `authenticate_eap` (a whole conversation through a `Peer`, the State carried, the MPPE keys checked against the MSK), `account`, `status` (RFC 5997), `disconnect` and `change_of_authorization` (RFC 5176, to a NAS) |
| `radius/server.goose` | `Server` (`server`; the secret, `require_ma`, EAP conversations kept by their State, at most `max_sessions` (64) for `session_ttl` (60 s), the oldest dropped first; each holds a TLS connection and two 64 KiB reassembly buffers, so size `max_sessions` to the memory and the load): `handle` (one request's bytes to the answer's: PAP, CHAP, MS-CHAPv2, EAP, accounting, Status-Server; dropped silently when it does not check), `sessions`; `handle_dynamic` (a NAS's side of CoA and Disconnect, the answer as a block decides) |

## Using it

A NAS asking a server, over UDP:

```goose
import gslib.radius;
import gslib.radius.client;

var c, e = radius::dial("127.0.0.1", 1812, "testing123");
let resp, er = radius::authenticate_pap(c, "alice", "alice-pw");
if er == radius::OK { print(radius::get_text(resp, radius::REPLY_MESSAGE)); }
```

Attributes of its own go in a template packet that every request copies
(`authenticate_pap(c, user, pw, base)`), or into a request built by
hand and sent with `exchange`:

```goose
var req = radius::request(radius::ACCESS_REQUEST);
radius::add(req, radius::USER_NAME, "alice");
radius::add_password(req, "alice-pw", "testing123");
radius::add_u32(req, radius::NAS_PORT_TYPE, radius::PORT_WIRELESS);
let resp, e = radius::exchange(c, req);           // req keeps its id and authenticator
let keys, ok = radius::mppe_keys(resp, "testing123", req.auth);
```

802.1X: a supplicant's EAP conversation, here PEAP with MS-CHAPv2 inside
and an anonymous outer identity; the MS-MPPE keys of the Access-Accept
are checked against the supplicant's own MSK:

```goose
import gslib.radius.eap;

var pc = radius::peer_config("alice", "alice-pw", radius::EAP_PEAP);
pc.outer_identity.append("anonymous");
pc.tls = tls::client_config("radius.example.com", ca_der);   // the server's name and CA
var p = radius::peer(pc);
let resp, e = radius::authenticate_eap(c, p, pc);
let msk = radius::peer_msk(p);                       // 64 bytes: what 802.1X's keys start from
```

`EAP_TTLS` with `pc.inner = radius::INNER_PAP` or `INNER_MSCHAPV2`;
`EAP_TLS` with a certificate (`tls::set_client_certificate(pc.tls, chain,
key)`); `EAP_MSCHAPV2` and `EAP_MD5` without TLS. A server that
proposes another method gets a Nak naming the peer's.

RadSec: TCP to port 2083 and TLS with a client certificate; the secret is
"radsec", and nothing is retransmitted:

```goose
var cc = tls::client_config("radius.example.com", ca_der);
tls::set_client_certificate(cc, chain_der, key_der);
var c, e = radius::dial_radsec("radius.example.com", 2083, cc);
```

A server: `handle` takes a datagram (or a packet off a RadSec stream) and
gives the answer, the passwords from a block (empty for an unknown
user). EAP conversations live in the `Server` between requests:

```goose
import gslib.radius.server;

var t, ok = tls::server_config(chain_der, key_der);   // PEAP's, TTLS's, EAP-TLS's certificate
t.client_auth = tls::VERIFY_CLIENT_CERT_IF_GIVEN;      // EAP-TLS: client certificates checked
x509::pool_add(t.client_cas, client_ca_der);
let methods: u8[3] = [radius::EAP_PEAP, radius::EAP_TTLS, radius::EAP_TLS];
let cfg = radius::eap_config(methods, t);
var srv = radius::server("testing123");
let fd = net::listen_udp("127.0.0.1", 1812);
loop {
    let n, from = net::recv_from(fd, buf, 0);
    var reply: u8[>..] = [];
    let req, e = radius::handle(srv, cfg, buf[..n], reply) { user => password_of(user) };
    if reply.len > 0 { net::send_to(fd, reply, from); }
}
```

An EAP method's MSK goes to the NAS as MS-MPPE-Recv-Key (its first half)
and MS-MPPE-Send-Key, salt-encrypted, as RFC 2548 and every access
point expect; the outer identity as User-Name.

The EAP steps know nothing of RADIUS: `peer_step` and `server_step` take
an EAP packet and give the next, so EAPOL could carry them as well.

## The EAP methods

| Method | Peer | Server | Keys |
|---|---|---|---|
| MD5-Challenge (4) | yes | yes | none |
| MS-CHAPv2 (26) | yes, the server's proof checked | yes | 32-byte MSK ([MS-CHAP] §3.1.5.1) |
| EAP-TLS (13) | yes | yes, client certificates required | TLS 1.2: PRF "client EAP encryption"; TLS 1.3: exporter "EXPORTER_EAP_TLS_Key_Material", type 13 (RFC 9190) |
| PEAPv0 (25) | yes, EAP-MS-CHAPv2 inside, the Result TLV | yes, the same | "client EAP encryption"; TLS 1.3: the exporter, type 25 (RFC 9427) |
| TTLS (21) | yes, PAP or MS-CHAPv2 inside | yes, either | "ttls keying material"; TLS 1.3: the exporter, type 21 |

TLS messages are cut into EAP-TLS fragments of 1000 bytes by default
(`fragment`), the first of several with its total length; the other
side's fragments are acknowledged, and its acknowledgments bring the next
fragment. Over TLS 1.3, EAP-TLS's server sends one byte of 0x00 inside
the tunnel to say the handshake is done (RFC 9190 §2.5) and the peer
takes Success only after it. A peer whose TLS fails sends its alert, or
acknowledges the server's, so that the server ends with EAP-Failure.
PEAPv0's inner EAP packets go without their header but for EAP-TLV's,
and FreeRADIUS's whole-header Identity request is taken too. TTLS's
MS-CHAPv2 challenge comes from the TLS keys (RFC 5281 §11.2.4), so the
server checks that the peer used that one.

## goose-radtest and goose-radiusd

```
goose-radtest [options] HOST METHOD [USER PASSWORD]
```

One exchange, as FreeRADIUS's radtest and wpa_supplicant's eapol_test
make them: METHOD is `pap`, `chap`, `mschapv2`, `eap-md5`,
`eap-mschapv2`, `eap-tls`, `peap`, `ttls-pap`, `ttls-mschapv2`, `acct`
(a Start and a Stop) or `status`. `--secret`, `--port`, `--radsec` with
`--cert`/`--key`, `--ca` and `--name` for the server's certificate,
`--eap-cert`/`--eap-key` for EAP-TLS, `--anon` for the outer identity,
`--tls12`, `--fragment`; `disconnect` and `coa` send RFC 5176's requests
to a NAS (port 3799) for USER. It prints the answer and, for the methods with
keys, whether the MS-MPPE keys are the peer's MSK.

```
goose-radiusd --cert server.pem --key server.key [options]
```

A small server: UDP authentication and accounting, `--radsec-port` for
RadSec with client certificates, `--coa-port` to answer CoA and
Disconnect as a NAS would, `--user NAME:PASSWORD` (as many as wanted),
`--ca` for EAP-TLS's and RadSec's client certificates, `--methods
peap,ttls,tls,mschapv2,md5`, `--tls12`.

## Examples

`examples/radius/`:

- `eap_in_memory.goose`: 802.1X from end to end with no network: a
  supplicant and `handle` trading EAP inside Access-Requests and
  Access-Challenges, PEAP then EAP-TLS over TLS 1.3, the MS-MPPE keys
  equal to the supplicant's MSK; certificates made at the start.
- `client.goose`: PAP, PEAP and accounting against a real server, over
  UDP or RadSec.
- `server.goose`: a server in a few lines on 127.0.0.1:11812.

## Tests

```bash
make test-radius                                  # or: cd radius && python3 scripts/run_tests.py
make interop-radius                               # Linux with Docker
```

Every test runs at -O0, -O2 and with `--debug`:

- `test/packets.goose`: RFC 2865 §7.1's Access-Request and Access-Accept
  byte for byte (the hidden password, the Response Authenticator, both
  rebuilt), User-Password of every length to 128 and longer refused,
  CHAP with and without CHAP-Challenge, Tunnel-Password and the MPPE
  keys round trips; the Message-Authenticator first, checked, a byte
  changed, another secret; Accounting-, CoA- and Disconnect-Requests'
  authenticators and their answers; Proxy-State copied in order;
  EAP-Message in pieces; EAP without Message-Authenticator refused;
  malformed packets (short, a length past the datagram, attributes of
  length 1 or past the end, padding dropped); MS-CHAPv2 against RFC 2759
  §9.2 (ChallengeHash, NtPasswordHash, NT-Response,
  AuthenticatorResponse) and RFC 3079 §3.5.3 (MasterKey, SendStartKey128,
  which side's key it is), and the RADIUS attributes both ways.
- `test/eap.goose`: a peer against a server in memory for every method:
  MD5, MS-CHAPv2 (the same 32-byte MSK), PEAP, TTLS/PAP, TTLS/MS-CHAPv2,
  EAP-TLS, each over TLS 1.3 and 1.2 with 1000- and 300-byte fragments,
  the same MSK on both sides; wrong passwords inside each tunnel, EAP-TLS
  without a certificate, a server the peer does not trust, a Nak to
  another method and to one not offered, a Success before any method,
  truncated packets, fragments longer than their total.
- `test/server.goose`: `handle` given what a NAS sends: PAP, CHAP and
  MS-CHAPv2 right and wrong (MS-CHAP2-Success and the MPPE keys),
  accounting, Status-Server, whole PEAP, TTLS and EAP-TLS conversations
  in Access-Challenges with their State (the MPPE keys checked, no
  conversation left behind); dropped: another secret, no
  Message-Authenticator, EAP without a conversation, CoA sent to a
  server; `handle_dynamic`'s ACK and NAK (with Error-Cause) for CoA and
  Disconnect, and another secret.
- `crypto/tls/test/exporter.goose`: `tls::export_keys`, both ends the
  same for TLS 1.3 and 1.2, with and without a context.

`scripts/interop.py` (`make interop-radius`) runs everything live in
Docker on loopback: FreeRADIUS 3.2.10 (its stock configuration, test
certificates, TLS up to 1.3, RadSec), wpa_supplicant 2.11's eapol_test
built from hostap, and a second FreeRADIUS as a proxy:

- `goose-radtest` against FreeRADIUS: PAP, CHAP, MS-CHAPv2,
  Status-Server, accounting, EAP-MD5, EAP-MS-CHAPv2, PEAP, TTLS/PAP,
  TTLS/MS-CHAPv2, EAP-TLS with RSA and P-256 certificates, each TLS
  method over TLS 1.3 and 1.2 and PEAP with 300-byte fragments; RadSec
  (PAP, PEAP, accounting); the MS-MPPE keys equal to the MSK every time;
  a wrong password, a wrong secret (no answer), an untrusted CA and a
  wrong server name refused.
- `goose-radiusd` against eapol_test: PEAP, TTLS/PAP, TTLS/MS-CHAPv2 and
  EAP-TLS over TLS 1.2 and 1.3, EAP-MS-CHAPv2 and EAP-MD5, eapol_test
  checking the MPPE keys against its own MSK; a wrong password refused;
  against radclient: PAP, CHAP, a wrong password, accounting,
  Status-Server, and as a NAS Disconnect (ACK, and NAK for an unknown
  user) and CoA; `goose-radtest`'s `disconnect` and `coa` to it as well
  (ACK, and NAK with its Error-Cause).
- RadSec both ways: `goose-radtest` to `goose-radiusd` (PAP, PEAP,
  EAP-TLS, a client without a certificate refused), and FreeRADIUS
  proxying `user@radsec.example` over RadSec to `goose-radiusd`: PAP, a
  wrong password, and eapol_test's PEAP and EAP-TLS through it.

`fuzz/targets/radius.goose` drives the packet parser and everything that
reads a packet (attributes, the hidden ones decrypted, the checks), EAP's
header, EAP-TLS reassembly and TTLS's AVPs, `handle` on requests
re-signed with the secret (so the checks after the Message-Authenticator
run), and a peer given arbitrary EAP requests.

## Not done

- MS-CHAP version 1, EAP-LEAP, EAP-FAST and TEAP; PEAPv1 and PEAP's
  crypto-binding TLV (neither FreeRADIUS nor wpa_supplicant asks for
  them by default).
- A signer block for EAP-TLS's client key (a key in a TPM or on a
  token), as `tls::client_feed` takes one: the peer's key is in memory.
- EAP-TLS session resumption; TLS session tickets are off in the EAP
  server.
- RADIUS over DTLS (RFC 7360), and the RADIUS/1.1 ALPN (RFC 9765).
- Proxying and realms: the server answers; it does not forward.
- A dictionary of every vendor's attributes: attributes are numbers and
  bytes, with helpers for the standard and Microsoft ones.
