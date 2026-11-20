# quic

QUIC version 1 and HTTP/3 for Goose, both sides: RFC 9000's transport,
RFC 9001's use of TLS 1.3 (gslib's tls, in its QUIC mode), RFC 9002's
loss detection and congestion control, RFC 9114's HTTP/3 and RFC 9204's
QPACK. The connection is sans-IO, as gslib's TLS is: it takes the
datagrams that arrive and the time, gives the datagrams to send, and says
when it next wants to be woken, so a test runs both ends in memory and a
driver carries them over UDP. Eleven modules in namespace `quic`, and two
tools, `goose-h3` and `goose-h3d`.

```goose
import gslib from "SorinS/gslib@v0.8.0";
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509.pool;
import gslib.quic;
import gslib.quic.conn;
import gslib.quic.transport;
import gslib.quic.http3;

fn main() {
    let roots, ok = x509::system_roots();
    var cfg = tls::client_config_pool("cloudflare-quic.com", roots);
    tls::add_alpn(cfg.alpn, "h3");
    var c, fd, e = quic::dial("cloudflare-quic.com", 443, cfg, 10000);
    if e != 0 { exit(1); }
    var h = quic::h3(false);
    let id = quic::h3_send_request(c, h, "GET", "https", "cloudflare-quic.com", "/", "", "");
    var body: u8[>..] = [];
    while !quic::h3_done(h, id) {
        if quic::step(fd, c, cfg, 50) != 0 { break; }
        quic::h3_poll(c, h);
        quic::h3_take_body(h, id, body);
    }
    print(quic::h3_status(h, id), " ", body.len);           // 200 125959
    quic::hang_up(fd, c, 0x100, "");
}
```

| Module | What |
|---|---|
| `quic.goose` | versions, transport error codes (`error_name`), variable-length integers: `put_varint`, `put_varint_n`, `read_varint`, the `Rd` reader |
| `quic/packet.goose` | packet protection: `initial_keys(dcid, client)`, `keys_from_secret(suite, secret)`, `next_keys` (key update), header protection (AES-ECB, ChaCha20), `seal` and `open` in place, packet numbers (`pn_length`, `decode_pn`), `retry_tag`, long and short headers (`read_header`) |
| `quic/frame.goose` | every frame of RFC 9000 §19: `read_frame` (minimal type encodings, ACK ranges checked, offsets and limits in range), `ack_ranges`, a writer for each, `frame_allowed` (§12.4's table), `ack_eliciting` |
| `quic/params.goose` | transport parameters (§18): `Params` with the RFC's defaults, `put_params`, `read_params` (duplicates, ranges, server-only ones from a client refused; unknown and GREASE ids skipped) |
| `quic/recovery.goose` | RFC 9002: RTT estimates (`update_rtt`), loss by the packet and time thresholds, the PTO with its backoff and the client's anti-deadlock probe, NewReno (slow start, recovery, persistent congestion); `on_packet_sent`, `on_ack_received`, `loss_timer`, `on_loss_timeout`, `discard_space` |
| `quic/stream.goose` | `SendBuf` and `RecvBuf`: reassembly of data out of order, overlaps and duplicates; lost data sent again before new; final sizes; the 64 KiB window |
| `quic/conn.goose` | `Conn`: `client(cfg, now)`, `server(cfg, first, now)`, `recv`, `poll`, `next_timeout`, `on_timeout`; streams (`open_stream`, `accept_stream`, `stream_write`, `stream_read`, `stream_finished`, `reset_stream`, `stop_sending`); `update_keys`; `close`, `close_error`; `server_accepts`, `version_negotiation` |
| `quic/transport.goose` | over UDP: `dial`, `step`, `hang_up` for a client; `listen`, `serve_step`, `accept`, `shut_down` for a server, its connections found by Destination Connection ID |
| `quic/qpack.goose` | QPACK with the static table only: `qpack_decode`, `qpack_encode`, `qpack_record`, `qpack_get`, Huffman, the encoder and decoder streams' instructions, request/response/trailer field rules |
| `quic/h3.goose` | HTTP/3 frames and settings, unidirectional stream types, the control stream's reader (`H3Control`), the reader of a request or response stream (`H3Message`), `h3_request`, `h3_response` |
| `quic/http3.goose` | HTTP/3 on a `Conn`: `h3(is_server)`, `h3_poll`; a client's `h3_send_request`, `h3_done`, `h3_status`, `h3_headers`, `h3_take_body`; a server's `h3_next_request`, `h3_field`, `h3_body`, `h3_respond`, `h3_respond_head` |

## The connection

`client(cfg, now)` makes a connection to the server `cfg` names (its
`alpn` must hold the protocol, "h3" for HTTP/3) and has its first
datagram ready; `server(cfg, first, now)` makes one for a client's first
Initial (`server_accepts` says whether a datagram is one). From then on:
`recv(c, cfg, datagram, now)` for each datagram that arrives,
`poll(c, now)` until it gives an empty datagram, `on_timeout(c, now)`
when `next_timeout(c)` comes. Times are microseconds.

Inside, TLS runs in its QUIC mode (`tls::quic_client`,
`tls::quic_server`, `tls::feed_crypto`): its messages go out as CRYPTO
frames tagged with their encryption level, and each new TLS secret
becomes the keys of a level. Initial, Handshake and 1-RTT packets are
coalesced into datagrams, a client's padded to 1200 bytes (and a
server's that carry an ack-eliciting Initial); a server sends no more
than three times what it received until the client's address is
validated by a Handshake packet. Initial keys are discarded when the
first Handshake packet goes (client) or comes (server), Handshake keys
when the handshake is confirmed (HANDSHAKE_DONE). The transport
parameters' connection IDs are checked as §7.3 asks:
original_destination_connection_id, initial_source_connection_id,
retry_source_connection_id when there was a Retry.

A client follows a Retry (its integrity tag checked; the Initial keys
taken from the new ID, the ClientHello sent again with the token) and
gives up on a Version Negotiation that lists no version it has; a server
answers a datagram of another version with Version Negotiation
(`version_negotiation`). Key updates go both ways: the peer's are
followed (the previous keys kept for packets reordered across the
change), and `update_keys` starts one once the last is acknowledged. A
stateless reset with the peer's token closes the connection. The idle
timeout is the smaller of the two sides' (30 s here).

Streams are the peer's up to the limits this side gives (16
bidirectional, 8 unidirectional) and this side's up to the peer's, 32
held at once; each has a 64 KiB window, the connection a 1 MiB one,
credit given back (MAX_STREAM_DATA, MAX_DATA, MAX_STREAMS) as the
application reads. A stream done both ways leaves the table.

Errors close the connection with the transport error RFC 9000 names
(FRAME_ENCODING_ERROR, PROTOCOL_VIOLATION, STREAM_STATE_ERROR,
FLOW_CONTROL_ERROR, ...), or CRYPTO_ERROR plus TLS's alert. `close(c,
code, reason)` is the application's close; the connection then waits
three PTOs answering what still comes, as §10.2 asks, and is `closed`.

## Over UDP

A client: `dial(host, port, cfg, timeout_ms)` returns the connection
and its socket once the handshake is confirmed; `step(fd, c, cfg,
max_ms)` sends what there is, waits for a datagram up to max_ms or the
next timer, takes what came and fires the timers; `hang_up` closes. A
server: `listen(addr, port)`, then `serve_step(srv, cfg, max_ms)` does
the same for every connection, routing each datagram by its Destination
Connection ID (the server's own, or for a client's first Initials the ID
the client chose), making a connection for a new client's Initial and
answering other versions with Version Negotiation; `accept` gives a new
connection's index in `srv.conns`.

## HTTP/3

`h3(is_server)` is one side's HTTP/3 state on a connection; `h3_poll(c,
h)` after each step opens this side's control stream (SETTINGS first)
and its QPACK encoder and decoder streams, reads the peer's (a second
control stream, or one that closes, is a connection error), and feeds
request and response streams to their readers. QPACK advertises no
dynamic table, so the peer can only use the static table and literals;
its encoder stream may only set the capacity to 0. A client sends
`h3_send_request(c, h, method, scheme, authority, path, headers, body)`
and reads `h3_status`, `h3_headers` and the body (`h3_take_body` as it
comes, so a body longer than 64 KiB is read); a server takes
`h3_next_request`, reads `h3_field(h, id, ":path")` and `h3_body`, and
answers with `h3_respond`, or `h3_respond_head` and the body written as
the stream takes it. A malformed message resets its stream
(H3_MESSAGE_ERROR); the frame-order and control-stream rules are
connection errors. Server push is not used.

## Tools

- `goose-h3 [-k] [--ca roots.pem] [--data BODY] [--header 'n: v']... URL`:
  a GET (or a POST of --data) of an https URL over HTTP/3, the body to
  stdout, the status and headers to stderr; the certificate checked
  against the system's roots or --ca's unless -k.
- `goose-h3d --cert chain.pem --key key.pem [--listen 127.0.0.1] [--port 4433] [--root DIR]`:
  an HTTP/3 server: files under --root (long ones written as the stream
  takes them), POST echoed, or a line naming the path; one line a
  request to stderr.

## Examples

- `examples/quic/in_memory.goose`: a client and a server in one program
  with no network: the handshake, a stream each way, the close.
- `examples/quic/h3_get.goose`: a server and a client over UDP on
  127.0.0.1 in one thread: a GET and a POST answered; with a URL, a GET
  of a real server (`-- https://cloudflare-quic.com/` gives 200 and
  126 KB).

## Tests

```bash
make test-quic                             # or: cd quic && python3 scripts/run_tests.py
make interop-quic                          # Linux with Docker
```

Every test runs at -O0, -O2 and with `--debug`:

- `test/packet.goose`: RFC 9001 Appendix A: the Initial secrets and
  keys, the client's and the server's Initial packets sealed to the
  RFC's bytes and opened, the Retry tag, a ChaCha20-Poly1305 short
  header packet and its key update secret; RFC 9000 Appendix A's
  varints and packet numbers: 26 checks.
- `test/frame.goose`: every frame type round trip, boundaries, each
  frame cut at every byte, non-minimal types, ACK ranges below zero,
  offsets past 2^62, the §12.4 table: 108 checks.
- `test/params.goose`: transport parameters both ways, defaults, every
  refusal, GREASE skipped: 30 checks.
- `test/recovery.goose`: RFC 9002's first RTT sample and smoothing with
  the ack delay, the packet and time thresholds, the PTO and its
  doubling, the client's anti-deadlock PTO, slow start, a loss halving
  the window, persistent congestion: 16 checks.
- `test/stream.goose`: reassembly out of order, overlaps, every final
  size error, the window's edge, lost data first, a lost FIN, and
  randomized transfers through a channel that loses, reorders and
  duplicates: 1379 checks.
- `test/loopback.goose`: a client and a server in memory with a
  simulated clock: the handshake and both keys discarded, 200 KB over a
  stream and an answer, a server's unidirectional stream, key updates
  started by each side, an application's close; HTTP/3: a GET and a
  POST, SETTINGS both ways; with 15% of datagrams lost and some
  reordered, the handshake and 300 KB; the idle timeout; a Retry (a bad
  tag and the client's own ID ignored, the Initial sent again to the
  new ID with the token); Version Negotiation both ways: 34 checks.
- `test/udp.goose`: the same over UDP on 127.0.0.1 through
  `quic.transport`: 6 checks.
- `test/qpack.goose`: RFC 9204 B.1, every static entry, Huffman, the
  limits and refusals, field validation: 64 checks.
- `test/h3.goose`: frames, settings, the control stream a byte at a
  time, requests and responses in pieces with trailers and interim
  responses, and each error: 61 checks.

tls's `test/quic.goose` covers the QUIC mode: both ends through CRYPTO
data only, the secrets equal, the transport parameters exchanged, ALPN
required, a HelloRetryRequest, resumption with a ticket at the 1-RTT
level, data at the wrong level, a KeyUpdate and a compatibility-mode
session ID refused: 28 checks.

`scripts/interop.py` (`make interop-quic`) runs live in Docker on
loopback, with small peers written for it on aioquic 1.2.0 and quic-go
v0.48.2: goose-h3 against aioquic's server (with and without its
Retry) and quic-go's, and their clients against goose-h3d, each a GET,
a POST echoed and 300 KB: 15 checks. A libFuzzer target (`quic`) feeds
frames to an established connection and to one in the middle of its
handshake, datagrams to both, transport parameters, QPACK and HTTP/3.

## Not done

- 0-RTT, connection migration (disable_active_migration is sent; the
  peer's new connection IDs are taken only to follow a retirement), path
  MTU discovery (datagrams stay at 1200 bytes), ECN, a server's Retry,
  NEW_TOKEN's tokens (a client ignores them).
- QPACK's dynamic table (this side never uses one, and asks the peer
  not to), server push, extended CONNECT, HTTP/3 datagrams.
- Bodies of more than 64 KiB in a request, or as one write from
  `h3_respond`; a client reads longer ones as they come, and a server
  writes them with `h3_respond_head`.
- Connections are held whole in memory (about 3 MiB each, mostly stream
  buffers); a server takes 16 at once.
