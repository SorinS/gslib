# websocket

WebSocket for Goose, both sides, as Go's gorilla/websocket has it: RFC
6455's framing and opening handshake, RFC 7692's permessage-deflate
with all four of its parameters, over TCP or TLS (wss), through an HTTP
proxy when asked. A client dials a URL; a server accepts a connection
itself or upgrades a request its HTTP server read (net.http's conn1).
Messages are read whole or a frame at a time, and written whole or as
they are made; pings are answered and closes echoed while reading; text
is checked as UTF-8 as it arrives. Six modules in namespace `websocket`,
and two tools, `goose-wscat` and `goose-wsecho`.

```goose
import gslib from "SorinS/gslib@v0.9.4";
import gslib.websocket;
import gslib.websocket.deflate;
import gslib.websocket.handshake;
import gslib.websocket.conn;
import gslib.websocket.client;

fn main() {
    var c = websocket::Conn { .. };
    var d = websocket::dialer();
    d.compression = true;
    if websocket::dial(c, "wss://echo.example.com/", d) != websocket::OK { exit(1); }
    websocket::write_message(c, websocket::TEXT, "hello");
    var msg: u8[>..] = [];
    let kind, e = websocket::read_message(c, msg);     // TEXT, "hello"
    websocket::close(c, websocket::CLOSE_NORMAL, "bye");
}
```

A server, gorilla's Upgrader:

```goose
import gslib.websocket.server;

let fd = net::accept(listener, 0);
var c = websocket::Conn { .. };
var u = websocket::upgrader();          // the Origin must be the Host's (gorilla's default)
u.compression = true;
u.subprotocols.append("v2.chat, v1.chat");
if websocket::accept(c, fd, u, 10000) == websocket::OK {
    var msg: u8[>..] = [];
    loop {
        let kind, e = websocket::read_message(c, msg);
        if e != websocket::OK { break; }           // ERR_CLOSED: c.close_code, c.close_reason
        websocket::write_message(c, kind, msg);
    }
}
```

| Module | What |
|---|---|
| `websocket.goose` | errors (`error_text`); opcodes (`TEXT`, `BINARY`, `CLOSE`, `PING`, `PONG`, `CONTINUATION`) and close codes (`CLOSE_NORMAL` ... `CLOSE_BAD_GATEWAY`, `valid_close_code`); frame headers (`Header`, `parse_header`, `put_header`, `put_frame`), masking (`mask_bytes`, in pieces); UTF-8 checked as it comes (`Utf8`, `utf8_feed`, `utf8_complete`, `valid_utf8`); close payloads (`put_close_payload`, `parse_close_payload`); `accept_key`, `valid_key` |
| `websocket/deflate.goose` | permessage-deflate: `Pmd` (what was agreed); the extension header (`parse_extensions`); a client's `PmdOffer` (`pmd_offer`, `put_offer`) and `check_answer`; a server's `PmdPolicy` (`pmd_policy`), `choose_offer`, `put_answer` |
| `websocket/handshake.goose` | the opening handshake without I/O: `Upgrader` (`upgrader`: origin policy `ORIGIN_SAME`, `ORIGIN_ANY`, `ORIGIN_LIST`, subprotocols, compression, more fields), `check_request` (an `Accepted`: 101 with the key, subprotocol and extension, or 400, 403, 405, 426 and why), `put_accept`, `put_refusal`; `Dialer` (`dialer`: subprotocols, Origin, compression and its offer, fields, proxy, timeout, roots, `insecure`, server name), `new_key`, `put_request`, `check_response` (an `Answer`) |
| `websocket/conn.goose` | `Conn` (a root struct), `Options` (`options`: read limit, write buffer, fragment size, compression level and threshold, `auto_pong`, `control_events`, timeouts); `read_message`; `next_message` and `read_part` (a frame at a time); `write_message`; `begin_message`, `write_part`, `end_message` (as it is made); `ping`, `pong`; `write_close`, `close` (the closing handshake), `close_now`, `closed`; without a socket: `start`, `feed`, `take_output` |
| `websocket/client.goose` | `dial` (ws:// and wss://, an HTTP proxy's CONNECT with Basic credentials from its URL), `dial_tls` (wss with a TLS configuration of the caller's: a client certificate, pinned roots) |
| `websocket/server.goose` | `accept` and `accept_tls` (the request read on the socket), `upgrade` and `upgrade_tls` (a request an HTTP server read: its head, and the bytes after it) |

## Reading and writing

`read_message` returns a whole message, TEXT or BINARY, its payload
inflated when it came compressed; pings are answered and pongs dropped
on the way unless `control_events` is set, which hands them over as
PING and PONG with the payload in `c.control`. `next_message` and
`read_part` hand over a message as its frames come (gorilla's
NextReader), each part a frame's payload or what it inflates to.
`write_message` sends a message in one frame, or in frames of
`fragment_size`; `begin_message`, `write_part` and `end_message` send
one as it is made, a frame each `write_buffer` bytes (gorilla's
NextWriter), compressed as it goes when permessage-deflate was agreed.
Pings and pongs may go between a message's frames both ways.

`close` sends a close and waits (`close_timeout_ms`) for the peer's,
skipping messages that come before it; a peer's close is echoed with
its code, and the read that met it ends with `ERR_CLOSED`, the code and
reason in `c.close_code` and `c.close_reason`. A server closes the TCP
connection first, a client waits for it a moment (§7.1.1). A
connection that ends without a close reads as `ERR_CLOSED` with
`CLOSE_ABNORMAL` (1006).

A Conn without a socket (`start` after a handshake made elsewhere, or
`upgrade` with fd -1) takes bytes from `feed` and leaves what it would
send for `take_output`; reads then end with `ERR_NEED_MORE` when they
need more, and the same call goes on where it stopped. That is how the
tests run both sides in one thread, and how a program with its own
event loop, or another transport, uses it.

## Strictness

A peer that breaks the protocol is closed with the code RFC 6455 names
for it, and the read fails:

| Refused | Close |
|---|---|
| A client's frame not masked, a server's masked (§5.1) | 1002 |
| RSV bits no extension agreed defines; RSV1 on a continuation or a control frame | 1002 |
| A reserved opcode (3-7, 11-15) | 1002 |
| A control frame fragmented or longer than 125 bytes (§5.5) | 1002 |
| A continuation with no message to continue, a new message inside one (§5.4) | 1002 |
| A 64-bit length with its top bit set (§5.2) | 1002 |
| A close of one byte, or with a code that may not be sent (1004-1006, 1015, below 1000, 1016-2999, 5000 and up) | 1002 |
| Text, or a close's reason, that is not UTF-8: at the first byte that shows it, before the frame has all come (§8.1) | 1007 |
| Compressed data that does not inflate | 1007 |
| A message past `read_limit` (32 MiB), counted after inflating, so a small frame that inflates to much is refused as it inflates | 1009 |

A length in more bytes than it needs is taken, as gorilla, Go's x/net
and Python's websockets take it. The handshake is checked whole both
ways: a server refuses a method other than GET (405), HTTP/1.0, a
missing `Connection: upgrade` or `Upgrade: websocket`, a key that is not
the base64 of 16 bytes or comes twice (400), a version other than 13
(426, naming 13), and an Origin its policy does not allow (403); a
client refuses an answer that is not 101, whose Sec-WebSocket-Accept is
not its key's, that picks a subprotocol it did not offer, or names an
extension, or permessage-deflate parameters, it did not offer.

## permessage-deflate

Both sides take part in all of RFC 7692: `server_no_context_takeover`
and `client_no_context_takeover` (the compressor starts each message
afresh, the decompressor too), and `server_max_window_bits` and
`client_max_window_bits` from 8 to 15, which the compressor keeps to:
`compress.deflate` gained `deflate_set_window_bits` for it, a match
never reaching further back than the window allows. A server takes the
first offer it can (an offer with a parameter twice, an unknown one or
a bad value is declined, as §7.1 asks), and may add its own wishes
(`PmdPolicy`: keep no history itself, have the client keep none, limit
the client's window when the client allows it). A client offers
`client_max_window_bits` so that the server may limit it, and holds the
answer to its offer. A message may end its DEFLATE stream with a final
block, and the next one then starts a new stream that still reaches
back into the old one's output (§7.2.3.4): `compress.flate` gained
`inflate_continue` for it. Messages below `compress_threshold` go
uncompressed.

## Tools

```bash
goose-wsecho [--port 9001] [--cert chain.pem --key key.pem] [--stream] [--no-compression]
goose-wscat -x hello -x world --compression ws://127.0.0.1:9001/
echo hello | goose-wscat wss://echo.example.com/ --cacert ca.pem
```

goose-wsecho echoes every message, whole or (`--stream`) a frame at a
time, each connection on a thread of its own; goose-wscat sends stdin's
lines (or each `-x`) and prints what comes back, as npm's wscat.

## Examples

- `examples/websocket/echo.goose`: a server on a thread and a client
  over loopback: compressed messages, one in parts, a ping, the close.
- `examples/websocket/in_memory.goose`: net.http's conn1 reads an
  ordinary request and an upgrade on one connection; the upgraded
  connection then runs on bytes the program carries.

## Tests

```bash
make test-websocket                        # or: cd websocket && python3 scripts/run_tests.py
make interop-websocket                     # Linux with Docker
```

Every test runs at -O0, -O2 and with `--debug`:

- `test/frames.goose`: RFC 6455 §5.7's frames byte for byte, every
  length at its boundaries, headers cut short, masking in pieces, UTF-8
  failing at the right byte, close payloads and codes, §1.3's key:
  330 checks.
- `test/handshake.goose`: a server's every check and the status it
  answers, origins, subprotocols, permessage-deflate's offers and
  answers both ways (declined offers, values, the client keeping to its
  own offer), a client's checks of the answer, and a handshake with
  frames right behind the request: 94 checks.
- `test/conn.goose`: a client and a server Conn joined in memory:
  messages of every size both ways, fed whole and a byte at a time,
  fragments with pings between them, parts, the closing handshake,
  every violation in the table above, RFC 7692 §7.2.3's frames, a new
  stream after a final block, a decompression bomb, and
  permessage-deflate with every combination of its parameters and
  every window from 8 to 15 bits: 4078 checks.

`scripts/interop.py` (`make interop-websocket`) runs live in Docker on
loopback:

- Autobahn|Testsuite's fuzzingclient against goose-wsecho, every case
  (framing, pings and pongs, reserved bits and opcodes, fragmentation,
  UTF-8 in every way it can fail, limits and performance, the closing
  handshake, and permessage-deflate with every parameter), messages
  echoed whole and a frame at a time; its fuzzingserver against gslib's
  client (`test/interop_autobahn.goose`), both ways too: 517 cases in
  each of the four runs, 514 OK and 3 informational, none non-strict,
  failed or unimplemented.
- Python's websockets library: its client against goose-wsecho (sizes
  to 1 MiB, compression on and off, fragments, ping, subprotocols, the
  close code), and goose-wscat against its server.

`fuzz/targets/websocket.goose` fuzzes the Conn as server and client
(with and without permessage-deflate, whole messages and frames), the
handshake's checks and the extension header.

## Not done

- WebSocket over HTTP/2 (RFC 8441, extended CONNECT): `http.h2` would
  need SETTINGS_ENABLE_CONNECT_PROTOCOL and the `:protocol`
  pseudo-header, and a Conn whose bytes are an HTTP/2 stream's DATA;
  the Conn's I/O is separate from its protocol, so it can carry them,
  but neither side is written.
- Following redirects in `dial` (gorilla does not either), SOCKS
  proxies, and HTTPS proxies (TLS to the proxy).
- Extensions other than permessage-deflate.
