# dns

The DNS for Goose, modelled on Go's
[miekg/dns](https://github.com/miekg/dns) (v1.1.73): messages and the 79
record types miekg implements, in their wire form (with name compression) and
their text form, zone files, EDNS0, DNSSEC, TSIG and SIG(0), dynamic
updates, zone transfers, a client and a server; and two tools,
`goose-dig` and `goose-dnsd`.

DNSSEC here is the primitives (signing, verifying one RRSIG with one
DNSKEY, DS, NSEC3 hashing and matching), as in miekg: there is no
validating resolver, nothing that builds a chain of trust from a root
anchor or proves non-existence. A caller who needs validated answers
must do that walk itself, or ask a validating resolver it trusts.

| Module | What |
|---|---|
| `dns` | errors; the numbers and names of types, classes, rcodes and opcodes; domain names: wire and text forms, escapes, labels, comparison, canonical order, `reverse_addr` |
| `dns.rdata` | each type's rdata, described by a layout (as miekg's struct tags describe it): checking, decompressing, canonical form, text |
| `dns.msg` | records and lists of them, questions, messages: `pack` (with compression), `unpack`, `msg_string`, `set_question`, `set_reply`, `truncate`, `dedup` |
| `dns.zone` | the text form read: `new_rr`, `parse_zone` with `$ORIGIN`, `$TTL`, `$INCLUDE`, `$GENERATE` |
| `dns.edns` | the OPT record and its options |
| `dns.dnssec` | key tags, DS, RRSIG signing and verification, validity periods, NSEC3 hashes, key generation, BIND private-key files |
| `dns.tsig` | TSIG (RFC 8945) on packed messages |
| `dns.sig0` | SIG(0) (RFC 2931), with dns.dnssec's keys |
| `dns.update` | dynamic update (RFC 2136) messages |
| `dns.client` | queries over UDP and TCP, zone transfers in, resolv.conf |
| `dns.server` | serving over UDP and TCP, with the handler a block |

All of them are in the namespace `dns`, as miekg's are in one package.

```goose
import gslib from "SorinS/gslib@v0.1";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.zone;
import gslib.dns.client;

fn main() {
    var m = dns::Msg { .. };
    dns::set_question(m, "example.org.", dns::TYPE_MX);
    dns::set_edns0(m, 1232, true);
    var c = dns::Client { .. };
    c.tcp_fallback = true;
    var r = dns::Msg { .. };
    if dns::exchange(c, m, "9.9.9.9", r) != dns::OK { return; }
    print(dns::msg_string(r));
    dns::each_rr(r.answer) { rr =>
        if rr.rtype == dns::TYPE_MX { print(dns::rr_string(r.answer, rr)); }
    };
}
```

## How records are held

miekg gives each type a struct behind the `RR` interface. Goose has no
interfaces and no garbage collector, so a record here is its wire form,
uncompressed: owner name, type, class, TTL, rdata length, rdata (names in
it uncompressed too). A list of records (a section, a zone, an RRset) is
such records back to back in a `u8[>..]`, and an `Rr` is where one of them
is in its list: offsets, which `name(rr, list)`, `rdata(rr, list)` and the
like read through.

```goose
var rrs: u8[>..] = [];
dns::new_rr(rrs, "www.example.org. 300 IN AAAA 2001:db8::1");
dns::new_rr(rrs, "www.example.org. 300 IN AAAA 2001:db8::2");
dns::each_rr(rrs) { rr => print(rr.ttl, " ", dns::rr_string(rrs, rr)); };
```

A `Msg` is a root struct: the header's fields (`hdr`), `compress`, and the
question and three sections as such lists, as miekg's `Msg` has them. A
name is its wire form too (`dns::Name`, at most 255 bytes); text goes in
and out at the edges with `name_parse` and `name_text`, escaped as miekg
escapes it.

Each type's rdata is described by a layout, one character per field
(`dns/rdata.goose` lists them: integers, names that may or may not be
compressed, addresses, character-strings, hex, base64, base32, type
bitmaps, and the types with their own grammar: LOC, APL, IPSECKEY,
AMTRELAY, HIP, SVCB/HTTPS). One walk over a layout checks rdata, finds its
names (to decompress, compress or lower-case them) and writes its text.
Which names may be compressed, and which are lower-cased for DNSSEC, are
miekg's lists (`cdomain-name`; RFC 4034 §6.2 less HINFO). A type without a
layout is unknown and kept opaque, written as RFC 3597's `\# n hex`.

## API, as miekg's

| miekg | here |
|---|---|
| `NewRR(s)`, `ZoneParser` | `new_rr(list&, s)`, `parse_zone(text, ZoneOptions, list&) -> ZoneResult` (`err`, `line`, `msg`) |
| `RR.String()`, `Msg.String()` | `rr_string(list, rr)`, `msg_string(m)` |
| `Msg.Pack()`, `Msg.Unpack(b)` | `pack(m&, out&)`, `unpack(b, m&)` |
| `PackRR`, `UnpackRR` | records are already their uncompressed wire; `unpack_rr(msg, off, list&)` |
| `SetQuestion`, `SetReply`, `SetRcode`, `SetEdns0`, `IsEdns0`, `Truncate`, `Copy` | `set_question`, `set_reply`, `set_rcode`, `set_edns0`, `opt_offset`, `truncate`, `copy_msg` |
| `Id()` | `new_id()` |
| `IsDuplicate`, `Dedup` | `rr_duplicate`, `dedup` |
| `CountLabel`, `SplitDomainName`, `CompareDomainName`, `IsSubDomain`, `Fqdn`, `IsFqdn`, `CanonicalName`, `IsDomainName`, `ReverseAddr` | `label_count`, `split_domain_name`, `common_labels`, `is_subdomain`, `fqdn`, `is_fqdn`, `canonical_name`, `is_domain_name`, `reverse_addr` |
| `EDNS0_*` options | `each_option`, `option_append`, `add_option`, `find_option`; `subnet_data`, `keepalive_data`, `ede_data`; `opt_udp_size`, `opt_do`, `opt_version`, ... |
| `DNSKEY.KeyTag`, `ToDS`, `Generate`, `PrivateKeyString`, `ReadPrivateKey` | `key_tag`, `ds_rdata`, `generate_key`, `private_key_string`, `read_private_key` |
| `RRSIG.Sign`, `Verify`, `ValidityPeriod` | `sign_rrset`, `verify_rrsig`, `validity_period` |
| `HashName`, `NSEC3.Cover`, `Match` | `nsec3_label` (and `nsec3_hash`), `nsec3_cover`, `nsec3_match` |
| `TsigGenerate`, `TsigVerify` | `tsig_sign` (and `tsig_sign_error`), `tsig_verify`, `tsig_strip`, `tsig_key` |
| `SIG.Sign`, `SIG.Verify` | `sig0_sign`, `sig0_verify` |
| `SetUpdate`, `Insert`, `Remove`, `RemoveRRset`, `RemoveName`, `Used`, `NameUsed`, `NameNotUsed`, `RRsetUsed`, `RRsetNotUsed` | the same names in snake case |
| `Client.Exchange`, `Exchange` | `exchange(client, m&, server, r&)`, `query(server, name, type, r&)` (EDNS0, TCP after a truncated reply) |
| `Transfer.In` | `transfer_in(client, m&, server) { r => ... }`: each message as it arrives |
| `ClientConfigFromFile`, `NameList` | `client_config_file`, `client_config`, `name_list` |
| `Server`, `HandleFunc`, `Transfer.Out` | `server_open(cfg)`, `serve(srv, cfg) { req, resp, peer => ... }`; a TCP reply too big for one message is split, so a handler answers AXFR by putting the zone in its answer |

`serve`'s handler is a block, so a `return` in it returns from the
function that called `serve`, ending the server, as it would in a `for`
body. To answer early, fill in `resp` and end that call of the block with
`guard cond;` (the rest runs only where `cond` holds) or an `if`/`else`.
`peer.addr` is the client's address over both UDP and TCP.

## Tools

- **goose-dig** (`tools/dig.goose`), miekg's `q`: `goose-dig [@server]
  [-p port] [+tcp] [+dnssec] [+nord] [+cd] [+short] [+bufsize=n] [-y
  [alg:]name:secret] [-x address] [name] [type] [class]`; AXFR and
  IXFR=serial transfer the zone.
- **goose-dnsd** (`tools/dnsd.goose`), an authoritative server for zone
  files: `goose-dnsd [-a address] [-p port] [-y [alg:]name:secret] [-u]
  [-n requests] [-v] origin=file ...`. Answers, CNAMEs followed within the
  zone, wildcards, referrals with glue, NXDOMAIN and NODATA with the SOA,
  RRSIGs from the zone when DO is set, AXFR and IXFR (the whole zone) over
  TCP, NOTIFY, dynamic updates applied in memory. Transfers and updates
  must be signed with the `-y` key (an algorithm given pins it); **without
  `-y` they are REFUSED** unless `-u` allows them unsigned from anyone (an
  earlier version allowed them by default). Updates get RFC 2136's checks:
  §3.2's on prerequisites and §3.4.1's prescan (class, meta types, TTLs and
  rdata of deletes, complete rdata on adds), FORMERR for what fails; an
  added SOA replaces the old only when its serial is newer, and the apex
  keeps its last NS.

## Examples

In gslib's `examples/dns/`, run from gslib's top as `goose examples/dns/<name>.goose`
(or from that folder); each checks its own results.

- `query_reply.goose`: a query and its reply built, packed, unpacked and printed as dig does, and truncation.
- `records.goose`: records in text and wire form, and domain-name functions.
- `parse_zone.goose`: `example.zone` parsed, its records counted and looked up, and a broken zone's error line.
- `edns.goose`: EDNS0 options: cookie, client subnet, NSID, keepalive, Extended DNS Error.
- `dnssec_sign.goose`: keys made, RRsets signed and verified, a DS, BIND private-key files, NSEC3.
- `tsig.goose`: a TSIG-signed query and reply, and what is refused.
- `sig0.goose`: an update signed with SIG(0) and verified.
- `dyn_update.goose`: a dynamic update built and applied to a zone in memory.
- `loopback.goose`: the server and the client in one process over UDP on 127.0.0.1, TSIG included.
- `query.goose`: a dig-like client: UDP falling back to TCP, AXFR: `[@SERVER[:PORT]] NAME [TYPE] [+tcp]`. Needs a live server; `run_tests.py` only type-checks it.
- `serve.goose`: an authoritative server for `example.zone` (or a zone file given) on 127.0.0.1, for `query` to ask. It serves until stopped, so `run_tests.py` only type-checks it.

## Tests

The oracle is miekg/dns itself: `scripts/oracle` is a Go module pinned to
v1.1.73 that writes the vectors in `test/vectors` (`go run . rr|msg|zone|
dnssec|tsig|misc`, the commands at the top of `main.go`).

`python3 scripts/run_tests.py` (`make test-dns`) runs every test/*.goose
at -O0, -O2 and `--debug` (natively too with `--native`):

| Test | What |
|---|---|
| rr | 160 records of every type, in many forms (escapes, quoted and bare strings, `\#` for known types, odd addresses, LOC, APL, SVCB parameters, TTL units, classes), read into miekg's wire bytes, written as miekg's text, and read back; 23 lines miekg refuses, refused |
| msg | 52 messages of those records in every section, with EDNS0 options, extended rcodes and opcodes: packed with compression into miekg's bytes, miekg's unpacked and written as its `Msg.String()`; hostile ones: HIP past 65535 bytes decompressed, SOA, RRSIG, NSEC3 and MX cut short or empty refused, update deletes and empty bitmaps taken |
| zone | a zone file with `$ORIGIN`, `$TTL`, `$INCLUDE` (with and without an origin), `$GENERATE`, omitted owners and TTLs, parentheses and comments, read into the records miekg's `ZoneParser` reads, stopping at the same error on the same line; the same with CRLF line ends; `new_rr` refusing `$INCLUDE` and an empty token; records without rdata |
| dnssec | miekg's keys (RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512, ECDSA P-256 and P-384, Ed25519) read from its private-key files and written back the same; its signatures over 5 RRsets (case, wildcards, duplicates) verified, and refused after a byte changes; the same RRsets signed here into the same signatures (RSA, Ed25519) or ones that verify (ECDSA); DS and key tags; NSEC3 hashes (RFC 5155's too); RFC 8080's Ed25519 RRSIG remade exactly, RFC 6605's ECDSA one verified; a revoked key; NSEC3 records cut short or over 150 iterations |
| tsig | for HMAC-SHA1, -SHA224, -SHA256, -SHA384 and -SHA512, miekg's signed query, reply (over the query's MAC) and timers-only message remade byte for byte and verified, and refused with a changed byte, a wrong secret, or the time outside the fudge; HMAC-MD5 with itself; a MAC size past the message, BADKEY for an unknown algorithm, the server's fudge cap, a keyed AXFR refusing an unsigned message |
| sig0 | miekg's SIG(0) messages (RSASHA256, ECDSA P-256) verified, refused expired or changed; messages signed here with miekg's keys verified; a signer past the rdata refused |
| misc | the name functions, resolv.conf and `NameList`, an update built with every helper (miekg's bytes and text), EDNS0 options (miekg's bytes and text), and `Truncate` at four sizes (miekg's bytes); EDE text escaped |
| client | against goose-dnsd on 127.0.0.1: UDP and TCP, CNAME chains, NXDOMAIN, NODATA, wildcards, referrals, truncation and TCP fallback, DO, an AXFR of 5024 records in several TSIG-signed messages (refused unsigned), signed updates and their prerequisites, a wrong key answered NOTAUTH, NOTIFY; updates RFC 2136 refuses (rdata cut short, meta types, TTLs on deletes and prerequisites), the apex's last NS kept, an SOA replaced only by a newer one |
| server | in one process: the handler's Peer over UDP and TCP on 127.0.0.1 and ::1; UDP replies capped at 1232; BADVERS, and FORMERR for two OPTs or a short option; a TCP client stopped mid-query holding up no UDP query; `tcp_queries` |

`python3 scripts/interop.py` (`make interop-dns`, needs Go; dig if
installed): dig against goose-dnsd (answers, truncation, a TSIG-signed AXFR
that dig verifies across its 6 messages); miekg's client against
goose-dnsd (UDP, TCP, TSIG, an AXFR whose every message miekg's `Transfer`
verifies, a signed update); goose-dig against a miekg server (truncation,
TSIG, a signed AXFR from `Transfer.Out`). 26 checks.

`python3 scripts/differential.py` (`make differential-dns`): the vectors
made again by miekg, with fresh keys and signatures, checked by the same
tests.

Tested on macOS (arm64) with Go 1.25 and dig 9.10.6; on Ubuntu 20.04
(x86-64, Python 3.8) with Go 1.22 and dig 9.18, whose DNS cookies found
OPT records with options refused by an earlier version of the unpacker;
and on Windows Server (MSVC, Winsock), where every test but dnssec and
sig0 passes, the client test against a goose-dnsd built there included:
those two need crypto/bignum's random bytes, which Windows does not have
yet (the top README's Requirements).

## Departures from miekg

- **Records are bytes, not structs** (above). Typed access is through the
  text form or the rdata's layout; there are no per-type Go-style fields.
- **AMTRELAY**: miekg drops the gateway when the D-bit is set (it switches
  on the type byte with the bit still in it); here the gateway is kept.
- **NSEC type lists** are sorted here; miekg refuses a list out of order
  when it packs it.
- **RFC 3597 rdata** (`\# n hex`) for a known type must fit that type
  exactly; miekg keeps what it can read and drops the rest.
- **The server** drops a request shorter than a DNS header unanswered (as
  miekg and BIND do), and handles one request at a time, UDP and TCP from one loop
  (Goose threads need a native build). A TCP connection has `idle_ms`
  (8 s) for each query, all of its bytes, and as long for each reply to go
  out; it is closed after `tcp_queries` (128) queries, and UDP is served
  between its bytes, so a slow client stalls no one else. A UDP reply is
  cut to the client's EDNS0 size but to no more than `max_udp_size`
  (1232), so a forged small query draws no large reply; when a datagram
  cannot be sent, a bare truncated reply goes instead. More than one OPT
  record or options cut short get FORMERR, an EDNS version above 0 BADVERS
  (RFC 6891). A request with a bad TSIG is answered NOTAUTH by the server
  itself (RFC 8945 §5.2), before the handler; in miekg the handler checks
  `TsigStatus`. Its time must be within the server's `tsig_fudge`, not the
  fudge the request names, and `tsig_alg` pins the key's algorithm.
  Replies to signed requests are signed by the server.
- **Rdata must be complete**: miekg's unpacker stops quietly at any field
  boundary (an SOA of two names, an RRSIG without its signature); here
  every field of the type must be there, and only the fields that run to
  the end (bitmaps, hex, base64, SVCB parameters) may be empty. SVCB and
  HTTPS parameters are checked inside, as miekg unpacks them: alpn's ids
  fill it exactly, mandatory is pairs of bytes, port two bytes, the hints
  whole addresses, no-default-alpn and ohttp empty. Rdata may
  be empty only in dynamic update's deletes and prerequisites (class ANY
  or NONE) or where the whole of it may be; the same holds for `list_valid`
  and for zone files (`ZoneOptions.empty_rdata` allows it; `new_rr` sets it,
  for update deletes written as text). Rdata that decompresses past 65535
  bytes is ERR_BUF.
- **LOC** in text is held to RFC 1876's ranges: latitude to 90°,
  longitude to 180°, altitude from -100000 m to 42849672.95 m; an
  infinite or NaN number is refused.
- **`new_rr` reads no `$INCLUDE`** (miekg's `NewRR` does): text from
  elsewhere would otherwise read files. `parse_zone` reads it when
  `ZoneOptions.include` is set.
- **Zone transfers with a key**: every message must be signed. RFC 8945
  §5.3.1 lets a server sign only every 100th, and miekg takes the unsigned
  ones between, but those could come from anyone on the path.
- **NSEC3**: `nsec3_match` and `nsec3_cover` take no record with more than
  150 iterations (`NSEC3_MAX_ITERATIONS`, RFC 9276 §3.2) and no malformed
  one. A DNSKEY with the REVOKE flag (RFC 5011) verifies only an RRSIG over
  the DNSKEY RRset.
- **EDNS0 text** (NSID, EDE, ESU, ZONEVERSION) is written with bytes outside
  printable ASCII as `\DDD`; miekg writes them as they are.
- **Message IDs** come from the runtime's entropy (`random_seed`), not
  crypto/bignum's. Only dns.dnssec and dns.sig0 need bignum's random bytes
  (for keys), so the client, the server, TSIG and both tools run on
  Windows too; there `random_seed` may fall back to the clocks, which
  makes IDs guessable (use TSIG, or TCP, against spoofing there).
- **RRSIG records made here** have the RRset's TTL (RFC 4034 §3); miekg
  leaves the RRSIG's own TTL to the caller.

Kept as miekg has them: `$GENERATE`'s records default to TTL 3600, not the
`$TTL` in force; class 255 is written `CLASS255` (ANY is a type too).

## Limits

- No DNS over TLS or HTTPS, no Unix sockets, no `Server.Shutdown` (`serve`
  returns after `max_requests`, or when the handler returns from its own
  function).
- DNSSEC: no DSA, RSAMD5, GOST or Ed448; DS digests SHA-1, SHA-256 and
  SHA-384. SIG(0) with RSA and ECDSA, as miekg verifies it.
- TSIG: a truncated MAC (RFC 8945 §5.2.2.1) is not accepted; no TKEY
  negotiation (GSS-TSIG), TKEY records are read and written only.
- No private RR types (miekg's `PrivateRR`), no IDN conversion (miekg's
  `idn` package).
- goose-dnsd gives no NSEC or NSEC3 proofs of non-existence, and IXFR is
  always the whole zone.
- No validating resolver (above): DNSSEC primitives only.
