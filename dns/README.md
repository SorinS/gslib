# dns

The DNS for Goose, modelled on Go's
[miekg/dns](https://github.com/miekg/dns) (v1.1.73): messages and the 79
record types miekg implements, in their wire form (with name compression) and
their text form, zone files, EDNS0, DNSSEC, TSIG and SIG(0), dynamic
updates, zone transfers, a client and a server; and two tools,
`goose-dig` and `goose-dnsd`.

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

## Tools

- **goose-dig** (`tools/dig.goose`), miekg's `q`: `goose-dig [@server]
  [-p port] [+tcp] [+dnssec] [+nord] [+cd] [+short] [+bufsize=n] [-y
  [alg:]name:secret] [-x address] [name] [type] [class]`; AXFR and
  IXFR=serial transfer the zone.
- **goose-dnsd** (`tools/dnsd.goose`), an authoritative server for zone
  files: `goose-dnsd [-a address] [-p port] [-y name:secret] [-n requests]
  [-v] origin=file ...`. Answers, CNAMEs followed within the zone,
  wildcards, referrals with glue, NXDOMAIN and NODATA with the SOA, RRSIGs
  from the zone when DO is set, AXFR and IXFR (the whole zone) over TCP,
  NOTIFY, dynamic updates applied in memory; with `-y`, transfers and
  updates must be signed.

## Tests

The oracle is miekg/dns itself: `scripts/oracle` is a Go module pinned to
v1.1.73 that writes the vectors in `test/vectors` (`go run . rr|msg|zone|
dnssec|tsig|misc`, the commands at the top of `main.go`).

`python3 scripts/run_tests.py` (`make test-dns`) runs every test/*.goose
at -O0, -O2 and `--debug` (natively too with `--native`):

| Test | What |
|---|---|
| rr | 160 records of every type, in many forms (escapes, quoted and bare strings, `\#` for known types, odd addresses, LOC, APL, SVCB parameters, TTL units, classes), read into miekg's wire bytes, written as miekg's text, and read back; 23 lines miekg refuses, refused |
| msg | 52 messages of those records in every section, with EDNS0 options, extended rcodes and opcodes: packed with compression into miekg's bytes, miekg's unpacked and written as its `Msg.String()` |
| zone | a zone file with `$ORIGIN`, `$TTL`, `$INCLUDE` (with and without an origin), `$GENERATE`, omitted owners and TTLs, parentheses and comments, read into the records miekg's `ZoneParser` reads, stopping at the same error on the same line; the same with CRLF line ends |
| dnssec | miekg's keys (RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512, ECDSA P-256 and P-384, Ed25519) read from its private-key files and written back the same; its signatures over 5 RRsets (case, wildcards, duplicates) verified, and refused after a byte changes; the same RRsets signed here into the same signatures (RSA, Ed25519) or ones that verify (ECDSA); DS and key tags; NSEC3 hashes (RFC 5155's too); RFC 8080's Ed25519 RRSIG remade exactly, RFC 6605's ECDSA one verified |
| tsig | for HMAC-SHA1, -SHA224, -SHA256, -SHA384 and -SHA512, miekg's signed query, reply (over the query's MAC) and timers-only message remade byte for byte and verified, and refused with a changed byte, a wrong secret, or the time outside the fudge; HMAC-MD5 with itself |
| sig0 | miekg's SIG(0) messages (RSASHA256, ECDSA P-256) verified, refused expired or changed; messages signed here with miekg's keys verified |
| misc | the name functions, resolv.conf and `NameList`, an update built with every helper (miekg's bytes and text), EDNS0 options (miekg's bytes and text), and `Truncate` at four sizes (miekg's bytes) |
| client | against goose-dnsd on 127.0.0.1: UDP and TCP, CNAME chains, NXDOMAIN, NODATA, wildcards, referrals, truncation and TCP fallback, DO, an AXFR of 5024 records in several TSIG-signed messages (refused unsigned), signed updates and their prerequisites, a wrong key answered NOTAUTH, NOTIFY |

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
- **The server** handles one request at a time, UDP and TCP from one loop
  (Goose threads need a native build). A request with a bad TSIG is
  answered NOTAUTH by the server itself (RFC 8945 §5.2), before the
  handler; in miekg the handler checks `TsigStatus`. Replies to signed
  requests are signed by the server.
- **Message IDs** come from the runtime's entropy (`random_seed`), not
  crypto/bignum's. Only dns.dnssec and dns.sig0 need bignum's random bytes
  (for keys), so the client, the server, TSIG and both tools run on
  Windows too.
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
