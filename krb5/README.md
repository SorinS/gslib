# krb5

Kerberos V5 (RFC 4120) for Goose, with its GSS-API mechanism (RFC 4121),
SPNEGO (RFC 4178), HTTP Negotiate (RFC 4559) and Microsoft's PAC
(MS-PAC), after [go-krb5](https://github.com/go-krb5/krb5) (the fork at
`v0.1.0-28-g7e3cb81`). Clients get TGTs (password or keytab) and service
tickets, across realms and by referral; services accept AP-REQs, GSS-API
and SPNEGO tokens with a keytab and read the PAC. Keytabs and credential
caches are MIT's file formats, readable by MIT's and Heimdal's tools and
reading theirs. Only `krb5.net`, the file functions and the tools do I/O.

| Module | What |
|---|---|
| `krb5` | The protocol's numbers (encryption, checksum and pre-authentication types, key usages, flags, name types) and error codes, with their names and texts: `error_text` |
| `krb5.crypto` | Encryption types (RFC 3961, 3962, 4757, 8009): des3-cbc-sha1-kd, aes128/256-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, aes256-cts-hmac-sha384-192, rc4-hmac: `string_to_key`, `encrypt`, `decrypt`, `checksum`, `verify_checksum`, `prf`, `random_key`, n-fold, DK/DR, KDF-HMAC-SHA2, CTS |
| `krb5.messages` | Every message of RFC 4120 §5 as a struct, decoded and encoded (DER out, DER and BER's long lengths in): tickets, AS/TGS-REQ and REP and their encrypted parts, AP-REQ, Authenticator, AP-REP, KRB-SAFE, KRB-PRIV, KRB-CRED, KRB-ERROR, PA-ENC-TS-ENC, ETYPE-INFO(2), TYPED-DATA; principal names |
| `krb5.keytab` | MIT keytabs (versions 1 and 2, holes, 32-bit key versions): `keytab_load`, `keytab_save_private`, `keytab_key`, `keytab_entries_from_password` (ktutil's addent) |
| `krb5.ccache` | MIT FILE credential caches (versions 1 to 4, configuration entries): `ccache_load`, `ccache_save` (0600), `ccache_find`, `ccache_add`, `default_ccache_name` |
| `krb5.config` | krb5.conf in MIT's profile syntax (sections, subsections, `include`, `includedir`, final markers): `default_config`, the realms' KDCs, `domain_realm`, `capaths`, enctype lists, durations |
| `krb5.net` | Sending to a realm's KDCs: UDP first below `udp_preference_limit`, TCP above it or on KRB_ERR_RESPONSE_TOO_BIG, each KDC in turn, as MIT does |
| `krb5.client` | AS exchanges (`get_tgt_password`, `get_tgt_keytab`, encrypted-timestamp pre-authentication from ETYPE-INFO2, enterprise names and client referrals), TGS exchanges (`get_service_ticket`: cross-realm along `capaths` or the hierarchy, server referrals), `renew`, `forward_tgt`, clock skew learned from the KDC; `kinit_password`, `kinit_keytab`, `get_service_ticket_cached` keep a cache |
| `krb5.service` | The acceptor: `verify_ap_req` (keytab, ticket times, skew, authenticator, replay cache), `make_ap_rep`, `verify_ap_rep`, `make_ap_req` |
| `krb5.gssapi` | RFC 4121: `gss_init`, `gss_init_continue`, `gss_accept` (mutual authentication, channel bindings, delegation through KRB-CRED, acceptor subkeys), `gss_get_mic`, `gss_verify_mic`, `gss_wrap`, `gss_unwrap` (sealed or not, any RRC), sequence checks |
| `krb5.spnego` | RFC 4178: `spnego_init`, `spnego_init_continue`, `spnego_accept` (Kerberos under RFC 4121's OID or Microsoft's, a second round when another mechanism was preferred, mechListMIC both ways, NegTokenInit2, bare Kerberos tokens); `negotiate_header`, `negotiate_token` |
| `krb5.ndr` | NDR as MS-RPCE's type serialization: the reader the PAC's types use |
| `krb5.pac` | The PAC: logon info (`LogonInfo`, `logon_sids`), client info, UPN/DNS info with its SAM-name and SID extension, S4U delegation info, device info, attributes, requestor, signatures; `pac_verify` (server signature with the service key, client info against the ticket), `pac_verify_kdc` |
| `krb5.claims` | The PAC's claims (client and device): `decode_claims`, `pac_claims`, with MS-XCA's LZ77+Huffman decompression (`xpress_huff_decompress`) for the compressed ones |
| `krb5.sys` | The C krb5 calls (`src/krb5sys.c`: UDP, files only their owner reads, the uid, host names; and http's TCP sockets) |

```goose
import gslib from "SorinS/gslib@v0.1";   // or a path to gslib.git
import gslib.krb5;
import gslib.krb5.config;
import gslib.krb5.client;
import gslib.krb5.keytab;
import gslib.krb5.service;
import gslib.krb5.spnego;
import gslib.krb5.pac;

// The client: a service ticket from the cache kinit made, then an HTTP
// Negotiate header for it.
let cfg, err = krb5::default_config();
let cred, terr = krb5::get_service_ticket_cached(cfg, krb5::default_ccache_name(), "HTTP@web.example.com", true);
let now = time_ns() / 1000000000;
var token: u8[>..] = [];
var ctx, ierr = krb5::spnego_init(cred, krb5::GSS_MUTUAL, "", false, "", now, 0, token);
let header = krb5::negotiate_header(token);   // Authorization: Negotiate ...

// The service: the token checked with its keytab, the PAC read.
let kt, kerr = krb5::keytab_load("/etc/krb5.keytab");
var rc: krb5::ReplayEntry[>..] = [];
var sctx = krb5::empty_spnego();
var reply: u8[>..] = [];
let done, acc, aerr = krb5::spnego_accept(sctx, token, kt, true, rc, now, 0, 300, "", false, reply);
let pac, found, perr = krb5::pac_verify(acc.ap, acc.ap.service_key);
for sid in krb5::logon_sids(pac.logon_info) { print(sid); }
```

Errors are codes: 0 is `krb5::OK`, 1 to 99 are the protocol's (a
KRB-ERROR's error-code), 1000 and up the library's; `error_text` names
both. Names are kept as MIT's `krb5_unparse_name` writes them without the
realm (components joined by `/`, `/`, `@` and `\` escaped), the realm
apart: `parse_principal`, `principal_string`, `name_parts`.

## Tools

`tools/krb5.goose` (goose-krb5): `kinit [-k KEYTAB] PRINCIPAL`, `kvno
[-gss] SERVICE`, `klist [-k KEYTAB]`, `renew`, on `$KRB5_CONFIG` and
`$KRB5CCNAME`. `tools/gss.goose` (goose-gss): a GSS-API client and server
speaking MIT's gss-sample protocol, and an HTTP Negotiate client and
server; servers listen on 127.0.0.1 only.

## Tests

`make test-krb5` (`scripts/run_tests.py`, every program at -O0, -O2,
`--debug`, and `--native`):

- `test/crypto.goose`: the vectors of RFC 3961 Appendix A (n-fold, DES3
  DR/DK and string-to-key), RFC 3962 Appendix B (PBKDF2 string-to-key, CTS)
  and RFC 8009 Appendix A (string-to-key, key derivation, encryption,
  checksums, PRF); RC4's string-to-key; every type's round trips,
  tampering and wrong usages.
- `test/messages.goose`: MIT's reference encodings
  (`src/tests/asn.1/reference_encode.out`, through go-krb5's
  `test_vectors.go`) decode, carry MIT's test values, and re-encode to the
  same bytes (but two whose key versions MIT writes as signed INTEGERs,
  which we read and write as RFC 4120's UInt32); truncations.
- `test/files.goose`: go-krb5's keytabs and cache (MIT-written): testuser1's
  keys are our string-to-key of its password, the cache re-encodes byte
  for byte; version 1 keytabs, holes, 32-bit key versions.
- `test/config.goose`: go-krb5's krb5.conf and MIT's syntax corners.
- `test/gssapi.goose`, `test/spnego.goose`: tickets made with known keys,
  contexts both ways, tokens, tampering, replays, channel bindings,
  delegation, Windows' and NTLM-first SPNEGO exchanges.
- `test/pac.goose`: go-krb5's PAC vectors (two from Windows AD) and its
  five uncompressed claims vectors read the same as go-krb5 reads them,
  line for line (`test/vectors/pac_oracle.txt`, from `tools/krb5oracle`);
  the server signature checked with the service's key; extended
  UPN_DNS_INFO; the compressed claims vector decompressed to its declared
  size, its claims those of the uncompressed vectors for the same user.

`make interop-krb5` (`scripts/interop.py`, macOS with Homebrew's
`krb5`): two MIT 1.22 realms (`scripts/kdc.py`, on 127.0.0.1, trusting
each other), and 57 checks: kinit with each user (pre-auth required,
RC4-only, DES3-only, keytab), every encryption type for TGT and service
ticket, cross-realm both ways, our cache in MIT's klist and kvno and
MIT's in ours, TCP only, `tcp/` and `udp/` KDCs, a silent KDC skipped,
renewal, forwardable flags, clock skew corrected against a KDC ten minutes
ahead; our initiator against MIT's gss-server (krb5, SPNEGO, sequence,
integrity-only, delegation) and MIT's gss-client against our acceptor
(the same and `-d`), the PAC of MIT's tickets verified, our HTTP
Negotiate client and `curl --negotiate` against our server.

`scripts/gen_vectors.py` writes `test/vectors` from go-krb5's checkout
(`--oracle`, `~/Dev/Go.Code/krb5.git` by default); `pac_oracle.txt` needs
Go, and `tools/krb5oracle/go.mod` points (`replace`) at that checkout.

## Not done yet

- Camellia (RFC 6803; bignum has neither Camellia nor CMAC).
- FAST (RFC 6113) and what needs it (encrypted challenge), PKINIT (RFC
  4556), SPAKE, OTP.
- S4U2Self and S4U2Proxy (constrained delegation), user-to-user.
- RFC 1964 / RFC 4757 per-message tokens: contexts with DES3 or RC4
  session keys establish, but `gss_get_mic` and `gss_wrap` refuse them.
- DNS SRV discovery of KDCs (`dns_lookup_kdc`), kpasswd (RFC 3244),
  KKDCP, MEMORY/KEYRING/KCM caches.
- Windows is built for (the C has its Windows branches) but untested.

Where go-krb5 differs, we follow the RFCs: RC4's string-to-key encodes
the password as UTF-16LE (go-krb5 leaves gaps after non-ASCII bytes), the
RC4 usage number is little-endian (go-krb5 writes a varint, the same
below 128), and XPRESS_HUFF claims are MS-XCA's LZ77+Huffman, not HPACK's Huffman
code (go-krb5 misreads its own compressed vector). Claims compressed with
LZNT1 or plain LZ77, which AD does not use, are refused.
