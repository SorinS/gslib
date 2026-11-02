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
| `krb5.crypto` | Encryption types (RFC 3961, 3962, 4757, 6803, 8009): des3-cbc-sha1-kd, aes128/256-cts-hmac-sha1-96, aes128-cts-hmac-sha256-128, aes256-cts-hmac-sha384-192, rc4-hmac, camellia128/256-cts-cmac: `string_to_key`, `encrypt`, `decrypt`, `checksum`, `verify_checksum`, `prf`, `prf_plus`, `fx_cf2` (RFC 6113's KRB-FX-CF2), `random_key`, n-fold, DK/DR, KDF-HMAC-SHA2, KDF-FEEDBACK-CMAC, CTS over AES or Camellia |
| `krb5.messages` | Every message of RFC 4120 §5 as a struct, decoded and encoded (DER out, DER and BER's long lengths in): tickets, AS/TGS-REQ and REP and their encrypted parts, AP-REQ, Authenticator, AP-REP, KRB-SAFE, KRB-PRIV, KRB-CRED, KRB-ERROR, PA-ENC-TS-ENC, ETYPE-INFO(2), TYPED-DATA; FAST's (RFC 6113): PA-FX-FAST request and reply, KrbFastArmor, KrbFastReq, KrbFastResponse, KrbFastFinished; principal names |
| `krb5.keytab` | MIT keytabs (versions 1 and 2, holes, 32-bit key versions): `keytab_load`, `keytab_save_private`, `keytab_key`, `keytab_entries_from_password` (ktutil's addent) |
| `krb5.ccache` | MIT FILE credential caches (versions 1 to 4, configuration entries): `ccache_load`, `ccache_save` (0600), `ccache_find`, `ccache_add`, `ccache_config`, `ccache_with_config`, `default_ccache_name` |
| `krb5.config` | krb5.conf in MIT's profile syntax (sections, subsections, `include`, `includedir`, final markers): `default_config`, the realms' KDCs, `domain_realm`, `capaths`, enctype lists, durations |
| `krb5.net` | Sending to a realm's KDCs: UDP first below `udp_preference_limit`, TCP above it or on KRB_ERR_RESPONSE_TOO_BIG, each KDC in turn, as MIT does |
| `krb5.client` | AS exchanges (`get_tgt_password`, `get_tgt_keytab`, encrypted-timestamp pre-authentication from ETYPE-INFO2, enterprise names and client referrals; armored with FAST: `get_tgt_password_fast`, `get_tgt_keytab_fast`, with encrypted challenge; `disable_encrypted_timestamp` as MIT has it), TGS exchanges (`get_service_ticket`: cross-realm along `capaths` or the hierarchy, server referrals; armored by the TGT, as MIT's are), `renew`, `forward_tgt`, clock skew learned from the KDC; `kinit_password`, `kinit_keytab`, `kinit_password_fast`, `kinit_keytab_fast` (MIT's `kinit -T`), `get_service_ticket_cached` keep a cache (with MIT's `fast_avail` entry when the KDC does FAST) |
| `krb5.fast` | FAST (RFC 6113), the client's side: armor from a TGT (`fast_armor_as`) or a TGS request's own (`fast_armor_tgs`), `fast_wrap`, the reply's checks (`fast_reply`: nonce, finished part, the ticket's checksum), `fast_reply_key` (the strengthen key), `fast_error` (the error inside the armor, the cookie), encrypted challenge both ways |
| `krb5.service` | The acceptor: `verify_ap_req` (keytab, ticket times, skew, authenticator, replay cache), `make_ap_rep`, `verify_ap_rep`, `make_ap_req` |
| `krb5.gssapi` | RFC 4121: `gss_init`, `gss_init_continue`, `gss_accept` (mutual authentication, channel bindings, delegation through KRB-CRED, acceptor subkeys), `gss_get_mic`, `gss_verify_mic`, `gss_wrap`, `gss_unwrap` (sealed or not, any RRC), sequence checks; RFC 4757's tokens for RC4 session keys |
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

`tools/krb5.goose` (goose-krb5): `kinit [-T ARMOR_CACHE] [-k KEYTAB] PRINCIPAL`, `kvno
[-gss] SERVICE`, `klist [-k KEYTAB]`, `renew`, on `$KRB5_CONFIG` and
`$KRB5CCNAME`. `tools/gss.goose` (goose-gss): a GSS-API client and server
speaking MIT's gss-sample protocol, and an HTTP Negotiate client and
server; servers listen on 127.0.0.1 only.

## Tests

`make test-krb5` (`scripts/run_tests.py`, every program at -O0, -O2,
`--debug`, and `--native`):

- `test/crypto.goose`: the vectors of RFC 3961 Appendix A (n-fold, DES3
  DR/DK and string-to-key), RFC 3962 Appendix B (PBKDF2 string-to-key,
  CTS), RFC 8009 Appendix A (string-to-key, key derivation, encryption,
  checksums, PRF) and RFC 6803 §10 (Camellia: every string-to-key,
  derivation, encryption and checksum); RC4's string-to-key; MIT's
  libk5crypto's answers for every type (`test/vectors/mit_crypto.txt`:
  string-to-key with UTF-8 passwords and explicit iteration counts, PRF,
  checksums, KRB-FX-CF2 for every pair of types, and MIT's ciphertexts
  decrypted); every type's round trips, tampering and wrong usages.
- `test/fast.goose`: FAST with the test as the KDC, for every type as the
  armor's: the armor key the KDC makes from our AP-REQ, the armored
  request (padata, checksum, inner request), replies and errors read,
  and each refused: no FAST response, another nonce, no finished part,
  an altered ticket, an unkeyed checksum, another armor key, a KDC
  challenge missing, crossed in direction or under another key.
- `test/messages.goose`: MIT's reference encodings
  (`src/tests/asn.1/reference_encode.out`, through go-krb5's
  `test_vectors.go`) decode, carry MIT's test values, and re-encode to the
  same bytes (but two whose key versions MIT writes as signed INTEGERs,
  which we read and write as RFC 4120's UInt32), KrbFastResponse and
  PA-FX-FAST-REPLY among them; truncations.
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
each other) and a third, F.TEST, whose KDC refuses the encrypted
timestamp, and 120 checks: kinit with each user (pre-auth required,
RC4-only, DES3-only, Camellia-only with pre-auth, keytab), every
encryption type for TGT and service ticket (Camellia's keys from MIT's
keytab too), cross-realm both ways, our cache in MIT's klist and kvno and
MIT's in ours, TCP only, `tcp/` and `udp/` KDCs, a silent KDC skipped,
renewal, forwardable flags, clock skew corrected against a KDC ten minutes
ahead; our initiator against MIT's gss-server (krb5, SPNEGO, sequence,
integrity-only, delegation) and MIT's gss-client against our acceptor
(the same and `-d`), RC4 session keys both ways (RFC 4757's tokens),
Camellia session keys both ways, a Camellia-only service whose ticket
and PAC signature (cmac-camellia256) are Camellia's, the PAC of MIT's
tickets verified, our HTTP
Negotiate client and `curl --negotiate` against our server. FAST in
F.TEST: kinit -T with a host keytab's TGT as armor (encrypted challenge,
a Camellia reply key under AES armor, a keytab exchange armored, a wrong
password read from the armored error), unarmored kinit refused, kvno
armored by the TGT, MIT's kinit -T armored by our cache (our
`fast_avail` entry read) and ours by MIT's, MIT's kvno with our armored
TGT, armor of another realm refused, clock skew corrected under armor (the
KDC refuses the armor's authenticator in the clear),
`disable_encrypted_timestamp` on the client; and a relay on 127.0.0.1 that alters the KDC's replies: an
AS-REP's or TGS-REP's ticket (the finished checksum fails), PA-FX-FAST
stripped from an AS-REP (refused) or a TGS-REP (its strengthened key
fails), the AS-REP's client name (the finished part's name used), the
armor stripped from an error (no retry in the clear).

`scripts/mit_crypto.py` writes `test/vectors/mit_crypto.txt`: it builds
a small C program against MIT's libk5crypto (Homebrew's `krb5`) and asks
it (MIT picks its confounders, so the ciphertexts change on every run).
`scripts/gen_vectors.py` writes the rest of `test/vectors` from go-krb5's checkout
(`--oracle`, `~/Dev/Go.Code/krb5.git` by default); `pac_oracle.txt` needs
Go, and `tools/krb5oracle/go.mod` points (`replace`) at that checkout.

## Not done yet

- PKINIT (RFC 4556, and with it anonymous PKINIT as armor: MIT's
  `kinit -n`), SPAKE, OTP. Of FAST: the hide-client-names and
  kdc-follow-referrals options, explicit armor in a TGS exchange
  (Windows' compound identity: MIT's KDC refuses it, so it waits for
  AD), armor across a realm referral (the armor TGT is for the realm
  asked), and the KDC's side.
- S4U2Self and S4U2Proxy (constrained delegation), user-to-user.
- DNS SRV discovery of KDCs (`dns_lookup_kdc`), kpasswd (RFC 3244),
  KKDCP, MEMORY/KEYRING/KCM caches.
- Windows is built for (the C has its Windows branches) but untested.
- An acceptor taking any name (`any_name`) tries the first keytab key of
  the ticket's realm, type and version, where MIT tries each in turn.
- No live Active Directory yet (`scripts/windows` makes a test DC: the
  firewall, the promotion, users, SPNs, a ktpass keytab, claims): the
  PAC and claims are checked against Windows AD PACs recorded by go-krb5
  and against MIT's live PACs, but a KDC exchange with AD, its referrals,
  a ktpass keytab, a live logon-info PAC, the LDAP GSSAPI bind with
  signing and SID lookups are untested against AD.

FAST follows MIT's client with one difference: given armor, every AS
request is armored from the first, where MIT's kinit -T tries without
it unless the armor cache says the KDC does FAST, and upgrades on
seeing PA-FX-FAST in an error (which an attacker in the middle can
strip). Its TGS exchanges are MIT's: always armored by the TGT, a reply
without FAST taken as a KDC that does not do it. We also require the
KDC's answer to our encrypted challenge, which MIT's client checks only
when it is there. The FAST response and challenge are plain SEQUENCEs, so DES3's
block padding is cut off them before they decode.

DES3 and RC4 are legacy and kept for old KDCs and keytabs only; RFC
1964's per-message tokens for DES3 session keys are not planned (such
contexts establish, but `gss_get_mic` and `gss_wrap` refuse them).

Camellia (bignum's, constant time) is checked against all of RFC
6803's vectors and against MIT (libk5crypto, PRF included, and its KDC).
The RFC doesn't give its sample encryptions' key usages: they are 0 to 4
in order.

MIT refuses PBKDF2 iteration counts below a type's default (4096 for
RFC 3962, 32768 for RFC 8009 and 6803) as weak; `string_to_key` takes
any count from 1 to 2^24, as the RFCs' own vectors need.

RFC 4757 §7.2's pseudocode puts the direction bytes of RC4 tokens the
wrong way round; we follow RFC 1964 and MIT (00 from the initiator), and
its Wrap checksum's salt is 13, not the 15 it writes, as MIT, Heimdal and
Windows have it. Its table also gives key usage 9 (the TGS-REP under a
subkey) the message type 8; MIT and Heimdal use 9, and so do we (MIT's
ciphertexts decrypt only so; go-krb5 has 8). Where go-krb5 differs
otherwise, we follow the RFCs: RC4's string-to-key encodes
the password as UTF-16LE (go-krb5 leaves gaps after non-ASCII bytes), the
RC4 usage number is little-endian (go-krb5 writes a varint, the same
below 128), and XPRESS_HUFF claims are MS-XCA's LZ77+Huffman, not HPACK's Huffman
code (go-krb5 misreads its own compressed vector). Claims compressed with
LZNT1 or plain LZ77, which AD does not use, are refused.
