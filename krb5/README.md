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
| `krb5.config` | krb5.conf in MIT's profile syntax (sections, subsections, `include`, `includedir`, final markers): `config_load` (a `:`-separated list, as `$KRB5_CONFIG`; files that cannot be read are skipped, `ERR_FILE` when none can), `default_config` (empty when no file is there, as MIT's), the realms' KDCs, `domain_realm`, `capaths`, enctype lists, durations |
| `krb5.net` | Sending to a realm's KDCs: UDP first below `udp_preference_limit`, TCP above it or on KRB_ERR_RESPONSE_TOO_BIG, each KDC in turn, as MIT does |
| `krb5.client` | AS exchanges (`get_tgt_password`, `get_tgt_keytab`, encrypted-timestamp pre-authentication from ETYPE-INFO2, enterprise names and client referrals; armored with FAST: `get_tgt_password_fast`, `get_tgt_keytab_fast`, with encrypted challenge; SPAKE when the KDC offers it, armored or not, its optimistic challenge taken; `disable_encrypted_timestamp` as MIT has it; PKINIT: `get_tgt_identity`, anonymous `get_tgt_anonymous`), TGS exchanges (`get_service_ticket`: cross-realm along `capaths` or the hierarchy, server referrals; armored by the TGT, as MIT's are), `renew`, `forward_tgt`, clock skew learned from the KDC; `kinit_password`, `kinit_keytab`, `kinit_password_fast`, `kinit_keytab_fast` (MIT's `kinit -T`), `kinit_identity` (`kinit -X`, armored or not), `kinit_anonymous` (`kinit -n`), `get_service_ticket_cached` keep a cache (with MIT's `fast_avail` entry when the KDC does FAST) |
| `krb5.fast` | FAST (RFC 6113), the client's side: armor from a TGT (`fast_armor_as`) or a TGS request's own (`fast_armor_tgs`), `fast_wrap`, the reply's checks (`fast_reply`: nonce, finished part, the ticket's checksum), `fast_reply_key` (the strengthen key), `fast_error` (the error inside the armor, the cookie), encrypted challenge both ways |
| `krb5.pkinit` | PKINIT (RFC 4556) with RFC 8636's KDFs (SHA-1, -256, -384, -512) and octetstring2key, freshness tokens (RFC 8070) and anonymous PKINIT (RFC 8062, PA-PKINIT-KX checked): Diffie-Hellman in MODP 2048 and 4096 and P-256, P-384, P-521 (`pkinit_dh_min_bits`; another group from the KDC's TD-DH-PARAMETERS); the AuthPack signed in CMS (`x509.cms`) by an RSA or ECDSA key; the KDC's certificate checked against `pkinit_anchors` (`pkinit_pool`, `pkinit_kdc_hostname`, `pkinit_eku_checking` as MIT reads them); identities `FILE:cert[,key]` and `PKCS12:file` (`pkinit_load_identity`) |
| `krb5.spake` | SPAKE pre-authentication (draft-ietf-kitten-krb-spake-preauth, MIT 1.17+), the client's side with SF-NONE: the four groups (edwards25519, P-256, P-384, P-521; `spake_preauth_groups` as MIT names them, edwards25519 by default), PA-SPAKE's messages, w, the transcript hash and K'[n]; `spake_on_challenge`, `spake_response` |
| `krb5.service` | The acceptor: `verify_ap_req` (keytab, ticket times, skew, authenticator, replay cache), `make_ap_rep`, `verify_ap_rep`, `make_ap_req` |
| `krb5.gssapi` | RFC 4121: `gss_init`, `gss_init_continue`, `gss_accept` (mutual authentication, channel bindings, delegation through KRB-CRED, acceptor subkeys), `gss_get_mic`, `gss_verify_mic`, `gss_wrap`, `gss_unwrap` (sealed or not, any RRC), sequence checks; RFC 4757's tokens for RC4 session keys |
| `krb5.spnego` | RFC 4178: `spnego_init`, `spnego_init_continue`, `spnego_accept` (Kerberos under RFC 4121's OID or Microsoft's, a second round when another mechanism was preferred, mechListMIC both ways, NegTokenInit2, bare Kerberos tokens); `negotiate_header`, `negotiate_token`; NTLM as the mechanism on gslib's ntlm (`spnego_ntlm_*`: both sides, mechListMIC with the NTLM keys, bare NTLMSSP tokens; ntlm/README.md) |
| `krb5.ndr` | NDR as MS-RPCE's type serialization: the reader the PAC's types use |
| `krb5.pac` | The PAC: logon info (`LogonInfo`, `logon_sids`), client info, UPN/DNS info with its SAM-name and SID extension, S4U delegation info, device info, attributes, requestor, signatures; `pac_verify` (server signature with the service key, client info against the ticket), `pac_verify_kdc` |
| `krb5.claims` | The PAC's claims (client and device): `decode_claims`, `pac_claims`, with MS-XCA's LZ77+Huffman decompression (`xpress_huff_decompress`) for the compressed ones |
| `krb5.sys` | The C krb5 calls (`src/krb5sys.c`: UDP, files only their owner reads, the uid, host names; TCP is gslib's `net` module, `net::dial`) |

```goose
import gslib from "SorinS/gslib@v0.7.0";   // or a path to gslib.git
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

`tools/krb5.goose` (goose-krb5): `kinit [-T ARMOR_CACHE] [-k KEYTAB | -X
X509_user_identity=FILE:cert[,key] | -X X509_user_identity=PKCS12:file] PRINCIPAL`,
`kinit -n @REALM` (anonymous), `kvno
[-gss] [-T ARMOR_CACHE] SERVICE` (with -T: from the KDC, the TGS request
armored by the cache's TGT, a computer's for AD's compound identity),
`klist [-k KEYTAB]`, `renew`, on `$KRB5_CONFIG` and
`$KRB5CCNAME`. `tools/gss.goose` (goose-gss): a GSS-API client and server
speaking MIT's gss-sample protocol, and an HTTP Negotiate client and
server; servers listen on 127.0.0.1 only.

## Examples

In gslib's `examples/krb5/`, run from gslib's top as `goose examples/krb5/<name>.goose`
(or from that folder); each checks its own results.

- `string_to_key.goose`: keys from a password for each encryption type, encryption with key usages, checksums, the PRF.
- `keytab.goose`: a service keytab written, read back and listed like `klist -k`.
- `ccache.goose`: a credential cache written, read back and listed like `klist`.
- `config.goose`: krb5.conf: realms, KDCs, domain_realm, capaths, an app's own section.
- `messages.goose`: a password login's messages built and decoded on both sides: AS-REQ, PREAUTH_REQUIRED, PA-ENC-TIMESTAMP.
- `gss_context.goose`: a client and a service authenticating each other in memory: AP-REQ/AP-REP, a GSS-API context, Wrap and MIC.
- `http_negotiate.goose`: SPNEGO over HTTP Negotiate in memory, with mutual authentication.
- `read_pac.goose`: an AD PAC from the test vectors: its signature, the user, the groups and claims.
- `kinit.goose`: a TGT into a cache: password, keytab, PKINIT or FAST: `KRB5_CONF CCACHE ...`. Needs a live KDC; `run_tests.py` only type-checks it.
- `service_ticket.goose`: a service ticket from the cached TGT, and its Negotiate header: `KRB5_CONF CCACHE ...`. Needs a live KDC; `run_tests.py` only type-checks it.

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
  decrypted); every type's round trips, tampering and wrong usages;
  unkeyed checksums made but never verified.
- `test/fast.goose`: FAST with the test as the KDC, for every type as the
  armor's: the armor key the KDC makes from our AP-REQ, the armored
  request (padata, checksum, inner request), replies and errors read,
  and each refused: no FAST response, another nonce, no finished part,
  an altered ticket, an unkeyed checksum, another armor key, a KDC
  challenge missing, crossed in direction or under another key; a TGS
  request's implicit armor and its explicit armor by another TGT, each
  key the one the KDC makes.
- `test/spake.goose`: every vector of the SPAKE draft's Appendix C
  (`test/vectors/spake.txt`, from `scripts/spake_vectors.py`): DES3, RC4,
  AES128 and AES256 on edwards25519, AES256 on P-256, P-384 and P-521, an
  optimistic challenge taken and one refused: w, w reduced, x*G and y*G,
  T, S, K from both sides, the support and challenge messages byte for
  byte, both transcript hashes and K'[0..3]; then the client's own path
  through them (its response's factor decrypted with the KDC's K'[1], its
  reply key K'[0], bound to the request body); keys that are not points,
  the identity (w*M sent as T), a small-order point added to it; a
  challenge without SF-NONE or in a group we lack; malformed messages;
  fresh exchanges in each group for each type.
- `test/pkinit.goose`: octetstring2key against RFC 4556 Appendix B's
  four sets; RFC 8636's KDF against its §8 vectors (SHA-1 and SHA-256
  for AES256; SHA-512 for DES3, whose stated key length is wrong);
  Diffie-Hellman in each group, both sides agreeing, the KDC's values
  refused (0, 1, p-1, -2 outside the subgroup, too long, not an INTEGER,
  off the curve); TD-DH-PARAMETERS; PA-PK-AS-REP, KDCDHKeyInfo and
  TYPED-DATA read and refused. Then replies signed here as the KDC
  signs them, with OpenSSL's certificates and KDC key
  (`test/vectors/pkinit.txt`, from `scripts/pkinit_vectors.py`): the
  reply key the KDC's by each KDF and by octetstring2key, in P-256 and
  MODP 2048; refused: another nonce, another realm's KDC, an expired or
  untrusted KDC certificate, a KDF we did not offer or do not know,
  another content type, no signer, a value off the curve; a KDC named by
  host only with `pkinit_kdc_hostname` and the EKU asked for; one named
  by id-pkinit-san with EKU serverAuth taken (as MIT); PA-PKINIT-KX.
- `test/messages.goose`: MIT's reference encodings
  (`src/tests/asn.1/reference_encode.out`, through go-krb5's
  `test_vectors.go`) decode, carry MIT's test values, and re-encode to the
  same bytes (but two whose key versions MIT writes as signed INTEGERs,
  which we read and write as RFC 4120's UInt32), KrbFastResponse and
  PA-FX-FAST-REPLY among them; truncations.
- `test/files.goose`: go-krb5's keytabs and cache (MIT-written): testuser1's
  keys are our string-to-key of its password, the cache re-encodes byte
  for byte; version 1 keytabs, holes, 32-bit key versions.
- `test/config.goose`: go-krb5's krb5.conf and MIT's syntax corners;
  des3 and rc4 only with `allow_des3`/`allow_rc4`; the floor on a KDC's
  s2kparams.
- `test/gssapi.goose`, `test/spnego.goose`: tickets made with known keys,
  contexts both ways, tokens, tampering, replays (an authenticator at
  the skew's edge replayed at twice the skew; a replayed Wrap token
  giving nothing), channel bindings, delegation, transited realms,
  Windows' and NTLM-first SPNEGO exchanges, DES3 when not first refused.
- `test/pac.goose`: go-krb5's PAC vectors (two from Windows AD) and its
  five uncompressed claims vectors read the same as go-krb5 reads them,
  line for line (`test/vectors/pac_oracle.txt`, from `tools/krb5oracle`);
  the server signature checked with the service's key, an unkeyed one
  (RSA-MD5, SHA-1) refused, two PACs refused; extended
  UPN_DNS_INFO; the compressed claims vector decompressed to its declared
  size, its claims those of the uncompressed vectors for the same user.

`make interop-krb5` (`scripts/interop.py`, macOS with Homebrew's
`krb5`): two MIT 1.22 realms (`scripts/kdc.py`, on 127.0.0.1, trusting
each other); a third, F.TEST, whose KDC refuses the encrypted
timestamp; S.TEST, which offers SPAKE in all four groups and refuses the
timestamp too; O.TEST, which sends an optimistic edwards25519 challenge;
P.TEST, Q.TEST, R.TEST and N.TEST with PKINIT (certificates from
`scripts/pki.py`, OpenSSL); and 183 checks: kinit with each user (pre-auth required,
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
armor stripped from an error (no retry in the clear). SPAKE in S.TEST
and O.TEST, each exchange read back from the KDC's log: kinit for a user
of every type (the reply key of that type), in each NIST group alone,
with the client's `disable_encrypted_timestamp`, inside FAST (and a
wrong password there), kvno with the TGT; the optimistic challenge
answered at once, refused for P-256 (support, then P-256), no group in
common (the timestamp instead, or nothing with
`disable_encrypted_timestamp`), a wrong password (PREAUTH_FAILED, no
timestamp after it); a relay that sends -T for the KDC's T (still a
point; the KDC refuses the response). With the client's SPAKE turned
off, every check that relies on it fails. PKINIT (40 checks): RSA 2048
and 3072 and ECDSA P-256, P-384 and P-521 certificates, MIT's kvno with
the TGT; a certificate under an intermediate sent with it (refused
without it), PKCS #12 (a wrong password refused), a UPN SAN; each group
and each KDF (and none: octetstring2key); Q.TEST's freshness tokens and
its refusal of 2048 answered with its group, or P-521 at once;
anonymous (`kinit -n`), its TGT as FAST armor for PKINIT, for MIT's
kinit too; refused by the KDC: another CA, EKU serverAuth, expired,
another principal; refused by us: a KDC certificate from a CA we do not
trust, naming a host (taken with `pkinit_kdc_hostname`, refused again
with `pkinit_eku_checking = kpServerAuth`), and one with the
id-pkinit-san and EKU serverAuth taken; through the relay, the KDC's DH
value altered (signature), the KDF it names altered (another key),
anonymous PA-PKINIT-KX altered. With each of the client's checks taken
out in turn (the signature, the chain, the KDC's name, the EKU,
PA-PKINIT-KX, the KDF), a check here fails; the nonce's is
`test/pkinit.goose`'s.

`scripts/ad.py`: against Active Directory, the DC `scripts/windows`
makes (goose.test on Windows Server 2022, reached by an ssh tunnel to its
loopback; the script's header has the commands), 43 checks: kinit with a
password (AES; RC4 for bob), a computer account (goosepc$, its salt from
ETYPE-INFO2) and ktpass's keytab, wrong passwords and unknown users,
FAST (kinit -T, an error read inside AD's armor), renewal; kvno for both
of svc-web's SPNs at the keytab's kvno, an unknown SPN, an RC4 ticket
for an AES-only service refused; our acceptor verifying AD's PAC (logon
info, both signatures, client info, UPN_DNS_INFO with its SAM name and
SID, claims, the ticket and full checksums), the claim
`department = Engineering`, Claims Valid, no claim for bob, SPNEGO,
delegation, HTTP Negotiate; compound identity (kvno -T with goosepc$'s
TGT: device info and device claims in the PAC, the device in Domain
Computers, Compounded Authentication in the user's SIDs, none of it
without the armor); LDAP with SASL GSSAPI at each protection layer (Who
am I?), the PAC's user and device SIDs found by SID, and tokenGroups
equal to the PAC's domain groups. With `--trust-password-file`, the
two-way realm trust between goose.test and MIT's A.TEST
(`windows/trust.ps1`; scripts/kdc.py's KDCs with the trust's keys): AD's
alice to an MIT service (AD's cross-realm TGT, MIT's ticket, whose PAC
is MIT's own: AD's logon info does not cross) and MIT's alice and bob to
svc-web (AD's PAC for alice is the account mapped to her,
`altSecurityIdentities`; unmapped bob's ticket has none).

Across the trust: AD refuses (KRB_ERR_GENERIC, nothing in e-text or
e-data) a cross-realm TGT from MIT that carries a PAC, which MIT puts in
every ticket since 1.20; `+no_auth_data_required` on
`krbtgt/GOOSE.TEST@A.TEST` leaves it out. AD refers nothing to an MIT
realm (`ksetup /addhosttorealmmap` is the DC's own client's map): the
client needs `[domain_realm]` for the realm's hosts.

AD leaves the claims out of the PAC unless the request carries
PA-PAC-OPTIONS with the claims bit (MS-KILE §2.2.10), as Windows' does;
ours do (MIT's KDC ignores it). AD's `msDS-SupportedEncryptionTypes`
governs the tickets issued to an account as a service, not its own
keys: every account keeps an RC4 key (its NT hash). MIT's tools don't
take `tcp/` in `kdc =` (Heimdal's form, which ours take);
`udp_preference_limit = 1` sends them over TCP.

`scripts/mit_crypto.py` writes `test/vectors/mit_crypto.txt`: it builds
a small C program against MIT's libk5crypto (Homebrew's `krb5`) and asks
it (MIT picks its confounders, so the ciphertexts change on every run).
`scripts/gen_vectors.py` writes the rest of `test/vectors` from go-krb5's checkout
(`--oracle`, `~/Dev/Go.Code/krb5.git` by default); `pac_oracle.txt` needs
Go, and `tools/krb5oracle/go.mod` points (`replace`) at that checkout.

## Not done yet

- PKINIT's RSA key transport (encKeyPack: MIT 1.22's KDC refuses it;
  AD has it), reused DH keys, smart cards (PKCS #11), `DIR:`/`ENV:`
  identities, CRLs for the KDC's certificate (`pkinit_revoke`), PKINIT
  against AD (the DC has no KDC certificate yet); OTP; SPAKE's second factors (only SF-NONE, as MIT) and
  its KDC side. Of FAST: the hide-client-names and
  kdc-follow-referrals options, armor across a realm referral (the
  armor TGT is for the realm asked; compound identity likewise only in
  the device's realm), and the KDC's side.
- S4U2Self and S4U2Proxy (constrained delegation), user-to-user.
- DNS SRV discovery of KDCs (`dns_lookup_kdc`), kpasswd (RFC 3244),
  KKDCP, MEMORY/KEYRING/KCM caches.
- Windows is built for (the C has its Windows branches) but untested.
- An acceptor taking any name (`any_name`) tries the first keytab key of
  the ticket's realm, type and version, where MIT tries each in turn.
- Against AD (one DC, one domain): no trust between AD domains or
  forests (an MIT realm trust only), no read-only DC, no AD-side checks of our initiator by
  Windows' own clients (only by our acceptor).

FAST follows MIT's client with one difference: given armor, every AS
request is armored from the first, where MIT's kinit -T tries without
it unless the armor cache says the KDC does FAST, and upgrades on
seeing PA-FX-FAST in an error (which an attacker in the middle can
strip). Its TGS exchanges are MIT's: always armored by the TGT, a reply
without FAST taken as a KDC that does not do it. We also require the
KDC's answer to our encrypted challenge, which MIT's client checks only
when it is there. The FAST response and challenge are plain SEQUENCEs, so DES3's
block padding is cut off them before they decode.

SPAKE: the draft's registry gives P-521 a 48-byte multiplier; MIT
(`iana.c`) and the draft's own P-521 vectors use 66, and so do we. Its
SHA-1 vector (a group -1 whose keys take two hash blocks) we cannot
reproduce: our derivation is the draft's text and MIT's `derive_key`,
and gives every other vector's keys, and MIT's `t_vectors.c` leaves this
one out; no registered group needs a second block. The KDC keeps its
SPAKE state in PA-FX-COOKIE, so the cookie goes back unarmored too
(before, only inside FAST). A K that is the identity is refused (MIT's
NIST groups fail there; its edwards25519 does not check). Given a SPAKE
offer we take it over the encrypted challenge and the timestamp; after
our response there is no fallback (the draft's §10.5, MIT's
`disable_fallback`), but when the KDC has no group of ours the other
mechanisms it offered are tried.

PKINIT follows MIT's client: it waits for the KDC's PREAUTH_REQUIRED
(with an empty PA-AS-FRESHNESS asking for a token), so a principal that
needs no pre-authentication gets a reply nothing of ours opens
(ERR_PREAUTH). A KDC that names no KDF is taken (RFC 4556's
octetstring2key), as MIT takes it; RFC 8636 leaves that to the client.
Anonymous, the client's name in RFC 8636's KDF is the anonymous
principal in the realm WELLKNOWN:ANONYMOUS, as MIT's KDC renames it.
MIT sends PA-PKINIT-KX to anonymous clients only (RFC 8062 says SHOULD
for the others); we check it whenever it comes and require it when
anonymous. MIT's KDC says CANT_VERIFY_CERTIFICATE, not
CLIENT_NOT_TRUSTED, for a certificate whose issuer it does not know.
The KDC's MODP value is checked to be in the subgroup of order q (y^q =
1), beyond [2, p-2].

DES3 and RC4 are legacy and kept for old KDCs and keytabs only: the
client asks for them (in `conf_etypes`, listed or by default) only when
`[libdefaults]` has `allow_des3 = true` or `allow_rc4 = true`, MIT
1.21's relations, both false by default; and it takes an AS-REP under
a password or keytab key only in a type it asked for. RFC 1964's per-message tokens for DES3 session keys
are not planned (such contexts establish, but `gss_get_mic` and
`gss_wrap` refuse them, and SPNEGO refuses such a context when Kerberos
was not the initiator's first choice, the mechListMIC being then
required).

A checksum is verified (`verify_checksum`, and through it the PAC's
signatures, FAST's and the AS-REQ's) only when keyed: RSA-MD5 and SHA-1,
which anyone can compute, give `KRB_AP_ERR_INAPP_CKSUM` (`checksum` still
makes them). `pac_verify` refuses a ticket with more than one PAC
(`ERR_PAC`), as MIT does. The acceptor keeps no capaths: a ticket whose
transited field is not empty is taken only when the KDC checked it
(TRANSITED-POLICY-CHECKED, which MIT's KDC sets), else
`KRB_AP_PATH_NOT_ACCEPTED`; direct cross-realm trust leaves it empty.
`gss_unwrap` gives no message for a token out of sequence.

Camellia (bignum's, constant time) is checked against all of RFC
6803's vectors and against MIT (libk5crypto, PRF included, and its KDC).
The RFC doesn't give its sample encryptions' key usages: they are 0 to 4
in order.

`string_to_key` takes any PBKDF2 iteration count from 1 to 2^24, as the
RFCs' own vectors need; but the client refuses a KDC's s2kparams below
the type's default (4096 for RFC 3962, 32768 for RFC 8009 and 6803),
`ERR_S2K_PARAMS`, unless `[libdefaults]` has `allow_weak_s2kparams =
true`: the hint comes unauthenticated, and a low count would make the
password cheap to guess from the PA-ENC-TIMESTAMP that follows.

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
