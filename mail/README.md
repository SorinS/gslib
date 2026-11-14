# mail

Email for Goose: messages built and written in RFC 5322 / MIME form, an
SMTP client, a POP3 client and an IMAP client, DKIM, S/MIME and PGP/MIME. Sending is modelled on Go's
[go-mail](https://github.com/wneessen/go-mail) (its `Msg`, msgwriter and
`smtp` package); fetching on Python's `poplib` and RFC 1939. The clients do
their own I/O over gslib's `net` sockets and its TLS, and a tool,
`goose-mail`, drives them all.

| Module | What |
|---|---|
| `mail` | errors (`OK`, `ERR_*`, `error_text`), `eq_fold` |
| `mail.address` | addresses as Go's net/mail reads and writes them: `parse_address`, `parse_address_list`, `make_address`, `write_address` (display names quoted or RFC 2047-encoded as needed) |
| `mail.message` | a message, `mail::Msg`: From/To/Cc/Bcc/Reply-To, subject, headers, Date and Message-ID, text and HTML bodies, attachments and inline parts, written by `write` as multipart/mixed > related > alternative, quoted-printable, base64 or 8bit; the SMTP envelope (`envelope_from`, `recipients`) |
| `mail.link` | the connection under both clients: a socket, TLS from the first byte or after STARTTLS/STLS, lines in and out |
| `mail.sasl` | SASL's client side: PLAIN, LOGIN, CRAM-MD5, SCRAM-SHA-1, SCRAM-SHA-256 (the server's signature checked), XOAUTH2 |
| `mail.smtp` | an SMTP client (namespace `smtp`): EHLO/HELO, STARTTLS or TLS on 465, AUTH, MAIL with 8BITMIME, SMTPUTF8 and DSN, RCPT, DATA, RSET, NOOP, VRFY, QUIT; `send`, `send_message` |
| `mail.pop3` | a POP3 client (namespace `pop3`): CAPA, STLS or TLS on 995, USER/PASS, APOP, AUTH, STAT, LIST, UIDL, RETR, TOP, DELE, RSET, NOOP, UTF8, QUIT |
| `mail.imap` | an IMAP client (namespace `imap`), IMAP4rev2 and IMAP4rev1 servers: CAPABILITY, STARTTLS or TLS on 993, LOGIN, AUTHENTICATE (SASL-IR), ID, ENABLE, SELECT/EXAMINE, LIST/LSUB (modified UTF-7 decoded), CREATE, DELETE, RENAME, SUBSCRIBE, STATUS, FETCH (ENVELOPE and BODYSTRUCTURE parsed), SEARCH/ESEARCH, STORE, COPY, MOVE, EXPUNGE, UID EXPUNGE, APPEND (LITERAL+), NOOP, IDLE, CLOSE, UNSELECT, LOGOUT; a response parser with literals |
| `mail.dkim` | DKIM (namespace `dkim`, RFC 6376): signing and verifying with RSA-SHA256 and Ed25519-SHA256 (RFC 8463), rsa-sha1 verified only on request and RSA keys under 1024 bits refused (RFC 8301); simple and relaxed canonicalization, l=, i=, t=, x=, From over-signed; `sign`, `signature`, `sign_msg`, `verify` with a key-lookup block, `verify_record`, `verify_dns` (dns.client), `parse_key`, `key_record` |
| `mail.pgp` | PGP/MIME (RFC 3156), namespace `pgp`, over crypto.openpgp: `sign` (multipart/signed, micalg=pgp-sha256), `encrypt` (multipart/encrypted), `sign_encrypt` (one OpenPGP message, §6.2), each over a `mail::Msg` or a written message; `open`, `verify`, `decrypt` read every layer back, §6.1 nesting too |
| `mail.smime` | S/MIME 4.0 (RFC 8551), namespace `smime`: `sign` (multipart/signed), `sign_opaque`, `encrypt` (enveloped-data, or authEnveloped-data with GCM), `sign_encrypt`, each over a `mail::Msg` or a written message; `open` and `verify` read every layer back; `check_signer`, `check_path`, `has_address`, `from_address` |

## Using it

```goose
import gslib from "SorinS/gslib@v0.1";
import gslib.mail;
import gslib.mail.message;
import gslib.mail.smtp;

var m = mail::Msg { .. };
mail::set_from(m, "Zoë <zoe@example.com>");
mail::add_to(m, "bob@example.com, \"Müller, Jörg\" <joerg@example.org>");
mail::set_subject(m, "Lunch?");
mail::set_body(m, mail::TEXT_PLAIN, "At noon?\n");
mail::attach(m, "menu.pdf", pdf_bytes);

var c = smtp::Client { .. };                    // a root struct: a local
var e = smtp::dial(c, "smtp.example.com", 0, smtp::TLS_MANDATORY);   // 587, STARTTLS
if e == mail::OK { e = smtp::auth(c, mail::AUTH_AUTO, "zoe", password); }
if e == mail::OK { e = smtp::send_message(c, m); }
if e == mail::ERR_REPLY { print(c.code, " ", c.text); }   // the server's refusal
smtp::quit(c);
```

```goose
import gslib.mail.pop3;

var c = pop3::Client { .. };
var e = pop3::dial(c, "pop.example.com", 0, pop3::TLS_IMPLICIT);    // 995
if e == mail::OK { e = pop3::auth(c, mail::AUTH_AUTO, "zoe", password); }
let count, size, se = pop3::stat(c);
var msg: u8[>..] = [];
if count > 0 { e = pop3::retr(c, 1, msg); }    // CRLF lines, dots undone
pop3::quit(c);                                 // DELEs take effect here
```

```goose
import gslib.mail.imap;

var c = imap::Client { .. };
var e = imap::dial(c, "imap.example.com", 0, imap::TLS_IMPLICIT);     // 993
if e == mail::OK { e = imap::authenticate(c, mail::AUTH_AUTO, "zoe", password); }
if e == mail::OK { e = imap::select(c, "INBOX"); }                   // c.exists, c.uidvalidity
var msgs: imap::Message[>..] = [];
if e == mail::OK { e = imap::fetch(c, "1:*", "(UID FLAGS ENVELOPE BODY.PEEK[HEADER])", msgs); }
for m in msgs {
    var env = imap::Envelope { .. };
    if imap::envelope(c, m, env) { print(m.uid, " ", env.subject); }
    var head: u8[>..] = [];
    imap::fetch_item(c, m, "BODY[HEADER]", head);    // until the next command
}
imap::logout(c);
```

Every fallible function returns `mail::OK` or an `mail::ERR_*`; a server's
refusal is `ERR_REPLY`, with its reply in the client (`c.code` and `c.text`
for SMTP, `c.text` after `-ERR` for POP3, and for IMAP a NO or BAD's text
in `c.text` and its `[code]` in `c.code`). Each client is a `root struct`,
so it lives in a local or a global. `c.tlscfg` is the TLS client's
configuration: the system's roots by default, `verify = false` for a test
server's own certificate. `c.timeout_ms` (30 s) bounds the connect and each
read and write.

TLS, for all three clients, is one of `TLS_MANDATORY` (STARTTLS/STLS, failing
with `ERR_NO_TLS` when the server lacks it: go-mail's default),
`TLS_OPPORTUNISTIC`, `TLS_NONE` and `TLS_IMPLICIT` (465, 995, 993). Port 0
means the mode's usual port.

An IMAP command's untagged responses stay in `c.data` until the next
command, and items are read from there (`messages`, `fetch_item`,
`envelope`, `bodystructure`). A response line may be at most 1 MiB, a
literal `c.max_literal` (64 MiB), and a command's responses together
`c.max_data` (256 MiB). Anything over is `ERR_PROTOCOL`: close then, and
fetch many bodies in smaller sets.

### Safety

- Commands are checked for CR and LF (`ERR_LINE`), MAIL and RCPT
  addresses for '<' and '>' too (`ERR_ADDRESS`), as go-mail's
  `validateLine` does.
- After STARTTLS or STLS, bytes the server sent with its reply, before
  TLS, fail the connection (`ERR_PROTOCOL`) instead of being read as if
  they came under TLS (the injection of CVE-2011-0411), and EHLO, CAPA and
  CAPABILITY are asked again; IMAP's STARTTLS too.
- PLAIN, LOGIN and XOAUTH2 (and POP3's USER/PASS, IMAP's LOGIN) send the password
  readable, so without TLS they are refused (`ERR_AUTH`) except to
  localhost, as Go's `smtp.PlainAuth`.
- SCRAM checks the server's signature: a server that does not know the
  password, and says yes anyway, fails with `ERR_AUTH`, and the exchange
  is cancelled with `*`.
- IMAP string arguments go as an atom, a quoted string or a literal as
  needed; CR, LF and NUL in them are refused (`ERR_LINE`), as are sequence
  sets and flags that do not parse (`ERR_ARG`). Mailbox names go in
  modified UTF-7 unless UTF8=ACCEPT or IMAP4rev2 is enabled.
- `AUTH_AUTO` picks, of what the server offers, SCRAM-SHA-256, then
  SCRAM-SHA-1, CRAM-MD5, PLAIN and LOGIN (go-mail's order).
- Nothing logs. goose-mail takes the user and password from
  `MAIL_USER` and `MAIL_PASSWORD`, never its arguments.

### DKIM

```goose
import gslib.mail.dkim;

let key, ke = dkim::parse_key(pem_text);          // RSA or Ed25519: PEM, or an Ed25519 seed in base64
var o = dkim::SignOptions { .. };                 // relaxed/relaxed, the usual fields, From over-signed
o.domain.append("example.com");
o.selector.append("mail2026");
var signed: u8[>..] = [];
var e = dkim::sign_msg(m, key, o, signed);        // a mail::Msg; or dkim::sign(bytes, key, o, signed)

var res: dkim::Result[>..] = [];
e = dkim::verify_dns(signed, "", res);            // the keys from DNS (resolv.conf's server)
e = dkim::verify(signed, res) { domain, selector, rec => rec.append(my_record(domain, selector)); };
for r in res { print(r.d, " ", r.s, " ", mail::error_text(r.status)); }   // OK: pass
```

Each DKIM-Signature gets a `dkim::Result`: `mail::OK` (pass),
`ERR_SIGNATURE` (the signature or, with `body_mismatch`, the body hash; or
x= passed), `ERR_KEY` (the key record: revoked, malformed, the wrong k= or
h=, too small), `ERR_DNS` (no record), `ERR_FORMAT` (the header does not
parse, does not sign From, or i= is outside d=), `ERR_UNSUPPORTED` (an
algorithm not done; rsa-sha1 unless `allow_sha1`), with `reason` in words.
`dkim::result_text` writes RFC 8601's form. `verify` returns `mail::OK`
when any signature passes.

### S/MIME

```goose
import gslib.mail.smime;

var o = smime::Options { .. };              // SHA-256, AES-256-CBC, RSA-OAEP, signingTime now
var out: u8[>..] = [];
var rc = smime::sign(m, key, cert, chain, o, out);                  // multipart/signed
rc = smime::sign_encrypt(m, key, cert, chain, recipients, o, out);  // then application/pkcs7-mime

var r = smime::Opened { .. };               // a root struct: a local
rc = smime::open(received, my_key, my_cert, r);       // decrypts and verifies every layer
if rc == mail::OK && r.signed {
    rc = smime::check_signer(r, roots, now, smime::from_address(received));
}
```

The header fields that are not Content-* (Date, From, To, Subject,
Message-ID, ...) stay outside; the entity (the Content-* fields and the
body) is what is signed or encrypted. multipart/signed signs the entity
exactly as it is sent, so it must be 7bit: a `Msg` with `ENC_8BIT` is
refused. RSA keys sign with PKCS #1 v1.5 (`pss` for PSS), EC keys with
ECDSA, Ed25519 keys with Ed25519 (RFC 8419). Recipients are certificates,
DER laid end to end: RSA ones by RSAES-OAEP with SHA-256 (`rsa_pkcs1` for
v1.5), EC ones (P-256, P-384, P-521) by ECDH with the X9.63 KDF and AES
key wrap; the content by AES-CBC (EnvelopedData) or AES-GCM
(AuthEnvelopedData). The sender reads their own message only if their
certificate is among the recipients. `open` reads what openssl, and BER
CMS, send: OAEP with SHA-1 too, RSA PKCS #1 v1.5 without a padding oracle
(a bad block gives a random key, then ERR_DECRYPT), the SHA-1 ECDH KDF
openssl uses by default. Whether to trust the signer is the caller's:
`check_signer` checks the path to the roots given (for email protection,
with a key usage that signs) and that one of the certificate's rfc822Name
addresses is From's. The CMS underneath is crypto/x509's `x509.cms` and
`x509.cms_env`.

### PGP/MIME

```goose
import gslib.crypto.openpgp.keyring;
import gslib.mail.pgp;

var kr = openpgp::Keyring { .. };           // openpgp::add_keys, openpgp::unlock
let o = pgp::Options { .. };                // SHA-256, AES-256, signature time now
var rc = pgp::sign(m, kr, signer, o, out);  // signer, recipients: openpgp::find_key indices
rc = pgp::sign_encrypt(m, kr, signer, [bob], o, out);
var r = pgp::Opened { .. };
rc = pgp::open(received, kr, "", r);        // r.entity, r.signed, r.encrypted, r.signer
```

As with S/MIME, the fields that are not Content-* stay outside, and the
entity is signed exactly as it is sent (7bit only). `sign_encrypt` makes
one OpenPGP message that is signed and encrypted (RFC 3156 §6.2); `open`
also reads the §6.1 nesting (multipart/signed inside multipart/encrypted).
Whether the signing key belongs to From is the caller's to decide. The
OpenPGP underneath is crypto/openpgp (its README has the formats).

## Tools

`goose-mail` (`mail/tools/mail.goose`, built by `make build`):

```bash
MAIL_USER=zoe MAIL_PASSWORD=... goose-mail smtp --auth auto smtp.example.com msg.eml zoe@example.com bob@example.com
goose-mail smtp --tls none --auth none localhost - zoe@example.com bob@example.com bcc:archive@example.com
MAIL_USER=zoe MAIL_PASSWORD=... goose-mail pop3 --tls implicit pop.example.com stat list uidl retr 1 dele 1
MAIL_USER=zoe MAIL_PASSWORD=... goose-mail imap --tls implicit imap.example.com list select INBOX fetch 1:* "(UID FLAGS ENVELOPE)" search UNSEEN
goose-mail dkim sign --key key.pem --domain example.com --selector mail2026 msg.eml > signed.eml
goose-mail dkim verify signed.eml                     # keys from DNS; or --record "v=DKIM1; ..." offline
goose-mail dkim record --key key.pem                  # the TXT record to publish
goose-mail smime sign cert.pem key.pem msg.eml signed.eml
goose-mail smime encrypt --cipher aes256-gcm msg.eml enc.eml bob.pem carol.pem
goose-mail smime decrypt --roots roots.pem cert.pem key.pem enc.eml -
```

FILE `-` builds a small message with mail.message (an attachment, a
dotted line, a `bcc:` recipient kept out of the headers). Options:
`--port`, `--tls mandatory|opportunistic|none|implicit`, `--insecure`,
`--auth auto|plain|login|cram-md5|scram-sha-1|scram-sha-256|xoauth2|none`
(and `user` for pop3 and imap, `apop` for pop3), `--name` (EHLO's).

imap's commands run in order on one connection: `capa`, `id`, `enable
CAPS`, `list [PAT]`, `lsub [PAT]`, `select`/`examine MBOX`, `status MBOX`,
`create`/`delete`/`subscribe`/`unsubscribe MBOX`, `rename OLD NEW`,
`[uid-]fetch SET ITEMS`, `[uid-]search CRIT`, `[uid-]store SET HOW FLAGS`,
`[uid-]copy`/`[uid-]move SET MBOX`, `expunge`, `uid-expunge SET`, `append
MBOX FILE [FLAGS]`, `noop`, `close`, `unselect`, `idle SECONDS`, then
LOGOUT.

```
goose-mail dkim sign --key FILE --domain D --selector S [--canon H/B] [--headers LIST] [--no-oversign]
                     [--identity ID] [--timestamp T|now] [--expire T|now] [--length] [FILE|-]
goose-mail dkim verify [--record TEXT | --record-file FILE | --dns SERVER] [--allow-sha1] [--now T] [FILE|-]
goose-mail dkim record --key FILE
goose-mail smime sign [--opaque] [--pss] [--hash N] [--keyid] [--time T] [--boundary B] CERT KEY IN OUT
goose-mail smime encrypt [--cipher aes128-cbc|aes256-cbc|aes128-gcm|aes256-gcm] [--pkcs1] [--keyid] IN OUT RCERT...
goose-mail smime sign-encrypt [sign and encrypt options] CERT KEY IN OUT RCERT...
goose-mail smime verify [--roots FILE] [--now T] IN [OUT]
goose-mail smime decrypt [--roots FILE] [--now T] CERT KEY IN [OUT]
```

dkim verify prints one RFC 8601 line per signature and exits 0 when one
passes; without `--dns` it asks `/etc/resolv.conf`'s first nameserver.
For smime, CERT is a PEM file whose first certificate is the signer's or
recipient's (any others go as the chain), KEY a PEM private key; IN and
OUT are RFC 5322 files, OUT `-` for standard output. verify and decrypt
print `encrypted`, `signed by SUBJECT`, the signing time, and with
`--roots` `signer ok` (path, email-protection usage and From).

## Examples

`examples/mail/`:

- `compose.goose`: a text body with an HTML alternative, non-ASCII names
  and subject, a Bcc; prints the message and its envelope.
- `attachments.goose`: attachments and an inline image, deterministic.
- `send.goose`: builds a message and sends it with STARTTLS and
  `AUTH_AUTO` (needs a server: only type-checked by the tests).
- `fetch.goose`: lists a POP3 mailbox and prints the newest message's
  headers (needs a server too).
- `imap_list.goose`: lists an IMAP account's mailboxes, then the envelope
  and parts of INBOX's newest message (needs a server: only type-checked).
- `dkim_sign.goose`: a message from mail.message signed with an Ed25519
  test key and verified with the key record handed in, deterministic.
- `smime_sign.goose`: a message signed as multipart/signed with an
  embedded test key, then verified and its signer checked against From;
  deterministic.

## Tests

```bash
make test-mail          # or: cd mail && python3 scripts/run_tests.py
make interop-mail       # or: cd mail && python3 scripts/interop.py [-k NAME]
                        #   and scripts/interop_dkim.py, interop_smime.py, interop_pgp.py
python3 mail/scripts/check_message.py
```

- `test/sasl.goose`: SCRAM-SHA-1 (RFC 5802 §5), SCRAM-SHA-256 (RFC 7677
  §3), CRAM-MD5 (RFC 2195) and PLAIN byte for byte, and a server's
  mistakes: a foreign nonce, a wrong signature, `e=`, no iterations.
- `test/protocol.goose`: dot-stuffing and line ends, APOP (RFC 1939 §7's
  digest), POP3's numbers, the CR/LF and address checks, commands before
  a connection.
- `test/imap.goose`: the response parser (literals holding parentheses,
  quotes and CRLF, `BODY[HEADER.FIELDS (...)]` atoms, NIL, escapes, and
  malformed text: unclosed quotes, lists or brackets, a literal past the
  end, nesting too deep); FETCH items, ENVELOPE (NIL, escapes, RFC 2047,
  groups, literals), a nested BODYSTRUCTURE and its section numbers, LIST,
  STATUS, SEARCH and ESEARCH, response codes; modified UTF-7 (RFC 3501's
  examples, surrogates, invalid input); sequence sets; atom/quoted/literal
  choices and CR/LF/NUL refused; commands before a connection.
- `test/dkim.goose`: RFC 6376 §3.4.5's canonicalization examples and the
  empty-body hashes, RFC 8463 Appendix A's message verified with its
  Ed25519 and RSA keys, tag-lists, round trips in all four
  canonicalizations, l=, a changed body or header, an added unsigned
  field, an over-signed From against an added one, every header and
  key-record check (a revoked key, t=s, h=, a bare RSAPublicKey, a 512-bit
  key), rsa-sha1 refused unless allowed.
- `test/smime.goose`: a `Msg` signed by RSA (v1.5 and PSS), P-256, P-384
  and Ed25519, the entity signed exactly as sent and read back; a changed
  byte refused; `check_signer`'s path, usage and From checks; opaque
  signing; encryption with every cipher, OAEP and v1.5, ECDH, several
  recipients; not a recipient, a wrong key, a changed GCM ciphertext
  refused; sign-then-encrypt; 8bit refused for multipart/signed; and 14
  messages openssl made (`test/smime/`, from `scripts/interop_smime.py
  --write-vectors`, test keys only; `.gitattributes` keeps their bytes).
- `test/pgp.goose`: a Msg signed by Ed25519 and RSA keys and read back,
  LF input, a changed byte refused, encryption signed and not, not for
  us, 8bit refused, and 4 messages gpg made (`test/pgp/`, from
  `scripts/interop_pgp.py --write-vectors`, test keys only;
  `.gitattributes` keeps their bytes).
- `test/address.goose`: 80 addresses and 10 lists with Go 1.27's
  net/mail's answers, and round trips.
- `test/message.goose`: four messages byte for byte against
  `test/expected/` (`-- update` rewrites them; `.gitattributes` keeps
  their CRLFs), dates, headers, folding, the envelope, the encodings, the
  998-byte limit.
- `scripts/check_message.py`: 12 messages from `test/gen_messages.goose`
  parsed by Python's `email` (headers, nesting, bodies and attachments
  decoded and compared, Bcc absent, CRLF only, no line over 998), and
  addresses both ways against `email.headerregistry`.
- `scripts/interop.py`: goose-mail against
  - scripted SMTP and POP3 servers in the script, which check SASL the
    server's way (SCRAM proofs, CRAM-MD5, APOP) and misbehave on purpose:
    STARTTLS/STLS and implicit TLS, a certificate that does not check,
    every mechanism with the right and a wrong password, a SCRAM server
    with the wrong signature, HELO fallback, a refused recipient (then
    RSET), SMTPUTF8, dot-stuffing both ways, bare LFs, the STARTTLS and
    STLS injection; and a message from mail.message, read back by
    Python's `email`;
  - a scripted IMAP server: LOGIN (an 8-bit password as a literal), every
    SASL mechanism with and without SASL-IR, right and wrong passwords, a
    SCRAM server without the password, STARTTLS, 993, the certificate
    check, the STARTTLS injection, PREAUTH, BYE at the greeting and
    mid-session, LOGINDISABLED, a greeting and login without CAPABILITY,
    the mailbox (SELECT/EXAMINE, LIST in modified UTF-7, FETCH with
    ENVELOPE, BODYSTRUCTURE and literal bodies, untagged responses
    interleaved, SEARCH, STATUS, STORE, COPY, MOVE, EXPUNGE), APPEND
    synchronizing and with LITERAL+, IDLE, ID, ENABLE UTF8=ACCEPT and
    IMAP4rev2 (ESEARCH, UTF-8 names), CR/LF in an argument, an oversized
    literal, a malformed FETCH, a completion with another tag;
  - mailpit (`brew install mailpit`), SMTP with STARTTLS and PLAIN,
    LOGIN and auto, then its POP3 over TLS reading what was sent;
  - dovecot 2.4 (`brew install dovecot`), POP3 and IMAP run as the user
    from a configuration the script writes: STARTTLS/STLS, TLS on 993 and
    995, the certificate check, APOP and every SASL mechanism over TLS;
    without TLS, the POP3 mailbox (STAT, LIST, UIDL, RETR, TOP, DELE) and
    the IMAP one (FETCH with ENVELOPE and BODYSTRUCTURE, SEARCH and
    ESEARCH, CREATE/RENAME/DELETE with non-ASCII names, APPEND, STORE,
    COPY, MOVE, EXPUNGE, UID commands, IDLE).

  On macOS, dovecot 2.4.5 drops a TLS session when its login process
  hands it to the pop3 or imap process (OpenSSL's `s_client` sees the same), so
  over TLS the cases stop at the login. Its memory limit is set to 1T:
  macOS refuses `setrlimit(RLIMIT_DATA)` at dovecot's 256M default, and
  its "unlimited" is over the hard limit. This dovecot offers neither
  UTF8=ACCEPT nor IMAP4rev2, so those are tested on the scripted server.
- `scripts/interop_dkim.py`: goose-mail's dkim against dkimpy (`pip
  install dkimpy pynacl`, or `DKIMPY_PYTHON` naming a python that has
  them; skipped without): each signs and the other verifies, RSA-2048 and
  Ed25519, all four canonicalizations, l=, i=, a changed body, rsa-sha1;
  then the keys looked up through dns.client in goose-dnsd on 127.0.0.1 (a
  record in two strings, a missing selector, a revoked key).
- `scripts/interop_smime.py`: goose-mail's smime and `openssl cms` (3 or
  later) both ways, 57 cases: signing detached, opaque and BER by every
  key, checked to the test root; encryption by RSA-OAEP, RSA v1.5, P-256
  and P-384 (openssl's SHA-1 and SHA-256 KDFs), AES-CBC and AES-GCM,
  several recipients, key identifiers; sign-then-encrypt; refusals.
- `scripts/interop_pgp.py`: mail.pgp and gpg both ways (11 cases): gpg
  verifies and decrypts our parts; we open gpg's signed, encrypted,
  combined and nested messages, and refuse a changed body.

## Departures from go-mail

- Header order is fixed: Date, From, Reply-To, To, Cc, Subject,
  Message-ID, MIME-Version, the importance headers, then the others as
  added. No User-Agent or X-Mailer unless set.
- Each multipart level has its own boundary (go-mail's `SetBoundary`
  gives every level the same one, which nested is invalid), and one
  inline part with one attachment and no text is still nested properly.
- Attachment types come from Go's built-in extension table; the
  Message-ID's host is `localhost.localdomain` unless `set_host` names
  one; nothing asks the system.
- `set_header` writes non-ASCII values as Q encoded-words and refuses
  the fields the builder writes itself.
- Dates are written in UTC (`+0000`).
- SMTP: no PIPELINING, no CHUNKING/BDAT, one message after another on a
  connection.

## Not done

- SCRAM's -PLUS variants (channel binding), NTLM, GSSAPI.
- IMAP: CONDSTORE/QRESYNC beyond MODSEQ, NAMESPACE, COMPRESS, NOTIFY,
  LIST-EXTENDED; IDLE is polled; SEARCH criteria are sent as written (no
  CHARSET for 8-bit strings without UTF8=ACCEPT).
- DKIM: no z=, no clock-skew allowance on t=; an i= local part is not
  quoted-printable encoded; the first of several TXT records is used.
- S/MIME: one signer; no header protection (RFC 8551 §3.1), certs-only or
  compressed-data; no X25519/X448, KEK, password or static-static ECDH
  recipients; no CRL/OCSP check of the signer.
- PGP/MIME: base64-encoded signature parts, a micalg cross-check on
  verify, inline (non-MIME) PGP.
- Other charsets than UTF-8; per-part encodings; RFC 2231
  continuations for very long file names.
- `message/rfc822` and `multipart/*` attachments are base64-encoded,
  which RFC 2046 forbids (go-mail has the same gap).
