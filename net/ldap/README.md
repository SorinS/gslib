# ldap

LDAPv3 (RFC 4511) for the Goose language, a client as Go's
[go-ldap](https://github.com/go-ldap/ldap) (v3.4.4) has it, on
[asn1](../../encoding/asn1) for the BER and [bignum](../../crypto/bignum)
for DIGEST-MD5. Nothing here does I/O: a connection writes the requests
to a byte builder and is fed the bytes that arrive; the caller owns the
socket, and TLS ([tlsgoose](../../crypto/tls) in `tools/`).

- **`ldap`**: the protocol's numbers; result codes with go-ldap's names
  (`result_name`) and its error text (`error_text`: `LDAP Result Code 49
  "Invalid Credentials": ...`); every request's encoding; controls
  (paged results, ManageDsaIT, subtree delete, the Behera password
  policy, proxied authorization, assertion, server-side sorting,
  authorization identity, Microsoft's, and any other); messages checked
  whole when they arrive, then read in place: results (code, matched DN,
  message, referrals), entries and their attributes, references, bind
  credentials, extended and intermediate responses, response controls
  (paging cookie, password policy, sort result, VChu warning).
- **`ldap.conn`**: `Conn`, a client connection: message IDs, the
  requests outstanding, framing messages out of the byte stream; bind
  (simple, unauthenticated, SASL: EXTERNAL, PLAIN, DIGEST-MD5 as RFC 2831
  and go-ldap do it), search, modify, add, delete, modify DN, compare,
  extended operations (StartTLS, Who am I, Password Modify, Cancel),
  abandon, unbind; Notice of Disconnection.
- **`ldap.filter`**: RFC 4515 filters compiled to BER and back, as
  go-ldap's `CompileFilter` and `DecompileFilter`; `escape_filter`.
- **`ldap.dn`**: RFC 4514 DNs, as go-ldap's `ParseDN`; `dn_string` (its
  `String()`), `dn_equal`, `dn_equal_fold`, `dn_ancestor_of`;
  `escape_dn_value`.
- **`ldap.url`**: RFC 4516 URLs: `ldap://`, `ldaps://`, `ldapi://`.
- **`ldap.ldif`**: RFC 2849: entries written as OpenLDAP's ldapsearch
  writes them; change records read as its ldapmodify reads them.

```goose
import gslib from "SorinS/gslib@v0.1";   // or a path to gslib.git
import gslib.net.ldap;
import gslib.net.ldap.conn;

var c = ldap::client();
var out: u8[>..] = [];
let b = ldap::bind(c, "cn=admin,dc=example,dc=com", "secret", out);
let s = ldap::search(c, "dc=example,dc=com", ldap::SCOPE_SUB, "(&(objectClass=person)(cn=a*))", "cn,mail", out);
// ... send out; read into input ...
var msgs: u8[>..] = [];
ldap::feed(c, input, msgs);                   // 0, or the code that ended the connection
var pos = 0;
loop {
    let m, ok = ldap::next_message(msgs, pos);
    if !ok { break; }
    if m.op == ldap::OP_SEARCH_ENTRY {
        print(ldap::entry_dn(msgs, m), " ", ldap::get_value(msgs, m, "mail"));
    } else if m.op == ldap::OP_SEARCH_DONE || m.op == ldap::OP_BIND_RESPONSE {
        let err = ldap::result_error(msgs, m);     // "" for success
    }
}
```

Attributes and controls go to a request as BER, built with `put_value`,
`put_attribute`, `put_change` and the `put_<control>` functions;
results are read as offsets into the bytes they came in (asn1 `Tlv`s),
with `bytes(buf, t)` for their content. A request returns its message
ID, or -1 with `c.error` and `c.message` (`conn_error(c)` as go-ldap
words it): after the connection closed, while StartTLS waits for its
response, an empty password to `bind` (`unauthenticated_bind` sends one
on purpose), a filter that does not compile. A successful StartTLS sets
`c.tls_ready`: the transport then speaks TLS, and the plaintext goes on
being fed here. A response to a request no longer outstanding (an
abandoned one) is dropped, as go-ldap drops it; one of the wrong kind, a
message that is not well formed, or one over `c.max_message` (64 MiB)
fails the connection. Messages are read as BER, as servers send it:
Active Directory's four-octet lengths too (asn1's `ber` mode).

Where go-ldap is not RFC 4514 and 4515, this is:
- a filter must close each parenthesis it opens (go-ldap takes
  `(!(a=b)x` and `(&(a=b)x`), and `!` takes a parenthesized filter (go-ldap
  takes `(!a=b)`);
- an `=` in a DN's value is part of it (`cn=a=b` is cn `a=b`; go-ldap
  makes the type `a`);
- a DN's last AVA with an empty value is kept, and a trailing `,`, `+`
  or `\` is refused (go-ldap drops the AVA);
- BOOLEAN TRUE goes as FF (RFC 4511 §5.1), where go-ldap writes 01;
- DIGEST-MD5's cnonce is the caller's random bytes (go-ldap's comes from
  math/rand), and `charset=utf-8` is sent when the server offers it.

## The programs

```bash
cd tools
for t in ldapsearch ldapmodify ldapdelete ldapmodrdn ldapcompare ldapwhoami ldappasswd; do goose build $t.goose; done
goose build -o goose-ldapadd ldapmodify.goose   # ldapmodify -a, by its name

./goose-ldapsearch -H ldaps://ldap.example.com -x -D cn=admin,dc=example,dc=com -W -b dc=example,dc=com '(uid=alice)' cn mail
./goose-ldapwhoami -H ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi -Y EXTERNAL
```

`goose-ldapsearch`, `goose-ldapmodify` (`goose-ldapadd`),
`goose-ldapdelete`, `goose-ldapmodrdn`, `goose-ldapcompare`,
`goose-ldapwhoami` and `goose-ldappasswd` work as OpenLDAP's tools of
those names, and print what they print, byte for byte, with the same
exit status. Common options: `-H uri`, `-x`, `-D binddn`, `-w`, `-W`,
`-y file`, `-Y EXTERNAL|PLAIN|DIGEST-MD5`, `-U`, `-X`, `-Z`/`-ZZ`,
`-M`/`-MM`, `-e [!]assert=|authzid=|manageDSAit|ppolicy|subtreeDelete`,
`-o ldif_wrap=|nettimeout=`, `-n`, `-c`, `-v`, `-Q`. ldapsearch: `-b`,
`-s`, `-a`, `-z`, `-l`, `-A`, `-L`/`-LL`/`-LLL`, `-E pr=n/noprompt`,
`-E sss=keys`, a filter (with or without its parentheses) and
attributes. TLS takes OpenLDAP's environment: `LDAPTLS_CACERT` (else the
system's roots), `LDAPTLS_REQCERT` (`never` or `allow` turn checking
off), `LDAPTLS_CERT` and `LDAPTLS_KEY` (a client certificate, for
EXTERNAL); `LDAPURI` and `LDAPBINDDN` stand in for `-H` and `-D`.
Without `-x`, `-D`, `-w` or `-Y` there is no bind (OpenLDAP's would be
SASL). tools/net.c is their operating-system part (TCP and Unix
sockets, the terminal), for macOS and Linux.

## Tests

```bash
python3 scripts/run_tests.py            # at -O0, -O2 and --debug
python3 scripts/run_tests.py --native   # also built with the C compiler
python3 scripts/interop.py              # live, against OpenLDAP's slapd and tools (below)
tools/goldap.sh vectors > test/vectors/goldap.txt   # remake go-ldap's vectors
tools/goldap.sh search <url> <base> <filter> [binddn password]   # go-ldap's client by hand
```

They take the compiler from `$GOOSE`, else `goose` on PATH, else
`../goose.git/build/goose` (run_tests.py and interop.py also take
`--goose`), and asn1goose.git, bigmongoose.git, x509goose.git and
tlsgoose.git beside this repository. interop.py also needs OpenLDAP 2.5
or later (`slapd`, `slapadd` and the client tools; `--openldap PREFIX`,
`$OPENLDAP`, else Homebrew's), `openssl`, and Go with go-ldap v3.4.4 in
the module cache; it runs slapd as you, on free ports of 127.0.0.1 and a
socket in a temporary directory, and leaves nothing running.
`tools/goldap` builds offline from the module cache
(`GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off`).

- `goldap`: against go-ldap (`test/vectors/goldap.txt`, from
  `tools/goldap`): every request go-ldap writes (binds, searches with
  every option and control, add, modify, delete, modify DN, compare,
  Password Modify, Who am I, StartTLS, unbind) written here byte for
  byte; 660 filters, hand-picked and random, compiled to the same BER or
  refused as go-ldap refuses them, decompiled to the same text; escapes;
  329 DNs read to go-ldap's `String()` or refused, and compared as its
  Equal, EqualFold and AncestorOf compare.
- `conn`: a server played in memory: every kind of response read back,
  response controls, messages fed a byte at a time and many at once,
  Active Directory's lengths, abandoned requests, StartTLS holding other
  requests, a Notice of Disconnection, the connection failed by
  malformed, mismatched, unsolicited and oversized messages and by the
  transport ending.
- `text`: LDIF written (base64, folding) and read (every change type,
  controls, URL values, errors and their lines), LDAP URLs, the inputs
  where go-ldap and the RFCs part, deep and long filters, and DIGEST-MD5
  against RFC 2831's example.

`scripts/interop.py` (235 cases) starts slapd with an mdb database of
test entries (binary, UTF-8, values LDIF must base64, long values, an
alias, a referral, a multi-valued RDN), TLS from a CA it makes, and
SASL, and requires each goose tool to print what OpenLDAP's prints and
exit as it exits: 22 filters over each of ldap://, ldaps://, StartTLS
and ldapi:// (EXTERNAL); every output form; scopes, attribute
selections, types only, wrapping, size and time limits, paged results,
sorting, every deref, referrals and references, ManageDsaIT, assertion
and proxied authorization, errors; binds of each kind (anonymous,
simple, from a file, unauthenticated, EXTERNAL over ldapi and with a TLS
client certificate, PLAIN, DIGEST-MD5, refused ones) through
ldapwhoami; compare; ldapadd, ldapmodify, ldapmodrdn and ldapdelete
each changing a subtree of their own from the same input, which must
end up the same (adds, modifies, modrdn, controls in the LDIF, recursive
deletes, failures with and without -c); ldappasswd; TLS refused for an
unknown CA. And go-ldap reads the same entries as goose-ldapsearch.
