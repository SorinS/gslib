# sspi

Windows' Security Support Provider Interface, after Go's
[alexbrainman/sspi](https://github.com/alexbrainman/sspi): the security
packages Windows has, credentials, security contexts built a token at a
time, and the messages a context protects. Two modules use it:

| Module | What it is |
|---|---|
| `sspi` | Packages, credentials (the logged-on user's, or a name and password), contexts (client and server), sign, verify, seal and unseal |
| `sspi.schannel` | A TLS client with Windows' own TLS (Schannel) over `net`'s sockets, as alexbrainman/sspi/schannel |
| `sspi.negotiate` | HTTP's Negotiate authentication (RFC 4559) from the Windows login: Kerberos in a domain, NTLM otherwise |

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.sspi;
import gslib.sspi.schannel;

fn main() {
    var c, st = sspi::tls_dial("example.com", 443, sspi::tls_config("example.com"));
    if st != sspi::OK { print(sspi::tls_error_text(st)); return; }
    sspi::tls_write(c, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    var buf: u8[>..] = [];
    buf.resize(16384, 0);
    let n = sspi::tls_read(c, buf);         // > 0 bytes, 0 at the end, < 0 an error
    sspi::tls_close(c);
}
```

It is Windows only. Elsewhere every call returns
`SEC_E_UNSUPPORTED_FUNCTION`, so a program that uses it builds and runs on
every platform and asks `available()` first.

## The core

| | |
|---|---|
| `available() -> bool` | Windows |
| `packages() -> Package[>..], i64` | Every package (EnumerateSecurityPackages): name, comment, capabilities, version, RPC id, largest token |
| `package_info(name) -> Package, i64` | One (QuerySecurityPackageInfo); `SEC_E_SECPKG_NOT_FOUND` if none |
| `acquire(package, use) -> i64` | The logged-on user's credentials: `CRED_OUTBOUND` (a client), `CRED_INBOUND` (a server), `CRED_BOTH`. An id, or a status < 0 |
| `acquire_as(package, use, user, domain, password) -> i64` | A user's, by password (SEC_WINNT_AUTH_IDENTITY); checked only when a context is made |
| `acquire_schannel(flags, min_version = 0, max_version = 0) -> i64` | Schannel's client credentials: `SCH_CRED_*` flags, TLS versions (0x0301 to 0x0304; 0: the system's policy) |
| `free_credentials(cred)` | |
| `context(cred, server = false) -> i64` | A context on credentials |
| `step(ctx, target, flags, input, out&) -> i64` | One step: InitializeSecurityContext (a client) or AcceptSecurityContext (a server) on the peer's last token. `out` is the token to send. `OK` when made, `SEC_I_CONTINUE_NEEDED` while the peer has more to say |
| `context_package(ctx)`, `context_user(ctx)`, `context_flags(ctx)` | The package agreed (NTLM or Kerberos under Negotiate), the user (a server's client), the `ISC_RET_*`/`ASC_RET_*` flags |
| `sign(ctx, msg, sig&)`, `verify(ctx, msg, sig)` | MakeSignature, VerifySignature |
| `seal(ctx, msg, out&)`, `unseal(ctx, msg, out&)` | EncryptMessage and DecryptMessage: the token, then the ciphertext, then any padding, as GSS-API's wrap lays them out |
| `delete_context(ctx)` | |
| `error_text(st)` | `"SEC_E_LOGON_DENIED (0x8009030C): the logon was denied"` |

Results are SSPI's status codes: `OK` (SEC_E_OK, 0), `SEC_I_*` (> 0, a
step that goes on), `SEC_E_*` and `CERT_E_*` (< 0, errors, the int32
HRESULTs widened). `sspi.goose` names the common ones. Credentials and
contexts are ids (> 0) whose handles the C half keeps. A context is used
from one thread at a time.

## Schannel

| | |
|---|---|
| `tls_config(server_name) -> TlsConfig` | `server_name` (sent as SNI and checked against the certificate), `min_version`, `max_version`, `verify` (default true), `revocation`, `flags`, `timeout_ms` (30000) |
| `tls_dial(host, port, cfg) -> TlsConn, i64` | `net::dial`, then the handshake |
| `tls_client(fd, cfg) -> TlsConn, i64` | The handshake over a connected socket |
| `tls_read(c, buf) -> i64` | Plaintext: > 0 bytes, 0 at the end (close_notify, or the socket's end), < 0 an error |
| `tls_write(c, data) -> i64` | All of it, in records |
| `tls_close(c)` | close_notify, then the socket closed |
| `tls_peer_certificate(c)` | The server's certificate (DER), for `x509::parse` |
| `tls_version(c)`, `tls_cipher_suite(c)`, `tls_cipher_suite_name(c)` | 0x0303 or 0x0304; IANA's number; `"TLS_AES_256_GCM_SHA384"` |
| `tls_error_text(st)` | Says `net::ERR_*` and SSPI's codes alike |

The system decides the protocol versions and cipher suites by its policy
(TLS 1.3 where it has it: Windows Server 2022, Windows 11), checks the
server's chain against its roots and the name against `server_name`, and
can check revocation (`revocation`). `verify false`
(SCH_CRED_MANUAL_CRED_VALIDATION) takes any certificate: the checking is
then the caller's, with `tls_peer_certificate` and x509, as for a test
server's. A server's renegotiation (TLS 1.2) is refused; TLS 1.3's
NewSessionTicket and KeyUpdate after the handshake are taken, a KeyUpdate
answered.

## Negotiate over HTTP

| | |
|---|---|
| `http_negotiate(host, package = "Negotiate", user = "", password = "", domain = "") -> HttpAuth, i64` | The target is `HTTP/host`. With `user` empty, the logged-on user's credentials; else that user's (`DOMAIN\user`) by password. `package`: `NEGOTIATE`, `NTLM` (the `NTLM` scheme) or `KERBEROS` |
| `http_authorization(a, challenge) -> u8[>..], i64` | The Authorization value for the next request: with `""` the first, then with each 401's WWW-Authenticate value. `OK` once the context is made, `SEC_I_CONTINUE_NEEDED` while the server has more to say |
| `http_challenge_token(value, scheme)` | The token a WWW-Authenticate value carries for a scheme |
| `http_package(a)`, `http_close(a)` | The package agreed; the end |

The authentication is the connection's: every request of the exchange
goes on one kept-alive HTTP/1.1 connection. Mutual authentication is
asked for, so with Kerberos the context is made only by the 200's
WWW-Authenticate token, the server's AP-REP: give it to
`http_authorization` and a server without the service's key is found
out. Channel bindings over HTTPS are not sent.

## How it works

`src/sspi.c` holds SSPI's handles in two tables, and Goose sees their
ids. A context also keeps the bytes it was given and has not used: a TLS
record split over two reads, what comes after a handshake message
(SECBUFFER_EXTRA), plaintext not yet taken, the bytes of a message after
the handshake. So Goose only moves bytes between the socket and these
functions (`gsspi_feed`, `gsspi_step`, `gsspi_decrypt`, `gsspi_encrypt`).

The C looks up secur32's and crypt32's functions when first used, and
declares the structures SSPI takes itself rather than including
`<sspi.h>` and `<schannel.h>`. Every C compiler goose drives (TinyCC
under `goose run`, MSVC, clang-cl, clang, MinGW gcc) has `<windows.h>`,
not all have those, and nothing needs linking. Schannel's credentials
are SCH_CREDENTIALS, which TLS 1.3 needs, or SCHANNEL_CRED where the
system predates it (before Windows 10 1809).

## Example and tests

`examples/sspi/`:

```bash
goose build -o packages packages.goose          # the security packages
goose build -o https_get https_get.goose
./https_get https://www.microsoft.com/          # version, suite, certificate, status
./https_get --insecure --tls1.2 https://localhost:8443/
goose build -o negotiate_get negotiate_get.goose
./negotiate_get http://intranet.example.com/    # as the logged-on user
./negotiate_get --user 'EXAMPLE\alice' --password-env PW http://127.0.0.1:8080/
```

```bash
python3 sspi/scripts/run_tests.py [--native]    # text, and the system's packages and contexts
python sspi/scripts/sspi_check.py [--public]    # live, on Windows
```

`test/system.goose` makes a Negotiate context between a client and a
server in one process (NTLM, or Kerberos in a domain), then signs,
verifies, seals and unseals across it and alters a message to see it
refused, and makes a ClientHello through Schannel. Elsewhere it checks
that every call says `SEC_E_UNSUPPORTED_FUNCTION`; the output is the same.

The live check builds the examples, gslib's TLS server
(`crypto/tls/tools/peer`, relayed to a local socket) and `goose-ntlm`. It
connects through Schannel to gslib's TLS server at TLS 1.3 and 1.2 with
P-256 and RSA certificates, through a TLS 1.3 KeyUpdate and with 128 KiB
bodies, and sees its test root refused without `--insecure`. With
`--public` it also checks public sites at TLS 1.3 and 1.2, and badssl.com's
self-signed, wrong-name and expired certificates refused. Negotiate goes
to gslib's NTLM acceptor (`goose-ntlm serve`) as a user with a password
made up for the run, under the Negotiate and NTLM schemes, and a wrong
password is refused.

It passed on Windows Server 2022 with programs built by MSVC, clang-cl and
MinGW gcc.

Kerberos was tried by hand against an Active Directory domain
(Windows Server 2022): a service account with the SPN
`HTTP/<name>` (`setspn -S`), its keytab from `ktpass` (AES256), the name
in DNS, and krb5's `examples/krb5/negotiate_server.goose` serving with the
keytab. `negotiate_get` was authenticated as a domain user by password
(Negotiate, and Kerberos alone) and as the machine account (the
logged-on credentials, run as SYSTEM); the server verified each ticket's
PAC and the client the server's AP-REP. A wrong password was refused
(`SEC_E_LOGON_DENIED`).
