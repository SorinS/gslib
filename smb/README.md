# smb

An SMB2 and SMB3 client for Goose, as Windows and Samba speak it: every
dialect from 2.0.2 to 3.1.1 over direct TCP (port 445), logins with
NTLMv2 or Kerberos inside SPNEGO, signing and encryption with every
algorithm the dialects have, and the operations of a file share: trees,
files and directories, reading and writing, listing, information, renames
and deletes. Four modules in namespace `smb`, and a tool,
`goose-smbclient`.

**Nothing that should be protected is taken unprotected.** The default
options require signing: every request after SESSION_SETUP is signed, and
every response must carry a right signature. When the session or a share
is encrypted (the server asks, or `require_encryption`), every request
goes in a TRANSFORM_HEADER and every response must come back in one that
decrypts. A response that should have been signed or encrypted and was
not, or whose signature or tag is wrong, ends the request with
`ERR_SIGNATURE` or `ERR_DECRYPT`. The negotiation itself is protected
too: under 3.1.1 the session's keys come from the SHA-512 preauth
integrity hash of every NEGOTIATE and SESSION_SETUP message, and the
server's signature on its last SESSION_SETUP response is checked with
them, so a NEGOTIATE changed on the way makes the login fail; under 3.0
and 3.0.2 the first TREE_CONNECT is followed by a signed
FSCTL_VALIDATE_NEGOTIATE_INFO whose answer must repeat what NEGOTIATE
said. The 3.1.1 server's choices of cipher and signing algorithm must be
among those offered.

**2.x has none of that.** 2.0.2 and 2.1 sign with HMAC-SHA256 under the
session key and cannot encrypt; nothing protects their NEGOTIATE. Raise
`min_dialect` to `SMB30` (or `SMB311`) where the servers allow it.
NTLMv2's session key is only as strong as the password (see `ntlm`);
prefer Kerberos.

Crypto is `crypto/bignum`'s: HMAC-SHA256 and SHA-512, AES-CMAC,
AES-GCM (for GMAC too) and AES-CCM (`bignum.ccm`, added for SMB). NTLM
is `ntlm`'s and SPNEGO and Kerberos are `krb5`'s.

| Module | What |
|---|---|
| `smb.goose` | errors (`error_text`); commands (`command_name`), dialects (`dialect_name`, `parse_dialect`), NT status codes (`status_name`), negotiation's flags and contexts, ciphers (`cipher_name`, `parse_cipher`, `cipher_key_len`) and signing algorithms (`signing_name`, `parse_signing`), session, share and file constants; the header (`Header`, `header`, `put_header`, `parse_header`); little-endian helpers; FILETIMEs (`unix_time`, `filetime_of`); names (`utf16`, `utf8`, `share_path`, `split_unc`); the TCP framing (`put_transport`, `transport_len`) |
| `smb/crypto.goose` | `kdf` (SP 800-108 counter mode, HMAC-SHA256); `Keys` and `derive_keys` (2.x, 3.0's labels, 3.1.1's with the preauth hash, 256-bit keys for AES-256); `preauth_update`; `signature`, `sign`, `verify` (HMAC-SHA256, AES-128-CMAC, AES-128-GMAC); `encrypt_message`, `decrypt_message`, `transform_session` (AES-128/256-CCM/GCM) |
| `smb/messages.goose` | every request's body (`negotiate_request` with its contexts, `session_setup_request`, `tree_connect_request`, `create_request`, `close_request`, `flush_request`, `read_request`, `write_request`, `query_directory_request`, `query_info_request`, `set_info_request`, `ioctl_request`, `empty_request`) and the information they carry (`basic_info`, `rename_info`); every response read (`parse_negotiate_response`, `parse_session_setup_response`, `parse_tree_connect_response`, `parse_create_response`, `parse_close_response`, `parse_read_response`, `parse_write_response`, `parse_output_response`, `parse_ioctl_response`, `error_data`) and what is in them (`parse_directory`, `parse_network_open`, `parse_fs_full_size`), buffers as `Span`s checked to lie in the message |
| `smb/client.goose` | `Options` (`options()`), `Conn`: `dial` (TCP and NEGOTIATE), `login_ntlm`, `login_kerberos`, `login_anonymous`, `logoff`, `hangup`, `echo`; `Tree`: `tree_connect`, `tree_disconnect`; `File`: `open`, `close`, `read`, `write`, `flush`, `query`, `set_times`, `truncate`, `delete_on_close`; by path: `list`, `stat`, `mkdir`, `unlink`, `rmdir`, `rename`, `read_file`, `write_file`, `statfs` |

## Using it

NTLMv2, a share, a file:

```goose
import gslib.smb;
import gslib.smb.messages;
import gslib.smb.client;

var c, e = smb::dial("fs.example.test", 445, smb::options());
e = smb::login_ntlm(c, "alice", "EXAMPLE", "password");
var t, te = smb::tree_connect(c, "\\\\fs.example.test\\share");
let data, re = smb::read_file(c, t, "dir/notes.txt");      // '/' or '\'
smb::write_file(c, t, "dir/copy.txt", data);
let entries, le = smb::list(c, t, "dir", "*");
for x in entries { print(x.name, " ", x.info.size); }
smb::tree_disconnect(c, t);
smb::logoff(c);
smb::hangup(c);
```

A request that the server refused returns `ERR_STATUS`, with the NT
status in `c.status` (`smb::status_name(c.status)`).

The options choose the dialects (`min_dialect`, `max_dialect`), whether
signing (`require_signing`, true) and encryption (`require_encryption`,
false) are required, 3.1.1's offers of ciphers (`ciphers`: AES-128-GCM,
AES-128-CCM, AES-256-GCM, AES-256-CCM) and signing algorithms (`signing`:
AES-128-GMAC, AES-128-CMAC), `validate_negotiate`, the timeout, and the
largest READ or WRITE (`max_io`, 1 MiB):

```goose
var o = smb::options();
o.min_dialect = smb::SMB311;
o.require_encryption = true;
o.ciphers.clear();
o.ciphers.push(smb::AES256_GCM);
var c, e = smb::dial(host, 445, o);
```

Kerberos: a service ticket for `cifs/HOST` from `krb5` (from a password,
a keytab or the ticket cache), then the login; the server's AP-REP is
checked (mutual authentication) and the session key is the subkey, all
of it for AES-256's keys:

```goose
let cfg, ce = krb5::default_config();
let tgt, te = krb5::get_tgt_password(cfg, "alice@EXAMPLE.TEST", password);
let sname, realm, se = krb5::service_name(cfg, "cifs/fs.example.test", false);
let creds, ge = krb5::get_service_ticket(cfg, tgt, sname, realm);   // the service's ticket last
e = smb::login_kerberos(c, ticket);
```

Files by handle, for more than whole files:

```goose
var f, oe = smb::open(c, t, "log.txt", smb::FILE_READ_DATA | smb::FILE_WRITE_DATA | smb::SYNCHRONIZE,
                      smb::FILE_OPEN_IF, smb::FILE_NON_DIRECTORY_FILE);
smb::write(c, f, f.info.size, "one more line\n");      // append at the end
let head, re = smb::read(c, f, 0, 4096);
smb::truncate(c, f, 1024);
let info, qe = smb::query(c, f);                       // FileNetworkOpenInformation
smb::close(c, f);
```

## What happens on the wire

| | 2.0.2, 2.1 | 3.0, 3.0.2 | 3.1.1 |
|---|---|---|---|
| Signing | HMAC-SHA256, the session key | AES-128-CMAC, SP 800-108 keys ("SMB2AESCMAC", "SmbSign") | AES-128-GMAC or AES-128-CMAC (SIGNING_CAPABILITIES), keys from the preauth hash |
| Encryption | none | AES-128-CCM (CAP_ENCRYPTION) | AES-128-GCM, AES-128-CCM, AES-256-GCM, AES-256-CCM (ENCRYPTION_CAPABILITIES) |
| The negotiation protected by | nothing | FSCTL_VALIDATE_NEGOTIATE_INFO | the preauth integrity hash (SHA-512) |
| Credits | one per request, 64 KiB at most | several per request with LARGE_MTU | the same |

Credits: each request is charged one credit per 64 KiB of its payload
(when the server has LARGE_MTU), asks for more while fewer than 256 are
in hand, and a READ or WRITE larger than the server's maximum, `max_io`
or the credits allow is cut into several. Interim responses
(STATUS_PENDING) are waited past; no oplocks or leases are asked for, so
no breaks come. Encryption nonces are a counter and a random salt, never
repeated under one key.

A login with a password or a Kerberos ticket that the server's last
SESSION_SETUP answer calls a guest or null session is refused (`ERR_AUTH`)
rather than carried on without keys: those flags come before the session
has keys to check a signature with, so a man in the middle could set them
to take signing and encryption off a real login. Windows refuses such a
guest fallback too. `login_anonymous` is the way to an anonymous session.

## goose-smbclient

```
goose-smbclient [options] //SERVER/SHARE COMMAND [ARGS] [\; COMMAND [ARGS]]...
```

`ls [DIR]`, `get REMOTE [LOCAL]`, `put LOCAL [REMOTE]`, `cat`, `mkdir`,
`rmdir`, `rm`, `mv FROM TO`, `stat`, `truncate FILE SIZE`, `touch`,
`df`, `info` (the dialect, signing and encryption negotiated) and `echo`,
several in one connection separated by `;`. `-U USER` (or `DOMAIN\user`),
the password from `--password` or `$SMB_PASSWORD`, `--kerberos` (a TGT
from the password through `KRB5_CONFIG`'s KDC, else the ticket cache;
`--spn-host` for the SPN's host), `--anonymous`, `--dialect`,
`--min-dialect`, `--max-dialect`, `--cipher`, `--signing`, `--encrypt`,
`--no-sign`, `--no-validate`, `--max-io`, `--port`.

## Examples

`examples/smb/`:

- `keys.goose`: 3.1.1's keys, encryption and GMAC signing without a
  server, on Microsoft's published vector: the same keys and the same
  encrypted WRITE as Windows.
- `client.goose`: NTLMv2 against a real server: a listing, a file
  written, read back, renamed, deleted.
- `kerberos.goose`: Kerberos, then a session encrypted with AES-256-GCM.

## Tests

```bash
make test-smb                                     # or: cd smb && python3 scripts/run_tests.py
make interop-smb                                  # Linux with Docker
```

Every test runs at -O0, -O2 and with `--debug`:

- `test/vectors.goose`: Microsoft's SMB 3 test vectors from the Open
  Specifications blog (`test/vectors/ms.txt`): the 3.1.1 preauth hash
  over Windows's NEGOTIATE and SESSION_SETUP messages (10), the 3.0 and
  3.1.1 keys of seven sessions (signing, encryption, decryption,
  application; a binding channel's signing key), the AES-128-CMAC
  signatures of final SESSION_SETUP responses, and twelve WRITE and
  READ messages encrypted and decrypted with AES-128-CCM (3.0, 3.1.1)
  and AES-128-GCM (3.1.1), byte for byte both ways, and refused when
  changed; HMAC-SHA256 and AES-128-GMAC signing against their
  definitions (the direction and CANCEL in GMAC's nonce, a reflected
  request refused), AES-256's keys from a 32-byte session key, each
  cipher round-tripped and the other direction's key refused.
- `test/messages.goose`: Windows's NEGOTIATE (with its contexts),
  SESSION_SETUP, WRITE and READ requests built again byte for byte, and
  the responses in the vectors read; the header both ways; every
  truncation of a NEGOTIATE response refused, misaligned or repeated
  contexts, a hash other than SHA-512, two ciphers, buffers outside the
  message; directory listings (UTF-16 names, every truncation, entries
  that overlap or have odd names refused); file and file system
  information; share paths (".." refused), UNC names, FILETIMEs.
- `crypto/bignum/test/ccm_vectors.goose`: AES-CCM against SP 800-38C's
  examples, RFC 3610's packet vector 1, Microsoft's SMB 3.0 vector and
  42 random cases from a Python transcription (every nonce and tag
  length, AAD past the two-byte length form), tampering refused.

`scripts/interop.py` (`make interop-smb`) runs against Samba 4.17 in
Docker on loopback: a file server (signing and encryption as the client
asks, a share that requires encryption), a second that requires signing
and encryption for every session, and an AD DC (realm SMB.TEST) for
Kerberos:

- every dialect, 2.0.2 to 3.1.1, with NTLMv2: directories, small files
  and a 5 MiB one (multi-credit READ and WRITE), ls, stat, mv, truncate,
  touch, rm, rmdir, df, echo, the signing algorithm each dialect has and
  3.0's validate-negotiate; what goose-smbclient wrote read by Samba's
  smbclient, and the other way;
- 3.1.1 with GMAC and with CMAC; READ and WRITE of 64 KiB and of 8 MiB;
- encryption the client asks for: AES-128-CCM on 3.0 and 3.0.2, all four
  ciphers on 3.1.1; a share that requires it, and a server that does,
  on 3.0, 3.0.2 and 3.1.1; 2.1 refused by both, and encryption required
  of a 2.1 server refused by the client;
- Kerberos: 3.1.1 encrypted with AES-256-GCM (the 256-bit key from the
  whole session key), 3.0, 2.1, a wrong password; NTLM as a domain user
  on the DC;
- an anonymous session on IPC$, and refused when signing is required; a
  wrong password, an unknown share, a missing file;
- a man in the middle (a proxy in the script) changing one response: a
  signature, the SIGNED flag removed, the final SESSION_SETUP's
  signature, an encrypted message, a NEGOTIATE response under 3.1.1
  (caught by the preauth hash) and under 3.0 (twice: the capabilities
  and the security mode, caught by validate-negotiate). Each one fails
  the client; the proxy unchanged lets it through.

`fuzz/targets/smb.goose` gives arbitrary bytes to every response parser
and what reads their buffers, to decryption under each cipher, to
signature checks under each algorithm, and to the name helpers.

## Not done

- A server.
- Compounded requests, multichannel (session binding), durable and
  persistent handles, oplocks and leases, change notifications, byte-range
  locks, SMB over QUIC and RDMA, compression, DFS referrals.
- Security descriptors (QUERY_INFO's SECURITY), extended attributes,
  alternate data streams, reparse points and symbolic links.
- SMB1, and the SMB1 NEGOTIATE that asks a server for SMB2.
- RPC over IPC$ (listing a server's shares needs srvsvc).
