// gslib: libraries for Goose, the batteries a standard library leaves out:
// arbitrary-precision and constant-time arithmetic and the cryptography
// built on it (bignum), ASN.1 and PEM (asn1), X.509 (x509), TLS 1.2 and
// 1.3 (tls), SSH and SFTP (ssh), LDAP (ldap), YAML (yaml), HTTP/1.1 and
// HTTP/2 (http), TCP sockets (net), compression and archives (compress),
// MIME (mime), and Kerberos with GSS-API, SPNEGO and the PAC (krb5),
// JOSE: JWK, JWS, JWE and JWT (jwx), PKCS#11 modules, HSMs and tokens (pkcs11), the
// DNS: messages, zone files, DNSSEC, TSIG, a client and a server (dns),
// email: messages, SMTP, POP3 and IMAP clients, DKIM, S/MIME and PGP/MIME
// (mail), OpenPGP: keys, signatures and encryption as gpg reads and
// writes them (openpgp), certificates from ACME servers (acme), and
// OAuth 2.0 and OpenID Connect clients: tokens, PKCE, DPoP, ID token
// validation (oauth). A program declares the package once and imports the
// modules it uses, grouped as Go groups them (compress, crypto/,
// encoding/, mime, net/; krb5, jwx, pkcs11, dns, mail, acme, oauth and
// net's sockets at the top too);
// each keeps its own namespace:
//
//   import gslib from "SorinS/gslib@v0.1";
//   import gslib.net.http.fetch;      // http::fetch, http::get, ...
//   import gslib.crypto.tls.handshake;   // tls::client, tls::server, ...
//
// Only the modules a program imports are compiled. This entry holds the
// version alone.

namespace gslib;

let VERSION: const u8[:] = "0.1";
