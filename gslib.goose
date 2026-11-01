// gslib: libraries for Goose, the batteries a standard library leaves out:
// arbitrary-precision and constant-time arithmetic and the cryptography
// built on it (bignum), ASN.1 and PEM (asn1), X.509 (x509), TLS 1.2 and
// 1.3 (tls), SSH and SFTP (ssh), LDAP (ldap), YAML (yaml), HTTP/1.1 and
// HTTP/2 (http), compression and archives (compress), MIME (mime), and
// Kerberos with GSS-API, SPNEGO and the PAC (krb5). A
// program declares the package once and imports the modules it uses,
// grouped as Go groups them (compress, crypto/, encoding/, mime, net/;
// krb5 at the top too);
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
