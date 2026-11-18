// gslib: libraries for Goose, the batteries a standard library leaves out:
// arbitrary-precision and constant-time arithmetic and the cryptography
// built on it (bignum), ASN.1 and PEM (asn1), X.509 (x509), TLS 1.2 and
// 1.3 (tls), SSH and SFTP (ssh), LDAP (ldap), YAML (yaml), XML with
// canonicalization, signatures and encryption (xml), CBOR, strict and
// deterministic, and COSE keys (cbor), HTTP/1.1 and
// HTTP/2 (http), TCP sockets (net), compression and archives (compress),
// MIME (mime), and Kerberos with GSS-API, SPNEGO and the PAC (krb5),
// JOSE: JWK, JWS, JWE and JWT (jwx), PKCS#11 modules, HSMs and tokens (pkcs11), the
// DNS: messages, zone files, DNSSEC, TSIG, a client and a server (dns),
// email: messages, SMTP, POP3 and IMAP clients, DKIM, S/MIME and PGP/MIME
// (mail), OpenPGP: keys, signatures and encryption as gpg reads and
// writes them (openpgp), certificates from ACME servers (acme),
// OAuth 2.0 and OpenID Connect clients: tokens, PKCE, DPoP, ID token
// validation (oauth), RFC 3161 time-stamps: asking a TSA, checking
// its tokens, being one (tsp), certificates by EST (est) and by SCEP
// (scep), with test CAs for each, and SAML 2.0 single sign-on and logout,
// service provider and identity provider (saml), NTLMv2
// authentication, both sides, with SPNEGO, HTTP and SASL (ntlm), and
// TPM 2.0: sessions, keys, sealing, NV and attestation, its checks in
// software (tpm2), and WebAuthn and passkeys for a relying party, with
// every attestation format and FIDO MDS3 (webauthn), RADIUS, RadSec
// and EAP (PEAP, TTLS, EAP-TLS), client and server (radius), an SMB2
// and SMB3 client: dialects 2.0.2 to 3.1.1, signing and encryption,
// NTLMv2 and Kerberos (smb), programs as
// Windows services, systemd units and launchd jobs (service), and the
// operating system's own calls: processes, users, files, the Windows
// registry and management, signals, terminals (sys), and Windows' SSPI:
// Schannel TLS and Negotiate (Kerberos/NTLM) from the login (sspi), with
// the OS's random bytes for keys under all of it (entropy). A program
// declares the package once and imports the
// modules it uses, grouped as Go groups them (compress, crypto/,
// encoding/, mime, net/; krb5, jwx, pkcs11, dns, mail, acme, oauth, tsp, est, scep, saml, ntlm, tpm2, webauthn, radius, smb, service, sys, sspi, entropy and
// net's sockets at the top too);
// each keeps its own namespace:
//
//   import gslib from "SorinS/gslib@v0.7.0";
//   import gslib.net.http.fetch;      // http::fetch, http::get, ...
//   import gslib.crypto.tls.handshake;   // tls::client, tls::server, ...
//
// Only the modules a program imports are compiled. This entry holds the
// version alone.

namespace gslib;

let VERSION: const u8[:] = "0.1";
