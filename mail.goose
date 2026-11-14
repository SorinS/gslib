// mail: sending and fetching email, as Go's go-mail (github.com/wneessen/go-mail)
// does for sending: messages built and written in RFC 5322 / MIME form, an
// SMTP client, and a POP3 client.
//
//   mail          this module: errors, shared by all of them
//   mail.address  addresses: parsing and writing "Name <user@host>" (RFC 5322 §3.4)
//   mail.message  a message: headers, text and HTML bodies, attachments,
//                 inline parts, written as MIME (namespace mail)
//   mail.link     the connection: a socket, TLS from the start or after
//                 STARTTLS/STLS, lines in and out (namespace mail)
//   mail.sasl     authentication: PLAIN, LOGIN, CRAM-MD5, SCRAM-SHA-1 and
//                 SCRAM-SHA-256, XOAUTH2 (namespace mail)
//   mail.smtp     an SMTP client (RFC 5321) (namespace smtp)
//   mail.pop3     a POP3 client (RFC 1939) (namespace pop3)
//   mail.imap     an IMAP client (RFC 9051, RFC 3501 servers too) (namespace imap)
//   mail.dkim     DKIM signing and verification (RFC 6376, RFC 8463) (namespace dkim)
//   mail.smime    S/MIME signing and encryption (RFC 8551) (namespace smime)
//   mail.pgp      PGP/MIME signing and encryption (RFC 3156), over
//                 crypto.openpgp (namespace pgp)
//
// The clients do their own I/O, over gslib's net sockets and its TLS.

namespace mail;

import std;

// --- Errors -------------------------------------------------------------------
//
// Fallible functions return one of these, OK (0) for success; error_text
// says what each means. A server's refusal is ERR_REPLY; the client keeps
// the reply itself (its code and text).

let OK:              i64 = 0;
let ERR_ARG:         i64 = 1;    // an argument that cannot be used: a host, a port, an empty address
let ERR_RESOLVE:     i64 = 2;    // the host name does not resolve
let ERR_CONNECT:     i64 = 3;    // refused or unreachable
let ERR_TIMEOUT:     i64 = 4;
let ERR_IO:          i64 = 5;    // reset, closed early, or another socket error
let ERR_TLS:         i64 = 6;    // the TLS handshake failed (the certificate, an alert) or TLS broke
let ERR_PROTOCOL:    i64 = 7;    // a reply that does not parse, or one too long
let ERR_REPLY:       i64 = 8;    // the server refused: its reply is in the client
let ERR_LINE:        i64 = 9;    // CR, LF (or NUL, for IMAP) inside a command's argument
let ERR_NO_TLS:      i64 = 10;   // TLS is required and the server does not offer STARTTLS/STLS
let ERR_AUTH:        i64 = 11;   // no mechanism both sides have, a malformed challenge, or a SCRAM server that does not prove itself
let ERR_STATE:       i64 = 12;   // a command out of order: not connected, or already closed
let ERR_ADDRESS:     i64 = 13;   // an address that does not parse
let ERR_HEADER:      i64 = 14;   // a header name or value that cannot be written
let ERR_UNSUPPORTED: i64 = 15;   // something the server does not have (SMTPUTF8, an extension), or an algorithm not done here
let ERR_LONG_LINE:   i64 = 16;   // a message line would pass 998 bytes (an 8bit body's, say)
let ERR_SIGNATURE:   i64 = 17;   // a DKIM or S/MIME signature that does not verify, or a body hash that does not match
let ERR_KEY:         i64 = 18;   // a key that cannot be used: missing, malformed, revoked, the wrong type or too small
let ERR_DNS:         i64 = 19;   // a DKIM key lookup failed (no record, or the server did not answer)
let ERR_DECRYPT:     i64 = 20;   // an encrypted message not for this key, or one that does not decrypt
let ERR_CERT:        i64 = 21;   // a certificate that cannot be used: no match for the signer or recipient, the wrong usage
let ERR_FORMAT:      i64 = 22;   // a malformed signature header, CMS structure or MIME part

// Whether a and b are equal, ASCII letters compared without case: command
// and extension names, header names.
fn eq_fold(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len {
        var x = a[i];
        var y = b[i];
        if x >= 'A' && x <= 'Z' { x += 32; }
        if y >= 'A' && y <= 'Z' { y += 32; }
        if x != y { return false; }
    }
    return true;
}

fn error_text(code: i64) -> const u8[:] {
    match code {
        OK => "",
        ERR_ARG => "mail: invalid argument",
        ERR_RESOLVE => "mail: host name does not resolve",
        ERR_CONNECT => "mail: connection refused or host unreachable",
        ERR_TIMEOUT => "mail: timed out",
        ERR_IO => "mail: connection error",
        ERR_TLS => "mail: TLS failed",
        ERR_PROTOCOL => "mail: malformed server reply",
        ERR_REPLY => "mail: the server refused the command",
        ERR_LINE => "mail: a command argument contains CR, LF or NUL",
        ERR_NO_TLS => "mail: the server does not offer TLS",
        ERR_AUTH => "mail: authentication failed: no common mechanism, a malformed challenge, or the server did not prove itself",
        ERR_STATE => "mail: command out of order",
        ERR_ADDRESS => "mail: invalid address",
        ERR_HEADER => "mail: invalid header",
        ERR_UNSUPPORTED => "mail: not supported (by the server, or here)",
        ERR_LONG_LINE => "mail: a line of the message is longer than 998 bytes",
        ERR_SIGNATURE => "mail: the signature does not verify",
        ERR_KEY => "mail: the key cannot be used",
        ERR_DNS => "mail: the key's DNS lookup failed",
        ERR_DECRYPT => "mail: the message does not decrypt with this key",
        ERR_CERT => "mail: the certificate cannot be used",
        ERR_FORMAT => "mail: malformed signature, CMS structure or MIME part",
        _ => "mail: unknown error",
    }
}
