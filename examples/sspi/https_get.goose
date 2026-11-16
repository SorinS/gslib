// https_get: a GET over Windows' own TLS (Schannel): the version and
// cipher suite agreed, the server's certificate, the response's status
// line and how long its body was.
//
//   https_get [--insecure] [--tls1.2 | --tls1.3] [--body] URL
//
// --insecure takes any certificate (SCH_CRED_MANUAL_CRED_VALIDATION), for
// a test server's; the check is then the caller's, and this prints the
// certificate's subject and issuer either way. --tls1.2 and --tls1.3 pin
// the version. --body prints the body too.

import std;
import os;
import gslib from "../..";
import gslib.sspi;
import gslib.sspi.schannel;
import gslib.encoding.asn1;
import gslib.crypto.x509;

fn usage() {
    write_stderr("usage: https_get [--insecure] [--tls1.2 | --tls1.3] [--body] https://host[:port]/path\n");
    exit(2);
}

fn main() {
    let argv = args();
    var insecure = false;
    var body = false;
    var version = 0;
    var url: const u8[:] = "";
    for i in 1..argv.len {
        let a = argv[i];
        if a == "--insecure" { insecure = true; }
        else if a == "--body" { body = true; }
        else if a == "--tls1.2" { version = 0x0303; }
        else if a == "--tls1.3" { version = 0x0304; }
        else if url.len == 0 && starts_with(a, "https://") { url = a; }
        else { usage(); }
    }
    if url.len == 0 { usage(); }
    var rest = url[8..];
    var slash = 0;
    while slash < rest.len && rest[slash] != '/' { slash++; }
    let hostport = rest[..slash];
    let path = if slash < rest.len { rest[slash..] } else { "/" };
    var colon = 0;
    while colon < hostport.len && hostport[colon] != ':' { colon++; }
    let host = hostport[..colon];
    var port = 443;
    if colon < hostport.len {
        let p, ok = parse_int(hostport[colon + 1..]);
        if !ok { usage(); }
        port = p;
    }

    var cfg = sspi::tls_config(host);
    cfg.verify = !insecure;
    cfg.min_version = version;
    cfg.max_version = version;
    var c, st = sspi::tls_dial(host, port, cfg);
    if st != sspi::OK {
        write_stderr(str("https_get: ", sspi::tls_error_text(st), "\n"));
        exit(1);
    }
    let v = sspi::tls_version(c);
    print(str("version: ", if v == 0x0304 { "TLS 1.3" } else if v == 0x0303 { "TLS 1.2" } else { "older" },
              "  suite: ", sspi::tls_cipher_suite_name(c)));
    let der = sspi::tls_peer_certificate(c);
    let cert, e = x509::parse(der);
    if e == x509::OK {
        print(str("subject: ", x509::subject_text(cert)));
        print(str("issuer: ", x509::issuer_text(cert)));
    } else {
        print(str("certificate: ", der.len, " bytes, not parsed"));
    }

    var req: u8[>..] = [];
    req.append(str("GET ", path, " HTTP/1.1\r\nHost: ", hostport, "\r\nUser-Agent: goose-sspi\r\nConnection: close\r\n\r\n"));
    let w = sspi::tls_write(c, req);
    if w < 0 { write_stderr(str("https_get: ", sspi::tls_error_text(w), "\n")); exit(1); }
    var resp: u8[>..] = [];
    var buf:  u8[>..] = [];
    buf.resize(16384, 0);
    while true {
        let n = sspi::tls_read(c, buf);
        if n == 0 { break; }
        if n < 0 { write_stderr(str("https_get: ", sspi::tls_error_text(n), "\n")); exit(1); }
        resp.append(buf[..n]);
    }
    sspi::tls_close(c);
    var eol = 0;
    while eol < resp.len && resp[eol] != '\r' { eol++; }
    print(str("status: ", resp[..eol]));
    var hdr_end = 0;
    while hdr_end + 4 <= resp.len && resp[hdr_end..hdr_end + 4] != "\r\n\r\n" { hdr_end++; }
    let b = if hdr_end + 4 <= resp.len { resp[hdr_end + 4..] } else { resp[resp.len..] };
    print(str("body: ", b.len, " bytes"));
    if body { write_stdout(b); }
}
