// http_client: GET a page that wants NTLM (IIS, an http.sys service, a
// proxy's web front), with net/http's client: AUTH_NTLM answers the 401's
// "WWW-Authenticate: NTLM" (or "Negotiate", carrying raw NTLMSSP) with
// the NEGOTIATE, then the CHALLENGE with the AUTHENTICATE, on the same
// HTTP/1.1 connection; over https the server certificate's
// tls-server-end-point goes in as the channel binding. The password comes
// from the environment, never the command line.
//
//   NTLM_PASSWORD=... goose examples/ntlm/http_client.goose -- 'DOMAIN\user' https://web.example.test/
//
// goose-ntlm serve (ntlm/tools) is a server to try it against.

import std;
import os;
import gslib from "../..";
import gslib.net.http;
import gslib.net.http.client;
import gslib.net.http.fetch;

fn main() {
    let a = args();
    if a.len < 3 {
        print("usage: http_client 'DOMAIN\\user' URL (password in NTLM_PASSWORD)");
        exit(2);
    }
    var password: u8[>..] = [];
    if !env("NTLM_PASSWORD", password) {
        print("http_client: set NTLM_PASSWORD");
        exit(2);
    }
    var c = http::Client { .. };
    c.opt.auth = http::AUTH_NTLM;     // NTLM only; AUTH_ANY ranks it after Digest, before Basic
    c.opt.http2 = false;              // NTLM is per connection: HTTP/1.1
    http::set_credentials(c, a[1], password);
    var r = http::get(c, a[2]);
    if r.err != 0 {
        print("http_client: ", http::client_error_text(r.err));
        exit(1);
    }
    print("HTTP ", r.status);
    print(http::response_body(r));
    if r.status != 200 { exit(1); }
}
