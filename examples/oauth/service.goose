// service: a service calling an API with a token of its own (client
// credentials), as a backend does: discover the issuer, get a token,
// look at what the server says of it (introspection), call the API with
// it, and give it back (revocation). The secret comes from the
// environment, never from the command line.
//
//   OAUTH_CLIENT_SECRET=... goose examples/oauth/service.goose -- https://login.example.test my-service https://api.example.test/things
//
// Needs a server, so `make test` only type-checks it.

import std;
import os;
import gslib from "../..";
import gslib.oauth;
import gslib.net.http;
import gslib.net.http.client;
import gslib.net.http.fetch;

fn main() {
    let a = args();
    if a.len < 4 {
        print("usage: service.goose ISSUER CLIENT_ID API_URL (secret in $OAUTH_CLIENT_SECRET)");
        exit(2);
    }
    var secret: u8[>..] = [];
    if !env("OAUTH_CLIENT_SECRET", secret) || secret.len == 0 {
        print("set OAUTH_CLIENT_SECRET");
        exit(2);
    }
    var hc = http::Client { .. };
    var c = oauth::Client { .. };
    var err = oauth::discover(c, hc, a[1]);
    if err != oauth::OK { print("discovery: ", oauth::error_text(err)); exit(1); }
    oauth::set_secret(c, a[2], secret, oauth::AUTH_SECRET_BASIC);

    let t, terr = oauth::client_credentials(c, hc, "api:read");
    if terr != oauth::OK {
        print("no token: ", oauth::error_text(terr), " ", c.error.code, " ", c.error.description);
        exit(1);
    }
    print("a ", t.token_type, " token for ", t.expires_in, " s, scope \"", t.scope, "\"");

    if c.meta.introspection_endpoint.len > 0 {
        let it, ierr = oauth::introspect(c, hc, t.access_token, "access_token");
        if ierr == oauth::OK { print("introspection: active ", it.active, ", client ", it.client_id, ", expires ", it.exp); }
    }

    let r, rerr = oauth::resource_request(c, hc, "GET", a[3], t, "Accept: application/json\r\n");
    if rerr == oauth::OK {
        print("the API answered ", r.status, " with ", http::response_body(r).len, " bytes");
    } else if rerr == oauth::ERR_OAUTH {
        print("the API refused the token: ", c.error.code, " ", c.error.description);
    } else {
        print("the API could not be reached: ", oauth::error_text(rerr));
    }

    if c.meta.revocation_endpoint.len > 0 {
        err = oauth::revoke(c, hc, t.access_token, "access_token");
        print("revoked: ", err == oauth::OK);
    }
}
