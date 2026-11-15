// request: a time-stamp for a file from a TSA you name, over HTTP, checked
// against the roots in a PEM file: the token's signature, the TSA's
// certificate and its path, the imprint and the nonce. Needs a TSA, so
// `make test` only type-checks it.
//
//   goose examples/tsp/request.goose -- URL FILE ROOTS.pem
//
// URL is the TSA's (http:// or https://); the reply is written to FILE.tsr.

import std;
import os;
import gslib from "../..";
import gslib.tsp;
import gslib.net.http;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.crypto.x509;
import gslib.crypto.x509.pool;

fn main() {
    let a = args();
    if a.len != 4 {
        write_stderr("usage: goose examples/tsp/request.goose -- URL FILE ROOTS.pem\n");
        exit(2);
    }
    var data: u8[>..] = [];
    var pem:  u8[>..] = [];
    if !read_file(a[2], data) || !read_file(a[3], pem) {
        write_stderr("cannot read the file or the roots\n");
        exit(1);
    }
    var roots = x509::new_pool();
    if x509::pool_append_pem(roots, pem) <= 0 { write_stderr("no certificates in the roots file\n"); exit(1); }

    let req, e = tsp::new_request(tsp::SHA256, data);
    let query, qe = tsp::request_der(req);
    var hc = http::Client { .. };
    let reply, he, why_http = tsp::post(hc, a[1], query);
    if he != tsp::OK { print("no reply: ", tsp::error_text(he), " (", why_http, ")"); exit(1); }
    write_file(str(a[2], ".tsr"), reply);

    let r, pe = tsp::parse_response(reply);
    if pe != tsp::OK { print("not a time-stamp reply"); exit(1); }
    if r.status != tsp::GRANTED && r.status != tsp::GRANTED_WITH_MODS {
        print("refused: ", tsp::status_name(r.status), " ", tsp::fail_info_text(r.fail_info), " ", r.status_text);
        exit(1);
    }
    let o = tsp::VerifyOptions { now: time_ns() / 1000000000, .. };
    let info, ve, why = tsp::verify_reply(r, req, roots, "", o);
    if ve != tsp::OK { print("not verified: ", tsp::error_text(ve), " ", x509::error_text(why)); exit(1); }
    write_stdout(tsp::info_text(info));
    print("verified; the reply is in ", a[2], ".tsr");
}
