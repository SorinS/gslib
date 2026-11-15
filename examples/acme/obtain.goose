// obtain: a certificate from an ACME server in one call, proving the names
// by dns-01; the TXT records are printed for you to publish (a program
// would update its DNS here: goose-acme does it by RFC 2136). The account
// key is made for this run. Needs a server, so `make test` only
// type-checks it:
//
//   goose examples/acme/obtain.goose -- DIRECTORY-URL CA-FILE NAME...
//
// For instance against Let's Encrypt's staging server (whose roots are not
// in the system's store), for names whose DNS you control:
//
//   goose examples/acme/obtain.goose -- https://acme-staging-v02.api.letsencrypt.org/directory \
//       staging-roots.pem www.example.org

import std;
import os;
import gslib from "../..";
import gslib.acme;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.pool;

fn main() {
    let args = args();
    if args.len < 4 {
        write_stderr("usage: obtain DIRECTORY-URL CA-FILE NAME...\n");
        exit(2);
    }
    var hc = http::Client { .. };
    var roots: u8[>..] = [];
    if !read_file(args[2], roots) { write_stderr("cannot read the CA file\n"); exit(1); }
    var pool = x509::new_pool();
    x509::pool_append_pem(pool, roots);
    hc.tlscfg = tls::client_config_pool("", pool);

    var a = acme::Client { .. };
    let account_key = jwk::generate_ec(jwa::CRV_P256);
    acme::set_key(a, account_key);
    var err = acme::open(a, hc, args[1]);
    if err == acme::OK { err = acme::new_account(a, hc, "", true); }
    if err != acme::OK { print("no account: ", acme::error_text(err), " ", a.problem.detail); exit(1); }

    var names: u8[>..]    = [];
    var san:   u8[..4096] = [];
    for name, i in args {
        if i < 3 { continue; }
        names.append(name);
        names.push('\n');
        x509::add_dns(san, name);
    }
    let key = x509::generate_key(x509::KEY_EC_P256);
    let subject, ok = x509::name_der("");
    let csr, cerr = x509::create_csr(subject, san, key);

    let chain, oerr = acme::obtain(a, hc, names, csr, "dns-01") { z, ch, value =>
        print("publish TXT ", acme::dns01_name(z.id_value), " \"", value, "\", then press return");
        var line: u8[>..] = [];
        read_line(line);
        true
    };
    if oerr != acme::OK { print("failed: ", acme::error_text(oerr), " ", a.problem.detail); exit(1); }
    // The chain is public; a program keeps `key` too (x509::marshal_pkcs8),
    // in a file only its owner can read, as goose-acme does.
    print(chain);
}
