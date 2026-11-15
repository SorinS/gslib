// Messages made by Go's lestrrat-go/jwx v4 (test/vectors/go_jwx.txt, from
// scripts/differential: go run . gen): every signature algorithm (Ed448,
// and ML-DSA with AKP keys, too), compact and JSON, and every key management
// algorithm with every content algorithm, some compressed, some as JSON,
// each verified or decrypted here with its key, and refused with a byte
// of the signature or tag changed. tools/tokens.goose and `go run . check` go the other way.
import std;
import os;
import gslib from "../..";
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwe;
import tv;

fn main() {
    // The file differential.py names, or the one kept with the tests.
    var path: const u8[:] = "vectors/go_jwx.txt";
    var i = 0;
    for a in args() {
        if i > 0 { path = a; }     // args()[0] is the program
        i++;
    }
    var text: u8[>..] = [];
    if !read_file(path, text) { abort(str("cannot read ", path)); }
    var count = 0;
    each_split(text, '\n') {
        let f = split(it, '\t');
        if f.len == 7 {
            var p: const u8[:][7] = ["", "", "", "", "", "", ""];
            var i = 0;
            for x in f { p[i] = x; i++; }
            let kind = p[0];
            let alg = jwa::lookup(p[1]);
            let key, ek = jwk::parse(p[4]);
            let what = str(kind, " ", p[1], " ", p[2], if p[3] == "1" { " zip" } else { "" });
            tv::check_int(str(what, " key"), ek, jwx::OK);
            let payload = p[5];
            let msg = p[6];
            // A changed byte near the end: the signature, or the tag.
            var bad: u8[>..] = [];
            bad.append(msg);
            let at = if kind == "jws" || kind == "jwe" { bad.len - 2 } else { find(bad, "\"tag\"") + 9 };
            bad[at] = if bad[at] == 'A' { 'B' } else { 'A' };
            if starts_with(kind, "jws") {
                let pub = jwk::public_key(key);
                let got, e = jws::verify(msg, alg, pub);
                tv::check(str(what, " verified ", jwx::error_text(e)), e == jwx::OK && got == payload);
                let x, ex = jws::verify(bad, alg, pub);
                tv::check(str(what, " changed refused"), ex != jwx::OK);
            } else {
                let got, e = jwe::decrypt(msg, alg, key);
                tv::check(str(what, " decrypted ", jwx::error_text(e)), e == jwx::OK && got == payload);
                let x, ex = jwe::decrypt(bad, alg, key);
                tv::check(str(what, " changed refused"), ex != jwx::OK);
            }
            count++;
        }
    };
    tv::check("vectors read", count > 100);
    print("go jwx: ", count, " messages");
    tv::done("go_jwx");
}
