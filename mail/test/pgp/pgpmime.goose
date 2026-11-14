// pgpmime: PGP/MIME from the command line, for scripts/interop_pgp.py
// (not a test of its own; run_tests.py runs test/*.goose only).
//
//   pgpmime sign KEYS SIGNER IN OUT               multipart/signed
//   pgpmime encrypt KEYS RECIPIENT SIGNER IN OUT  multipart/encrypted (SIGNER "-": unsigned)
//   pgpmime open KEYS IN OUT                      the entity inside; "signed by FPR" and
//                                                 "encrypted" lines on standard output
//
// KEYS is a file of OpenPGP keys (secret ones unprotected); SIGNER and
// RECIPIENT are what openpgp::find_key takes (an email address, say).
import std;
import os;
import gslib from "../../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import gslib.mail;
import gslib.mail.pgp;

fn slurp(path: const u8[:]) -> u8[>..] {
    var d: u8[>..] = [];
    if !read_file(path, d) { write_stderr(str("cannot read ", path, "\n")); exit(1); }
    return d;
}

fn fail(what: const u8[:], rc: i64) {
    write_stderr(str("pgpmime: ", what, ": ", mail::error_text(rc), "\n"));
    exit(1);
}

fn key(kr: const openpgp::Keyring&, who: const u8[:]) -> i64 {
    let k = openpgp::find_key(kr, who);
    if k < 0 { write_stderr(str("pgpmime: no key for ", who, "\n")); exit(1); }
    return k;
}

fn main() {
    let a = args();
    if a.len < 5 { write_stderr("usage: pgpmime sign|encrypt|open KEYS ...\n"); exit(2); }
    var kr = openpgp::Keyring { .. };
    let ek = openpgp::add_keys(kr, slurp(a[2]));
    if ek != openpgp::OK { write_stderr(str("pgpmime: keys: ", openpgp::error_text(ek), "\n")); exit(1); }
    let o = pgp::Options { .. };
    var out: u8[>..] = [];
    if a[1] == "sign" && a.len == 6 {
        let rc = pgp::sign(slurp(a[4]), kr, key(kr, a[3]), o, out);
        if rc != mail::OK { fail("sign", rc); }
        if !write_file(a[5], out) { exit(1); }
    } else if a[1] == "encrypt" && a.len == 7 {
        let r = key(kr, a[3]);
        let rc = if a[4] == "-" { pgp::encrypt(slurp(a[5]), kr, [r], o, out) }
                 else { pgp::sign_encrypt(slurp(a[5]), kr, key(kr, a[4]), [r], o, out) };
        if rc != mail::OK { fail("encrypt", rc); }
        if !write_file(a[6], out) { exit(1); }
    } else if a[1] == "open" && a.len == 5 {
        var r = pgp::Opened { .. };
        let rc = pgp::open(slurp(a[3]), kr, "", r);
        if rc != mail::OK { fail("open", rc); }
        if r.encrypted { print("encrypted"); }
        if r.signed { print("signed by ", openpgp::hex(r.signer_fpr)); }
        if !write_file(a[4], r.entity) { exit(1); }
    } else {
        write_stderr("usage: pgpmime sign|encrypt|open KEYS ...\n");
        exit(2);
    }
}
