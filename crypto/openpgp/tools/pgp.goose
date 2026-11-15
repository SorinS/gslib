// goose-pgp: OpenPGP from the command line, over crypto.openpgp, as
// scripts/interop.py drives it against gpg.
//
//   goose-pgp sign [-k KEYS]... [-u WHO] [--detach | --clear] [--text] [--binary] [-z ALGO] [--hash H] IN OUT
//   goose-pgp verify [-k KEYS]... IN [SIG]          IN is a message, a cleartext message, or data SIG signs
//   goose-pgp encrypt [-k KEYS]... [-r WHO]... [--symmetric] [--sign [-u WHO]] [--binary] [-z ALGO] [--cipher C] IN OUT
//   goose-pgp decrypt [-k KEYS]... [--allow-unprotected] IN OUT
//   goose-pgp list-packets IN
//   goose-pgp list-keys KEYS...
//   goose-pgp export [--secret] [-k KEYS]... WHO OUT
//   goose-pgp armor message|signature|public|private IN OUT
//   goose-pgp dearmor IN OUT
//   goose-pgp genkey [--pass-file F] [--type T] "Name <email>" SECRET_OUT [PUBLIC_OUT]
//
// genkey's --type: ed25519 (the default: Ed25519 + Curve25519, as gpg's
// default), rsa (RSA-3072), brainpoolP256r1, brainpoolP384r1 or
// brainpoolP512r1 (ECDSA + ECDH on that curve), ed448 (gpg's: v5 Ed448 +
// cv448), ed448-v6 (RFC 9580's Ed448 + X448, v6, which gpg does not read),
// pqc (gpg 2.5's default post-quantum key: brainpoolP384r1 with a v5
// ky768_bp256 Kyber subkey, ML-KEM-768+brainpoolP256r1), ky768_cv25519
// (Ed25519 with a ky768_cv25519 subkey, ML-KEM-768+X25519) or rfc9980 (v6
// ML-DSA-65+Ed25519 with an ML-KEM-768+X25519 subkey, which gpg does not
// read).
//
// --pass-file FILE gives the passphrase that unlocks the keys and opens
// (or, with --symmetric, makes) a passphrase-encrypted message; it is read
// from a file so that it never shows in a process list. OUT "-" is
// standard output. Exit status 0 on success, 1 with a message on standard
// error otherwise; verify prints one line per signature.
import std;
import os;
import gslib from "../../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.armor;
import gslib.crypto.openpgp.packet;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.sig;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import gslib.crypto.openpgp.dump;
import gslib.crypto.openpgp.keygen;

fn usage() {
    write_stderr("usage: goose-pgp sign|verify|encrypt|decrypt|list-packets|list-keys|export|armor|dearmor|genkey [options] ...\n");
    exit(2);
}

fn fail(what: const u8[:], err: i64) {
    write_stderr(str("goose-pgp: ", what, ": ", openpgp::error_text(err), "\n"));
    exit(1);
}

fn die(msg: const u8[:]) {
    write_stderr(str("goose-pgp: ", msg, "\n"));
    exit(1);
}

fn slurp(path: const u8[:]) -> u8[>..] {
    var d: u8[>..] = [];
    if path == "-" { read_stdin(d); return d; }
    if !read_file(path, d) { die(str("cannot read ", path)); }
    return d;
}

// A text literal's data with its CRLF line ends made LF again, as gpg
// writes it out.
fn native_text(data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < data.len {
        if data[i] == '\r' && i + 1 < data.len && data[i + 1] == '\n' { i++; }
        out.push(data[i]);
        i++;
    }
    return out;
}

fn emit(path: const u8[:], data: const u8[:]) {
    if path == "-" { write_stdout(data); flush_stdout(); return; }
    if !write_file(path, data) { die(str("cannot write ", path)); }
}

root struct Opts {
    keys:              u8[>..]               = [], // key file names, NUL-separated
    signer:            u8[>..]               = [],
    recipients:        u8[>..]               = [], // NUL-separated
    pass:              u8[>..]               = [],
    has_pass:          bool                  = false,
    detach:            bool                  = false,
    clear:             bool                  = false,
    symmetric:         bool                  = false,
    do_sign:           bool                  = false,
    secret:            bool                  = false,
    allow_unprotected: bool                  = false,
    key_type:          u8[>..]               = [],
    w:                 openpgp::WriteOptions = openpgp::WriteOptions { .. },
    rest:              i64[>..]              = [], // the indices of the arguments that are not options
}

fn add_name(list: u8[>..]&, n: const u8[:]) {
    if list.len > 0 { list.push(0); }
    list.append(n);
}

fn parse_opts(a, o: Opts&) {
    var i = 2;
    while i < a.len {
        let f = a[i];
        i++;
        if f == "--detach" { o.detach = true; continue; }
        if f == "--clear" { o.clear = true; continue; }
        if f == "--text" { o.w.text = true; continue; }
        if f == "--binary" { o.w.armored = false; continue; }
        if f == "--symmetric" { o.symmetric = true; continue; }
        if f == "--sign" { o.do_sign = true; continue; }
        if f == "--secret" { o.secret = true; continue; }
        if f == "--allow-unprotected" { o.allow_unprotected = true; continue; }
        if starts_with(f, "-") && f.len > 1 {
            if i >= a.len { usage(); }
            let v = a[i];
            i++;
            if f == "-k" { add_name(o.keys, v); }
            else if f == "-u" { o.signer.clear(); o.signer.append(v); }
            else if f == "-r" { add_name(o.recipients, v); }
            else if f == "--type" { o.key_type.clear(); o.key_type.append(v); }
            else if f == "--pass-file" {
                var p = slurp(v);
                while p.len > 0 && (p[p.len - 1] == '\n' || p[p.len - 1] == '\r') { p.resize(p.len - 1); }
                o.pass.clear();
                o.pass.append(p);
                o.has_pass = true;
            } else if f == "-z" {
                if v == "zip" { o.w.compression = openpgp::COMP_ZIP; }
                else if v == "zlib" { o.w.compression = openpgp::COMP_ZLIB; }
                else if v == "bzip2" { o.w.compression = openpgp::COMP_BZIP2; }
                else if v == "none" { o.w.compression = openpgp::COMP_NONE; }
                else { usage(); }
            } else if f == "--hash" {
                var h = 0;
                if v == "sha256" { h = openpgp::HASH_SHA256; }
                else if v == "sha384" { h = openpgp::HASH_SHA384; }
                else if v == "sha512" { h = openpgp::HASH_SHA512; }
                else if v == "sha224" { h = openpgp::HASH_SHA224; }
                else { usage(); }
                o.w.hash = h;
            } else if f == "--cipher" {
                if v == "aes128" { o.w.cipher = openpgp::CIPHER_AES128; }
                else if v == "aes192" { o.w.cipher = openpgp::CIPHER_AES192; }
                else if v == "aes256" { o.w.cipher = openpgp::CIPHER_AES256; }
                else { usage(); }
            } else if f == "--name" {
                o.w.filename.clear();
                o.w.filename.append(v[.. ::min(v.len, 255)]);
            } else if f == "--time" {
                let t, ok = parse_int(v);
                if !ok { usage(); }
                o.w.created = t;
                o.w.mtime = t;
            } else {
                usage();
            }
            continue;
        }
        o.rest.push(i - 1);
    }
}

// The keyring of the -k files, unlocked with the passphrase if there is one.
fn load_keys(o: const Opts&, kr: openpgp::Keyring&) {
    if o.keys.len == 0 { return; }
    for f in split(o.keys, 0) {
        let e = openpgp::add_keys(kr, slurp(f));
        if e != openpgp::OK { fail(f, e); }
    }
    if o.has_pass { let e = openpgp::unlock_all(kr, o.pass); }
}

fn find(kr: const openpgp::Keyring&, who: const u8[:], secret: bool) -> i64 {
    let k = openpgp::find_key(kr, who, secret);
    if k < 0 { die(str("no key for ", who)); }
    return k;
}

// The signer: -u, else the first key whose secret is here.
fn the_signer(kr: const openpgp::Keyring&, o: const Opts&) -> i64 {
    if o.signer.len > 0 { return find(kr, o.signer, true); }
    for i in kr.keys.len {
        if openpgp::is_primary(kr, i) && kr.keys[i].has_secret { return i; }
    }
    die("no secret key to sign with");
    return -1;
}

fn report(kr: const openpgp::Keyring&, m: const openpgp::Message&) -> bool {
    var good = false;
    for r in m.sigs {
        var line: u8[>..] = [];
        if r.err == openpgp::OK {
            good = true;
            let k = kr.keys[r.key];
            line.append(str("good signature by ", openpgp::hex(k.fpr), " \"", openpgp::primary_uid(kr, k.primary), "\""));
        } else {
            line.append(str("bad signature (", openpgp::error_text(r.err), ") by key ", openpgp::hex(r.keyid)));
        }
        line.append(str(", ", openpgp::hash_name(r.hash), ", created ", r.created, "\n"));
        write_stdout(line);
    }
    flush_stdout();
    return good;
}

fn main() {
    let a = args();
    if a.len < 2 { usage(); }
    let cmd = a[1];
    var o = Opts { .. };
    parse_opts(a, o);
    var kr = openpgp::Keyring { .. };
    if cmd == "sign" {
        if o.rest.len != 2 { usage(); }
        load_keys(o, kr);
        let signer = the_signer(kr, o);
        var out: u8[>..] = [];
        let data = slurp(a[o.rest[0]]);
        var e = openpgp::OK;
        if o.clear { e = openpgp::sign_cleartext(kr, signer, data, out, o.w); }
        else if o.detach { e = openpgp::sign_detached(kr, signer, data, out, o.w); }
        else { e = openpgp::sign(kr, signer, data, out, o.w); }
        if e != openpgp::OK { fail("sign", e); }
        emit(a[o.rest[1]], out);
    } else if cmd == "verify" {
        if o.rest.len < 1 || o.rest.len > 2 { usage(); }
        load_keys(o, kr);
        let input = slurp(a[o.rest[0]]);
        var m = openpgp::Message { .. };
        var e = openpgp::OK;
        if o.rest.len == 2 {
            e = openpgp::verify_detached(kr, input, slurp(a[o.rest[1]]), m);
        } else {
            let at, l = openpgp::find_begin(input, 0);
            if at >= 0 && l[..] == openpgp::ARMOR_SIGNED_MESSAGE {
                e = openpgp::verify_cleartext(kr, input, m);
            } else {
                var ro = openpgp::ReadOptions { .. };
                ro.passphrase.append(o.pass[.. ::min(o.pass.len, 256)]);
                e = openpgp::verify(kr, input, m, ro);
            }
        }
        let good = report(kr, m);
        if e != openpgp::OK || !good { fail("verify", if e != openpgp::OK { e } else { openpgp::ERR_BAD_SIGNATURE }); }
    } else if cmd == "encrypt" {
        if o.rest.len != 2 { usage(); }
        load_keys(o, kr);
        var rcpt: i64[>..] = [];
        if o.recipients.len > 0 { for r in split(o.recipients, 0) { rcpt.push(find(kr, r, false)); } }
        let signer = if o.do_sign { the_signer(kr, o) } else { -1 };
        var out: u8[>..] = [];
        let pass = if o.symmetric { o.pass[..] } else { "" };
        if o.symmetric && !o.has_pass { die("--symmetric needs --pass-file"); }
        let e = openpgp::encrypt(kr, rcpt, pass, slurp(a[o.rest[0]]), out, o.w, signer);
        if e != openpgp::OK { fail("encrypt", e); }
        emit(a[o.rest[1]], out);
    } else if cmd == "decrypt" {
        if o.rest.len != 2 { usage(); }
        load_keys(o, kr);
        var m = openpgp::Message { .. };
        var ro = openpgp::ReadOptions { .. };
        ro.passphrase.append(o.pass[.. ::min(o.pass.len, 256)]);
        ro.allow_unprotected = o.allow_unprotected;
        let e = openpgp::read_message(kr, slurp(a[o.rest[0]]), m, ro);
        if e != openpgp::OK { fail("decrypt", e); }
        if m.sigs.len > 0 {
            for r in m.sigs {
                if r.err == openpgp::OK {
                    write_stderr(str("good signature by ", openpgp::hex(kr.keys[r.key].fpr), "\n"));
                } else {
                    write_stderr(str("bad signature (", openpgp::error_text(r.err), ") by key ", openpgp::hex(r.keyid), "\n"));
                }
            }
        }
        if m.format == 't' || m.format == 'u' { emit(a[o.rest[1]], native_text(m.data)); } else { emit(a[o.rest[1]], m.data); }
    } else if cmd == "list-packets" {
        if o.rest.len != 1 { usage(); }
        var out: u8[>..] = [];
        let e = openpgp::list_packets(slurp(a[o.rest[0]]), out);
        write_stdout(out);
        if e != openpgp::OK { fail("list-packets", e); }
    } else if cmd == "list-keys" {
        for ri in o.rest {
            let f = a[ri];
            let e = openpgp::add_keys(kr, slurp(f));
            if e != openpgp::OK { fail(f, e); }
        }
        var out: u8[>..] = [];
        for i in kr.keys.len {
            let k = kr.keys[i];
            let kind = if k.subkey { if k.has_secret { "ssb" } else { "sub" } } else { if k.has_secret { "sec" } else { "pub" } };
            out.append(str(kind, "   ", openpgp::key_type_name(k), "/", openpgp::hex(k.keyid), " ", k.created,
                           if k.valid { "" } else { " [invalid]" }, if k.revoked { " [revoked]" } else { "" },
                           if k.locked { " [protected]" } else { "" }, "\n      ", openpgp::hex(k.fpr), "\n"));
            if !k.subkey {
                for u in kr.uids {
                    if u.key == i { out.append(str("uid   ", if u.valid { "" } else { "[invalid] " }, u.text, "\n")); }
                }
            }
        }
        write_stdout(out);
    } else if cmd == "export" {
        if o.rest.len != 2 { usage(); }
        load_keys(o, kr);
        let k = find(kr, a[o.rest[0]], o.secret);
        var out: u8[>..] = [];
        let e = if o.secret { openpgp::export_secret(kr, k, out, o.w.armored, "") }
                else { openpgp::export_public(kr, k, out, o.w.armored) };
        if e != openpgp::OK { fail("export", e); }
        emit(a[o.rest[1]], out);
    } else if cmd == "armor" {
        if o.rest.len != 3 { usage(); }
        let l = a[o.rest[0]];
        let label = if l == "message" { openpgp::ARMOR_MESSAGE } else if l == "signature" { openpgp::ARMOR_SIGNATURE }
                    else if l == "public" { openpgp::ARMOR_PUBLIC_KEY } else if l == "private" { openpgp::ARMOR_PRIVATE_KEY }
                    else { "" };
        if label.len == 0 { usage(); }
        var out: u8[>..] = [];
        openpgp::armor(out, label, slurp(a[o.rest[1]]));
        emit(a[o.rest[2]], out);
    } else if cmd == "dearmor" {
        if o.rest.len != 2 { usage(); }
        var out: u8[>..] = [];
        let label, e = openpgp::dearmor(slurp(a[o.rest[0]]), out);
        if e != openpgp::OK { fail("dearmor", e); }
        emit(a[o.rest[1]], out);
    } else if cmd == "genkey" {
        if o.rest.len < 2 || o.rest.len > 3 { usage(); }
        let pass = if o.has_pass { o.pass[..] } else { "" };
        let t = o.key_type[..];
        var e = openpgp::OK;
        if t.len == 0 || t == "ed25519" { e = openpgp::generate_key(kr, a[o.rest[0]], o.w.created); }
        else if t == "rsa" { e = openpgp::generate_rsa_key(kr, a[o.rest[0]], 3072, o.w.created); }
        else if t == "brainpoolP256r1" { e = openpgp::generate_brainpool_key(kr, a[o.rest[0]], 256, o.w.created); }
        else if t == "brainpoolP384r1" { e = openpgp::generate_brainpool_key(kr, a[o.rest[0]], 384, o.w.created); }
        else if t == "brainpoolP512r1" { e = openpgp::generate_brainpool_key(kr, a[o.rest[0]], 512, o.w.created); }
        else if t == "ed448" { e = openpgp::generate_ed448_key(kr, a[o.rest[0]], o.w.created); }
        else if t == "ed448-v6" { e = openpgp::generate_ed448_v6_key(kr, a[o.rest[0]], o.w.created); }
        else if t == "pqc" { e = openpgp::generate_pqc_bp_key(kr, a[o.rest[0]], o.w.created); }
        else if t == "ky768_cv25519" { e = openpgp::generate_pqc_key(kr, a[o.rest[0]], o.w.created); }
        else if t == "rfc9980" { e = openpgp::generate_rfc9980_key(kr, a[o.rest[0]], o.w.created); }
        else { usage(); }
        if e != openpgp::OK { fail("genkey", e); }
        var sec: u8[>..] = [];
        let es = openpgp::export_secret(kr, 0, sec, o.w.armored, pass);
        if es != openpgp::OK { fail("genkey", es); }
        emit(a[o.rest[1]], sec);
        if o.rest.len == 3 {
            var pub: u8[>..] = [];
            let ep = openpgp::export_public(kr, 0, pub, o.w.armored);
            emit(a[o.rest[2]], pub);
        }
    } else {
        usage();
    }
}
