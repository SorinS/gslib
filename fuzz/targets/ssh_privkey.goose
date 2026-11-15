// Fuzz target: ssh_privkey. The first byte picks:
//   0  an openssh-key-v1 structure in binary (what the PEM holds), read
//      without a passphrase and with "correct horse" (the test vectors');
//   1  a key file's text: parse_private_key (OpenSSH, PKCS #8, PKCS #1,
//      SEC 1 PEM) without a passphrase; an OPENSSH PEM is then also read
//      in binary as for 0;
//   2  DER for x509::parse_private_key, made an SSH key.
// A key that reads is written back out (marshal_private_key) and read
// again, its public blob parsed, and it signs and verifies.
//
// bcrypt_pbkdf's rounds come from the input (a u32): above 2 they are
// cut to 1 or 2 in a copy before the read, or one input costs minutes.
// The vectors use 1 and 2 (and 16, 3: those read as 2 and 1).

import std;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.crypto.ssh;
import gslib.crypto.ssh.keys;
import gslib.crypto.x509;

let PASS = "correct horse";

fn rd32(b: const u8[:], at: i64) -> i64 { (b[at] as i64) << 24 | (b[at + 1] as i64) << 16 | (b[at + 2] as i64) << 8 | b[at + 3] }

// The offset of the kdf options' rounds, or -1.
fn rounds_at(b: const u8[:]) -> i64 {
    var at = ssh::OPENSSH_MAGIC.len;
    if b.len < at { return -1; }
    // cipher, kdf, then kdfoptions = string(string salt, u32 rounds).
    for i in 2 {
        if at + 4 > b.len { return -1; }
        let n = rd32(b, at);
        if n > b.len - at - 4 { return -1; }
        at += 4 + n;
    }
    if at + 4 > b.len { return -1; }
    let olen = rd32(b, at);
    at += 4;
    if olen > b.len - at || at + 4 > b.len { return -1; }
    let slen = rd32(b, at);
    if olen < 8 || slen > olen - 8 { return -1; }
    at += 4 + slen;
    if at + 4 > b.len { return -1; }
    return at;
}

fn use_key(k: const ssh::PrivateKey&) {
    let pk, ok = ssh::parse_public_key(k.public.blob);
    let f = ssh::fingerprint_sha256(k.public);
    let line = ssh::marshal_authorized_key(k.public, k.comment);
    let text = ssh::marshal_private_key(k);
    let k2, e2 = ssh::parse_private_key(text);
    // Signing: not RSA. Its private operation (a 3072-bit seed) took over
    // libFuzzer's 10 s under ASan on a loaded machine: crypto, not parsing.
    if k.key.kind == x509::KEY_RSA { return; }
    let alg = if k.key.kind == x509::KEY_RSA { "rsa-sha2-256" } else { ssh::key_type(k.key.kind) };
    if !ssh::sig_fits(k.key.kind, alg) { return; }
    let sig, oks = ssh::sign(k, alg, "data");
    if oks { let v = ssh::verify(k.public, alg, "data", sig); }
}

fn binary(b: const u8[:]) {
    let k0, e0 = ssh::parse_openssh_key(b, "");
    if e0 == ssh::KEY_OK { use_key(k0); }
    var c: u8[>..] = [];
    c.append(b);
    let at = rounds_at(c);
    if at >= 0 {
        let r = rd32(c, at);
        if r > 2 {
            let nr: u8 = 1 + (r % 2) as! u8;
            c[at] = 0; c[at + 1] = 0; c[at + 2] = 0; c[at + 3] = nr;
        }
    }
    let k, e = ssh::parse_openssh_key(c, PASS);
    if e == ssh::KEY_OK { use_key(k); }
}

fn text(b: const u8[:]) {
    let k, e = ssh::parse_private_key(b);
    if e == ssh::KEY_OK { use_key(k); }
    let blocks, ok = asn1::pem_decode(b, "OPENSSH PRIVATE KEY");
    if ok { for blk in blocks { binary(blk); } }
}

fn der(b: const u8[:]) {
    let key, ok = x509::parse_private_key(b);
    if !ok { return; }
    let k, okp = ssh::private_key(key, "comment");
    if okp { use_key(k); }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let rest = data[1..];
    let sel = data[0] % 3;
    if sel == 0 { binary(rest); }
    else if sel == 1 { text(rest); }
    else { der(rest); }
    return 0;
}

fn main() {}
