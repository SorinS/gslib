// Fuzz target: smb. The first byte picks a path (data[0] % 4), the rest
// is the input:
//   0: the input as a response: the header, then every response parser
//      on it (NEGOTIATE with 3.1.1's contexts, SESSION_SETUP,
//      TREE_CONNECT, CREATE, CLOSE, READ, WRITE, QUERY_DIRECTORY and
//      QUERY_INFO's output, IOCTL, ERROR), and what is inside their
//      buffers (directory entries, file and file system information).
//   1: the input as a transformed (encrypted) message, opened with fixed
//      keys under each cipher (data[0] / 4 picks one), and as a transform
//      header; a message encrypted and opened again.
//   2: the input as a signed message, checked under each algorithm, then
//      signed and checked again.
//   3: names: share paths, UNC names, UTF-16 both ways, the transport
//      length.

import std;
import gslib from "../..";
import gslib.smb;
import gslib.smb.crypto;
import gslib.smb.messages;

let KEY32: const u8[:] = "0123456789abcdef0123456789abcdef";

fn responses(m: const u8[:]) {
    let h, ok = smb::parse_header(m);
    let n, nok = smb::parse_negotiate_response(m);
    if nok { let b = smb::span_bytes(m, n.blob); }
    let flags, blob, sok = smb::parse_session_setup_response(m);
    if sok { let b = smb::span_bytes(m, blob); }
    let t, tok = smb::parse_tree_connect_response(m);
    let action, info, id, cok = smb::parse_create_response(m);
    let ci, clok = smb::parse_close_response(m);
    let rs, rok = smb::parse_read_response(m);
    if rok { let b = smb::span_bytes(m, rs); }
    let count, wok = smb::parse_write_response(m);
    let os, ook = smb::parse_output_response(m);
    if ook {
        let b = smb::span_bytes(m, os);
        var es: smb::DirEntry[>..] = [];
        let dok = smb::parse_directory(b, es);
        let ni, niok = smb::parse_network_open(b);
        let fs, fsok = smb::parse_fs_full_size(b);
    }
    let ctl, io, iok = smb::parse_ioctl_response(m);
    if iok { let b = smb::span_bytes(m, io); }
    let ed, eok = smb::error_data(m);
    if eok { let b = smb::span_bytes(m, ed); }
    // The raw input as a directory listing too.
    var es2: smb::DirEntry[>..] = [];
    let d2 = smb::parse_directory(m, es2);
}

fn transforms(m: const u8[:], pick: u8) {
    let ciphers: u16[4] = [smb::AES128_CCM, smb::AES128_GCM, smb::AES256_CCM, smb::AES256_GCM];
    let cipher = ciphers[pick % 4];
    let key = KEY32[..smb::cipher_key_len(cipher)];
    let s = smb::transform_session(m);
    let plain, ok = smb::decrypt_message(cipher, key, m);
    let nonce: u8[16] = [7; 16];
    let tm = smb::encrypt_message(cipher, key, nonce[..smb::nonce_len(cipher)], s, m);
    let back, ok2 = smb::decrypt_message(cipher, key, tm);
    assert(ok2 && back == m);
}

fn signatures(m: const u8[:]) {
    if m.len < smb::HEADER_LEN { return; }
    let algs: u16[3] = [smb::HMAC_SHA256, smb::AES_CMAC, smb::AES_GMAC];
    for a in algs {
        let v = smb::verify(a, KEY32[..16], m);
        var c: u8[>..] = [];
        c.append(m);
        smb::sign(a, KEY32[..16], c);
        assert(smb::verify(a, KEY32[..16], c));
    }
}

fn names(m: const u8[:]) {
    let p, ok = smb::share_path(m);
    let server, share, uok = smb::split_unc(m);
    var u: u8[>..] = [];
    if smb::utf16(u, m) {
        var back: u8[>..] = [];
        assert(smb::utf8(back, u) && back == m);
    }
    var v: u8[>..] = [];
    let ok8 = smb::utf8(v, m);
    let n, tok = smb::transport_len(m);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let m = data[1..];
    let sel = data[0] % 4;
    if sel == 0 { responses(m); }
    else if sel == 1 { transforms(m, data[0] / 4); }
    else if sel == 2 { signatures(m); }
    else { names(m); }
    return 0;
}

fn main() {}
