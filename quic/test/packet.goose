// QUIC's packet protection against RFC 9001 Appendix A: the Initial keys
// from the client's Destination Connection ID, the client's and server's
// Initial packets sealed to the RFC's bytes and opened back, the Retry
// integrity tag, and a ChaCha20-Poly1305 short header packet with its
// key update secret. Also RFC 9000's varint and packet number examples
// (Appendix A).

import std;
import gslib from "../..";
import gslib.quic;
import gslib.quic.packet;
import gslib.crypto.tls;

var checks = 0;

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let hi, ok1 = parse_int(s[i..i + 1], 16);
        let lo, ok2 = parse_int(s[i + 1..i + 2], 16);
        out.push((hi * 16 + lo) as! u8);
        i += 2;
    }
    return out;
}

fn vector(name: const u8[:]) -> u8[>..] {
    for line in split(embed_file("vectors/rfc9001.txt"), '\n') {
        let w = words(line);
        if w.len == 2 && w[0] == name { return unhex(w[1]); }
    }
    print("no vector ", name);
    exit(1);
    return [];
}

fn varints() {
    // RFC 9000 Appendix A.1.
    let a = unhex("c2197c5eff14e88c");
    let v1, n1, ok1 = quic::read_varint(a, 0);
    check(ok1 && v1 == 151288809941952652 && n1 == 8, "an 8-byte varint");
    let b = unhex("9d7f3e7d");
    let v2, n2, ok2 = quic::read_varint(b, 0);
    check(ok2 && v2 == 494878333 && n2 == 4, "a 4-byte varint");
    let c = unhex("7bbd");
    let v3, n3, ok3 = quic::read_varint(c, 0);
    check(ok3 && v3 == 15293 && n3 == 2, "a 2-byte varint");
    let d = unhex("25");
    let v4, n4, ok4 = quic::read_varint(d, 0);
    let e = unhex("4025");
    let v5, n5, ok5 = quic::read_varint(e, 0);
    check(ok4 && v4 == 37 && ok5 && v5 == 37 && n5 == 2, "37 in one byte and in two");
    var out: u8[>..] = [];
    quic::put_varint(out, 151288809941952652);
    quic::put_varint(out, 494878333);
    quic::put_varint(out, 15293);
    quic::put_varint(out, 37);
    check(out[..] == unhex("c2197c5eff14e88c9d7f3e7d7bbd25")[..], "written in their shortest forms");
    let cut = unhex("c2197c");
    let v6, n6, ok6 = quic::read_varint(cut, 0);
    check(!ok6, "a varint cut short");
    // Appendix A.3: 0xa82f9b32 from 0x9b32 after 0xa82f30ea.
    check(quic::decode_pn(0xa82f30ea, 0x9b32, 2) == 0xa82f9b32, "a packet number recovered");
    check(quic::pn_length(0xac5c02, 0xabe8b3) == 2 && quic::pn_length(0xace8fe, 0xabe8b3) == 3, "packet number lengths");
}

fn initial_keys() {
    let dcid = unhex("8394c8f03e515708");
    let c = quic::initial_keys(dcid, true);
    let s = quic::initial_keys(dcid, false);
    check(c.secret[..] == vector("client_secret")[..] && s.secret[..] == vector("server_secret")[..], "the Initial secrets");
    check(c.key[..] == vector("client_key")[..] && c.iv[..] == vector("client_iv")[..] && c.hp[..] == vector("client_hp")[..],
          "the client's key, IV and header protection key");
    check(s.key[..] == vector("server_key")[..] && s.iv[..] == vector("server_iv")[..] && s.hp[..] == vector("server_hp")[..],
          "the server's key, IV and header protection key");
}

fn client_initial() {
    let dcid = unhex("8394c8f03e515708");
    let k = quic::initial_keys(dcid, true);
    var pkt: u8[>..] = [];
    pkt.append(vector("client_header"));
    let hdr_len = pkt.len;
    pkt.append(vector("client_crypto"));
    while pkt.len < hdr_len + 1162 { pkt.push(0); }      // PADDING
    quic::seal(k, pkt, hdr_len - 4, 4, 2);
    let want = vector("client_packet");
    check(pkt.len == 1200 && pkt[..] == want[..], "the client's Initial sealed");
    // The server opens it.
    var got: u8[>..] = [];
    got.append(want);
    let h, hok = quic::read_header(got, 0, 0);
    check(hok && h.long && h.ptype == quic::PT_INITIAL && h.version == quic::VERSION_1 && h.dcid_len == 8 &&
          h.token_len == 0 && h.end == 1200, "its header read");
    let pn, hdr_end, ok = quic::open(k, got, h.pn_at, h.end, -1);
    check(ok && pn == 2 && hdr_end == hdr_len, "and opened");
    let crypto = vector("client_crypto");
    check(got[hdr_end..hdr_end + crypto.len] == crypto[..] && got[..hdr_len] == vector("client_header")[..], "to the same frames");
    var bad: u8[>..] = [];
    bad.append(want);
    bad[600] = bad[600] ^ 1;
    let pn2, he2, ok2 = quic::open(k, bad, h.pn_at, h.end, -1);
    check(!ok2, "a changed byte refused");
    let other = quic::initial_keys(dcid, false);
    var copy2: u8[>..] = [];
    copy2.append(want);
    let pn3, he3, ok3 = quic::open(other, copy2, h.pn_at, h.end, -1);
    check(!ok3, "the server's keys do not open it");
}

fn server_initial() {
    let dcid = unhex("8394c8f03e515708");
    let k = quic::initial_keys(dcid, false);
    var pkt: u8[>..] = [];
    pkt.append(vector("server_header"));
    let hdr_len = pkt.len;
    pkt.append(vector("server_payload"));
    quic::seal(k, pkt, hdr_len - 2, 2, 1);
    let want = vector("server_packet");
    check(pkt[..] == want[..], "the server's Initial sealed");
    var got: u8[>..] = [];
    got.append(want);
    let h, hok = quic::read_header(got, 0, 0);
    let pn, hdr_end, ok = quic::open(k, got, h.pn_at, h.end, 0);
    let payload = vector("server_payload");
    check(hok && h.scid_len == 8 && ok && pn == 1 && got[hdr_end..hdr_end + payload.len] == payload[..], "and opened");
}

fn retry() {
    let odcid = unhex("8394c8f03e515708");
    let pkt = vector("retry_packet");
    let tag = quic::retry_tag(odcid, pkt[..pkt.len - 16]);
    check(tag[..] == pkt[pkt.len - 16..], "the Retry integrity tag");
    let h, ok = quic::read_header(pkt, 0, 0);
    check(ok && h.ptype == quic::PT_RETRY && h.dcid_len == 0 && h.scid_len == 8 && h.token_len == pkt.len - h.token_at,
          "its header: the token, then the tag");
    let other = unhex("8394c8f03e515709");
    let tag2 = quic::retry_tag(other, pkt[..pkt.len - 16]);
    check(tag2[..] != pkt[pkt.len - 16..], "another connection ID's tag differs");
}

fn chacha_short() {
    let s, sok = tls::suite(tls::TLS_CHACHA20_POLY1305_SHA256);
    let k = quic::keys_from_secret(s, vector("chacha_secret"));
    check(k.key[..] == vector("chacha_key")[..] && k.iv[..] == vector("chacha_iv")[..] && k.hp[..] == vector("chacha_hp")[..],
          "ChaCha20-Poly1305 keys");
    let n = quic::next_keys(k);
    check(n.secret[..] == vector("chacha_ku")[..] && n.hp[..] == k.hp[..], "the key update secret; the same header protection key");
    var pkt: u8[>..] = [];
    pkt.append(unhex("4200bff4"));
    pkt.push(0x01);                                       // PING
    quic::seal(k, pkt, 1, 3, 654360564);
    let want = vector("chacha_packet");
    check(pkt[..] == want[..], "a short header packet sealed");
    var got: u8[>..] = [];
    got.append(want);
    let h, hok = quic::read_header(got, 0, 0);
    let pn, hdr_end, ok = quic::open(k, got, h.pn_at, got.len, 654360563);
    check(hok && !h.long && ok && pn == 654360564 && hdr_end == 4 && got[4] == 0x01, "and opened");
}

fn main() {
    varints();
    initial_keys();
    client_initial();
    server_initial();
    retry();
    chacha_short();
    print("packet: ", checks, " checks");
}
