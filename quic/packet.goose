// quic.packet: QUIC's packet protection (RFC 9001 §5) and headers (RFC
// 9000 §17). The Initial packets' keys come from the client's first
// Destination Connection ID and version 1's salt; the others' from TLS's
// traffic secrets, with the labels "quic key", "quic iv" and "quic hp".
// Packets are sealed with the TLS suite's AEAD, the nonce the IV XORed
// with the packet number; the header's first byte and packet number are
// then masked by header protection, AES-ECB or ChaCha20 over a sample of
// the ciphertext. Packet numbers are sent in 1 to 4 bytes and recovered
// from the largest one received (Appendix A). Retry packets carry an
// AES-128-GCM tag over the original Destination Connection ID (§5.8).

namespace quic;

import std;
import quic;
import crypto.tls;
import crypto.tls.schedule;
import crypto.bignum;
import crypto.bignum.aes;
import crypto.bignum.gcm;
import crypto.bignum.chacha20;
import crypto.bignum.hmac;

// RFC 9001 §5.2.
let INITIAL_SALT_V1: u8[20] = [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                               0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a];
// §5.8: Retry's key and nonce.
let RETRY_KEY_V1: u8[16] = [0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e];
let RETRY_NONCE_V1: u8[12] = [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];

// Long header packet types (§17.2), in the first byte's bits 4-5.
let PT_INITIAL: u8   = 0;
let PT_ZERO_RTT: u8  = 1;
let PT_HANDSHAKE: u8 = 2;
let PT_RETRY: u8     = 3;

let MAX_CID: i64 = 20;

// One direction's keys at one encryption level: the AEAD's key and IV,
// and the header protection key.
struct Keys {
    suite: tls::Suite,
    secret: u8[..48],          // the traffic secret, for key updates
    key: u8[..32],
    iv: u8[12],
    hp: u8[..32],
    gcm: bignum::AesGcm,
    hp_aes: bignum::Aes,
}

// Keys from a TLS traffic secret (§5.1).
fn keys_from_secret(s: tls::Suite, secret: const u8[:]) -> Keys {
    let key = tls::hkdf_expand_label(s.hash, secret, "quic key", "", s.key_len);
    let iv = tls::hkdf_expand_label(s.hash, secret, "quic iv", "", 12);
    let hp = tls::hkdf_expand_label(s.hash, secret, "quic hp", "", s.key_len);
    var k = Keys { suite: s, secret: [], key: [], iv: [0; 12], hp: [], gcm: bignum::gcm_init(key),
                   hp_aes: bignum::aes_init(if s.aead == tls::AEAD_AES_GCM { hp[..] } else { key[..16] }) };
    k.secret.append(secret);
    k.key.append(key);
    for i in 12 { k.iv[i] = iv[i]; }
    k.hp.append(hp);
    return k;
}

// The next generation's keys (§6.1): a new secret and AEAD key, the same
// header protection key.
fn next_keys(k: const Keys&) -> Keys {
    let secret = tls::hkdf_expand_label(k.suite.hash, k.secret, "quic ku", "", k.secret.len);
    var n = keys_from_secret(k.suite, secret);
    n.hp.clear();
    n.hp.append(k.hp);
    n.hp_aes = k.hp_aes;
    return n;
}

// The Initial keys of a connection whose client chose dcid: the client's
// (to send as client, or to read as server) or the server's (§5.2).
fn initial_keys(dcid: const u8[:], client: bool) -> Keys {
    let s, ok = tls::suite(tls::TLS_AES_128_GCM_SHA256);
    let initial = bignum::hkdf_extract(256, INITIAL_SALT_V1, dcid);
    let secret = tls::hkdf_expand_label(256, initial, if client { "client in" } else { "server in" }, "", 32);
    return keys_from_secret(s, secret);
}

// --- Header protection (§5.4) --------------------------------------------------------

// The 5-byte mask from a 16-byte sample of the ciphertext.
fn hp_mask(k: const Keys&, sample: const u8[:]) -> u8[5] {
    var m: u8[5] = [0; 5];
    if k.suite.aead == tls::AEAD_AES_GCM {
        let e = bignum::aes_encrypt_block(k.hp_aes, sample[..16]);
        for i in 5 { m[i] = e[i]; }
    } else {
        // ChaCha20: the sample's first 4 bytes the counter (little-endian),
        // the other 12 the nonce; the mask encrypts five zeros.
        let counter: u32 = sample[0] | (sample[1] as u32) << 8 | (sample[2] as u32) << 16 | (sample[3] as u32) << 24;
        let blk = bignum::chacha20_block(k.hp, counter, sample[4..16]);
        for i in 5 { m[i] = blk[i]; }
    }
    return m;
}

// --- Packet numbers (Appendix A) -----------------------------------------------------

// The bytes to send pn in, given the largest packet number the peer has
// acknowledged (-1: none): enough for twice the range in flight.
fn pn_length(pn: i64, largest_acked: i64) -> i64 {
    let range: i64 = if largest_acked < 0 { pn + 1 } else { pn - largest_acked };
    let need = 2 * range;
    if need < 0x100 { return 1; }
    if need < 0x10000 { return 2; }
    if need < 0x1000000 { return 3; }
    return 4;
}

// The full packet number from its truncated form (n bytes) and the
// largest one received in the space (-1: none) (§A.3).
fn decode_pn(largest: i64, truncated: u64, n: i64) -> i64 {
    let expected = largest + 1;
    let win: i64 = 1 << (8 * n);
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & ~mask) | truncated as! i64;
    if candidate <= expected - hwin && candidate < (1 << 62) - win { return candidate + win; }
    if candidate > expected + hwin && candidate >= win { return candidate - win; }
    return candidate;
}

// --- Sealing and opening ------------------------------------------------------------

fn nonce_of(k: const Keys&, pn: i64) -> u8[12] {
    var n = k.iv;
    for i in 8 { n[11 - i] = n[11 - i] ^ ((pn as! u64 >> (8 * i as! u64)) as! u8); }
    return n;
}

// Seals a packet in place: pkt holds the header (its first byte with the
// packet number length bits, the packet number at pn_at, pn_len bytes)
// and then the payload; the tag is appended and header protection
// applied. The header must leave the payload room for a 16-byte sample
// 4 bytes after pn_at (pad the payload, §5.4.2).
fn seal(k: const Keys&, pkt: u8[>..]&, pn_at: i64, pn_len: i64, pn: i64) {
    let hdr_end = pn_at + pn_len;
    let nonce = nonce_of(k, pn);
    var aad: u8[>..] = [];
    aad.append(pkt[..hdr_end]);
    let body = pkt[hdr_end..];
    let tag = if k.suite.aead == tls::AEAD_AES_GCM {
        bignum::gcm_encrypt(k.gcm, nonce, aad, body)
    } else {
        bignum::chacha20_poly1305_encrypt(k.key, nonce, aad, body)
    };
    pkt.append(tag);
    let mask = hp_mask(k, pkt[pn_at + 4..pn_at + 20]);
    let long = pkt[0] & 0x80 != 0;
    pkt[0] = pkt[0] ^ (mask[0] & (if long { 0x0f } else { 0x1f }));
    for i in pn_len { pkt[pn_at + i] = pkt[pn_at + i] ^ mask[1 + i]; }
}

// Opens a packet in place: pkt[..end] is one packet whose packet number
// starts at pn_at; largest is the largest packet number received in its
// space. The packet number, the header's end and true, with pkt[0] and the
// packet number unmasked and the payload decrypted at pkt[hdr_end..end -
// 16]; or false (too short to sample, or the tag does not check, which
// also means the keys are not these).
fn open(k: const Keys&, pkt: u8[:], pn_at: i64, end: i64, largest: i64) -> i64, i64, bool {
    if pn_at + 20 > end { return 0, 0, false; }
    let mask = hp_mask(k, pkt[pn_at + 4..pn_at + 20]);
    let long = pkt[0] & 0x80 != 0;
    let first = pkt[0] ^ (mask[0] & (if long { 0x0f } else { 0x1f }));
    let pn_len = (first & 0x03) as i64 + 1;
    var truncated: u64 = 0;
    for i in pn_len { truncated = truncated << 8 | (pkt[pn_at + i] ^ mask[1 + i]); }
    let hdr_end = pn_at + pn_len;
    if hdr_end + 16 > end { return 0, 0, false; }
    let pn = decode_pn(largest, truncated, pn_len);
    var aad: u8[>..] = [];
    aad.push(first);
    aad.append(pkt[1..pn_at]);
    for i in pn_len { aad.push(pkt[pn_at + i] ^ mask[1 + i]); }
    let nonce = nonce_of(k, pn);
    let body = pkt[hdr_end..end - 16];
    let tag = pkt[end - 16..end];
    let ok = if k.suite.aead == tls::AEAD_AES_GCM {
        bignum::gcm_decrypt(k.gcm, nonce, aad, body, tag)
    } else {
        bignum::chacha20_poly1305_decrypt(k.key, nonce, aad, body, tag)
    };
    if !ok { return 0, 0, false; }
    for i in aad.len { pkt[i] = aad[i]; }
    return pn, hdr_end, true;
}

// --- Retry (§5.8) ---------------------------------------------------------------

// The integrity tag of a Retry packet (pkt without its tag) for the
// original Destination Connection ID.
fn retry_tag(odcid: const u8[:], pkt: const u8[:]) -> u8[16] {
    var pseudo: u8[>..] = [];
    pseudo.push(odcid.len as! u8);
    pseudo.append(odcid);
    pseudo.append(pkt);
    let g = bignum::gcm_init(RETRY_KEY_V1);
    var none: u8[0] = [];
    return bignum::gcm_encrypt(g, RETRY_NONCE_V1, pseudo, none);
}

// --- Headers (§17) -----------------------------------------------------------------

// What a packet's header says, before header protection is removed: its
// form and type, version, connection IDs (offsets into the datagram),
// token, where the packet number starts and where the packet ends.
struct Header {
    long: bool,
    ptype: u8,                 // PT_*, for a long header
    version: u32,
    dcid_at: i64, dcid_len: i64,
    scid_at: i64, scid_len: i64,
    token_at: i64, token_len: i64,
    pn_at: i64,
    end: i64,                  // the packet's end in the datagram (coalesced packets follow)
}

// Reads the header of the packet at d[at..]. A short header's
// Destination Connection ID has the length the endpoint chose (cid_len).
// False when it is cut short or malformed; a Version Negotiation packet
// (version 0) and a Retry come back with what they have (pn_at and end the
// datagram's end).
fn read_header(d: const u8[:], at: i64, cid_len: i64) -> Header, bool {
    var h = Header { long: false, ptype: 0, version: 0, dcid_at: 0, dcid_len: 0, scid_at: 0, scid_len: 0,
                     token_at: 0, token_len: 0, pn_at: 0, end: d.len };
    if at >= d.len { return h, false; }
    let first = d[at];
    if first & 0x80 == 0 {
        // Short header: the fixed bit, then the DCID and the packet number.
        if at + 1 + cid_len > d.len { return h, false; }
        h.dcid_at = at + 1;
        h.dcid_len = cid_len;
        h.pn_at = at + 1 + cid_len;
        return h, true;
    }
    h.long = true;
    if at + 7 > d.len { return h, false; }
    h.version = u32be(d, at + 1);
    h.ptype = (first >> 4) & 0x03;
    var p = at + 5;
    h.dcid_len = d[p];
    p++;
    if h.dcid_len > MAX_CID && h.version == VERSION_1 { return h, false; }
    if p + h.dcid_len + 1 > d.len { return h, false; }
    h.dcid_at = p;
    p += h.dcid_len;
    h.scid_len = d[p];
    p++;
    if h.scid_len > MAX_CID && h.version == VERSION_1 { return h, false; }
    if p + h.scid_len > d.len { return h, false; }
    h.scid_at = p;
    p += h.scid_len;
    if h.version != VERSION_1 || h.ptype == PT_RETRY {
        h.token_at = p;
        h.token_len = d.len - p;
        h.pn_at = d.len;
        return h, true;
    }
    if h.ptype == PT_INITIAL {
        let tl, after, ok = read_varint(d, p);
        if !ok || tl > (d.len - after) as! u64 { return h, false; }
        h.token_at = after;
        h.token_len = tl as! i64;
        p = after + h.token_len;
    }
    let len, after, ok = read_varint(d, p);
    if !ok || len > (d.len - after) as! u64 { return h, false; }
    h.pn_at = after;
    h.end = after + len as! i64;
    return h, true;
}
