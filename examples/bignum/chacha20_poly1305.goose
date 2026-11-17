// ChaCha20-Poly1305 (RFC 8439): seal and open with associated data, a
// counter nonce for a stream of messages, tamper detection, and the
// in-place form; then XChaCha20-Poly1305, whose 24-byte nonce is long
// enough to pick at random; and bare ChaCha20 as a stream cipher.
//
//   goose examples/bignum/chacha20_poly1305.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.chacha20;
import gslib.entropy;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

// A 12-byte nonce from a message counter: never repeat one under a key.
fn counter_nonce(n: u64) -> u8[12] {
    var out: u8[12] = [0; 12];
    for i in 8 { out[11 - i] = (n >> (8 * i)) as! u8; }
    return out;
}

fn main() {
    var key: u8[32] = [0; 32];
    entropy::random_bytes(key);
    let header = "session 7";                // authenticated, not encrypted

    // A stream of records, each under the next nonce: the sender seals,
    // the receiver, counting the same way, opens.
    let records = ["hello", "a second record", "and a third, rather longer than the others"];
    var first: u8[>..] = [];
    var seq:   u64     = 0;
    for r in records {
        let ct = bignum::chacha20_poly1305_seal(key, counter_nonce(seq), header, r);
        print("record ", seq, ": ", r.len, " bytes -> ", ct.len, " (", hex(ct[ct.len - 16..]), " tag)");
        let pt, ok = bignum::chacha20_poly1305_open(key, counter_nonce(seq), header, ct);
        guard ok && pt == r else { print("chacha20_poly1305: record ", seq, " did not open"); exit(1); }
        if seq == 0 { first.append(ct); }
        seq++;
    }

    // Any change is caught: a flipped bit, other associated data, or a
    // record replayed under another nonce. Nothing is released then.
    var bad = copy(first);
    bad[0] ^= 1;
    let p1, ok1 = bignum::chacha20_poly1305_open(key, counter_nonce(0), header, bad);
    let p2, ok2 = bignum::chacha20_poly1305_open(key, counter_nonce(0), "session 8", first);
    let p3, ok3 = bignum::chacha20_poly1305_open(key, counter_nonce(1), header, first);
    guard !ok1 && !ok2 && !ok3 && p1.len == 0 else { print("chacha20_poly1305: a forgery opened"); exit(1); }
    print("tampered, misattributed and replayed records refused");

    // In place: the buffer is encrypted where it lies and the tag returned.
    var buf: u8[>..] = [];
    buf.append("encrypted in place");
    let tag = bignum::chacha20_poly1305_encrypt(key, counter_nonce(99), "", buf);
    let okd = bignum::chacha20_poly1305_decrypt(key, counter_nonce(99), "", buf, tag);
    guard okd && buf == "encrypted in place" else { print("chacha20_poly1305: in-place round trip failed"); exit(1); }

    // XChaCha20-Poly1305: random 24-byte nonces, safe for many messages
    // under one key with no counter to keep.
    var xnonce: u8[24] = [0; 24];
    entropy::random_bytes(xnonce);
    let xct = bignum::xchacha20_poly1305_seal(key, xnonce, "", "random nonce, no state");
    let xpt, xok = bignum::xchacha20_poly1305_open(key, xnonce, "", xct);
    guard xok && xpt == "random nonce, no state" else { print("chacha20_poly1305: xchacha round trip failed"); exit(1); }
    print("xchacha20-poly1305 nonce ", hex(xnonce));

    // Bare ChaCha20 (no integrity): XOR from a block counter, twice to undo.
    var stream: u8[>..] = [];
    stream.append("keystream only");
    bignum::chacha20_xor(key, 1, counter_nonce(0), stream);
    bignum::chacha20_xor(key, 1, counter_nonce(0), stream);
    guard stream == "keystream only" else { print("chacha20_poly1305: chacha20 did not invert"); exit(1); }
    print("all round trips checked");
}
