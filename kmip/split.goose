// kmip.split: Split Key objects (KMIP 1.2 on), and splitting a key into
// parts and joining them again with bignum.shamir, as KMIP 2.1 §13.1 has
// it: XOR, or polynomial sharing in GF(2^16), in a prime field or in
// GF(2^8). A part's Key Block keeps the split key's format, algorithm and
// length; its material is the part's share, Key Part Identifier its x.

namespace kmip;

import std;
import kmip;
import kmip.tables;
import kmip.objects;
import crypto.bignum;
import crypto.bignum.shamir;

// Writes a Split Key's Structure. False when it is not one.
fn put_split_key(out: u8[>..]&, o: const Object&) -> bool {
    if o.obj_type != OBJ_SPLIT_KEY { return false; }
    let s = begin(out, TAG_SPLIT_KEY);
    put_int(out, TAG_SPLIT_KEY_PARTS, o.parts);
    put_int(out, TAG_KEY_PART_IDENTIFIER, o.part_id);
    put_int(out, TAG_SPLIT_KEY_THRESHOLD, o.threshold);
    put_enum(out, TAG_SPLIT_KEY_METHOD, o.split_method);
    if o.split_method == SPLIT_POLYNOMIAL_SHARING_PRIME_FIELD { put_biguint(out, TAG_PRIME_FIELD_SIZE, o.prime); }
    put_key_block(out, o);
    end(out, s);
    return true;
}

// Reads a Split Key's Structure, at s, into o.
fn read_split_key(buf: const u8[:], doc: const Node[:], s: i64, o: Object&) -> bool {
    let n, nok = child_int(buf, doc, s, TAG_SPLIT_KEY_PARTS);
    let x, xok = child_int(buf, doc, s, TAG_KEY_PART_IDENTIFIER);
    let t, tok = child_int(buf, doc, s, TAG_SPLIT_KEY_THRESHOLD);
    let m, mok = child_enum(buf, doc, s, TAG_SPLIT_KEY_METHOD);
    if !nok || !xok || !tok || !mok { return false; }
    if n < 1 || t < 1 || t > n || x < 1 || x > n { return false; }
    o.parts = n;
    o.part_id = x;
    o.threshold = t;
    o.split_method = m;
    if m == SPLIT_POLYNOMIAL_SHARING_PRIME_FIELD {
        let p, pok = as_biguint(buf, doc, child(doc, s, TAG_PRIME_FIELD_SIZE));
        if !pok || p.len > o.prime.cap { return false; }
        o.prime.clear();
        o.prime.append(p);
    }
    return read_key_block(buf, doc, child(doc, s, TAG_KEY_BLOCK), o);
}

// Splits secret into n parts, any t of them enough, by the method (with
// prime, big-endian, for the prime field): the parts' shares one after
// another, and each share's length. False for a method or numbers that
// do not go together: XOR needs t = n, GF(2^16) an even length, the prime
// field a prime above every secret of the length.
fn split_secret(method: u32, secret: const u8[:], n: i64, t: i64, prime: const u8[:], shares: u8[>..]&) -> bool, i64 {
    if secret.len == 0 { return false, 0; }
    if method == SPLIT_XOR {
        if t != n { return false, 0; }
        let ok = bignum::split_xor(secret, n, shares);
        return ok, secret.len;
    }
    if method == SPLIT_POLYNOMIAL_SHARING_GF_2_8 { let ok = bignum::split_gf8(secret, n, t, shares); return ok, secret.len; }
    if method == SPLIT_POLYNOMIAL_SHARING_GF_2_16 { let ok = bignum::split_gf16(secret, n, t, shares); return ok, secret.len; }
    if method == SPLIT_POLYNOMIAL_SHARING_PRIME_FIELD {
        if !bignum::prime_field_ok(prime, secret.len) { return false, 0; }
        let ok = bignum::split_prime(secret, prime, n, t, shares);
        return ok, prime.len;
    }
    return false, 0;
}

// The secret, len bytes, from the parts numbered xs, their shares
// (share_len bytes each) one after another in the same order.
fn join_secret(method: u32, xs: const i64[:], shares: const u8[:], share_len: i64, prime: const u8[:], len: i64, out: u8[>..]&) -> bool {
    if method == SPLIT_XOR { return bignum::join_xor(shares, share_len, out); }
    if method == SPLIT_POLYNOMIAL_SHARING_GF_2_8 { return bignum::join_gf8(xs, shares, share_len, out); }
    if method == SPLIT_POLYNOMIAL_SHARING_GF_2_16 { return bignum::join_gf16(xs, shares, share_len, out); }
    if method == SPLIT_POLYNOMIAL_SHARING_PRIME_FIELD {
        if prime.len != share_len { return false; }
        return bignum::join_prime(xs, shares, prime, len, out);
    }
    return false;
}
