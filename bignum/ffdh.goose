// bignum.ffdh: finite-field Diffie-Hellman over the MODP groups of
// RFC 3526 (2048-, 3072- and 4096-bit primes, generator 2), as SSH
// (diffie-hellman-group14/15/16, RFC 8268) and IKE use them. The secret
// exponent is raised in constant time (mont_modexp, every window); values
// are big-endian magnitudes as long as the prime.

namespace bignum;

import std;
import bignum;
import mont;
import ct;
import entropy;

// The primes, from RFC 3526's formula 2^n - 2^(n-64) - 1 + 2^64 *
// (floor(2^(n-130) pi) + offset): group 14 (2048 bits), 15 (3072), 16 (4096).
let FFDH_MODP_2048: const u8[:] = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
let FFDH_MODP_3072: const u8[:] = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
let FFDH_MODP_4096: const u8[:] = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

fn ffdh_hex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// The prime of a group by its RFC 3526 number (14, 15 or 16).
fn ffdh_prime(group: i64) -> u8[>..] {
    assert(group == 14 || group == 15 || group == 16);
    return ffdh_hex(if group == 14 { FFDH_MODP_2048 } else if group == 15 { FFDH_MODP_3072 } else { FFDH_MODP_4096 });
}

// base^x mod p, for base < p, in time that depends on the lengths of x and
// p alone; as long as p.
fn ffdh_modexp(base: const u8[:], x: const u8[:], p: const u8[:]) -> u8[>..] {
    let n = (p.len + 3) / 4;
    var m: u32[>..] = [];
    m.resize(n, 0);
    limbs_from_be(m, p);
    var b: u32[>..] = [];
    b.resize(n, 0);
    limbs_from_be(b, base);
    var e: u32[>..] = [];
    e.resize((x.len + 3) / 4, 0);
    limbs_from_be(e, x);
    var r2: u32[>..] = [];
    r2.resize(n, 0);
    mont_r2(r2, m);
    var r: u32[>..] = [];
    r.resize(n, 0);
    mont_modexp(r, b, e, m, mont_m0i(m[0]), r2);
    var out: u8[>..] = [];
    out.resize(p.len, 0);
    be_from_limbs(out, r);
    return out;
}

// Whether a peer's value v is in [2, p - 2] (RFC 4253 §8, NIST SP 800-56A's
// range check), so not 0, 1 or p - 1.
fn ffdh_value_ok(v: const u8[:], p: const u8[:]) -> bool {
    let vb = from_bytes_be(v);
    return cmp_i64(vb, 1) > 0 && cmp(vb, sub(from_bytes_be(p), one())) < 0;
}

// A secret exponent of xlen random bytes (top bit set, so its length is
// fixed) and the public value 2^x mod p. xlen is at least 28 bytes (224
// bits, twice the 112-bit strength of a 2048-bit group: NIST SP 800-56A,
// RFC 7919 §5.2) and at most p's length.
fn ffdh_keygen(p: const u8[:], xlen: i64) -> u8[>..], u8[>..] {
    assert(xlen >= 28 && xlen <= p.len);
    var x: u8[>..] = [];
    x.resize(xlen, 0);
    random_bytes(x);
    x[0] |= 0x80;
    let two: u8[1] = [2];
    let pub = ffdh_modexp(two, x, p);
    return x, pub;
}

// The shared secret peer^x mod p, and false for a peer value out of range.
fn ffdh_shared(x: const u8[:], peer: const u8[:], p: const u8[:]) -> u8[>..], bool {
    if peer.len > p.len || !ffdh_value_ok(peer, p) {
        var none: u8[>..] = [];
        return none, false;
    }
    return ffdh_modexp(peer, x, p), true;
}
