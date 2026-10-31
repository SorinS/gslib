// bignum.aes: AES-128/192/256 (FIPS 197) and CTR mode, constant time.
//
// Bitsliced, after BearSSL's aes_ct: no table lookups, so no cache timing.
// Eight u32 words hold two blocks at once, bit j of every byte in word j
// (orthogonalized), and the S-box is Boyar and Peralta's 113-gate circuit
// evaluated on all 32 bytes in parallel. ShiftRows and MixColumns become
// shifts and rotations of the words.

namespace bignum;

import std;

// The expanded key: rounds + 1 round keys, eight bitsliced words each.
struct Aes { rounds: i64, sk: u32[120] }

let AES_RCON: u32[10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// The S-box on the eight bit planes of q (q[0] the low bit). The x and s
// names run from the high bit down, as in the paper.
fn aes_sbox(q: u32[:]) {
    let x0 = q[7]; let x1 = q[6]; let x2 = q[5]; let x3 = q[4];
    let x4 = q[3]; let x5 = q[2]; let x6 = q[1]; let x7 = q[0];

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ ~t62;
    let s7 = t48 ^ ~t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ ~s3;
    let s2 = t55 ^ ~t67;

    q[7] = s0; q[6] = s1; q[5] = s2; q[4] = s3;
    q[3] = s4; q[2] = s5; q[1] = s6; q[0] = s7;
}

// The inverse affine map with 0x63 folded in: B(x ^ 0x63) on the planes.
fn aes_inv_affine(q: u32[:]) {
    let q0 = ~q[0]; let q1 = ~q[1]; let q2 = q[2]; let q3 = q[3];
    let q4 = q[4]; let q5 = ~q[5]; let q6 = ~q[6]; let q7 = q[7];
    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;
}

// S(x) = A(I(x)) ^ 0x63 with A linear and I an involution, so the inverse
// S-box is B(S(B(x ^ 0x63)) ^ 0x63) for B the inverse of A.
fn aes_inv_sbox(q: u32[:]) {
    aes_inv_affine(q);
    aes_sbox(q);
    aes_inv_affine(q);
}

// Swaps bit groups between word pairs so that word j collects bit j of
// every byte; its own inverse.
fn aes_swapn(q: u32[:], i: i64, j: i64, cl: u32, ch: u32, s: u32) {
    let a = q[i];
    let b = q[j];
    q[i] = (a & cl) | ((b & cl) << s);
    q[j] = ((a & ch) >> s) | (b & ch);
}

fn aes_ortho(q: u32[:]) {
    aes_swapn(q, 0, 1, 0x55555555, 0xaaaaaaaa, 1);
    aes_swapn(q, 2, 3, 0x55555555, 0xaaaaaaaa, 1);
    aes_swapn(q, 4, 5, 0x55555555, 0xaaaaaaaa, 1);
    aes_swapn(q, 6, 7, 0x55555555, 0xaaaaaaaa, 1);
    aes_swapn(q, 0, 2, 0x33333333, 0xcccccccc, 2);
    aes_swapn(q, 1, 3, 0x33333333, 0xcccccccc, 2);
    aes_swapn(q, 4, 6, 0x33333333, 0xcccccccc, 2);
    aes_swapn(q, 5, 7, 0x33333333, 0xcccccccc, 2);
    aes_swapn(q, 0, 4, 0x0f0f0f0f, 0xf0f0f0f0, 4);
    aes_swapn(q, 1, 5, 0x0f0f0f0f, 0xf0f0f0f0, 4);
    aes_swapn(q, 2, 6, 0x0f0f0f0f, 0xf0f0f0f0, 4);
    aes_swapn(q, 3, 7, 0x0f0f0f0f, 0xf0f0f0f0, 4);
}

fn aes_add_round_key(q: u32[:], sk: const u32[:]) {
    for i in 8 { q[i] ^= sk[i]; }
}

fn aes_shift_rows(q: u32[:]) {
    for i in 8 {
        let x = q[i];
        q[i] = (x & 0x000000ff)
             | ((x & 0x0000fc00) >> 2) | ((x & 0x00000300) << 6)
             | ((x & 0x00f00000) >> 4) | ((x & 0x000f0000) << 4)
             | ((x & 0xc0000000) >> 6) | ((x & 0x3f000000) << 2);
    }
}

fn aes_inv_shift_rows(q: u32[:]) {
    for i in 8 {
        let x = q[i];
        q[i] = (x & 0x000000ff)
             | ((x & 0x00003f00) << 2) | ((x & 0x0000c000) >> 6)
             | ((x & 0x000f0000) << 4) | ((x & 0x00f00000) >> 4)
             | ((x & 0x03000000) << 6) | ((x & 0xfc000000) >> 2);
    }
}

fn rotr8(x: u32) -> u32 { (x >> 8) | (x << 24) }
fn rotr16(x: u32) -> u32 { (x << 16) | (x >> 16) }

fn aes_mix_columns(q: u32[:]) {
    let q0 = q[0]; let q1 = q[1]; let q2 = q[2]; let q3 = q[3];
    let q4 = q[4]; let q5 = q[5]; let q6 = q[6]; let q7 = q[7];
    let r0 = rotr8(q0); let r1 = rotr8(q1); let r2 = rotr8(q2); let r3 = rotr8(q3);
    let r4 = rotr8(q4); let r5 = rotr8(q5); let r6 = rotr8(q6); let r7 = rotr8(q7);
    q[0] = q7 ^ r7 ^ r0 ^ rotr16(q0 ^ r0);
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr16(q1 ^ r1);
    q[2] = q1 ^ r1 ^ r2 ^ rotr16(q2 ^ r2);
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr16(q3 ^ r3);
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr16(q4 ^ r4);
    q[5] = q4 ^ r4 ^ r5 ^ rotr16(q5 ^ r5);
    q[6] = q5 ^ r5 ^ r6 ^ rotr16(q6 ^ r6);
    q[7] = q6 ^ r6 ^ r7 ^ rotr16(q7 ^ r7);
}

fn aes_inv_mix_columns(q: u32[:]) {
    let q0 = q[0]; let q1 = q[1]; let q2 = q[2]; let q3 = q[3];
    let q4 = q[4]; let q5 = q[5]; let q6 = q[6]; let q7 = q[7];
    let r0 = rotr8(q0); let r1 = rotr8(q1); let r2 = rotr8(q2); let r3 = rotr8(q3);
    let r4 = rotr8(q4); let r5 = rotr8(q5); let r6 = rotr8(q6); let r7 = rotr8(q7);
    q[0] = q5 ^ q6 ^ q7 ^ r0 ^ r5 ^ r7 ^ rotr16(q0 ^ q5 ^ q6 ^ r0 ^ r5);
    q[1] = q0 ^ q5 ^ r0 ^ r1 ^ r5 ^ r6 ^ r7 ^ rotr16(q1 ^ q5 ^ q7 ^ r1 ^ r5 ^ r6);
    q[2] = q0 ^ q1 ^ q6 ^ r1 ^ r2 ^ r6 ^ r7 ^ rotr16(q0 ^ q2 ^ q6 ^ r2 ^ r6 ^ r7);
    q[3] = q0 ^ q1 ^ q2 ^ q5 ^ q6 ^ r0 ^ r2 ^ r3 ^ r5
         ^ rotr16(q0 ^ q1 ^ q3 ^ q5 ^ q6 ^ q7 ^ r0 ^ r3 ^ r5 ^ r7);
    q[4] = q1 ^ q2 ^ q3 ^ q5 ^ r1 ^ r3 ^ r4 ^ r5 ^ r6 ^ r7
         ^ rotr16(q1 ^ q2 ^ q4 ^ q5 ^ q7 ^ r1 ^ r4 ^ r5 ^ r6);
    q[5] = q2 ^ q3 ^ q4 ^ q6 ^ r2 ^ r4 ^ r5 ^ r6 ^ r7
         ^ rotr16(q2 ^ q3 ^ q5 ^ q6 ^ r2 ^ r5 ^ r6 ^ r7);
    q[6] = q3 ^ q4 ^ q5 ^ q7 ^ r3 ^ r5 ^ r6 ^ r7
         ^ rotr16(q3 ^ q4 ^ q6 ^ q7 ^ r3 ^ r6 ^ r7);
    q[7] = q4 ^ q5 ^ q6 ^ r4 ^ r6 ^ r7 ^ rotr16(q4 ^ q5 ^ q7 ^ r4 ^ r7);
}

// The S-box on each byte of a word, for the key schedule.
fn aes_sub_word(x: u32) -> u32 {
    var q: u32[8] = [x; 8];
    aes_ortho(q);
    aes_sbox(q);
    aes_ortho(q);
    return q[0];
}

// The key schedule for a 16-, 24- or 32-byte key. The branches depend on
// the position in the schedule only.
fn aes_init(key: const u8[:]) -> Aes {
    assert(key.len == 16 || key.len == 24 || key.len == 32);
    let nk = key.len / 4;
    let rounds = nk + 6;
    let nw = 4 * (rounds + 1);
    var w: u32[60] = [0; 60];
    for i in nk { w[i] = le32(key[4 * i..]); }
    var j = 0;
    var k = 0;
    for i in nk..nw {
        var t = w[i - 1];
        if j == 0 {
            t = aes_sub_word((t >> 8) | (t << 24)) ^ AES_RCON[k];
        } else if nk > 6 && j == 4 {
            t = aes_sub_word(t);
        }
        w[i] = w[i - nk] ^ t;
        j++;
        if j == nk { j = 0; k++; }
    }
    // Each round key goes into both block lanes, then into bit planes.
    var r = Aes { rounds: rounds, sk: [0; 120] };
    for rk in rounds + 1 {
        let q = r.sk[8 * rk..8 * rk + 8];
        for c in 4 {
            q[2 * c] = w[4 * rk + c];
            q[2 * c + 1] = w[4 * rk + c];
        }
        aes_ortho(q);
    }
    return r;
}

fn aes_encrypt_planes(k: const Aes&, q: u32[:]) {
    aes_add_round_key(q, k.sk[..8]);
    for u in 1..k.rounds {
        aes_sbox(q);
        aes_shift_rows(q);
        aes_mix_columns(q);
        aes_add_round_key(q, k.sk[8 * u..8 * u + 8]);
    }
    aes_sbox(q);
    aes_shift_rows(q);
    aes_add_round_key(q, k.sk[8 * k.rounds..8 * k.rounds + 8]);
}

fn aes_decrypt_planes(k: const Aes&, q: u32[:]) {
    aes_add_round_key(q, k.sk[8 * k.rounds..8 * k.rounds + 8]);
    var u = k.rounds - 1;
    while u > 0 {
        aes_inv_shift_rows(q);
        aes_inv_sbox(q);
        aes_add_round_key(q, k.sk[8 * u..8 * u + 8]);
        aes_inv_mix_columns(q);
        u--;
    }
    aes_inv_shift_rows(q);
    aes_inv_sbox(q);
    aes_add_round_key(q, k.sk[..8]);
}

fn le32(p: const u8[:]) -> u32 {
    p[0] | (p[1] as u32) << 8 | (p[2] as u32) << 16 | (p[3] as u32) << 24
}

fn put_le32(p: u8[:], x: u32) {
    p[0] = x as! u8; p[1] = (x >> 8) as! u8; p[2] = (x >> 16) as! u8; p[3] = (x >> 24) as! u8;
}

// Two blocks into planes: a in the even words, b in the odd ones.
fn aes_load2(q: u32[:], a: const u8[:], b: const u8[:]) {
    for c in 4 {
        q[2 * c] = le32(a[4 * c..]);
        q[2 * c + 1] = le32(b[4 * c..]);
    }
    aes_ortho(q);
}

fn aes_store2(q: u32[:], a: u8[:], b: u8[:]) {
    aes_ortho(q);
    for c in 4 {
        put_le32(a[4 * c..], q[2 * c]);
        put_le32(b[4 * c..], q[2 * c + 1]);
    }
}

// One block each way.
fn aes_encrypt_block(k: const Aes&, blk: const u8[:]) -> u8[16] {
    assert(blk.len == 16);
    var q: u32[8] = [0; 8];
    var out: u8[16] = [0; 16];
    var other: u8[16] = [0; 16];
    aes_load2(q, blk, other);
    aes_encrypt_planes(k, q);
    aes_store2(q, out, other);
    return out;
}

fn aes_decrypt_block(k: const Aes&, blk: const u8[:]) -> u8[16] {
    assert(blk.len == 16);
    var q: u32[8] = [0; 8];
    var out: u8[16] = [0; 16];
    var other: u8[16] = [0; 16];
    aes_load2(q, blk, other);
    aes_decrypt_planes(k, q);
    aes_store2(q, out, other);
    return out;
}

// Adds one to the counter block: the whole 16 bytes big-endian, or only the
// last 4 (GCM's inc32) when `low32`.
fn ctr_increment(cb: u8[:], low32: bool) {
    var carry: u32 = 1;
    let stop = if low32 { 12 } else { 0 };
    var i = 16;
    while i > stop {
        i--;
        let t = cb[i] + carry;
        cb[i] = t as! u8;
        carry = t >> 8;
    }
}

// data ^= the keystream from counter block cb, which is left at the next
// unused value. Two blocks of keystream per pass.
fn aes_ctr_xor(k: const Aes&, cb: u8[:], data: u8[:], low32: bool) {
    var q: u32[8] = [0; 8];
    var c1: u8[16] = [0; 16];
    var ks1: u8[16] = [0; 16];
    var ks2: u8[16] = [0; 16];
    var off = 0;
    while off < data.len {
        for i in 16 { c1[i] = cb[i]; }
        ctr_increment(cb, low32);
        aes_load2(q, c1, cb);
        ctr_increment(cb, low32);
        aes_encrypt_planes(k, q);
        aes_store2(q, ks1, ks2);
        let n = ::min(32, data.len - off);
        for i in ::min(n, 16) { data[off + i] ^= ks1[i]; }
        for i in 16..n { data[off + i] ^= ks2[i - 16]; }
        if n <= 16 {
            // The second block went unused: step the counter back.
            for i in 16 { cb[i] = c1[i]; }
            ctr_increment(cb, low32);
        }
        off += n;
    }
}

// AES-CTR (SP 800-38A): data ^= the keystream from a 16-byte initial
// counter block, incremented as a 128-bit big-endian number. Encryption and
// decryption are the same.
fn aes_ctr(k: const Aes&, iv: const u8[:], data: u8[:]) {
    assert(iv.len == 16);
    var cb: u8[16] = [0; 16];
    for i in 16 { cb[i] = iv[i]; }
    aes_ctr_xor(k, cb, data, false);
}
