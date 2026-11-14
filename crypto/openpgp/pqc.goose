// openpgp.pqc: the post-quantum pieces of openpgp.key, on bytes alone.
//
// Two composite KEMs of ML-KEM-768 and X25519, which differ in every
// detail but the parts:
//
//   RFC 9980 (algo 35)     KEK = SHA3-256(mlkemSS || ecdhSS || ecdhCT ||
//                          ecdhPK || algo || "OpenPGPCompositeKDFv1" || 21)
//   LibrePGP (algo 8, gpg) eccSS = SHA3-256(ecdh || ecdhCT || ecdhPK);
//                          KEK = KMAC256("OpenPGPCompositeKeyDerivation
//                          Function", 00000001 || eccSS || ecdhCT ||
//                          mlkemSS || mlkemCT || cipher || v5 fingerprint,
//                          256, "KDF")
//
// and in both the session key is wrapped with AES-256 (RFC 3394). ML-DSA-65
// + Ed25519 signatures (RFC 9980 algo 30) are two signatures over the same
// digest, both checked.
//
// gpg keeps the secret of a Kyber subkey in its agent's format, and exports
// it so (S2K mode 1003, "gnu-mode1003"): a canonical S-expression
//
//   (composite-key (private-key (ecc (curve Curve25519) (flags djb-tweak)
//      (q 40||X25519 public) (d big-endian secret)))
//    (private-key (kyber768 (p ek) (s dk) (seed d||z))))
//
// with a passphrase, either part may be a protected-private-key whose
// (protected openpgp-s2k3-ocb-aes ((sha1 salt count) nonce) data) is
// AES-128-OCB under an iterated SHA-1 S2K, the rest of its algorithm list
// the associated data. The S-expression reader here is binary-safe and
// bounded: it walks tokens, never the bytes inside atoms.

namespace openpgp;

import std;
import crypto.bignum;
import crypto.bignum.sha3;
import crypto.bignum.kmac;
import crypto.openpgp;
import crypto.openpgp.ocb;

let MLKEM768_EK_LEN: i64 = 1184;
let MLKEM768_DK_LEN: i64 = 2400;
let MLKEM768_CT_LEN: i64 = 1088;
let MLKEM_SEED_LEN:  i64 = 64;
let MLDSA65_PK_LEN:  i64 = 1952;
let MLDSA65_SIG_LEN: i64 = 3309;
let MLDSA_SEED_LEN:  i64 = 32;

let IETF_KEM_DOMAIN:      const u8[:] = "OpenPGPCompositeKDFv1";
let LIBREPGP_KMAC_KEY:    const u8[:] = "OpenPGPCompositeKeyDerivationFunction";
let LIBREPGP_KMAC_CUSTOM: const u8[:] = "KDF";

fn is_pq_kem(algo: i64) -> bool { algo == PK_KYBER || algo == PK_MLKEM768_X25519 || algo == PK_MLKEM1024_X448 }
fn is_pq_sig(algo: i64) -> bool { algo >= PK_MLDSA65_ED25519 && algo <= PK_SLHDSA_256S }

// RFC 9980 §4.2.1's multiKeyCombine.
fn ietf_kek(mlkem_ss: const u8[:], ecdh_ss: const u8[:], ecdh_ct: const u8[:], ecdh_pk: const u8[:],
            algo: i64) -> u8[>..] {
    var s = bignum::sha3_init(256);
    bignum::sha3_update(s, mlkem_ss);
    bignum::sha3_update(s, ecdh_ss);
    bignum::sha3_update(s, ecdh_ct);
    bignum::sha3_update(s, ecdh_pk);
    let tail: u8[1] = [algo as! u8];
    bignum::sha3_update(s, tail);
    bignum::sha3_update(s, IETF_KEM_DOMAIN);
    let n: u8[1] = [IETF_KEM_DOMAIN.len as! u8];
    bignum::sha3_update(s, n);
    return bignum::sha3_final(s);
}

// gpg's KEK for a Kyber subkey (common/kem.c: gnupg_ecc_kem_simple_kdf,
// then gnupg_kem_combiner): ecdh is X25519's shared secret, fpr the
// subkey's v5 fingerprint, cipher the session key's algorithm.
fn librepgp_kek(ecdh: const u8[:], ecdh_ct: const u8[:], ecdh_pk: const u8[:], mlkem_ss: const u8[:],
                mlkem_ct: const u8[:], cipher: i64, fpr: const u8[:]) -> u8[>..] {
    var s = bignum::sha3_init(256);
    bignum::sha3_update(s, ecdh);
    bignum::sha3_update(s, ecdh_ct);
    bignum::sha3_update(s, ecdh_pk);
    let ecc_ss = bignum::sha3_final(s);
    var x: u8[>..] = [];
    x.append("\x00\x00\x00\x01");
    x.append(ecc_ss);
    x.append(ecdh_ct);
    x.append(mlkem_ss);
    x.append(mlkem_ct);
    x.push(cipher as! u8);
    x.append(fpr);
    return bignum::kmac(256, LIBREPGP_KMAC_KEY, x, 32, LIBREPGP_KMAC_CUSTOM);
}

// --- Canonical S-expressions -------------------------------------------------------

// The atom at s[at..] ("<len>:<bytes>"): where its bytes start and end.
fn sexp_atom(s: const u8[:], at: i64) -> i64, i64, bool {
    var p = at;
    var n: i64 = 0;
    if p < 0 || p >= s.len || s[p] < '0' || s[p] > '9' { return 0, 0, false; }
    while p < s.len && s[p] >= '0' && s[p] <= '9' {
        n = n * 10 + (s[p] - '0');
        if n > s.len { return 0, 0, false; }
        p++;
    }
    if p >= s.len || s[p] != ':' || n > s.len - p - 1 { return 0, 0, false; }
    return p + 1, p + 1 + n, true;
}

// The end of the element (atom or list) at s[at..].
fn sexp_skip(s: const u8[:], at: i64) -> i64, bool {
    if at >= s.len { return at, false; }
    if s[at] != '(' {
        let a, e, ok = sexp_atom(s, at);
        return e, ok;
    }
    var p = at + 1;
    var depth = 1;
    while p < s.len {
        let c = s[p];
        if c == '(' { depth++; p++; }
        else if c == ')' {
            depth--;
            p++;
            if depth == 0 { return p, true; }
        } else {
            let a, e, ok = sexp_atom(s, p);
            if !ok { return p, false; }
            p = e;
        }
    }
    return p, false;
}

// Whether the list at s[at] starts with the atom name.
fn sexp_is(s: const u8[:], at: i64, name: const u8[:]) -> bool {
    if at >= s.len || s[at] != '(' { return false; }
    let a, e, ok = sexp_atom(s, at + 1);
    return ok && s[a..e] == name;
}

// The first list inside s[at..end] (at a list's start) named name: its
// start and end; -1 if there is none.
fn sexp_find(s: const u8[:], name: const u8[:]) -> i64, i64 {
    var p = 0;
    while p < s.len {
        let c = s[p];
        if c == '(' {
            if sexp_is(s, p, name) {
                let e, ok = sexp_skip(s, p);
                if !ok { return -1, -1; }
                return p, e;
            }
            p++;
        } else if c == ')' {
            p++;
        } else {
            let a, e, ok = sexp_atom(s, p);
            if !ok { return -1, -1; }
            p = e;
        }
    }
    return -1, -1;
}

// The value of (name value) anywhere in s: its bytes; false if absent.
fn sexp_value(s: const u8[:], name: const u8[:]) -> const u8[:], bool {
    let b, e = sexp_find(s, name);
    if b < 0 { return s[..0], false; }
    let a1, e1, ok1 = sexp_atom(s, b + 1);
    let a2, e2, ok2 = sexp_atom(s, e1);
    if !ok2 || e2 >= e { return s[..0], false; }
    return s[a2..e2], true;
}

// The elements of the list at s[0..]: each one's start and end, up to 8.
fn sexp_items(s: const u8[:], starts: i64[..8]&, ends: i64[..8]&) -> bool {
    starts.clear();
    ends.clear();
    if s.len < 2 || s[0] != '(' { return false; }
    var p = 1;
    while p < s.len && s[p] != ')' {
        if starts.len == starts.cap { return false; }
        let e, ok = sexp_skip(s, p);
        if !ok { return false; }
        starts.push(p);
        ends.push(e);
        p = e;
    }
    return p + 1 == s.len;
}

fn put_atom(out: u8[>..]&, v: const u8[:]) {
    out.append(str(v.len));
    out.push(':');
    out.append(v);
}

fn put_pair(out: u8[>..]&, name: const u8[:], v: const u8[:]) {
    out.push('(');
    put_atom(out, name);
    put_atom(out, v);
    out.push(')');
}

// --- gpg-agent's key protection (openpgp-s2k3-ocb-aes) ------------------------------------

// The cleartext of a protected-private-key list: ((d ...)...) of its
// protected parameters, with the passphrase. ERR_PASSPHRASE when the tag
// does not match.
fn agent_unprotect(sk: const u8[:], pass: const u8[:], out: u8[>..]&) -> i64 {
    if !sexp_is(sk, 0, "protected-private-key") { return ERR_MALFORMED; }
    let a0, e0, ok0 = sexp_atom(sk, 1);
    if !ok0 || e0 >= sk.len || sk[e0] != '(' { return ERR_MALFORMED; }
    let alg_end, oka = sexp_skip(sk, e0);
    if !oka { return ERR_MALFORMED; }
    let alg = sk[e0..alg_end];
    let pb, pe = sexp_find(alg, "protected");
    if pb < 0 { return ERR_MALFORMED; }
    let prot = alg[pb..pe];
    // (protected <mode> ((sha1 <salt> <count>) <nonce>) <data>)
    let a1, e1, ok1 = sexp_atom(prot, 1);
    let ma, me, ok2 = sexp_atom(prot, e1);
    if !ok1 || !ok2 || prot[ma..me] != "openpgp-s2k3-ocb-aes" { return ERR_UNSUPPORTED; }
    if me + 2 > prot.len || prot[me] != '(' || prot[me + 1] != '(' { return ERR_MALFORMED; }
    let ha, he, ok3 = sexp_atom(prot, me + 2);
    if !ok3 || prot[ha..he] != "sha1" { return ERR_UNSUPPORTED; }
    let sa, se, ok4 = sexp_atom(prot, he);
    let ca, ce, ok5 = sexp_atom(prot, se);
    if !ok4 || !ok5 || se - sa != 8 || ce >= prot.len || prot[ce] != ')' || ce - ca > 10 { return ERR_MALFORMED; }
    var count: i64 = 0;
    for c in prot[ca..ce] {
        if c < '0' || c > '9' { return ERR_MALFORMED; }
        count = count * 10 + (c - '0');
    }
    if count < 256 { count = s2k_count(count); }
    if count < 65536 { return ERR_MALFORMED; }
    // 256 MiB hashed at most (gpg's default is about 65 million octets).
    if count > 1 << 28 { return ERR_LIMIT; }
    let na, ne, ok6 = sexp_atom(prot, ce + 1);
    if !ok6 || ne - na != 12 || ne >= prot.len || prot[ne] != ')' { return ERR_MALFORMED; }
    let da, de, ok7 = sexp_atom(prot, ne + 1);
    if !ok7 || de - da < 16 + 4 { return ERR_MALFORMED; }
    var s2k = S2k { kind: S2K_ITERATED, hash: HASH_SHA1, count: count };
    s2k.salt.append(prot[sa..se]);
    let key, err = s2k_key(s2k, pass, 16);
    if err != OK { return err; }
    var ad: u8[>..] = [];
    ad.append(alg[..pb]);
    ad.append(alg[pe..]);
    let o = ocb_init(key);
    let mark = out.len;
    out.append(prot[da..de - 16]);
    if !ocb_decrypt(o, prot[na..ne], ad, out[mark..], prot[de - 16..de]) {
        out.resize(mark);
        return ERR_PASSPHRASE;
    }
    return OK;
}

// A protected-private-key list of algorithm alg with the public parameters
// pub (pairs, as they go in the list) and the secret ones sec (pairs)
// protected by pass: the agent's format, as gpg exports it.
fn agent_protect(out: u8[>..]&, alg: const u8[:], pub: const u8[:], sec: const u8[:], pass: const u8[:],
                 count: i64) -> i64 {
    var s2k = S2k { kind: S2K_ITERATED, hash: HASH_SHA1, count: count };
    s2k.salt.append(random(8));
    let key, err = s2k_key(s2k, pass, 16);
    if err != OK { return err; }
    let nonce = random(12);
    var head: u8[>..] = [];
    head.push('(');
    put_atom(head, alg);
    head.append(pub);
    var ad: u8[>..] = [];
    ad.append(head);
    ad.push(')');
    var data: u8[>..] = [];
    data.append("((");
    data.append(sec);
    data.append("))");
    let o = ocb_init(key);
    let tag = ocb_encrypt(o, nonce, ad, data);
    data.append(tag);
    out.push('(');
    put_atom(out, "protected-private-key");
    out.append(head);
    out.push('(');
    put_atom(out, "protected");
    put_atom(out, "openpgp-s2k3-ocb-aes");
    out.append("((");
    put_atom(out, "sha1");
    put_atom(out, s2k.salt);
    put_atom(out, str(count));
    out.push(')');
    put_atom(out, nonce);
    out.push(')');
    put_atom(out, data);
    out.push(')');
    out.append("))");
    return OK;
}
