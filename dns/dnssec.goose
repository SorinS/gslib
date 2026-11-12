// dns.dnssec: DNSSEC (RFC 4033-4035) as miekg has it: key tags, DS
// records from DNSKEYs, RRSIG signing and verification over the
// canonical form of an RRset (RFC 4034 §6), validity periods in serial
// arithmetic, NSEC3 hashing (RFC 5155), key generation, and private keys
// in BIND's file format.
//
// Algorithms: RSASHA1 (5), RSASHA1-NSEC3-SHA1 (7), RSASHA256 (8),
// RSASHA512 (10), ECDSAP256SHA256 (13), ECDSAP384SHA384 (14) and
// ED25519 (15). DS digests: SHA-1 (1), SHA-256 (2) and SHA-384 (4).
//
// An RRset is a list of records (dns.msg) of one owner, type and class;
// a DNSKEY and an RRSIG are taken as their rdata, with the owner where
// it counts.

namespace dns;

import std;
import base64;
import dns;
import dns.rdata;
import dns.msg;
import crypto.bignum;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import crypto.bignum.ed25519;
import crypto.bignum.entropy;
import crypto.bignum.hmac;
import crypto.bignum.sha256;
import crypto.bignum.sha512;

let ALG_RSAMD5: u8 = 1;
let ALG_DH: u8 = 2;
let ALG_DSA: u8 = 3;
let ALG_RSASHA1: u8 = 5;
let ALG_DSANSEC3SHA1: u8 = 6;
let ALG_RSASHA1NSEC3SHA1: u8 = 7;
let ALG_RSASHA256: u8 = 8;
let ALG_RSASHA512: u8 = 10;
let ALG_ECCGOST: u8 = 12;
let ALG_ECDSAP256SHA256: u8 = 13;
let ALG_ECDSAP384SHA384: u8 = 14;
let ALG_ED25519: u8 = 15;
let ALG_ED448: u8 = 16;

let DIGEST_SHA1: u8 = 1;
let DIGEST_SHA256: u8 = 2;
let DIGEST_GOST94: u8 = 3;
let DIGEST_SHA384: u8 = 4;
let DIGEST_SHA512: u8 = 5;

// DNSKEY flags.
let FLAG_SEP: u16 = 1;
let FLAG_REVOKE: u16 = 0x80;
let FLAG_ZONE: u16 = 0x100;

// The hash an algorithm signs with, as a bignum.hmac id; 0 for none.
fn alg_hash(alg: u8) -> i64 {
    if alg == ALG_RSASHA1 || alg == ALG_RSASHA1NSEC3SHA1 { return 160; }
    if alg == ALG_RSASHA256 || alg == ALG_ECDSAP256SHA256 { return 256; }
    if alg == ALG_ECDSAP384SHA384 { return 384; }
    if alg == ALG_RSASHA512 { return 512; }
    return 0;
}

fn is_rsa(alg: u8) -> bool { alg == ALG_RSASHA1 || alg == ALG_RSASHA1NSEC3SHA1 || alg == ALG_RSASHA256 || alg == ALG_RSASHA512 }
fn is_ecdsa(alg: u8) -> bool { alg == ALG_ECDSAP256SHA256 || alg == ALG_ECDSAP384SHA384 }

fn curve_of(alg: u8) -> bignum::Curve { if alg == ALG_ECDSAP384SHA384 { bignum::p384() } else { bignum::p256() } }

fn hash_of(id: i64, data: const u8[:]) -> u8[>..] { bignum::hash_bits(id, data) }

// --- DNSKEY ---------------------------------------------------------------------

// DNSKEY rdata: flags, protocol 3, algorithm, public key.
fn dnskey_rdata(flags: u16, alg: u8, public_key: const u8[:]) -> u8[>..] {
    var rd: u8[>..] = [];
    put16(rd, flags);
    rd.push(3);
    rd.push(alg);
    rd.append(public_key);
    return rd;
}

fn dnskey_flags(rd: const u8[:]) -> u16 { get16(rd, 0) }
fn dnskey_alg(rd: const u8[:]) -> u8 { rd[3] }
fn dnskey_public(rd: const u8[:]) -> const u8[:] { rd[4..] }

// The key tag (RFC 4034 Appendix B), over the whole rdata, as miekg's
// KeyTag computes it for every algorithm.
fn key_tag(rd: const u8[:]) -> u16 {
    var acc: i64 = 0;
    for i in rd.len { acc += if i & 1 != 0 { rd[i] } else { (rd[i] as i64) << 8 }; }
    acc += (acc >> 16) & 0xFFFF;
    return (acc & 0xFFFF) as! u16;
}

// DS rdata for a DNSKEY (RFC 4034 §5.1.4): the digest over the owner,
// lower-cased, and the DNSKEY rdata. ERR_ALG for a digest type not done.
fn ds_rdata(owner: const u8[:], dnskey: const u8[:], digest_type: u8, out: u8[>..]&) -> i64 {
    var data: u8[>..] = [];
    data.append(name_lower(owner));
    data.append(dnskey);
    put16(out, key_tag(dnskey));
    out.push(dnskey_alg(dnskey));
    out.push(digest_type);
    if digest_type == DIGEST_SHA1 { out.append(hash_of(160, data)); }
    else if digest_type == DIGEST_SHA256 { out.append(hash_of(256, data)); }
    else if digest_type == DIGEST_SHA384 { out.append(hash_of(384, data)); }
    else { return ERR_ALG; }
    return OK;
}

// RSA public keys in DNSKEYs (RFC 3110 §2): the exponent's length in one
// byte, or 0 and two bytes, the exponent, the modulus. Keys from 512 to
// 4096 bits, as miekg takes them, are read; a shorter or odd modulus is not.
fn rsa_public_of(pk: const u8[:]) -> bignum::RsaPublicKey, bool {
    var k = bignum::RsaPublicKey { n: [], e: [] };
    if pk.len < 3 { return k, false; }
    var el = pk[0] as i64;
    var off = 1;
    if el == 0 { el = get16(pk, 1); off = 3; }
    if el == 0 || el > 4 || off + el >= pk.len { return k, false; }
    let e = bignum::from_bytes_be(pk[off .. off + el]);
    let n = bignum::from_bytes_be(pk[off + el ..]);
    let bits = bignum::bit_len(n);
    if bits < 512 || bits > 4096 || n.mag[0] & 1 == 0 { return k, false; }
    for l in n.mag { k.n.push(l); }
    for l in e.mag { k.e.push(l); }
    return k, true;
}

// The DNSKEY form of an RSA public key.
fn rsa_public_bytes(n: const u8[:], e: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var ei = 0;
    while ei < e.len - 1 && e[ei] == 0 { ei++; }
    var ni = 0;
    while ni < n.len - 1 && n[ni] == 0 { ni++; }
    let el = e.len - ei;
    if el < 256 { out.push(el as! u8); } else { out.push(0); put16(out, el as! u16); }
    out.append(e[ei..]);
    out.append(n[ni..]);
    return out;
}

// --- Private keys ------------------------------------------------------------------

// A private key: RSA's numbers, or ECDSA's scalar (32 or 48 bytes), or an
// Ed25519 seed (32 bytes).
struct PrivateKey {
    alg: u8,
    rsa: bignum::RsaPrivateKey,
    sk: u8[..48],
}

fn empty_private() -> PrivateKey {
    PrivateKey { 0, bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] }, [] }
}

fn limbs_be(limbs: const u32[:]) -> u8[>..] {
    var v = bignum::zero();
    for l in limbs { v.mag.push(l); }
    while v.mag.len > 0 && v.mag[v.mag.len - 1] == 0 { v.mag.pop(); }
    return bignum::to_bytes_be(v, max(1, (bignum::bit_len(v) + 7) / 8));
}

// The key's public half, as a DNSKEY holds it.
fn public_key_bytes(k: const PrivateKey&) -> u8[>..] {
    if is_rsa(k.alg) { return rsa_public_bytes(limbs_be(k.rsa.n), limbs_be(k.rsa.e)); }
    if is_ecdsa(k.alg) {
        let c = curve_of(k.alg);
        let pub = bignum::ec_public_key(c, k.sk);
        var out: u8[>..] = [];
        out.append(pub[1..]);      // x || y, without SEC 1's 04
        return out;
    }
    var out: u8[>..] = [];
    out.append(bignum::ed25519_public(k.sk));
    return out;
}

// A new key for the algorithm (miekg's DNSKEY.Generate): bits for RSA
// (1024 to 4096), ignored otherwise. ERR_ALG for an algorithm not done,
// ERR_KEY for a bad size.
fn generate_key(alg: u8, bits: i64) -> PrivateKey, i64 {
    var k = empty_private();
    k.alg = alg;
    if is_rsa(alg) {
        if bits < 1024 || bits > 4096 || (alg == ALG_RSASHA512 && bits < 1024) { return k, ERR_KEY; }
        k.rsa = bignum::rsa_generate(bits);
        return k, OK;
    }
    if is_ecdsa(alg) {
        let c = curve_of(alg);
        let sk, pk = bignum::ec_keypair(c);
        k.sk.append(sk);
        return k, OK;
    }
    if alg == ALG_ED25519 {
        let seed, pk = bignum::ed25519_keypair();
        k.sk.append(seed);
        return k, OK;
    }
    return k, ERR_ALG;
}

fn b64(out: u8[>..]&, b: const u8[:]) { base64::encode(out, b); }

// The key in BIND's private-key format v1.3 (miekg's PrivateKeyString).
fn private_key_string(k: const PrivateKey&) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("Private-key-format: v1.3\nAlgorithm: ");
    format(out, k.alg);
    out.append(" (");
    alg_append(out, k.alg);
    out.append(")\n");
    if is_rsa(k.alg) {
        out.append("Modulus: "); b64(out, limbs_be(k.rsa.n));
        out.append("\nPublicExponent: "); b64(out, limbs_be(k.rsa.e));
        out.append("\nPrivateExponent: "); b64(out, limbs_be(k.rsa.d));
        out.append("\nPrime1: "); b64(out, limbs_be(k.rsa.p));
        out.append("\nPrime2: "); b64(out, limbs_be(k.rsa.q));
        out.append("\nExponent1: "); b64(out, limbs_be(k.rsa.dp));
        out.append("\nExponent2: "); b64(out, limbs_be(k.rsa.dq));
        out.append("\nCoefficient: "); b64(out, limbs_be(k.rsa.qinv));
        out.push('\n');
        return out;
    }
    out.append("PrivateKey: ");
    b64(out, k.sk);
    out.push('\n');
    return out;
}

// A key from BIND's private-key file (v1.2 or v1.3; miekg's
// ReadPrivateKey), checked against the DNSKEY's public key when one is
// given. ERR_PRIVATE_KEY if it does not parse, ERR_KEY if it does not
// match, ERR_ALG for an algorithm not done.
fn read_private_key(text: const u8[:], dnskey: const u8[:]) -> PrivateKey, i64 {
    var k = empty_private();
    var version_ok = false;
    var alg = -1;
    var blob: u8[>..] = [];             // the RSA numbers, decoded, back to back
    var spans: i64[16] = [0; 16];
    let names = ["modulus", "publicexponent", "privateexponent", "prime1", "prime2", "exponent1", "exponent2", "coefficient"];
    var sk: u8[>..] = [];
    var bad = false;
    each_split(text, '\n') { line0 =>
        let line = trim(line0);
        let key, val0, has = split_once(line, ':');
        if has && line.len > 0 && line[0] != ';' {
            let val = trim(val0);
            var lk: u8[>..] = [];
            for c in trim(key) { lk.push(lower(c)); }
            if lk == "private-key-format" { version_ok = val == "v1.2" || val == "v1.3"; }
            else if lk == "algorithm" {
                let a, rest, sp = split_once(val, ' ');
                alg = uint_parse_dec(a, 255);
            } else if lk == "privatekey" {
                if !base64::decode(sk, val) { bad = true; }
            } else {
                for i in 8 {
                    if lk == names[i] {
                        spans[2 * i] = blob.len;
                        if !base64::decode(blob, val) { bad = true; }
                        spans[2 * i + 1] = blob.len;
                    }
                }
            }
        }
    };
    if !version_ok || alg < 0 || bad { return k, ERR_PRIVATE_KEY; }
    k.alg = alg as! u8;
    if is_rsa(k.alg) {
        for i in 5 { if spans[2 * i + 1] == spans[2 * i] { return k, ERR_PRIVATE_KEY; } }
        let r, ok = bignum::rsa_key_from_bytes(blob[spans[0]..spans[1]], blob[spans[2]..spans[3]], blob[spans[4]..spans[5]],
                                               blob[spans[6]..spans[7]], blob[spans[8]..spans[9]]);
        if !ok { return k, ERR_KEY; }
        k.rsa = r;
    } else if is_ecdsa(k.alg) {
        let want = if k.alg == ALG_ECDSAP256SHA256 { 32 } else { 48 };
        if sk.len == 0 || sk.len > want { return k, ERR_PRIVATE_KEY; }
        for i in want - sk.len { k.sk.push(0); }
        k.sk.append(sk);
        let c = curve_of(k.alg);
        let s, ok = bignum::ec_scalar(c, k.sk);
        if !ok { return k, ERR_KEY; }
    } else if k.alg == ALG_ED25519 {
        if sk.len != 32 { return k, ERR_PRIVATE_KEY; }
        k.sk.append(sk);
    } else {
        return k, ERR_ALG;
    }
    if dnskey.len > 4 {
        if dnskey_alg(dnskey) != k.alg || public_key_bytes(k) != dnskey_public(dnskey) { return k, ERR_KEY; }
    }
    return k, OK;
}

fn uint_parse_dec(s: const u8[:], max: i64) -> i64 {
    if !all_digits(s) || s.len > 18 { return -1; }
    let n, ok = parse_int(s);
    return if ok && n <= max { n } else { -1 };
}

// --- Signatures --------------------------------------------------------------------

// RRSIG rdata's fields.
fn rrsig_type_covered(rd: const u8[:]) -> u16 { get16(rd, 0) }
fn rrsig_alg(rd: const u8[:]) -> u8 { rd[2] }
fn rrsig_labels(rd: const u8[:]) -> u8 { rd[3] }
fn rrsig_orig_ttl(rd: const u8[:]) -> u32 { get32(rd, 4) }
fn rrsig_expiration(rd: const u8[:]) -> u32 { get32(rd, 8) }
fn rrsig_inception(rd: const u8[:]) -> u32 { get32(rd, 12) }
fn rrsig_key_tag(rd: const u8[:]) -> u16 { get16(rd, 16) }
fn rrsig_signer(rd: const u8[:]) -> const u8[:] { rd[18 .. 18 + name_len_at(rd, 18)] }
fn rrsig_signature(rd: const u8[:]) -> const u8[:] { rd[18 + name_len_at(rd, 18) ..] }

// Whether now (seconds since the epoch) is within the RRSIG's inception
// and expiration, read in serial arithmetic (miekg's ValidityPeriod).
fn validity_period(rd: const u8[:], now: i64) -> bool {
    let inc = rrsig_inception(rd) as i64;
    let exp = rrsig_expiration(rd) as i64;
    let ti = inc + (inc - now) / YEAR68 * YEAR68;
    let te = exp + (exp - now) / YEAR68 * YEAR68;
    return ti <= now && now <= te;
}

struct Canon { off: i64, rd: i64, end: i64 }

// The data an RRSIG signs (RFC 4034 §3.1.8.1): its rdata to the signer
// name (lower-cased), then each record of the set in canonical form
// (§6.2: owner lower-cased, or the wildcard it came from; the original
// TTL; rdata names lower-cased where the type says), sorted by rdata,
// duplicates once.
fn signed_data(rrsig_head: const u8[:], rrset: const u8[:], out: u8[>..]&) {
    out.append(rrsig_head[..18]);
    out.append(name_lower(rrsig_head[18 .. 18 + name_len_at(rrsig_head, 18)]));
    let labels = rrsig_labels(rrsig_head) as i64;
    let ttl = rrsig_orig_ttl(rrsig_head);
    var canon: u8[>..] = [];
    var idx: Canon[>..] = [];
    each_rr(rrset) { rr =>
        let start = canon.len;
        var owner = name_lower(rr.name(rrset));
        let n = label_count(owner);
        if n > labels { owner = wildcard_of_labels(owner, labels); }
        canon.append(owner);
        put16(canon, rr.rtype);
        put16(canon, rr.class);
        put32(canon, ttl);
        let lp = canon.len;
        put16(canon, 0);
        rdata_canonical(rr.rtype, rr.rdata(rrset), canon);
        set16(canon, lp, (canon.len - lp - 2) as! u16);
        idx.push(Canon { start, lp + 2, canon.len });
    };
    sort(idx) { a, b => compare(canon[a.rd .. a.end], canon[b.rd .. b.end]) < 0 };
    for i in idx.len {
        let c = idx[i];
        if i > 0 && canon[c.off .. c.end] == canon[idx[i - 1].off .. idx[i - 1].end] { continue; }
        out.append(canon[c.off .. c.end]);
    }
}

// Signs the RRset with the key (miekg's RRSIG.Sign): appends an RRSIG
// record for it to out, its owner and class the set's, its labels the
// owner's (less a wildcard's "*"), its original TTL the set's first TTL,
// the signer the key's owner, the key tag the DNSKEY's. Times are seconds
// since the epoch, kept modulo 2^32.
fn sign_rrset(rrset: const u8[:], key: const PrivateKey&, signer: const u8[:], dnskey: const u8[:],
              inception: i64, expiration: i64, out: u8[>..]&) -> i64 {
    if rrset.len == 0 { return ERR_RDATA; }
    if dnskey_alg(dnskey) != key.alg { return ERR_KEY; }
    let first = rr_at(rrset, 0);
    let owner = first.name(rrset);
    var labels = label_count(owner);
    if owner.len > 2 && owner[0] == 1 && owner[1] == '*' { labels--; }
    var rd: u8[>..] = [];
    put16(rd, first.rtype);
    rd.push(key.alg);
    rd.push(labels as! u8);
    put32(rd, first.ttl);
    put32(rd, (expiration & 0xffffffff) as! u32);
    put32(rd, (inception & 0xffffffff) as! u32);
    put16(rd, key_tag(dnskey));
    rd.append(signer);
    var data: u8[>..] = [];
    signed_data(rd, rrset, data);
    var sig: u8[>..] = [];
    let e = sign_data(key, data, sig);
    if e != OK { return e; }
    rd.append(sig);
    return rr_append(out, owner, TYPE_RRSIG, first.class, first.ttl, rd);
}

fn sign_data(key: const PrivateKey&, data: const u8[:], sig: u8[>..]&) -> i64 {
    if is_rsa(key.alg) {
        let h = alg_hash(key.alg);
        let s, ok = bignum::rsa_sign_pkcs1_digest(key.rsa, hash_of(h, data), h);
        if !ok { return ERR_KEY; }
        sig.append(s);
        return OK;
    }
    if is_ecdsa(key.alg) {
        let h = alg_hash(key.alg);
        let c = curve_of(key.alg);
        sig.append(bignum::ecdsa_sign_digest(c, key.sk, hash_of(h, data), h));
        return OK;
    }
    if key.alg == ALG_ED25519 {
        sig.append(bignum::ed25519_sign(key.sk, data));
        return OK;
    }
    return ERR_ALG;
}

// Verifies an RRSIG (its rdata) over the RRset with a DNSKEY (its owner
// and rdata), as miekg's RRSIG.Verify: the key tag, algorithm and signer
// must be the key's, the key a zone key of protocol 3, the set the one
// the RRSIG covers and below the signer. The validity period is not
// checked here: validity_period does that.
fn verify_rrsig(rrsig: const u8[:], rrset: const u8[:], key_owner: const u8[:], dnskey: const u8[:]) -> i64 {
    if rrset.len == 0 || rrsig.len < 20 || dnskey.len < 5 { return ERR_RDATA; }
    if rrsig_key_tag(rrsig) != key_tag(dnskey) || rrsig_alg(rrsig) != dnskey_alg(dnskey) { return ERR_KEY; }
    let signer = rrsig_signer(rrsig);
    if !name_equal(signer, key_owner) { return ERR_KEY; }
    if dnskey[2] != 3 || dnskey_flags(dnskey) & FLAG_ZONE == 0 { return ERR_KEY; }
    let first = rr_at(rrset, 0);
    var same = true;
    each_rr(rrset) { rr =>
        if rr.rtype != first.rtype || rr.class != first.class || !name_equal(rr.name(rrset), first.name(rrset)) { same = false; }
    };
    if !same || first.rtype != rrsig_type_covered(rrsig) || label_count(first.name(rrset)) < rrsig_labels(rrsig)
        || !is_subdomain(signer, first.name(rrset)) {
        return ERR_RDATA;
    }
    var data: u8[>..] = [];
    signed_data(rrsig, rrset, data);
    let sig = rrsig_signature(rrsig);
    let alg = rrsig_alg(rrsig);
    let pk = dnskey_public(dnskey);
    if is_rsa(alg) {
        let k, ok = rsa_public_of(pk);
        if !ok { return ERR_KEY; }
        let h = alg_hash(alg);
        return if bignum::rsa_verify_pkcs1_digest(k, hash_of(h, data), sig, h) { OK } else { ERR_SIG };
    }
    if is_ecdsa(alg) {
        let c = curve_of(alg);
        if pk.len != 2 * c.len || sig.len != 2 * c.len { return ERR_KEY; }
        var full: u8[>..] = [4];
        full.append(pk);
        let h = alg_hash(alg);
        return if bignum::ecdsa_verify_digest(c, full, hash_of(h, data), sig) { OK } else { ERR_SIG };
    }
    if alg == ALG_ED25519 {
        if pk.len != 32 || sig.len != 64 { return ERR_KEY; }
        return if bignum::ed25519_verify(pk, data, sig) { OK } else { ERR_SIG };
    }
    return ERR_ALG;
}

// --- NSEC3 ---------------------------------------------------------------------------

// RFC 5155 §5's hash of a name: SHA-1 over the lower-cased wire name and
// the salt, then again over the hash and the salt, iterations times.
// Only algorithm 1 (SHA-1) is defined; ERR_ALG otherwise.
fn nsec3_hash(n: const u8[:], alg: u8, iterations: u16, salt: const u8[:]) -> u8[20], i64 {
    var h: u8[20] = [0; 20];
    if alg != 1 { return h, ERR_ALG; }
    var buf: u8[>..] = [];
    buf.append(name_lower(n));
    buf.append(salt);
    h = bignum::sha1(buf);
    for i in iterations {
        buf.clear();
        buf.append(h);
        buf.append(salt);
        h = bignum::sha1(buf);
    }
    return h, OK;
}

// The hash as its label: base32hex, upper case (miekg's HashName).
fn nsec3_label(n: const u8[:], alg: u8, iterations: u16, salt: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let h, e = nsec3_hash(n, alg, iterations, salt);
    if e == OK { base32_append(out, h); }
    return out;
}

// Whether the NSEC3 record (owner and rdata) is the one for name: its
// first label is the name's hash (miekg's NSEC3.Match).
fn nsec3_match(owner: const u8[:], rd: const u8[:], n: const u8[:]) -> bool {
    let salt = rd[5 .. 5 + rd[4] as i64];
    let label = nsec3_label(n, rd[0], get16(rd, 2), salt);
    if owner.len < 1 || owner[0] != label.len { return false; }
    let zone = name_suffix(owner, 1);
    if !is_subdomain(zone, n) { return false; }
    for i in label.len { if lower(owner[1 + i]) != lower(label[i]) { return false; } }
    return true;
}

// Whether the NSEC3 record covers name: its hash falls strictly between
// the owner's hash and the next one, around the end of the chain too
// (miekg's NSEC3.Cover).
fn nsec3_cover(owner: const u8[:], rd: const u8[:], n: const u8[:]) -> bool {
    let sl = rd[4] as i64;
    let salt = rd[5 .. 5 + sl];
    let hl = rd[5 + sl] as i64;
    let next = rd[6 + sl .. 6 + sl + hl];
    let h, e = nsec3_hash(n, rd[0], get16(rd, 2), salt);
    if e != OK || owner.len < 1 { return false; }
    let zone = name_suffix(owner, 1);
    if !is_subdomain(zone, n) { return false; }
    var mine: u8[>..] = [];
    if !base32_decode(mine, owner[1 .. 1 + owner[0] as i64]) { return false; }
    let c1 = compare(mine, h);
    let c2 = compare(h, next);
    let c3 = compare(mine, next);
    if c3 < 0 { return c1 < 0 && c2 < 0; }
    return c1 < 0 || c2 < 0;        // the last record wraps around
}
