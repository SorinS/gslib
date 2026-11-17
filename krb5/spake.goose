// krb5.spake: SPAKE pre-authentication (draft-ietf-kitten-krb-spake-preauth,
// MIT 1.17 and later), the client's side, with the second factor SF-NONE.
// The password never leaves the client in a form that can be guessed at
// offline: where encrypted timestamp sends something encrypted in the
// password's key, SPAKE runs a key exchange masked by it.
//
// The exchange. The KDC offers PA-SPAKE (empty) in its PREAUTH_REQUIRED
// error; the client sends the groups it takes (support); the KDC picks one
// and answers MORE_PREAUTH_DATA_REQUIRED with its public key
// T = x*G + w*M (challenge), or sends that challenge at once
// (optimistically) in place of the empty offer. The client's public key is
// S = y*G + w*N and the shared element K = y*(T - w*M), which the KDC finds
// as x*(S - w*N). The client's response carries S and SF-NONE encrypted in
// K'[1]; the reply key becomes K'[0].
//
// w is PRF+(initial reply key, "SPAKEsecret" || group) as a scalar (mod
// the group's order). The transcript hash starts at zeros and takes
// H(hash || support || challenge), then H(hash || S); a challenge the
// client refuses (a group it does not take) is not in it. K'[n] is
// KRB-FX-CF2(initial key, "SPAKE", random-to-key(H("SPAKEkey" || group ||
// etype || w's bytes || K || hash || KDC-REQ-BODY || n || block)),
// "keyderiv"), the body the one inside FAST when armored.
//
// The groups: edwards25519 (SHA-256), P-256 (SHA-256), P-384 (SHA-384) and
// P-521 (SHA-512). P-521's multiplier is 66 bytes, as MIT's iana.c and the
// draft's own test vectors have it; the draft's registry table says 48.
// Private scalars are multiples of the cofactor (8 for edwards25519), and
// every multiplication by w, x or y runs in constant time (bignum.ed25519,
// bignum.ec).

namespace krb5;

import std;
import encoding.asn1;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.bignum.mont;
import crypto.bignum.ec;
import crypto.bignum.x25519;
import crypto.bignum.ed25519;
import crypto.bignum.sha1;
import crypto.bignum.sha256;
import crypto.bignum.sha512;
import entropy;
import krb5.crypto;
import krb5.messages;

// A group: its number, its curve (edwards25519 or a NIST curve by bits),
// the lengths of its multiplier, of an encoded element and of its hash,
// and its M and N. hash_bits 1 is SHA-1: only the draft's test vector for
// a key derivation of several blocks uses it (its group -1).
struct SpakeGroup { id: i64, curve_bits: i64, mult_len: i64, elem_len: i64, hash_bits: i64, m: u8[..67], n: u8[..67] }

fn spake_hex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn spake_group_of(id: i64, bits: i64, mult: i64, elem: i64, hash: i64, m: const u8[:], n: const u8[:]) -> SpakeGroup {
    var g = SpakeGroup { id: id, curve_bits: bits, mult_len: mult, elem_len: elem, hash_bits: hash, m: [], n: [] };
    g.m.append(spake_hex(m));
    g.n.append(spake_hex(n));
    return g;
}

// The group numbered `id`; false for one we do not have.
fn spake_group(id: i64) -> SpakeGroup, bool {
    if id == SPAKE_EDWARDS25519 {
        return spake_group_of(id, 255, 32, 32, 256,
            "d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf",
            "d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab"), true;
    }
    if id == SPAKE_P256 {
        return spake_group_of(id, 256, 32, 33, 256,
            "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f",
            "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"), true;
    }
    if id == SPAKE_P384 {
        return spake_group_of(id, 384, 48, 49, 384,
            "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853",
            "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10"), true;
    }
    if id == SPAKE_P521 {
        return spake_group_of(id, 521, 66, 67, 512,
            "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa",
            "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25"), true;
    }
    return spake_group_of(0, 0, 0, 0, 0, "", ""), false;
}

// MIT's names (spake_preauth_groups in krb5.conf), case ignored; 0 if none.
fn spake_group_by_name(name: const u8[:]) -> i64 {
    var low: u8[>..] = [];
    for ch in name { low.push(if ch >= 'A' && ch <= 'Z' { ch + 32 } else { ch }); }
    if low == "edwards25519" { return SPAKE_EDWARDS25519; }
    if low == "p-256" { return SPAKE_P256; }
    if low == "p-384" { return SPAKE_P384; }
    if low == "p-521" { return SPAKE_P521; }
    return 0;
}

// The groups a list names (spaces or commas between), in its order, each
// once; unknown names skipped, as MIT does.
fn spake_groups_named(list: const u8[:]) -> i64[>..] {
    var out: i64[>..] = [];
    var at = 0;
    while at < list.len {
        while at < list.len && (list[at] == ' ' || list[at] == ',' || list[at] == '\t') { at++; }
        let start = at;
        while at < list.len && list[at] != ' ' && list[at] != ',' && list[at] != '\t' { at++; }
        if at == start { continue; }
        let g = spake_group_by_name(list[start..at]);
        var dup = false;
        for o in out { if o == g { dup = true; } }
        if g != 0 && !dup { out.push(g); }
    }
    return out;
}

fn spake_hash(g: const SpakeGroup&, data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if g.hash_bits == 1 { out.append(bignum::sha1(data)); }
    else if g.hash_bits == 256 { out.append(bignum::sha256(data)); }
    else if g.hash_bits == 384 { out.append(bignum::sha384(data)); }
    else { out.append(bignum::sha512(data)); }
    return out;
}

fn spake_hash_len(g: const SpakeGroup&) -> i64 {
    if g.hash_bits == 1 { 20 } else { g.hash_bits / 8 }
}

fn spake_curve(g: const SpakeGroup&) -> bignum::Curve {
    if g.curve_bits == 256 { bignum::p256() } else if g.curve_bits == 384 { bignum::p384() } else { bignum::p521() }
}

fn put_be32(out: u8[>..]&, v: i64) {
    let u = v as! u32;
    out.push((u >> 24) as! u8);
    out.push((u >> 16) as! u8);
    out.push((u >> 8) as! u8);
    out.push(u as! u8);
}

// --- The key exchange -------------------------------------------------------

// w's bytes: PRF+(key, "SPAKEsecret" || group), the multiplier's length.
fn spake_wbytes(g: const SpakeGroup&, key: Key, out: u8[>..]&) -> i64 {
    var pepper: u8[>..] = [];
    pepper.append("SPAKEsecret");
    put_be32(pepper, g.id);
    return prf_plus(key, pepper, g.mult_len, out);
}

// w as a scalar, reduced mod the group's order: little-endian 32 bytes
// on edwards25519, big-endian of the curve's width on the others.
fn spake_w(g: const SpakeGroup&, wbytes: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if g.curve_bits == 255 {
        out.append(bignum::ed_reduce(wbytes));
        return out;
    }
    let c = spake_curve(g);
    var x: u32[>..] = [];
    x.resize((wbytes.len + 3) / 4, 0);
    bignum::limbs_from_be(x[..], wbytes);
    var r = bignum::ec_zero(c);
    bignum::ct_reduce(r[..], x[..], c.n[..]);
    out.resize(g.mult_len, 0);
    bignum::be_from_limbs(out[..], r[..]);
    return out;
}

// A fresh private scalar, uniform below the order and a multiple of the
// cofactor: for edwards25519 (little-endian) 64 random bytes mod L, times 8
// (MIT reduces 32); for a NIST curve (big-endian) drawn until below n.
fn spake_private(g: const SpakeGroup&) -> u8[>..] {
    var out: u8[>..] = [];
    if g.curve_bits == 255 {
        var r: u8[64] = [0; 64];
        entropy::random_bytes(r[..]);
        var s = bignum::ed_reduce(r[..]);
        var carry: u8 = 0;
        for i in 32 {
            let next = s[i] >> 5;
            s[i] = (s[i] << 3) | carry;
            carry = next;
        }
        out.append(s);
        return out;
    }
    let c = spake_curve(g);
    out.resize(g.mult_len, 0);
    let top_bits = c.bits - 8 * (g.mult_len - 1);
    while true {
        entropy::random_bytes(out[..]);
        out[0] = out[0] & (((1 << top_bits) - 1) as! u8);
        var k = bignum::ec_zero(c);
        bignum::limbs_from_be(k[..], out[..]);
        if bignum::ct_lt(k[..], c.n[..]) == 1 { break; }
    }
    return out;
}

// The public key priv*G + w*(M, or N when !use_m): the KDC's T uses M,
// the client's S uses N.
fn spake_public(g: const SpakeGroup&, priv: const u8[:], wbytes: const u8[:], use_m: bool) -> u8[>..], i64 {
    let w = spake_w(g, wbytes);
    var out: u8[>..] = [];
    if g.curve_bits == 255 {
        let cp, ok = bignum::ed_decode(if use_m { g.m[..] } else { g.n[..] });
        if !ok { return out, ERR_PREAUTH; }
        let b = bignum::ed_base();
        let x = bignum::ed_mul(priv, b);
        let wc = bignum::ed_mul(w, cp);
        let p = bignum::ed_add(x, wc);
        out.append(bignum::ed_encode(p));
        return out, OK;
    }
    let c = spake_curve(g);
    let cp, ok = bignum::ec_decode_compressed(c, if use_m { g.m[..] } else { g.n[..] });
    if !ok { return out, ERR_PREAUTH; }
    var k = bignum::ec_zero(c);
    bignum::limbs_from_be(k[..], priv);
    var wl = bignum::ec_zero(c);
    bignum::limbs_from_be(wl[..], w);
    let gen = bignum::ec_generator(c);
    let x = bignum::ec_mul(c, k[..], gen);
    let wc = bignum::ec_mul(c, wl[..], cp);
    let p = bignum::ec_add(c, x, wc);
    let ax, ay, finite = bignum::ec_affine(c, p);
    if !finite { return out, ERR_PREAUTH; }
    out.append(bignum::ec_encode_compressed(c, p));
    return out, OK;
}

// The shared element K = priv*(peer - w*(M, or N when !use_m)): the
// client's uses M (the KDC's T), the KDC's N. ERR_PREAUTH for a peer key
// that is not a point of the group, or a K that is the identity (which
// would make the keys predictable). The peer's point need not be in the
// prime-order subgroup: priv is a multiple of the cofactor.
fn spake_result(g: const SpakeGroup&, priv: const u8[:], wbytes: const u8[:], peer: const u8[:], use_m: bool)
    -> u8[>..], i64 {
    let w = spake_w(g, wbytes);
    var out: u8[>..] = [];
    if peer.len != g.elem_len { return out, ERR_PREAUTH; }
    if g.curve_bits == 255 {
        let cp, ok = bignum::ed_decode(if use_m { g.m[..] } else { g.n[..] });
        let pp, pok = bignum::ed_decode(peer);
        if !ok || !pok { return out, ERR_PREAUTH; }
        let wc = bignum::ed_mul(w, cp);
        let nwc = bignum::ed_neg(wc);
        let d = bignum::ed_add(pp, nwc);
        let k = bignum::ed_mul(priv, d);
        let enc = bignum::ed_encode(k);
        let o = bignum::ed_identity();
        let id = bignum::ed_encode(o);
        if enc == id { return out, ERR_PREAUTH; }
        out.append(enc);
        return out, OK;
    }
    let c = spake_curve(g);
    let cp, ok = bignum::ec_decode_compressed(c, if use_m { g.m[..] } else { g.n[..] });
    let pp, pok = bignum::ec_decode_compressed(c, peer);
    if !ok || !pok { return out, ERR_PREAUTH; }
    var k = bignum::ec_zero(c);
    bignum::limbs_from_be(k[..], priv);
    var wl = bignum::ec_zero(c);
    bignum::limbs_from_be(wl[..], w);
    let wc = bignum::ec_mul(c, wl[..], cp);
    let nwc = bignum::ec_neg(c, wc);
    let d = bignum::ec_add(c, pp, nwc);
    let r = bignum::ec_mul(c, k[..], d);
    let ax, ay, finite = bignum::ec_affine(c, r);
    if !finite { return out, ERR_PREAUTH; }
    out.append(bignum::ec_encode_compressed(c, r));
    return out, OK;
}

// The transcript hash updated with a || b; an empty one starts at zeros.
fn spake_thash(g: const SpakeGroup&, thash: const u8[:], a: const u8[:], b: const u8[:]) -> u8[>..] {
    var hin: u8[>..] = [];
    if thash.len == 0 { hin.resize(spake_hash_len(g), 0); } else { hin.append(thash); }
    hin.append(a);
    hin.append(b);
    return spake_hash(g, hin);
}

// K'[n] (§7), of the initial key's type.
fn spake_key(g: const SpakeGroup&, ikey: Key, wbytes: const u8[:], k: const u8[:], thash: const u8[:],
             body: const u8[:], n: i64) -> Key, i64 {
    let e = ikey.etype;
    if !etype_supported(e) { return no_key(), ERR_ETYPE; }
    var hin: u8[>..] = [];
    hin.append("SPAKEkey");
    put_be32(hin, g.id);
    put_be32(hin, e);
    hin.append(wbytes);
    hin.append(k);
    hin.append(thash);
    hin.append(body);
    put_be32(hin, n);
    hin.push(0);
    let want = seed_len(e);
    var seed: u8[>..] = [];
    var counter = 1;
    while seed.len < want {
        hin[hin.len - 1] = counter as! u8;
        seed.append(spake_hash(g, hin));
        counter++;
    }
    let hk = random_to_key(e, seed[..want]);
    return fx_cf2(ikey, "SPAKE", hk, "keyderiv");
}

// --- Messages ---------------------------------------------------------------

// SPAKESecondFactor ::= SEQUENCE { type [0] Int32, data [1] OCTET STRING OPTIONAL }
struct SpakeFactor { ftype: i64, has_data: bool, data: u8[] }

// PA-SPAKE ::= CHOICE { support [0], challenge [1], response [2], encdata [3] }.
// support: groups; challenge: group, pubkey, factors; response: pubkey,
// factor; encdata: enc.
struct PaSpake {
    choice: i64,
    groups: i64[],
    group: i64,
    pubkey: u8[],
    factors: SpakeFactor[],
    enc: EncryptedData,
}

let SPAKE_SUPPORT: i64 = 0;
let SPAKE_CHALLENGE: i64 = 1;
let SPAKE_RESPONSE: i64 = 2;
let SPAKE_ENCDATA: i64 = 3;

fn put_factor(out: u8[>..]&, f: const SpakeFactor&) {
    var s: u8[>..] = [];
    put_int_f(s, 0, f.ftype);
    if f.has_data { put_octets_f(s, 1, f.data); }
    put_seq(out, s);
}

fn encode_spake_factor(out: u8[>..]&, f: const SpakeFactor&) { put_factor(out, f); }

fn factor_at(buf: const u8[:], t: asn1::Tlv, bad: bool&) -> SpakeFactor {
    var fs = fields_at(buf, t);
    require(fs, 1);
    let f = SpakeFactor { ftype: f_int32(buf, fs, 0), has_data: has(fs, 1), data: f_octets(buf, fs, 1) };
    if fs.bad { bad = true; }
    return f;
}

fn decode_spake_factor(buf: const u8[:]) -> SpakeFactor, i64 {
    let t, ok = asn1::parse(buf, true);
    var bad = !ok;
    let f = factor_at(buf, if ok { t } else { no_tlv() }, bad);
    return f, if bad { ERR_MALFORMED } else { OK };
}

fn encode_spake_support(out: u8[>..]&, groups: const i64[:]) {
    var list: u8[>..] = [];
    for g in groups { asn1::put_i64(list, g); }
    var seq: u8[>..] = [];
    put_seq(seq, list);
    var s: u8[>..] = [];
    put_field(s, 0, seq);
    var body: u8[>..] = [];
    put_seq(body, s);
    put_field(out, SPAKE_SUPPORT as! u32, body);
}

fn encode_spake_challenge(out: u8[>..]&, group: i64, pubkey: const u8[:], factors: const SpakeFactor[:]) {
    var s: u8[>..] = [];
    put_int_f(s, 0, group);
    put_octets_f(s, 1, pubkey);
    var list: u8[>..] = [];
    for f in factors { put_factor(list, f); }
    var seq: u8[>..] = [];
    put_seq(seq, list);
    put_field(s, 2, seq);
    var body: u8[>..] = [];
    put_seq(body, s);
    put_field(out, SPAKE_CHALLENGE as! u32, body);
}

fn encode_spake_response(out: u8[>..]&, pubkey: const u8[:], factor: const EncryptedData&) {
    var s: u8[>..] = [];
    put_octets_f(s, 0, pubkey);
    put_enc_data_f(s, 1, factor);
    var body: u8[>..] = [];
    put_seq(body, s);
    put_field(out, SPAKE_RESPONSE as! u32, body);
}

fn encode_spake_encdata(out: u8[>..]&, d: const EncryptedData&) {
    var body: u8[>..] = [];
    put_enc_data(body, d);
    put_field(out, SPAKE_ENCDATA as! u32, body);
}

// The EncryptedData of a response's field 1 or of encdata, else none.
fn spake_enc_at(buf: const u8[:], choice: i64, inner: asn1::Tlv, fs: Fields&) -> EncryptedData {
    if choice == SPAKE_ENCDATA { return enc_data_at(buf, inner, fs.bad); }
    if choice == SPAKE_RESPONSE { return f_enc_data(buf, fs, 1); }
    return no_enc_data();
}

fn decode_pa_spake(buf: const u8[:]) -> PaSpake, i64 {
    var groups: i64[>..] = [];
    var factors: SpakeFactor[>..] = [];
    var pubkey: u8[>..] = [];
    var group: i64 = 0;
    let t, ok = asn1::parse(buf, true);
    var choice: i64 = -1;
    var inner = no_tlv();
    var fs = Fields { bad: true, mask: 0, t: [no_tlv(); 16] };
    if ok && t.cls == asn1::CLASS_CONTEXT && t.constructed && t.number <= 3 {
        choice = t.number;
        let in2, iok = asn1::explicit(buf, t, true);
        inner = in2;
        if !iok {
            choice = -1;
        } else if choice == SPAKE_ENCDATA {
            fs.bad = false;
        } else {
            fs = fields_at(buf, inner);
            if choice == SPAKE_SUPPORT {
                require(fs, 1);
                if has(fs, 0) {
                    for k in seq_items(buf, fs.t[0], fs.bad) { groups.push(int32_at(buf, k, fs.bad)); }
                    if groups.len == 0 { fs.bad = true; }
                }
            } else if choice == SPAKE_CHALLENGE {
                require(fs, 7);
                group = f_int32(buf, fs, 0);
                pubkey.append(f_octets(buf, fs, 1));
                if has(fs, 2) {
                    for k in seq_items(buf, fs.t[2], fs.bad) { factors.push(factor_at(buf, k, fs.bad)); }
                    if factors.len == 0 { fs.bad = true; }
                }
            } else {
                require(fs, 3);
                pubkey.append(f_octets(buf, fs, 0));
            }
        }
    }
    let m = PaSpake { choice: choice, groups: copy(groups), group: group, pubkey: copy(pubkey), factors: copy(factors),
                      enc: spake_enc_at(buf, choice, inner, fs) };
    return m, if fs.bad || choice < 0 { ERR_MALFORMED } else { OK };
}

// --- The client -------------------------------------------------------------

// The client's state across the exchange: the support message it sent
// (empty if none), and once it has a challenge: the group, the initial
// reply key, w's bytes, K, the final transcript hash and its own public key.
struct SpakeState {
    sent_support: bool,
    support: u8[..64],
    ready: bool,
    group: i64,
    ikey: Key,
    wbytes: u8[..66],
    k: u8[..67],
    thash: u8[..64],
    pubkey: u8[..67],
}

// What the client's next request carries.
let SPAKE_NONE: i64 = 0;
let SPAKE_SEND_SUPPORT: i64 = 1;
let SPAKE_SEND_RESPONSE: i64 = 2;

fn spake_state() -> SpakeState {
    SpakeState { sent_support: false, support: [], ready: false, group: 0, ikey: no_key(), wbytes: [], k: [], thash: [],
                 pubkey: [] }
}

// The support message for `groups`, kept for the transcript.
fn spake_send_support(st: SpakeState&, groups: const i64[:]) -> u8[>..] {
    var m: u8[>..] = [];
    encode_spake_support(m, groups);
    st.sent_support = true;
    st.support.clear();
    st.support.append(m);
    return m;
}

fn spake_permitted(groups: const i64[:], g: i64) -> bool {
    for x in groups { if x == g { return true; } }
    return false;
}

// Answers a challenge (its DER `der`, decoded as `m`) with the initial
// reply key `ikey` and private scalar `priv` (spake_private, or a test's):
// the transcript, w, the public key and K. The caller has checked the
// group is one it takes. ERR_PREAUTH if SF-NONE is not offered or the
// KDC's key is no point.
fn spake_on_challenge(st: SpakeState&, m: const PaSpake&, der: const u8[:], ikey: Key, priv: const u8[:]) -> i64 {
    let g, known = spake_group(m.group);
    if !known { return ERR_PREAUTH; }
    var none = false;
    for f in m.factors { if f.ftype == SPAKE_SF_NONE { none = true; } }
    if !none { return ERR_PREAUTH; }
    var support: u8[>..] = [];
    if st.sent_support { support.append(st.support); }
    let th1 = spake_thash(g, "", support, der);
    var wb: u8[>..] = [];
    let werr = spake_wbytes(g, ikey, wb);
    if werr != OK { return werr; }
    let pubkey, perr = spake_public(g, priv, wb, false);
    if perr != OK { return perr; }
    let k, kerr = spake_result(g, priv, wb, m.pubkey, true);
    if kerr != OK { return kerr; }
    let th = spake_thash(g, th1, pubkey, "");
    st.ready = true;
    st.group = m.group;
    st.ikey = ikey;
    st.wbytes.clear();
    st.wbytes.append(wb);
    st.k.clear();
    st.k.append(k);
    st.thash.clear();
    st.thash.append(th);
    st.pubkey.clear();
    st.pubkey.append(pubkey);
    return OK;
}

// The response for a request whose KDC-REQ-BODY (the inner one, under
// FAST) is `body`: its PA-SPAKE value, and K'[0], the reply key.
fn spake_response(st: const SpakeState&, body: const u8[:]) -> u8[>..], Key, i64 {
    var out: u8[>..] = [];
    let g, known = spake_group(st.group);
    if !st.ready || !known { return out, no_key(), ERR_PREAUTH; }
    let k1, err1 = spake_key(g, st.ikey, st.wbytes, st.k, st.thash, body, 1);
    if err1 != OK { return out, no_key(), err1; }
    let k0, err0 = spake_key(g, st.ikey, st.wbytes, st.k, st.thash, body, 0);
    if err0 != OK { return out, no_key(), err0; }
    var f: u8[>..] = [];
    let none = SpakeFactor { ftype: SPAKE_SF_NONE, has_data: false, data: "" };
    encode_spake_factor(f, none);
    var c: u8[>..] = [];
    let eerr = encrypt(k1, USAGE_SPAKE, f, c);
    if eerr != OK { return out, no_key(), eerr; }
    let ed = EncryptedData { etype: k1.etype, has_kvno: false, kvno: 0, cipher: copy(c) };
    encode_spake_response(out, st.pubkey, ed);
    return out, k0, OK;
}
