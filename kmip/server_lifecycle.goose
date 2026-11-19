// kmip.server_lifecycle: the server's operations on keys' lives: Re-key
// and Re-key Key Pair (the replacement linked both ways, its dates moved
// by the Offset), Derive Key (PBKDF2, HASH, HMAC, ENCRYPT, the three
// SP 800-108 modes, HKDF, and ECDH from a key pair), Check, Obtain Lease,
// Get Usage Allocation, Archive and Recover, Import, Adjust Attribute and
// Interop.

namespace kmip;

import std;
import entropy;
import binary;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;
import kmip.formats;
import kmip.crypto;
import kmip.wrap;
import kmip.server;
import crypto.bignum;
import crypto.bignum.hmac;
import crypto.bignum.kdf;
import crypto.bignum.cmac;
import crypto.bignum.aes;
import crypto.bignum.ec;
import crypto.x509;
import crypto.x509.keys;
import encoding.asn1;

// --- Replacement keys -----------------------------------------------------------

// The attributes a replacement keeps from the key it replaces: all but
// the server's own, Links and Names (moved apart), the dates the Offset
// rules set, and Usage Limits (renewed).
fn kept_on_rekey(tag: u32) -> bool {
    !(server_only(tag) || tag == TAG_LINK || tag == TAG_NAME || tag == TAG_ACTIVATION_DATE ||
      tag == TAG_DEACTIVATION_DATE || tag == TAG_PROCESS_START_DATE || tag == TAG_PROTECT_STOP_DATE ||
      tag == TAG_USAGE_LIMITS || tag == TAG_CRYPTOGRAPHIC_ALGORITHM || tag == TAG_CRYPTOGRAPHIC_LENGTH ||
      tag == TAG_SENSITIVE || tag == TAG_EXTRACTABLE)
}

// The replacement's attributes from the old key's, with the dates the
// Offset gives (Table 303): when one is given, Activation is the new
// Initial Date plus it and the other dates keep their distance from it;
// when not, they are copied.
fn replacement_attrs(old: const Attrs&, now: i64, has_off: bool, off: i64, keep: Attrs&, own: Attrs&) {
    each_attr(old) { t, item =>
        if kept_on_rekey(t) || t == TAG_SENSITIVE || t == TAG_EXTRACTABLE { keep.enc.append(item); }
        if t == TAG_NAME { own.enc.append(item); }
    };
    let at1, a1 = get_datetime(old, TAG_ACTIVATION_DATE);
    let dates: u32[3] = [TAG_DEACTIVATION_DATE, TAG_PROCESS_START_DATE, TAG_PROTECT_STOP_DATE];
    if has_off {
        let at2 = now + off;
        let ad = item_of_date(TAG_ACTIVATION_DATE, at2);
        own.enc.append(ad);
        if a1 {
            for d in dates {
                let v, ok = get_datetime(old, d);
                if ok { let x = item_of_date(d, v + (at2 - at1)); own.enc.append(x); }
            }
        }
    } else {
        if a1 { let ad = item_of_date(TAG_ACTIVATION_DATE, at1); own.enc.append(ad); }
        for d in dates {
            let v, ok = get_datetime(old, d);
            if ok { let x = item_of_date(d, v); own.enc.append(x); }
        }
    }
    // Usage Limits: the Total kept, the Count back to it.
    let ul = find_attr(old, TAG_USAGE_LIMITS, 0);
    if ul.len > 0 {
        var doc: Node[>..] = [];
        let r, e = decode(ul, Options { .. }, doc);
        let total, tok = child_long(ul, doc, r, TAG_USAGE_LIMITS_TOTAL);
        let unit, uok = child_enum(ul, doc, r, TAG_USAGE_LIMITS_UNIT);
        if e == OK && tok && uok {
            let s = begin(own.enc, TAG_USAGE_LIMITS);
            put_long(own.enc, TAG_USAGE_LIMITS_TOTAL, total);
            put_long(own.enc, TAG_USAGE_LIMITS_COUNT, total);
            put_enum(own.enc, TAG_USAGE_LIMITS_UNIT, unit);
            end(own.enc, s);
        }
    }
}

// The old key gives up its Names and points at its replacement.
fn hand_over(s: Server&, owner: const u8[:], old_uid: const u8[:], new_uid: const u8[:], keep_names: bool) {
    let i = find_object(s, owner, old_uid);
    if i < 0 { return; }
    var a = attrs_of(s.objects[i]);
    if !keep_names { while remove_attr(a, TAG_NAME, 0) {} }
    attr_link(a, LINK_REPLACEMENT_OBJECT, new_uid);
    let ok = set_attrs(s.objects[i], a);
    let j = find_object(s, owner, new_uid);
    if j < 0 { return; }
    var b = attrs_of(s.objects[j]);
    attr_link(b, LINK_REPLACED_OBJECT, old_uid);
    let ok2 = set_attrs(s.objects[j], b);
    settle(s, j);
}

// The Names a request gives a replacement go after those it takes over.
fn move_names(keep: Attrs&, own: Attrs&) {
    var rest = attrs();
    each_attr(keep) { t, item => if t == TAG_NAME { own.enc.append(item); } else { rest.enc.append(item); } };
    keep.enc.clear();
    keep.enc.append(rest.enc);
}

fn offset_of(buf: const u8[:], doc: const Node[:], p: i64) -> i64, bool {
    let o, ok = as_interval(buf, doc, child(doc, p, TAG_OFFSET));
    return o, ok;
}

fn op_rekey(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    if s.objects[i].obj_type != OBJ_SYMMETRIC_KEY { return fail(REASON_INVALID_OBJECT_TYPE, "Re-key takes a symmetric key"); }
    let o, ok = object_of(s.objects[i]);
    if !ok || o.wrapped { return fail(REASON_KEY_VALUE_NOT_PRESENT, "the key's value is not here to renew"); }
    let old = attrs_of(s.objects[i]);
    let off, hoff = offset_of(buf, doc, p);
    var keep = attrs();
    var own = attrs();
    replacement_attrs(old, now_of(s), hoff, off, keep, own);
    // The request's attributes over the old key's.
    let given = payload_attrs(buf, doc, p, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    each_attr(given) { t, item => if multi_valued(t) { keep.enc.append(item); } else { set_single(keep, item); } };
    // The Names it takes over first, then any given it (TC-REKEY-1).
    move_names(keep, own);
    var k: u8[>..] = [];
    k.resize(o.material.len, 0);
    entropy::random_bytes(k);
    let nk = symmetric_key(o.alg, k);
    var uid: u8[>..] = [];
    var old_uid: u8[>..] = [];
    old_uid.append(s.objects[i].uid);
    generated(s, own);
    let r = add_object_with(s, owner, nk, keep, own, uid);
    if r.reason != 0 { return r; }
    hand_over(s, owner, old_uid, uid, false);
    rotate_after_replace(s, owner, old_uid, uid);
    put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    return done();
}

fn op_rekey_key_pair(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    var pv_uid: u8[>..] = [];
    let given_pv, gok = child_text(buf, doc, p, TAG_PRIVATE_KEY_UNIQUE_IDENTIFIER);
    if gok { pv_uid.append(given_pv); } else { pv_uid.append(s.batch_ids[UID_ID_PLACEHOLDER]); }
    let i = find_object(s, owner, pv_uid);
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such private key"); }
    if s.objects[i].obj_type != OBJ_PRIVATE_KEY { return fail(REASON_INVALID_OBJECT_TYPE, "Re-key Key Pair takes a private key"); }
    let o, ok = object_of(s.objects[i]);
    if !ok || o.wrapped { return fail(REASON_KEY_VALUE_NOT_PRESENT, "the key's value is not here to renew"); }
    let k, kok = private_of(o);
    if !kok { return fail(REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED, "the private key is not one gslib reads"); }
    let pa_old = attrs_of(s.objects[i]);
    // The public key, by the private key's Link.
    var pu_uid: u8[>..] = [];
    each_attr(pa_old) { t, item =>
        if t == TAG_LINK && pu_uid.len == 0 {
            var d: Node[>..] = [];
            let r, e = decode(item, Options { .. }, d);
            let lt, lok = child_enum(item, d, r, TAG_LINK_TYPE);
            let lu, uok = child_text(item, d, r, TAG_LINKED_OBJECT_IDENTIFIER);
            if e == OK && lok && uok && lt == LINK_PUBLIC_KEY { pu_uid.append(lu); }
        }
    };
    let j = find_object(s, owner, pu_uid);
    if j < 0 { return fail(REASON_ITEM_NOT_FOUND, "the private key's public key is not here"); }
    let pb_old = attrs_of(s.objects[j]);
    let bits: i64 = if k.kind == x509::KEY_RSA { o.length } else { 0 };
    let nk = x509::generate_key(k.kind, if bits > 0 { bits } else { 2048 });
    let po, pu = pair_objects(nk, o.alg, o.length);
    let now = now_of(s);
    let off, hoff = offset_of(buf, doc, p);
    var keep1 = attrs();
    var own1 = attrs();
    replacement_attrs(pa_old, now, hoff, off, keep1, own1);
    var keep2 = attrs();
    var own2 = attrs();
    replacement_attrs(pb_old, now, hoff, off, keep2, own2);
    let common = payload_attrs(buf, doc, p, TAG_COMMON_TEMPLATE_ATTRIBUTE, TAG_COMMON_ATTRIBUTES);
    let pa = payload_attrs(buf, doc, p, TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE, TAG_PRIVATE_KEY_ATTRIBUTES);
    let pb = payload_attrs(buf, doc, p, TAG_PUBLIC_KEY_TEMPLATE_ATTRIBUTE, TAG_PUBLIC_KEY_ATTRIBUTES);
    each_attr(common) { t, item => if multi_valued(t) { keep1.enc.append(item); keep2.enc.append(item); } else { set_single(keep1, item); set_single(keep2, item); } };
    each_attr(pa) { t, item => if multi_valued(t) { keep1.enc.append(item); } else { set_single(keep1, item); } };
    each_attr(pb) { t, item => if multi_valued(t) { keep2.enc.append(item); } else { set_single(keep2, item); } };
    move_names(keep1, own1);
    move_names(keep2, own2);
    generated(s, own1);
    generated(s, own2);
    var u1: u8[>..] = [];
    let r1 = add_object_with(s, owner, po, keep1, own1, u1);
    if r1.reason != 0 { return r1; }
    var u2: u8[>..] = [];
    let r2 = add_object_with(s, owner, pu, keep2, own2, u2);
    if r2.reason != 0 { return r2; }
    link_both(s, u1, LINK_PUBLIC_KEY, u2, owner);
    link_both(s, u2, LINK_PRIVATE_KEY, u1, owner);
    hand_over(s, owner, pv_uid, u1, false);
    hand_over(s, owner, pu_uid, u2, false);
    rotate_after_replace(s, owner, pv_uid, u1);
    rotate_after_replace(s, owner, pu_uid, u2);
    put_text(out, TAG_PRIVATE_KEY_UNIQUE_IDENTIFIER, u1);
    put_text(out, TAG_PUBLIC_KEY_UNIQUE_IDENTIFIER, u2);
    return done();
}

// --- Derive Key -----------------------------------------------------------------

// A PRF for SP 800-108: HMAC with the key's hash (or the parameters', or
// SHA-256), or CMAC for an AES key asked for it.
fn kdf_prf(base: const Object&, cp: const CryptoParams&, data: const u8[:], out: u8[>..]&) -> u32 {
    if base.alg == ALG_AES && cp.mode == MODE_CMAC {
        let k = bignum::aes_init(base.material);
        out.append(bignum::cmac(k, data));
        return 0;
    }
    var h = hmac_bits(base.alg);
    if h == 0 { h = hash_id(if cp.hash != 0 { cp.hash } else { HASH_SHA_256 }); }
    if h == 0 || h == 128 { return REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
    out.append(bignum::hmac(h, base.material, data));
    return 0;
}

fn be32(out: u8[>..]&, v: u32) { out.push((v >> 24) as! u8); out.push((v >> 16) as! u8); out.push((v >> 8) as! u8); out.push(v as! u8); }

// SP 800-108's counter, feedback and double-pipeline modes, the
// Derivation Data being Label || 0x00 || Context and the counter and
// length 32 bits before and after it.
fn sp800_108(method: u32, base: const Object&, cp: const CryptoParams&, data: const u8[:], iv: const u8[:], n: i64, out: u8[>..]&) -> u32 {
    var lbits: u8[>..] = [];
    be32(lbits, (n * 8) as! u32);
    var prev: u8[>..] = [];
    prev.append(iv);
    var a: u8[>..] = [];
    if method == DERIVE_NIST800_108_DPI { a.append(data); a.append(lbits); }
    var i: u32 = 1;
    while out.len < n {
        var msg: u8[>..] = [];
        if method == DERIVE_NIST800_108_F { msg.append(prev); }
        if method == DERIVE_NIST800_108_DPI {
            var na: u8[>..] = [];
            let r = kdf_prf(base, cp, a, na);
            if r != 0 { return r; }
            a.clear();
            a.append(na);
            msg.append(a);
        }
        be32(msg, i);
        msg.append(data);
        msg.append(lbits);
        var blk: u8[>..] = [];
        let r = kdf_prf(base, cp, msg, blk);
        if r != 0 { return r; }
        out.append(blk);
        prev.clear();
        prev.append(blk);
        i++;
        if i > 0xFFFF { return REASON_INVALID_FIELD; }
    }
    out.resize(n, 0);
    return 0;
}

fn op_derive_key(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let t, tok = child_enum(buf, doc, p, TAG_OBJECT_TYPE);
    if !tok || (t != OBJ_SYMMETRIC_KEY && t != OBJ_SECRET_DATA) { return fail(REASON_INVALID_OBJECT_TYPE, "Derive Key makes symmetric keys and secret data"); }
    let method, mok = child_enum(buf, doc, p, TAG_DERIVATION_METHOD);
    if !mok { return fail(REASON_INVALID_MESSAGE, "no Derivation Method"); }
    let dp = child(doc, p, TAG_DERIVATION_PARAMETERS);
    if !is_type(doc, dp, STRUCTURE) { return fail(REASON_INVALID_MESSAGE, "no Derivation Parameters"); }
    var cp = CryptoParams { .. };
    let cpi = child(doc, dp, TAG_CRYPTOGRAPHIC_PARAMETERS);
    if cpi >= 0 { let c, cok = read_crypto_params(buf, doc, cpi); if !cok { return fail(REASON_INVALID_FIELD, "Cryptographic Parameters not read"); } cp = c; }
    var data: u8[>..] = [];
    var has_data = false;
    each(doc, dp) { k => if doc[k].tag == TAG_DERIVATION_DATA { let d, ok = as_bytes(buf, doc, k); if ok { data.append(d); has_data = true; } } };
    let iv, ivok = child_bytes(buf, doc, dp, TAG_INITIALIZATION_VECTOR);
    let salt, sok = child_bytes(buf, doc, dp, TAG_SALT);
    let iter, iok = child_int(buf, doc, dp, TAG_ITERATION_COUNT);
    var a = payload_attrs(buf, doc, p, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    apply_defaults(s, t, a);
    let cr = check_constraints(s, t, a);
    if cr.reason != 0 { return cr; }

    let bits, lok = get_int(a, TAG_CRYPTOGRAPHIC_LENGTH);
    let alg, aok = get_enum(a, TAG_CRYPTOGRAPHIC_ALGORITHM);
    if !lok || bits <= 0 || bits % 8 != 0 || bits > 8192 { return fail(REASON_INVALID_FIELD, "a Cryptographic Length of whole bytes, to 8192 bits"); }
    if t == OBJ_SYMMETRIC_KEY && !aok { return fail(REASON_INVALID_FIELD, "a derived key needs a Cryptographic Algorithm"); }
    let n: i64 = bits / 8;
    // The objects derived from: the first is the key; a Secret Data after
    // it gives the derivation data (an ECDH peer is the other key).
    var uids: u8[..64][>..] = [];
    each(doc, p) { k => if doc[k].tag == TAG_UNIQUE_IDENTIFIER { let u, ok = as_text(buf, doc, k); if ok && u.len <= 64 { var x: u8[..64] = []; x.append(u); uids.push(x); } } };
    if uids.len == 0 { return fail(REASON_INVALID_MESSAGE, "no Unique Identifier to derive from"); }
    var base = new_object(0);
    var peer = new_object(0);
    var first = true;
    for u in uids {
        var i: i64 = -1;
        let r = usable(s, owner, u, USAGE_DERIVE_KEY, i);
        if r.reason != 0 {
            // An ECDH peer's public key needs no Derive Key bit.
            let j = find_object(s, owner, u);
            if first || j < 0 || s.objects[j].obj_type != OBJ_PUBLIC_KEY { return r; }
            i = j;
        }
        let o, ok = object_of(s.objects[i]);
        if !ok || o.wrapped { return fail(REASON_KEY_VALUE_NOT_PRESENT, "a base object's value is not here"); }
        if first { base = copy(o); first = false; }
        else if o.obj_type == OBJ_SECRET_DATA && method != DERIVE_ASYMMETRIC_KEY {
            if has_data { return fail(REASON_INVALID_FIELD, "Derivation Data both given and named"); }
            data.append(o.material);
            has_data = true;
        } else { peer = copy(o); }
    }
    var key: u8[>..] = [];
    var r: u32 = 0;
    if method == DERIVE_PBKDF2 {
        if !sok || !iok || iter < 1 { return fail(REASON_INVALID_FIELD, "PBKDF2 needs a Salt and an Iteration Count"); }
        let h = hash_id(if cp.hash != 0 { cp.hash } else { HASH_SHA_1 });
        if h == 0 || h == 128 { return fail(REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, "a PRF hash not done here"); }
        // At most 200000 rounds in all, over every block of output (a
        // second or two here): one request is not to hold the server.
        let blocks = (n + bignum::hash_len(h) - 1) / bignum::hash_len(h);
        if iter as i64 * blocks > 200000 { return fail(REASON_INVALID_FIELD, "PBKDF2 of more than 200000 rounds in all"); }
        key = bignum::pbkdf2(h, base.material, salt, iter, n);
    } else if method == DERIVE_HASH {
        let h = hash_id(cp.hash);
        if h == 0 { return fail(REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, "HASH needs a Hashing Algorithm"); }
        var m: u8[>..] = [];
        m.append(base.material);
        m.append(data);
        key = bignum::hash_bits(h, m);
    } else if method == DERIVE_HMAC {
        if !has_data { return fail(REASON_INVALID_MESSAGE, "HMAC needs Derivation Data"); }
        var h = hmac_bits(base.alg);
        if h == 0 { h = hash_id(if cp.hash != 0 { cp.hash } else { HASH_SHA_256 }); }
        if h == 0 { return fail(REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, "an HMAC hash not done here"); }
        key = bignum::hmac(h, base.material, data);
    } else if method == DERIVE_ENCRYPT {
        if !has_data { return fail(REASON_INVALID_MESSAGE, "ENCRYPT needs Derivation Data"); }
        var sy = sym();
        if ivok { if iv.len > 64 { return fail(REASON_INVALID_FIELD, "an IV of more than 64 bytes"); } sy.iv.append(iv); }
        var p2 = cp;
        if p2.padding == 0 { p2.padding = PAD_NONE; }
        var tag: u8[>..] = [];
        r = sym_crypt(base, p2, true, data, sy, tag, key);
    } else if method == DERIVE_NIST800_108_C || method == DERIVE_NIST800_108_F || method == DERIVE_NIST800_108_DPI {
        if !has_data { return fail(REASON_INVALID_MESSAGE, "SP 800-108 needs Derivation Data"); }
        r = sp800_108(method, base, cp, data, if ivok { iv } else { "" }, n, key);
    } else if method == DERIVE_HKDF {
        let h = hash_id(if cp.hash != 0 { cp.hash } else { HASH_SHA_256 });
        if h == 0 || h == 128 { return fail(REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, "a hash not done here"); }
        if n > 255 * bignum::hash_len(h) { return fail(REASON_INVALID_FIELD, "longer than HKDF gives"); }
        key = bignum::hkdf(h, if sok { salt } else { "" }, base.material, data, n);
    } else if method == DERIVE_ASYMMETRIC_KEY {
        // ECDH: the private key and the peer's public key.
        var pv = copy(base);
        var pb = copy(peer);
        if pv.obj_type == OBJ_PUBLIC_KEY { pv = copy(peer); pb = copy(base); }
        if pv.obj_type != OBJ_PRIVATE_KEY || pb.obj_type != OBJ_PUBLIC_KEY { return fail(REASON_INVALID_OBJECT_TYPE, "ECDH takes a private key and a public key"); }
        let k, kok = private_of(pv);
        if !kok || !x509::is_ec(k.kind) { return fail(REASON_INVALID_OBJECT_TYPE, "ECDH takes EC keys"); }
        let spki, pok = spki_of_object(pb);
        let pt, ptok = point_of(spki);
        if !pok || !ptok { return fail(REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED, "the public key is not read"); }
        let curve = x509::curve_of_key(k.kind);
        let z, zok = bignum::ecdh_shared(curve, k.ec_sk, pt);
        if !zok { return fail(REASON_CRYPTOGRAPHIC_FAILURE, "the public key is not on the curve"); }
        key.append(z);
    } else {
        return fail(REASON_FEATURE_NOT_SUPPORTED, "a Derivation Method not done here");
    }
    if r != 0 { return fail(r, "the derivation failed"); }
    if key.len < n { return fail(REASON_INVALID_FIELD, "longer than the derivation gives"); }
    key.resize(n, 0);
    let o = if t == OBJ_SYMMETRIC_KEY { symmetric_key(alg, key) } else { secret_data(SECRET_SEED, key) };
    var uid: u8[>..] = [];
    let ar = add_object(s, owner, o, a, uid);
    if ar.reason != 0 { return ar; }
    for u in uids {
        let bi = find_object(s, owner, u);
        if bi >= 0 { var ba = attrs_of(s.objects[bi]); attr_link(ba, LINK_DERIVED_KEY, uid); let ok = set_attrs(s.objects[bi], ba); }
    }
    let ni = find_object(s, owner, uid);
    if ni >= 0 {
        var na = attrs_of(s.objects[ni]);
        for u in uids { attr_link(na, LINK_DERIVATION_BASE_OBJECT, u); }
        let ok = set_attrs(s.objects[ni], na);
    }
    put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    return done();
}

// The point of an EC SubjectPublicKeyInfo.
fn point_of(spki: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let t, ok = asn1::parse(spki);
    if !ok { return out, false; }
    let kind, key, kok = x509::spki_of(spki, t);
    if !kok || !x509::is_ec(kind) { return out, false; }
    let bits, unused, bok = asn1::read_bits(spki, key);
    if !bok { return out, false; }
    out.append(bits);
    return out, true;
}

// --- Check, leases and usage --------------------------------------------------------

// The remaining count of an object's Usage Limits, and whether it has any.
fn usage_left(a: const Attrs&) -> i64, bool {
    let ul = find_attr(a, TAG_USAGE_LIMITS, 0);
    if ul.len == 0 { return 0, false; }
    var doc: Node[>..] = [];
    let r, e = decode(ul, Options { .. }, doc);
    if e != OK { return 0, false; }
    let c, cok = child_long(ul, doc, r, TAG_USAGE_LIMITS_COUNT);
    return c, cok;
}

fn set_usage_left(a: Attrs&, left: i64) {
    let ul = find_attr(a, TAG_USAGE_LIMITS, 0);
    var doc: Node[>..] = [];
    let r, e = decode(ul, Options { .. }, doc);
    let total, tok = child_long(ul, doc, r, TAG_USAGE_LIMITS_TOTAL);
    let unit, uok = child_enum(ul, doc, r, TAG_USAGE_LIMITS_UNIT);
    var item: u8[>..] = [];
    let s = begin(item, TAG_USAGE_LIMITS);
    put_long(item, TAG_USAGE_LIMITS_TOTAL, total);
    put_long(item, TAG_USAGE_LIMITS_COUNT, left);
    put_enum(item, TAG_USAGE_LIMITS_UNIT, unit);
    end(item, s);
    set_single(a, item);
}

fn op_check(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { s.batch_ids[UID_ID_PLACEHOLDER].clear(); return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let a = attrs_of(s.objects[i]);
    let want_mask, mok = child_int(buf, doc, p, TAG_CRYPTOGRAPHIC_USAGE_MASK);
    let want_count, cok = child_long(buf, doc, p, TAG_USAGE_LIMITS_COUNT);
    let want_lease, lok = as_interval(buf, doc, child(doc, p, TAG_LEASE_TIME));
    if mok {
        let m, hok = get_int(a, TAG_CRYPTOGRAPHIC_USAGE_MASK);
        if !hok || ((want_mask as! u32) & ~(m as! u32)) != 0 {
            s.batch_ids[UID_ID_PLACEHOLDER].clear();
            return fail(REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK, "Check Failed");
        }
    }
    if cok {
        let left, has = usage_left(a);
        if has && want_count > left { s.batch_ids[UID_ID_PLACEHOLDER].clear(); return fail(REASON_USAGE_LIMIT_EXCEEDED, "Check Failed"); }
    }
    if lok {
        let have, hok = get_interval(a, TAG_LEASE_TIME);
        if hok && have != 0 && want_lease > have { s.batch_ids[UID_ID_PLACEHOLDER].clear(); return fail(REASON_PERMISSION_DENIED, "Check Failed"); }
    }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    return done();
}

fn op_obtain_lease(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let a = attrs_of(s.objects[i]);
    let lease, lok = get_interval(a, TAG_LEASE_TIME);
    let changed, cok = get_datetime(a, TAG_LAST_CHANGE_DATE);
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    put_interval(out, TAG_LEASE_TIME, if lok { lease } else { 0 });
    put_datetime(out, TAG_LAST_CHANGE_DATE, if cok { changed } else { now_of(s) });
    return done();
}

fn op_get_usage_allocation(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let want, wok = child_long(buf, doc, p, TAG_USAGE_LIMITS_COUNT);
    if !wok || want < 0 { return fail(REASON_INVALID_MESSAGE, "no Usage Limits Count"); }
    var a = attrs_of(s.objects[i]);
    let left, has = usage_left(a);
    if has {
        if want > left { return fail(REASON_USAGE_LIMIT_EXCEEDED, "more than the object's usage limits leave"); }
        set_usage_left(a, left - want);
        if !set_attrs(s.objects[i], a) { return fail(REASON_SERVER_LIMIT_EXCEEDED, "the object is too large"); }
    }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    return done();
}

// --- Archive and Recover -------------------------------------------------------

fn op_archive(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&, archive: bool) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    if archive {
        if s.objects[i].archived { return fail(REASON_OBJECT_ARCHIVED, "the object is archived"); }
        var a = attrs_of(s.objects[i]);
        let d = item_of_date(TAG_ARCHIVE_DATE, now_of(s));
        set_single(a, d);
        let ok = set_attrs(s.objects[i], a);
    }
    s.objects[i].archived = archive;
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    return done();
}

// --- Import ---------------------------------------------------------------------

// Import: the object stored under the Unique Identifier and with the
// attributes given, as they are (State and dates included).
fn op_import(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let uid, uok = child_text(buf, doc, p, TAG_UNIQUE_IDENTIFIER);
    if !uok || uid.len == 0 || uid.len > 64 { return fail(REASON_INVALID_MESSAGE, "no Unique Identifier"); }
    let t, tok = child_enum(buf, doc, p, TAG_OBJECT_TYPE);
    if !tok { return fail(REASON_INVALID_MESSAGE, "no Object Type"); }
    let replace, rok = child_bool(buf, doc, p, TAG_REPLACE_EXISTING);
    let kwt, kwtok = child_enum(buf, doc, p, TAG_KEY_WRAP_TYPE);
    var o, ok = read_object(buf, doc, p, t);
    if !ok { return fail(REASON_INVALID_FIELD, "no object of that type, or not one this server keeps"); }
    if o.wrapped && kwtok && kwt == KEY_WRAP_NOT_WRAPPED {
        var plain = new_object(0);
        let r = unwrap_stored(s, owner, o, plain);
        if r.reason != 0 { return r; }
        o = copy(plain);
    }
    let a = payload_attrs(buf, doc, p, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    // Any object with that identifier, whoever has it.
    var at: i64 = -1;
    for k in s.objects.len { if at < 0 && s.objects[k].obj_type != 0 && s.objects[k].uid[..] == uid { at = k; } }
    if at >= 0 {
        if !(rok && replace) { return fail(REASON_OBJECT_ALREADY_EXISTS, "an object has that identifier"); }
        if s.objects[at].owner[..] != owner { return fail(REASON_PERMISSION_DENIED, "another client's object"); }
    } else if s.live >= s.max_objects {
        return fail(REASON_SERVER_LIMIT_EXCEEDED, "the store is full");
    }
    var obj: u8[>..] = [];
    if !put_object(obj, o) { return fail(REASON_INVALID_OBJECT_TYPE, "an object type not kept here"); }
    var all = attrs();
    each_attr(a) { tag, item => if tag != TAG_UNIQUE_IDENTIFIER && tag != TAG_OBJECT_TYPE { all.enc.append(item); } };
    attr_text(all, TAG_UNIQUE_IDENTIFIER, uid);
    attr_enum(all, TAG_OBJECT_TYPE, t);
    let st, sok = get_enum(all, TAG_STATE);
    if !sok { attr_enum(all, TAG_STATE, STATE_PRE_ACTIVE); }
    var m = Managed { uid: [], obj_type: t, state: if sok { st } else { STATE_PRE_ACTIVE }, owner: [], archived: false, enc: [] };
    m.uid.append(uid);
    m.owner.append(owner[..::min(owner.len, 128)]);
    if !store_into(m, obj, all) { return fail(REASON_SERVER_LIMIT_EXCEEDED, "the object is too large"); }
    if at >= 0 { s.objects[at] = m; }
    else {
        var slot = -1;
        for k in s.objects.len { if slot < 0 && s.objects[k].obj_type == 0 { slot = k; } }
        if slot >= 0 { s.objects[slot] = m; } else { s.objects.push(m); }
        s.live++;
    }
    put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    return done();
}

// --- Adjust Attribute, Interop ---------------------------------------------------

fn op_adjust_attribute(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let ref = child(doc, p, TAG_ATTRIBUTE_REFERENCE);
    if ref < 0 { return fail(REASON_INVALID_MESSAGE, "no Attribute Reference"); }
    let tag = reference_tag(buf, doc, ref);
    let how, hok = child_enum(buf, doc, p, TAG_ADJUSTMENT_TYPE);
    if tag == 0 || !hok { return fail(REASON_INVALID_FIELD, "no attribute or Adjustment Type"); }
    if server_only(tag) { return fail(REASON_READ_ONLY_ATTRIBUTE, "the server sets that attribute"); }
    var a = attrs_of(s.objects[i]);
    if multi_valued(tag) || (has_attr(a, tag) && find_attr(a, tag, 1).len > 0) { return fail(REASON_MULTI_VALUED_ATTRIBUTE, "an attribute with more than one value"); }
    let cur = find_attr(a, tag, 0);
    let by = child(doc, p, TAG_ADJUSTMENT_VALUE);
    var typ: u8 = 0;
    var x: i64 = 0;
    if cur.len >= 8 {
        typ = cur[3];
        if typ == INTEGER || typ == INTERVAL { x = binary::u32be(cur, 8); if typ == INTEGER { x = x as! u32 as! i32; } }
        else if typ == LONG_INTEGER || typ == DATE_TIME { x = binary::u64be(cur, 8) as! i64; }
        else if typ == BOOLEAN { x = if binary::u64be(cur, 8) != 0 { 1 } else { 0 }; }
        else { return fail(REASON_INVALID_DATA_TYPE, "an attribute that is not a number"); }
    } else if by >= 0 {
        typ = doc[by].typ;
    } else {
        return fail(REASON_INVALID_FIELD, "nothing to adjust");
    }
    var d: i64 = 0;
    if by >= 0 {
        let bt = doc[by].typ;
        if bt == INTEGER { let y, ok = as_int(buf, doc, by); d = y; }
        else if bt == LONG_INTEGER { let y, ok = as_long(buf, doc, by); d = y; }
        else if bt == INTERVAL { let y, ok = as_interval(buf, doc, by); d = y; }
        else { return fail(REASON_INVALID_DATA_TYPE, "an Adjustment Value that is not a number"); }
    }
    if how == ADJUST_INCREMENT { x = x + d; }
    else if how == ADJUST_DECREMENT { x = x - d; }
    else if how == ADJUST_NEGATE { x = if typ == BOOLEAN { 1 - x } else { 0 - x }; }
    else { return fail(REASON_INVALID_FIELD, "an Adjustment Type not known"); }
    var item: u8[>..] = [];
    if typ == INTEGER { if x < -2147483648 || x > 2147483647 { return fail(REASON_NUMERIC_RANGE, "out of an Integer's range"); } put_int(item, tag, x as! i32); }
    else if typ == INTERVAL { if x < 0 || x > 4294967295 { return fail(REASON_NUMERIC_RANGE, "out of an Interval's range"); } put_interval(item, tag, x as! u32); }
    else if typ == LONG_INTEGER { put_long(item, tag, x); }
    else if typ == DATE_TIME { put_datetime(item, tag, x); }
    else if typ == BOOLEAN { put_bool(item, tag, x != 0); }
    else { return fail(REASON_INVALID_DATA_TYPE, "an attribute that is not a number"); }
    set_single(a, item);
    if !set_attrs(s.objects[i], a) { return fail(REASON_SERVER_LIMIT_EXCEEDED, "the object is too large"); }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    return done();
}

// Interop (2.0): the bounds of a test case the client runs; nothing to do.
fn op_interop(buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    if p >= 0 {
        let f, fok = child_enum(buf, doc, p, TAG_INTEROP_FUNCTION);
        if fok && f != INTEROP_BEGIN && f != INTEROP_END && f != INTEROP_RESET { return fail(REASON_INVALID_FIELD, "an Interop Function not known"); }
    }
    return done();
}
