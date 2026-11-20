// kmip.server_manage: the server's operations on objects and their
// attributes: Discover Versions and Query, Create, Create Key Pair,
// Register, Get, the attribute operations, Locate and the life cycle.

namespace kmip;

import std;
import os;
import binary;
import entropy;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;
import kmip.server;
import kmip.formats;
import kmip.crypto;
import kmip.wrap;
import crypto.bignum;
import crypto.bignum.aes;
import crypto.bignum.modes;
import crypto.bignum.gcm;
import crypto.bignum.hmac;
import crypto.x509;
import crypto.x509.keys;
import encoding.asn1;

// --- Operations -----------------------------------------------------------------

fn op_discover(buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    var asked = false;
    var pv = child(doc, p, TAG_PROTOCOL_VERSION);
    while pv >= 0 {
        asked = true;
        let v, ok = read_version(buf, doc, pv);
        if ok {
            for mine in SUPPORTED { if version_eq(v, mine) { put_version(out, v); } }
        }
        pv = next_same(doc, pv);
    }
    if !asked { for v in SUPPORTED { put_version(out, v); } }
    return done();
}

fn op_query(s: const Server&, v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    var ops = false;
    var objs = false;
    var info = false;
    each(doc, p) { k =>
        let f, ok = as_enum(buf, doc, k);
        if ok && doc[k].tag == TAG_QUERY_FUNCTION {
            if f == QUERY_OPERATIONS { ops = true; }
            if f == QUERY_OBJECTS { objs = true; }
            if f == QUERY_SERVER_INFORMATION { info = true; }
        }
    };
    if ops {
        var seen: u32[>..] = [];
        for o in OPERATIONS {
            var dup = false;
            for x in seen { if x == o.op { dup = true; } }
            if !dup && !version_lt(v, o.since) { put_enum(out, TAG_OPERATION, o.op); seen.push(o.op); }
        }
    }
    if objs {
        let types: u32[8] = [OBJ_CERTIFICATE, OBJ_SYMMETRIC_KEY, OBJ_PUBLIC_KEY, OBJ_PRIVATE_KEY, OBJ_SPLIT_KEY, OBJ_SECRET_DATA,
                             OBJ_OPAQUE_DATA, OBJ_CERTIFICATE_REQUEST];
        for t in types { put_enum(out, TAG_OBJECT_TYPE, t); }
    }
    if info { put_text(out, TAG_VENDOR_IDENTIFICATION, s.vendor); }
    return done();
}

fn new_key_bytes(n: i64) -> u8[>..] {
    var k: u8[>..] = [];
    k.resize(n, 0);
    entropy::random_bytes(k);
    return k;
}

fn op_create(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let t, tok = child_enum(buf, doc, p, TAG_OBJECT_TYPE);
    if !tok { return fail(REASON_INVALID_MESSAGE, "no Object Type"); }
    var a = payload_attrs(buf, doc, p, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    apply_defaults(s, t, a);
    let cr = check_constraints(s, t, a);
    if cr.reason != 0 { return cr; }
    var o = new_object(t);
    if t == OBJ_SYMMETRIC_KEY {
        let alg, aok = get_enum(a, TAG_CRYPTOGRAPHIC_ALGORITHM);
        let bits, lok = get_int(a, TAG_CRYPTOGRAPHIC_LENGTH);
        if !aok || !lok { return fail(REASON_INVALID_FIELD, "a key needs a Cryptographic Algorithm and Length"); }
        if alg == ALG_AES {
            if bits != 128 && bits != 192 && bits != 256 { return fail(REASON_INVALID_FIELD, "AES keys are 128, 192 or 256 bits"); }
        } else if hmac_bits(alg) != 0 {
            if bits < 8 || bits > 4096 || bits % 8 != 0 { return fail(REASON_INVALID_FIELD, "an HMAC key of whole bytes, up to 4096 bits"); }
        } else if alg == ALG_TRIPLE_DES {
            if bits != 112 && bits != 168 && bits != 128 && bits != 192 { return fail(REASON_INVALID_FIELD, "Triple DES keys are 112 or 168 bits (128 or 192 with parity)"); }
        } else if alg == ALG_CHACHA20 || alg == ALG_CHACHA20_POLY1305 {
            if bits != 256 { return fail(REASON_INVALID_FIELD, "ChaCha20 keys are 256 bits"); }
        } else {
            return fail(REASON_INVALID_FIELD, "symmetric keys made here are AES, Triple DES, ChaCha20 and HMAC");
        }
        // Triple DES: 112 and 168 effective bits are two or three DES keys,
        // 8 bytes each with their parity bits.
        let nbytes: i64 = if alg == ALG_TRIPLE_DES { if bits == 112 || bits == 128 { 16 } else { 24 } } else { bits / 8 };
        var k = new_key_bytes(nbytes);
        if alg == ALG_TRIPLE_DES { for j in k.len { let b = k[j] & 0xfe; k[j] = b | ((popcount(b) & 1) ^ 1) as! u8; } }
        o = symmetric_key(alg, k);
        o.length = bits;
    } else if t == OBJ_SECRET_DATA {
        // As long as the Cryptographic Length says (256 bits by default),
        // a Password (TC-CREATE-SD-1).
        let bits, lok = get_int(a, TAG_CRYPTOGRAPHIC_LENGTH);
        if lok && (bits < 8 || bits > 8192 || bits % 8 != 0) { return fail(REASON_INVALID_FIELD, "secret data of whole bytes, up to 8192 bits"); }
        let k = new_key_bytes(if lok { bits / 8 } else { 32 });
        o = secret_data(SECRET_PASSWORD, k);
    } else {
        return fail(REASON_INVALID_OBJECT_TYPE, "Create makes symmetric keys and secret data");
    }
    var uid: u8[>..] = [];
    generated(s, a);
    let r = add_object(s, owner, o, a, uid);
    if r.reason != 0 { return r; }
    put_enum(out, TAG_OBJECT_TYPE, t);
    put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    return done();
}

fn link_both(s: Server&, a_uid: const u8[:], a_type: u32, b_uid: const u8[:], owner: const u8[:]) {
    let i = find_object(s, owner, a_uid);
    if i < 0 { return; }
    var a = attrs_of(s.objects[i]);
    attr_link(a, a_type, b_uid);
    let ok = set_attrs(s.objects[i], a);
}

fn op_create_key_pair(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let common = payload_attrs(buf, doc, p, TAG_COMMON_TEMPLATE_ATTRIBUTE, TAG_COMMON_ATTRIBUTES);
    var pa = payload_attrs(buf, doc, p, TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE, TAG_PRIVATE_KEY_ATTRIBUTES);
    var pb = payload_attrs(buf, doc, p, TAG_PUBLIC_KEY_TEMPLATE_ATTRIBUTE, TAG_PUBLIC_KEY_ATTRIBUTES);
    // Set Defaults' and Set Constraints' (2.1), for each key.
    var both1 = attrs();
    both1.enc.append(common.enc);
    both1.enc.append(pa.enc);
    apply_defaults(s, OBJ_PRIVATE_KEY, both1);
    let cr1 = check_constraints(s, OBJ_PRIVATE_KEY, both1);
    if cr1.reason != 0 { return cr1; }
    var both2 = attrs();
    both2.enc.append(common.enc);
    both2.enc.append(pb.enc);
    apply_defaults(s, OBJ_PUBLIC_KEY, both2);
    let cr2 = check_constraints(s, OBJ_PUBLIC_KEY, both2);
    if cr2.reason != 0 { return cr2; }
    var all = attrs();
    all.enc.append(common.enc);
    all.enc.append(pa.enc);
    let alg, aok = get_enum(all, TAG_CRYPTOGRAPHIC_ALGORITHM);
    let bits, lok = get_int(all, TAG_CRYPTOGRAPHIC_LENGTH);
    let curve, cok = get_curve(all);
    if !aok { return fail(REASON_INVALID_FIELD, "a key pair needs a Cryptographic Algorithm"); }
    var kind = x509::KEY_UNKNOWN;
    var length: i32 = 0;
    if alg == ALG_RSA {
        if !lok || (bits != 2048 && bits != 3072 && bits != 4096) { return fail(REASON_INVALID_FIELD, "RSA keys are 2048, 3072 or 4096 bits"); }
        kind = x509::KEY_RSA;
        length = bits;
    } else if alg == ALG_EC || alg == ALG_ECDSA || alg == ALG_ECDH {
        if cok { kind = kind_of_curve(curve); }
        else if lok && bits == 256 { kind = x509::KEY_EC_P256; }
        else if lok && bits == 384 { kind = x509::KEY_EC_P384; }
        else if lok && bits == 521 { kind = x509::KEY_EC_P521; }
        if kind == x509::KEY_UNKNOWN { return fail(REASON_INVALID_FIELD, "EC keys are on P-224, P-256, P-384, P-521, secp256k1 or brainpoolP256r1, P384r1 and P512r1"); }
        length = x509::curve_of_key(kind).bits as! i32;
    } else {
        return fail(REASON_INVALID_FIELD, "key pairs made here are RSA and EC");
    }
    let k = x509::generate_key(kind, length);
    let po, pu = pair_objects(k, alg, length);
    var a1 = attrs();
    a1.enc.append(common.enc);
    a1.enc.append(pa.enc);
    var a2 = attrs();
    a2.enc.append(common.enc);
    a2.enc.append(pb.enc);
    generated(s, a1);
    generated(s, a2);
    var u1: u8[>..] = [];
    let r1 = add_object(s, owner, po, a1, u1);
    if r1.reason != 0 { return r1; }
    var u2: u8[>..] = [];
    let r2 = add_object(s, owner, pu, a2, u2);
    if r2.reason != 0 { return r2; }
    link_both(s, u1, LINK_PUBLIC_KEY, u2, owner);
    link_both(s, u2, LINK_PRIVATE_KEY, u1, owner);
    put_text(out, TAG_PRIVATE_KEY_UNIQUE_IDENTIFIER, u1);
    put_text(out, TAG_PUBLIC_KEY_UNIQUE_IDENTIFIER, u2);
    return done();
}

fn op_register(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let t, tok = child_enum(buf, doc, p, TAG_OBJECT_TYPE);
    if !tok { return fail(REASON_INVALID_MESSAGE, "no Object Type"); }
    let o, ok = read_object(buf, doc, p, t);
    if !ok { return fail(REASON_INVALID_FIELD, "no object of that type, or not one this server keeps"); }
    var a = payload_attrs(buf, doc, p, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    apply_defaults(s, t, a);
    let cr = check_constraints(s, t, a);
    if cr.reason != 0 { return cr; }
    var uid: u8[>..] = [];
    if o.obj_type == OBJ_PRIVATE_KEY && o.key_format == FMT_PKCS_12 && !o.wrapped {
        let rp = register_pkcs12(s, owner, v, o, a, uid);
        if rp.reason != 0 { return rp; }
        put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
        return done();
    }
    var sa = attrs();
    if o.obj_type == OBJ_CERTIFICATE && !cert_attrs(o.material, v, sa) { return fail(REASON_INVALID_FIELD, "the certificate is not read"); }
    let r = add_object_with(s, owner, o, a, sa, uid);
    if r.reason != 0 { return r; }
    put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    return done();
}

// A key that wraps or unwraps another: the owner's, with the usage; its
// Cryptographic Parameters attribute, when it has one. A key retired from
// protecting (Deactivated, Compromised, past its Protect Stop Date) wraps
// nothing new, and one destroyed, or before its Process Start Date,
// unwraps nothing. Pre-Active keys are taken, as clients commonly wrap
// with a key they never activated.
fn wrapping_key(s: const Server&, owner: const u8[:], uid: const u8[:], usage: u32, k: Object&, own: CryptoParams&,
                has_own: bool&) -> Outcome {
    let i = find_object(s, owner, uid);
    if i < 0 { return fail(REASON_WRAPPING_OBJECT_NOT_FOUND, "no such wrapping key"); }
    let a = attrs_of(s.objects[i]);
    let st = s.objects[i].state;
    let now = now_of(s);
    if st == STATE_DESTROYED || st == STATE_DESTROYED_COMPROMISED {
        return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "the wrapping key is destroyed");
    }
    if (usage & USAGE_WRAP_KEY) != 0 {
        let stop, sok = get_datetime(a, TAG_PROTECT_STOP_DATE);
        if st == STATE_DEACTIVATED || st == STATE_COMPROMISED || (sok && stop <= now) {
            return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "the wrapping key no longer protects");
        }
    } else {
        let start, pok = get_datetime(a, TAG_PROCESS_START_DATE);
        if pok && start > now { return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "the unwrapping key is before its Process Start Date"); }
    }
    let m, mok = get_int(a, TAG_CRYPTOGRAPHIC_USAGE_MASK);
    if !mok || ((m as! u32) & usage) == 0 { return fail(REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK, "the wrapping key's usage mask does not allow it"); }
    var ok = false;
    k, ok = object_of(s.objects[i]);
    if !ok { return fail(REASON_GENERAL_FAILURE, "the wrapping key is not readable"); }
    let item = find_attr(a, TAG_CRYPTOGRAPHIC_PARAMETERS, 0);
    has_own = false;
    if item.len > 0 {
        var pok = false;
        own, pok = crypto_params_of_item(item);
        has_own = pok;
    }
    return done();
}

// Parameters a Key Wrapping Specification gives must be among the key's
// own (7.18).
fn params_match(s: const Server&, owner: const u8[:], ki: const KeyInfo&) -> bool {
    if !ki.has_params { return true; }
    let i = find_object(s, owner, ki.uid);
    if i < 0 { return false; }
    let a = attrs_of(s.objects[i]);
    var found = false;
    each_attr(a) { t, item =>
        if t == TAG_CRYPTOGRAPHIC_PARAMETERS {
            let cp, ok = crypto_params_of_item(item);
            let w = ki.params;
            if ok && (w.mode == 0 || w.mode == cp.mode) && (w.padding == 0 || w.padding == cp.padding) &&
               (w.hash == 0 || w.hash == cp.hash) && (w.alg == 0 || w.alg == cp.alg) &&
               (w.mgf_hash == 0 || w.mgf_hash == cp.mgf_hash) { found = true; }
        }
    };
    return found;
}

// The object of a wrapped one, unwrapped with the server's keys its Key
// Wrapping Data names.
fn unwrap_stored(s: const Server&, owner: const u8[:], o: const Object&, plain: Object&) -> Outcome {
    let w, ok = wrapping_of(o);
    if !ok { return fail(REASON_INVALID_FIELD, "the Key Wrapping Data is not read"); }
    var ek = new_object(0);
    var mk = new_object(0);
    var ecp = CryptoParams { .. };
    var mcp = CryptoParams { .. };
    var he = false;
    var hm = false;
    if w.has_enc {
        // Unwrap Key, or Wrap Key as 1.4's cases have the key that wrapped it.
        let r = wrapping_key(s, owner, w.enc.uid, USAGE_UNWRAP_KEY | USAGE_WRAP_KEY, ek, ecp, he);
        if r.reason != 0 { return r; }
    }
    if w.has_mac {
        let r = wrapping_key(s, owner, w.mac.uid, USAGE_VERIFY | USAGE_MAC_VERIFY | USAGE_UNWRAP_KEY, mk, mcp, hm);
        if r.reason != 0 { return r; }
    }
    var a = attrs();
    var e: u32 = 0;
    plain, e = unwrap_object(o, ek, ecp, he, mk, mcp, hm, a);
    if e != 0 { return fail(e, "the key does not unwrap"); }
    return done();
}

// Get, and with exporting 1.4's Export: the object with all its attributes.
fn op_get(s: const Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&,
          exporting: bool) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let dst = s.objects[i].state;
    if dst == STATE_DESTROYED || dst == STATE_DESTROYED_COMPROMISED {
        return fail(if is_v2(v) { REASON_OBJECT_DESTROYED } else { REASON_ITEM_NOT_FOUND }, "the object is destroyed");
    }
    var o, ok = object_of(s.objects[i]);
    if !ok { return fail(REASON_GENERAL_FAILURE, "the object is not readable"); }
    let a = attrs_of(s.objects[i]);
    let f, fok = child_enum(buf, doc, p, TAG_KEY_FORMAT_TYPE);
    let kwt, kwtok = child_enum(buf, doc, p, TAG_KEY_WRAP_TYPE);
    let kc, kcok = child_enum(buf, doc, p, TAG_KEY_COMPRESSION_TYPE);
    let ks = child(doc, p, TAG_KEY_WRAPPING_SPECIFICATION);
    if kwtok && kwt != KEY_WRAP_NOT_WRAPPED && kwt != KEY_WRAP_AS_REGISTERED { return fail(REASON_KEY_WRAP_TYPE_NOT_SUPPORTED, "an unknown Key Wrap Type"); }
    if kcok && kc != COMPRESS_EC_PUBLIC_KEY_TYPE_UNCOMPRESSED { return fail(REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED, "EC public keys are given uncompressed"); }
    let is_key = o.obj_type == OBJ_SYMMETRIC_KEY || o.obj_type == OBJ_PRIVATE_KEY || o.obj_type == OBJ_PUBLIC_KEY ||
                 o.obj_type == OBJ_SECRET_DATA || o.obj_type == OBJ_SPLIT_KEY;
    let ext, eok = get_bool(a, TAG_EXTRACTABLE);
    if is_key && eok && !ext { return fail(REASON_NOT_EXTRACTABLE, "the object is not extractable"); }
    // A key registered wrapped is given as it was, unless asked unwrapped
    // or wrapped again.
    if o.wrapped && ((kwtok && kwt == KEY_WRAP_NOT_WRAPPED) || ks >= 0) {
        var plain = new_object(0);
        let r = unwrap_stored(s, owner, o, plain);
        if r.reason != 0 { return r; }
        o = copy(plain);
    }
    if fok && f == FMT_PKCS_12 && o.obj_type == OBJ_PRIVATE_KEY && o.key_format != FMT_PKCS_12 {
        let c, r = pkcs12_of(s, owner, o, a);
        if r.reason != 0 { return r; }
        o = copy(c);
    } else if fok && f != o.key_format {
        let c, reason = convert_key(o, f);
        if reason != 0 { return fail(reason, "the key does not go into that format"); }
        o = copy(c);
    }
    if ks >= 0 {
        if !is_key { return fail(REASON_INVALID_OBJECT_TYPE, "only keys and secrets are wrapped"); }
        let w, wok = read_wrapping(buf, doc, ks);
        if !wok { return fail(REASON_INVALID_FIELD, "the Key Wrapping Specification is not read"); }
        if !params_match(s, owner, w.enc) || !params_match(s, owner, w.mac) {
            return fail(REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, "parameters not among the wrapping key's");
        }
        var ek = new_object(0);
        var mk = new_object(0);
        var ecp = CryptoParams { .. };
        var mcp = CryptoParams { .. };
        var he = false;
        var hm = false;
        if w.has_enc {
            let r = wrapping_key(s, owner, w.enc.uid, USAGE_WRAP_KEY, ek, ecp, he);
            if r.reason != 0 { return r; }
        }
        if w.has_mac {
            let r = wrapping_key(s, owner, w.mac.uid, USAGE_SIGN | USAGE_MAC_GENERATE | USAGE_WRAP_KEY, mk, mcp, hm);
            if r.reason != 0 { return r; }
        }
        // The attributes asked for go into the wrapped Key Value.
        var wa = attrs();
        var at = 0;
        while at < w.attr_names.len {
            let n = item_len(w.attr_names, at);
            if n < 0 { break; }
            var d: Node[>..] = [];
            let root, de = decode(w.attr_names[at..at + n], Options { .. }, d);
            if de == OK {
                let one = w.attr_names[at..at + n];
                var tag: u32 = 0;
                if d[root].tag == TAG_ATTRIBUTE_NAME { let nm, nok = as_text(one, d, root); if nok { tag = attribute_tag(nm); } }
                else { tag = reference_tag(one, d, root); }
                if tag != 0 { each_attr(a) { t, item => if t == tag { wa.enc.append(item); } }; }
            }
            at += n;
        }
        let wrapped, e = wrap_object(o, w, ek, ecp, he, mk, mcp, hm, wa, v);
        if e != 0 { return fail(e, "the key is not wrapped so"); }
        o = copy(wrapped);
    } else if is_key && !o.wrapped {
        let sens, sok = get_bool(a, TAG_SENSITIVE);
        if sok && sens { return fail(REASON_SENSITIVE, "a sensitive object leaves wrapped only"); }
    }
    put_enum(out, TAG_OBJECT_TYPE, o.obj_type);
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    if exporting { put_attrs_for(out, a, v); }
    if !put_object(out, o) { return fail(REASON_INVALID_OBJECT_TYPE, "an object type not given here"); }
    return done();
}

fn put_attrs_for(out: u8[>..]&, a: const Attrs&, v: Version) {
    if is_v2(v) { put_attributes(out, a, TAG_ATTRIBUTES); return; }
    // 1.x numbers the instances of an attribute (Attribute Index).
    var seen: u32[>..] = [];
    each_attr(a) { t, item =>
        var ix: i32 = 0;
        if t == TAG_ATTRIBUTE {
            // A vendor's attributes are numbered by their name.
            ix = custom_index(a, item);
        } else {
            for x in seen { if x == t { ix++; } }
            seen.push(t);
        }
        let ok = put_attribute_1x_at(out, t, item, ix);
    };
}

fn op_get_attributes(s: const Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let a = attrs_of(s.objects[i]);
    let tags = named_tags(buf, doc, p);
    let customs = named_customs(buf, doc, p);
    var pick = attrs();
    if tags.len == 0 { pick.enc.append(a.enc); }
    else {
        each_attr(a) { t, item =>
            var want = false;
            if t == TAG_ATTRIBUTE {
                let key = custom_key(item);
                for x in customs { if x[..] == key[..] { want = true; } }
            } else {
                for x in tags { if x == t { want = true; } }
            }
            if want { pick.enc.append(item); }
        };
    }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    put_attrs_for(out, pick, v);
    return done();
}

fn op_get_attribute_list(s: const Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let a = attrs_of(s.objects[i]);
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    var seen: u32[>..] = [];
    var seen_custom: u8[..256][>..] = [];
    each_attr(a) { t, item =>
        var dup = false;
        if t == TAG_ATTRIBUTE {
            // A vendor's attribute: by its vendor and name.
            let key = custom_key(item);
            for x in seen_custom { if x[..] == key[..] { dup = true; } }
            if !dup && key.len <= 256 {
                var kk: u8[..256] = [];
                kk.append(key);
                seen_custom.push(kk);
                if is_v2(v) {
                    var d: Node[>..] = [];
                    let r, e = decode(item, Options { .. }, d);
                    let vn, vok = child_text(item, d, r, TAG_VENDOR_IDENTIFICATION);
                    let nm, nok = child_text(item, d, r, TAG_ATTRIBUTE_NAME);
                    let s2 = begin(out, TAG_ATTRIBUTE_REFERENCE);
                    put_text(out, TAG_VENDOR_IDENTIFICATION, if vok { vn } else { "" });
                    put_text(out, TAG_ATTRIBUTE_NAME, if nok { nm } else { "" });
                    end(out, s2);
                } else {
                    put_text(out, TAG_ATTRIBUTE_NAME, key);
                }
            }
            dup = true;
        }
        for x in seen { if x == t { dup = true; } }
        if !dup {
            seen.push(t);
            if is_v2(v) { put_enum(out, TAG_ATTRIBUTE_REFERENCE, t); }
            else { let n = attribute_name(t); if n.len > 0 { put_text(out, TAG_ATTRIBUTE_NAME, n); } }
        }
    };
    return done();
}

// The one attribute a 1.x Attribute or a 2.0 New Attribute (Current
// Attribute) carries, as an item; and the 1.x Attribute Index, 0 if none.
fn one_attribute(buf: const u8[:], doc: const Node[:], p: i64, tag2: u32) -> u8[>..], i64 {
    var item: u8[>..] = [];
    let one = child(doc, p, TAG_ATTRIBUTE);
    if one >= 0 {
        let name, ok = child_text(buf, doc, one, TAG_ATTRIBUTE_NAME);
        let val = child(doc, one, TAG_ATTRIBUTE_VALUE);
        let t = if ok { attribute_tag(name) } else { 0 };
        let ix, iok = child_int(buf, doc, one, TAG_ATTRIBUTE_INDEX);
        if t != 0 && val >= 0 { put_retagged(item, t, raw(buf, doc, val)); }
        else if ok && name.len > 0 && val >= 0 { put_custom(item, name, raw(buf, doc, val)); }
        return item, if iok { ix } else { 0 };
    }
    let n = child(doc, p, tag2);
    if is_type(doc, n, STRUCTURE) && doc[n].count == 1 { item.append(raw(buf, doc, n + 1)); }
    return item, 0;
}

fn echo_attribute(out: u8[>..]&, item: const u8[:], v: Version, index: i64) {
    if !is_v2(v) { let ok = put_attribute_1x_at(out, binary::u32be(item, 0) >> 8, item, index as! i32); }
}

// Which instance of a vendor's attribute (by vendor and name) an item is.
fn custom_index(a: const Attrs&, item: const u8[:]) -> i32 {
    let key = custom_key(item);
    var k: i32 = 0;
    var found: i32 = 0;
    var done_ = false;
    each_attr(a) { tt, it =>
        if tt == TAG_ATTRIBUTE && !done_ && custom_key(it)[..] == key[..] {
            if it == item { found = k; done_ = true; } else { k++; }
        }
    };
    return found;
}

// Which instance of its attribute an item is in a.
fn index_of(a: const Attrs&, item: const u8[:]) -> i64 {
    let t = binary::u32be(item, 0) >> 8;
    if t == TAG_ATTRIBUTE { return custom_index(a, item); }
    var k: i64 = 0;
    var found: i64 = 0;
    each_attr(a) { tt, it => if tt == t { if it == item { found = k; } k++; } };
    return found;
}

// Add Attribute (and 2.0's Set Attribute: single = true replaces).
fn op_add_attribute(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&, set: bool) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let item, ix = one_attribute(buf, doc, p, TAG_NEW_ATTRIBUTE);
    if item.len < 8 { return fail(REASON_INVALID_FIELD, "no attribute, or one not known here"); }
    let t = binary::u32be(item, 0) >> 8;
    if server_only(t) || t == TAG_CRYPTOGRAPHIC_ALGORITHM || t == TAG_CRYPTOGRAPHIC_LENGTH {
        return fail(REASON_READ_ONLY_ATTRIBUTE, "the server sets that attribute");
    }
    let ck = change_ok(s, owner, i, item);
    if ck.reason != 0 { return ck; }
    var a = attrs_of(s.objects[i]);
    if set {
        if multi_valued(t) && find_attr(a, t, 1).len > 0 { return fail(REASON_MULTI_VALUED_ATTRIBUTE, "the object has more than one of that attribute"); }
        set_single(a, item);
    } else {
        if !multi_valued(t) && has_attr(a, t) { return fail(REASON_ATTRIBUTE_SINGLE_VALUED, "the object has that attribute"); }
        a.enc.append(item);
    }
    if !set_attrs(s.objects[i], a) { return fail(REASON_SERVER_LIMIT_EXCEEDED, "the object is too large"); }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    if !set { echo_attribute(out, item, v, index_of(a, item)); }
    return done();
}

fn op_modify_attribute(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let item, ix = one_attribute(buf, doc, p, TAG_NEW_ATTRIBUTE);
    if item.len < 8 { return fail(REASON_INVALID_FIELD, "no attribute, or one not known here"); }
    let t = binary::u32be(item, 0) >> 8;
    if server_only(t) || t == TAG_CRYPTOGRAPHIC_ALGORITHM || t == TAG_CRYPTOGRAPHIC_LENGTH {
        return fail(REASON_ATTRIBUTE_READ_ONLY, "the server sets that attribute");
    }
    let ck = change_ok(s, owner, i, item);
    if ck.reason != 0 { return ck; }
    var a = attrs_of(s.objects[i]);
    var k = ix;
    // 2.0: the Current Attribute says which value is changed.
    let cur, cix = one_attribute(buf, doc, p, TAG_CURRENT_ATTRIBUTE);
    if is_v2(v) && child(doc, p, TAG_CURRENT_ATTRIBUTE) >= 0 {
        k = -1;
        var seen = 0;
        each_attr(a) { tt, it =>
            if tt == t { if k < 0 && it == cur[..] { k = seen; } seen++; }
        };
        if k < 0 { return fail(REASON_ATTRIBUTE_NOT_FOUND, "no such value"); }
    }
    if t == TAG_ATTRIBUTE && !(is_v2(v) && child(doc, p, TAG_CURRENT_ATTRIBUTE) >= 0) {
        // A vendor's attribute: the k-th of that vendor and name.
        let key = custom_key(item);
        var g: i64 = 0;
        var seen: i64 = 0;
        var at: i64 = -1;
        each_attr(a) { tt, it =>
            if tt == TAG_ATTRIBUTE {
                if at < 0 && custom_key(it)[..] == key[..] { if seen == k { at = g; } seen++; }
                g++;
            }
        };
        if at < 0 { return fail(REASON_ATTRIBUTE_NOT_FOUND, "the object has no such attribute"); }
        k = at;
    }
    if find_attr(a, t, k).len == 0 { return fail(REASON_ATTRIBUTE_NOT_FOUND, "the object has no such attribute"); }
    if t == TAG_SENSITIVE {
        let was, wok = get_bool(a, TAG_SENSITIVE);
        if wok && was && binary::u64be(item, 8) == 0 { return fail(REASON_INVALID_FIELD, "Sensitive goes from false to true only"); }
    }
    replace_attr(a, item, k);
    if !set_attrs(s.objects[i], a) { return fail(REASON_SERVER_LIMIT_EXCEEDED, "the object is too large"); }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    echo_attribute(out, item, v, k);
    return done();
}

fn op_delete_attribute(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    var a = attrs_of(s.objects[i]);
    var t: u32 = 0;
    var k: i64 = 0;
    let cur = child(doc, p, TAG_CURRENT_ATTRIBUTE);
    var cur_item: u8[>..] = [];
    if is_type(doc, cur, STRUCTURE) && doc[cur].count == 1 {
        cur_item.append(raw(buf, doc, cur + 1));
        t = doc[cur + 1].tag;
        k = -1;
        var seen = 0;
        each_attr(a) { tt, it =>
            if tt == t { if k < 0 && it == cur_item[..] { k = seen; } seen++; }
        };
        if k < 0 { return fail(REASON_ATTRIBUTE_NOT_FOUND, "no such value"); }
    } else {
        let tags = named_tags(buf, doc, p);
        let customs = named_customs(buf, doc, p);
        let ix, iok = child_int(buf, doc, p, TAG_ATTRIBUTE_INDEX);
        if tags.len == 1 && tags[0] == 0 && customs.len == 1 {
            // A vendor's attribute: the ix-th of that vendor and name, as
            // the k-th of all vendors' attributes.
            t = TAG_ATTRIBUTE;
            let want: i64 = if iok { ix } else { 0 };
            var g: i64 = 0;
            var seen: i64 = 0;
            k = -1;
            each_attr(a) { tt, it =>
                if tt == TAG_ATTRIBUTE {
                    if k < 0 && custom_key(it)[..] == customs[0][..] { if seen == want { k = g; } seen++; }
                    g++;
                }
            };
            if k < 0 { return fail(REASON_ATTRIBUTE_NOT_FOUND, "the object has no such attribute"); }
        } else {
            if tags.len != 1 || tags[0] == 0 { return fail(REASON_INVALID_FIELD, "no attribute named, or one not known here"); }
            t = tags[0];
            if iok { k = ix; }
        }
    }
    if server_only(t) || t == TAG_CRYPTOGRAPHIC_ALGORITHM || t == TAG_CRYPTOGRAPHIC_LENGTH {
        return fail(REASON_READ_ONLY_ATTRIBUTE, "the server sets that attribute");
    }
    var gone: u8[>..] = [];
    gone.append(find_attr(a, t, k));
    if gone.len == 0 { return fail(REASON_ITEM_NOT_FOUND, "the object has no such attribute"); }
    let ok = remove_attr(a, t, k);
    let st = set_attrs(s.objects[i], a);
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    echo_attribute(out, gone, v, k);
    return done();
}

// Whether an object's attributes a match what a Locate asks for: each
// attribute there with that value, except a date given twice, which is a
// range the object's date falls in.
fn locate_match(a: const Attrs&, want: const Attrs&) -> bool {
    var all = true;
    each_attr(want) { t, item =>
        let second = find_attr(want, t, 1);
        if item.len >= 16 && item[3] == DATE_TIME && second.len >= 16 && find_attr(want, t, 2).len == 0 {
            let x = binary::u64be(item, 8) as! i64;
            let y = binary::u64be(second, 8) as! i64;
            let lo = if x < y { x } else { y };
            let hi = if x < y { y } else { x };
            let d, ok = get_datetime(a, t);
            if !ok || d < lo || d > hi { all = false; }
        } else if !has_item(a, item) {
            all = false;
        }
    };
    return all;
}

fn op_locate(s: const Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let want = read_attrs(buf, doc, p);
    let max, mok = child_int(buf, doc, p, TAG_MAXIMUM_ITEMS);
    let off, ook = child_int(buf, doc, p, TAG_OFFSET_ITEMS);
    var skip = if ook { off as i64 } else { 0 };
    // Storage Status Mask: online objects unless it asks for archived ones.
    let ssm, sok = child_int(buf, doc, p, TAG_STORAGE_STATUS_MASK);
    let mask = if sok { ssm as! u32 } else { STORAGE_ONLINE_STORAGE };
    var n = 0;
    var total = 0;
    var uids: u8[>..] = [];
    // In the store's order, newest slots first.
    var i = s.objects.len - 1;
    while i >= 0 {
        let m = s.objects[i];
        i--;
        if m.obj_type == 0 || m.owner[..] != owner { continue; }
        let gone = m.state == STATE_DESTROYED || m.state == STATE_DESTROYED_COMPROMISED;
        if gone && (mask & STORAGE_DESTROYED_STORAGE) == 0 { continue; }
        if m.archived && (mask & STORAGE_ARCHIVAL_STORAGE) == 0 { continue; }
        if !gone && !m.archived && (mask & STORAGE_ONLINE_STORAGE) == 0 { continue; }
        let a = attrs_of(m);
        if !locate_match(a, want) { continue; }
        total++;
        if skip > 0 { skip--; continue; }
        if mok && max > 0 && n >= max { continue; }
        put_text(uids, TAG_UNIQUE_IDENTIFIER, m.uid);
        n++;
    }
    if is_v2(v) || !version_lt(v, V1_3) { put_int(out, TAG_LOCATED_ITEMS, total as! i32); }
    out.append(uids);
    return done();
}

fn op_activate(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    if s.objects[i].state != STATE_PRE_ACTIVE { return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "only a Pre-Active object is activated"); }
    let ok = set_state(s, s.objects[i], STATE_ACTIVE, TAG_ACTIVATION_DATE);
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    return done();
}

fn op_revoke(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let rr = child(doc, p, TAG_REVOCATION_REASON);
    let code, cok = child_enum(buf, doc, rr, TAG_REVOCATION_REASON_CODE);
    if !cok { return fail(REASON_INVALID_FIELD, "no Revocation Reason"); }
    let st = s.objects[i].state;
    if st == STATE_DESTROYED || st == STATE_DESTROYED_COMPROMISED {
        // A destroyed object's compromise is still recorded.
        if (code == REVOKE_KEY_COMPROMISE || code == REVOKE_CA_COMPROMISE) && st == STATE_DESTROYED {
            let ok = set_state(s, s.objects[i], STATE_DESTROYED_COMPROMISED, TAG_COMPROMISE_DATE);
        }
        put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
        return done();
    }
    var a = attrs_of(s.objects[i]);
    a.enc.append(raw(buf, doc, rr));
    let ok0 = remove_attr(a, TAG_REVOCATION_REASON, 0);
    let rritem = raw(buf, doc, rr);
    a.enc.append(rritem);
    let compromise = code == REVOKE_KEY_COMPROMISE || code == REVOKE_CA_COMPROMISE;
    if compromise {
        let when, wok = as_datetime(buf, doc, child(doc, p, TAG_COMPROMISE_OCCURRENCE_DATE));
        if wok { let d = item_of_date(TAG_COMPROMISE_OCCURRENCE_DATE, when); set_single(a, d); }
        let ok = set_attrs(s.objects[i], a);
        let ok2 = set_state(s, s.objects[i], STATE_COMPROMISED, TAG_COMPROMISE_DATE);
    } else {
        if st != STATE_ACTIVE && st != STATE_PRE_ACTIVE { return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "not Active"); }
        let ok = set_attrs(s.objects[i], a);
        let ok2 = set_state(s, s.objects[i], STATE_DEACTIVATED, TAG_DEACTIVATION_DATE);
    }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    return done();
}

fn op_destroy(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let i = find_object(s, owner, uid_in(s, buf, doc, p));
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    let st = s.objects[i].state;
    if st == STATE_ACTIVE { return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "an Active object is revoked before it is destroyed"); }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    if st == STATE_DESTROYED || st == STATE_DESTROYED_COMPROMISED { return done(); }
    // The key material goes; the object, its attributes and its Destroy
    // Date stay, for Get Attributes and Locate.
    var o, ok = object_of(s.objects[i]);
    o.material.clear();
    o.wrapped = false;
    o.wrapping.clear();
    var obj: u8[>..] = [];
    let w = put_object(obj, o);
    let a = attrs_of(s.objects[i]);
    let ok2 = store_into(s.objects[i], obj, a);
    let ok3 = set_state(s, s.objects[i], if st == STATE_COMPROMISED { STATE_DESTROYED_COMPROMISED } else { STATE_DESTROYED }, TAG_DESTROY_DATE);
    s.objects[i].archived = false;
    return done();
}
