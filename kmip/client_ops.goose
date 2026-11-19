// kmip.client_ops: the client's side of the operations past the basic
// ones: Get in a format, wrapped (a Key Wrapping Specification) or
// unwrapped (Key Wrap Type), Export and Import, Re-key and Re-key Key
// Pair, Derive Key, Check, Obtain Lease, Get Usage Allocation, Archive and
// Recover, Adjust Attribute, Interop, MAC Verify, Hash, RNG Seed,
// signatures over digests, and any of the cryptographic operations in
// parts (Init Indicator, Correlation Value, Final Indicator). Like
// client.goose's, each takes any client type with exchange, version and
// the last_* fields.

namespace kmip;

import std;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;
import kmip.wrap;
import kmip.client;

// --- Get, Export, Import ----------------------------------------------------------

fn put_get_fields(out: u8[>..]&, uid: const u8[:], format: u32, wrap_type: u32, w: const Wrapping&, wrapped: bool) {
    put_uid(out, uid);
    if format != 0 { put_enum(out, TAG_KEY_FORMAT_TYPE, format); }
    if wrap_type != 0 { put_enum(out, TAG_KEY_WRAP_TYPE, wrap_type); }
    if wrapped { put_wrapping_spec(out, w); }
}

// Get with all its fields: the format (0: as kept), the Key Wrap Type
// (0: not said; KEY_WRAP_NOT_WRAPPED for a key registered wrapped, given
// unwrapped), and a Key Wrapping Specification when wrapped.
fn get_as<C>(c: C&, uid: const u8[:], format: u32, wrap_type: u32, w: const Wrapping&, wrapped: bool) -> Object, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_GET, resp, doc) { out => put_get_fields(out, uid, format, wrap_type, w, wrapped); };
    if e != OK { return new_object(0), e; }
    let t, tok = child_enum(resp, doc, p, TAG_OBJECT_TYPE);
    if !tok { return new_object(0), ERR_MISSING; }
    let o, ok = read_object(resp, doc, p, t);
    return o, if ok { OK } else { ERR_MISSING };
}

// A key wrapped as w says (wrapping(WRAP_ENCRYPT) and wrap_encrypt_key,
// say); unwrap_with undoes it with the client's copy of the key.
fn get_wrapped<C>(c: C&, uid: const u8[:], w: const Wrapping&) -> Object, i64 {
    let o, e = get_as(c, uid, 0, 0, w, true);
    return o, e;
}

// Export (1.4): the object and all its attributes.
fn export_object<C>(c: C&, uid: const u8[:], format: u32, wrap_type: u32, w: const Wrapping&, wrapped: bool) -> Object, Attrs, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_EXPORT, resp, doc) { out => put_get_fields(out, uid, format, wrap_type, w, wrapped); };
    var a = attrs();
    if e != OK { return new_object(0), a, e; }
    let t, tok = child_enum(resp, doc, p, TAG_OBJECT_TYPE);
    if !tok { return new_object(0), a, ERR_MISSING; }
    let o, ok = read_object(resp, doc, p, t);
    let x = read_attrs(resp, doc, p);
    a.enc.append(x.enc);
    return o, a, if ok { OK } else { ERR_MISSING };
}

// Import (1.4): the object under the identifier given, with exactly the
// attributes given; replace an object already there. wrap_type
// KEY_WRAP_NOT_WRAPPED has a wrapped object unwrapped by the server.
fn import_object<C>(c: C&, uid: const u8[:], o: const Object&, a: const Attrs&, replace: bool, wrap_type: u32) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_IMPORT, resp, doc) { out =>
        put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
        put_enum(out, TAG_OBJECT_TYPE, o.obj_type);
        if replace { put_bool(out, TAG_REPLACE_EXISTING, true); }
        if wrap_type != 0 { put_enum(out, TAG_KEY_WRAP_TYPE, wrap_type); }
        put_template(out, a, v, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
        let ok = put_object(out, o);
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let u, ue = uid_of(resp, doc, p, TAG_UNIQUE_IDENTIFIER);
    return u, ue;
}

// --- Replacement and derived keys ----------------------------------------------------

// Re-key: a replacement for a symmetric key; offset the seconds from its
// Initial Date to its Activation Date (-1: the old key's dates copied).
fn rekey<C>(c: C&, uid: const u8[:], offset: i64, a: const Attrs&) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_REKEY, resp, doc) { out =>
        put_uid(out, uid);
        if offset >= 0 { put_interval(out, TAG_OFFSET, offset as! u32); }
        if a.enc.len > 0 { put_template(out, a, v, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES); }
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let u, ue = uid_of(resp, doc, p, TAG_UNIQUE_IDENTIFIER);
    return u, ue;
}

// Re-key Key Pair (1.1): the replacement private and public keys.
fn rekey_key_pair<C>(c: C&, private_uid: const u8[:], offset: i64, common: const Attrs&, private: const Attrs&,
                     public: const Attrs&) -> u8[>..], u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_REKEY_KEY_PAIR, resp, doc) { out =>
        if private_uid.len > 0 { put_text(out, TAG_PRIVATE_KEY_UNIQUE_IDENTIFIER, private_uid); }
        if offset >= 0 { put_interval(out, TAG_OFFSET, offset as! u32); }
        if common.enc.len > 0 { put_template(out, common, v, TAG_COMMON_TEMPLATE_ATTRIBUTE, TAG_COMMON_ATTRIBUTES); }
        if private.enc.len > 0 { put_template(out, private, v, TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE, TAG_PRIVATE_KEY_ATTRIBUTES); }
        if public.enc.len > 0 { put_template(out, public, v, TAG_PUBLIC_KEY_TEMPLATE_ATTRIBUTE, TAG_PUBLIC_KEY_ATTRIBUTES); }
    };
    var none: u8[>..] = [];
    if e != OK { return none, copy(none), e; }
    let u1, e1 = uid_of(resp, doc, p, TAG_PRIVATE_KEY_UNIQUE_IDENTIFIER);
    let u2, e2 = uid_of(resp, doc, p, TAG_PUBLIC_KEY_UNIQUE_IDENTIFIER);
    return u1, u2, if e1 != OK { e1 } else { e2 };
}

// What Derive Key derives with: the method (DERIVE_*), parameters (a
// hash, a mode), and as the method wants them the Derivation Data, Salt,
// Iteration Count (0: none) and IV.
struct Derivation {
    method: u32,
    params: CryptoParams,
    has_params: bool,
    salt: u8[..1024],
    iterations: i32,
    iv: u8[..64],
    data: u8[>..],
}

fn derivation(method: u32) -> Derivation {
    Derivation { method: method, params: CryptoParams { .. }, has_params: false, salt: [], iterations: 0, iv: [], data: [] }
}

// Derive Key: a new symmetric key or secret data (obj_type) from the
// objects named (the key first; a Secret Data or an ECDH peer's public
// key after it), with the attributes given (Cryptographic Length always,
// and the Algorithm of a key).
fn derive_key<C>(c: C&, obj_type: u32, from: const u8[..64][:], d: const Derivation&, a: const Attrs&) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_DERIVE_KEY, resp, doc) { out =>
        put_enum(out, TAG_OBJECT_TYPE, obj_type);
        for u in from { put_text(out, TAG_UNIQUE_IDENTIFIER, u); }
        put_enum(out, TAG_DERIVATION_METHOD, d.method);
        let dp = begin(out, TAG_DERIVATION_PARAMETERS);
        if d.has_params { put_crypto_params(out, d.params); }
        if d.iv.len > 0 { put_bytes(out, TAG_INITIALIZATION_VECTOR, d.iv); }
        if d.data.len > 0 { put_bytes(out, TAG_DERIVATION_DATA, d.data); }
        if d.salt.len > 0 { put_bytes(out, TAG_SALT, d.salt); }
        if d.iterations > 0 { put_int(out, TAG_ITERATION_COUNT, d.iterations); }
        end(out, dp);
        put_template(out, a, v, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let u, ue = uid_of(resp, doc, p, TAG_UNIQUE_IDENTIFIER);
    return u, ue;
}

// --- Check, leases, usage ----------------------------------------------------------

// Check: whether the object may be used so (usage mask, usage count and
// lease, -1 for each not asked). ERR_FAILED, with the reason in
// last_reason, when not.
fn check<C>(c: C&, uid: const u8[:], usage_mask: i64, usage_count: i64, lease: i64) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_CHECK, resp, doc) { out =>
        put_uid(out, uid);
        if usage_count >= 0 { put_long(out, TAG_USAGE_LIMITS_COUNT, usage_count); }
        if usage_mask >= 0 { put_int(out, TAG_CRYPTOGRAPHIC_USAGE_MASK, usage_mask as! i32); }
        if lease >= 0 { put_interval(out, TAG_LEASE_TIME, lease as! u32); }
    };
    return e;
}

// Obtain Lease: the lease (seconds; 0, none) and the Last Change Date.
fn obtain_lease<C>(c: C&, uid: const u8[:]) -> i64, i64, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_OBTAIN_LEASE, resp, doc) { out => put_uid(out, uid); };
    if e != OK { return 0, 0, e; }
    let l, lok = as_interval(resp, doc, child(doc, p, TAG_LEASE_TIME));
    let d, dok = as_datetime(resp, doc, child(doc, p, TAG_LAST_CHANGE_DATE));
    if !lok || !dok { return 0, 0, ERR_MISSING; }
    return l as i64, d, OK;
}

fn get_usage_allocation<C>(c: C&, uid: const u8[:], count: i64) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_GET_USAGE_ALLOCATION, resp, doc) { out => put_uid(out, uid); put_long(out, TAG_USAGE_LIMITS_COUNT, count); };
    return e;
}

fn archive<C>(c: C&, uid: const u8[:]) -> i64 { uid_only(c, OP_ARCHIVE, uid) }
fn recover<C>(c: C&, uid: const u8[:]) -> i64 { uid_only(c, OP_RECOVER, uid) }

// Adjust Attribute (2.0): how is ADJUST_INCREMENT, _DECREMENT or _NEGATE;
// by the Adjustment Value as an item (put_int, put_long or put_interval
// under TAG_ADJUSTMENT_VALUE; empty for none).
fn adjust_attribute<C>(c: C&, uid: const u8[:], tag: u32, how: u32, by: const u8[:]) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_ADJUST_ATTRIBUTE, resp, doc) { out =>
        put_uid(out, uid);
        put_enum(out, TAG_ATTRIBUTE_REFERENCE, tag);
        put_enum(out, TAG_ADJUSTMENT_TYPE, how);
        out.append(by);
    };
    return e;
}

// Interop (2.0): a test case's Begin, End or Reset.
fn interop<C>(c: C&, function: u32, id: const u8[:]) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_INTEROP, resp, doc) { out =>
        put_enum(out, TAG_INTEROP_FUNCTION, function);
        if id.len > 0 { put_text(out, TAG_INTEROP_IDENTIFIER, id); }
    };
    return e;
}

// --- More cryptography ------------------------------------------------------------

fn mac_verify<C>(c: C&, uid: const u8[:], params: CryptoParams, data: const u8[:], mac: const u8[:]) -> bool, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_MAC_VERIFY, resp, doc) { out =>
        put_uid(out, uid);
        if has_params(params) { put_crypto_params(out, params); }
        put_bytes(out, TAG_DATA, data);
        put_bytes(out, TAG_MAC_DATA, mac);
    };
    if e != OK { return false, e; }
    let vi, ok = child_enum(resp, doc, p, TAG_VALIDITY_INDICATOR);
    if !ok { return false, ERR_MISSING; }
    return vi == VALIDITY_VALID, OK;
}

// Hash: the digest of data by the hash (HASH_SHA_256, ...).
fn hash<C>(c: C&, h: u32, data: const u8[:]) -> u8[>..], i64 {
    var d: u8[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_HASH, resp, doc) { out =>
        put_crypto_params(out, CryptoParams { hash: h });
        put_bytes(out, TAG_DATA, data);
    };
    if e != OK { return d, e; }
    let x, ok = child_bytes(resp, doc, p, TAG_DATA);
    if !ok { return d, ERR_MISSING; }
    d.append(x);
    return d, OK;
}

// RNG Seed: how much of the seed the server took (it may take none).
fn rng_seed<C>(c: C&, seed: const u8[:]) -> i32, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_RNG_SEED, resp, doc) { out => put_bytes(out, TAG_DATA, seed); };
    if e != OK { return 0, e; }
    let n, ok = child_int(resp, doc, p, TAG_DATA_LENGTH);
    return n, if ok { OK } else { ERR_MISSING };
}

// Sign a digest already made (Digested Data), and check a signature on one.
fn sign_digest<C>(c: C&, uid: const u8[:], params: CryptoParams, digest: const u8[:]) -> u8[>..], i64 {
    var s: u8[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_SIGN, resp, doc) { out =>
        put_uid(out, uid);
        if has_params(params) { put_crypto_params(out, params); }
        put_bytes(out, TAG_DIGESTED_DATA, digest);
    };
    if e != OK { return s, e; }
    let x, ok = child_bytes(resp, doc, p, TAG_SIGNATURE_DATA);
    if !ok { return s, ERR_MISSING; }
    s.append(x);
    return s, OK;
}

fn verify_digest<C>(c: C&, uid: const u8[:], params: CryptoParams, digest: const u8[:], sig: const u8[:]) -> bool, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_SIGNATURE_VERIFY, resp, doc) { out =>
        put_uid(out, uid);
        if has_params(params) { put_crypto_params(out, params); }
        put_bytes(out, TAG_DIGESTED_DATA, digest);
        put_bytes(out, TAG_SIGNATURE_DATA, sig);
    };
    if e != OK { return false, e; }
    let vi, ok = child_enum(resp, doc, p, TAG_VALIDITY_INDICATOR);
    if !ok { return false, ERR_MISSING; }
    return vi == VALIDITY_VALID, OK;
}

// --- In parts ---------------------------------------------------------------------

// One part of an operation in parts, and what its answer carried: the
// Correlation Value for the next part (empty after the Final one), the
// data (encrypted, decrypted, a signature, a MAC, a digest), an IV the
// server made, a GCM tag, and for the verifications the Validity
// Indicator (0 before the Final part).
struct Part {
    corr: u8[..16],
    iv: u8[..64],
    tag: u8[..16],
    validity: u32,
    data: u8[>..],
}

// Sends one part of op (OP_ENCRYPT, OP_DECRYPT, OP_SIGN, OP_SIGNATURE_VERIFY,
// OP_MAC, OP_MAC_VERIFY, OP_HASH): the first (corr empty: the uid,
// parameters and IV go with it) or the next (corr from the last part).
// fin marks the last; check is the signature, MAC or AEAD tag to check,
// given with the last part (or the first, for a tag).
fn part<C>(c: C&, op: u32, uid: const u8[:], params: CryptoParams, data: const u8[:], iv: const u8[:],
           corr: const u8[:], fin: bool, check: const u8[:]) -> Part, i64 {
    var r = Part { corr: [], iv: [], tag: [], validity: 0, data: [] };
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let first = corr.len == 0;
    let p, e = call(c, op, resp, doc) { out =>
        if first {
            if op != OP_HASH { put_uid(out, uid); }
            if has_params(params) || op == OP_HASH { put_crypto_params(out, params); }
        }
        if data.len > 0 || op == OP_HASH { put_bytes(out, TAG_DATA, data); }
        if first && iv.len > 0 { put_bytes(out, TAG_IV_COUNTER_NONCE, iv); }
        if check.len > 0 {
            let t = if op == OP_SIGNATURE_VERIFY { TAG_SIGNATURE_DATA } else if op == OP_MAC_VERIFY { TAG_MAC_DATA }
                    else { TAG_AUTHENTICATED_ENCRYPTION_TAG };
            put_bytes(out, t, check);
        }
        if first { put_bool(out, TAG_INIT_INDICATOR, true); } else { put_bytes(out, TAG_CORRELATION_VALUE, corr); }
        if fin { put_bool(out, TAG_FINAL_INDICATOR, true); }
    };
    if e != OK { return r, e; }
    let cv, cok = child_bytes(resp, doc, p, TAG_CORRELATION_VALUE);
    if cok && cv.len <= 16 { r.corr.append(cv); }
    let out_tag = if op == OP_SIGN { TAG_SIGNATURE_DATA } else if op == OP_MAC { TAG_MAC_DATA } else { TAG_DATA };
    let d, dok = child_bytes(resp, doc, p, out_tag);
    if dok { r.data.append(d); }
    let ivo, ivok = child_bytes(resp, doc, p, TAG_IV_COUNTER_NONCE);
    if ivok && ivo.len <= 64 { r.iv.append(ivo); }
    let tg, tok = child_bytes(resp, doc, p, TAG_AUTHENTICATED_ENCRYPTION_TAG);
    if tok && tg.len <= 16 { r.tag.append(tg); }
    let vi, vok = child_enum(resp, doc, p, TAG_VALIDITY_INDICATOR);
    if vok { r.validity = vi; }
    return r, OK;
}
