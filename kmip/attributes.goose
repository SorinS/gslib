// kmip.attributes: a list of attributes, each kept as the item 2.0 writes
// (its own tag: Cryptographic Algorithm, Enumeration, AES), and rendered
// for the version spoken: 1.x's Attribute { Attribute Name, Attribute
// Value } in a Template-Attribute, or 2.0's Attributes. Read back from
// either, the same list.
//
//   var a = kmip::attrs();
//   kmip::attr_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
//   kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
//   kmip::attr_name(a, "backup-key-7");
//   kmip::put_template(out, a, kmip::V1_2, kmip::TAG_TEMPLATE_ATTRIBUTE, kmip::TAG_ATTRIBUTES);

namespace kmip;

import std;
import binary;
import kmip;
import kmip.tables;
import kmip.messages;

struct Attrs { enc: u8[>..] }

fn attrs() -> Attrs { Attrs { enc: [] } }

fn attr_text(a: Attrs&, tag: u32, v: const u8[:]) { put_text(a.enc, tag, v); }
fn attr_bytes(a: Attrs&, tag: u32, v: const u8[:]) { put_bytes(a.enc, tag, v); }
fn attr_int(a: Attrs&, tag: u32, v: i32) { put_int(a.enc, tag, v); }
fn attr_long(a: Attrs&, tag: u32, v: i64) { put_long(a.enc, tag, v); }
fn attr_enum(a: Attrs&, tag: u32, v: u32) { put_enum(a.enc, tag, v); }
fn attr_bool(a: Attrs&, tag: u32, v: bool) { put_bool(a.enc, tag, v); }
fn attr_datetime(a: Attrs&, tag: u32, secs: i64) { put_datetime(a.enc, tag, secs); }
fn attr_interval(a: Attrs&, tag: u32, secs: u32) { put_interval(a.enc, tag, secs); }

// The Cryptographic Usage Mask, USAGE_* or'ed.
fn attr_usage(a: Attrs&, mask: u32) { put_int(a.enc, TAG_CRYPTOGRAPHIC_USAGE_MASK, mask as! i32); }

// A Name, as uninterpreted text.
fn attr_name(a: Attrs&, name: const u8[:]) {
    let s = begin(a.enc, TAG_NAME);
    put_text(a.enc, TAG_NAME_VALUE, name);
    put_enum(a.enc, TAG_NAME_TYPE, NAME_UNINTERPRETED_TEXT_STRING);
    end(a.enc, s);
}

// A Link to another object (LINK_PUBLIC_KEY, ...).
fn attr_link(a: Attrs&, link_type: u32, uid: const u8[:]) {
    let s = begin(a.enc, TAG_LINK);
    put_enum(a.enc, TAG_LINK_TYPE, link_type);
    put_text(a.enc, TAG_LINKED_OBJECT_IDENTIFIER, uid);
    end(a.enc, s);
}

// The curve of an EC key: Cryptographic Domain Parameters holding a
// Recommended Curve (CURVE_P_256, ...), which is no attribute of its own.
fn attr_curve(a: Attrs&, curve: u32) {
    let s = begin(a.enc, TAG_CRYPTOGRAPHIC_DOMAIN_PARAMETERS);
    put_enum(a.enc, TAG_RECOMMENDED_CURVE, curve);
    end(a.enc, s);
}

// The Recommended Curve of the list's Cryptographic Domain Parameters.
fn get_curve(a: const Attrs&) -> u32, bool {
    let item = find_attr(a, TAG_CRYPTOGRAPHIC_DOMAIN_PARAMETERS, 0);
    if item.len == 0 { return 0, false; }
    var doc: Node[>..] = [];
    let r, e = decode(item, Options { .. }, doc);
    if e != OK { return 0, false; }
    let c, ok = child_enum(item, doc, r, TAG_RECOMMENDED_CURVE);
    return c, ok;
}

// Cryptographic Parameters: each field 0 is left out.
struct CryptoParams {
    mode: u32 = 0,          // MODE_CBC, MODE_GCM, ...
    padding: u32 = 0,       // PAD_PKCS5, PAD_OAEP, ...
    hash: u32 = 0,          // HASH_SHA_256, ...
    sig: u32 = 0,           // SIG_SHA256_WITH_RSA_ENCRYPTION, ...
    alg: u32 = 0,           // ALG_AES, ... (1.2)
    random_iv: bool = false,
    tag_length: i32 = 0,    // AEAD tag, bytes
    // The rest of the Cryptographic Parameters (1.2 and later); 0 or empty
    // for absent.
    key_role: u32 = 0,      // ROLE_KEK, ...
    iv_length: i32 = 0,     // bits
    fixed_field_length: i32 = 0,
    invocation_field_length: i32 = 0,
    counter_length: i32 = 0,
    initial_counter: i32 = 0,
    has_initial_counter: bool = false,
    salt_length: i32 = -1,  // PSS salt, bytes; -1 absent
    mgf: u32 = 0,           // MGF_MGF1
    mgf_hash: u32 = 0,      // Mask Generator Hashing Algorithm, HASH_SHA_1 by KMIP's default
    trailer_field: i32 = 0,
    p_source: u8[..256] = [],  // OAEP's label
}

fn put_crypto_params(out: u8[>..]&, p: CryptoParams) {
    let s = begin(out, TAG_CRYPTOGRAPHIC_PARAMETERS);
    if p.mode != 0 { put_enum(out, TAG_BLOCK_CIPHER_MODE, p.mode); }
    if p.padding != 0 { put_enum(out, TAG_PADDING_METHOD, p.padding); }
    if p.hash != 0 { put_enum(out, TAG_HASHING_ALGORITHM, p.hash); }
    if p.sig != 0 { put_enum(out, TAG_DIGITAL_SIGNATURE_ALGORITHM, p.sig); }
    if p.alg != 0 { put_enum(out, TAG_CRYPTOGRAPHIC_ALGORITHM, p.alg); }
    if p.random_iv { put_bool(out, TAG_RANDOM_IV, true); }
    if p.key_role != 0 { put_enum(out, TAG_KEY_ROLE_TYPE, p.key_role); }
    if p.iv_length != 0 { put_int(out, TAG_IV_LENGTH, p.iv_length); }
    if p.tag_length != 0 { put_int(out, TAG_TAG_LENGTH, p.tag_length); }
    if p.fixed_field_length != 0 { put_int(out, TAG_FIXED_FIELD_LENGTH, p.fixed_field_length); }
    if p.invocation_field_length != 0 { put_int(out, TAG_INVOCATION_FIELD_LENGTH, p.invocation_field_length); }
    if p.counter_length != 0 { put_int(out, TAG_COUNTER_LENGTH, p.counter_length); }
    if p.has_initial_counter { put_int(out, TAG_INITIAL_COUNTER_VALUE, p.initial_counter); }
    if p.salt_length >= 0 { put_int(out, TAG_SALT_LENGTH, p.salt_length); }
    if p.mgf != 0 { put_enum(out, TAG_MASK_GENERATOR, p.mgf); }
    if p.mgf_hash != 0 { put_enum(out, TAG_MASK_GENERATOR_HASHING_ALGORITHM, p.mgf_hash); }
    if p.p_source.len > 0 { put_bytes(out, TAG_P_SOURCE, p.p_source); }
    if p.trailer_field != 0 { put_int(out, TAG_TRAILER_FIELD, p.trailer_field); }
    end(out, s);
}

// A Cryptographic Parameters Structure, at i, read; false when it is not
// one. Fields it does not know are left out.
fn read_crypto_params(buf: const u8[:], doc: const Node[:], i: i64) -> CryptoParams, bool {
    var cp = CryptoParams { .. };
    if !is_type(doc, i, STRUCTURE) { return cp, false; }
    var ok = true;
    each(doc, i) { k =>
        let t = doc[k].tag;
        if t == TAG_BLOCK_CIPHER_MODE { let v, o = as_enum(buf, doc, k); cp.mode = v; ok = ok && o; }
        else if t == TAG_PADDING_METHOD { let v, o = as_enum(buf, doc, k); cp.padding = v; ok = ok && o; }
        else if t == TAG_HASHING_ALGORITHM { let v, o = as_enum(buf, doc, k); cp.hash = v; ok = ok && o; }
        else if t == TAG_DIGITAL_SIGNATURE_ALGORITHM { let v, o = as_enum(buf, doc, k); cp.sig = v; ok = ok && o; }
        else if t == TAG_CRYPTOGRAPHIC_ALGORITHM { let v, o = as_enum(buf, doc, k); cp.alg = v; ok = ok && o; }
        else if t == TAG_RANDOM_IV { let v, o = as_bool(buf, doc, k); cp.random_iv = v; ok = ok && o; }
        else if t == TAG_KEY_ROLE_TYPE { let v, o = as_enum(buf, doc, k); cp.key_role = v; ok = ok && o; }
        else if t == TAG_IV_LENGTH { let v, o = as_int(buf, doc, k); cp.iv_length = v; ok = ok && o; }
        else if t == TAG_TAG_LENGTH { let v, o = as_int(buf, doc, k); cp.tag_length = v; ok = ok && o; }
        else if t == TAG_FIXED_FIELD_LENGTH { let v, o = as_int(buf, doc, k); cp.fixed_field_length = v; ok = ok && o; }
        else if t == TAG_INVOCATION_FIELD_LENGTH { let v, o = as_int(buf, doc, k); cp.invocation_field_length = v; ok = ok && o; }
        else if t == TAG_COUNTER_LENGTH { let v, o = as_int(buf, doc, k); cp.counter_length = v; ok = ok && o; }
        else if t == TAG_INITIAL_COUNTER_VALUE { let v, o = as_int(buf, doc, k); cp.initial_counter = v; cp.has_initial_counter = true; ok = ok && o; }
        else if t == TAG_SALT_LENGTH { let v, o = as_int(buf, doc, k); cp.salt_length = v; ok = ok && o; }
        else if t == TAG_MASK_GENERATOR { let v, o = as_enum(buf, doc, k); cp.mgf = v; ok = ok && o; }
        else if t == TAG_MASK_GENERATOR_HASHING_ALGORITHM { let v, o = as_enum(buf, doc, k); cp.mgf_hash = v; ok = ok && o; }
        else if t == TAG_TRAILER_FIELD { let v, o = as_int(buf, doc, k); cp.trailer_field = v; ok = ok && o; }
        else if t == TAG_P_SOURCE {
            let v, o = as_bytes(buf, doc, k);
            if o && v.len <= 256 { cp.p_source.append(v); } else { ok = false; }
        }
    };
    return cp, ok;
}

// Cryptographic Parameters given as an encoded item (an attribute's).
fn crypto_params_of_item(item: const u8[:]) -> CryptoParams, bool {
    var doc: Node[>..] = [];
    let r, e = decode(item, Options { .. }, doc);
    if e != OK { return CryptoParams { .. }, false; }
    let cp, ok = read_crypto_params(item, doc, r);
    return cp, ok;
}

fn attr_crypto_params(a: Attrs&, p: CryptoParams) { put_crypto_params(a.enc, p); }

// An item already written, kept as it is (an attribute of a type with
// no helper here).
fn attr_raw(a: Attrs&, item: const u8[:]) { a.enc.append(item); }

// --- Walking the list -----------------------------------------------------------

fn item_len(enc: const u8[:], at: i64) -> i64 {
    if at + 8 > enc.len { return -1; }
    let len = binary::u32be(enc, at + 4) as i64;
    let n = 8 + padded(len);
    if at + n > enc.len { return -1; }
    return n;
}

fn item_tag(enc: const u8[:], at: i64) -> u32 { binary::u32be(enc, at) >> 8 }

// F(tag, item) for each attribute, in order; item is its whole encoding.
fn each_attr<F>(a: const Attrs&) {
    var at = 0;
    while at < a.enc.len {
        let n = item_len(a.enc, at);
        if n < 0 { return; }
        F(item_tag(a.enc, at), a.enc[at..at + n]);
        at += n;
    }
}

fn attr_count(a: const Attrs&) -> i64 {
    var n = 0;
    each_attr(a) { t, item => n++; };
    return n;
}

// The k-th attribute with the tag (0, the first), as it is encoded, or "".
fn find_attr(a: const Attrs&, tag: u32, k: i64) -> const u8[:] {
    var at = 0;
    var seen = 0;
    while at < a.enc.len {
        let n = item_len(a.enc, at);
        if n < 0 { return ""; }
        if item_tag(a.enc, at) == tag {
            if seen == k { return a.enc[at..at + n]; }
            seen++;
        }
        at += n;
    }
    return "";
}

fn has_attr(a: const Attrs&, tag: u32) -> bool { find_attr(a, tag, 0).len > 0 }

// One attribute's value, when it is of that type.
fn item_value(item: const u8[:], typ: u8) -> const u8[:], bool {
    if item.len < 8 || item[3] != typ { return "", false; }
    let len = binary::u32be(item, 4) as i64;
    // An item put in raw (attr_raw) is not checked as decode checks: a
    // number of the wrong length, or one longer than the item, is none.
    let fl = fixed_len(typ);
    if (fl >= 0 && len != fl) || len > item.len - 8 { return "", false; }
    return item[8..8 + len], true;
}

fn get_text(a: const Attrs&, tag: u32) -> const u8[:], bool { let v, ok = item_value(find_attr(a, tag, 0), TEXT_STRING); return v, ok; }
fn get_bytes(a: const Attrs&, tag: u32) -> const u8[:], bool { let v, ok = item_value(find_attr(a, tag, 0), BYTE_STRING); return v, ok; }

fn get_enum(a: const Attrs&, tag: u32) -> u32, bool {
    let v, ok = item_value(find_attr(a, tag, 0), ENUMERATION);
    if !ok { return 0, false; }
    return binary::u32be(v, 0), true;
}

fn get_int(a: const Attrs&, tag: u32) -> i32, bool {
    let v, ok = item_value(find_attr(a, tag, 0), INTEGER);
    if !ok { return 0, false; }
    return binary::u32be(v, 0) as! i32, true;
}

fn get_long(a: const Attrs&, tag: u32) -> i64, bool {
    let v, ok = item_value(find_attr(a, tag, 0), LONG_INTEGER);
    if !ok { return 0, false; }
    return binary::u64be(v, 0) as! i64, true;
}

fn get_bool(a: const Attrs&, tag: u32) -> bool, bool {
    let v, ok = item_value(find_attr(a, tag, 0), BOOLEAN);
    if !ok { return false, false; }
    return binary::u64be(v, 0) == 1, true;
}

fn get_interval(a: const Attrs&, tag: u32) -> u32, bool {
    let v, ok = item_value(find_attr(a, tag, 0), INTERVAL);
    if !ok { return 0, false; }
    return binary::u32be(v, 0), true;
}

fn get_datetime(a: const Attrs&, tag: u32) -> i64, bool {
    let v, ok = item_value(find_attr(a, tag, 0), DATE_TIME);
    if !ok { return 0, false; }
    return binary::u64be(v, 0) as! i64, true;
}

// The k-th Name's text, or "".
fn get_name(a: const Attrs&, k: i64) -> u8[>..] {
    var s: u8[>..] = [];
    let item = find_attr(a, TAG_NAME, k);
    if item.len == 0 { return s; }
    var doc: Node[>..] = [];
    let r, e = decode(item, Options { .. }, doc);
    if e != OK { return s; }
    let v, ok = child_text(item, doc, r, TAG_NAME_VALUE);
    if ok { s.append(v); }
    return s;
}

// --- Rendering ------------------------------------------------------------------

// 1.x's Attribute for one item: its Attribute Name, and its value under
// the tag Attribute Value. False for a tag with no 1.x name.
fn put_attribute_1x(out: u8[>..]&, tag: u32, item: const u8[:]) -> bool { return put_attribute_1x_at(out, tag, item, 0); }

// The same with its Attribute Index (which instance of the attribute it
// is), written when not 0.
fn put_attribute_1x_at(out: u8[>..]&, tag: u32, item: const u8[:], index: i32) -> bool {
    // A vendor's attribute: 1.x names it vendor-name ("x-ID").
    if tag == TAG_ATTRIBUTE {
        var doc: Node[>..] = [];
        let r, e = decode(item, Options { .. }, doc);
        let val = child(doc, r, TAG_ATTRIBUTE_VALUE);
        if e != OK || val < 0 { return false; }
        let s = begin(out, TAG_ATTRIBUTE);
        put_text(out, TAG_ATTRIBUTE_NAME, custom_key(item));
        if index != 0 { put_int(out, TAG_ATTRIBUTE_INDEX, index); }
        out.append(raw(item, doc, val));
        end(out, s);
        return true;
    }
    let name = attribute_name(tag);
    if name.len == 0 { return false; }
    let s = begin(out, TAG_ATTRIBUTE);
    put_text(out, TAG_ATTRIBUTE_NAME, name);
    if index != 0 { put_int(out, TAG_ATTRIBUTE_INDEX, index); }
    put_retagged(out, TAG_ATTRIBUTE_VALUE, item);
    end(out, s);
    return true;
}

// The attributes as bare 1.x Attributes (a Locate's), or, in 2.0, an
// Attributes Structure.
fn put_attribute_items(out: u8[>..]&, a: const Attrs&, v: Version) {
    if is_v2(v) { put_attributes(out, a, TAG_ATTRIBUTES); return; }
    each_attr(a) { t, item => let ok = put_attribute_1x(out, t, item); };
}

// 2.0's form: a Structure with the tag (Attributes, Common Attributes,
// Private Key Attributes, ...) holding the items as they are.
fn put_attributes(out: u8[>..]&, a: const Attrs&, tag: u32) {
    let s = begin(out, tag);
    out.append(a.enc);
    end(out, s);
}

// What Create, Register and Create Key Pair carry: in 1.x a Structure
// tagged tag1 (Template-Attribute, Common Template-Attribute, ...) of
// Attributes, in 2.0 one tagged tag2 (Attributes, Common Attributes, ...).
fn put_template(out: u8[>..]&, a: const Attrs&, v: Version, tag1: u32, tag2: u32) {
    if is_v2(v) { put_attributes(out, a, tag2); return; }
    let s = begin(out, tag1);
    each_attr(a) { t, item => let ok = put_attribute_1x(out, t, item); };
    end(out, s);
}

// Reads attributes from a Structure: 1.x Attributes among its children
// (a Get Attributes response, a Template-Attribute), or a 2.0 Attributes
// Structure in it or being it. Attributes with names not known here
// (custom ones, x-...) are left out.
fn read_attrs(buf: const u8[:], doc: const Node[:], i: i64) -> Attrs {
    var a = attrs();
    if !is_type(doc, i, STRUCTURE) { return a; }
    if doc[i].tag == TAG_ATTRIBUTES {
        each(doc, i) { c => a.enc.append(raw(buf, doc, c)); };
        return a;
    }
    each(doc, i) { c =>
        if doc[c].tag == TAG_ATTRIBUTE {
            let name, ok = child_text(buf, doc, c, TAG_ATTRIBUTE_NAME);
            let val = child(doc, c, TAG_ATTRIBUTE_VALUE);
            let tag = if ok { attribute_tag(name) } else { 0 };
            if tag != 0 && val >= 0 { put_retagged(a.enc, tag, raw(buf, doc, val)); }
            else if ok && val >= 0 && name.len > 0 { put_custom(a.enc, name, raw(buf, doc, val)); }
        } else if doc[c].tag == TAG_ATTRIBUTES {
            each(doc, c) { d => a.enc.append(raw(buf, doc, d)); };
        }
    };
    return a;
}

// --- Attribute References (2.0) -------------------------------------------------

// An Attribute Reference names an attribute in 2.0 either by its tag (an
// Enumeration) or as a Structure of Vendor Identification and Attribute
// Name; the tag it names, or 0.
// --- Vendors' attributes ----------------------------------------------------------

// 2.0 keeps a vendor's attribute (1.x's custom attribute, "x-ID") as an
// Attribute Structure: Vendor Identification, Attribute Name, Attribute
// Value. Such items are kept under TAG_ATTRIBUTE, each one apart.

// A 1.x custom attribute's name and value (its Attribute Value item) as
// that Structure: the vendor is what comes before the first '-'.
fn put_custom(out: u8[>..]&, name: const u8[:], value_item: const u8[:]) {
    var dash = 0;
    while dash < name.len && name[dash] != '-' { dash++; }
    let s = begin(out, TAG_ATTRIBUTE);
    if dash < name.len {
        put_text(out, TAG_VENDOR_IDENTIFICATION, name[..dash]);
        put_text(out, TAG_ATTRIBUTE_NAME, name[dash + 1..]);
    } else {
        put_text(out, TAG_VENDOR_IDENTIFICATION, "");
        put_text(out, TAG_ATTRIBUTE_NAME, name);
    }
    put_retagged(out, TAG_ATTRIBUTE_VALUE, value_item);
    end(out, s);
}

// A vendor's attribute's name as 1.x writes it: vendor-name.
fn custom_key(item: const u8[:]) -> u8[>..] {
    var k: u8[>..] = [];
    var doc: Node[>..] = [];
    let r, e = decode(item, Options { .. }, doc);
    if e != OK { return k; }
    let v, vok = child_text(item, doc, r, TAG_VENDOR_IDENTIFICATION);
    let n, nok = child_text(item, doc, r, TAG_ATTRIBUTE_NAME);
    if vok && v.len > 0 { k.append(v); k.push('-'); }
    if nok { k.append(n); }
    return k;
}

// The vendor-name of an Attribute Reference Structure naming a vendor's
// attribute, or empty.
fn reference_custom(buf: const u8[:], doc: const Node[:], i: i64) -> u8[>..] {
    var k: u8[>..] = [];
    if !is_type(doc, i, STRUCTURE) { return k; }
    let v, vok = child_text(buf, doc, i, TAG_VENDOR_IDENTIFICATION);
    let n, nok = child_text(buf, doc, i, TAG_ATTRIBUTE_NAME);
    if !vok || v.len == 0 || !nok { return k; }
    k.append(v);
    k.push('-');
    k.append(n);
    return k;
}

fn reference_tag(buf: const u8[:], doc: const Node[:], i: i64) -> u32 {
    if is_type(doc, i, ENUMERATION) { let t, ok = as_enum(buf, doc, i); return t; }
    if !is_type(doc, i, STRUCTURE) { return 0; }
    let vendor, vok = child_text(buf, doc, i, TAG_VENDOR_IDENTIFICATION);
    if vok && vendor.len > 0 { return 0; }
    let n, ok = child_text(buf, doc, i, TAG_ATTRIBUTE_NAME);
    if !ok { return 0; }
    return attribute_tag(n);
}

// The Structure form, which some servers (PyKMIP's Delete Attribute) take alone.
fn put_reference_struct(out: u8[>..]&, tag: u32) {
    let s = begin(out, TAG_ATTRIBUTE_REFERENCE);
    put_text(out, TAG_VENDOR_IDENTIFICATION, "");
    put_text(out, TAG_ATTRIBUTE_NAME, attribute_name(tag));
    end(out, s);
}

// --- Changing the list ----------------------------------------------------------

// Removes the k-th attribute with the tag (k -1: all of them); whether
// there was one.
fn remove_attr(a: Attrs&, tag: u32, k: i64) -> bool {
    var kept: u8[>..] = [];
    var at = 0;
    var seen = 0;
    var gone = false;
    while at < a.enc.len {
        let n = item_len(a.enc, at);
        if n < 0 { break; }
        var drop = false;
        if item_tag(a.enc, at) == tag {
            if k < 0 || seen == k { drop = true; }
            seen++;
        }
        if drop { gone = true; } else { kept.append(a.enc[at..at + n]); }
        at += n;
    }
    a.enc.clear();
    a.enc.append(kept);
    return gone;
}

// Puts the item in place of the k-th attribute with its tag, or, when
// there is no such one, at the end.
fn replace_attr(a: Attrs&, item: const u8[:], k: i64) {
    if item.len < 8 { return; }
    let tag = item_tag(item, 0);
    var out: u8[>..] = [];
    var at = 0;
    var seen = 0;
    var done = false;
    while at < a.enc.len {
        let n = item_len(a.enc, at);
        if n < 0 { break; }
        if !done && item_tag(a.enc, at) == tag {
            if seen == k { out.append(item); done = true; } else { out.append(a.enc[at..at + n]); }
            seen++;
        } else {
            out.append(a.enc[at..at + n]);
        }
        at += n;
    }
    if !done { out.append(item); }
    a.enc.clear();
    a.enc.append(out);
}

// Sets an attribute that has one value: all others with its tag go.
fn set_single(a: Attrs&, item: const u8[:]) {
    if item.len < 8 { return; }
    let gone = remove_attr(a, item_tag(item, 0), -1);
    a.enc.append(item);
}

// Whether the list has an attribute equal to item, byte for byte (what
// Locate matches on).
fn has_item(a: const Attrs&, item: const u8[:]) -> bool {
    var found = false;
    each_attr(a) { t, it => if it == item { found = true; } };
    return found;
}
