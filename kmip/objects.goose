// kmip.objects: the managed objects a Register carries and a Get answers
// with, flattened: their type, the format and algorithm of a key, and the
// material as bytes (a symmetric key's, a key in PKCS#1, PKCS#8 or X.509
// SubjectPublicKeyInfo DER, a certificate's DER, a secret, opaque data).
// A Transparent Symmetric Key's Key is taken as its material; the other
// transparent formats keep their Key Material Structure, as it is
// encoded, in material.

namespace kmip;

import std;
import kmip;
import kmip.tables;
import kmip.split;

struct Object {
    obj_type: u32,           // OBJ_SYMMETRIC_KEY, ...
    key_format: u32,         // FMT_RAW, FMT_PKCS_8, ... (keys and secret data)
    alg: u32,                // ALG_AES, ALG_RSA, ... (keys)
    length: i32,             // bits (keys)
    sub_type: u32,           // Certificate Type, Secret Data Type, Opaque Data Type, PGP Key Version
    wrapped: bool,           // the Key Block has Key Wrapping Data: material is wrapped
    wrapping: u8[..4096],    // that Key Wrapping Data, its TTLV as it came
    // A Split Key's (kmip.split): Split Key Parts, Key Part Identifier,
    // Split Key Threshold, Split Key Method, Prime Field Size (big-endian).
    parts: i32,
    part_id: i32,
    threshold: i32,
    split_method: u32,
    prime: u8[..512],
    material: u8[>..],
}

fn new_object(obj_type: u32) -> Object {
    Object { obj_type: obj_type, key_format: 0, alg: 0, length: 0, sub_type: 0, wrapped: false, wrapping: [],
             parts: 0, part_id: 0, threshold: 0, split_method: 0, prime: [], material: [] }
}

// A symmetric key in Raw format.
fn symmetric_key(alg: u32, key: const u8[:]) -> Object {
    var o = new_object(OBJ_SYMMETRIC_KEY);
    o.key_format = FMT_RAW;
    o.alg = alg;
    o.length = (key.len * 8) as! i32;
    o.material.append(key);
    return o;
}

// A private key in PKCS#8 (or, with FMT_PKCS_1, PKCS#1) DER.
fn private_key(alg: u32, bits: i32, format: u32, der: const u8[:]) -> Object {
    var o = new_object(OBJ_PRIVATE_KEY);
    o.key_format = format;
    o.alg = alg;
    o.length = bits;
    o.material.append(der);
    return o;
}

// A public key as an X.509 SubjectPublicKeyInfo (or, with FMT_PKCS_1, an
// RSAPublicKey) in DER.
fn public_key(alg: u32, bits: i32, format: u32, der: const u8[:]) -> Object {
    var o = new_object(OBJ_PUBLIC_KEY);
    o.key_format = format;
    o.alg = alg;
    o.length = bits;
    o.material.append(der);
    return o;
}

fn certificate(der: const u8[:]) -> Object {
    var o = new_object(OBJ_CERTIFICATE);
    o.sub_type = CERT_X_509;
    o.material.append(der);
    return o;
}

// Secret Data: a password (SECRET_PASSWORD) or a seed (SECRET_SEED).
fn secret_data(kind: u32, secret: const u8[:]) -> Object {
    var o = new_object(OBJ_SECRET_DATA);
    o.sub_type = kind;
    o.key_format = FMT_OPAQUE;
    o.material.append(secret);
    return o;
}

// A PGP Key (2.0): an OpenPGP key of the version given (4 for RFC 4880's),
// public or private, as the bytes of its transferable key (binary or
// armored), in Raw format; the algorithm and length are its key's. The
// server keeps it as it came and does no cryptography with it.
fn pgp_key(version: i32, alg: u32, length: i32, key: const u8[:]) -> Object {
    var o = new_object(OBJ_PGP_KEY);
    o.sub_type = version as! u32;
    o.key_format = FMT_RAW;
    o.alg = alg;
    o.length = length;
    o.material.append(key);
    return o;
}

// Opaque Data, of a type KMIP leaves to its users (0x80000000 and up).
fn opaque_data(kind: u32, data: const u8[:]) -> Object {
    var o = new_object(OBJ_OPAQUE_DATA);
    o.sub_type = kind;
    o.material.append(data);
    return o;
}

// The tag of the Structure an object type is written as, or 0.
fn object_tag(obj_type: u32) -> u32 {
    if obj_type == OBJ_SYMMETRIC_KEY { return TAG_SYMMETRIC_KEY; }
    if obj_type == OBJ_PRIVATE_KEY { return TAG_PRIVATE_KEY; }
    if obj_type == OBJ_PUBLIC_KEY { return TAG_PUBLIC_KEY; }
    if obj_type == OBJ_SECRET_DATA { return TAG_SECRET_DATA; }
    if obj_type == OBJ_CERTIFICATE { return TAG_CERTIFICATE; }
    if obj_type == OBJ_OPAQUE_DATA { return TAG_OPAQUE_OBJECT; }
    if obj_type == OBJ_SPLIT_KEY { return TAG_SPLIT_KEY; }
    if obj_type == OBJ_PGP_KEY { return TAG_PGP_KEY; }
    if obj_type == OBJ_CERTIFICATE_REQUEST { return TAG_CERTIFICATE_REQUEST; }
    return 0;
}

// Whether a Key Format Type's Key Material is a Structure (the
// transparent formats); kmip.formats has the conversions.
fn material_is_structure(f: u32) -> bool {
    f == FMT_TRANSPARENT_SYMMETRIC_KEY || (f >= FMT_TRANSPARENT_DSA_PRIVATE_KEY && f <= FMT_TRANSPARENT_ECMQV_PUBLIC_KEY) ||
    f == FMT_TRANSPARENT_EC_PRIVATE_KEY || f == FMT_TRANSPARENT_EC_PUBLIC_KEY
}

fn put_key_block(out: u8[>..]&, o: const Object&) {
    let kb = begin(out, TAG_KEY_BLOCK);
    put_enum(out, TAG_KEY_FORMAT_TYPE, o.key_format);
    if o.wrapped {
        // The Key Value wrapped: a Byte String.
        put_bytes(out, TAG_KEY_VALUE, o.material);
    } else if o.material.len == 0 {
        // None: the material is kept elsewhere, or destroyed.
    } else {
        let kv = begin(out, TAG_KEY_VALUE);
        if o.key_format == FMT_TRANSPARENT_SYMMETRIC_KEY {
            let km = begin(out, TAG_KEY_MATERIAL);
            put_bytes(out, TAG_KEY, o.material);
            end(out, km);
        } else if material_is_structure(o.key_format) {
            out.append(o.material);
        } else {
            put_bytes(out, TAG_KEY_MATERIAL, o.material);
        }
        end(out, kv);
    }
    if o.alg != 0 { put_enum(out, TAG_CRYPTOGRAPHIC_ALGORITHM, o.alg); }
    if o.length != 0 { put_int(out, TAG_CRYPTOGRAPHIC_LENGTH, o.length); }
    if o.wrapped { out.append(o.wrapping); }
    end(out, kb);
}

// Writes the object's Structure (a Symmetric Key, a Certificate, ...).
// False for a type not written here.
fn put_object(out: u8[>..]&, o: const Object&) -> bool {
    if o.obj_type == OBJ_SPLIT_KEY { return put_split_key(out, o); }
    let tag = object_tag(o.obj_type);
    if tag == 0 || o.obj_type == OBJ_CERTIFICATE_REQUEST { return false; }
    let s = begin(out, tag);
    if o.obj_type == OBJ_CERTIFICATE {
        put_enum(out, TAG_CERTIFICATE_TYPE, if o.sub_type != 0 { o.sub_type } else { CERT_X_509 });
        put_bytes(out, TAG_CERTIFICATE_VALUE, o.material);
    } else if o.obj_type == OBJ_OPAQUE_DATA {
        put_enum(out, TAG_OPAQUE_DATA_TYPE, o.sub_type);
        put_bytes(out, TAG_OPAQUE_DATA_VALUE, o.material);
    } else {
        if o.obj_type == OBJ_SECRET_DATA { put_enum(out, TAG_SECRET_DATA_TYPE, o.sub_type); }
        // A PGP Key (2.0): its version, then a Key Block kept as it came.
        if o.obj_type == OBJ_PGP_KEY { put_int(out, TAG_PGP_KEY_VERSION, o.sub_type as! i32); }
        put_key_block(out, o);
    }
    end(out, s);
    return true;
}

fn read_key_block(buf: const u8[:], doc: const Node[:], kb: i64, o: Object&) -> bool {
    let f, fok = child_enum(buf, doc, kb, TAG_KEY_FORMAT_TYPE);
    if !fok { return false; }
    o.key_format = f;
    let a, aok = child_enum(buf, doc, kb, TAG_CRYPTOGRAPHIC_ALGORITHM);
    if aok { o.alg = a; }
    let l, lok = child_int(buf, doc, kb, TAG_CRYPTOGRAPHIC_LENGTH);
    if lok { o.length = l; }
    let kwd = child(doc, kb, TAG_KEY_WRAPPING_DATA);
    o.wrapped = is_type(doc, kwd, STRUCTURE);
    if o.wrapped {
        let w = raw(buf, doc, kwd);
        if w.len > o.wrapping.cap { return false; }
        o.wrapping.append(w);
    }
    let kv = child(doc, kb, TAG_KEY_VALUE);
    // No Key Value: the material is kept elsewhere (Key Value Location).
    if kv < 0 { return true; }
    // A wrapped key's Key Value is a Byte String; otherwise a Structure
    // holding the Key Material.
    if is_type(doc, kv, BYTE_STRING) { o.material.append(value(buf, doc, kv)); return true; }
    let km = child(doc, kv, TAG_KEY_MATERIAL);
    if is_type(doc, km, BYTE_STRING) { o.material.append(value(buf, doc, km)); return true; }
    if is_type(doc, km, STRUCTURE) {
        let k = child(doc, km, TAG_KEY);
        if f == FMT_TRANSPARENT_SYMMETRIC_KEY && is_type(doc, k, BYTE_STRING) { o.material.append(value(buf, doc, k)); }
        else { o.material.append(raw(buf, doc, km)); }
        return true;
    }
    return false;
}

// Reads the object of the given type among the children of a payload
// (a Get's response, a Register's request). False when it is not there
// or not as KMIP writes it.
fn read_object(buf: const u8[:], doc: const Node[:], payload: i64, obj_type: u32) -> Object, bool {
    var o = new_object(obj_type);
    let s = child(doc, payload, object_tag(obj_type));
    if !is_type(doc, s, STRUCTURE) { return o, false; }
    if obj_type == OBJ_SPLIT_KEY { let ok = read_split_key(buf, doc, s, o); return o, ok; }
    if obj_type == OBJ_CERTIFICATE {
        let t, tok = child_enum(buf, doc, s, TAG_CERTIFICATE_TYPE);
        let v, vok = child_bytes(buf, doc, s, TAG_CERTIFICATE_VALUE);
        if !tok || !vok { return o, false; }
        o.sub_type = t;
        o.material.append(v);
        return o, true;
    }
    if obj_type == OBJ_OPAQUE_DATA {
        let t, tok = child_enum(buf, doc, s, TAG_OPAQUE_DATA_TYPE);
        let v, vok = child_bytes(buf, doc, s, TAG_OPAQUE_DATA_VALUE);
        if !tok || !vok { return o, false; }
        o.sub_type = t;
        o.material.append(v);
        return o, true;
    }
    if obj_type == OBJ_SECRET_DATA {
        let t, tok = child_enum(buf, doc, s, TAG_SECRET_DATA_TYPE);
        if !tok { return o, false; }
        o.sub_type = t;
    }
    if obj_type == OBJ_PGP_KEY {
        let v, vok = child_int(buf, doc, s, TAG_PGP_KEY_VERSION);
        if !vok || v < 0 { return o, false; }
        o.sub_type = v as! u32;
    }
    let ok = read_key_block(buf, doc, child(doc, s, TAG_KEY_BLOCK), o);
    return o, ok;
}
