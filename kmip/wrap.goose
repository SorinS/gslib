// kmip.wrap: wrapped keys. A Key Wrapping Specification (what a Get or
// an Export asks for) and the Key Wrapping Data a wrapped Key Block
// carries read into one Wrapping; wrap_object wraps an object's Key Value
// with the keys it names (Encrypt, MAC/sign, Encrypt then MAC/sign, MAC/sign
// then Encrypt; the Key Value TTLV-encoded with the attributes asked for,
// or its Key Material alone, No Encoding), and unwrap_object undoes it.
// Encryption is by a symmetric key (NIST Key Wrap unless the parameters
// say otherwise: AES Key Wrap with Padding, GCM with its tag after the
// ciphertext, the other modes of kmip.crypto) or an RSA public key (OAEP
// or PKCS #1 v1.5); MACs are HMAC or CMAC, signatures those of
// kmip.crypto. A client unwraps a key a server wrapped with
// unwrap_object and its own copy of the wrapping key.
//
//   var w = kmip::wrapping(kmip::WRAP_ENCRYPT);
//   kmip::wrap_encrypt_key(w, kek_uid);
//   let o, e = kmip::get_wrapped(c, uid, w);        // the client
//   let plain, reason = kmip::unwrap_object(o, kek, kmip::new_object(0));

namespace kmip;

import std;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;
import kmip.formats;
import kmip.crypto;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.x509;
import crypto.x509.keys;

// The key an Encryption Key Information or MAC/Signature Key Information
// names, with the parameters to use it with.
struct KeyInfo {
    uid: u8[..64],
    params: CryptoParams,
    has_params: bool,
}

struct Wrapping {
    method: u32,             // WRAP_ENCRYPT, WRAP_MAC_SIGN, ...
    has_enc: bool,
    enc: KeyInfo,
    has_mac: bool,
    mac: KeyInfo,
    encoding: u32,           // ENCODING_NO_ENCODING or ENCODING_TTLV_ENCODING; 0, TTLV
    mac_sig: u8[..1024],     // Key Wrapping Data's MAC/Signature
    iv: u8[..64],            // its IV/Counter/Nonce
    attr_names: u8[..4096],  // a specification's Attribute Names, their items
}

fn key_info() -> KeyInfo { KeyInfo { uid: [], params: CryptoParams { .. }, has_params: false } }

fn wrapping(method: u32) -> Wrapping {
    Wrapping { method: method, has_enc: false, enc: key_info(), has_mac: false, mac: key_info(), encoding: 0,
               mac_sig: [], iv: [], attr_names: [] }
}

// The key to encrypt with, and its parameters (has_params false: the
// key's own Cryptographic Parameters, else NIST Key Wrap or OAEP).
fn wrap_encrypt_key(w: Wrapping&, uid: const u8[:]) {
    w.has_enc = true;
    w.enc.uid.clear();
    w.enc.uid.append(uid[..::min(uid.len, 64)]);
}

fn wrap_mac_key(w: Wrapping&, uid: const u8[:]) {
    w.has_mac = true;
    w.mac.uid.clear();
    w.mac.uid.append(uid[..::min(uid.len, 64)]);
}

// An attribute to wrap with the key (a TTLV-encoded Key Value only), by
// its 1.x name ("Cryptographic Usage Mask").
fn wrap_attribute(w: Wrapping&, name: const u8[:]) {
    var item: u8[>..] = [];
    put_text(item, TAG_ATTRIBUTE_NAME, name);
    if w.attr_names.len + item.len <= w.attr_names.cap { w.attr_names.append(item); }
}

fn uses_encryption(m: u32) -> bool { m == WRAP_ENCRYPT || m == WRAP_ENCRYPT_THEN_MAC_SIGN || m == WRAP_MAC_SIGN_THEN_ENCRYPT }
fn uses_mac(m: u32) -> bool { m == WRAP_MAC_SIGN || m == WRAP_ENCRYPT_THEN_MAC_SIGN || m == WRAP_MAC_SIGN_THEN_ENCRYPT }

// --- Reading and writing ----------------------------------------------------------

fn read_key_info(buf: const u8[:], doc: const Node[:], i: i64) -> KeyInfo, bool {
    var k = key_info();
    let u, uok = child_text(buf, doc, i, TAG_UNIQUE_IDENTIFIER);
    if !uok || u.len > 64 { return k, false; }
    k.uid.append(u);
    let cp = child(doc, i, TAG_CRYPTOGRAPHIC_PARAMETERS);
    if cp >= 0 {
        let p, pok = read_crypto_params(buf, doc, cp);
        if !pok { return k, false; }
        k.params = p;
        k.has_params = true;
    }
    return k, true;
}

// A Key Wrapping Specification or Key Wrapping Data, at i.
fn read_wrapping(buf: const u8[:], doc: const Node[:], i: i64) -> Wrapping, bool {
    var w = wrapping(0);
    if !is_type(doc, i, STRUCTURE) { return w, false; }
    let m, mok = child_enum(buf, doc, i, TAG_WRAPPING_METHOD);
    if !mok { return w, false; }
    w.method = m;
    let e = child(doc, i, TAG_ENCRYPTION_KEY_INFORMATION);
    if e >= 0 {
        let k, ok = read_key_info(buf, doc, e);
        if !ok { return w, false; }
        w.enc = k;
        w.has_enc = true;
    }
    let s = child(doc, i, TAG_MAC_SIGNATURE_KEY_INFORMATION);
    if s >= 0 {
        let k, ok = read_key_info(buf, doc, s);
        if !ok { return w, false; }
        w.mac = k;
        w.has_mac = true;
    }
    let sig, sok = child_bytes(buf, doc, i, TAG_MAC_SIGNATURE);
    if sok { if sig.len > 1024 { return w, false; } w.mac_sig.append(sig); }
    let iv, ivok = child_bytes(buf, doc, i, TAG_IV_COUNTER_NONCE);
    if ivok { if iv.len > 64 { return w, false; } w.iv.append(iv); }
    let eo, eok = child_enum(buf, doc, i, TAG_ENCODING_OPTION);
    if eok { w.encoding = eo; }
    var bad = false;
    each(doc, i) { k =>
        if doc[k].tag == TAG_ATTRIBUTE_NAME || doc[k].tag == TAG_ATTRIBUTE_REFERENCE {
            let item = raw(buf, doc, k);
            if w.attr_names.len + item.len <= w.attr_names.cap { w.attr_names.append(item); } else { bad = true; }
        }
    };
    return w, !bad;
}

fn put_key_info(out: u8[>..]&, tag: u32, k: const KeyInfo&) {
    let s = begin(out, tag);
    put_text(out, TAG_UNIQUE_IDENTIFIER, k.uid);
    if k.has_params { put_crypto_params(out, k.params); }
    end(out, s);
}

// The Key Wrapping Data of a key wrapped as w says.
fn put_wrapping_data(out: u8[>..]&, w: const Wrapping&) {
    let s = begin(out, TAG_KEY_WRAPPING_DATA);
    put_enum(out, TAG_WRAPPING_METHOD, w.method);
    if w.has_enc { put_key_info(out, TAG_ENCRYPTION_KEY_INFORMATION, w.enc); }
    if w.has_mac { put_key_info(out, TAG_MAC_SIGNATURE_KEY_INFORMATION, w.mac); }
    if w.mac_sig.len > 0 { put_bytes(out, TAG_MAC_SIGNATURE, w.mac_sig); }
    if w.iv.len > 0 { put_bytes(out, TAG_IV_COUNTER_NONCE, w.iv); }
    if w.encoding != 0 { put_enum(out, TAG_ENCODING_OPTION, w.encoding); }
    end(out, s);
}

// The Key Wrapping Specification asking for a key wrapped as w says.
fn put_wrapping_spec(out: u8[>..]&, w: const Wrapping&) {
    let s = begin(out, TAG_KEY_WRAPPING_SPECIFICATION);
    put_enum(out, TAG_WRAPPING_METHOD, w.method);
    if w.has_enc { put_key_info(out, TAG_ENCRYPTION_KEY_INFORMATION, w.enc); }
    if w.has_mac { put_key_info(out, TAG_MAC_SIGNATURE_KEY_INFORMATION, w.mac); }
    out.append(w.attr_names);
    if w.encoding != 0 { put_enum(out, TAG_ENCODING_OPTION, w.encoding); }
    end(out, s);
}

// The Wrapping a wrapped object carries.
fn wrapping_of(o: const Object&) -> Wrapping, bool {
    var doc: Node[>..] = [];
    let r, e = decode(o.wrapping, Options { .. }, doc);
    if e != OK { return wrapping(0), false; }
    let w, ok = read_wrapping(o.wrapping, doc, r);
    return w, ok;
}

// --- The Key Value --------------------------------------------------------------

// What is wrapped: the Key Value Structure, TTLV-encoded, with the
// attributes given (1.x Attribute Structures, or 2.0's Attributes), or
// with No Encoding the Key Material's bytes alone.
fn plain_key_value(o: const Object&, encoding: u32, a: const Attrs&, v: Version, out: u8[>..]&) -> u32 {
    if encoding == ENCODING_NO_ENCODING {
        if is_transparent(o.key_format) || a.enc.len > 0 { return REASON_ENCODING_OPTION_ERROR; }
        out.append(o.material);
        return 0;
    }
    if encoding != 0 && encoding != ENCODING_TTLV_ENCODING { return REASON_ENCODING_OPTION_ERROR; }
    let kv = begin(out, TAG_KEY_VALUE);
    if o.key_format == FMT_TRANSPARENT_SYMMETRIC_KEY {
        let km = begin(out, TAG_KEY_MATERIAL);
        put_bytes(out, TAG_KEY, o.material);
        end(out, km);
    } else if is_transparent(o.key_format) {
        out.append(o.material);
    } else {
        put_bytes(out, TAG_KEY_MATERIAL, o.material);
    }
    if a.enc.len > 0 {
        if is_v2(v) { put_attributes(out, a, TAG_ATTRIBUTES); }
        else { each_attr(a) { t, item => let ok = put_attribute_1x(out, t, item); }; }
    }
    end(out, kv);
    return 0;
}

// The Key Material of a Key Value unwrapped, into o; the attributes it
// carried into a.
fn read_plain_key_value(plain: const u8[:], encoding: u32, o: Object&, a: Attrs&) -> u32 {
    o.material.clear();
    if encoding == ENCODING_NO_ENCODING { o.material.append(plain); return 0; }
    var doc: Node[>..] = [];
    let r, e = decode(plain, Options { .. }, doc);
    if e != OK || doc[r].tag != TAG_KEY_VALUE || !is_type(doc, r, STRUCTURE) { return REASON_CRYPTOGRAPHIC_FAILURE; }
    let km = child(doc, r, TAG_KEY_MATERIAL);
    if is_type(doc, km, BYTE_STRING) { o.material.append(value(plain, doc, km)); }
    else if is_type(doc, km, STRUCTURE) {
        let k = child(doc, km, TAG_KEY);
        if o.key_format == FMT_TRANSPARENT_SYMMETRIC_KEY && is_type(doc, k, BYTE_STRING) { o.material.append(value(plain, doc, k)); }
        else { o.material.append(raw(plain, doc, km)); }
    } else { return REASON_CRYPTOGRAPHIC_FAILURE; }
    let x = read_attrs(plain, doc, r);
    a.enc.append(x.enc);
    return 0;
}

// --- Wrapping -------------------------------------------------------------------

// The parameters a key info carries, else the key's own (given), else
// none: NIST Key Wrap for a symmetric key, OAEP for RSA.
fn wrap_params(k: const KeyInfo&, own: const CryptoParams&, has_own: bool) -> CryptoParams {
    if k.has_params { return k.params; }
    if has_own { return own; }
    return CryptoParams { .. };
}

fn encrypt_with(kek: const Object&, cp: const CryptoParams&, data: const u8[:], w: Wrapping&, out: u8[>..]&) -> u32 {
    if kek.obj_type == OBJ_PUBLIC_KEY { return rsa_crypt(kek, cp, true, data, out); }
    if kek.obj_type != OBJ_SYMMETRIC_KEY { return REASON_INVALID_OBJECT_TYPE; }
    var p = cp;
    if p.mode == 0 { p.mode = MODE_NIST_KEY_WRAP; }
    var s = sym();
    var tag: u8[>..] = [];
    let r = sym_crypt(kek, p, true, data, s, tag, out);
    if r != 0 { return r; }
    w.iv.clear();
    w.iv.append(s.iv);
    out.append(tag);
    return 0;
}

fn decrypt_with(kek: const Object&, cp: const CryptoParams&, data: const u8[:], w: const Wrapping&, out: u8[>..]&) -> u32 {
    if kek.obj_type == OBJ_PRIVATE_KEY { return rsa_crypt(kek, cp, false, data, out); }
    if kek.obj_type != OBJ_SYMMETRIC_KEY { return REASON_INVALID_OBJECT_TYPE; }
    var p = cp;
    if p.mode == 0 { p.mode = MODE_NIST_KEY_WRAP; }
    var s = sym();
    s.iv.append(w.iv);
    var tag: u8[>..] = [];
    var ct = data;
    let aead = p.mode == MODE_GCM || p.mode == MODE_CCM || kek.alg == ALG_CHACHA20_POLY1305;
    if aead {
        let tl: i64 = if p.tag_length > 0 { p.tag_length } else { 16 };
        if data.len < tl { return REASON_CRYPTOGRAPHIC_FAILURE; }
        tag.append(data[data.len - tl..]);
        ct = data[..data.len - tl];
    }
    return sym_crypt(kek, p, false, ct, s, tag, out);
}

fn mac_with(mk: const Object&, cp: const CryptoParams&, data: const u8[:], out: u8[>..]&) -> u32 {
    if mk.obj_type == OBJ_SYMMETRIC_KEY { return sym_mac(mk, cp, data, out); }
    if mk.obj_type == OBJ_PRIVATE_KEY { return sign_with(mk, cp, data, false, out); }
    return REASON_INVALID_OBJECT_TYPE;
}

// The public key object of a private key one (a signature checked with
// the key that made it).
fn public_of(o: const Object&) -> Object, bool {
    let k, ok = private_of(o);
    if !ok { return new_object(0), false; }
    let p = public_key(o.alg, o.length, FMT_X_509, x509::marshal_public_key(k));
    return p, true;
}

fn mac_check(mk: const Object&, cp: const CryptoParams&, data: const u8[:], sig: const u8[:]) -> u32 {
    if mk.obj_type == OBJ_SYMMETRIC_KEY {
        var m: u8[>..] = [];
        let r = sym_mac(mk, cp, data, m);
        if r != 0 { return r; }
        if m.len != sig.len || bignum::ct_eq_bytes(m, sig) != 1 { return REASON_CRYPTOGRAPHIC_FAILURE; }
        return 0;
    }
    var pk = new_object(0);
    if mk.obj_type == OBJ_PRIVATE_KEY {
        var ok = false;
        pk, ok = public_of(mk);
        if !ok { return REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED; }
    } else {
        pk = copy(mk);
    }
    let r, good = verify_with(pk, cp, data, sig, false);
    if r != 0 { return r; }
    return if good { 0 } else { REASON_CRYPTOGRAPHIC_FAILURE };
}

// o with its Key Value wrapped as w says: enc_key and mac_key are the
// keys w names (new_object(0) for one not used), with their own
// Cryptographic Parameters when the specification gives none (has_*);
// a the attributes to wrap with it. 0, or the Result Reason.
fn wrap_object(o: const Object&, w: const Wrapping&, enc_key: const Object&, enc_own: const CryptoParams&, has_enc_own: bool,
               mac_key: const Object&, mac_own: const CryptoParams&, has_mac_own: bool, a: const Attrs&, v: Version) -> Object, u32 {
    var r = copy(o);
    if o.wrapped { return r, REASON_KEY_WRAP_TYPE_NOT_SUPPORTED; }
    if o.obj_type != OBJ_SYMMETRIC_KEY && o.obj_type != OBJ_PRIVATE_KEY && o.obj_type != OBJ_PUBLIC_KEY &&
       o.obj_type != OBJ_SECRET_DATA && o.obj_type != OBJ_SPLIT_KEY {
        return r, REASON_INVALID_OBJECT_TYPE;
    }
    let m = w.method;
    if !uses_encryption(m) && !uses_mac(m) { return r, REASON_BAD_CRYPTOGRAPHIC_PARAMETERS; }
    if uses_encryption(m) != w.has_enc || uses_mac(m) != w.has_mac { return r, REASON_INVALID_FIELD; }
    var plain: u8[>..] = [];
    let pr = plain_key_value(o, w.encoding, a, v, plain);
    if pr != 0 { return r, pr; }
    var out = w;
    out.attr_names.clear();
    out.mac_sig.clear();
    out.iv.clear();
    let ecp = wrap_params(w.enc, enc_own, has_enc_own);
    let mcp = wrap_params(w.mac, mac_own, has_mac_own);
    var value: u8[>..] = [];
    if m == WRAP_ENCRYPT {
        let e = encrypt_with(enc_key, ecp, plain, out, value);
        if e != 0 { return r, e; }
    } else if m == WRAP_MAC_SIGN {
        var sig: u8[>..] = [];
        let e = mac_with(mac_key, mcp, plain, sig);
        if e != 0 { return r, e; }
        if sig.len > 1024 { return r, REASON_INVALID_FIELD; }
        out.mac_sig.append(sig);
        value.append(plain);
    } else if m == WRAP_ENCRYPT_THEN_MAC_SIGN {
        let e = encrypt_with(enc_key, ecp, plain, out, value);
        if e != 0 { return r, e; }
        var sig: u8[>..] = [];
        let e2 = mac_with(mac_key, mcp, value, sig);
        if e2 != 0 { return r, e2; }
        if sig.len > 1024 { return r, REASON_INVALID_FIELD; }
        out.mac_sig.append(sig);
    } else {
        var sig: u8[>..] = [];
        let e = mac_with(mac_key, mcp, plain, sig);
        if e != 0 { return r, e; }
        if sig.len > 1024 { return r, REASON_INVALID_FIELD; }
        out.mac_sig.append(sig);
        let e2 = encrypt_with(enc_key, ecp, plain, out, value);
        if e2 != 0 { return r, e2; }
    }
    r.material.clear();
    r.material.append(value);
    r.wrapped = true;
    r.wrapping.clear();
    var kwd: u8[>..] = [];
    put_wrapping_data(kwd, out);
    if kwd.len > r.wrapping.cap { return r, REASON_INVALID_FIELD; }
    r.wrapping.append(kwd);
    return r, 0;
}

// A wrapped object unwrapped with the keys its Key Wrapping Data names
// (enc_key and mac_key; new_object(0) for one it does not use), with
// their own parameters as for wrap_object; the attributes wrapped with it
// into a. 0, or the Result Reason (Cryptographic Failure when a MAC or
// signature does not match or the unwrapping fails).
fn unwrap_object(o: const Object&, enc_key: const Object&, enc_own: const CryptoParams&, has_enc_own: bool,
                 mac_key: const Object&, mac_own: const CryptoParams&, has_mac_own: bool, a: Attrs&) -> Object, u32 {
    var r = copy(o);
    if !o.wrapped { return r, 0; }
    let w, ok = wrapping_of(o);
    if !ok { return r, REASON_INVALID_FIELD; }
    let m = w.method;
    if uses_encryption(m) != w.has_enc || uses_mac(m) != w.has_mac { return r, REASON_INVALID_FIELD; }
    let ecp = wrap_params(w.enc, enc_own, has_enc_own);
    let mcp = wrap_params(w.mac, mac_own, has_mac_own);
    var plain: u8[>..] = [];
    if m == WRAP_ENCRYPT {
        let e = decrypt_with(enc_key, ecp, o.material, w, plain);
        if e != 0 { return r, e; }
    } else if m == WRAP_MAC_SIGN {
        let e = mac_check(mac_key, mcp, o.material, w.mac_sig);
        if e != 0 { return r, e; }
        plain.append(o.material);
    } else if m == WRAP_ENCRYPT_THEN_MAC_SIGN {
        let e = mac_check(mac_key, mcp, o.material, w.mac_sig);
        if e != 0 { return r, e; }
        let e2 = decrypt_with(enc_key, ecp, o.material, w, plain);
        if e2 != 0 { return r, e2; }
    } else if m == WRAP_MAC_SIGN_THEN_ENCRYPT {
        let e = decrypt_with(enc_key, ecp, o.material, w, plain);
        if e != 0 { return r, e; }
        let e2 = mac_check(mac_key, mcp, plain, w.mac_sig);
        if e2 != 0 { return r, e2; }
    } else {
        return r, REASON_KEY_WRAP_TYPE_NOT_SUPPORTED;
    }
    let pr = read_plain_key_value(plain, w.encoding, r, a);
    if pr != 0 { return r, pr; }
    r.wrapped = false;
    r.wrapping.clear();
    return r, 0;
}

// unwrap_object with one key and the parameters the Key Wrapping Data
// names: the client's common case.
fn unwrap_with(o: const Object&, key: const Object&) -> Object, u32 {
    var a = attrs();
    let none = CryptoParams { .. };
    let w, ok = wrapping_of(o);
    if !ok { return copy(o), REASON_INVALID_FIELD; }
    if uses_mac(w.method) && uses_encryption(w.method) { return copy(o), REASON_INVALID_FIELD; }
    let r, e = unwrap_object(o, key, none, false, key, none, false, a);
    return r, e;
}
