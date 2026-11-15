// xml.enc: XML Encryption 1.1, the core that SAML's EncryptedAssertion,
// EncryptedID and EncryptedAttribute use: an EncryptedData of an element
// or of content, its key in an EncryptedKey (in its KeyInfo, named by a
// RetrievalMethod, or beside it, as SAML puts it), encrypted to an RSA or
// EC key of the recipient's certificate.
//
// Content: AES-GCM (128, 192, 256), and AES-CBC to decrypt only, with
// DecryptOptions.allow_cbc: CBC has no integrity, and a decrypter that
// says whether a ciphertext was well formed is an oracle that gives up the
// plaintext (Jager and Somorovsky, 2011); accept it only from senders
// that cannot be moved to GCM, and only where the plaintext is signed.
// Key transport: RSA-OAEP (rsa-oaep-mgf1p, and xmlenc11's rsa-oaep with
// any of SHA-1/256/384/512 for the digest and for MGF1); RSA PKCS #1
// v1.5 to decrypt only, with allow_rsa15 (Bleichenbacher's attack: the
// key is decrypted with implicit rejection, a random key standing in for
// a bad one, so a padding error looks like a content error, but v1.5 is
// still best refused). Key agreement: ECDH-ES on P-256, P-384 and P-521
// with ConcatKDF and AES key wrap (kw-aes128, -192, -256). Every
// decryption failure is the one error ERR_ENC_DECRYPT.

namespace xml;

import std;
import dictionary;
import base64;
import encoding.xml;
import encoding.xml.dsig;
import crypto.x509;
import crypto.x509.keys;
import crypto.bignum;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import crypto.bignum.aes;
import crypto.bignum.gcm;
import crypto.bignum.modes;
import crypto.bignum.keywrap;
import crypto.bignum.hmac;
import crypto.bignum.ct;
import crypto.bignum.entropy;

let XENC_NS:   const u8[:] = "http://www.w3.org/2001/04/xmlenc#";
let XENC11_NS: const u8[:] = "http://www.w3.org/2009/xmlenc11#";

let URI_TYPE_ELEMENT:       const u8[:] = "http://www.w3.org/2001/04/xmlenc#Element";
let URI_TYPE_CONTENT:       const u8[:] = "http://www.w3.org/2001/04/xmlenc#Content";
let URI_TYPE_ENCRYPTED_KEY: const u8[:] = "http://www.w3.org/2001/04/xmlenc#EncryptedKey";

let URI_AES128_CBC:     const u8[:] = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
let URI_AES192_CBC:     const u8[:] = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
let URI_AES256_CBC:     const u8[:] = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
let URI_AES128_GCM:     const u8[:] = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
let URI_AES192_GCM:     const u8[:] = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
let URI_AES256_GCM:     const u8[:] = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
let URI_RSA_OAEP_MGF1P: const u8[:] = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
let URI_RSA_OAEP:       const u8[:] = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
let URI_RSA_15:         const u8[:] = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
let URI_KW_AES128:      const u8[:] = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
let URI_KW_AES192:      const u8[:] = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
let URI_KW_AES256:      const u8[:] = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
let URI_ECDH_ES:        const u8[:] = "http://www.w3.org/2009/xmlenc11#ECDH-ES";
let URI_CONCAT_KDF:     const u8[:] = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
let URI_MGF1_PREFIX:    const u8[:] = "http://www.w3.org/2009/xmlenc11#mgf1sha";

// Content encryption algorithms.
let ENC_AES128_GCM: i64 = 1;
let ENC_AES192_GCM: i64 = 2;
let ENC_AES256_GCM: i64 = 3;
let ENC_AES128_CBC: i64 = 4;   // decrypt only
let ENC_AES192_CBC: i64 = 5;
let ENC_AES256_CBC: i64 = 6;

// Key transport and agreement.
let KEY_RSA_OAEP_MGF1P: i64 = 1;   // SHA-1 digest (or another, by DigestMethod), MGF1 with SHA-1
let KEY_RSA_OAEP:       i64 = 2;   // xmlenc11: digest and MGF1 hash both chosen
let KEY_RSA_15:         i64 = 3;   // decrypt only
let KEY_ECDH_ES:        i64 = 4;   // with ConcatKDF and AES key wrap

let ERR_ENC_MALFORMED: i64 = 40;   // not laid out as XML Encryption says
let ERR_ENC_ALGORITHM: i64 = 41;   // an algorithm not supported, or not allowed
let ERR_ENC_KEY:       i64 = 42;   // no EncryptedKey to decrypt with this key
let ERR_ENC_DECRYPT:   i64 = 43;   // does not decrypt (one error for every cause)
let ERR_ENC_CONTENT:   i64 = 44;   // decrypts to what is not the XML its Type says

fn enc_error_name(code: i64) -> const u8[:] {
    if code == ERR_ENC_MALFORMED { return "malformed EncryptedData or EncryptedKey"; }
    if code == ERR_ENC_ALGORITHM { return "algorithm not allowed"; }
    if code == ERR_ENC_KEY { return "no key to decrypt with"; }
    if code == ERR_ENC_DECRYPT { return "does not decrypt"; }
    if code == ERR_ENC_CONTENT { return "decrypted content not well formed"; }
    return dsig_error_name(code);
}

struct DecryptOptions {
    allow_cbc:    bool    = false, // AES-CBC content (see the header)
    allow_rsa15:  bool    = false, // RSA PKCS #1 v1.5 key transport (see the header)
    min_rsa_bits: i64     = 2048,
    max_keys:     i64     = 4,    // EncryptedKeys tried: each an RSA or ECDH operation, before any signature
    parse:        Options = Options { .. }, // for the decrypted content
}

fn decrypt_options() -> DecryptOptions { DecryptOptions { .. } }

struct EncryptOptions {
    alg:         i64      = ENC_AES256_GCM,
    key_alg:     i64      = 0,     // 0: RSA-OAEP (mgf1p) for an RSA key, ECDH-ES for an EC key
    oaep_digest: i64      = 160,   // KEY_RSA_OAEP: the digest and MGF1's hash
    oaep_mgf:    i64      = 160,
    kw:          i64      = 256,   // KEY_ECDH_ES: kw-aes128, -192, -256
    kdf_digest:  i64      = 256,   // KEY_ECDH_ES: ConcatKDF's hash
    prefix:      u8[..32] = "xenc",
    ds_prefix:   u8[..32] = "ds",
}

fn encrypt_options() -> EncryptOptions { EncryptOptions { .. } }

// The key length in bytes, and whether it is GCM, of a content algorithm URI.
fn content_alg(uri: const u8[:]) -> i64, i64 {
    if uri == URI_AES128_GCM { return ENC_AES128_GCM, 16; }
    if uri == URI_AES192_GCM { return ENC_AES192_GCM, 24; }
    if uri == URI_AES256_GCM { return ENC_AES256_GCM, 32; }
    if uri == URI_AES128_CBC { return ENC_AES128_CBC, 16; }
    if uri == URI_AES192_CBC { return ENC_AES192_CBC, 24; }
    if uri == URI_AES256_CBC { return ENC_AES256_CBC, 32; }
    return 0, 0;
}

fn content_uri(alg: i64) -> const u8[:] {
    if alg == ENC_AES128_GCM { return URI_AES128_GCM; }
    if alg == ENC_AES192_GCM { return URI_AES192_GCM; }
    if alg == ENC_AES256_GCM { return URI_AES256_GCM; }
    if alg == ENC_AES128_CBC { return URI_AES128_CBC; }
    if alg == ENC_AES192_CBC { return URI_AES192_CBC; }
    if alg == ENC_AES256_CBC { return URI_AES256_CBC; }
    return "";
}

fn content_key_len(alg: i64) -> i64 {
    if alg == ENC_AES128_GCM || alg == ENC_AES128_CBC { return 16; }
    if alg == ENC_AES192_GCM || alg == ENC_AES192_CBC { return 24; }
    return 32;
}

fn kw_len(uri: const u8[:]) -> i64 {
    if uri == URI_KW_AES128 { return 16; }
    if uri == URI_KW_AES192 { return 24; }
    if uri == URI_KW_AES256 { return 32; }
    return 0;
}

fn kw_uri(bits: i64) -> const u8[:] {
    if bits == 128 { return URI_KW_AES128; }
    if bits == 192 { return URI_KW_AES192; }
    return URI_KW_AES256;
}

// --- RSA-OAEP with a digest and an MGF1 hash of its own -----------------------------

// OAEP decoding as bignum's rsa_decrypt_oaep, but with MGF1 over mgf
// rather than the digest's hash, as xmlenc11's rsa-oaep allows. Every check
// is made in constant time and folded into one flag.
fn oaep_decrypt(key: const bignum::RsaPrivateKey&, ct: const u8[:], label: const u8[:], hash: i64, mgf: i64) -> u8[>..], bool {
    var out: u8[>..] = [];
    let k = bignum::rsa_size(key);
    let hl = bignum::hash_len(hash);
    if k < 2 * hl + 2 { return out, false; }
    var em, ok, checked = bignum::rsa_private_raw(key, ct);
    if !ok { return out, false; }
    let dblen = k - hl - 1;
    let sd = em[1..hl + 1];
    let db = em[hl + 1..];
    bignum::mgf1(mgf, sd, db);
    bignum::mgf1(mgf, db, sd);
    let lhash = bignum::hash_bits(hash, label);
    var good = checked & bignum::ct_is_zero_u32(em[0]) & bignum::ct_eq_bytes(db[..hl], lhash);
    var found: u32 = 0;
    var badb:  u32 = 0;
    var start: u32 = 0;
    for i in hl..dblen {
        let b: u32 = db[i];
        let is1 = bignum::ct_eq_u32(b, 1) & (found ^ 1);
        let is0 = bignum::ct_is_zero_u32(b);
        badb = badb | ((found ^ 1) & (is0 ^ 1) & (is1 ^ 1));
        start = bignum::ct_select_u32(bignum::ct_mask(is1), (i + 1) as! u32, start);
        found = found | is1;
    }
    good = good & found & (badb ^ 1);
    if good == 0 { return out, false; }
    let from: i64 = start;
    out.append(db[from..]);
    return out, true;
}

fn oaep_encrypt(key: const bignum::RsaPublicKey&, msg: const u8[:], label: const u8[:], hash: i64, mgf: i64) -> u8[>..], bool {
    let k = bignum::rsa_size(key);
    let hl = bignum::hash_len(hash);
    var em: u8[>..] = [];
    if msg.len > k - 2 * hl - 2 { return em, false; }
    em.resize(k, 0);
    let lhash = bignum::hash_bits(hash, label);
    let dblen = k - hl - 1;
    let db = em[hl + 1..];
    for i in hl { db[i] = lhash[i]; }
    db[dblen - msg.len - 1] = 1;
    for i in msg.len { db[dblen - msg.len + i] = msg[i]; }
    let sd = em[1..hl + 1];
    bignum::random_bytes(sd);
    bignum::mgf1(mgf, db, sd);
    bignum::mgf1(mgf, sd, db);
    let c, ok = bignum::rsa_public_op_ct(key, em);
    return c, ok;
}

// --- ConcatKDF (NIST SP 800-56A, XML Encryption 1.1 §5.4.1) ---------------------------

// The bytes of a ConcatKDFParams attribute: hex of a bit string whose first
// byte is its count of padding bits, which must be 0. Absent is empty.
fn kdf_param(d: const Doc&, el: i64, name: const u8[:], out: u8[>..]&) -> bool {
    let v, has = attr(d, el, name);
    if !has || v.len == 0 { return true; }
    if v.len % 2 != 0 || v.len < 2 { return false; }
    for i in 0..v.len / 2 {
        let hi = ascii::hex_value(v[2 * i]);
        let lo = ascii::hex_value(v[2 * i + 1]);
        if hi < 0 || lo < 0 { return false; }
        if i == 0 { if hi != 0 || lo != 0 { return false; } }
        else { out.push((hi * 16 + lo) as u8); }
    }
    return true;
}

fn concat_kdf(hash: i64, z: const u8[:], other: const u8[:], len: i64) -> u8[>..] {
    var out:     u8[>..] = [];
    var counter: u32     = 1;
    while out.len < len {
        var m: u8[>..] = [];
        m.push((counter >> 24) as! u8);
        m.push((counter >> 16) as! u8);
        m.push((counter >> 8) as! u8);
        m.push(counter as! u8);
        m.append(z);
        m.append(other);
        let h = bignum::hash_bits(hash, m);
        let n = ::min(h.len, len - out.len);
        out.append(h[..n]);
        counter++;
    }
    return out;
}

fn hex_param(out: u8[>..]&, b: const u8[:]) {
    out.append("00");
    for x in b { format_uint(out, x, 16, 2, '0'); }
    to_upper(out);
}

// --- the key of an EncryptedData -----------------------------------------------------

fn curve_uri(kind: i64) -> const u8[:] {
    if kind == x509::KEY_EC_P256 { return "urn:oid:1.2.840.10045.3.1.7"; }
    if kind == x509::KEY_EC_P384 { return "urn:oid:1.3.132.0.34"; }
    if kind == x509::KEY_EC_P521 { return "urn:oid:1.3.132.0.35"; }
    return "";
}

// The EncryptionMethod child of el and its Algorithm, which it must have.
fn method_of(d: const Doc&, el: i64) -> i64, const u8[:] {
    let m = child(d, el, XENC_NS, "EncryptionMethod");
    if m < 0 { return -1, ""; }
    let a, has = attr(d, m, "Algorithm");
    if !has { return -1, ""; }
    return m, a;
}

// The bytes of el's CipherData/CipherValue (a CipherReference is refused).
fn cipher_value(d: const Doc&, el: i64, out: u8[>..]&) -> bool {
    let cd = child(d, el, XENC_NS, "CipherData");
    if cd < 0 || count_children(d, el, XENC_NS, "CipherData") != 1 { return false; }
    let cv = child(d, cd, XENC_NS, "CipherValue");
    if cv < 0 || first_element(d, cd) != cv || next_element(d, cv) >= 0 { return false; }
    return base64_content(d, cv, out);
}

// The hash of a ds:DigestMethod child of el (default when absent; 0 for
// one not supported).
fn digest_child(d: const Doc&, el: i64, default_hash: i64) -> i64 {
    let dm = child(d, el, DSIG_NS, "DigestMethod");
    if dm < 0 { return default_hash; }
    let a, has = attr(d, dm, "Algorithm");
    if !has { return 0; }
    return digest_of_uri(a, true);
}

// The key that ECDH-ES and ConcatKDF agree for an EncryptedKey's
// AgreementMethod `am`, kwlen bytes long.
fn agree_key(d: const Doc&, am: i64, key: const x509::PrivateKey&, kwlen: i64) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let a, has = attr(d, am, "Algorithm");
    if !has || a != URI_ECDH_ES { return none, ERR_ENC_ALGORITHM; }
    if key.kind != x509::KEY_EC_P256 && key.kind != x509::KEY_EC_P384 && key.kind != x509::KEY_EC_P521 { return none, ERR_ENC_KEY; }
    let kdm = child(d, am, XENC11_NS, "KeyDerivationMethod");
    if kdm < 0 { return none, ERR_ENC_MALFORMED; }
    let ka, khas = attr(d, kdm, "Algorithm");
    if !khas || ka != URI_CONCAT_KDF { return none, ERR_ENC_ALGORITHM; }
    let params = child(d, kdm, XENC11_NS, "ConcatKDFParams");
    if params < 0 { return none, ERR_ENC_MALFORMED; }
    let h = digest_child(d, params, 0);
    if h == 0 || h == 160 { return none, ERR_ENC_ALGORITHM; }
    var other: u8[>..] = [];
    if !kdf_param(d, params, "AlgorithmID", other) || !kdf_param(d, params, "PartyUInfo", other)
       || !kdf_param(d, params, "PartyVInfo", other) || !kdf_param(d, params, "SuppPubInfo", other)
       || !kdf_param(d, params, "SuppPrivInfo", other) {
        return none, ERR_ENC_MALFORMED;
    }
    // The originator's ephemeral key: ds:KeyValue/dsig11:ECKeyValue.
    let oki = child(d, am, XENC_NS, "OriginatorKeyInfo");
    if oki < 0 { return none, ERR_ENC_MALFORMED; }
    let kv = child(d, oki, DSIG_NS, "KeyValue");
    if kv < 0 { return none, ERR_ENC_MALFORMED; }
    let eckv = child(d, kv, DSIG11_NS, "ECKeyValue");
    if eckv < 0 { return none, ERR_ENC_MALFORMED; }
    let nc = child(d, eckv, DSIG11_NS, "NamedCurve");
    let pkel = child(d, eckv, DSIG11_NS, "PublicKey");
    if nc < 0 || pkel < 0 { return none, ERR_ENC_MALFORMED; }
    let curi, chas = attr(d, nc, "URI");
    if !chas || curi != curve_uri(key.kind) { return none, ERR_ENC_KEY; }
    var peer: u8[>..] = [];
    if !base64_content(d, pkel, peer) { return none, ERR_ENC_MALFORMED; }
    let curve = x509::curve_of_key(key.kind);
    let z, okz = bignum::ecdh_shared(curve, key.ec_sk[..], peer);
    if !okz { return none, ERR_ENC_DECRYPT; }
    return concat_kdf(h, z, other, kwlen), OK;
}

// Decrypts EncryptedKey ek with key, for content keys of klen bytes.
fn decrypt_key(d: const Doc&, ek: i64, key: const x509::PrivateKey&, klen: i64, o: const DecryptOptions&) -> u8[>..], i64 {
    var cek: u8[>..] = [];
    let m, alg = method_of(d, ek);
    if m < 0 { return cek, ERR_ENC_MALFORMED; }
    var wrapped: u8[>..] = [];
    if !cipher_value(d, ek, wrapped) { return cek, ERR_ENC_MALFORMED; }
    if alg == URI_RSA_OAEP_MGF1P || alg == URI_RSA_OAEP || alg == URI_RSA_15 {
        if key.kind != x509::KEY_RSA { return cek, ERR_ENC_KEY; }
        if bignum::rsa_bits(key.rsa) < o.min_rsa_bits { return cek, ERR_ENC_KEY; }
        if alg == URI_RSA_15 {
            if !o.allow_rsa15 { return cek, ERR_ENC_ALGORITHM; }
            // Implicit rejection: a random key unless the padding is right.
            cek.resize(klen, 0);
            bignum::random_bytes(cek);
            if !bignum::rsa_decrypt_pkcs1_session_key(key.rsa, wrapped, cek) { return cek, ERR_ENC_DECRYPT; }
            return cek, OK;
        }
        let h = digest_child(d, m, 160);
        if h == 0 { return cek, ERR_ENC_ALGORITHM; }
        var mgf = 160;
        if alg == URI_RSA_OAEP {
            let mg = child(d, m, XENC11_NS, "MGF");
            if mg >= 0 {
                let ma, mhas = attr(d, mg, "Algorithm");
                if !mhas || !starts_with(ma, URI_MGF1_PREFIX) { return cek, ERR_ENC_ALGORITHM; }
                let suffix = ma[URI_MGF1_PREFIX.len..];
                mgf = if suffix == "1" { 160 } else if suffix == "224" { 224 } else if suffix == "256" { 256 }
                      else if suffix == "384" { 384 } else if suffix == "512" { 512 } else { 0 };
                if mgf == 0 { return cek, ERR_ENC_ALGORITHM; }
            }
        }
        var label: u8[>..] = [];
        let op = child(d, m, XENC_NS, "OAEPparams");
        if op >= 0 && !base64_content(d, op, label) { return cek, ERR_ENC_MALFORMED; }
        let k, ok = oaep_decrypt(key.rsa, wrapped, label, h, mgf);
        if !ok || k.len != klen { return cek, ERR_ENC_DECRYPT; }
        cek.append(k);
        return cek, OK;
    }
    let kwl = kw_len(alg);
    if kwl > 0 {
        let ki = child(d, ek, DSIG_NS, "KeyInfo");
        if ki < 0 { return cek, ERR_ENC_KEY; }
        let am = child(d, ki, XENC_NS, "AgreementMethod");
        if am < 0 { return cek, ERR_ENC_KEY; }
        let kek, e = agree_key(d, am, key, kwl);
        if e != OK { return cek, e; }
        let k, ok = bignum::aes_key_unwrap(kek, wrapped);
        if !ok || k.len != klen { return cek, ERR_ENC_DECRYPT; }
        cek.append(k);
        return cek, OK;
    }
    return cek, ERR_ENC_ALGORITHM;
}

// The EncryptedKeys that may hold ed's key, in the order tried: in its
// KeyInfo, named by a RetrievalMethod there, then its siblings (SAML's
// EncryptedAssertion holds them beside the EncryptedData). It stops once
// it has more than max (the caller's ERR_LIMIT); the RetrievalMethods'
// IDs are looked up in one pass over the document.
fn candidate_keys(d: const Doc&, ed: i64, max: i64, out: i64[>..<]&) -> bool {
    let ki = child(d, ed, DSIG_NS, "KeyInfo");
    if ki >= 0 {
        var ok = true;
        var methods = 0;
        each_element(d, ki) { c =>
            if out.len > max {
                // Enough: the caller refuses this many.
            } else if is(d, c, XENC_NS, "EncryptedKey") {
                out.push(c);
            } else if is(d, c, DSIG_NS, "RetrievalMethod") {
                let t, th = attr(d, c, "Type");
                let u, uh = attr(d, c, "URI");
                if !th || t != URI_TYPE_ENCRYPTED_KEY || !uh || u.len < 2 || u[0] != '#' || first_element(d, c) >= 0 {
                    ok = false;
                } else {
                    out.push(-2 - c);   // resolved below
                    methods++;
                }
            }
        };
        if !ok { return false; }
        if methods > 0 && !resolve_methods(d, out) { return false; }
    }
    let par = parent(d, ed);
    if par > 0 {
        each_element(d, par) { c =>
            if out.len <= max && c != ed && is(d, c, XENC_NS, "EncryptedKey") {
                var dup = false;
                for x in out { if x == c { dup = true; } }
                if !dup { out.push(c); }
            }
        };
    }
    return true;
}

// Replaces each -2 - RetrievalMethod in keys with the EncryptedKey its URI
// names; false unless each names exactly one attached element, an
// EncryptedKey. The document's IDs are indexed once for all of them.
fn resolve_methods(d: const Doc&, keys: i64[>..<]&) -> bool {
    var ids = dictionary<const u8[:], i64> {};
    var dups = dictionary<const u8[:], bool> {};
    for i in d.nodes.len {
        let n = d.nodes[i];
        if n.kind == ATTRIBUTE && n.is_id && n.parent >= 0 && attached(d, n.parent) {
            let v = view(d, n.value);
            let first = ids.get_or_insert(v, n.parent);
            if first != n.parent { dups.insert(v, true); }
        }
    }
    for j in keys.len {
        if keys[j] < 0 {
            let u, uh = attr(d, -2 - keys[j], "URI");
            let id = u[1..];
            if !ids.contains(id) || dups.contains(id) { return false; }
            let el = ids.get_or_insert(id, -1);
            if !is(d, el, XENC_NS, "EncryptedKey") { return false; }
            keys[j] = el;
        }
    }
    return true;
}

// Decrypts EncryptedData ed with the recipient's private key: the
// plaintext octets and OK, or an error.
fn decrypt(d: const Doc&, ed: i64, key: const x509::PrivateKey&, o: const DecryptOptions&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if !is(d, ed, XENC_NS, "EncryptedData") { return out, ERR_ENC_MALFORMED; }
    let m, uri = method_of(d, ed);
    if m < 0 { return out, ERR_ENC_MALFORMED; }
    let alg, klen = content_alg(uri);
    if alg == 0 { return out, ERR_ENC_ALGORITHM; }
    let gcm = alg == ENC_AES128_GCM || alg == ENC_AES192_GCM || alg == ENC_AES256_GCM;
    if !gcm && !o.allow_cbc { return out, ERR_ENC_ALGORITHM; }
    var ct: u8[>..] = [];
    if !cipher_value(d, ed, ct) { return out, ERR_ENC_MALFORMED; }
    var keys: i64[>..<] = [];
    if !candidate_keys(d, ed, o.max_keys, keys) { return out, ERR_ENC_MALFORMED; }
    if keys.len == 0 { return out, ERR_ENC_KEY; }
    if keys.len > o.max_keys { return out, ERR_LIMIT; }
    var err = ERR_ENC_KEY;
    for ek in keys {
        let cek, e = decrypt_key(d, ek, key, klen, o);
        if e != OK {
            // A key for someone else (another key type) is passed over.
            if e != ERR_ENC_KEY || err == ERR_ENC_KEY { err = e; }
            continue;
        }
        if gcm {
            if ct.len < 12 + 16 { return out, ERR_ENC_DECRYPT; }
            let pt, ok = bignum::aes_gcm_open(cek, ct[..12], "", ct[12..]);
            if !ok { err = ERR_ENC_DECRYPT; continue; }
            out.append(pt);
            return out, OK;
        }
        // CBC: IV, then blocks; ISO 10126 padding, its last byte the count.
        if ct.len < 32 || ct.len % 16 != 0 { return out, ERR_ENC_DECRYPT; }
        let aes = bignum::aes_init(cek);
        var buf: u8[>..] = [];
        buf.append(ct[16..]);
        bignum::cbc_decrypt(aes, ct[..16], buf);
        let padn: i64 = buf[buf.len - 1];
        if padn < 1 || padn > 16 { err = ERR_ENC_DECRYPT; continue; }
        out.append(buf[..buf.len - padn]);
        return out, OK;
    }
    return out, err;
}

fn decrypt(d: const Doc&, ed: i64, key: const x509::PrivateKey&) -> u8[>..], i64 {
    let o = decrypt_options();
    let pt, e = decrypt(d, ed, key, o);
    return pt, e;
}

// Decrypts EncryptedData ed and puts what it held in its place: an element
// (Type Element; the plaintext must be exactly one element) or content,
// parsed with o.parse in the scope of ed's parent (so its prefixes resolve
// as the sender's did, and an ID the document already has is refused).
// The EncryptedData is detached. OK, or an error with d unchanged.
fn decrypt_replace(d: Doc&, ed: i64, key: const x509::PrivateKey&, o: const DecryptOptions&) -> i64 {
    let pt, e = decrypt(d, ed, key, o);
    if e != OK { return e; }
    let t, has_type = attr(d, ed, "Type");
    let element = has_type && t == URI_TYPE_ELEMENT;
    if has_type && !element && t != URI_TYPE_CONTENT { return ERR_ENC_MALFORMED; }
    let par = parent(d, ed);
    if par < 0 { return ERR_ENC_MALFORMED; }
    let before_count = d.nodes.len;
    let first_new = prev_sibling(d, ed);
    let pe = parse_fragment(d, par, ed, pt, o.parse);
    if pe.code != OK { return ERR_ENC_CONTENT; }
    // What the fragment added: the children between first_new and ed.
    var elements = 0;
    var text = false;
    var c = if first_new >= 0 { next_sibling(d, first_new) } else { first_child(d, par) };
    while c >= 0 && c != ed {
        if kind(d, c) == ELEMENT { elements++; }
        else if kind(d, c) == TEXT || kind(d, c) == CDATA { for b in value(d, c) { if !is_space(b) { text = true; } } }
        c = next_sibling(d, c);
    }
    if element && (elements != 1 || text) {
        // Undo: take the new nodes back out.
        var x = if first_new >= 0 { next_sibling(d, first_new) } else { first_child(d, par) };
        while x >= 0 && x != ed { let nx = next_sibling(d, x); detach(d, x); x = nx; }
        return ERR_ENC_CONTENT;
    }
    assert(d.nodes.len >= before_count);
    detach(d, ed);
    return OK;
}

fn decrypt_replace(d: Doc&, ed: i64, key: const x509::PrivateKey&) -> i64 {
    let o = decrypt_options();
    return decrypt_replace(d, ed, key, o);
}

// The xenc:EncryptedData elements of the document, in document order.
fn find_encrypted(d: const Doc&, out: i64[>..<]&) {
    walk(d, 0) { n, entering =>
        if entering && is(d, n, XENC_NS, "EncryptedData") { out.push(n); }
        true
    };
}

// --- encrypting ----------------------------------------------------------------------------

fn x_element(d: Doc&, parent: i64, before: i64, local: const u8[:], o: const EncryptOptions&) -> i64 {
    insert_element(d, parent, before, o.prefix[..], local, XENC_NS)
}

fn x_algorithm(d: Doc&, parent: i64, local: const u8[:], alg: const u8[:], o: const EncryptOptions&) -> i64 {
    let e = x_element(d, parent, -1, local, o);
    set_attr(d, e, "Algorithm", alg);
    return e;
}

fn cipher_data(d: Doc&, parent: i64, bytes: const u8[:], o: const EncryptOptions&) {
    let cd = x_element(d, parent, -1, "CipherData", o);
    let cv = x_element(d, cd, -1, "CipherValue", o);
    var b: u8[>..] = [];
    base64::encode(b, bytes);
    set_text(d, cv, b);
}

fn ds_child(d: Doc&, parent: i64, local: const u8[:], o: const EncryptOptions&) -> i64 {
    insert_element(d, parent, -1, o.ds_prefix[..], local, DSIG_NS)
}

// An EncryptedKey for the content key cek, to cert's key, as the last
// child of parent.
fn encrypted_key(d: Doc&, parent: i64, cek: const u8[:], cert: const x509::Cert&, o: const EncryptOptions&) -> i64 {
    var ka = o.key_alg;
    if ka == 0 { ka = if cert.key_type == x509::KEY_RSA { KEY_RSA_OAEP_MGF1P } else { KEY_ECDH_ES }; }
    let ek = x_element(d, parent, -1, "EncryptedKey", o);
    if ka == KEY_RSA_OAEP_MGF1P || ka == KEY_RSA_OAEP {
        let pub, okp = x509::rsa_public_key(cert);
        if !okp { return ERR_ENC_KEY; }
        let h = if ka == KEY_RSA_OAEP_MGF1P { 160 } else { o.oaep_digest };
        let mgf = if ka == KEY_RSA_OAEP_MGF1P { 160 } else { o.oaep_mgf };
        let m = x_algorithm(d, ek, "EncryptionMethod", if ka == KEY_RSA_OAEP_MGF1P { URI_RSA_OAEP_MGF1P } else { URI_RSA_OAEP }, o);
        let dm = ds_child(d, m, "DigestMethod", o);
        set_attr(d, dm, "Algorithm", digest_uri(h));
        if ka == KEY_RSA_OAEP {
            let mg = insert_element(d, m, -1, "xenc11", "MGF", XENC11_NS);
            set_attr(d, mg, "Algorithm", str(URI_MGF1_PREFIX, if mgf == 160 { 1 } else { mgf }));
        }
        let wrapped, ok = oaep_encrypt(pub, cek, "", h, mgf);
        if !ok { return ERR_ENC_KEY; }
        cipher_data(d, ek, wrapped, o);
        return OK;
    }
    if ka != KEY_ECDH_ES { return ERR_ENC_ALGORITHM; }
    let curi = curve_uri(cert.key_type);
    if curi.len == 0 { return ERR_ENC_KEY; }
    let kb, okb = x509::key_bytes(cert.der, cert.key);
    if !okb { return ERR_ENC_KEY; }
    let curve = x509::curve_of_key(cert.key_type);
    let esk, epk = bignum::ec_keypair(curve);
    let z, okz = bignum::ecdh_shared(curve, esk, kb);
    if !okz { return ERR_ENC_KEY; }
    let kwl = o.kw / 8;
    x_algorithm(d, ek, "EncryptionMethod", kw_uri(o.kw), o);
    let ki = ds_child(d, ek, "KeyInfo", o);
    let am = x_algorithm(d, ki, "AgreementMethod", URI_ECDH_ES, o);
    let kdm = insert_element(d, am, -1, "xenc11", "KeyDerivationMethod", XENC11_NS);
    set_attr(d, kdm, "Algorithm", URI_CONCAT_KDF);
    let params = insert_element(d, kdm, -1, "xenc11", "ConcatKDFParams", XENC11_NS);
    var alg_id: u8[>..] = [];
    hex_param(alg_id, kw_uri(o.kw));
    set_attr(d, params, "AlgorithmID", alg_id);
    set_attr(d, params, "PartyUInfo", "");
    set_attr(d, params, "PartyVInfo", "");
    let pdm = ds_child(d, params, "DigestMethod", o);
    set_attr(d, pdm, "Algorithm", digest_uri(o.kdf_digest));
    let oki = x_element(d, am, -1, "OriginatorKeyInfo", o);
    let kv = ds_child(d, oki, "KeyValue", o);
    let eckv = insert_element(d, kv, -1, "dsig11", "ECKeyValue", DSIG11_NS);
    let nc = insert_element(d, eckv, -1, "dsig11", "NamedCurve", DSIG11_NS);
    set_attr(d, nc, "URI", curi);
    let pk = insert_element(d, eckv, -1, "dsig11", "PublicKey", DSIG11_NS);
    var pb: u8[>..] = [];
    base64::encode(pb, epk);
    set_text(d, pk, pb);
    var other: u8[>..] = [];
    other.append(kw_uri(o.kw));
    let kek = concat_kdf(o.kdf_digest, z, other, kwl);
    let wrapped, okw = bignum::aes_key_wrap(kek, cek);
    if !okw { return ERR_ENC_KEY; }
    cipher_data(d, ek, wrapped, o);
    return OK;
}

// Encrypts element el to cert's key (RSA or EC) and puts an EncryptedData
// (Type Element) in its place, with the EncryptedKey in its KeyInfo; el is
// detached. The EncryptedData and OK, or -1 and an error.
fn encrypt_element(d: Doc&, el: i64, cert: const x509::Cert&, o: const EncryptOptions&) -> i64, i64 {
    if o.alg != ENC_AES128_GCM && o.alg != ENC_AES192_GCM && o.alg != ENC_AES256_GCM { return -1, ERR_ENC_ALGORITHM; }
    if o.key_alg == KEY_RSA_15 { return -1, ERR_ENC_ALGORITHM; }
    if kind(d, el) != ELEMENT || parent(d, el) < 0 { return -1, ERR_ARG; }
    var pt: u8[>..] = [];
    write(d, el, pt);
    var cek: u8[>..] = [];
    cek.resize(content_key_len(o.alg), 0);
    bignum::random_bytes(cek);
    var iv: u8[12] = [0; 12];
    bignum::random_bytes(iv);
    let sealed = bignum::aes_gcm_seal(cek, iv, "", pt);
    var ct: u8[>..] = [];
    ct.append(iv);
    ct.append(sealed);
    let ed = x_element(d, parent(d, el), el, "EncryptedData", o);
    set_attr(d, ed, "Type", URI_TYPE_ELEMENT);
    x_algorithm(d, ed, "EncryptionMethod", content_uri(o.alg), o);
    let ki = ds_child(d, ed, "KeyInfo", o);
    let e = encrypted_key(d, ki, cek, cert, o);
    if e != OK { detach(d, ed); return -1, e; }
    cipher_data(d, ed, ct, o);
    detach(d, el);
    return ed, OK;
}

fn encrypt_element(d: Doc&, el: i64, cert: const x509::Cert&) -> i64, i64 {
    let o = encrypt_options();
    let ed, e = encrypt_element(d, el, cert, o);
    return ed, e;
}
