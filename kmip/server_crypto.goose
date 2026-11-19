// kmip.server_crypto: the server's cryptographic operations: Encrypt and
// Decrypt (kmip.crypto's ciphers with symmetric keys, RSA with key pairs),
// Sign and Signature Verify (on data or its digest), MAC and MAC Verify
// (HMAC, CMAC), Hash, RNG Retrieve and RNG Seed. Each but the RNGs can be
// done in parts (1.3): an Init Indicator opens a stream that a
// Correlation Value names until the Final Indicator.

namespace kmip;

import std;
import entropy;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;
import kmip.formats;
import kmip.crypto;
import kmip.server;
import crypto.bignum;
import crypto.bignum.hmac;
import crypto.bignum.ct;

// The object to use for an operation: there, Active, with the usage.
fn usable(s: const Server&, owner: const u8[:], uid: const u8[:], usage: u32, i: i64&) -> Outcome {
    i = find_object(s, owner, uid);
    if i < 0 { return fail(REASON_ITEM_NOT_FOUND, "no such object"); }
    // Protecting (encrypting, signing, wrapping, making MACs) needs an
    // Active key before its Protect Stop Date; processing (decrypting,
    // verifying, unwrapping) a key past its Process Start Date that is
    // Active, Deactivated or Compromised.
    let protect = (usage & (USAGE_ENCRYPT | USAGE_SIGN | USAGE_WRAP_KEY | USAGE_MAC_GENERATE | USAGE_DERIVE_KEY)) != 0;
    let st = s.objects[i].state;
    let a = attrs_of(s.objects[i]);
    let now = now_of(s);
    if protect {
        if st != STATE_ACTIVE { return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "the object is not Active"); }
        let stop, sok = get_datetime(a, TAG_PROTECT_STOP_DATE);
        if sok && stop <= now { return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "past its Protect Stop Date"); }
    } else {
        if st != STATE_ACTIVE && st != STATE_DEACTIVATED && st != STATE_COMPROMISED {
            return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "the object is not Active");
        }
        let start, sok = get_datetime(a, TAG_PROCESS_START_DATE);
        if sok && start > now { return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "before its Process Start Date"); }
    }
    let m, mok = get_int(a, TAG_CRYPTOGRAPHIC_USAGE_MASK);
    if !mok || ((m as! u32) & usage) == 0 { return fail(REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK, "the usage mask does not allow it"); }
    return done();
}

// Cryptographic Parameters from the request, else the object's.
fn params_of(buf: const u8[:], doc: const Node[:], p: i64, m: const Managed&) -> CryptoParams {
    let at = child(doc, p, TAG_CRYPTOGRAPHIC_PARAMETERS);
    if at >= 0 { let cp, ok = read_crypto_params(buf, doc, at); return cp; }
    let a = attrs_of(m);
    let item = find_attr(a, TAG_CRYPTOGRAPHIC_PARAMETERS, 0);
    if item.len == 0 { return CryptoParams { .. }; }
    let cp, ok = crypto_params_of_item(item);
    return cp;
}

fn reason_text(r: u32) -> const u8[:] {
    if r == REASON_CRYPTOGRAPHIC_FAILURE { return "the cryptography failed (a tag, padding or signature that does not match)"; }
    if r == REASON_BAD_CRYPTOGRAPHIC_PARAMETERS { return "parameters this key does not take"; }
    if r == REASON_INVALID_OBJECT_TYPE { return "not a key for this operation"; }
    if r == REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED { return "a key format not read here"; }
    if r == REASON_MISSING_INITIALIZATION_VECTOR { return "no IV"; }
    if r == REASON_INVALID_FIELD { return "a field of the wrong size"; }
    if r == REASON_ENCODING_OPTION_ERROR { return "that encoding does not hold this key"; }
    if r == REASON_KEY_WRAP_TYPE_NOT_SUPPORTED { return "a wrapping not done here"; }
    return "refused";
}

fn failed(r: u32) -> Outcome { fail(r, reason_text(r)) }

// --- Streams --------------------------------------------------------------------

// The parts of a request that make it one of a stream.
struct Parts { init: bool, fin: bool, corr: u8[..16], streaming: bool }

fn parts_of(buf: const u8[:], doc: const Node[:], p: i64) -> Parts, bool {
    var r = Parts { init: false, fin: false, corr: [], streaming: false };
    let iv, iok = child_bool(buf, doc, p, TAG_INIT_INDICATOR);
    let fv, fok = child_bool(buf, doc, p, TAG_FINAL_INDICATOR);
    let c, cok = child_bytes(buf, doc, p, TAG_CORRELATION_VALUE);
    r.init = iok && iv;
    r.fin = fok && fv;
    if cok {
        if c.len > 16 { return r, false; }
        r.corr.append(c);
    }
    r.streaming = r.init || cok;
    return r, !(r.init && cok);
}

fn find_stream(s: const Server&, owner: const u8[:], op: u32, corr: const u8[:]) -> i64 {
    for k in MAX_STREAMS {
        if s.streams[k].corr.len > 0 && s.streams[k].corr[..] == corr && s.streams[k].op == op && s.streams[k].owner[..] == owner { return k; }
    }
    return -1;
}

// A new stream for owner's op on uid, or -1 when every slot is taken.
fn open_stream(s: Server&, owner: const u8[:], op: u32, uid: const u8[:], cp: const CryptoParams&) -> i64 {
    for k in MAX_STREAMS {
        if s.streams[k].corr.len == 0 {
            s.streams[k] = empty_stream();
            s.streams[k].corr.resize(16, 0);
            entropy::random_bytes(s.streams[k].corr);
            s.streams[k].op = op;
            s.streams[k].owner.append(owner[..::min(owner.len, 128)]);
            s.streams[k].uid.append(uid[..::min(uid.len, 64)]);
            s.streams[k].params = cp;
            return k;
        }
    }
    return -1;
}

fn close_stream(s: Server&, k: i64) { s.streams[k] = empty_stream(); }

fn add_pending(st: Stream&, data: const u8[:]) -> bool {
    if st.pending.len + data.len > st.pending.cap { return false; }
    st.pending.append(data);
    return true;
}

// --- Encrypt and Decrypt --------------------------------------------------------

// A block mode streamed block by block: ECB and CBC.
fn block_streamed(o: const Object&, cp: const CryptoParams&) -> bool {
    let mode = if cp.mode != 0 { cp.mode } else { MODE_CBC };
    return (mode == MODE_ECB || mode == MODE_CBC) && (o.alg == ALG_AES || o.alg == ALG_TRIPLE_DES);
}

fn op_crypt(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&, enc: bool) -> Outcome {
    let op = if enc { OP_ENCRYPT } else { OP_DECRYPT };
    let pt, pok = parts_of(buf, doc, p);
    if !pok { return fail(REASON_INVALID_MESSAGE, "an Init Indicator with a Correlation Value"); }
    var k: i64 = -1;
    var uid: u8[>..] = [];
    if pt.streaming && !pt.init {
        k = find_stream(s, owner, op, pt.corr);
        if k < 0 { return fail(REASON_INVALID_CORRELATION_VALUE, "no such operation in parts"); }
        uid.append(s.streams[k].uid);
    } else {
        uid.append(uid_in(s, buf, doc, p));
    }
    var i: i64 = -1;
    let u = usable(s, owner, uid, if enc { USAGE_ENCRYPT } else { USAGE_DECRYPT }, i);
    if u.reason != 0 { if k >= 0 { close_stream(s, k); } return u; }
    let o, ok = object_of(s.objects[i]);
    if !ok { return fail(REASON_GENERAL_FAILURE, "the object is not readable"); }
    let cp = if k >= 0 { s.streams[k].params } else { params_of(buf, doc, p, s.objects[i]) };
    let data, dok = child_bytes(buf, doc, p, TAG_DATA);
    if !dok && !pt.streaming { return fail(REASON_INVALID_MESSAGE, "no Data"); }
    let given, giv = child_bytes(buf, doc, p, TAG_IV_COUNTER_NONCE);
    let aad, aok = child_bytes(buf, doc, p, TAG_AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA);
    let tag_in, tok = child_bytes(buf, doc, p, TAG_AUTHENTICATED_ENCRYPTION_TAG);
    var res: u8[>..] = [];
    var tag: u8[>..] = [];
    var made: u8[>..] = [];
    // RSA: a public key encrypts, a private one decrypts.
    if o.obj_type == OBJ_PUBLIC_KEY || o.obj_type == OBJ_PRIVATE_KEY {
        if pt.streaming { return fail(REASON_FEATURE_NOT_SUPPORTED, "RSA in parts"); }
        if (o.obj_type == OBJ_PUBLIC_KEY) != enc { return fail(REASON_INVALID_OBJECT_TYPE, "a public key encrypts and a private key decrypts"); }
        let r = rsa_crypt(o, cp, enc, data, res);
        if r != 0 { return failed(r); }
        put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
        put_bytes(out, TAG_DATA, res);
        return done();
    }
    if enc && !pt.streaming {
        let uu = use_up(s, i, data.len);
        if uu.reason != 0 { return uu; }
    }
    if !pt.streaming {
        var sy = sym();
        if giv { if given.len > 64 { return fail(REASON_INVALID_FIELD, "an IV of more than 64 bytes"); } sy.iv.append(given); }
        if aok { sy.aad.append(aad); }
        if tok { tag.append(tag_in); }
        let r = sym_crypt(o, cp, enc, data, sy, tag, res);
        if r != 0 { return failed(r); }
        put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
        put_bytes(out, TAG_DATA, res);
        if sy.made_iv { put_bytes(out, TAG_IV_COUNTER_NONCE, sy.iv); }
        if enc && tag.len > 0 { put_bytes(out, TAG_AUTHENTICATED_ENCRYPTION_TAG, tag); }
        return done();
    }
    // In parts.
    if pt.init {
        k = open_stream(s, owner, op, uid, cp);
        if k < 0 { return fail(REASON_SERVER_LIMIT_EXCEEDED, "too many operations in parts at once"); }
        if giv {
            if given.len > 64 { close_stream(s, k); return fail(REASON_INVALID_FIELD, "an IV of more than 64 bytes"); }
            s.streams[k].iv.append(given);
        } else {
            let mode = if cp.mode != 0 { cp.mode } else { MODE_CBC };
            let need = iv_len_of(o.alg, mode, cp);
            if need > 0 {
                if !enc { close_stream(s, k); return fail(REASON_INVALID_MESSAGE, "no IV"); }
                s.streams[k].iv.resize(need, 0);
                entropy::random_bytes(s.streams[k].iv);
                made.append(s.streams[k].iv);
            }
        }
    }
    if aok {
        if s.streams[k].aad.len + aad.len > 1024 { close_stream(s, k); return fail(REASON_INVALID_FIELD, "too much additional data"); }
        s.streams[k].aad.append(aad);
    }
    if tok {
        if tag_in.len > 16 { close_stream(s, k); return fail(REASON_INVALID_FIELD, "a tag of more than 16 bytes"); }
        s.streams[k].tag.clear();
        s.streams[k].tag.append(tag_in);
    }
    if dok && !add_pending(s.streams[k], data) { close_stream(s, k); return fail(REASON_RESPONSE_TOO_LARGE, "more than 64 KiB pending in an operation in parts"); }
    if block_streamed(o, cp) {
        let bs: i64 = if o.alg == ALG_AES { 16 } else { 8 };
        let mode = if cp.mode != 0 { cp.mode } else { MODE_CBC };
        let padm = if cp.padding != 0 { cp.padding } else { PAD_NONE };
        let have = s.streams[k].pending.len;
        var n = have / bs * bs;
        // Decrypting with padding keeps the last block for the Final part.
        if !pt.fin && !enc && padm != PAD_NONE && n == have && n > 0 { n -= bs; }
        if pt.fin { n = have; }
        if n > 0 || (pt.fin && enc && padm != PAD_NONE) {
            var p2 = cp;
            if !pt.fin { p2.padding = PAD_NONE; }
            var sy = sym();
            sy.iv.append(s.streams[k].iv);
            var chunk: u8[>..] = [];
            chunk.append(s.streams[k].pending[..n]);
            let r = sym_crypt(o, p2, enc, chunk, sy, tag, res);
            if r != 0 { close_stream(s, k); return failed(r); }
            if mode == MODE_CBC && n >= bs {
                // The next part chains from the last ciphertext block.
                s.streams[k].iv.clear();
                if enc { s.streams[k].iv.append(res[res.len - bs..]); } else { s.streams[k].iv.append(chunk[n - bs..]); }
            }
            var rest: u8[>..] = [];
            rest.append(s.streams[k].pending[n..]);
            s.streams[k].pending.clear();
            s.streams[k].pending.append(rest);
        }
    } else if pt.fin {
        var sy = sym();
        sy.iv.append(s.streams[k].iv);
        sy.aad.append(s.streams[k].aad);
        if !enc { tag.append(s.streams[k].tag); }
        var all: u8[>..] = [];
        all.append(s.streams[k].pending);
        let r = sym_crypt(o, cp, enc, all, sy, tag, res);
        if r != 0 { close_stream(s, k); return failed(r); }
    }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    if res.len > 0 { put_bytes(out, TAG_DATA, res); }
    if made.len > 0 { put_bytes(out, TAG_IV_COUNTER_NONCE, made); }
    if pt.fin {
        if enc && tag.len > 0 { put_bytes(out, TAG_AUTHENTICATED_ENCRYPTION_TAG, tag); }
        close_stream(s, k);
    } else {
        put_bytes(out, TAG_CORRELATION_VALUE, s.streams[k].corr);
    }
    return done();
}

// --- Data gathered then done: Sign, Signature Verify, MAC, MAC Verify, Hash ------

// The data of a request, single or the whole of a stream at its Final
// part; false when a part was taken and its response written.
fn gather(s: Server&, owner: const u8[:], op: u32, uid: const u8[:], cp: const CryptoParams&, pt: const Parts&,
          data: const u8[:], whole: u8[>..]&, out: u8[>..]&) -> Outcome, bool {
    var none: u8[>..] = [];
    let r, all = gather_check(s, owner, op, uid, cp, pt, data, "", whole, none, out);
    return r, all;
}

// gather, with the signature or MAC a verification checks: given with
// any part, it is kept until the Final one and handed back in check.
fn gather_check(s: Server&, owner: const u8[:], op: u32, uid: const u8[:], cp: const CryptoParams&, pt: const Parts&,
                data: const u8[:], given: const u8[:], whole: u8[>..]&, check: u8[>..]&, out: u8[>..]&) -> Outcome, bool {
    if !pt.streaming { whole.append(data); check.append(given); return done(), true; }
    var k: i64 = -1;
    if pt.init {
        k = open_stream(s, owner, op, uid, cp);
        if k < 0 { return fail(REASON_SERVER_LIMIT_EXCEEDED, "too many operations in parts at once"), false; }
    } else {
        k = find_stream(s, owner, op, pt.corr);
        if k < 0 { return fail(REASON_INVALID_CORRELATION_VALUE, "no such operation in parts"), false; }
    }
    if !add_pending(s.streams[k], data) { close_stream(s, k); return fail(REASON_RESPONSE_TOO_LARGE, "more than 64 KiB in an operation in parts"), false; }
    if given.len > 0 {
        if given.len > s.streams[k].check.cap { close_stream(s, k); return fail(REASON_INVALID_FIELD, "a signature of more than 1024 bytes"), false; }
        s.streams[k].check.clear();
        s.streams[k].check.append(given);
    }
    if !pt.fin {
        if uid.len > 0 { put_text(out, TAG_UNIQUE_IDENTIFIER, uid); }
        put_bytes(out, TAG_CORRELATION_VALUE, s.streams[k].corr);
        return done(), false;
    }
    whole.append(s.streams[k].pending);
    check.append(s.streams[k].check);
    close_stream(s, k);
    return done(), true;
}

// The object of a keyed operation, by the request's uid or its stream's,
// checked for the usage; the parameters to use (the stream's, else the
// request's or the object's).
fn keyed(s: Server&, owner: const u8[:], op: u32, usage: u32, pt: const Parts&, buf: const u8[:], doc: const Node[:], p: i64,
         i: i64&, cp: CryptoParams&) -> Outcome {
    var uid: u8[>..] = [];
    let cont = pt.streaming && !pt.init;
    if cont {
        let k = find_stream(s, owner, op, pt.corr);
        if k < 0 { return fail(REASON_INVALID_CORRELATION_VALUE, "no such operation in parts"); }
        uid.append(s.streams[k].uid);
        cp = s.streams[k].params;
    } else {
        uid.append(uid_in(s, buf, doc, p));
    }
    let u = usable(s, owner, uid, usage, i);
    if u.reason != 0 { return u; }
    if !cont { cp = params_of(buf, doc, p, s.objects[i]); }
    return done();
}

fn validity(out: u8[>..]&, uid: const u8[:], good: bool) {
    put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
    put_enum(out, TAG_VALIDITY_INDICATOR, if good { VALIDITY_VALID } else { VALIDITY_INVALID });
}

fn op_sign(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let pt, pok = parts_of(buf, doc, p);
    if !pok { return fail(REASON_INVALID_MESSAGE, "an Init Indicator with a Correlation Value"); }
    var i: i64 = -1;
    var cp = CryptoParams { .. };
    let u = keyed(s, owner, OP_SIGN, USAGE_SIGN, pt, buf, doc, p, i, cp);
    if u.reason != 0 { return u; }
    let o, ok = object_of(s.objects[i]);
    if !ok { return fail(REASON_GENERAL_FAILURE, "the object is not readable"); }
    let digest, hok = child_bytes(buf, doc, p, TAG_DIGESTED_DATA);
    let data, dok = child_bytes(buf, doc, p, TAG_DATA);
    var sig: u8[>..] = [];
    if hok && !pt.streaming {
        let r = sign_with(o, cp, digest, true, sig);
        if r != 0 { return failed(r); }
    } else {
        if !dok && !pt.streaming { return fail(REASON_INVALID_MESSAGE, "no Data"); }
        var whole: u8[>..] = [];
        let g, all = gather(s, owner, OP_SIGN, s.objects[i].uid, cp, pt, data, whole, out);
        if g.reason != 0 || !all { return g; }
        let r = sign_with(o, cp, whole, false, sig);
        if r != 0 { return failed(r); }
    }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    put_bytes(out, TAG_SIGNATURE_DATA, sig);
    return done();
}

fn op_verify(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let pt, pok = parts_of(buf, doc, p);
    if !pok { return fail(REASON_INVALID_MESSAGE, "an Init Indicator with a Correlation Value"); }
    var i: i64 = -1;
    var cp = CryptoParams { .. };
    let u = keyed(s, owner, OP_SIGNATURE_VERIFY, USAGE_VERIFY, pt, buf, doc, p, i, cp);
    if u.reason != 0 { return u; }
    let o, ok = object_of(s.objects[i]);
    if !ok { return fail(REASON_GENERAL_FAILURE, "the object is not readable"); }
    let digest, hok = child_bytes(buf, doc, p, TAG_DIGESTED_DATA);
    let data, dok = child_bytes(buf, doc, p, TAG_DATA);
    let sig, sok = child_bytes(buf, doc, p, TAG_SIGNATURE_DATA);
    if hok && !pt.streaming {
        if !sok { return fail(REASON_INVALID_MESSAGE, "no Signature Data"); }
        let r, good = verify_with(o, cp, digest, sig, true);
        if r != 0 { return failed(r); }
        validity(out, s.objects[i].uid, good);
        return done();
    }
    if !pt.streaming && !dok { return fail(REASON_INVALID_MESSAGE, "no Data"); }
    // In parts the signature comes with the Final part.
    var whole: u8[>..] = [];
    var check: u8[>..] = [];
    let g, all = gather_check(s, owner, OP_SIGNATURE_VERIFY, s.objects[i].uid, cp, pt, data, if sok { sig } else { "" }, whole, check, out);
    if g.reason != 0 || !all { return g; }
    if check.len == 0 { return fail(REASON_INVALID_MESSAGE, "no Signature Data"); }
    let r, good = verify_with(o, cp, whole, check, false);
    if r != 0 { return failed(r); }
    validity(out, s.objects[i].uid, good);
    return done();
}

fn op_mac(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let pt, pok = parts_of(buf, doc, p);
    if !pok { return fail(REASON_INVALID_MESSAGE, "an Init Indicator with a Correlation Value"); }
    var i: i64 = -1;
    var cp = CryptoParams { .. };
    let u = keyed(s, owner, OP_MAC, USAGE_MAC_GENERATE, pt, buf, doc, p, i, cp);
    if u.reason != 0 { return u; }
    let o, ok = object_of(s.objects[i]);
    if !ok { return fail(REASON_GENERAL_FAILURE, "the object is not readable"); }
    let data, dok = child_bytes(buf, doc, p, TAG_DATA);
    if !dok && !pt.streaming { return fail(REASON_INVALID_MESSAGE, "no Data"); }
    var whole: u8[>..] = [];
    let g, all = gather(s, owner, OP_MAC, s.objects[i].uid, cp, pt, data, whole, out);
    if g.reason != 0 || !all { return g; }
    var m: u8[>..] = [];
    let r = sym_mac(o, cp, whole, m);
    if r != 0 { return failed(r); }
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    put_bytes(out, TAG_MAC_DATA, m);
    return done();
}

fn op_mac_verify(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let pt, pok = parts_of(buf, doc, p);
    if !pok { return fail(REASON_INVALID_MESSAGE, "an Init Indicator with a Correlation Value"); }
    var i: i64 = -1;
    var cp = CryptoParams { .. };
    let u = keyed(s, owner, OP_MAC_VERIFY, USAGE_MAC_VERIFY, pt, buf, doc, p, i, cp);
    if u.reason != 0 { return u; }
    let o, ok = object_of(s.objects[i]);
    if !ok { return fail(REASON_GENERAL_FAILURE, "the object is not readable"); }
    let data, dok = child_bytes(buf, doc, p, TAG_DATA);
    let mac, mok = child_bytes(buf, doc, p, TAG_MAC_DATA);
    if !pt.streaming && (!dok || !mok) { return fail(REASON_INVALID_MESSAGE, "no Data or MAC Data"); }
    var whole: u8[>..] = [];
    var check: u8[>..] = [];
    let g, all = gather_check(s, owner, OP_MAC_VERIFY, s.objects[i].uid, cp, pt, data, if mok { mac } else { "" }, whole, check, out);
    if g.reason != 0 || !all { return g; }
    if check.len == 0 { return fail(REASON_INVALID_MESSAGE, "no MAC Data"); }
    var m: u8[>..] = [];
    let r = sym_mac(o, cp, whole, m);
    if r != 0 { return failed(r); }
    validity(out, s.objects[i].uid, m.len == check.len && bignum::ct_eq_bytes(m, check) == 1);
    return done();
}

fn op_hash(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let pt, pok = parts_of(buf, doc, p);
    if !pok { return fail(REASON_INVALID_MESSAGE, "an Init Indicator with a Correlation Value"); }
    var cp = CryptoParams { .. };
    if pt.streaming && !pt.init {
        let k = find_stream(s, owner, OP_HASH, pt.corr);
        if k < 0 { return fail(REASON_INVALID_CORRELATION_VALUE, "no such operation in parts"); }
        cp = s.streams[k].params;
    } else {
        let at = child(doc, p, TAG_CRYPTOGRAPHIC_PARAMETERS);
        if at < 0 { return fail(REASON_INVALID_MESSAGE, "no Cryptographic Parameters"); }
        let c, cok = read_crypto_params(buf, doc, at);
        if !cok { return fail(REASON_INVALID_FIELD, "Cryptographic Parameters not read"); }
        cp = c;
    }
    let h = hash_id(cp.hash);
    if h == 0 { return fail(REASON_BAD_CRYPTOGRAPHIC_PARAMETERS, "a Hashing Algorithm not done here"); }
    let data, dok = child_bytes(buf, doc, p, TAG_DATA);
    if !dok && !pt.streaming { return fail(REASON_INVALID_MESSAGE, "no Data"); }
    var whole: u8[>..] = [];
    let g, all = gather(s, owner, OP_HASH, "", cp, pt, data, whole, out);
    if g.reason != 0 || !all { return g; }
    put_bytes(out, TAG_DATA, bignum::hash_bits(h, whole));
    return done();
}

fn op_rng(buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let n, ok = child_int(buf, doc, p, TAG_DATA_LENGTH);
    if !ok || n <= 0 || n > 1048576 { return fail(REASON_INVALID_FIELD, "a Data Length of 1 to 1048576"); }
    var r: u8[>..] = [];
    r.resize(n as i64, 0);
    entropy::random_bytes(r);
    put_bytes(out, TAG_DATA, r);
    return done();
}

// RNG Seed: the operating system's generator takes no seed from a
// client, which KMIP allows: none of it is used.
fn op_rng_seed(buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let d, ok = child_bytes(buf, doc, p, TAG_DATA);
    if !ok { return fail(REASON_INVALID_MESSAGE, "no Data"); }
    put_int(out, TAG_DATA_LENGTH, 0);
    return done();
}
