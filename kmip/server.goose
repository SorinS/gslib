// kmip.server: a key manager's pieces and an in-memory one. handle takes
// a request message's bytes and the client's identity (the CN of its TLS
// certificate, as PyKMIP and most servers know their clients) and writes
// the response: each batch item done in order, an item that fails getting
// its Result Reason and Message. Objects belong to who made them and are
// seen by them alone.
//
// What it does: Discover Versions, Query, Create (AES and HMAC keys, and
// secret data), Create Key Pair (RSA, and EC on P-256, P-384 and P-521),
// Register (keys, certificates, secret data, opaque data), Get, Get
// Attributes, Get Attribute List, Add, Set, Modify and Delete Attribute,
// Locate, Activate, Revoke, Destroy, Encrypt and Decrypt (AES: CBC, ECB,
// CTR, GCM), Sign and Signature Verify (RSA PKCS #1 v1.5 and PSS, ECDSA),
// MAC (HMAC) and RNG Retrieve; in KMIP 1.0 to 1.4 and 2.0, each operation
// from the version that brought it. The life cycle is KMIP's: Pre-Active,
// Active, then Deactivated or Compromised; an Active object is not
// destroyed, and a destroyed one is gone.
//
//   var srv = kmip::server();
//   var out: u8[>..] = [];
//   kmip::handle(srv, "alice", request, out);


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
import crypto.bignum;
import crypto.bignum.aes;
import crypto.bignum.modes;
import crypto.bignum.gcm;
import crypto.bignum.hmac;
import crypto.x509;
import crypto.x509.keys;
import encoding.asn1;
import kmip.formats;
import kmip.crypto;
import kmip.wrap;
import kmip.server_manage;
import kmip.server_crypto;
import kmip.server_pki;
import kmip.server_lifecycle;
import kmip.server_session;

// One managed object: what it is, its state, whose it is, and its
// encoding: the object's Structure, then its attributes (2.0's items).
struct Managed {
    uid: u8[..64],
    obj_type: u32,
    state: u32,
    owner: u8[..128],
    archived: bool,            // Archive: kept, but used only once Recovered
    enc: u8[..32768],
}

// A cryptographic operation done in parts (1.3's Correlation Value):
// the key, the parameters, the chaining state, and the data not yet
// processed (ECB and CBC give whole blocks as they come; the others, and
// signatures, MACs and hashes, are done at the Final part).
struct Stream {
    corr: u8[..16],            // empty: the slot is free
    op: u32,
    owner: u8[..128],
    uid: u8[..64],
    params: CryptoParams,
    iv: u8[..64],
    aad: u8[..1024],
    tag: u8[..16],
    check: u8[..1024],         // a signature or MAC to verify, given with any part
    pending: u8[..65536],
}

let MAX_STREAMS: i64 = 4;

struct Server {
    next_id: i64,
    now: i64,                  // the time it says it is, seconds; 0: the clock's
    max_objects: i64,          // 100000
    lease_time: u32,           // the Lease Time objects get, seconds; 3600 (0: none)
    live: i64,                 // objects kept (destroyed ones leave free slots)
    vendor: u8[..64],          // its Vendor Identification
    // The Unique Identifiers of the batch being done: [UID_ID_PLACEHOLDER]
    // is the ID Placeholder, the others what 2.0's Unique Identifier
    // enumeration names (the last Create's, Register's, ...).
    batch_ids: u8[..64][18],
    ca_cert: u8[..16384],      // Certify's and Re-certify's issuer, DER; none: they are refused
    ca_key: u8[..16384],       // its private key, PKCS #8 DER
    streams: Stream[4],
    version: Version,          // of the request being done
    // kmip.server_session's: asynchronous items, tickets, users, policy.
    pending: Pending[8],
    tickets: Ticket[16],
    users: User[8],            // add_user; none: passwords are not checked
    require_auth: bool,        // refuse requests with no valid credential and no TLS identity
    defaults: u8[..8192],      // Set Defaults' Defaults Information, encoded
    constraints: u8[..8192],   // Set Constraints' Constraints, encoded
    groups: u8[..4096],        // the Object Groups known, Text String items; none: any
    log_count: i64,            // Log operations taken
    last_log: u8[..1024],
    endpoint_role: u32,        // ENDPOINT_SERVER
    p11: P11Session[4],
    objects: Managed[>..],
}

fn server() -> Server {
    var s = Server { next_id: 1, now: 0, max_objects: 100000, lease_time: 3600, live: 0, vendor: [], batch_ids: [[]; 18], ca_cert: [], ca_key: [], streams: [empty_stream(); 4], version: Version { major: 1, minor: 0 },
                     pending: [empty_pending(); 8], tickets: [empty_ticket(); 16], users: [empty_user(); 8],
                     require_auth: false, defaults: [], constraints: [], groups: [], log_count: 0, last_log: [],
                     endpoint_role: ENDPOINT_SERVER, p11: [empty_p11(); 4], objects: [] };
    s.vendor.append("gslib kmip");
    return s;
}

fn empty_stream() -> Stream {
    Stream { corr: [], op: 0, owner: [], uid: [], params: CryptoParams { .. }, iv: [], aad: [], tag: [], check: [], pending: [] }
}

fn now_of(s: const Server&) -> i64 { if s.now != 0 { s.now } else { time_ns() / 1000000000 } }

fn object_count(s: const Server&) -> i64 { s.live }

let SUPPORTED: Version[7] = [
    Version { major: 2, minor: 1 }, Version { major: 2, minor: 0 }, Version { major: 1, minor: 4 }, Version { major: 1, minor: 3 },
    Version { major: 1, minor: 2 }, Version { major: 1, minor: 1 }, Version { major: 1, minor: 0 },
];

// The operations it does, and the version each came with.
struct OpVersion { op: u32, since: Version }

let OPERATIONS: OpVersion[57] = [
    OpVersion { op: OP_CREATE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_CREATE_KEY_PAIR, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_REGISTER, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_LOCATE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_GET, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_GET_ATTRIBUTES, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_GET_ATTRIBUTE_LIST, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_ADD_ATTRIBUTE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_MODIFY_ATTRIBUTE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_DELETE_ATTRIBUTE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_ACTIVATE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_REVOKE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_DESTROY, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_QUERY, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_CERTIFY, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_RECERTIFY, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_VALIDATE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_DISCOVER_VERSIONS, since: Version { major: 1, minor: 1 } },
    OpVersion { op: OP_ENCRYPT, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_DECRYPT, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_SIGN, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_SIGNATURE_VERIFY, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_MAC, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_MAC_VERIFY, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_RNG_RETRIEVE, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_RNG_SEED, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_HASH, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_CREATE_SPLIT_KEY, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_JOIN_SPLIT_KEY, since: Version { major: 1, minor: 2 } },
    OpVersion { op: OP_SET_ATTRIBUTE, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_REKEY, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_DERIVE_KEY, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_CHECK, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_OBTAIN_LEASE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_GET_USAGE_ALLOCATION, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_ARCHIVE, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_RECOVER, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_REKEY_KEY_PAIR, since: Version { major: 1, minor: 1 } },
    OpVersion { op: OP_IMPORT, since: Version { major: 1, minor: 4 } },
    OpVersion { op: OP_EXPORT, since: Version { major: 1, minor: 4 } },
    OpVersion { op: OP_ADJUST_ATTRIBUTE, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_INTEROP, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_CANCEL, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_POLL, since: Version { major: 1, minor: 0 } },
    OpVersion { op: OP_LOG, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_LOGIN, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_LOGOUT, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_DELEGATED_LOGIN, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_SET_ENDPOINT_ROLE, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_PKCS_11, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_REPROVISION, since: Version { major: 2, minor: 0 } },
    OpVersion { op: OP_SET_DEFAULTS, since: Version { major: 2, minor: 1 } },
    OpVersion { op: OP_SET_CONSTRAINTS, since: Version { major: 2, minor: 1 } },
    OpVersion { op: OP_GET_CONSTRAINTS, since: Version { major: 2, minor: 1 } },
    OpVersion { op: OP_QUERY_ASYNCHRONOUS_REQUESTS, since: Version { major: 2, minor: 1 } },
    OpVersion { op: OP_PROCESS, since: Version { major: 2, minor: 1 } },
    OpVersion { op: OP_PING, since: Version { major: 2, minor: 1 } },
];

fn supports(op: u32, v: Version) -> bool {
    for o in OPERATIONS {
        if o.op == op && !version_lt(v, o.since) { return true; }
    }
    return false;
}

// --- Outcomes -------------------------------------------------------------------

// What an operation came to: reason 0 for success (the payload is in the
// buffer the operation was given), else the Result Reason and Message.
struct Outcome { reason: u32, msg: const u8[:] }

fn done() -> Outcome { Outcome { reason: 0, msg: "" } }
fn fail(reason: u32, msg: const u8[:]) -> Outcome { Outcome { reason: reason, msg: msg } }

// --- The store ------------------------------------------------------------------

fn find_object(s: const Server&, owner: const u8[:], uid: const u8[:]) -> i64 {
    if uid.len == 0 { return -1; }
    for i in s.objects.len {
        if s.objects[i].obj_type != 0 && s.objects[i].uid[..] == uid && s.objects[i].owner[..] == owner { return i; }
    }
    return -1;
}

fn object_item_of(m: const Managed&) -> const u8[:] {
    let n = item_len(m.enc, 0);
    if n < 0 { return ""; }
    return m.enc[..n];
}

fn attrs_of(m: const Managed&) -> Attrs {
    var a = attrs();
    let n = item_len(m.enc, 0);
    if n >= 0 { a.enc.append(m.enc[n..]); }
    return a;
}

// Stores the object's encoding and its attributes; false when they do
// not fit.
fn store_into(m: Managed&, object: const u8[:], a: const Attrs&) -> bool {
    if object.len + a.enc.len > m.enc.cap { return false; }
    m.enc.clear();
    m.enc.append(object);
    m.enc.append(a.enc);
    return true;
}

fn set_attrs(m: Managed&, a: const Attrs&) -> bool {
    var obj: u8[>..] = [];
    obj.append(object_item_of(m));
    return store_into(m, obj, a);
}

// The object's Object, decoded from what is stored.
fn object_of(m: const Managed&) -> Object, bool {
    var wrap: u8[>..] = [];
    let s = begin(wrap, TAG_RESPONSE_PAYLOAD);
    wrap.append(object_item_of(m));
    end(wrap, s);
    var doc: Node[>..] = [];
    let r, e = decode(wrap, Options { .. }, doc);
    if e != OK { return new_object(0), false; }
    let o, ok = read_object(wrap, doc, r, m.obj_type);
    return o, ok;
}

fn item_of_enum(tag: u32, v: u32) -> u8[>..] { var o: u8[>..] = []; put_enum(o, tag, v); return o; }
fn item_of_int(tag: u32, v: i32) -> u8[>..] { var o: u8[>..] = []; put_int(o, tag, v); return o; }
fn item_of_text(tag: u32, v: const u8[:]) -> u8[>..] { var o: u8[>..] = []; put_text(o, tag, v); return o; }
fn item_of_date(tag: u32, v: i64) -> u8[>..] { var o: u8[>..] = []; put_datetime(o, tag, v); return o; }

fn set_state(s: const Server&, m: Managed&, state: u32, date_tag: u32) -> bool {
    var a = attrs_of(m);
    let st = item_of_enum(TAG_STATE, state);
    set_single(a, st);
    let t = now_of(s);
    if date_tag != 0 { let d = item_of_date(date_tag, t); set_single(a, d); }
    let lc = item_of_date(TAG_LAST_CHANGE_DATE, t);
    set_single(a, lc);
    m.state = state;
    return set_attrs(m, a);
}

// Attributes a client may not give or change: the server's own.
fn server_only(tag: u32) -> bool {
    tag == TAG_UNIQUE_IDENTIFIER || tag == TAG_OBJECT_TYPE || tag == TAG_STATE || tag == TAG_INITIAL_DATE ||
    tag == TAG_LAST_CHANGE_DATE || tag == TAG_DESTROY_DATE ||
    tag == TAG_COMPROMISE_DATE || tag == TAG_COMPROMISE_OCCURRENCE_DATE || tag == TAG_REVOCATION_REASON ||
    tag == TAG_DIGEST || tag == TAG_ALWAYS_SENSITIVE || tag == TAG_NEVER_EXTRACTABLE ||
    tag == TAG_FRESH ||
    tag == TAG_ARCHIVE_DATE || tag == TAG_LEASE_TIME ||
    // A certificate's, from the certificate itself.
    tag == TAG_CERTIFICATE_TYPE || tag == TAG_CERTIFICATE_LENGTH || tag == TAG_CERTIFICATE_IDENTIFIER ||
    tag == TAG_CERTIFICATE_SUBJECT || tag == TAG_CERTIFICATE_ISSUER || tag == TAG_X_509_CERTIFICATE_IDENTIFIER ||
    tag == TAG_X_509_CERTIFICATE_SUBJECT || tag == TAG_X_509_CERTIFICATE_ISSUER || tag == TAG_DIGITAL_SIGNATURE_ALGORITHM
}

// A client's attributes without the ones only the server sets (for an
// operation that takes some of them as input, as Certify does).
fn without_server_only(a: const Attrs&) -> Attrs {
    var r = attrs();
    each_attr(a) { t, item => if !server_only(t) { r.enc.append(item); } };
    return r;
}

// Attributes with more than one value.
fn multi_valued(tag: u32) -> bool {
    tag == TAG_NAME || tag == TAG_OBJECT_GROUP || tag == TAG_APPLICATION_SPECIFIC_INFORMATION ||
    tag == TAG_LINK || tag == TAG_CUSTOM_ATTRIBUTE || tag == TAG_ALTERNATIVE_NAME ||
    tag == TAG_CRYPTOGRAPHIC_PARAMETERS || tag == TAG_CRYPTOGRAPHIC_DOMAIN_PARAMETERS || tag == TAG_ATTRIBUTE
}

// Adds a new object made by owner: its Unique Identifier, and the
// attributes the server keeps (State, dates, type) with the client's.
fn add_object(s: Server&, owner: const u8[:], o: const Object&, client: const Attrs&, uid: u8[>..]&) -> Outcome {
    let none = attrs();
    return add_object_with(s, owner, o, client, none, uid);
}

// add_object with attributes the server sets itself (a certificate's,
// a replacement key's dates), which are taken as they are.
fn add_object_with(s: Server&, owner: const u8[:], o: const Object&, client: const Attrs&, own: const Attrs&,
                   uid: u8[>..]&) -> Outcome {
    if s.live >= s.max_objects { return fail(REASON_SERVER_LIMIT_EXCEEDED, "the store is full"); }
    var obj: u8[>..] = [];
    if !put_object(obj, o) { return fail(REASON_INVALID_OBJECT_TYPE, "an object type not kept here"); }
    var a = attrs();
    uid.clear();
    format_int(uid, s.next_id, 10, 0, ' ');
    s.next_id++;
    let t = now_of(s);
    attr_text(a, TAG_UNIQUE_IDENTIFIER, uid);
    attr_enum(a, TAG_OBJECT_TYPE, o.obj_type);
    if o.alg != 0 { attr_enum(a, TAG_CRYPTOGRAPHIC_ALGORITHM, o.alg); }
    if o.length != 0 { attr_int(a, TAG_CRYPTOGRAPHIC_LENGTH, o.length); }
    attr_enum(a, TAG_STATE, STATE_PRE_ACTIVE);
    attr_datetime(a, TAG_INITIAL_DATE, t);
    attr_datetime(a, TAG_LAST_CHANGE_DATE, t);
    var bad = false;
    each_attr(client) { tag, item =>
        if server_only(tag) {
            // An algorithm and length that say what the object is are fine,
            // as is one the server sets itself here (a certificate's type).
            if !(tag == TAG_CRYPTOGRAPHIC_ALGORITHM || tag == TAG_CRYPTOGRAPHIC_LENGTH || has_attr(own, tag)) { bad = true; }
        } else if tag == TAG_CRYPTOGRAPHIC_ALGORITHM || tag == TAG_CRYPTOGRAPHIC_LENGTH {
        } else if multi_valued(tag) {
            a.enc.append(item);
        } else {
            set_single(a, item);
        }
    };
    if bad { s.next_id--; return fail(REASON_INVALID_FIELD, "an attribute only the server sets"); }
    var dup = false;
    each_attr(a) { tag, item => if tag == TAG_NAME && change_ok(s, owner, -1, item).reason != 0 { dup = true; } };
    if dup { s.next_id--; return fail(REASON_NON_UNIQUE_NAME_ATTRIBUTE, "another object has that Name"); }
    // 2.1's Quantum Safe: only what a quantum computer is not known to
    // break, symmetric keys of 256 bits and more.
    let qs, qok = get_bool(a, TAG_QUANTUM_SAFE);
    if qok && qs && !(o.obj_type == OBJ_SYMMETRIC_KEY && o.material.len >= 32) && !(o.obj_type == OBJ_SECRET_DATA && o.material.len >= 32) {
        s.next_id--;
        return fail(REASON_GENERAL_FAILURE, "NOT_SAFE: not a quantum-safe object");
    }
    each_attr(own) { tag, item => if multi_valued(tag) { a.enc.append(item); } else { set_single(a, item); } };
    server_attrs(s, o, uid, a);
    rotate_on_create(a);
    // 1.4's Sensitive and Extractable, and the server's record of them.
    if !version_lt(s.version, V1_4) {
        let sens, sok = get_bool(a, TAG_SENSITIVE);
        let ext, eok = get_bool(a, TAG_EXTRACTABLE);
        if !sok { attr_bool(a, TAG_SENSITIVE, false); }
        if !eok { attr_bool(a, TAG_EXTRACTABLE, true); }
        attr_bool(a, TAG_ALWAYS_SENSITIVE, sok && sens);
        attr_bool(a, TAG_NEVER_EXTRACTABLE, eok && !ext);
    }
    var m = Managed { uid: [], obj_type: o.obj_type, state: STATE_PRE_ACTIVE, owner: [], archived: false, enc: [] };
    if uid.len > 64 || owner.len > 128 { return fail(REASON_INVALID_FIELD, "owner too long"); }
    m.uid.append(uid);
    m.owner.append(owner);
    if !store_into(m, obj, a) { return fail(REASON_SERVER_LIMIT_EXCEEDED, "the object is too large"); }
    var slot = -1;
    for k in s.objects.len { if slot < 0 && s.objects[k].obj_type == 0 { slot = k; } }
    if slot < 0 { slot = s.objects.len; s.objects.push(m); } else { s.objects[slot] = m; }
    s.live++;
    settle(s, slot);
    return done();
}

// The attributes the server keeps of each object: its Digest (SHA-256 of
// the Key Material, or of a certificate's or opaque object's value;
// symmetric keys and secret data as Raw, the others in the format they
// are kept in), its Short Unique Identifier (2.0: SHA-256 of the Unique
// Identifier), Fresh (1.4: until it is first got) and the Lease Time.
fn server_attrs(s: const Server&, o: const Object&, uid: const u8[:], a: Attrs&) {
    let v = s.version;
    if !o.wrapped && o.material.len > 0 && !has_attr(a, TAG_DIGEST) {
        var d: u8[>..] = [];
        let st = begin(d, TAG_DIGEST);
        put_enum(d, TAG_HASHING_ALGORITHM, HASH_SHA_256);
        put_bytes(d, TAG_DIGEST_VALUE, bignum::hash_bits(256, o.material));
        if o.obj_type == OBJ_SYMMETRIC_KEY || o.obj_type == OBJ_SECRET_DATA { put_enum(d, TAG_KEY_FORMAT_TYPE, FMT_RAW); }
        else if o.obj_type == OBJ_CERTIFICATE { put_enum(d, TAG_KEY_FORMAT_TYPE, FMT_X_509); }
        else if o.key_format != 0 { put_enum(d, TAG_KEY_FORMAT_TYPE, o.key_format); }
        end(d, st);
        a.enc.append(d);
        // A key registered in a transparent format: a digest of that, its
        // TTLV-encoded Key Material, too (4.21).
        if o.key_format == FMT_TRANSPARENT_SYMMETRIC_KEY || (o.key_format != 0 && material_is_structure(o.key_format) && o.obj_type != OBJ_SYMMETRIC_KEY) {
            var km: u8[>..] = [];
            if o.key_format == FMT_TRANSPARENT_SYMMETRIC_KEY {
                let ks = begin(km, TAG_KEY_MATERIAL);
                put_bytes(km, TAG_KEY, o.material);
                end(km, ks);
            } else {
                km.append(o.material);
            }
            var d2: u8[>..] = [];
            let s2 = begin(d2, TAG_DIGEST);
            put_enum(d2, TAG_HASHING_ALGORITHM, HASH_SHA_256);
            put_bytes(d2, TAG_DIGEST_VALUE, bignum::hash_bits(256, km));
            put_enum(d2, TAG_KEY_FORMAT_TYPE, o.key_format);
            end(d2, s2);
            if o.obj_type == OBJ_SYMMETRIC_KEY { a.enc.append(d2); }
        }
    }
    if is_v2(v) && !has_attr(a, TAG_SHORT_UNIQUE_IDENTIFIER) {
        let su = bignum::hash_bits(256, uid);
        attr_bytes(a, TAG_SHORT_UNIQUE_IDENTIFIER, su);
    }
    if !version_lt(v, V1_4) && !has_attr(a, TAG_FRESH) { attr_bool(a, TAG_FRESH, true); }
    // 2.0 has the Key Format Type an attribute too.
    let keyish = o.obj_type == OBJ_SYMMETRIC_KEY || o.obj_type == OBJ_PRIVATE_KEY || o.obj_type == OBJ_PUBLIC_KEY ||
                 o.obj_type == OBJ_SECRET_DATA || o.obj_type == OBJ_SPLIT_KEY;
    if is_v2(v) && keyish && o.key_format != 0 && !has_attr(a, TAG_KEY_FORMAT_TYPE) { attr_enum(a, TAG_KEY_FORMAT_TYPE, o.key_format); }
    if s.lease_time != 0 && !has_attr(a, TAG_LEASE_TIME) { attr_interval(a, TAG_LEASE_TIME, s.lease_time); }
    // A key registered without its Key Value (Key Value Location).
    let has_value = o.material.len > 0 || o.wrapped;
    if !has_value && o.obj_type != OBJ_OPAQUE_DATA && o.obj_type != OBJ_CERTIFICATE && !version_lt(v, V1_2) && !has_attr(a, TAG_KEY_VALUE_PRESENT) {
        attr_bool(a, TAG_KEY_VALUE_PRESENT, false);
    }
    // 2.0's Protection Storage Mask: where it is kept, in software.
    if is_v2(v) && !has_attr(a, TAG_PROTECTION_STORAGE_MASK) { attr_int(a, TAG_PROTECTION_STORAGE_MASK, PSM_SOFTWARE as! i32); }
}

// An object got: no longer Fresh.
fn served(s: Server&, owner: const u8[:], pl: const u8[:]) {
    var doc: Node[>..] = [];
    var wrap: u8[>..] = [];
    let w = begin(wrap, TAG_RESPONSE_PAYLOAD);
    wrap.append(pl);
    end(wrap, w);
    let r, e = decode(wrap, Options { .. }, doc);
    let u, ok = child_text(wrap, doc, r, TAG_UNIQUE_IDENTIFIER);
    if e != OK || !ok { return; }
    let i = find_object(s, owner, u);
    if i < 0 { return; }
    var a = attrs_of(s.objects[i]);
    let f, fok = get_bool(a, TAG_FRESH);
    if !fok || !f { return; }
    let item = item_of_bool(TAG_FRESH, false);
    set_single(a, item);
    let st = set_attrs(s.objects[i], a);
}

fn item_of_bool(tag: u32, v: bool) -> u8[>..] { var o: u8[>..] = []; put_bool(o, tag, v); return o; }

// Whether an attribute may be given to object i (-1: one being made):
// a Name no other object of the owner has (but destroyed ones), and an Activation Date only
// while the object is Pre-Active.
fn change_ok(s: const Server&, owner: const u8[:], i: i64, item: const u8[:]) -> Outcome {
    let t = binary::u32be(item, 0) >> 8;
    if t == TAG_ACTIVATION_DATE && i >= 0 && s.objects[i].state != STATE_PRE_ACTIVE {
        return fail(REASON_WRONG_KEY_LIFECYCLE_STATE, "the Activation Date of an object no longer Pre-Active");
    }
    if t == TAG_NAME {
        for k in s.objects.len {
            let gone = s.objects[k].state == STATE_DESTROYED || s.objects[k].state == STATE_DESTROYED_COMPROMISED;
            if s.objects[k].obj_type != 0 && s.objects[k].owner[..] == owner && !gone {
                let a = attrs_of(s.objects[k]);
                if has_item(a, item) { return fail(REASON_NON_UNIQUE_NAME_ATTRIBUTE, "another object has that Name"); }
            }
        }
    }
    return done();
}

// Usage Limits: what an operation uses up (bytes of data, or one
// object), refused when the limits have less left.
fn use_up(s: Server&, i: i64, bytes: i64) -> Outcome {
    var a = attrs_of(s.objects[i]);
    let ul = find_attr(a, TAG_USAGE_LIMITS, 0);
    if ul.len == 0 { return done(); }
    var doc: Node[>..] = [];
    let r, e = decode(ul, Options { .. }, doc);
    if e != OK { return done(); }
    let total, tok = child_long(ul, doc, r, TAG_USAGE_LIMITS_TOTAL);
    let count, cok = child_long(ul, doc, r, TAG_USAGE_LIMITS_COUNT);
    let unit, uok = child_enum(ul, doc, r, TAG_USAGE_LIMITS_UNIT);
    let left = if cok { count } else if tok { total } else { 0 };
    let need = if uok && unit == LIMITS_BYTE { bytes } else { 1 };
    if need > left { return fail(REASON_PERMISSION_DENIED, "past the object's Usage Limits"); }
    var item: u8[>..] = [];
    let st = begin(item, TAG_USAGE_LIMITS);
    put_long(item, TAG_USAGE_LIMITS_TOTAL, if tok { total } else { left });
    put_long(item, TAG_USAGE_LIMITS_COUNT, left - need);
    put_enum(item, TAG_USAGE_LIMITS_UNIT, if uok { unit } else { LIMITS_OBJECT });
    end(item, st);
    set_single(a, item);
    let ok = set_attrs(s.objects[i], a);
    return done();
}

// What made an object the server generated (1.3's Random Number
// Generator attribute): the operating system's generator, through the
// entropy package, whose algorithm KMIP has no name for.
fn generated(s: const Server&, a: Attrs&) {
    if version_lt(s.version, V1_3) { return; }
    // And when it was made (Original Creation Date).
    if !has_attr(a, TAG_ORIGINAL_CREATION_DATE) { attr_datetime(a, TAG_ORIGINAL_CREATION_DATE, now_of(s)); }
    if has_attr(a, TAG_RANDOM_NUMBER_GENERATOR) { return; }
    let st = begin(a.enc, TAG_RANDOM_NUMBER_GENERATOR);
    put_enum(a.enc, TAG_RNG_ALGORITHM, RNG_UNSPECIFIED);
    end(a.enc, st);
}

// A Result Reason as the version has it: 1.x's list ends at Object
// Already Exists (and General Failure); 2.0's reasons go to the 1.x one
// nearest them.
fn reason_for(r: u32, v: Version) -> u32 {
    // Wrong Key Lifecycle State came with 2.1; 2.0 says Permission Denied.
    if r == REASON_WRONG_KEY_LIFECYCLE_STATE && version_lt(v, V2_1) { return REASON_PERMISSION_DENIED; }
    if is_v2(v) || r <= REASON_OBJECT_ALREADY_EXISTS || r == REASON_GENERAL_FAILURE { return r; }
    if r == REASON_WRONG_KEY_LIFECYCLE_STATE || r == REASON_READ_ONLY_ATTRIBUTE || r == REASON_ATTRIBUTE_READ_ONLY ||
       r == REASON_NOT_AUTHORISED || r == REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK || r == REASON_USAGE_LIMIT_EXCEEDED {
        return REASON_PERMISSION_DENIED;
    }
    if r == REASON_ATTRIBUTE_NOT_FOUND || r == REASON_ATTRIBUTE_INSTANCE_NOT_FOUND || r == REASON_OBJECT_NOT_FOUND ||
       r == REASON_WRAPPING_OBJECT_NOT_FOUND || r == REASON_OBJECT_DESTROYED || r == REASON_WRAPPING_OBJECT_DESTROYED {
        return REASON_ITEM_NOT_FOUND;
    }
    if r == REASON_WRAPPING_OBJECT_ARCHIVED { return REASON_OBJECT_ARCHIVED; }
    if r == REASON_KEY_WRAP_TYPE_NOT_SUPPORTED { return REASON_FEATURE_NOT_SUPPORTED; }
    if r == REASON_MISSING_INITIALIZATION_VECTOR || r == REASON_CODEC_ERROR { return REASON_INVALID_MESSAGE; }
    if r == REASON_SERVER_LIMIT_EXCEEDED || r == REASON_PROTECTION_STORAGE_UNAVAILABLE || r == REASON_INTERNAL_SERVER_ERROR {
        return REASON_GENERAL_FAILURE;
    }
    return REASON_INVALID_FIELD;
}

// The state the object's dates put it in: Active once its Activation
// Date has come, Deactivated once its Deactivation Date has.
fn settle(s: Server&, i: i64) {
    if i < 0 || s.objects[i].obj_type == 0 { return; }
    let st = s.objects[i].state;
    if st != STATE_PRE_ACTIVE && st != STATE_ACTIVE { return; }
    let a = attrs_of(s.objects[i]);
    let now = now_of(s);
    let act, aok = get_datetime(a, TAG_ACTIVATION_DATE);
    let deact, dok = get_datetime(a, TAG_DEACTIVATION_DATE);
    var want = st;
    if st == STATE_PRE_ACTIVE && aok && act <= now { want = STATE_ACTIVE; }
    if (want == STATE_ACTIVE || st == STATE_PRE_ACTIVE) && dok && deact <= now { want = STATE_DEACTIVATED; }
    if want != st { let ok = set_state(s, s.objects[i], want, 0); }
}

// --- Requests' attributes -------------------------------------------------------

// The attributes a payload carries, in either form: 1.x's
// Template-Attribute (or the payload's own Attributes, a Locate's) or
// 2.0's Attributes, under the tags given.
fn payload_attrs(buf: const u8[:], doc: const Node[:], p: i64, tag1: u32, tag2: u32) -> Attrs {
    var a = attrs();
    let t1 = child(doc, p, tag1);
    if t1 >= 0 { let x = read_attrs(buf, doc, t1); a.enc.append(x.enc); }
    // 2.0's are the items themselves, whatever the Structure's tag.
    let t2 = child(doc, p, tag2);
    if is_type(doc, t2, STRUCTURE) && t2 != t1 { each(doc, t2) { c => a.enc.append(raw(buf, doc, c)); }; }
    return a;
}

// The tags a Get Attributes or Delete Attribute names: 1.x Attribute
// Names, 2.0 Attribute References.
// The vendors' attributes a Get Attributes names (1.x names not known
// here, 2.0 Attribute References with a vendor), as vendor-name.
fn named_customs(buf: const u8[:], doc: const Node[:], p: i64) -> u8[..256][>..] {
    var keys: u8[..256][>..] = [];
    each(doc, p) { k =>
        var key: u8[..256] = [];
        if doc[k].tag == TAG_ATTRIBUTE_NAME {
            let n, ok = as_text(buf, doc, k);
            if ok && attribute_tag(n) == 0 && n.len <= 256 { key.append(n); }
        } else if doc[k].tag == TAG_ATTRIBUTE_REFERENCE {
            let c = reference_custom(buf, doc, k);
            if c.len <= 256 { key.append(c); }
        }
        if key.len > 0 { keys.push(key); }
    };
    return keys;
}

fn named_tags(buf: const u8[:], doc: const Node[:], p: i64) -> u32[>..] {
    var tags: u32[>..] = [];
    each(doc, p) { k =>
        if doc[k].tag == TAG_ATTRIBUTE_NAME {
            let n, ok = as_text(buf, doc, k);
            let t = if ok { attribute_tag(n) } else { 0 };
            tags.push(t);
        } else if doc[k].tag == TAG_ATTRIBUTE_REFERENCE {
            tags.push(reference_tag(buf, doc, k));
        }
    };
    return tags;
}

// The object a request names: its Unique Identifier, or in 2.0 an
// enumeration naming one of the batch's (the ID Placeholder, the last
// Create's, ...); none means the ID Placeholder.
fn uid_in(s: const Server&, buf: const u8[:], doc: const Node[:], p: i64) -> const u8[:] {
    let k = child(doc, p, TAG_UNIQUE_IDENTIFIER);
    if k < 0 { return s.batch_ids[UID_ID_PLACEHOLDER]; }
    let u, ok = as_text(buf, doc, k);
    if ok { return u; }
    let e, eok = as_enum(buf, doc, k);
    if eok && e > 0 && e < 18 { return s.batch_ids[e]; }
    return "";
}

fn keep_id(s: Server&, which: u32, uid: const u8[:]) {
    s.batch_ids[which].clear();
    s.batch_ids[which].append(uid[..::min(uid.len, 64)]);
}

// After an item done: the Unique Identifiers it returned, for the ones
// after it in the batch.
fn note_ids(s: Server&, op: u32, pl: const u8[:]) {
    var doc: Node[>..] = [];
    var wrap: u8[>..] = [];
    let w = begin(wrap, TAG_RESPONSE_PAYLOAD);
    wrap.append(pl);
    end(wrap, w);
    let r, e = decode(wrap, Options { .. }, doc);
    if e != OK { return; }
    let u, uok = child_text(wrap, doc, r, TAG_UNIQUE_IDENTIFIER);
    let pv, pvok = child_text(wrap, doc, r, TAG_PRIVATE_KEY_UNIQUE_IDENTIFIER);
    let pu, puok = child_text(wrap, doc, r, TAG_PUBLIC_KEY_UNIQUE_IDENTIFIER);
    if op == OP_CREATE_KEY_PAIR || op == OP_REKEY_KEY_PAIR {
        if !pvok || !puok { return; }
        let base = if op == OP_CREATE_KEY_PAIR { UID_CREATE_KEY_PAIR } else { UID_REKEY_KEY_PAIR };
        keep_id(s, base, pv);
        keep_id(s, base + 1, pv);
        keep_id(s, base + 2, pu);
        keep_id(s, UID_ID_PLACEHOLDER, pv);
        return;
    }
    if op == OP_LOCATE {
        if count(doc, r, TAG_UNIQUE_IDENTIFIER) == 1 && uok { keep_id(s, UID_LOCATE, u); keep_id(s, UID_ID_PLACEHOLDER, u); }
        else { s.batch_ids[UID_ID_PLACEHOLDER].clear(); }
        return;
    }
    if !uok { return; }
    var which: u32 = 0;
    if op == OP_CREATE { which = UID_CREATE; }
    else if op == OP_REGISTER { which = UID_REGISTER; }
    else if op == OP_DERIVE_KEY { which = UID_DERIVE_KEY; }
    else if op == OP_REKEY { which = UID_REKEY; }
    else if op == OP_CERTIFY { which = UID_CERTIFY; }
    else if op == OP_RECERTIFY { which = UID_RECERTIFY; }
    else if op == OP_CREATE_SPLIT_KEY { which = UID_CREATE_SPLIT_KEY; }
    else if op == OP_JOIN_SPLIT_KEY { which = UID_JOIN_SPLIT_KEY; }
    else if op == OP_IMPORT { which = UID_IMPORT; }
    else if op == OP_EXPORT { keep_id(s, UID_ID_PLACEHOLDER, u); }
    if which != 0 { keep_id(s, which, u); }
    if which != 0 || op == OP_RECOVER { keep_id(s, UID_ID_PLACEHOLDER, u); }
}

// --- Requests -------------------------------------------------------------------

fn process(s: Server&, owner: const u8[:], v: Version, op: u32, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    if !supports(op, v) { return fail(REASON_OPERATION_NOT_SUPPORTED, "not an operation of this server in this version"); }
    let empty_ok = op == OP_QUERY || op == OP_DISCOVER_VERSIONS || op == OP_PING || op == OP_GET_CONSTRAINTS ||
                   op == OP_QUERY_ASYNCHRONOUS_REQUESTS || op == OP_SET_DEFAULTS || op == OP_SET_CONSTRAINTS ||
                   op == OP_REPROVISION || op == OP_LOGIN;
    if p < 0 && !empty_ok { return fail(REASON_INVALID_MESSAGE, "no Request Payload"); }
    if op == OP_PING { return done(); }
    if op == OP_LOGIN { return op_login(s, owner, buf, doc, p, out, false); }
    if op == OP_DELEGATED_LOGIN { return op_login(s, owner, buf, doc, p, out, true); }
    if op == OP_LOGOUT { return op_logout(s, owner, buf, doc, p, out); }
    if op == OP_PROCESS { return op_process(s, owner, buf, doc, p, out); }
    if op == OP_CANCEL { return op_cancel(s, owner, buf, doc, p, out); }
    if op == OP_QUERY_ASYNCHRONOUS_REQUESTS { return op_query_async(s, owner, buf, doc, p, out); }
    if op == OP_LOG { return op_log(s, buf, doc, p, out); }
    if op == OP_SET_ENDPOINT_ROLE { return op_set_endpoint_role(s, buf, doc, p, out); }
    if op == OP_REPROVISION { return op_reprovision(s, owner, v, buf, doc, p, out); }
    if op == OP_PKCS_11 { return op_pkcs11(s, owner, buf, doc, p, out); }
    if op == OP_SET_DEFAULTS { return op_set_defaults(s, buf, doc, p, out); }
    if op == OP_SET_CONSTRAINTS { return op_set_constraints(s, buf, doc, p, out); }
    if op == OP_GET_CONSTRAINTS { return op_get_constraints(s, out); }
    if op == OP_DISCOVER_VERSIONS { return op_discover(buf, doc, p, out); }
    if op == OP_INTEROP { return op_interop(buf, doc, p, out); }
    // The object named: its state brought up to its dates, and an archived
    // one used only to be found, read about, recovered or destroyed.
    if p >= 0 && op != OP_IMPORT {
        let ti = find_object(s, owner, uid_in(s, buf, doc, p));
        settle(s, ti);
        if ti >= 0 && s.objects[ti].archived && op != OP_RECOVER && op != OP_GET_ATTRIBUTES &&
           op != OP_GET_ATTRIBUTE_LIST && op != OP_LOCATE && op != OP_DESTROY {
            return fail(REASON_OBJECT_ARCHIVED, "the object is archived; Recover it first");
        }
    }
    if op == OP_QUERY { return op_query_all(s, v, buf, doc, p, out); }
    if op == OP_CREATE { return op_create(s, owner, v, buf, doc, p, out); }
    if op == OP_CREATE_KEY_PAIR { return op_create_key_pair(s, owner, v, buf, doc, p, out); }
    if op == OP_REGISTER { return op_register(s, owner, v, buf, doc, p, out); }
    if op == OP_GET { return op_get(s, owner, v, buf, doc, p, out, false); }
    if op == OP_EXPORT { return op_get(s, owner, v, buf, doc, p, out, true); }
    if op == OP_GET_ATTRIBUTES { return op_get_attributes(s, owner, v, buf, doc, p, out); }
    if op == OP_GET_ATTRIBUTE_LIST { return op_get_attribute_list(s, owner, v, buf, doc, p, out); }
    if op == OP_ADD_ATTRIBUTE { return op_add_attribute(s, owner, v, buf, doc, p, out, false); }
    if op == OP_SET_ATTRIBUTE { return op_add_attribute(s, owner, v, buf, doc, p, out, true); }
    if op == OP_MODIFY_ATTRIBUTE { return op_modify_attribute(s, owner, v, buf, doc, p, out); }
    if op == OP_DELETE_ATTRIBUTE { return op_delete_attribute(s, owner, v, buf, doc, p, out); }
    if op == OP_LOCATE { return op_locate(s, owner, v, buf, doc, p, out); }
    if op == OP_ACTIVATE { return op_activate(s, owner, buf, doc, p, out); }
    if op == OP_REVOKE { return op_revoke(s, owner, buf, doc, p, out); }
    if op == OP_DESTROY { return op_destroy(s, owner, buf, doc, p, out); }
    if op == OP_ENCRYPT { return op_crypt(s, owner, buf, doc, p, out, true); }
    if op == OP_DECRYPT { return op_crypt(s, owner, buf, doc, p, out, false); }
    if op == OP_MAC { return op_mac(s, owner, buf, doc, p, out); }
    if op == OP_MAC_VERIFY { return op_mac_verify(s, owner, buf, doc, p, out); }
    if op == OP_HASH { return op_hash(s, owner, buf, doc, p, out); }
    if op == OP_RNG_SEED { return op_rng_seed(buf, doc, p, out); }
    if op == OP_REKEY { return op_rekey(s, owner, v, buf, doc, p, out); }
    if op == OP_REKEY_KEY_PAIR { return op_rekey_key_pair(s, owner, v, buf, doc, p, out); }
    if op == OP_DERIVE_KEY { return op_derive_key(s, owner, v, buf, doc, p, out); }
    if op == OP_CHECK { return op_check(s, owner, v, buf, doc, p, out); }
    if op == OP_OBTAIN_LEASE { return op_obtain_lease(s, owner, v, buf, doc, p, out); }
    if op == OP_GET_USAGE_ALLOCATION { return op_get_usage_allocation(s, owner, v, buf, doc, p, out); }
    if op == OP_ARCHIVE { return op_archive(s, owner, buf, doc, p, out, true); }
    if op == OP_RECOVER { return op_archive(s, owner, buf, doc, p, out, false); }
    if op == OP_IMPORT { return op_import(s, owner, v, buf, doc, p, out); }
    if op == OP_ADJUST_ATTRIBUTE { return op_adjust_attribute(s, owner, v, buf, doc, p, out); }
    if op == OP_SIGN { return op_sign(s, owner, buf, doc, p, out); }
    if op == OP_SIGNATURE_VERIFY { return op_verify(s, owner, buf, doc, p, out); }
    if op == OP_RNG_RETRIEVE { return op_rng(buf, doc, p, out); }
    if op == OP_CERTIFY { return op_certify(s, owner, v, buf, doc, p, out); }
    if op == OP_RECERTIFY { return op_recertify(s, owner, v, buf, doc, p, out); }
    if op == OP_VALIDATE { return op_validate(s, owner, v, buf, doc, p, out); }
    if op == OP_CREATE_SPLIT_KEY { return op_create_split_key(s, owner, v, buf, doc, p, out); }
    if op == OP_JOIN_SPLIT_KEY { return op_join_split_key(s, owner, v, buf, doc, p, out); }
    return fail(REASON_OPERATION_NOT_SUPPORTED, "not an operation of this server");
}

// A response of one failed item, for a request that could not be read.
fn refuse(s: const Server&, v: Version, reason: u32, msg: const u8[:], out: u8[>..]&) {
    out.clear();
    let m = begin_response(out, v, now_of(s), 1);
    let it, p = begin_result(out, 0, "", STATUS_OPERATION_FAILED, reason, msg);
    end_result(out, it, p);
    end(out, m);
}

// Answers a request message from the client known as owner (its TLS
// certificate's CN, or "" for one not told apart), writing the response
// into out. Each item is done in order; after one fails the rest are
// left out when the request asks to stop (the default) and done when it
// asks to continue.
fn handle(s: Server&, owner: const u8[:], req: const u8[:], out: u8[>..]&) {
    out.clear();
    var doc: Node[>..] = [];
    let root, e = decode(req, Options { .. }, doc);
    if e != OK { refuse(s, V1_0, REASON_INVALID_MESSAGE, "the request is not TTLV", out); return; }
    let r, pe = parse_request(req, doc, root);
    if pe != OK { refuse(s, V1_0, REASON_INVALID_MESSAGE, "not a request message", out); return; }
    var v = r.version;
    s.version = v;
    var known = false;
    for x in SUPPORTED { if version_eq(x, v) { known = true; } }
    if !known {
        refuse(s, V1_0, REASON_UNSUPPORTED_PROTOCOL_VERSION, "a protocol version this server does not speak", out);
        return;
    }
    for k in 18 { s.batch_ids[k].clear(); }
    // Who the request acts as: the TLS identity, or a ticket's or user's.
    let who = authenticate(s, owner, req, r);
    var me: u8[>..] = [];
    me.append(who.owner);
    let delegated = who.ticket >= 0 && s.tickets[who.ticket].delegated;
    // Undo puts the store back as it was before the batch when an item
    // fails, and reports the items done before it as undone.
    let undo = r.batch_continue == BATCH_UNDO;
    var snap: Managed[>..] = [];
    let snap_next = s.next_id;
    let snap_live = s.live;
    if undo { snap = copy(s.objects); }
    var items: u8[>..] = [];
    var done_ops: u32[>..] = [];
    var done_at: i64[>..] = [];       // each done item's id and payload: offsets into done_buf
    var done_buf: u8[>..] = [];
    var n: i32 = 0;
    var stopped = false;
    for it in r.items {
        if stopped { break; }
        var pl: u8[>..] = [];
        let id = request_item_id(req, it);
        var res = done();
        if who.reason != 0 {
            res = fail(who.reason, who.msg);
        } else if delegated && (it.op == OP_LOGIN || it.op == OP_DELEGATED_LOGIN ||
                                !rights_allow(s.tickets[who.ticket].rights, it.op, if it.payload >= 0 { uid_in(s, req, doc, it.payload) } else { "" })) {
            res = fail(REASON_NOT_AUTHORISED, "DENIED");
        } else if it.op == OP_POLL && supports(OP_POLL, v) {
            // The item polled for, written as its own.
            if poll_item(s, me, v, req, doc, it.payload, id, items) { n++; continue; }
            res = fail(REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE, "DENIED");
        } else if r.async_ind == ASYNC_MANDATORY && deferrable(it.op) && supports(it.op, v) {
            let k = defer_item(s, me, v, it.op, id, req, doc, it.payload);
            if k >= 0 { put_pending_item(items, it.op, id, s.pending[k].corr); n++; continue; }
            res = process(s, me, v, it.op, req, doc, it.payload, pl);
        } else {
            res = process(s, me, v, it.op, req, doc, it.payload, pl);
        }
        // Maximum Response Size: an answer that would not fit fails.
        if res.reason == 0 && r.max_response_size > 0 && items.len + pl.len + 96 > r.max_response_size {
            res = fail(REASON_RESPONSE_TOO_LARGE, "TOO_LARGE");
        }
        if res.reason == 0 {
            if it.op == OP_PROCESS { process_after(s, me, req, doc, it.payload); }
            if it.op == OP_GET || it.op == OP_EXPORT { served(s, me, pl); }
            note_ids(s, it.op, pl);
            let b, p = begin_result(items, it.op, id, STATUS_SUCCESS, 0, "");
            items.append(pl);
            end_result(items, b, p);
            if undo {
                done_ops.push(it.op);
                done_at.push(done_buf.len);
                done_buf.append(id);
                done_at.push(done_buf.len);
                done_buf.append(pl);
                done_at.push(done_buf.len);
            }
        } else {
            if undo {
                // The store only grows in a batch: slots back as they were,
                // the ones added since freed.
                var k0 = 0;
                for m in snap { s.objects[k0] = m; k0++; }
                while k0 < s.objects.len { s.objects[k0].obj_type = 0; s.objects[k0].uid.clear(); s.objects[k0].owner.clear(); s.objects[k0].enc.clear(); k0++; }
                s.next_id = snap_next;
                s.live = snap_live;
                items.clear();
                var k = 0;
                for o in done_ops {
                    let a0 = done_at[3 * k];
                    let a1 = done_at[3 * k + 1];
                    let a2 = done_at[3 * k + 2];
                    let b, p = begin_result(items, o, done_buf[a0..a1], STATUS_OPERATION_UNDONE, 0, "");
                    items.append(done_buf[a1..a2]);
                    end_result(items, b, p);
                    k++;
                }
            }
            let b, p = begin_result(items, it.op, id, STATUS_OPERATION_FAILED, reason_for(res.reason, v), res.msg);
            end_result(items, b, p);
            if r.batch_continue != BATCH_CONTINUE { stopped = true; }
        }
        n++;
    }
    let m = begin_response(out, v, now_of(s), n);
    out.append(items);
    end(out, m);
}

// Who a client is: the first commonName of its certificate's subject
// (the leaf of a chain, concatenated DER, as tls::peer_certificates gives
// it); "" for none.
fn peer_identity(chain: const u8[:]) -> u8[>..] {
    var id: u8[>..] = [];
    if chain.len == 0 { return id; }
    let t, ok = asn1::read(chain, 0, chain.len);
    if !ok { return id; }
    let c, e = x509::parse(chain[t.start..t.end]);
    if e != x509::OK { return id; }
    let cns = x509::name_values(c.der, c.subject, "2.5.4.3");
    for cn in cns { if id.len == 0 { id.append(cn); } }
    return id;
}
