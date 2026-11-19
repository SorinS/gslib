// kmip.client: a KMIP client over TLS (port 5696). It speaks one protocol
// version, settled by negotiate (Discover Versions) or set; each operation
// is one request of one batch item, its answer checked: the batch count,
// the operation echoed, the Result Status. A failure's Result Reason and
// Result Message are kept in the client (last_reason, last_message).
//
//   var cc = tls::client_config("kms.example.com", ca_der);
//   tls::set_client_certificate(cc, cert_der, key_der);
//   var c, e = kmip::dial("kms.example.com", 5696, cc);
//   let v, ev = kmip::negotiate(c);
//   var a = kmip::attrs();
//   kmip::attr_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
//   kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
//   kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK, (kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT) as! i32);
//   let uid, ec = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);

namespace kmip;

import std;
import net;
import binary;
import crypto.tls;
import crypto.tls.handshake;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;

struct Client {
    fd: i64,
    version: Version,          // what requests are sent as: 1.2 until negotiate or set
    timeout_ms: i32,           // for each read and write: 30000
    max_response: i64,         // the longest answer taken: 16 MiB
    cred: Credential,          // the Authentication sent with each request, none by default
    last_status: u32,          // the last answer's Result Status and Reason
    last_reason: u32,
    last_message: u8[..1024],  // and its Result Message
    conn: tls::Conn,
    cc: tls::ClientConfig,
}

// A TLS client configuration for a key manager: tls::client_config's,
// with the suites KMIP's TLS 1.2 authentication suites name (KMIP
// Profiles §3.1) after Go's defaults, CBC with SHA-256, which servers
// built on them (PyKMIP) may take alone.
fn tls_config(server_name: const u8[:], roots: const u8[:]) -> tls::ClientConfig {
    var cc = tls::client_config(server_name, roots);
    let more: u16[3] = [tls::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                        tls::TLS_RSA_WITH_AES_128_CBC_SHA256];
    for s in more {
        var have = false;
        for t in cc.suites12 { if t == s { have = true; } }
        if !have && cc.suites12.len < cc.suites12.cap { cc.suites12.push(s); }
    }
    return cc;
}

// A client over TLS to host:port, the handshake done with cc (the
// server's name and CA, and the client's certificate, which is how most
// key managers know their clients). ERR_NETWORK or ERR_TLS when it fails.
fn dial(host: const u8[:], port: i64, cc: const tls::ClientConfig&) -> Client, i64 {
    let fd = net::dial(host, port as! i32, 10000);
    var c = Client {
        fd: fd, version: V1_2, timeout_ms: 30000, max_response: 16777216, cred: no_credential(),
        last_status: 0, last_reason: 0, last_message: [],
        conn: tls::client(cc), cc: copy(cc),
    };
    if fd < 0 { return c, ERR_NETWORK; }
    var out: u8[>..] = [];
    tls::client_start(c.conn, c.cc, out);
    var buf: u8[16384] = [0; 16384];
    while !tls::connected(c.conn) {
        if out.len > 0 && net::write(fd, out, c.timeout_ms) < 0 { return c, ERR_NETWORK; }
        out.clear();
        let n = net::read(fd, buf, c.timeout_ms);
        if n <= 0 { return c, ERR_NETWORK; }
        var app: u8[>..] = [];
        if tls::feed(c.conn, c.cc, buf[..n], out, app) < 0 {
            let w = net::write(fd, out, c.timeout_ms);
            return c, ERR_TLS;
        }
    }
    if out.len > 0 && net::write(fd, out, c.timeout_ms) < 0 { return c, ERR_NETWORK; }
    return c, OK;
}

fn close(c: Client&) {
    if c.fd < 0 { return; }
    if tls::connected(c.conn) {
        var out: u8[>..] = [];
        tls::close(c.conn, out);
        let w = net::write(c.fd, out, 1000);
    }
    net::close(c.fd);
    c.fd = -1;
}

// Sends a message and reads the one that answers it into resp.
fn exchange(c: Client&, msg: const u8[:], resp: u8[>..]&) -> i64 {
    resp.clear();
    var rec: u8[>..] = [];
    if !tls::send(c.conn, msg, rec) || net::write(c.fd, rec, c.timeout_ms) < 0 { return ERR_NETWORK; }
    var buf: u8[16384] = [0; 16384];
    loop {
        if resp.len >= 8 {
            let need = message_length(resp[..8]);
            if need < 0 { return ERR_MALFORMED; }
            if need > c.max_response { return ERR_TOO_LARGE; }
            if resp.len >= need {
                resp.resize(need, 0);   // KMIP answers one request at a time: nothing follows
                return OK;
            }
        }
        let n = net::read(c.fd, buf, c.timeout_ms);
        if n <= 0 { return ERR_NETWORK; }
        var out: u8[>..] = [];
        let fr = tls::feed(c.conn, c.cc, buf[..n], out, resp);
        if out.len > 0 { let w = net::write(c.fd, out, c.timeout_ms); }
        if fr < 0 { return ERR_TLS; }
        if tls::closed(c.conn) && resp.len < 8 { return ERR_NETWORK; }
    }
    return ERR_NETWORK;
}

// One operation: a request of one batch item, its payload written by
// F(out); the answer decoded into resp and doc. The index of the
// Response Payload's Node (-1 if it has none), or the error: ERR_FAILED
// when the Result Status is not Success (last_reason, last_message say
// why).
fn call<C, F>(c: C&, op: u32, resp: u8[>..]&, doc: Node[>..]&) -> i64, i64 {
    var out: u8[>..] = [];
    let m = begin_request(out, c.version, 1, c.cred);
    let it, p = begin_item(out, op, "");
    F(out);
    end_item(out, it, p);
    end(out, m);
    let e = exchange(c, out, resp);
    if e != OK { return -1, e; }
    doc.clear();
    let root, de = decode(resp, Options { .. }, doc);
    if de != OK { return -1, de; }
    let r, pe = parse_response(resp, doc, root);
    if pe != OK { return -1, pe; }
    if r.items.len != 1 { return -1, ERR_PROTOCOL; }
    let item = r.items[0];
    if item.op != 0 && item.op != op { return -1, ERR_PROTOCOL; }
    c.last_status = item.status;
    c.last_reason = item.reason;
    c.last_message.clear();
    let msg = result_message(resp, item);
    c.last_message.append(msg[..::min(msg.len, 1024)]);
    if item.status != STATUS_SUCCESS { return -1, ERR_FAILED; }
    return item.payload, OK;
}

// What went wrong with the last operation, for a message: the error, and
// for ERR_FAILED the server's reason and message.
fn describe<C>(c: const C&, e: i64) -> u8[>..] {
    var s: u8[>..] = [];
    s.append(error_text(e));
    if e == ERR_FAILED {
        s.append(": ");
        let rn = enum_name(TAG_RESULT_REASON, c.last_reason);
        if rn.len > 0 { s.append(rn); } else { s.append("reason "); format_uint(s, c.last_reason, 16, 0, ' '); }
        if c.last_message.len > 0 { s.append(" ("); s.append(c.last_message); s.append(")"); }
    }
    return s;
}

// --- Discover Versions and Query ------------------------------------------------

let ALL_VERSIONS: Version[7] = [
    Version { major: 2, minor: 1 }, Version { major: 2, minor: 0 }, Version { major: 1, minor: 4 }, Version { major: 1, minor: 3 },
    Version { major: 1, minor: 2 }, Version { major: 1, minor: 1 }, Version { major: 1, minor: 0 },
];

// The versions the server speaks of those offered (all it speaks, if
// none are), in its order of preference.
fn discover_versions<C>(c: C&, offer: const Version[:]) -> Version[>..], i64 {
    var got: Version[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_DISCOVER_VERSIONS, resp, doc) { out =>
        for v in offer { put_version(out, v); }
    };
    if e != OK { return got, e; }
    var pv = child(doc, p, TAG_PROTOCOL_VERSION);
    while pv >= 0 {
        let v, ok = read_version(resp, doc, pv);
        if ok { got.push(v); }
        pv = next_same(doc, pv);
    }
    return got, OK;
}

// Settles the version: the server's first choice of those this client
// speaks (2.0 down to 1.0). A server without Discover Versions (1.0) is
// spoken to in 1.0. ERR_VERSION when there is none in common.
fn negotiate<C>(c: C&) -> Version, i64 {
    let vs, e = discover_versions(c, ALL_VERSIONS);
    if e == ERR_FAILED && c.last_reason == REASON_OPERATION_NOT_SUPPORTED {
        c.version = V1_0;
        return c.version, OK;
    }
    if e != OK { return c.version, e; }
    if vs.len == 0 { return c.version, ERR_VERSION; }
    for v in vs {
        for mine in ALL_VERSIONS {
            if version_eq(v, mine) { c.version = v; return v, OK; }
        }
    }
    return c.version, ERR_VERSION;
}

// What a Query answers, of what was asked: the operations and object
// types the server supports, its vendor identification and server
// information (as it is written: a Structure, dumped).
struct QueryResult {
    operations: u32[..128],
    object_types: u32[..32],
    vendor: u8[..256],
    server_info: u8[>..],
}

fn query<C>(c: C&, functions: const u32[:]) -> QueryResult, i64 {
    var q = QueryResult { operations: [], object_types: [], vendor: [], server_info: [] };
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_QUERY, resp, doc) { out =>
        for f in functions { put_enum(out, TAG_QUERY_FUNCTION, f); }
    };
    if e != OK { return q, e; }
    each(doc, p) { k =>
        let t = doc[k].tag;
        if t == TAG_OPERATION && q.operations.len < q.operations.cap {
            let v, ok = as_enum(resp, doc, k);
            if ok { q.operations.push(v); }
        } else if t == TAG_OBJECT_TYPE && q.object_types.len < q.object_types.cap {
            let v, ok = as_enum(resp, doc, k);
            if ok { q.object_types.push(v); }
        } else if t == TAG_VENDOR_IDENTIFICATION {
            let v, ok = as_text(resp, doc, k);
            if ok { q.vendor.clear(); q.vendor.append(v[..::min(v.len, 256)]); }
        } else if t == TAG_SERVER_INFORMATION {
            q.server_info.append(dump(resp, doc, k));
        }
    };
    return q, OK;
}

// --- Objects --------------------------------------------------------------------

fn put_uid(out: u8[>..]&, uid: const u8[:]) { if uid.len > 0 { put_text(out, TAG_UNIQUE_IDENTIFIER, uid); } }

fn uid_of(buf: const u8[:], doc: const Node[:], p: i64, tag: u32) -> u8[>..], i64 {
    var u: u8[>..] = [];
    let v, ok = child_text(buf, doc, p, tag);
    if !ok { return u, ERR_MISSING; }
    u.append(v);
    return u, OK;
}

// Create: a new symmetric key (or secret data) the server makes, with the
// attributes; its Unique Identifier.
fn create<C>(c: C&, obj_type: u32, a: const Attrs&) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_CREATE, resp, doc) { out =>
        put_enum(out, TAG_OBJECT_TYPE, obj_type);
        put_template(out, a, v, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let u, eu = uid_of(resp, doc, p, TAG_UNIQUE_IDENTIFIER);
    return u, eu;
}

// Create Key Pair: the attributes of both keys, and those of each; the
// private key's Unique Identifier, then the public key's.
fn create_key_pair<C>(c: C&, common: const Attrs&, private: const Attrs&, public: const Attrs&) -> u8[>..], u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_CREATE_KEY_PAIR, resp, doc) { out =>
        if attr_count(common) > 0 { put_template(out, common, v, TAG_COMMON_TEMPLATE_ATTRIBUTE, TAG_COMMON_ATTRIBUTES); }
        if attr_count(private) > 0 { put_template(out, private, v, TAG_PRIVATE_KEY_TEMPLATE_ATTRIBUTE, TAG_PRIVATE_KEY_ATTRIBUTES); }
        if attr_count(public) > 0 { put_template(out, public, v, TAG_PUBLIC_KEY_TEMPLATE_ATTRIBUTE, TAG_PUBLIC_KEY_ATTRIBUTES); }
    };
    var none: u8[>..] = [];
    if e != OK { var none2: u8[>..] = []; return none, none2, e; }
    let pr, e1 = uid_of(resp, doc, p, TAG_PRIVATE_KEY_UNIQUE_IDENTIFIER);
    let pu, e2 = uid_of(resp, doc, p, TAG_PUBLIC_KEY_UNIQUE_IDENTIFIER);
    return pr, pu, if e1 != OK { e1 } else { e2 };
}

// Register: an object the client made, with the attributes; its Unique
// Identifier.
fn register<C>(c: C&, o: const Object&, a: const Attrs&) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    var written = true;
    let p, e = call(c, OP_REGISTER, resp, doc) { out =>
        put_enum(out, TAG_OBJECT_TYPE, o.obj_type);
        put_template(out, a, v, TAG_TEMPLATE_ATTRIBUTE, TAG_ATTRIBUTES);
        written = put_object(out, o);
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let u, eu = uid_of(resp, doc, p, TAG_UNIQUE_IDENTIFIER);
    return u, eu;
}

// Get: the object, in the format asked for (0: the server's choice).
fn get<C>(c: C&, uid: const u8[:], format: u32) -> Object, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_GET, resp, doc) { out =>
        put_uid(out, uid);
        if format != 0 { put_enum(out, TAG_KEY_FORMAT_TYPE, format); }
    };
    if e != OK { return new_object(0), e; }
    let t, tok = child_enum(resp, doc, p, TAG_OBJECT_TYPE);
    if !tok { return new_object(0), ERR_MISSING; }
    let o, ok = read_object(resp, doc, p, t);
    return o, if ok { OK } else { ERR_MISSING };
}

// --- Attributes -----------------------------------------------------------------

// Get Attributes: those with the tags, or all of them when there are none.
fn get_attributes<C>(c: C&, uid: const u8[:], tags: const u32[:]) -> Attrs, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_GET_ATTRIBUTES, resp, doc) { out =>
        put_uid(out, uid);
        for t in tags {
            if is_v2(v) { put_enum(out, TAG_ATTRIBUTE_REFERENCE, t); }
            else { put_text(out, TAG_ATTRIBUTE_NAME, attribute_name(t)); }
        }
    };
    if e != OK { return attrs(), e; }
    return read_attrs(resp, doc, p), OK;
}

// Get Attribute List: the tags of the attributes the object has (those
// with names known here, in 1.x).
fn get_attribute_list<C>(c: C&, uid: const u8[:]) -> u32[>..], i64 {
    var tags: u32[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_GET_ATTRIBUTE_LIST, resp, doc) { out => put_uid(out, uid); };
    if e != OK { return tags, e; }
    each(doc, p) { k =>
        if doc[k].tag == TAG_ATTRIBUTE_NAME {
            let n, ok = as_text(resp, doc, k);
            let t = if ok { attribute_tag(n) } else { 0 };
            if t != 0 { tags.push(t); }
        } else if doc[k].tag == TAG_ATTRIBUTE_REFERENCE {
            let t = reference_tag(resp, doc, k);
            if t != 0 { tags.push(t); }
        }
    };
    return tags, OK;
}

// One attribute, the item as attrs keep it, sent as 1.x's Attribute or
// under 2.0's tag (New Attribute, Current Attribute).
fn put_one(out: u8[>..]&, item: const u8[:], v: Version, tag2: u32) {
    if item.len < 8 { return; }
    if is_v2(v) {
        let s = begin(out, tag2);
        out.append(item);
        end(out, s);
    } else {
        let ok = put_attribute_1x(out, binary::u32be(item, 0) >> 8, item);
    }
}

fn first_item(a: const Attrs&) -> const u8[:] {
    var at = 0;
    let n = item_len(a.enc, 0);
    if n < 0 { return ""; }
    return a.enc[..n];
}

// Add Attribute: the first of the attributes, added to those the object
// has (another Name, Link, ...; set_attribute replaces instead).
fn add_attribute<C>(c: C&, uid: const u8[:], a: const Attrs&) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let item = first_item(a);
    let p, e = call(c, OP_ADD_ATTRIBUTE, resp, doc) { out =>
        put_uid(out, uid);
        put_one(out, item, v, TAG_NEW_ATTRIBUTE);
    };
    return e;
}

// Set Attribute (2.0): the attribute's value, whether it had one or not.
fn set_attribute<C>(c: C&, uid: const u8[:], a: const Attrs&) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let item = first_item(a);
    let p, e = call(c, OP_SET_ATTRIBUTE, resp, doc) { out =>
        put_uid(out, uid);
        put_one(out, item, V2_0, TAG_NEW_ATTRIBUTE);
    };
    return e;
}

// Modify Attribute: the attribute's new value.
fn modify_attribute<C>(c: C&, uid: const u8[:], a: const Attrs&) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let item = first_item(a);
    let p, e = call(c, OP_MODIFY_ATTRIBUTE, resp, doc) { out =>
        put_uid(out, uid);
        put_one(out, item, v, TAG_NEW_ATTRIBUTE);
    };
    return e;
}

// Delete Attribute: the first one with the tag.
fn delete_attribute<C>(c: C&, uid: const u8[:], tag: u32) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_DELETE_ATTRIBUTE, resp, doc) { out =>
        put_uid(out, uid);
        if is_v2(v) { put_reference_struct(out, tag); }
        else { put_text(out, TAG_ATTRIBUTE_NAME, attribute_name(tag)); }
    };
    return e;
}

// --- Locate and the life cycle --------------------------------------------------

// Locate: the Unique Identifiers of the objects with all the attributes
// (max_items 0: as many as the server gives).
fn locate<C>(c: C&, a: const Attrs&, max_items: i32) -> u8[..256][>..], i64 {
    var uids: u8[..256][>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let v = c.version;
    let p, e = call(c, OP_LOCATE, resp, doc) { out =>
        if max_items > 0 { put_int(out, TAG_MAXIMUM_ITEMS, max_items); }
        put_attribute_items(out, a, v);
    };
    if e != OK { return uids, e; }
    var k = child(doc, p, TAG_UNIQUE_IDENTIFIER);
    while k >= 0 {
        let t, ok = as_text(resp, doc, k);
        if ok && t.len <= 256 {
            var u: u8[..256] = [];
            u.append(t);
            uids.push(u);
        }
        k = next_same(doc, k);
    }
    return uids, OK;
}

fn uid_only<C>(c: C&, op: u32, uid: const u8[:]) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, op, resp, doc) { out => put_uid(out, uid); };
    return e;
}

fn activate<C>(c: C&, uid: const u8[:]) -> i64 { uid_only(c, OP_ACTIVATE, uid) }
fn destroy<C>(c: C&, uid: const u8[:]) -> i64 { uid_only(c, OP_DESTROY, uid) }

// Revoke: why (REVOKE_*), and a message if not empty; for a compromise,
// when it happened (0: not said).
fn revoke<C>(c: C&, uid: const u8[:], reason: u32, message: const u8[:], compromised: i64) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_REVOKE, resp, doc) { out =>
        put_uid(out, uid);
        let r = begin(out, TAG_REVOCATION_REASON);
        put_enum(out, TAG_REVOCATION_REASON_CODE, reason);
        if message.len > 0 { put_text(out, TAG_REVOCATION_MESSAGE, message); }
        end(out, r);
        if compromised != 0 { put_datetime(out, TAG_COMPROMISE_OCCURRENCE_DATE, compromised); }
    };
    return e;
}

// --- Cryptographic operations ---------------------------------------------------

// What Encrypt answers: the ciphertext, the IV, counter or nonce the
// server chose (when it did), and an AEAD's tag.
struct Sealed {
    iv: u8[..64],
    tag: u8[..64],
    data: u8[>..],
}

fn has_params(p: CryptoParams) -> bool {
    p.mode != 0 || p.padding != 0 || p.hash != 0 || p.sig != 0 || p.alg != 0 || p.random_iv || p.tag_length != 0
}

// Encrypt data with the key; iv may be empty (the server's, or random_iv).
fn encrypt<C>(c: C&, uid: const u8[:], params: CryptoParams, data: const u8[:], iv: const u8[:], aad: const u8[:]) -> Sealed, i64 {
    var s = Sealed { iv: [], tag: [], data: [] };
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_ENCRYPT, resp, doc) { out =>
        put_uid(out, uid);
        if has_params(params) { put_crypto_params(out, params); }
        put_bytes(out, TAG_DATA, data);
        if iv.len > 0 { put_bytes(out, TAG_IV_COUNTER_NONCE, iv); }
        if aad.len > 0 { put_bytes(out, TAG_AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, aad); }
    };
    if e != OK { return s, e; }
    let d, dok = child_bytes(resp, doc, p, TAG_DATA);
    if !dok { return s, ERR_MISSING; }
    s.data.append(d);
    let v, vok = child_bytes(resp, doc, p, TAG_IV_COUNTER_NONCE);
    if vok && v.len <= 64 { s.iv.append(v); }
    let t, tok = child_bytes(resp, doc, p, TAG_AUTHENTICATED_ENCRYPTION_TAG);
    if tok && t.len <= 64 { s.tag.append(t); }
    return s, OK;
}

fn decrypt<C>(c: C&, uid: const u8[:], params: CryptoParams, data: const u8[:], iv: const u8[:], aad: const u8[:], tag: const u8[:]) -> u8[>..], i64 {
    var plain: u8[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_DECRYPT, resp, doc) { out =>
        put_uid(out, uid);
        if has_params(params) { put_crypto_params(out, params); }
        put_bytes(out, TAG_DATA, data);
        if iv.len > 0 { put_bytes(out, TAG_IV_COUNTER_NONCE, iv); }
        if aad.len > 0 { put_bytes(out, TAG_AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, aad); }
        if tag.len > 0 { put_bytes(out, TAG_AUTHENTICATED_ENCRYPTION_TAG, tag); }
    };
    if e != OK { return plain, e; }
    let d, dok = child_bytes(resp, doc, p, TAG_DATA);
    if !dok { return plain, ERR_MISSING; }
    plain.append(d);
    return plain, OK;
}

// Sign data with the private key; the signature.
fn sign<C>(c: C&, uid: const u8[:], params: CryptoParams, data: const u8[:]) -> u8[>..], i64 {
    var sig: u8[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_SIGN, resp, doc) { out =>
        put_uid(out, uid);
        if has_params(params) { put_crypto_params(out, params); }
        put_bytes(out, TAG_DATA, data);
    };
    if e != OK { return sig, e; }
    let d, dok = child_bytes(resp, doc, p, TAG_SIGNATURE_DATA);
    if !dok { return sig, ERR_MISSING; }
    sig.append(d);
    return sig, OK;
}

// Signature Verify with the public key: true when the server says Valid.
fn verify<C>(c: C&, uid: const u8[:], params: CryptoParams, data: const u8[:], sig: const u8[:]) -> bool, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_SIGNATURE_VERIFY, resp, doc) { out =>
        put_uid(out, uid);
        if has_params(params) { put_crypto_params(out, params); }
        put_bytes(out, TAG_DATA, data);
        put_bytes(out, TAG_SIGNATURE_DATA, sig);
    };
    if e != OK { return false, e; }
    let v, ok = child_enum(resp, doc, p, TAG_VALIDITY_INDICATOR);
    if !ok { return false, ERR_MISSING; }
    return v == VALIDITY_VALID, OK;
}

// MAC of data with the key.
fn mac<C>(c: C&, uid: const u8[:], params: CryptoParams, data: const u8[:]) -> u8[>..], i64 {
    var m: u8[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_MAC, resp, doc) { out =>
        put_uid(out, uid);
        if has_params(params) { put_crypto_params(out, params); }
        put_bytes(out, TAG_DATA, data);
    };
    if e != OK { return m, e; }
    let d, dok = child_bytes(resp, doc, p, TAG_MAC_DATA);
    if !dok { return m, ERR_MISSING; }
    m.append(d);
    return m, OK;
}

// RNG Retrieve: n random bytes from the server.
fn rng_retrieve<C>(c: C&, n: i32) -> u8[>..], i64 {
    var r: u8[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_RNG_RETRIEVE, resp, doc) { out => put_int(out, TAG_DATA_LENGTH, n); };
    if e != OK { return r, e; }
    let d, dok = child_bytes(resp, doc, p, TAG_DATA);
    if !dok { return r, ERR_MISSING; }
    r.append(d);
    return r, OK;
}
