// kmip.messages: KMIP's request and response messages (§7 of KMIP 1.x,
// §8 of 2.0). A request is written in place: its header, then its batch
// items, each an operation and its payload, which the caller writes
// between begin_item and end_item. A response is read into a Response
// that points into its bytes: the header, and for each batch item the
// result and the payload's Node. The server's side is the same the other
// way: parse_request, then begin_response and the items.
//
//   var out: u8[>..] = [];
//   let m = kmip::begin_request(out, kmip::V1_2, 1, kmip::no_credential());
//   let it, p = kmip::begin_item(out, kmip::OP_QUERY, "");
//   kmip::put_enum(out, kmip::TAG_QUERY_FUNCTION, kmip::QUERY_OPERATIONS);
//   kmip::end_item(out, it, p);
//   kmip::end(out, m);

namespace kmip;

import std;
import kmip;
import kmip.tables;

struct Version { major: i32, minor: i32 }

let V1_0: Version = Version { major: 1, minor: 0 };
let V1_1: Version = Version { major: 1, minor: 1 };
let V1_2: Version = Version { major: 1, minor: 2 };
let V1_3: Version = Version { major: 1, minor: 3 };
let V1_4: Version = Version { major: 1, minor: 4 };
let V2_0: Version = Version { major: 2, minor: 0 };
let V2_1: Version = Version { major: 2, minor: 1 };

fn is_v2(v: Version) -> bool { v.major >= 2 }
fn version_eq(a: Version, b: Version) -> bool { a.major == b.major && a.minor == b.minor }
fn version_lt(a: Version, b: Version) -> bool { a.major < b.major || (a.major == b.major && a.minor < b.minor) }

fn put_version(out: u8[>..]&, v: Version) {
    let s = begin(out, TAG_PROTOCOL_VERSION);
    put_int(out, TAG_PROTOCOL_VERSION_MAJOR, v.major);
    put_int(out, TAG_PROTOCOL_VERSION_MINOR, v.minor);
    end(out, s);
}

fn read_version(buf: const u8[:], doc: const Node[:], i: i64) -> Version, bool {
    let a, ok1 = child_int(buf, doc, i, TAG_PROTOCOL_VERSION_MAJOR);
    let b, ok2 = child_int(buf, doc, i, TAG_PROTOCOL_VERSION_MINOR);
    return Version { major: a, minor: b }, ok1 && ok2;
}

// The credential of a request's Authentication: a username and password
// (Credential Type 1), a ticket from Login or Delegated Login (2.0's
// Ticket), or none. A server that knows its clients by their TLS
// certificates (PyKMIP) needs none.
struct Credential {
    username: u8[..256],
    password: u8[..256],
    ticket_type: u32,         // TICKET_LOGIN; 0: no ticket
    ticket: u8[..256],
}

fn no_credential() -> Credential { Credential { username: [], password: [], ticket_type: 0, ticket: [] } }

fn ticket_credential(ticket_type: u32, value: const u8[:]) -> Credential {
    var c = no_credential();
    c.ticket_type = ticket_type;
    c.ticket.append(value[..::min(value.len, 256)]);
    return c;
}

fn put_ticket(out: u8[>..]&, ticket_type: u32, value: const u8[:]) {
    let t = begin(out, TAG_TICKET);
    put_enum(out, TAG_TICKET_TYPE, ticket_type);
    put_bytes(out, TAG_TICKET_VALUE, value);
    end(out, t);
}

// What a request's header may say besides its version, credential and
// count: the Asynchronous Indicator (ASYNC_MANDATORY, ... in 2.1; in
// earlier versions a Boolean, written true for any but Prohibited), the
// Batch Error Continuation Option, and the Client Correlation Value (2.0).
struct HeaderOptions {
    async_ind: u32 = 0,
    batch_continue: u32 = 0,
    client_corr: u8[..256] = [],
}

fn password_credential(user: const u8[:], password: const u8[:]) -> Credential {
    var c = no_credential();
    c.username.append(user[..::min(user.len, 256)]);
    c.password.append(password[..::min(password.len, 256)]);
    return c;
}

// --- Requests -------------------------------------------------------------------

// Writes a RequestMessage's head and its RequestHeader; where the message
// starts, for end once the batch_count items are written.
fn begin_request(out: u8[>..]&, v: Version, batch_count: i32, cred: const Credential&) -> i64 {
    let none = HeaderOptions { .. };
    return begin_request_with(out, v, batch_count, cred, none);
}

fn begin_request_with(out: u8[>..]&, v: Version, batch_count: i32, cred: const Credential&, o: const HeaderOptions&) -> i64 {
    let m = begin(out, TAG_REQUEST_MESSAGE);
    let h = begin(out, TAG_REQUEST_HEADER);
    put_version(out, v);
    if o.client_corr.len > 0 && is_v2(v) { put_text(out, TAG_CLIENT_CORRELATION_VALUE, o.client_corr); }
    if o.async_ind != 0 {
        if version_lt(v, V2_1) { put_bool(out, TAG_ASYNCHRONOUS_INDICATOR, o.async_ind != ASYNC_PROHIBITED); }
        else { put_enum(out, TAG_ASYNCHRONOUS_INDICATOR, o.async_ind); }
    }
    if cred.ticket_type != 0 {
        let a = begin(out, TAG_AUTHENTICATION);
        let c = begin(out, TAG_CREDENTIAL);
        put_enum(out, TAG_CREDENTIAL_TYPE, CRED_TICKET);
        let cv = begin(out, TAG_CREDENTIAL_VALUE);
        put_ticket(out, cred.ticket_type, cred.ticket);
        end(out, cv);
        end(out, c);
        end(out, a);
    } else if cred.username.len > 0 {
        let a = begin(out, TAG_AUTHENTICATION);
        let c = begin(out, TAG_CREDENTIAL);
        put_enum(out, TAG_CREDENTIAL_TYPE, CRED_USERNAME_AND_PASSWORD);
        let cv = begin(out, TAG_CREDENTIAL_VALUE);
        put_text(out, TAG_USERNAME, cred.username);
        if cred.password.len > 0 { put_text(out, TAG_PASSWORD, cred.password); }
        end(out, cv);
        end(out, c);
        end(out, a);
    }
    if o.batch_continue != 0 { put_enum(out, TAG_BATCH_ERROR_CONTINUATION_OPTION, o.batch_continue); }
    put_int(out, TAG_BATCH_COUNT, batch_count);
    end(out, h);
    return m;
}

// A batch item's head: the operation and, if not empty, its Unique Batch
// Item ID. Where the item and its payload start, for end_item.
fn begin_item(out: u8[>..]&, op: u32, item_id: const u8[:]) -> i64, i64 {
    let it = begin(out, TAG_BATCH_ITEM);
    put_enum(out, TAG_OPERATION, op);
    if item_id.len > 0 { put_bytes(out, TAG_UNIQUE_BATCH_ITEM_ID, item_id); }
    let p = begin(out, TAG_REQUEST_PAYLOAD);
    return it, p;
}

fn end_item(out: u8[>..]&, item: i64, payload: i64) {
    end(out, payload);
    end(out, item);
}

// --- Responses ------------------------------------------------------------------

// One batch item of a response. Its ID and message are offsets into the
// response's bytes (id_off, msg_off: -1 when absent); payload is the index
// of its Response Payload's Node, or -1.
struct Item {
    op: u32,                      // 0 when the server left it out (it may, on a failure)
    status: u32,                  // STATUS_SUCCESS, STATUS_OPERATION_FAILED, ...
    reason: u32,                  // REASON_*, 0 when there is none
    id_off: i64, id_len: i64,
    msg_off: i64, msg_len: i64,
    payload: i64,
    async_off: i64 = -1, async_len: i64 = 0,   // an Operation Pending's Asynchronous Correlation Value
}

// The Asynchronous Correlation Value of an Operation Pending item, or "".
fn item_async(buf: const u8[:], it: const Item&) -> const u8[:] {
    if it.async_off < 0 { return ""; }
    return buf[it.async_off..it.async_off + it.async_len];
}

struct Response {
    version: Version,
    time: i64,                    // the server's Time Stamp, seconds since 1970
    root: i64,
    items: Item[>..],
}

fn item_id(buf: const u8[:], it: const Item&) -> const u8[:] {
    if it.id_off < 0 { return ""; }
    return buf[it.id_off..it.id_off + it.id_len];
}

// The Result Message, or "".
fn result_message(buf: const u8[:], it: const Item&) -> const u8[:] {
    if it.msg_off < 0 { return ""; }
    return buf[it.msg_off..it.msg_off + it.msg_len];
}

fn read_item(buf: const u8[:], doc: const Node[:], b: i64) -> Item, i64 {
    var it = Item { op: 0, status: 0, reason: 0, id_off: -1, id_len: 0, msg_off: -1, msg_len: 0, payload: -1, async_off: -1, async_len: 0 };
    let op, has_op = child_enum(buf, doc, b, TAG_OPERATION);
    if has_op { it.op = op; }
    let st, has_st = child_enum(buf, doc, b, TAG_RESULT_STATUS);
    if !has_st { return it, ERR_MISSING; }
    it.status = st;
    let rr, has_rr = child_enum(buf, doc, b, TAG_RESULT_REASON);
    if has_rr { it.reason = rr; }
    let id = child(doc, b, TAG_UNIQUE_BATCH_ITEM_ID);
    if is_type(doc, id, BYTE_STRING) { it.id_off = doc[id].off; it.id_len = doc[id].len; }
    let msg = child(doc, b, TAG_RESULT_MESSAGE);
    if is_type(doc, msg, TEXT_STRING) { it.msg_off = doc[msg].off; it.msg_len = doc[msg].len; }
    let p = child(doc, b, TAG_RESPONSE_PAYLOAD);
    if is_type(doc, p, STRUCTURE) { it.payload = p; }
    let ac = child(doc, b, TAG_ASYNCHRONOUS_CORRELATION_VALUE);
    if is_type(doc, ac, BYTE_STRING) { it.async_off = doc[ac].off; it.async_len = doc[ac].len; }
    return it, OK;
}

// Reads a ResponseMessage decoded into doc: its header and batch items.
// ERR_MISSING when a field it must have is not there, ERR_PROTOCOL when
// the Batch Count is not the number of items.
fn parse_response(buf: const u8[:], doc: const Node[:], root: i64) -> Response, i64 {
    var r = Response { version: Version { major: 0, minor: 0 }, time: 0, root: root, items: [] };
    if !is_type(doc, root, STRUCTURE) || doc[root].tag != TAG_RESPONSE_MESSAGE { return r, ERR_MISSING; }
    let h = child(doc, root, TAG_RESPONSE_HEADER);
    let v, vok = read_version(buf, doc, child(doc, h, TAG_PROTOCOL_VERSION));
    if !vok { return r, ERR_MISSING; }
    r.version = v;
    let t, tok = as_datetime(buf, doc, child(doc, h, TAG_TIME_STAMP));
    if tok { r.time = t; }
    let n, nok = child_int(buf, doc, h, TAG_BATCH_COUNT);
    if !nok { return r, ERR_MISSING; }
    var b = child(doc, root, TAG_BATCH_ITEM);
    while b >= 0 {
        let it, e = read_item(buf, doc, b);
        if e != OK { return r, e; }
        r.items.push(it);
        b = next_same(doc, b);
    }
    if r.items.len != n { return r, ERR_PROTOCOL; }
    return r, OK;
}

// --- The server's side ----------------------------------------------------------

// One batch item of a request: its operation, ID (offsets into the
// request's bytes, -1 when absent) and payload's Node.
struct RequestItem {
    op: u32,
    id_off: i64, id_len: i64,
    payload: i64,
}

struct Request {
    version: Version,
    max_response_size: i32,         // 0 when not given
    batch_continue: u32,            // Batch Error Continuation Option, BATCH_STOP by default
    user_off: i64, user_len: i64,   // the Authentication's username and password, -1 when absent
    pass_off: i64, pass_len: i64,
    cred_type: u32,                 // the Credential Type, 0 when there is no Authentication
    ticket_type: u32,               // a Ticket credential's
    ticket_off: i64, ticket_len: i64,
    async_ind: u32,                 // ASYNC_*: 1.x and 2.0's Boolean as Optional or Prohibited; 0 when absent
    corr_off: i64, corr_len: i64,   // the Client Correlation Value, -1 when absent
    root: i64,
    items: RequestItem[>..],
}

fn request_item_id(buf: const u8[:], it: const RequestItem&) -> const u8[:] {
    if it.id_off < 0 { return ""; }
    return buf[it.id_off..it.id_off + it.id_len];
}

fn request_username(buf: const u8[:], r: const Request&) -> const u8[:] {
    if r.user_off < 0 { return ""; }
    return buf[r.user_off..r.user_off + r.user_len];
}

fn request_password(buf: const u8[:], r: const Request&) -> const u8[:] {
    if r.pass_off < 0 { return ""; }
    return buf[r.pass_off..r.pass_off + r.pass_len];
}

fn request_ticket(buf: const u8[:], r: const Request&) -> const u8[:] {
    if r.ticket_off < 0 { return ""; }
    return buf[r.ticket_off..r.ticket_off + r.ticket_len];
}

fn request_client_correlation(buf: const u8[:], r: const Request&) -> const u8[:] {
    if r.corr_off < 0 { return ""; }
    return buf[r.corr_off..r.corr_off + r.corr_len];
}

// Reads a RequestMessage decoded into doc.
fn parse_request(buf: const u8[:], doc: const Node[:], root: i64) -> Request, i64 {
    var r = Request { version: Version { major: 0, minor: 0 }, max_response_size: 0, batch_continue: BATCH_STOP,
                      user_off: -1, user_len: 0, pass_off: -1, pass_len: 0, cred_type: 0, ticket_type: 0,
                      ticket_off: -1, ticket_len: 0, async_ind: 0, corr_off: -1, corr_len: 0, root: root, items: [] };
    if !is_type(doc, root, STRUCTURE) || doc[root].tag != TAG_REQUEST_MESSAGE { return r, ERR_MISSING; }
    let h = child(doc, root, TAG_REQUEST_HEADER);
    let v, vok = read_version(buf, doc, child(doc, h, TAG_PROTOCOL_VERSION));
    if !vok { return r, ERR_MISSING; }
    r.version = v;
    let mrs, mok = child_int(buf, doc, h, TAG_MAXIMUM_RESPONSE_SIZE);
    if mok { r.max_response_size = mrs; }
    let bc, bok = child_enum(buf, doc, h, TAG_BATCH_ERROR_CONTINUATION_OPTION);
    if bok { r.batch_continue = bc; }
    let cr = child(doc, child(doc, h, TAG_AUTHENTICATION), TAG_CREDENTIAL);
    let ctype, ctok = child_enum(buf, doc, cr, TAG_CREDENTIAL_TYPE);
    if ctok { r.cred_type = ctype; }
    let cv = child(doc, cr, TAG_CREDENTIAL_VALUE);
    let tk = child(doc, cv, TAG_TICKET);
    let tt, ttok = child_enum(buf, doc, tk, TAG_TICKET_TYPE);
    let tv = child(doc, tk, TAG_TICKET_VALUE);
    if ttok && is_type(doc, tv, BYTE_STRING) { r.ticket_type = tt; r.ticket_off = doc[tv].off; r.ticket_len = doc[tv].len; }
    let ai = child(doc, h, TAG_ASYNCHRONOUS_INDICATOR);
    if is_type(doc, ai, ENUMERATION) { let e, ok = as_enum(buf, doc, ai); r.async_ind = e; }
    else if is_type(doc, ai, BOOLEAN) { let b, ok = as_bool(buf, doc, ai); r.async_ind = if b { ASYNC_OPTIONAL } else { ASYNC_PROHIBITED }; }
    let cc = child(doc, h, TAG_CLIENT_CORRELATION_VALUE);
    if is_type(doc, cc, TEXT_STRING) { r.corr_off = doc[cc].off; r.corr_len = doc[cc].len; }
    let u = child(doc, cv, TAG_USERNAME);
    if is_type(doc, u, TEXT_STRING) { r.user_off = doc[u].off; r.user_len = doc[u].len; }
    let pw = child(doc, cv, TAG_PASSWORD);
    if is_type(doc, pw, TEXT_STRING) { r.pass_off = doc[pw].off; r.pass_len = doc[pw].len; }
    let n, nok = child_int(buf, doc, h, TAG_BATCH_COUNT);
    if !nok { return r, ERR_MISSING; }
    var b = child(doc, root, TAG_BATCH_ITEM);
    while b >= 0 {
        let op, ok = child_enum(buf, doc, b, TAG_OPERATION);
        if !ok { return r, ERR_MISSING; }
        var it = RequestItem { op: op, id_off: -1, id_len: 0, payload: child(doc, b, TAG_REQUEST_PAYLOAD) };
        let id = child(doc, b, TAG_UNIQUE_BATCH_ITEM_ID);
        if is_type(doc, id, BYTE_STRING) { it.id_off = doc[id].off; it.id_len = doc[id].len; }
        r.items.push(it);
        b = next_same(doc, b);
    }
    if r.items.len != n { return r, ERR_PROTOCOL; }
    return r, OK;
}

// A ResponseMessage's head and ResponseHeader.
fn begin_response(out: u8[>..]&, v: Version, time: i64, batch_count: i32) -> i64 {
    let m = begin(out, TAG_RESPONSE_MESSAGE);
    let h = begin(out, TAG_RESPONSE_HEADER);
    put_version(out, v);
    put_datetime(out, TAG_TIME_STAMP, time);
    put_int(out, TAG_BATCH_COUNT, batch_count);
    end(out, h);
    return m;
}

// A response's batch item with its result; for a success, the payload is
// written between this and end_item (payload -1: none). A failure has no
// payload: end_item(out, item, -1) right after.
fn begin_result(out: u8[>..]&, op: u32, item_id: const u8[:], status: u32, reason: u32, message: const u8[:]) -> i64, i64 {
    let it = begin(out, TAG_BATCH_ITEM);
    if op != 0 { put_enum(out, TAG_OPERATION, op); }
    if item_id.len > 0 { put_bytes(out, TAG_UNIQUE_BATCH_ITEM_ID, item_id); }
    put_enum(out, TAG_RESULT_STATUS, status);
    // Undone items keep their payload, with no reason (their undoing is
    // another item's failure).
    if status != STATUS_SUCCESS && status != STATUS_OPERATION_UNDONE {
        put_enum(out, TAG_RESULT_REASON, reason);
        if message.len > 0 { put_text(out, TAG_RESULT_MESSAGE, message); }
        return it, -1;
    }
    let p = begin(out, TAG_RESPONSE_PAYLOAD);
    return it, p;
}

fn end_result(out: u8[>..]&, item: i64, payload: i64) {
    if payload >= 0 { end(out, payload); }
    end(out, item);
}
