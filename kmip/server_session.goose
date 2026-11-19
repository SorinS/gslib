// kmip.server_session: the server's side of what spans requests.
// Asynchronous items (1.0's Poll and Cancel, 2.1's Process and Query
// Asynchronous Requests): an item asked for with the Asynchronous Indicator
// Mandatory is kept, answered Operation Pending with an Asynchronous
// Correlation Value, done by Process, and its result given by Poll as it
// would have been given at once. Tickets (2.0's Login, Delegated Login
// and Logout): a request authenticated by one acts as the client that
// logged in, for the number of requests and the time asked, within the
// Rights of a delegated one. Users and passwords (add_user). Log, Ping,
// Set Endpoint Role, Re-Provision, PKCS#11 (C_Initialize, C_GetInfo and
// C_Finalize), Set Defaults, Set Constraints and Get Constraints, the
// Query functions after 1.2's, 2.1's Rotate attributes, and the
// server-to-client Notify and Put written for a client to take.

namespace kmip;

import std;
import entropy;
import binary;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;
import kmip.server;
import crypto.x509;
import crypto.x509.keys;
import crypto.x509.create;

// --- State ----------------------------------------------------------------------

// An item kept to be done later: the request item's payload as it came,
// and once done its result.
struct Pending {
    corr: u8[..16],            // empty: the slot is free
    owner: u8[..128],
    op: u32,
    id: u8[..64],              // its Unique Batch Item ID
    version: Version,
    submitted: i64,            // microseconds (Submission Date is a Date Time Extended)
    stage: u32,                // STAGE_SUBMITTED, STAGE_COMPLETED
    has_payload: bool,
    request: u8[..8192],       // the Request Payload
    status: u32,
    reason: u32,
    msg: u8[..256],
    result: u8[..16384],       // the Response Payload's contents
}

fn empty_pending() -> Pending {
    Pending { corr: [], owner: [], op: 0, id: [], version: Version { major: 0, minor: 0 }, submitted: 0, stage: 0,
              has_payload: false, request: [], status: 0, reason: 0, msg: [], result: [] }
}

struct Ticket {
    value: u8[..16],           // empty: the slot is free
    owner: u8[..128],
    left: i64,                 // requests it may still authenticate; -1 for any number
    expires: i64,              // seconds; 0 for never
    delegated: bool,
    rights: u8[..4096],        // a Delegated Login's Rights, encoded
}

fn empty_ticket() -> Ticket { Ticket { value: [], owner: [], left: -1, expires: 0, delegated: false, rights: [] } }

struct User { name: u8[..128], password: u8[..128] }

fn empty_user() -> User { User { name: [], password: [] } }

// A PKCS#11 operation's state between calls: C_Initialize's Correlation
// Value and the client it is for.
struct P11Session { corr: u8[..16], owner: u8[..128] }

fn empty_p11() -> P11Session { P11Session { corr: [], owner: [] } }

// A user a password credential is checked against; false when the table
// is full. With no users, passwords are not checked.
fn add_user(s: Server&, name: const u8[:], password: const u8[:]) -> bool {
    if name.len == 0 || name.len > 128 || password.len > 128 { return false; }
    for k in 8 {
        if s.users[k].name.len == 0 {
            s.users[k].name.append(name);
            s.users[k].password.append(password);
            return true;
        }
    }
    return false;
}

fn password_ok(s: const Server&, name: const u8[:], password: const u8[:]) -> bool {
    var good = false;
    for u in s.users {
        if u.name.len > 0 && u.name[..] == name && u.password.len == password.len && bignum_eq(u.password, password) { good = true; }
    }
    return good;
}

fn has_users(s: const Server&) -> bool {
    for u in s.users { if u.name.len > 0 { return true; } }
    return false;
}

// Equal byte strings of equal length, without stopping at the first
// difference.
fn bignum_eq(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    var d: u8 = 0;
    for i in a.len { d = d | (a[i] ^ b[i]); }
    return d == 0;
}

// An Object Group the server knows (any when it has been told none).
fn known_group(s: const Server&, g: const u8[:]) -> bool {
    if s.groups.len == 0 { return true; }
    var at = 0;
    while at < s.groups.len {
        let n = 8 + padded(binary::u32be(s.groups, at + 4));
        let l: i64 = binary::u32be(s.groups, at + 4);
        if s.groups[at + 8..at + 8 + l] == g { return true; }
        at += n;
    }
    return false;
}

// Tells the server the Object Groups it knows (Set Defaults refuses
// others with Unknown Object Group); none: any.
fn add_group(s: Server&, g: const u8[:]) -> bool {
    var item: u8[>..] = [];
    put_text(item, TAG_OBJECT_GROUP, g);
    if s.groups.len + item.len > s.groups.cap { return false; }
    s.groups.append(item);
    return true;
}

// --- Authentication -------------------------------------------------------------

// What a request's credential comes to: the identity the request acts
// as, the ticket it used (-1 for none), or the Result Reason every item
// gets.
struct Who { owner: u8[..128], ticket: i64, reason: u32, msg: const u8[:] }

fn find_ticket(s: const Server&, value: const u8[:]) -> i64 {
    for k in 16 { if s.tickets[k].value.len > 0 && bignum_eq(s.tickets[k].value, value) { return k; } }
    return -1;
}

fn authenticate(s: Server&, tls_owner: const u8[:], buf: const u8[:], r: const Request&) -> Who {
    var w = Who { owner: [], ticket: -1, reason: 0, msg: "" };
    w.owner.append(tls_owner[..::min(tls_owner.len, 128)]);
    if r.cred_type == CRED_TICKET {
        let k = find_ticket(s, request_ticket(buf, r));
        if k < 0 || r.ticket_type != TICKET_LOGIN { w.reason = REASON_INVALID_TICKET; w.msg = "the ticket is not valid"; return w; }
        if s.tickets[k].expires != 0 && now_of(s) >= s.tickets[k].expires {
            s.tickets[k] = empty_ticket();
            w.reason = REASON_INVALID_TICKET;
            w.msg = "the ticket has expired";
            return w;
        }
        if s.tickets[k].left == 0 { w.reason = REASON_USAGE_LIMIT_EXCEEDED; w.msg = "the ticket's requests are used up"; return w; }
        if s.tickets[k].left > 0 { s.tickets[k].left--; }
        w.owner.clear();
        w.owner.append(s.tickets[k].owner);
        w.ticket = k;
        return w;
    }
    if r.cred_type == CRED_USERNAME_AND_PASSWORD && has_users(s) {
        let name = request_username(buf, r);
        if !password_ok(s, name, request_password(buf, r)) {
            w.reason = REASON_AUTHENTICATION_NOT_SUCCESSFUL;
            w.msg = "the username or password is not right";
            return w;
        }
        // A client known by its password and no certificate is its user.
        if tls_owner.len == 0 { w.owner.append(name[..::min(name.len, 128)]); }
        return w;
    }
    if r.cred_type != 0 && r.cred_type != CRED_USERNAME_AND_PASSWORD {
        w.reason = REASON_AUTHENTICATION_NOT_SUCCESSFUL;
        w.msg = "a credential type this server does not take";
        return w;
    }
    if s.require_auth && tls_owner.len == 0 && !(r.cred_type == CRED_USERNAME_AND_PASSWORD) {
        w.reason = REASON_AUTHENTICATION_NOT_SUCCESSFUL;
        w.msg = "a credential is required";
    }
    return w;
}

// Whether the object uid (of owner) has one of the Object Group names
// in the list at node g of the rights.
fn in_groups(s: const Server&, owner: const u8[:], uid: const u8[:], rights: const u8[:], doc: const Node[:], g: i64) -> bool {
    if uid.len == 0 { return false; }
    let i = find_object(s, owner, uid);
    if i < 0 { return false; }
    let a = attrs_of(s.objects[i]);
    var found = false;
    each(doc, g) { j =>
        let name, ok = as_text(rights, doc, j);
        each_attr(a) { t, item =>
            if t == TAG_OBJECT_GROUP {
                let v, vok = item_value(item, TEXT_STRING);
                if ok && vok && v == name { found = true; }
            }
        };
    };
    return found;
}

// Whether a delegated ticket's Rights let it do op on the object uid
// ("" when the item names none): some Right whose Operations (if given)
// hold op and whose Objects or Object Groups (if given) hold uid.
fn rights_allow(s: const Server&, owner: const u8[:], rights: const u8[:], op: u32, uid: const u8[:]) -> bool {
    var doc: Node[>..] = [];
    let r, e = decode(rights, Options { .. }, doc);
    if e != OK { return false; }
    var ok = false;
    each(doc, r) { k =>
        if doc[k].tag == TAG_RIGHT {
            var op_ok = true;
            let ops = child(doc, k, TAG_OPERATIONS);
            if ops >= 0 {
                op_ok = false;
                each(doc, ops) { j => let o, ook = as_enum(rights, doc, j); if ook && o == op { op_ok = true; } };
            }
            let objs = child(doc, k, TAG_OBJECTS);
            let groups = child(doc, k, TAG_OBJECT_GROUPS);
            var obj_ok = objs < 0 && groups < 0;
            if objs >= 0 {
                each(doc, objs) { j => let u, uok = as_text(rights, doc, j); if uok && uid.len > 0 && u == uid { obj_ok = true; } };
            }
            if groups >= 0 && in_groups(s, owner, uid, rights, doc, groups) { obj_ok = true; }
            if op_ok && obj_ok { ok = true; }
        }
    };
    return ok;
}

// The values of a list node (Operations, Objects, Object Groups) as raw
// items, for comparing.
fn list_has(buf: const u8[:], doc: const Node[:], list: i64, item: const u8[:]) -> bool {
    var found = false;
    each(doc, list) { j => if raw(buf, doc, j) == item { found = true; } };
    return found;
}

// Whether every item of list a (in buf a) is in list b (in buf b).
fn list_within(ab: const u8[:], ad: const Node[:], a: i64, bb: const u8[:], bd: const Node[:], b: i64) -> bool {
    var ok = true;
    each(ad, a) { j => if !list_has(bb, bd, b, raw(ab, ad, j)) { ok = false; } };
    return ok;
}

// Whether Rights asked for (want, a Rights item) are within the ones a
// delegated ticket has: each Right asked for is covered by one it has,
// whose Operations (if it lists any) include the asked Right's, and
// whose Objects and Object Groups (if it lists any) include the asked
// Right's, of the same kind.
fn rights_within(want: const u8[:], have: const u8[:]) -> bool {
    var wd: Node[>..] = [];
    let wr, we = decode(want, Options { .. }, wd);
    var hd: Node[>..] = [];
    let hr, he = decode(have, Options { .. }, hd);
    if we != OK || he != OK { return false; }
    var all = true;
    each(wd, wr) { k =>
        if wd[k].tag == TAG_RIGHT {
            let wops = child(wd, k, TAG_OPERATIONS);
            let wobj = child(wd, k, TAG_OBJECTS);
            let wgrp = child(wd, k, TAG_OBJECT_GROUPS);
            var covered = false;
            each(hd, hr) { c =>
                if hd[c].tag == TAG_RIGHT {
                    let hops = child(hd, c, TAG_OPERATIONS);
                    let hobj = child(hd, c, TAG_OBJECTS);
                    let hgrp = child(hd, c, TAG_OBJECT_GROUPS);
                    let ops_ok = hops < 0 || (wops >= 0 && list_within(want, wd, wops, have, hd, hops));
                    let any = hobj < 0 && hgrp < 0;
                    let obj_ok = wobj < 0 || (hobj >= 0 && list_within(want, wd, wobj, have, hd, hobj));
                    let grp_ok = wgrp < 0 || (hgrp >= 0 && list_within(want, wd, wgrp, have, hd, hgrp));
                    let named = (wobj >= 0 || wgrp >= 0) && obj_ok && grp_ok;
                    if ops_ok && (any || named) { covered = true; }
                }
            };
            if !covered { all = false; }
        }
    };
    return all;
}

// --- Login, Delegated Login, Logout ------------------------------------------------

fn new_ticket(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, delegated: bool, out: u8[>..]&) -> Outcome {
    var k: i64 = -1;
    for j in 16 { if k < 0 && s.tickets[j].value.len == 0 { k = j; } }
    if k < 0 { return fail(REASON_SERVER_LIMIT_EXCEEDED, "too many tickets"); }
    var t = empty_ticket();
    t.value.resize(16, 0);
    entropy::random_bytes(t.value);
    t.owner.append(owner[..::min(owner.len, 128)]);
    let n, nok = child_int(buf, doc, p, TAG_REQUEST_COUNT);
    if nok && n < 0 { return fail(REASON_INVALID_FIELD, "a negative Request Count"); }
    t.left = if nok && n > 0 { n } else { -1 };
    let lt = child(doc, p, TAG_LEASE_TIME);
    if is_type(doc, lt, INTERVAL) { let x, ok = as_interval(buf, doc, lt); if x != 0 { t.expires = now_of(s) + x; } }
    else if is_type(doc, lt, DATE_TIME) { let x, ok = as_datetime(buf, doc, lt); t.expires = x; }
    if delegated {
        let rr = child(doc, p, TAG_RIGHTS);
        if !is_type(doc, rr, STRUCTURE) { return fail(REASON_INVALID_MESSAGE, "no Rights"); }
        let raw_rights = raw(buf, doc, rr);
        if raw_rights.len > t.rights.cap { return fail(REASON_INVALID_FIELD, "Rights too long"); }
        t.rights.append(raw_rights);
        t.delegated = true;
    }
    s.tickets[k] = t;
    put_ticket(out, TICKET_LOGIN, s.tickets[k].value);
    return done();
}

fn op_login(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&, delegated: bool) -> Outcome {
    return new_ticket(s, owner, buf, doc, p, delegated, out);
}

fn op_logout(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let t = child(doc, p, TAG_TICKET);
    let v, vok = child_bytes(buf, doc, t, TAG_TICKET_VALUE);
    if !vok { return fail(REASON_INVALID_MESSAGE, "no Ticket"); }
    let k = find_ticket(s, v);
    if k < 0 || s.tickets[k].owner[..] != owner { return fail(REASON_INVALID_TICKET, "the ticket is not valid"); }
    s.tickets[k] = empty_ticket();
    return done();
}

// --- Asynchronous items ---------------------------------------------------------

// Whether an operation may be kept for later: not the ones about kept
// items, nor version discovery.
fn deferrable(op: u32) -> bool {
    op != OP_POLL && op != OP_CANCEL && op != OP_PROCESS && op != OP_QUERY_ASYNCHRONOUS_REQUESTS &&
    op != OP_DISCOVER_VERSIONS && op != OP_LOGIN && op != OP_LOGOUT && op != OP_DELEGATED_LOGIN && op != OP_INTEROP
}

// Keeps an item for later; its slot, or -1 when the server has no room
// (the item is then done at once).
fn defer_item(s: Server&, owner: const u8[:], v: Version, op: u32, id: const u8[:], buf: const u8[:], doc: const Node[:], p: i64) -> i64 {
    var k: i64 = -1;
    for j in 8 { if k < 0 && s.pending[j].corr.len == 0 { k = j; } }
    if k < 0 { return -1; }
    var e = empty_pending();
    if p >= 0 {
        let pl = raw(buf, doc, p);
        if pl.len > e.request.cap { return -1; }
        e.request.append(pl);
        e.has_payload = true;
    }
    if id.len > 64 || owner.len > 128 { return -1; }
    e.corr.resize(16, 0);
    entropy::random_bytes(e.corr);
    e.owner.append(owner);
    e.op = op;
    e.id.append(id);
    e.version = v;
    e.submitted = now_of(s) * 1000000;
    e.stage = STAGE_SUBMITTED;
    s.pending[k] = e;
    return k;
}

fn find_pending(s: const Server&, owner: const u8[:], corr: const u8[:]) -> i64 {
    for k in 8 { if s.pending[k].corr.len > 0 && s.pending[k].corr[..] == corr && s.pending[k].owner[..] == owner { return k; } }
    return -1;
}

// Does a kept item, keeping its result.
fn run_pending(s: Server&, k: i64) {
    var req: u8[>..] = [];
    req.append(s.pending[k].request);
    var doc: Node[>..] = [];
    var root: i64 = -1;
    if s.pending[k].has_payload {
        let r, e = decode(req, Options { .. }, doc);
        if e != OK {
            s.pending[k].status = STATUS_OPERATION_FAILED;
            s.pending[k].reason = REASON_INVALID_MESSAGE;
            s.pending[k].stage = STAGE_COMPLETED;
            return;
        }
        root = r;
    }
    var owner: u8[>..] = [];
    owner.append(s.pending[k].owner);
    let v = s.pending[k].version;
    let op = s.pending[k].op;
    var pl: u8[>..] = [];
    let res = process(s, owner, v, op, req, doc, root, pl);
    s.pending[k].stage = STAGE_COMPLETED;
    s.pending[k].result.clear();
    s.pending[k].msg.clear();
    if res.reason == 0 {
        s.pending[k].status = STATUS_SUCCESS;
        if pl.len > s.pending[k].result.cap {
            s.pending[k].status = STATUS_OPERATION_FAILED;
            s.pending[k].reason = REASON_RESPONSE_TOO_LARGE;
        } else {
            s.pending[k].result.append(pl);
        }
    } else {
        s.pending[k].status = STATUS_OPERATION_FAILED;
        s.pending[k].reason = res.reason;
        s.pending[k].msg.append(res.msg[..::min(res.msg.len, 256)]);
    }
}

fn async_value(buf: const u8[:], doc: const Node[:], p: i64) -> const u8[:] {
    let v, ok = child_bytes(buf, doc, p, TAG_ASYNCHRONOUS_CORRELATION_VALUE);
    return if ok { v } else { "" };
}

fn op_process(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let corr = async_value(buf, doc, p);
    let k = find_pending(s, owner, corr);
    if k < 0 { return fail(REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE, "DENIED"); }
    // handle does the item once this answer is written (process_after),
    // outside process.
    put_bytes(out, TAG_ASYNCHRONOUS_CORRELATION_VALUE, s.pending[k].corr);
    return done();
}

fn op_cancel(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let corr = async_value(buf, doc, p);
    let k = find_pending(s, owner, corr);
    if k < 0 { return fail(REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE, "DENIED"); }
    let result = if s.pending[k].stage == STAGE_COMPLETED { CANCEL_COMPLETED } else { CANCEL_CANCELED };
    put_bytes(out, TAG_ASYNCHRONOUS_CORRELATION_VALUE, s.pending[k].corr);
    put_enum(out, TAG_CANCELLATION_RESULT, result);
    s.pending[k] = empty_pending();
    return done();
}

fn put_async_request(out: u8[>..]&, e: const Pending&) {
    let a = begin(out, TAG_ASYNCHRONOUS_REQUEST);
    put_bytes(out, TAG_ASYNCHRONOUS_CORRELATION_VALUE, e.corr);
    put_enum(out, TAG_OPERATION, e.op);
    put_datetime_ext(out, TAG_SUBMISSION_DATE, e.submitted);
    put_enum(out, TAG_PROCESSING_STAGE, e.stage);
    end(out, a);
}

fn op_query_async(s: const Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let list = if p >= 0 { child(doc, p, TAG_ASYNCHRONOUS_CORRELATION_VALUES) } else { -1 };
    if list >= 0 {
        var bad = false;
        each(doc, list) { j =>
            let c, ok = as_bytes(buf, doc, j);
            let k = if ok { find_pending(s, owner, c) } else { -1 };
            if k < 0 { bad = true; } else { put_async_request(out, s.pending[k]); }
        };
        if bad { out.clear(); return fail(REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE, "DENIED"); }
        return done();
    }
    for e in s.pending { if e.corr.len > 0 && e.owner[..] == owner { put_async_request(out, e); } }
    return done();
}

// Poll: the item its result as the original's (written by handle), or
// still pending. Writes the whole batch item; false when the value is not
// known (handle then writes the failure).
fn poll_item(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, id: const u8[:], items: u8[>..]&) -> bool {
    let corr = async_value(buf, doc, p);
    let k = find_pending(s, owner, corr);
    if k < 0 { return false; }
    // Before 2.1 nothing asks for the item to be done: a Poll does it.
    if s.pending[k].stage != STAGE_COMPLETED && version_lt(v, V2_1) { run_pending(s, k); }
    let e = s.pending[k];
    let use_id = if id.len > 0 { id } else { e.id[..] };
    if e.stage != STAGE_COMPLETED {
        let it = begin(items, TAG_BATCH_ITEM);
        put_enum(items, TAG_OPERATION, e.op);
        if use_id.len > 0 { put_bytes(items, TAG_UNIQUE_BATCH_ITEM_ID, use_id); }
        put_enum(items, TAG_RESULT_STATUS, STATUS_OPERATION_PENDING);
        put_bytes(items, TAG_ASYNCHRONOUS_CORRELATION_VALUE, e.corr);
        end(items, it);
        return true;
    }
    let b, pl = begin_result(items, e.op, use_id, e.status, e.reason, e.msg);
    if e.status == STATUS_SUCCESS { items.append(e.result); }
    end_result(items, b, pl);
    s.pending[k] = empty_pending();
    return true;
}

// After a Process item: the item it names done (by handle, so that
// process, which run_pending calls, is not called from inside itself).
fn process_after(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64) {
    let k = find_pending(s, owner, async_value(buf, doc, p));
    if k >= 0 && s.pending[k].stage != STAGE_COMPLETED { run_pending(s, k); }
}

// The batch item of one kept for later.
fn put_pending_item(items: u8[>..]&, op: u32, id: const u8[:], corr: const u8[:]) {
    let it = begin(items, TAG_BATCH_ITEM);
    put_enum(items, TAG_OPERATION, op);
    if id.len > 0 { put_bytes(items, TAG_UNIQUE_BATCH_ITEM_ID, id); }
    put_enum(items, TAG_RESULT_STATUS, STATUS_OPERATION_PENDING);
    put_bytes(items, TAG_ASYNCHRONOUS_CORRELATION_VALUE, corr);
    end(items, it);
}

// --- Log, Ping, Set Endpoint Role --------------------------------------------------

fn op_log(s: Server&, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let m, ok = child_text(buf, doc, p, TAG_LOG_MESSAGE);
    if !ok { return fail(REASON_INVALID_MESSAGE, "no Log Message"); }
    s.log_count++;
    s.last_log.clear();
    s.last_log.append(m[..::min(m.len, 1024)]);
    return done();
}

fn op_set_endpoint_role(s: Server&, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let r, ok = child_enum(buf, doc, p, TAG_ENDPOINT_ROLE);
    if !ok { return fail(REASON_INVALID_MESSAGE, "no Endpoint Role"); }
    // This server does not turn round on a connection to send requests.
    if r != ENDPOINT_SERVER { return fail(REASON_FEATURE_NOT_SUPPORTED, "this server keeps the server's role"); }
    s.endpoint_role = r;
    put_enum(out, TAG_ENDPOINT_ROLE, r);
    return done();
}

// --- Re-Provision ---------------------------------------------------------------

// Re-Provision: a new client certificate from the server's CA, for a
// Certificate Request; a certificate the client gives, kept as its own;
// or with neither a new EC P-256 key pair and certificate for the
// client's identity (the private key's Unique Identifier given back).
fn op_reprovision(s: Server&, owner: const u8[:], v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let cert_given, cok = child_bytes(buf, doc, child(doc, p, TAG_CERTIFICATE), TAG_CERTIFICATE_VALUE);
    if cok {
        var sa = attrs();
        if !cert_attrs(cert_given, v, sa) { return fail(REASON_INVALID_FIELD, "the certificate is not read"); }
        let none = attrs();
        var uid: u8[>..] = [];
        let co = certificate(cert_given);
        let r = add_object_with(s, owner, co, none, sa, uid);
        if r.reason != 0 { return r; }
        put_text(out, TAG_UNIQUE_IDENTIFIER, uid);
        return done();
    }
    var csr: u8[>..] = [];
    let rc = request_csr(buf, doc, p, csr);
    if rc.reason != 0 { return rc; }
    var spki: u8[>..] = [];
    var subject: u8[>..] = [];
    var san: u8[>..] = [];
    var key_uid: u8[>..] = [];
    if csr.len > 0 {
        let r = read_csr(csr, spki, subject, san);
        if r.reason != 0 { return r; }
    } else {
        if owner.len == 0 { return fail(REASON_INVALID_FIELD, "a client with no identity to make a certificate for"); }
        let k = x509::generate_key(x509::KEY_EC_P256, 256);
        spki.append(x509::marshal_public_key(k));
        var text: u8[>..] = [];
        text.append("CN=");
        text.append(owner);
        let dn, dok = x509::name_der(text);
        if !dok { return fail(REASON_INVALID_FIELD, "the client's identity is not a name"); }
        subject.append(dn);
        let none = attrs();
        let pk = private_key(ALG_EC, 256, FMT_PKCS_8, x509::marshal_pkcs8(k));
        let r = add_object(s, owner, pk, none, key_uid);
        if r.reason != 0 { return r; }
    }
    var der: u8[>..] = [];
    let ri = issue(s, spki, subject, san, der);
    if ri.reason != 0 { return ri; }
    var sa = attrs();
    let ok = cert_attrs(der, v, sa);
    if key_uid.len > 0 { attr_link(sa, LINK_PRIVATE_KEY, key_uid); }
    let none = attrs();
    var uid: u8[>..] = [];
    let co = certificate(der);
    let r = add_object_with(s, owner, co, none, sa, uid);
    if r.reason != 0 { return r; }
    if key_uid.len > 0 { add_link(s, owner, key_uid, LINK_CERTIFICATE, uid); }
    put_text(out, TAG_UNIQUE_IDENTIFIER, if key_uid.len > 0 { key_uid[..] } else { uid[..] });
    return done();
}

// --- PKCS#11 --------------------------------------------------------------------

let CK_FN_INITIALIZE: u32 = 1;
let CK_FN_FINALIZE: u32 = 2;
let CK_FN_GET_INFO: u32 = 3;
let CKR_OK: u32 = 0x00000000;
let CKR_ARGUMENTS_BAD: u32 = 0x00000007;
let CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x00000054;
let CKR_CRYPTOKI_NOT_INITIALIZED: u32 = 0x00000190;

fn put_padded(out: u8[>..]&, s: const u8[:], n: i64) {
    for i in n { out.push(if i < s.len { s[i] } else { ' ' }); }
}

// PKCS#11 over KMIP (2.0, the PKCS#11 profile's encoding: CK_ULONG in 8
// bytes, big-endian): C_Initialize opens a session that its Correlation
// Value names, C_GetInfo tells of the library, C_Finalize closes it; other
// functions are answered CKR_FUNCTION_NOT_SUPPORTED.
fn op_pkcs11(s: Server&, owner: const u8[:], buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let f, fok = child_enum(buf, doc, p, TAG_PKCS11_FUNCTION);
    if !fok { return fail(REASON_INVALID_MESSAGE, "no PKCS#11 Function"); }
    let iface = child(doc, p, TAG_PKCS11_INTERFACE);
    if iface >= 0 { put_raw(out, raw(buf, doc, iface)); }
    put_enum(out, TAG_PKCS11_FUNCTION, f);
    let corr, cok = child_bytes(buf, doc, p, TAG_CORRELATION_VALUE);
    var k: i64 = -1;
    if cok { for j in 4 { if s.p11[j].corr.len > 0 && s.p11[j].corr[..] == corr && s.p11[j].owner[..] == owner { k = j; } } }
    var rv = CKR_OK;
    if f == CK_FN_INITIALIZE {
        for j in 4 { if k < 0 && s.p11[j].corr.len == 0 { k = j; } }
        if k < 0 { return fail(REASON_SERVER_LIMIT_EXCEEDED, "too many PKCS#11 sessions"); }
        s.p11[k] = empty_p11();
        s.p11[k].corr.resize(16, 0);
        entropy::random_bytes(s.p11[k].corr);
        s.p11[k].owner.append(owner[..::min(owner.len, 128)]);
        put_bytes(out, TAG_CORRELATION_VALUE, s.p11[k].corr);
    } else if k < 0 {
        rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    } else if f == CK_FN_GET_INFO {
        // CK_INFO: cryptokiVersion, manufacturerID[32], flags, libraryDescription[32], libraryVersion.
        var info: u8[>..] = [3, 0];
        put_padded(info, "gslib", 32);
        for i in 8 { info.push(0); }
        put_padded(info, "gslib kmip", 32);
        info.push(1);
        info.push(0);
        put_bytes(out, TAG_PKCS11_OUTPUT_PARAMETERS, info);
    } else if f == CK_FN_FINALIZE {
        s.p11[k] = empty_p11();
    } else {
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    }
    put_enum(out, TAG_PKCS11_RETURN_CODE, rv);
    return done();
}

// --- Defaults and constraints (2.1) ------------------------------------------------

fn groups_known(s: const Server&, buf: const u8[:], doc: const Node[:], i: i64) -> bool {
    var ok = true;
    each(doc, i) { k =>
        if doc[k].tag == TAG_OBJECT_DEFAULTS || doc[k].tag == TAG_CONSTRAINT {
            let g = child(doc, k, TAG_OBJECT_GROUPS);
            if g >= 0 { each(doc, g) { j => let n, nok = as_text(buf, doc, j); if !nok || !known_group(s, n) { ok = false; } }; }
        }
    };
    return ok;
}

fn op_set_defaults(s: Server&, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let d = if p >= 0 { child(doc, p, TAG_DEFAULTS_INFORMATION) } else { -1 };
    if d < 0 { s.defaults.clear(); return done(); }
    if !is_type(doc, d, STRUCTURE) { return fail(REASON_INVALID_FIELD, "Defaults Information is a Structure"); }
    if !groups_known(s, buf, doc, d) { return fail(REASON_UNKNOWN_OBJECT_GROUP, "an Object Group not known here"); }
    let item = raw(buf, doc, d);
    if item.len > s.defaults.cap { return fail(REASON_INVALID_FIELD, "Defaults Information too long"); }
    s.defaults.clear();
    s.defaults.append(item);
    return done();
}

fn op_set_constraints(s: Server&, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let c = if p >= 0 { child(doc, p, TAG_CONSTRAINTS) } else { -1 };
    if c < 0 { s.constraints.clear(); return done(); }
    if !is_type(doc, c, STRUCTURE) { return fail(REASON_INVALID_FIELD, "Constraints is a Structure"); }
    if !groups_known(s, buf, doc, c) { return fail(REASON_UNKNOWN_OBJECT_GROUP, "an Object Group not known here"); }
    let item = raw(buf, doc, c);
    if item.len > s.constraints.cap { return fail(REASON_INVALID_FIELD, "Constraints too long"); }
    s.constraints.clear();
    s.constraints.append(item);
    return done();
}

fn op_get_constraints(s: const Server&, out: u8[>..]&) -> Outcome {
    if s.constraints.len > 0 { out.append(s.constraints); }
    return done();
}

// Whether an object (an Object Defaults' or Constraint's Object Types,
// Object Groups) applies to an object of type t in the groups a gives.
fn applies(buf: const u8[:], doc: const Node[:], k: i64, t: u32, a: const Attrs&) -> bool {
    let types = child(doc, k, TAG_OBJECT_TYPES);
    var tok = types < 0;
    if types >= 0 { each(doc, types) { j => let x, ok = as_enum(buf, doc, j); if ok && x == t { tok = true; } }; }
    if !tok { return false; }
    let groups = child(doc, k, TAG_OBJECT_GROUPS);
    if groups < 0 { return true; }
    var gok = false;
    each(doc, groups) { j => let g, ok = as_text(buf, doc, j); if ok && has_item(a, raw(buf, doc, j)) { gok = true; } };
    return gok;
}

// The defaults Set Defaults gave, into a client's attributes for a new
// object of type t: each attribute the client did not give. For Create,
// Create Key Pair and Register to call before their own checks.
fn apply_defaults(s: const Server&, t: u32, a: Attrs&) {
    if s.defaults.len == 0 { return; }
    var doc: Node[>..] = [];
    let r, e = decode(s.defaults, Options { .. }, doc);
    if e != OK { return; }
    each(doc, r) { k =>
        if doc[k].tag == TAG_OBJECT_DEFAULTS && applies(s.defaults, doc, k, t, a) {
            let at = child(doc, k, TAG_ATTRIBUTES);
            if at >= 0 { each(doc, at) { j => if !has_attr(a, doc[j].tag) { a.enc.append(raw(s.defaults, doc, j)); } }; }
        }
    };
}

// Whether the attributes of a new object of type t keep to the
// constraints: every Constraint that applies, its attributes' values
// those the object has. Done, or Constraint Violation.
fn check_constraints(s: const Server&, t: u32, a: const Attrs&) -> Outcome {
    if s.constraints.len == 0 { return done(); }
    var doc: Node[>..] = [];
    let r, e = decode(s.constraints, Options { .. }, doc);
    if e != OK { return done(); }
    var ok = true;
    each(doc, r) { k =>
        if doc[k].tag == TAG_CONSTRAINT && applies(s.constraints, doc, k, t, a) {
            let at = child(doc, k, TAG_ATTRIBUTES);
            if at >= 0 { each(doc, at) { j => if has_attr(a, doc[j].tag) && !has_item(a, raw(s.constraints, doc, j)) { ok = false; } }; }
        }
    };
    if !ok { return fail(REASON_CONSTRAINT_VIOLATION, "an attribute the server's constraints do not allow"); }
    return done();
}

// --- Query ----------------------------------------------------------------------

// Query: 1.0's functions (kmip.server_manage's op_query), and the later
// ones: Capabilities, Profiles, RNGs, Validations (none), Client
// Registration Methods, Attestation Types (none), Defaults Information
// and Storage Protection Masks (2.1), and 2.0's Server Information.
fn op_query_all(s: const Server&, v: Version, buf: const u8[:], doc: const Node[:], p: i64, out: u8[>..]&) -> Outcome {
    let r = op_query(s, v, buf, doc, p, out);
    if r.reason != 0 || p < 0 { return r; }
    var fs: u32[>..] = [];
    each(doc, p) { k => if doc[k].tag == TAG_QUERY_FUNCTION { let f, ok = as_enum(buf, doc, k); if ok { fs.push(f); } } };
    for f in fs {
        if f == QUERY_SERVER_INFORMATION && is_v2(v) {
            let si = begin(out, TAG_SERVER_INFORMATION);
            end(out, si);
        } else if f == QUERY_CAPABILITIES && !version_lt(v, V1_3) {
            let c = begin(out, TAG_CAPABILITY_INFORMATION);
            put_bool(out, TAG_STREAMING_CAPABILITY, true);
            put_bool(out, TAG_ASYNCHRONOUS_CAPABILITY, true);
            put_bool(out, TAG_ATTESTATION_CAPABILITY, false);
            put_bool(out, TAG_BATCH_UNDO_CAPABILITY, true);
            put_bool(out, TAG_BATCH_CONTINUE_CAPABILITY, true);
            put_enum(out, TAG_UNWRAP_MODE, UNWRAP_PROCESSED);
            put_enum(out, TAG_DESTROY_ACTION, DESTROY_DELETED);
            put_enum(out, TAG_SHREDDING_ALGORITHM, SHRED_UNSUPPORTED);
            put_enum(out, TAG_RNG_MODE, RNG_MODE_SHARED_INSTANTIATION);
            end(out, c);
        } else if f == QUERY_PROFILES && !version_lt(v, V1_3) {
            let profiles: u32[5] = [PROFILE_SYMMETRIC_KEY_LIFECYCLE_SERVER, PROFILE_ASYMMETRIC_KEY_LIFECYCLE_SERVER,
                                    PROFILE_BASIC_CRYPTOGRAPHIC_SERVER, PROFILE_ADVANCED_CRYPTOGRAPHIC_SERVER,
                                    PROFILE_RNG_CRYPTOGRAPHIC_SERVER];
            for pr in profiles {
                let pi = begin(out, TAG_PROFILE_INFORMATION);
                put_enum(out, TAG_PROFILE_NAME, pr);
                if is_v2(v) {
                    let pv = begin(out, TAG_PROFILE_VERSION);
                    put_int(out, TAG_PROFILE_VERSION_MAJOR, v.major);
                    put_int(out, TAG_PROFILE_VERSION_MINOR, v.minor);
                    end(out, pv);
                }
                end(out, pi);
            }
        } else if f == QUERY_RNGS && !version_lt(v, V1_3) {
            let rp = begin(out, TAG_RNG_PARAMETERS);
            put_enum(out, TAG_RNG_ALGORITHM, RNG_UNSPECIFIED);
            end(out, rp);
        } else if f == QUERY_CLIENT_REGISTRATION_METHODS && !version_lt(v, V1_3) {
            put_enum(out, TAG_CLIENT_REGISTRATION_METHOD, REGISTER_CLIENT_GENERATED);
            put_enum(out, TAG_CLIENT_REGISTRATION_METHOD, REGISTER_CLIENT_REGISTERED);
        } else if f == QUERY_DEFAULTS_INFORMATION && !version_lt(v, V2_1) {
            if s.defaults.len > 0 { out.append(s.defaults); }
        } else if f == QUERY_STORAGE_PROTECTION_MASKS && !version_lt(v, V2_1) {
            let m = begin(out, TAG_PROTECTION_STORAGE_MASKS);
            put_int(out, TAG_PROTECTION_STORAGE_MASK, 0x00000001);   // Software
            end(out, m);
        }
    }
    return done();
}

// --- Rotate (2.1) ---------------------------------------------------------------

// A new object with a Rotate Name: generation 0, the latest (add_object_with).
fn rotate_on_create(a: Attrs&) {
    if !has_attr(a, TAG_ROTATE_NAME) || has_attr(a, TAG_ROTATE_GENERATION) { return; }
    var g: u8[>..] = [];
    put_int(g, TAG_ROTATE_GENERATION, 0);
    set_single(a, g);
    var l: u8[>..] = [];
    put_bool(l, TAG_ROTATE_LATEST, true);
    set_single(a, l);
}

// After Re-key, Re-key Key Pair or Re-certify: the replacement takes the
// old object's Rotate Name, the next generation and Rotate Latest; the
// old object is no longer the latest.
fn rotate_after_replace(s: Server&, owner: const u8[:], old_uid: const u8[:], new_uid: const u8[:]) {
    let i = find_object(s, owner, old_uid);
    let j = find_object(s, owner, new_uid);
    if i < 0 || j < 0 { return; }
    var a = attrs_of(s.objects[i]);
    let name = find_attr(a, TAG_ROTATE_NAME, 0);
    if name.len == 0 { return; }
    var nm: u8[>..] = [];
    nm.append(name);
    let gen, gok = get_int(a, TAG_ROTATE_GENERATION);
    var l: u8[>..] = [];
    put_bool(l, TAG_ROTATE_LATEST, false);
    set_single(a, l);
    let ok = set_attrs(s.objects[i], a);
    var b = attrs_of(s.objects[j]);
    set_single(b, nm);
    var g: u8[>..] = [];
    put_int(g, TAG_ROTATE_GENERATION, if gok { gen + 1 } else { 1 });
    set_single(b, g);
    var l2: u8[>..] = [];
    put_bool(l2, TAG_ROTATE_LATEST, true);
    set_single(b, l2);
    let ok2 = set_attrs(s.objects[j], b);
}

// --- Notify and Put (server to client) ---------------------------------------------

fn put_attrs_any(out: u8[>..]&, a: const Attrs&, v: Version) {
    if is_v2(v) { put_attributes(out, a, TAG_ATTRIBUTES); return; }
    each_attr(a) { t, item => let ok = put_attribute_1x(out, t, item); };
}

// A Put request message the server sends a client: the object uid of
// owner's with its attributes, new (PUT_NEW) or replacing replaced
// (PUT_REPLACE). False when there is no such object.
fn put_request(s: const Server&, owner: const u8[:], uid: const u8[:], function: u32, replaced: const u8[:], v: Version, out: u8[>..]&) -> bool {
    let i = find_object(s, owner, uid);
    if i < 0 { return false; }
    let o, ok = object_of(s.objects[i]);
    if !ok { return false; }
    let nc = no_credential();
    let m = begin_request(out, v, 1, nc);
    let it, p = begin_item(out, OP_PUT, "");
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    put_enum(out, TAG_PUT_FUNCTION, function);
    if replaced.len > 0 { put_text(out, TAG_REPLACED_UNIQUE_IDENTIFIER, replaced); }
    if !put_object(out, o) { return false; }
    let a = attrs_of(s.objects[i]);
    put_attrs_any(out, a, v);
    end_item(out, it, p);
    end(out, m);
    return true;
}

// A Notify request message: the attributes of uid that changed (all of
// them when changed is empty) and the ones deleted (their tags).
fn notify_request(s: const Server&, owner: const u8[:], uid: const u8[:], changed: const u32[:], deleted: const u32[:], v: Version, out: u8[>..]&) -> bool {
    let i = find_object(s, owner, uid);
    if i < 0 { return false; }
    let a = attrs_of(s.objects[i]);
    var pick = attrs();
    if changed.len == 0 { pick.enc.append(a.enc); }
    else { each_attr(a) { t, item => for c in changed { if c == t { pick.enc.append(item); } } }; }
    // The Last Change Date always.
    if !has_attr(pick, TAG_LAST_CHANGE_DATE) { pick.enc.append(find_attr(a, TAG_LAST_CHANGE_DATE, 0)); }
    let nc = no_credential();
    let m = begin_request(out, v, 1, nc);
    let it, p = begin_item(out, OP_NOTIFY, "");
    put_text(out, TAG_UNIQUE_IDENTIFIER, s.objects[i].uid);
    put_attrs_any(out, pick, v);
    for d in deleted {
        if is_v2(v) { put_enum(out, TAG_ATTRIBUTE_REFERENCE, d); }
        else { let n = attribute_name(d); if n.len > 0 { put_text(out, TAG_ATTRIBUTE_NAME, n); } }
    }
    end_item(out, it, p);
    end(out, m);
    return true;
}
