// kmip.client_session: the client's side of kmip.server_session.
// Asynchronous items (submit, poll, process_async, cancel, query_async),
// tickets (login, delegated_login with Rights, logout; a ticket then goes
// in the client's Credential), log, ping, set_endpoint_role, reprovision,
// PKCS#11 calls, Set Defaults and the constraints, the Query functions
// past 1.2's, and a client's answer to a server's Notify or Put. Like
// kmip.client's, each works on any client type with exchange, version,
// cred and the last_* fields.
//
//   let t, e = kmip::login(c, 10, 0);
//   c.cred = kmip::ticket_credential(kmip::TICKET_LOGIN, t);

namespace kmip;

import std;
import kmip;
import kmip.tables;
import kmip.messages;
import kmip.attributes;
import kmip.objects;
import kmip.client;

// One operation sent with header options; the response's one item into
// it. The payload's Node (-1 for none) and OK, or ERR_FAILED for a
// failure. An Operation Pending item is OK with c.last_status
// STATUS_OPERATION_PENDING. op 0 takes an item of any operation (Poll's).
fn call_with<C, F>(c: C&, op: u32, o: const HeaderOptions&, resp: u8[>..]&, doc: Node[>..]&, item: Item&) -> i64, i64 {
    var out: u8[>..] = [];
    let m = begin_request_with(out, c.version, 1, c.cred, o);
    let it, p = begin_item(out, if op != 0 { op } else { OP_POLL }, "");
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
    item = r.items[0];
    if op != 0 && item.op != 0 && item.op != op { return -1, ERR_PROTOCOL; }
    c.last_status = item.status;
    c.last_reason = item.reason;
    c.last_message.clear();
    let msg = result_message(resp, item);
    c.last_message.append(msg[..::min(msg.len, 1024)]);
    if item.status == STATUS_OPERATION_PENDING { return -1, OK; }
    if item.status != STATUS_SUCCESS { return -1, ERR_FAILED; }
    return item.payload, OK;
}

fn no_item() -> Item { Item { op: 0, status: 0, reason: 0, id_off: -1, id_len: 0, msg_off: -1, msg_len: 0, payload: -1, async_off: -1, async_len: 0 } }

// --- Asynchronous items ---------------------------------------------------------

// Sends one operation (its payload written by the block) asking for it
// to be done later (the Asynchronous Indicator Mandatory, in 2.1; true
// before). The Asynchronous Correlation Value when the server keeps it;
// empty when it answered at once (the payload is then in resp at the
// returned Node, as from call).
fn submit<C, F>(c: C&, op: u32, resp: u8[>..]&, doc: Node[>..]&) -> u8[>..], i64, i64 {
    var corr: u8[>..] = [];
    let o = HeaderOptions { async_ind: ASYNC_MANDATORY };
    var item = no_item();
    let p, e = call_with(c, op, o, resp, doc, item) { out => F(out); };
    if e != OK { return corr, -1, e; }
    if item.status == STATUS_OPERATION_PENDING { corr.append(item_async(resp, item)); }
    return corr, p, OK;
}

// Polls for an item kept for later: its result as the original
// operation's (the payload's Node, and the operation), or -1 while it is
// still pending (c.last_status STATUS_OPERATION_PENDING).
fn poll<C>(c: C&, corr: const u8[:], resp: u8[>..]&, doc: Node[>..]&) -> i64, u32, i64 {
    let o = HeaderOptions { .. };
    var item = no_item();
    let p, e = call_with(c, 0, o, resp, doc, item) { out => put_bytes(out, TAG_ASYNCHRONOUS_CORRELATION_VALUE, corr); };
    return p, item.op, e;
}

// 2.1's Process: the item is done now, its result kept for Poll.
fn process_async<C>(c: C&, corr: const u8[:]) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_PROCESS, resp, doc) { out => put_bytes(out, TAG_ASYNCHRONOUS_CORRELATION_VALUE, corr); };
    return e;
}

// Cancel: the Cancellation Result (CANCEL_CANCELED, CANCEL_COMPLETED, ...).
fn cancel<C>(c: C&, corr: const u8[:]) -> u32, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_CANCEL, resp, doc) { out => put_bytes(out, TAG_ASYNCHRONOUS_CORRELATION_VALUE, corr); };
    if e != OK { return 0, e; }
    let r, ok = child_enum(resp, doc, p, TAG_CANCELLATION_RESULT);
    if !ok { return 0, ERR_MISSING; }
    return r, OK;
}

struct AsyncRequest {
    corr: u8[..16],
    op: u32,
    submitted: i64,     // microseconds
    stage: u32,         // STAGE_SUBMITTED, STAGE_COMPLETED, ...
}

// 2.1's Query Asynchronous Requests: the client's items kept (those
// named, or all of them when corrs is empty).
fn query_async<C>(c: C&, corrs: const u8[..16][:]) -> AsyncRequest[>..], i64 {
    var r: AsyncRequest[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_QUERY_ASYNCHRONOUS_REQUESTS, resp, doc) { out =>
        if corrs.len > 0 {
            let l = begin(out, TAG_ASYNCHRONOUS_CORRELATION_VALUES);
            for x in corrs { put_bytes(out, TAG_ASYNCHRONOUS_CORRELATION_VALUE, x); }
            end(out, l);
        }
    };
    if e != OK { return r, e; }
    if p < 0 { return r, OK; }
    var bad = false;
    each(doc, p) { k =>
        if doc[k].tag == TAG_ASYNCHRONOUS_REQUEST {
            var a = AsyncRequest { corr: [], op: 0, submitted: 0, stage: 0 };
            let cv, cok = child_bytes(resp, doc, k, TAG_ASYNCHRONOUS_CORRELATION_VALUE);
            let op, ook = child_enum(resp, doc, k, TAG_OPERATION);
            let st, sok = child_enum(resp, doc, k, TAG_PROCESSING_STAGE);
            let sd = child(doc, k, TAG_SUBMISSION_DATE);
            if !cok || cv.len > 16 || !ook || !sok { bad = true; }
            else {
                a.corr.append(cv);
                a.op = op;
                a.stage = st;
                if is_type(doc, sd, DATE_TIME_EXTENDED) { a.submitted = binary_be64(value(resp, doc, sd)); }
                else { let t, tok = as_datetime(resp, doc, sd); if tok { a.submitted = t * 1000000; } }
                r.push(a);
            }
        }
    };
    if bad { return r, ERR_MISSING; }
    return r, OK;
}

fn binary_be64(b: const u8[:]) -> i64 {
    var x: u64 = 0;
    for i in 8 { x = (x << 8) | b[i]; }
    return x as! i64;
}

// --- Tickets --------------------------------------------------------------------

fn ticket_of(resp: const u8[:], doc: const Node[:], p: i64) -> u8[>..], i64 {
    var t: u8[>..] = [];
    let v, ok = child_bytes(resp, doc, child(doc, p, TAG_TICKET), TAG_TICKET_VALUE);
    if !ok { return t, ERR_MISSING; }
    t.append(v);
    return t, OK;
}

// Login (2.0): a ticket for requests (count of them, 0 for any number)
// for lease seconds (0 for no limit). Put it in the client's credential
// with ticket_credential(TICKET_LOGIN, ticket).
fn login<C>(c: C&, count: i32, lease: u32) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_LOGIN, resp, doc) { out =>
        put_interval(out, TAG_LEASE_TIME, lease);
        put_int(out, TAG_REQUEST_COUNT, count);
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let t, te = ticket_of(resp, doc, p);
    return t, te;
}

// Rights for a Delegated Login: each Right some operations (none: any)
// on some objects (none: any).
struct Rights { enc: u8[>..] }

fn rights() -> Rights { Rights { enc: [] } }

fn add_right(r: Rights&, ops: const u32[:], uids: const u8[..64][:]) {
    let k = begin(r.enc, TAG_RIGHT);
    if ops.len > 0 {
        let o = begin(r.enc, TAG_OPERATIONS);
        for op in ops { put_enum(r.enc, TAG_OPERATION, op); }
        end(r.enc, o);
    }
    if uids.len > 0 {
        let o = begin(r.enc, TAG_OBJECTS);
        for u in uids { put_text(r.enc, TAG_UNIQUE_IDENTIFIER, u); }
        end(r.enc, o);
    }
    end(r.enc, k);
}

// A Right of some operations (none: any) on the objects of some Object
// Groups.
fn add_right_groups(r: Rights&, ops: const u32[:], groups: const u8[..64][:]) {
    let k = begin(r.enc, TAG_RIGHT);
    if ops.len > 0 {
        let o = begin(r.enc, TAG_OPERATIONS);
        for op in ops { put_enum(r.enc, TAG_OPERATION, op); }
        end(r.enc, o);
    }
    let g = begin(r.enc, TAG_OBJECT_GROUPS);
    for n in groups { put_text(r.enc, TAG_OBJECT_GROUP, n); }
    end(r.enc, g);
    end(r.enc, k);
}

// Delegated Login (2.0): a ticket that may do only what the Rights say.
// A delegated ticket whose Rights allow Delegated Login makes others,
// with Rights within its own.
fn delegated_login<C>(c: C&, count: i32, lease: u32, r: const Rights&) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_DELEGATED_LOGIN, resp, doc) { out =>
        put_interval(out, TAG_LEASE_TIME, lease);
        put_int(out, TAG_REQUEST_COUNT, count);
        let s = begin(out, TAG_RIGHTS);
        out.append(r.enc);
        end(out, s);
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let t, te = ticket_of(resp, doc, p);
    return t, te;
}

fn logout<C>(c: C&, ticket: const u8[:]) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_LOGOUT, resp, doc) { out => put_ticket(out, TICKET_LOGIN, ticket); };
    return e;
}

// --- Log (log_message), Ping, Set Endpoint Role, Re-Provision ----------------------------------------

fn log_message<C>(c: C&, message: const u8[:]) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_LOG, resp, doc) { out => put_text(out, TAG_LOG_MESSAGE, message); };
    return e;
}

fn ping<C>(c: C&) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_PING, resp, doc) { out => };
    return e;
}

fn set_endpoint_role<C>(c: C&, role: u32) -> u32, i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_SET_ENDPOINT_ROLE, resp, doc) { out => put_enum(out, TAG_ENDPOINT_ROLE, role); };
    if e != OK { return 0, e; }
    let r, ok = child_enum(resp, doc, p, TAG_ENDPOINT_ROLE);
    return r, if ok { OK } else { ERR_MISSING };
}

// Re-Provision (2.0): a new client certificate for a PKCS #10 request
// (DER), or with none a key pair and certificate the server makes. The
// certificate's Unique Identifier, or the private key's when the server
// made the key.
fn reprovision<C>(c: C&, csr: const u8[:]) -> u8[>..], i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_REPROVISION, resp, doc) { out =>
        if csr.len > 0 {
            put_enum(out, TAG_CERTIFICATE_REQUEST_TYPE, CSR_PKCS_10);
            put_bytes(out, TAG_CERTIFICATE_REQUEST, csr);
        }
    };
    if e != OK { var none: u8[>..] = []; return none, e; }
    let u, ue = uid_of(resp, doc, p, TAG_UNIQUE_IDENTIFIER);
    return u, ue;
}

// --- PKCS#11 --------------------------------------------------------------------

struct P11Result {
    rv: u32,             // the CK_RV
    corr: u8[..256],     // a Correlation Value for the next call, when given
    output: u8[>..],     // the Output Parameters, in the PKCS#11 profile's encoding
}

// One PKCS#11 function (1 C_Initialize, 2 C_Finalize, 3 C_GetInfo, ...)
// with its Input Parameters, the Correlation Value of the session.
fn pkcs11<C>(c: C&, function: u32, corr: const u8[:], input: const u8[:]) -> P11Result, i64 {
    var r = P11Result { rv: 0, corr: [], output: [] };
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_PKCS_11, resp, doc) { out =>
        put_enum(out, TAG_PKCS11_FUNCTION, function);
        if corr.len > 0 { put_bytes(out, TAG_CORRELATION_VALUE, corr); }
        if input.len > 0 { put_bytes(out, TAG_PKCS11_INPUT_PARAMETERS, input); }
    };
    if e != OK { return r, e; }
    let rv, rok = child_enum(resp, doc, p, TAG_PKCS11_RETURN_CODE);
    if !rok { return r, ERR_MISSING; }
    r.rv = rv;
    let cv, cok = child_bytes(resp, doc, p, TAG_CORRELATION_VALUE);
    if cok && cv.len <= 256 { r.corr.append(cv); }
    let ov, ook = child_bytes(resp, doc, p, TAG_PKCS11_OUTPUT_PARAMETERS);
    if ook { r.output.append(ov); }
    return r, OK;
}

// --- Defaults and constraints (2.1) ------------------------------------------------

// An Object Defaults (for Set Defaults) or Constraint (for Set
// Constraints): for objects of the types (none: all) in the groups
// (none: any), the attributes.
fn put_object_rule(out: u8[>..]&, tag: u32, types: const u32[:], groups: const u8[..64][:], a: const Attrs&) {
    let s = begin(out, tag);
    if types.len > 0 {
        let t = begin(out, TAG_OBJECT_TYPES);
        for x in types { put_enum(out, TAG_OBJECT_TYPE, x); }
        end(out, t);
    }
    put_attributes(out, a, TAG_ATTRIBUTES);
    if groups.len > 0 {
        let g = begin(out, TAG_OBJECT_GROUPS);
        for x in groups { put_text(out, TAG_OBJECT_GROUP, x); }
        end(out, g);
    }
    end(out, s);
}

// Set Defaults with the Object Defaults written (put_object_rule with
// TAG_OBJECT_DEFAULTS); empty clears them.
fn set_defaults<C>(c: C&, object_defaults: const u8[:]) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_SET_DEFAULTS, resp, doc) { out =>
        if object_defaults.len > 0 {
            let d = begin(out, TAG_DEFAULTS_INFORMATION);
            out.append(object_defaults);
            end(out, d);
        }
    };
    return e;
}

// Set Constraints with the Constraints written (put_object_rule with
// TAG_CONSTRAINT); empty clears them.
fn set_constraints<C>(c: C&, constraints: const u8[:]) -> i64 {
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_SET_CONSTRAINTS, resp, doc) { out =>
        if constraints.len > 0 {
            let d = begin(out, TAG_CONSTRAINTS);
            out.append(constraints);
            end(out, d);
        }
    };
    return e;
}

// Get Constraints: the Constraint Structures, encoded one after another.
fn get_constraints<C>(c: C&) -> u8[>..], i64 {
    var r: u8[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_GET_CONSTRAINTS, resp, doc) { out => };
    if e != OK { return r, e; }
    let cs = if p >= 0 { child(doc, p, TAG_CONSTRAINTS) } else { -1 };
    if cs >= 0 { each(doc, cs) { k => r.append(raw(resp, doc, k)); }; }
    return r, OK;
}

// --- Query past 1.2 --------------------------------------------------------------

struct Capabilities {
    streaming: bool,
    asynchronous: bool,
    attestation: bool,
    batch_undo: bool,
    batch_continue: bool,
}

fn query_capabilities<C>(c: C&) -> Capabilities, i64 {
    var r = Capabilities { streaming: false, asynchronous: false, attestation: false, batch_undo: false, batch_continue: false };
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_QUERY, resp, doc) { out => put_enum(out, TAG_QUERY_FUNCTION, QUERY_CAPABILITIES); };
    if e != OK { return r, e; }
    let ci = child(doc, p, TAG_CAPABILITY_INFORMATION);
    if ci < 0 { return r, ERR_MISSING; }
    let a, a1 = child_bool(resp, doc, ci, TAG_STREAMING_CAPABILITY);
    let b, b1 = child_bool(resp, doc, ci, TAG_ASYNCHRONOUS_CAPABILITY);
    let d, d1 = child_bool(resp, doc, ci, TAG_ATTESTATION_CAPABILITY);
    let u, u1 = child_bool(resp, doc, ci, TAG_BATCH_UNDO_CAPABILITY);
    let k, k1 = child_bool(resp, doc, ci, TAG_BATCH_CONTINUE_CAPABILITY);
    r.streaming = a1 && a;
    r.asynchronous = b1 && b;
    r.attestation = d1 && d;
    r.batch_undo = u1 && u;
    r.batch_continue = k1 && k;
    return r, OK;
}

// One Query function whose answer is a list of enumerations under one
// tag (Profiles' names inside Profile Information, Client Registration
// Methods).
fn query_enums<C>(c: C&, function: u32, tag: u32) -> u32[>..], i64 {
    var r: u32[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_QUERY, resp, doc) { out => put_enum(out, TAG_QUERY_FUNCTION, function); };
    if e != OK { return r, e; }
    each(doc, p) { k =>
        if doc[k].tag == tag { let v, ok = as_enum(resp, doc, k); if ok { r.push(v); } }
        if doc[k].tag == TAG_PROFILE_INFORMATION && tag == TAG_PROFILE_NAME {
            let v, ok = child_enum(resp, doc, k, TAG_PROFILE_NAME);
            if ok { r.push(v); }
        }
    };
    return r, OK;
}

fn query_profiles<C>(c: C&) -> u32[>..], i64 {
    let r, e = query_enums(c, QUERY_PROFILES, TAG_PROFILE_NAME);
    return r, e;
}

fn query_registration_methods<C>(c: C&) -> u32[>..], i64 {
    let r, e = query_enums(c, QUERY_CLIENT_REGISTRATION_METHODS, TAG_CLIENT_REGISTRATION_METHOD);
    return r, e;
}

// 2.1's Query Defaults Information: the Object Defaults, encoded.
fn query_defaults<C>(c: C&) -> u8[>..], i64 {
    var r: u8[>..] = [];
    var resp: u8[>..] = [];
    var doc: Node[>..] = [];
    let p, e = call(c, OP_QUERY, resp, doc) { out => put_enum(out, TAG_QUERY_FUNCTION, QUERY_DEFAULTS_INFORMATION); };
    if e != OK { return r, e; }
    let d = child(doc, p, TAG_DEFAULTS_INFORMATION);
    if d >= 0 { each(doc, d) { k => r.append(raw(resp, doc, k)); }; }
    return r, OK;
}

// --- A server's Notify and Put ------------------------------------------------------

// What a server pushed: a Notify's object and the deleted attributes'
// tags, or a Put's object, new or replacing replaced; the attributes and
// a Put's object itself are take_server_request's out parameters.
struct ServerRequest {
    op: u32,                  // OP_NOTIFY or OP_PUT
    uid: u8[..64],
    put_function: u32,        // PUT_NEW, PUT_REPLACE
    replaced: u8[..64],
    has_object: bool,
    deleted: u32[..64],
}

// Reads a request message a server sent the client (Notify or Put, one
// item), its attributes into a and a Put's object into object, and
// writes the response the client sends back. OK, or an error for a
// message that is not one (the response then says so).
fn take_server_request(req: const u8[:], resp: u8[>..]&, object: Object&, a: Attrs&) -> ServerRequest, i64 {
    var r = ServerRequest { op: 0, uid: [], put_function: 0, replaced: [], has_object: false, deleted: [] };
    a.enc.clear();
    resp.clear();
    var doc: Node[>..] = [];
    let root, e = decode(req, Options { .. }, doc);
    if e != OK { return r, e; }
    let q, pe = parse_request(req, doc, root);
    if pe != OK || q.items.len != 1 { return r, if pe != OK { pe } else { ERR_PROTOCOL }; }
    let it = q.items[0];
    let p = it.payload;
    var ok = (it.op == OP_NOTIFY || it.op == OP_PUT) && p >= 0;
    var reason: u32 = REASON_OPERATION_NOT_SUPPORTED;
    if ok {
        r.op = it.op;
        let u, uok = child_text(req, doc, p, TAG_UNIQUE_IDENTIFIER);
        if !uok || u.len > 64 { ok = false; reason = REASON_INVALID_MESSAGE; } else { r.uid.append(u); }
    }
    if ok {
        let x = read_attrs(req, doc, p);
        a.enc.append(x.enc);
        if it.op == OP_PUT {
            let f, fok = child_enum(req, doc, p, TAG_PUT_FUNCTION);
            if fok { r.put_function = f; } else { ok = false; reason = REASON_INVALID_MESSAGE; }
            let ru, rok = child_text(req, doc, p, TAG_REPLACED_UNIQUE_IDENTIFIER);
            if rok && ru.len <= 64 { r.replaced.append(ru); }
            var types: u32[6] = [OBJ_SYMMETRIC_KEY, OBJ_PRIVATE_KEY, OBJ_PUBLIC_KEY, OBJ_CERTIFICATE, OBJ_SECRET_DATA, OBJ_OPAQUE_DATA];
            for ty in types {
                if !r.has_object && child(doc, p, object_tag(ty)) >= 0 {
                    let o, ook = read_object(req, doc, p, ty);
                    if ook { object = copy(o); r.has_object = true; }
                }
            }
        } else {
            each(doc, p) { k =>
                if doc[k].tag == TAG_ATTRIBUTE_REFERENCE && r.deleted.len < 64 { r.deleted.push(reference_tag(req, doc, k)); }
                if doc[k].tag == TAG_ATTRIBUTE_NAME && r.deleted.len < 64 { let n, nok = as_text(req, doc, k); if nok { r.deleted.push(attribute_tag(n)); } }
            };
        }
    }
    let m = begin_response(resp, q.version, 0, 1);
    if ok {
        // A response with no payload.
        let b = begin(resp, TAG_BATCH_ITEM);
        put_enum(resp, TAG_OPERATION, it.op);
        let id = request_item_id(req, it);
        if id.len > 0 { put_bytes(resp, TAG_UNIQUE_BATCH_ITEM_ID, id); }
        put_enum(resp, TAG_RESULT_STATUS, STATUS_SUCCESS);
        end(resp, b);
    } else {
        let b, pl = begin_result(resp, it.op, request_item_id(req, it), STATUS_OPERATION_FAILED, reason, "not taken");
        end_result(resp, b, pl);
    }
    end(resp, m);
    return r, if ok { OK } else { ERR_FAILED };
}
