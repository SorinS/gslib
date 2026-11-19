// What spans requests, through kmip.local: KMIP 2.1 spoken and
// negotiated; asynchronous items kept, processed, polled, queried and
// canceled; Login's and Delegated Login's tickets, their counts and
// rights, Logout; users' passwords; Log, Ping, Set Endpoint Role;
// PKCS#11's C_Initialize, C_GetInfo and C_Finalize; Set Defaults, the
// constraints and the Query functions past 1.2; Re-Provision; 2.1's
// Rotate attributes; and a server's Put and Notify taken by a client.

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.kmip.client_session;
import gslib.kmip.local;
import gslib.kmip.server;
import gslib.kmip.server_session;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn aes_attrs() -> kmip::Attrs {
    var a = kmip::attrs();
    kmip::attr_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 128);
    kmip::attr_usage(a, kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT);
    return a;
}

fn make_key(c: kmip::Local&) -> u8[>..], i64 {
    let a = aes_attrs();
    let u, e = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    return u, e;
}

fn write_create(out: u8[>..]&) {
    kmip::put_enum(out, kmip::TAG_OBJECT_TYPE, kmip::OBJ_SYMMETRIC_KEY);
    let a = aes_attrs();
    kmip::put_attributes(out, a, kmip::TAG_ATTRIBUTES);
}

fn versions() {
    var c = kmip::local("alice");
    c.version = kmip::V2_1;
    let vs, e = kmip::discover_versions(c, kmip::ALL_VERSIONS);
    check("2.1 among the versions", e == kmip::OK && vs.len == 7 && kmip::version_eq(vs[0], kmip::V2_1));
    c.version = kmip::V1_1;
    let v, ne = kmip::negotiate(c);
    check("negotiated 2.1", ne == kmip::OK && kmip::version_eq(v, kmip::V2_1));
}

fn asynchronous() {
    var c = kmip::local("alice");
    c.version = kmip::V2_1;
    var resp: u8[>..] = [];
    var doc: kmip::Node[>..] = [];
    let corr, p0, e = kmip::submit(c, kmip::OP_CREATE, resp, doc) { out => write_create(out); };
    check("Create kept for later", e == kmip::OK && corr.len == 16 && c.last_status == kmip::STATUS_OPERATION_PENDING);
    let p1, op1, e1 = kmip::poll(c, corr, resp, doc);
    check("polled before Process: pending", e1 == kmip::OK && p1 < 0 && op1 == kmip::OP_CREATE &&
          c.last_status == kmip::STATUS_OPERATION_PENDING);
    var none: u8[..16][>..] = [];
    let q0, qe0 = kmip::query_async(c, none);
    check("listed, submitted", qe0 == kmip::OK && q0.len == 1 && q0[0].stage == kmip::STAGE_SUBMITTED &&
          q0[0].op == kmip::OP_CREATE && q0[0].corr[..] == corr[..] && q0[0].submitted > 0);
    check("Process", kmip::process_async(c, corr) == kmip::OK);
    var one: u8[..16][>..] = [];
    var x: u8[..16] = [];
    x.append(corr);
    one.push(x);
    let q1, qe1 = kmip::query_async(c, one);
    check("listed, completed", qe1 == kmip::OK && q1.len == 1 && q1[0].stage == kmip::STAGE_COMPLETED);
    let p2, op2, e2 = kmip::poll(c, corr, resp, doc);
    check("polled: the Create's result", e2 == kmip::OK && op2 == kmip::OP_CREATE && p2 >= 0);
    let uid, ue = kmip::uid_of(resp, doc, p2, kmip::TAG_UNIQUE_IDENTIFIER);
    let o, ge = kmip::get(c, uid, 0);
    check("the key made", ue == kmip::OK && ge == kmip::OK && o.material.len == 16);
    let p3, op3, e3 = kmip::poll(c, corr, resp, doc);
    check("polled again: gone", e3 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE, c.version));
    let bad, be = kmip::cancel(c, "1234567890");
    check("Cancel of nothing", be == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE, c.version));
    check("Process of nothing", kmip::process_async(c, "1234567890") == kmip::ERR_FAILED);
    let c2, p4, e4 = kmip::submit(c, kmip::OP_CREATE, resp, doc) { out => write_create(out); };
    let r4, ce4 = kmip::cancel(c, c2);
    check("canceled before done", e4 == kmip::OK && ce4 == kmip::OK && r4 == kmip::CANCEL_CANCELED);
    let c3, p5, e5 = kmip::submit(c, kmip::OP_CREATE, resp, doc) { out => write_create(out); };
    let pe5 = kmip::process_async(c, c3);
    let r5, ce5 = kmip::cancel(c, c3);
    check("canceled once done: Completed", e5 == kmip::OK && pe5 == kmip::OK && ce5 == kmip::OK && r5 == kmip::CANCEL_COMPLETED);
    // Another client's items are not this one's.
    let c4, p6, e6 = kmip::submit(c, kmip::OP_CREATE, resp, doc) { out => write_create(out); };
    c.owner.clear();
    c.owner.append("mallory");
    let p7, op7, e7 = kmip::poll(c, c4, resp, doc);
    check("another client's item unknown", e7 == kmip::ERR_FAILED);
    c.owner.clear();
    c.owner.append("alice");
    // 2.0: the indicator is a Boolean the server may take as optional.
    c.version = kmip::V2_0;
    let c5, p8, e8 = kmip::submit(c, kmip::OP_CREATE, resp, doc) { out => write_create(out); };
    check("2.0: done at once", e8 == kmip::OK && c5.len == 0 && p8 >= 0 && c.last_status == kmip::STATUS_SUCCESS);
    // A batch: each item kept apart.
    c.version = kmip::V2_1;
    var out: u8[>..] = [];
    let opts = kmip::HeaderOptions { async_ind: kmip::ASYNC_MANDATORY };
    let m = kmip::begin_request_with(out, kmip::V2_1, 2, c.cred, opts);
    let i1, q1p = kmip::begin_item(out, kmip::OP_CREATE, "01");
    write_create(out);
    kmip::end_item(out, i1, q1p);
    let i2, q2p = kmip::begin_item(out, kmip::OP_CREATE, "02");
    write_create(out);
    kmip::end_item(out, i2, q2p);
    kmip::end(out, m);
    let ee = kmip::exchange(c, out, resp);
    doc.clear();
    let root, de = kmip::decode(resp, kmip::Options { .. }, doc);
    let rr, pe = kmip::parse_response(resp, doc, root);
    check("two items pending", ee == kmip::OK && pe == kmip::OK && rr.items.len == 2 &&
          rr.items[0].status == kmip::STATUS_OPERATION_PENDING && rr.items[1].status == kmip::STATUS_OPERATION_PENDING &&
          kmip::item_id(resp, rr.items[1])[..] == "02");
    var second: u8[>..] = [];
    second.append(kmip::item_async(resp, rr.items[1]));
    let pp = kmip::process_async(c, second);
    let p9, op9, e9 = kmip::poll(c, second, resp, doc);
    doc.clear();
    let root2, de2 = kmip::decode(resp, kmip::Options { .. }, doc);
    let rr2, pe2 = kmip::parse_response(resp, doc, root2);
    check("polled: the item's own ID", pp == kmip::OK && e9 == kmip::OK && pe2 == kmip::OK &&
          kmip::item_id(resp, rr2.items[0])[..] == "02");
}

fn tickets() {
    var c = kmip::local("alice");
    c.version = kmip::V2_0;
    let t, e = kmip::login(c, 2, 0);
    check("Login", e == kmip::OK && t.len == 16);
    c.cred = kmip::ticket_credential(kmip::TICKET_LOGIN, t);
    var q: u32[1] = [kmip::QUERY_OPERATIONS];
    let r1, e1 = kmip::query(c, q);
    let r2, e2 = kmip::query(c, q);
    let r3, e3 = kmip::query(c, q);
    check("two requests on the ticket", e1 == kmip::OK && e2 == kmip::OK);
    check("the third: used up", e3 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_USAGE_LIMIT_EXCEEDED, c.version));
    c.cred = kmip::no_credential();
    let t2, e4 = kmip::login(c, 0, 0);
    c.cred = kmip::ticket_credential(kmip::TICKET_LOGIN, t2);
    let uid, ce = make_key(c);
    check("a ticket's requests act as who logged in", e4 == kmip::OK && ce == kmip::OK);
    c.owner.clear();
    c.owner.append("bob");
    let a0, ge = kmip::get_attributes(c, uid, []);
    check("even on another connection", ge == kmip::OK);
    c.owner.clear();
    c.owner.append("alice");
    check("Logout", kmip::logout(c, t2) == kmip::OK);
    let r5, e5 = kmip::query(c, q);
    check("after Logout: Invalid Ticket", e5 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_TICKET, c.version));
    c.cred = kmip::ticket_credential(kmip::TICKET_LOGIN, "not a ticket");
    let r6, e6 = kmip::query(c, q);
    check("a made-up ticket", e6 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_INVALID_TICKET, c.version));
    // Delegated: Query anywhere, Get Attributes on one key.
    c.cred = kmip::no_credential();
    let u0, e7 = make_key(c);
    let u1, e8 = make_key(c);
    var rights = kmip::rights();
    var noobj: u8[..64][>..] = [];
    let ops1: u32[1] = [kmip::OP_QUERY];
    kmip::add_right(rights, ops1, noobj);
    var objs: u8[..64][>..] = [];
    var x: u8[..64] = [];
    x.append(u0);
    objs.push(x);
    let ops2: u32[1] = [kmip::OP_GET_ATTRIBUTES];
    kmip::add_right(rights, ops2, objs);
    let dt, de = kmip::delegated_login(c, 0, 3600, rights);
    check("Delegated Login", de == kmip::OK && dt.len == 16);
    c.cred = kmip::ticket_credential(kmip::TICKET_LOGIN, dt);
    let r9, e9 = kmip::query(c, q);
    let a1, e10 = kmip::get_attributes(c, u0, []);
    let o1, e11 = kmip::get(c, u0, 0);
    let a2, e12 = kmip::get_attributes(c, u1, []);
    check("rights: Query", e9 == kmip::OK);
    check("rights: Get Attributes of the key named", e10 == kmip::OK);
    check("rights: not Get", e11 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_NOT_AUTHORISED, c.version));
    check("rights: not another key", e12 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_NOT_AUTHORISED, c.version));
    let t3, e13 = kmip::login(c, 0, 0);
    check("a delegated ticket logs in no one", e13 == kmip::ERR_FAILED);
    // Rights on an Object Group, and a ticket that delegates within its own.
    c.cred = kmip::no_credential();
    var ga = kmip::attrs();
    kmip::attr_enum(ga, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(ga, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 128);
    kmip::attr_text(ga, kmip::TAG_OBJECT_GROUP, "group one");
    let gk, egk = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, ga);
    var groups: u8[..64][>..] = [];
    var g1: u8[..64] = [];
    g1.append("group one");
    groups.push(g1);
    var gr = kmip::rights();
    kmip::add_right_groups(gr, ops2, groups);
    let ops3: u32[2] = [kmip::OP_DELEGATED_LOGIN, kmip::OP_QUERY];
    kmip::add_right(gr, ops3, noobj);
    let gt, ege = kmip::delegated_login(c, 0, 3600, gr);
    c.cred = kmip::ticket_credential(kmip::TICKET_LOGIN, gt);
    let ga1, eg1 = kmip::get_attributes(c, gk, []);
    let ga2, eg2 = kmip::get_attributes(c, u1, []);
    check("rights on an Object Group: its key", egk == kmip::OK && ege == kmip::OK && eg1 == kmip::OK);
    check("rights on an Object Group: not another", eg2 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_NOT_AUTHORISED, c.version));
    var narrower = kmip::rights();
    kmip::add_right(narrower, ops1, noobj);
    let nt, ent = kmip::delegated_login(c, 0, 3600, narrower);
    check("a delegated ticket delegates within its Rights", ent == kmip::OK && nt.len == 16);
    var wider = kmip::rights();
    let ops4: u32[1] = [kmip::OP_GET];
    kmip::add_right(wider, ops4, noobj);
    let wt, ewt = kmip::delegated_login(c, 0, 3600, wider);
    check("and not beyond them", ewt == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_NOT_AUTHORISED, c.version));
    c.cred = kmip::ticket_credential(kmip::TICKET_LOGIN, dt);
    let dt2, edt2 = kmip::delegated_login(c, 0, 3600, narrower);
    check("one whose Rights do not allow it delegates nothing", edt2 == kmip::ERR_FAILED);
    // Users and passwords.
    var d = kmip::local("");
    d.version = kmip::V2_0;
    check("a user", kmip::add_user(d.srv, "carol", "correct horse"));
    d.cred = kmip::password_credential("carol", "wrong");
    let r14, e14 = kmip::query(d, q);
    check("a wrong password", e14 == kmip::ERR_FAILED && d.last_reason == kmip::REASON_AUTHENTICATION_NOT_SUCCESSFUL);
    d.cred = kmip::password_credential("carol", "correct horse");
    let u2, e15 = make_key(d);
    check("the right one", e15 == kmip::OK);
    d.cred = kmip::no_credential();
    d.srv.require_auth = true;
    let r16, e16 = kmip::query(d, q);
    check("none, when one is required", e16 == kmip::ERR_FAILED && d.last_reason == kmip::REASON_AUTHENTICATION_NOT_SUCCESSFUL);
}

fn small_operations() {
    var c = kmip::local("alice");
    c.version = kmip::V2_1;
    check("Log", kmip::log_message(c, "a line for the log") == kmip::OK && c.srv.log_count == 1 && c.srv.last_log[..] == "a line for the log");
    check("Ping", kmip::ping(c) == kmip::OK);
    c.version = kmip::V2_0;
    check("no Ping in 2.0", kmip::ping(c) == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_OPERATION_NOT_SUPPORTED, c.version));
    let role, re = kmip::set_endpoint_role(c, kmip::ENDPOINT_SERVER);
    check("Set Endpoint Role: server", re == kmip::OK && role == kmip::ENDPOINT_SERVER);
    let r2, re2 = kmip::set_endpoint_role(c, kmip::ENDPOINT_CLIENT);
    check("Set Endpoint Role: not client", re2 == kmip::ERR_FAILED && c.last_reason == kmip::reason_for(kmip::REASON_FEATURE_NOT_SUPPORTED, c.version));
    // PKCS#11.
    let g0, ge0 = kmip::pkcs11(c, 3, "", "");
    check("C_GetInfo before C_Initialize", ge0 == kmip::OK && g0.rv == 0x190);
    let i, ie = kmip::pkcs11(c, 1, "", "\x01");
    check("C_Initialize", ie == kmip::OK && i.rv == 0 && i.corr.len == 16);
    let g, ge = kmip::pkcs11(c, 3, i.corr, "");
    check("C_GetInfo: a CK_INFO", ge == kmip::OK && g.rv == 0 && g.output.len == 76 && g.output[0] == 3 && g.output[1] == 0);
    let n, ne = kmip::pkcs11(c, 5, i.corr, "");
    check("other functions not supported", ne == kmip::OK && n.rv == 0x54);
    let f, fe = kmip::pkcs11(c, 2, i.corr, "");
    let g2, ge2 = kmip::pkcs11(c, 3, i.corr, "");
    check("C_Finalize", fe == kmip::OK && f.rv == 0 && ge2 == kmip::OK && g2.rv == 0x190);
}

fn defaults_and_query() {
    var c = kmip::local("alice");
    c.version = kmip::V2_1;
    check("a known group", kmip::add_group(c.srv, "Group1"));
    var da = kmip::attrs();
    kmip::attr_enum(da, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
    kmip::attr_int(da, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 192);
    let types: u32[1] = [kmip::OBJ_SYMMETRIC_KEY];
    var groups: u8[..64][>..] = [];
    var g: u8[..64] = [];
    g.append("Group1");
    groups.push(g);
    var od: u8[>..] = [];
    kmip::put_object_rule(od, kmip::TAG_OBJECT_DEFAULTS, types, groups, da);
    check("Set Defaults", kmip::set_defaults(c, od) == kmip::OK);
    let back, qe = kmip::query_defaults(c);
    check("Query Defaults Information", qe == kmip::OK && back[..] == od[..]);
    var bad: u8[>..] = [];
    var bg: u8[..64][>..] = [];
    var b: u8[..64] = [];
    b.append("TheEvilTheBadTheUglyKeys");
    bg.push(b);
    kmip::put_object_rule(bad, kmip::TAG_OBJECT_DEFAULTS, types, bg, da);
    check("Set Defaults: an unknown group", kmip::set_defaults(c, bad) == kmip::ERR_FAILED &&
          c.last_reason == kmip::reason_for(kmip::REASON_UNKNOWN_OBJECT_GROUP, c.version));
    // Defaults fill what a request leaves out, for its groups.
    var a = kmip::attrs();
    kmip::attr_text(a, kmip::TAG_OBJECT_GROUP, "Group1");
    kmip::apply_defaults(c.srv, kmip::OBJ_SYMMETRIC_KEY, a);
    let alg, aok = kmip::get_enum(a, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM);
    let len, lok = kmip::get_int(a, kmip::TAG_CRYPTOGRAPHIC_LENGTH);
    check("defaults applied", aok && alg == kmip::ALG_AES && lok && len == 192);
    var a2 = kmip::attrs();
    kmip::apply_defaults(c.srv, kmip::OBJ_SYMMETRIC_KEY, a2);
    check("not outside their groups", a2.enc.len == 0);
    check("Set Defaults, empty, clears", kmip::set_defaults(c, "") == kmip::OK && c.srv.defaults.len == 0);
    // Constraints.
    var ca = kmip::attrs();
    kmip::attr_int(ca, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
    var none: u8[..64][>..] = [];
    var cs: u8[>..] = [];
    kmip::put_object_rule(cs, kmip::TAG_CONSTRAINT, types, none, ca);
    check("Set Constraints", kmip::set_constraints(c, cs) == kmip::OK);
    let got, ge = kmip::get_constraints(c);
    check("Get Constraints", ge == kmip::OK && got[..] == cs[..]);
    var k128 = kmip::attrs();
    kmip::attr_int(k128, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 128);
    var k256 = kmip::attrs();
    kmip::attr_int(k256, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256);
    check("a constraint kept", kmip::check_constraints(c.srv, kmip::OBJ_SYMMETRIC_KEY, k256).reason == 0);
    check("a constraint broken", kmip::check_constraints(c.srv, kmip::OBJ_SYMMETRIC_KEY, k128).reason == kmip::REASON_CONSTRAINT_VIOLATION);
    check("not for other types", kmip::check_constraints(c.srv, kmip::OBJ_SECRET_DATA, k128).reason == 0);
    check("Set Constraints, empty, clears", kmip::set_constraints(c, "") == kmip::OK && c.srv.constraints.len == 0);
    // Query.
    let cap, ce = kmip::query_capabilities(c);
    check("Query Capabilities", ce == kmip::OK && cap.streaming && cap.asynchronous && cap.batch_undo && cap.batch_continue && !cap.attestation);
    let prof, pe = kmip::query_profiles(c);
    check("Query Profiles", pe == kmip::OK && prof.len == 5);
    let reg, rge = kmip::query_registration_methods(c);
    check("Query Client Registration Methods", rge == kmip::OK && reg.len == 2);
}

fn reprovision() {
    var c = kmip::local("alice");
    c.version = kmip::V2_0;
    let none, e0 = kmip::reprovision(c, "");
    check("Re-Provision with no CA", e0 == kmip::ERR_FAILED);
    let k = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template("CN=session test CA", 1000000000, 4000000000);
    t.basic_constraints = true;
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_DIGITAL_SIGNATURE;
    let ca, ce = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    c.srv.ca_cert.append(ca);
    c.srv.ca_key.append(x509::marshal_pkcs8(k));
    let uid, e = kmip::reprovision(c, "");
    let o, ge = kmip::get(c, uid, 0);
    check("Re-Provision: a private key made", ce == x509::OK && e == kmip::OK && ge == kmip::OK && o.obj_type == kmip::OBJ_PRIVATE_KEY);
    let ck = x509::generate_key(x509::KEY_EC_P256);
    let subj, sok = x509::name_der("CN=alice");
    let csr, cse = x509::create_csr(subj, "", ck);
    let cuid, e2 = kmip::reprovision(c, csr);
    let co, ge2 = kmip::get(c, cuid, 0);
    var subj_ok = false;
    if ge2 == kmip::OK {
        let cert, pe = x509::parse(co.material);
        subj_ok = pe == x509::OK;
    }
    check("Re-Provision: a certificate for a request", cse == x509::OK && e2 == kmip::OK && co.obj_type == kmip::OBJ_CERTIFICATE && subj_ok);
}

fn rotate() {
    var c = kmip::local("alice");
    c.version = kmip::V2_1;
    var a = aes_attrs();
    var rn: u8[>..] = [];
    let s = kmip::begin(rn, kmip::TAG_ROTATE_NAME);
    kmip::put_text(rn, kmip::TAG_ROTATE_NAME_VALUE, "rotating key");
    kmip::put_enum(rn, kmip::TAG_ROTATE_NAME_TYPE, kmip::ROTATE_NAME_UNINTERPRETED_TEXT_STRING);
    kmip::end(rn, s);
    kmip::attr_raw(a, rn);
    let u1, e1 = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);
    let a1, ge1 = kmip::get_attributes(c, u1, []);
    let g1, gok1 = kmip::get_int(a1, kmip::TAG_ROTATE_GENERATION);
    let l1, lok1 = kmip::get_bool(a1, kmip::TAG_ROTATE_LATEST);
    check("Rotate Name: generation 0, the latest", e1 == kmip::OK && gok1 && g1 == 0 && lok1 && l1);
    let u2, e2 = make_key(c);
    kmip::rotate_after_replace(c.srv, "alice", u1, u2);
    let b1, be1 = kmip::get_attributes(c, u1, []);
    let b2, be2 = kmip::get_attributes(c, u2, []);
    let lo, loo = kmip::get_bool(b1, kmip::TAG_ROTATE_LATEST);
    let g2, gok2 = kmip::get_int(b2, kmip::TAG_ROTATE_GENERATION);
    let l2, lok2 = kmip::get_bool(b2, kmip::TAG_ROTATE_LATEST);
    check("replaced: no longer the latest", loo && !lo);
    check("the replacement: generation 1, the latest, the name", gok2 && g2 == 1 && lok2 && l2 && kmip::has_item(b2, rn));
}

fn server_to_client() {
    var c = kmip::local("alice");
    c.version = kmip::V1_4;
    let uid, e = make_key(c);
    let o, ge = kmip::get(c, uid, 0);
    var msg: u8[>..] = [];
    check("a Put written", kmip::put_request(c.srv, "alice", uid, kmip::PUT_NEW, "", kmip::V1_4, msg));
    var resp: u8[>..] = [];
    var po = kmip::new_object(0);
    var pa = kmip::attrs();
    let r, te = kmip::take_server_request(msg, resp, po, pa);
    check("the Put taken", te == kmip::OK && r.op == kmip::OP_PUT && r.uid[..] == uid[..] && r.put_function == kmip::PUT_NEW &&
          r.has_object && po.material[..] == o.material[..] && kmip::has_attr(pa, kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK));
    var doc: kmip::Node[>..] = [];
    let root, de = kmip::decode(resp, kmip::Options { .. }, doc);
    let rr, pe = kmip::parse_response(resp, doc, root);
    check("answered: success, no payload", pe == kmip::OK && rr.items.len == 1 && rr.items[0].status == kmip::STATUS_SUCCESS &&
          rr.items[0].payload < 0 && rr.items[0].op == kmip::OP_PUT);
    var msg2: u8[>..] = [];
    let changed: u32[1] = [kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK];
    let deleted: u32[1] = [kmip::TAG_CONTACT_INFORMATION];
    check("a Notify written", kmip::notify_request(c.srv, "alice", uid, changed, deleted, kmip::V2_0, msg2));
    let n, ne = kmip::take_server_request(msg2, resp, po, pa);
    check("the Notify taken", ne == kmip::OK && n.op == kmip::OP_NOTIFY && kmip::has_attr(pa, kmip::TAG_LAST_CHANGE_DATE) &&
          kmip::has_attr(pa, kmip::TAG_CRYPTOGRAPHIC_USAGE_MASK) && n.deleted.len == 1 && n.deleted[0] == kmip::TAG_CONTACT_INFORMATION);
    let x, xe = kmip::take_server_request("not TTLV", resp, po, pa);
    check("not a message", xe != kmip::OK);
}

fn main() {
    versions();
    asynchronous();
    tickets();
    small_operations();
    defaults_and_query();
    reprovision();
    rotate();
    server_to_client();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
