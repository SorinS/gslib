// ldap.conn with a server played from here: every kind of response read
// back (results, matched DN, referrals, entries and their attributes,
// references, bind credentials, extended and intermediate responses),
// response controls (paging, password policy, sort, VChu); messages fed
// a byte at a time and many at once, and with Active Directory's
// four-octet lengths; responses to abandoned requests dropped; StartTLS
// holding other requests until it is answered; a Notice of
// Disconnection; and the connection failed by a malformed message, a
// response of the wrong kind, an unsolicited message that is not a
// notification, one too long, or the transport ending with requests
// outstanding.
import std;
import gslib from "../../..";
import gslib.net.ldap;
import gslib.encoding.asn1;
import gslib.crypto.bignum;
import gslib.net.ldap.conn;
import gslib.net.ldap.filter;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// An LDAPResult's content: the code, matched DN, message, and what follows.
fn result_body(code: i64, matched: const u8[:], message: const u8[:], rest: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    asn1::put_i64(b, code, asn1::ENUMERATED);
    asn1::put_octets(b, matched);
    asn1::put_octets(b, message);
    b.append(rest);
    return b;
}

fn message(id: i64, op: u32, body: const u8[:], controls: const u8[:] = "") -> u8[>..] {
    var out: u8[>..] = [];
    ldap::put_message(out, id, op, body, controls);
    return out;
}

fn entry(id: i64, dn: const u8[:]) -> u8[>..] {
    var attrs: u8[>..] = [];
    var v: u8[>..] = [];
    ldap::put_value(v, "top");
    ldap::put_value(v, "person");
    ldap::put_attribute(attrs, "objectClass", v);
    v.clear();
    ldap::put_value(v, "Alice");
    ldap::put_attribute(attrs, "cn", v);
    v.clear();
    ldap::put_value(v, "\x00\xff");
    ldap::put_attribute(attrs, "jpegPhoto", v);
    ldap::put_attribute(attrs, "empty", "");
    var b: u8[>..] = [];
    asn1::put_octets(b, dn);
    asn1::put(b, asn1::SEQUENCE, attrs);
    return message(id, ldap::OP_SEARCH_ENTRY, b);
}

// Feeds and returns the messages.
fn feed_all(c: ldap::Conn&, input: const u8[:]) -> u8[>..], i64 {
    var msgs: u8[>..] = [];
    let code = ldap::feed(c, input, msgs);
    return msgs, code;
}

fn count(msgs: const u8[:]) -> i64 {
    var pos = 0;
    var n = 0;
    loop {
        let m, ok = ldap::next_message(msgs, pos);
        if !ok { break; }
        n++;
    }
    return n;
}

fn search_responses() {
    var c = ldap::client();
    var out: u8[>..] = [];
    let id = ldap::search(c, "dc=example,dc=com", ldap::SCOPE_SUB, "(cn=*)", "cn", out);
    check("search id", id == 1 && ldap::outstanding(c, 1));

    var wire: u8[>..] = [];
    wire.append(entry(1, "cn=alice,dc=example,dc=com"));
    var refs: u8[>..] = [];
    asn1::put_octets(refs, "ldap://other.example.com/dc=example,dc=com");
    asn1::put_octets(refs, "ldap://third.example.com/");
    wire.append(message(1, ldap::OP_SEARCH_REFERENCE, refs));
    var ctl: u8[>..] = [];
    ldap::put_paging(ctl, 42, "next\x00page");
    wire.append(message(1, ldap::OP_SEARCH_DONE, result_body(0, "", "", ""), ctl));

    // A byte at a time.
    var msgs: u8[>..] = [];
    var bad = false;
    for i in wire.len {
        if ldap::feed(c, wire[i..i + 1], msgs) != 0 { bad = true; }
    }
    check("fed a byte at a time", !bad && count(msgs) == 3 && !ldap::outstanding(c, 1));
    var pos = 0;
    let e, ok1 = ldap::next_message(msgs, pos);
    check("entry", ok1 && e.id == 1 && e.op == ldap::OP_SEARCH_ENTRY);
    check("entry dn", ldap::entry_dn(msgs, e) == "cn=alice,dc=example,dc=com");
    let attrs = ldap::attributes(msgs, e);
    check("four attributes", attrs.len == 4);
    let oc = ldap::get_values(msgs, e, "OBJECTCLASS");
    var ocs: u8[>..] = [];
    join(ocs, oc, ",");
    check("objectClass values", ocs == "top,person");
    check("first value", ldap::get_value(msgs, e, "cn") == "Alice");
    check("binary value", ldap::get_value(msgs, e, "jpegphoto") == "\x00\xff");
    check("no values", ldap::get_values(msgs, e, "empty").len == 0 && ldap::get_value(msgs, e, "missing") == "");
    let r, ok2 = ldap::next_message(msgs, pos);
    let urls = ldap::referrals(msgs, r);
    check("reference", ok2 && r.op == ldap::OP_SEARCH_REFERENCE && urls.len == 2 && urls[1] == "ldap://third.example.com/");
    let d, ok3 = ldap::next_message(msgs, pos);
    check("done", ok3 && d.op == ldap::OP_SEARCH_DONE && ldap::result_code(msgs, d) == 0 && ldap::result_error(msgs, d).len == 0);
    check("paging cookie", ldap::paging_cookie(msgs, d) == "next\x00page");
    let pc, okc = ldap::find_control(msgs, d, ldap::CONTROL_PAGING);
    let size, cookie, okp = ldap::paging(msgs, pc);
    check("paging size", okc && okp && size == 42 && !pc.critical);
    let none, ok4 = ldap::next_message(msgs, pos);
    check("no more", !ok4);
}

fn results() {
    var c = ldap::client();
    var out: u8[>..] = [];
    let b = ldap::bind(c, "cn=x", "wrong", out);
    let m = ldap::modify(c, "cn=x", "", out);
    let a = ldap::add(c, "cn=x", "", out);
    let d = ldap::delete(c, "cn=x", out);
    let r = ldap::modify_dn(c, "cn=x", "cn=y", true, "", out);
    let k = ldap::compare(c, "cn=x", "cn", "x", out);
    let w = ldap::who_am_i(c, out);
    check("ids in order", b == 1 && m == 2 && a == 3 && d == 4 && r == 5 && k == 6 && w == 7);
    var wire: u8[>..] = [];
    // Out of order, as a server may answer.
    var ext: u8[>..] = [];
    asn1::put(ext, 0x8a, ldap::OID_WHO_AM_I);
    asn1::put(ext, 0x8b, "dn:cn=x");
    wire.append(message(7, ldap::OP_EXTENDED_RESPONSE, result_body(0, "", "", ext)));
    var creds: u8[>..] = [];
    asn1::put(creds, 0x87, "server creds");
    wire.append(message(1, ldap::OP_BIND_RESPONSE, result_body(49, "", "invalid credentials", creds)));
    wire.append(message(2, ldap::OP_MODIFY_RESPONSE, result_body(32, "dc=x", "no such object", "")));
    var refs: u8[>..] = [];
    var urls: u8[>..] = [];
    asn1::put_octets(urls, "ldap://elsewhere/cn=x");
    asn1::put(refs, 0xa3, urls);
    wire.append(message(3, ldap::OP_ADD_RESPONSE, result_body(10, "", "", refs)));
    wire.append(message(4, ldap::OP_DELETE_RESPONSE, result_body(0, "", "", "")));
    wire.append(message(5, ldap::OP_MODDN_RESPONSE, result_body(68, "", "already", "")));
    wire.append(message(6, ldap::OP_COMPARE_RESPONSE, result_body(6, "", "", "")));
    let msgs, code = feed_all(c, wire);
    check("all at once", code == 0 && count(msgs) == 7 && c.pending.len == 0);
    var pos = 0;
    let x, okx = ldap::next_message(msgs, pos);
    let name, okn = ldap::response_name(msgs, x);
    let value, okv = ldap::response_value(msgs, x);
    check("whoami", okx && x.id == 7 && okn && name == ldap::OID_WHO_AM_I && okv && value == "dn:cn=x");
    let bm, okb = ldap::next_message(msgs, pos);
    let sc, oks = ldap::server_sasl_creds(msgs, bm);
    check("bind refused", okb && ldap::result_code(msgs, bm) == ldap::RESULT_INVALID_CREDENTIALS);
    check("bind error text", ldap::result_error(msgs, bm) == "LDAP Result Code 49 \"Invalid Credentials\": invalid credentials");
    check("server creds", oks && sc == "server creds");
    let mm, okm = ldap::next_message(msgs, pos);
    check("matched dn", okm && ldap::matched_dn(msgs, mm) == "dc=x" && ldap::result_message(msgs, mm) == "no such object");
    let am, oka = ldap::next_message(msgs, pos);
    let ru = ldap::referrals(msgs, am);
    check("referral", oka && ldap::result_code(msgs, am) == ldap::RESULT_REFERRAL && ru.len == 1 && ru[0] == "ldap://elsewhere/cn=x");
    let dm, okd = ldap::next_message(msgs, pos);
    check("delete ok", okd && ldap::result_code(msgs, dm) == 0);
    let rm, okr = ldap::next_message(msgs, pos);
    check("moddn exists", okr && ldap::result_code(msgs, rm) == ldap::RESULT_ENTRY_ALREADY_EXISTS);
    let km, okk = ldap::next_message(msgs, pos);
    check("compare true is no error", okk && ldap::result_code(msgs, km) == ldap::RESULT_COMPARE_TRUE && ldap::result_error(msgs, km).len == 0);
}

fn controls() {
    // Password policy: warning [0] { timeBeforeExpiration [0] 3600 }, no error.
    var pp: u8[>..] = [];
    var w: u8[>..] = [];
    asn1::put_i64(w, 3600, 0x80);
    var seq: u8[>..] = [];
    asn1::put(seq, 0xa0, w);
    asn1::put(pp, asn1::SEQUENCE, seq);
    var pp2: u8[>..] = [];
    var w2: u8[>..] = [];
    asn1::put_i64(w2, 2, 0x81);
    var seq2: u8[>..] = [];
    asn1::put(seq2, 0xa0, w2);
    let e: u8[1] = [ldap::PPOLICY_ACCOUNT_LOCKED as! u8];
    asn1::put(seq2, 0x81, e);
    asn1::put(pp2, asn1::SEQUENCE, seq2);
    var sort: u8[>..] = [];
    var ss: u8[>..] = [];
    asn1::put_i64(ss, 16, asn1::ENUMERATED);
    asn1::put(ss, 0x80, "sn");
    asn1::put(sort, asn1::SEQUENCE, ss);
    var ctl: u8[>..] = [];
    ldap::put_control(ctl, ldap::CONTROL_BEHERA_PASSWORD_POLICY, false, pp, true);
    ldap::put_control(ctl, ldap::CONTROL_SORT_RESPONSE, true, sort, true);
    ldap::put_control(ctl, ldap::CONTROL_VCHU_PASSWORD_WARNING, false, "120", true);
    var c = ldap::client();
    var out: u8[>..] = [];
    let id = ldap::bind(c, "cn=x", "pw", out);
    let id2 = ldap::bind(c, "cn=x", "pw", out);
    var wire: u8[>..] = [];
    wire.append(message(id, ldap::OP_BIND_RESPONSE, result_body(0, "", "", ""), ctl));
    var ctl2: u8[>..] = [];
    ldap::put_control(ctl2, ldap::CONTROL_BEHERA_PASSWORD_POLICY, false, pp2, true);
    wire.append(message(id2, ldap::OP_BIND_RESPONSE, result_body(49, "", "", ""), ctl2));
    let msgs, code = feed_all(c, wire);
    var pos = 0;
    let m, ok = ldap::next_message(msgs, pos);
    check("three controls", code == 0 && ok && ldap::controls(msgs, m).len == 3);
    let p, okp = ldap::find_control(msgs, m, ldap::CONTROL_BEHERA_PASSWORD_POLICY);
    let expire, grace, err, okd = ldap::ppolicy(msgs, p);
    check("ppolicy expire", okp && okd && expire == 3600 && grace == -1 && err == -1);
    let s, oks = ldap::find_control(msgs, m, ldap::CONTROL_SORT_RESPONSE);
    let sc, sattr, oksr = ldap::sort_result(msgs, s);
    check("sort result", oks && s.critical && oksr && sc == 16 && sattr == "sn");
    let v, okv = ldap::find_control(msgs, m, ldap::CONTROL_VCHU_PASSWORD_WARNING);
    let secs, okw = ldap::vchu_warning(msgs, v);
    check("vchu warning", okv && okw && secs == 120);
    let m2, ok2 = ldap::next_message(msgs, pos);
    let p2, okp2 = ldap::find_control(msgs, m2, ldap::CONTROL_BEHERA_PASSWORD_POLICY);
    let e2, g2, err2, okd2 = ldap::ppolicy(msgs, p2);
    check("ppolicy grace and error", ok2 && okp2 && okd2 && e2 == -1 && g2 == 2 && err2 == ldap::PPOLICY_ACCOUNT_LOCKED);
    check("ppolicy error name", ldap::ppolicy_error_name(err2) == "Account locked");
    let missing, okm = ldap::find_control(msgs, m2, ldap::CONTROL_PAGING);
    check("no paging control", !okm && ldap::paging_cookie(msgs, m2) == "");

    // Requests' controls: sort keys, proxied authorization, assertion.
    var rc: u8[>..] = [];
    ldap::put_sort(rc, "-sn:caseIgnoreOrderingMatch,cn");
    let t, okt = asn1::parse(rc);
    let parts, okc = asn1::children(rc, t);
    let inner, oki = asn1::parse(rc[parts[1].off..parts[1].end]);
    let val = rc[parts[1].off..parts[1].end];
    let keys, okk = asn1::children(val, inner);
    check("two sort keys", okt && okc && oki && okk && keys.len == 2);
    let k1, ok1 = asn1::children(val, keys[0]);
    check("reverse key", ok1 && k1.len == 3 && ldap::bytes(val, k1[0]) == "sn" && ldap::bytes(val, k1[1]) == "caseIgnoreOrderingMatch" &&
                        k1[2].tag == 0x81 && val[k1[2].off] == 0xff);
    let k2, ok2k = asn1::children(val, keys[1]);
    check("plain key", ok2k && k2.len == 1 && ldap::bytes(val, k2[0]) == "cn");
    var pa: u8[>..] = [];
    ldap::put_proxied_authz(pa, "dn:cn=x");
    let pt, okpt = asn1::parse(pa);
    let pp3, okpp = asn1::children(pa, pt);
    let crit, okcr = asn1::read_bool(pa, pp3[1]);
    check("proxied authz", okpt && okpp && pp3.len == 3 && ldap::bytes(pa, pp3[0]) == ldap::CONTROL_PROXIED_AUTHZ &&
                           okcr && crit && ldap::bytes(pa, pp3[2]) == "dn:cn=x");
    var asr: u8[>..] = [];
    let f, okf = ldap::compile("(cn=x)");
    ldap::put_assertion(asr, f);
    let at, okat = asn1::parse(asr);
    let ap, okap = asn1::children(asr, at);
    check("assertion", okf && okat && okap && ap.len == 3 && ldap::bytes(asr, ap[0]) == ldap::CONTROL_ASSERTION &&
                       ldap::bytes(asr, ap[2]) == f[..]);
}

fn framing() {
    // Active Directory's lengths: 84 00 00 00 nn everywhere.
    let ad = unhex("3084000000100201016584000000070a010004000400");
    var c = ldap::client();
    var out: u8[>..] = [];
    let id = ldap::search(c, "", ldap::SCOPE_BASE, "(objectClass=*)", "", out);
    let msgs, code = feed_all(c, ad);
    var pos = 0;
    let m, ok = ldap::next_message(msgs, pos);
    check("long lengths", code == 0 && ok && m.id == 1 && m.op == ldap::OP_SEARCH_DONE && ldap::result_code(msgs, m) == 0);

    // Abandoned: its entries and result are dropped.
    var c2 = ldap::client();
    let s = ldap::search(c2, "", ldap::SCOPE_SUB, "(cn=*)", "", out);
    let b = ldap::who_am_i(c2, out);
    check("abandon", ldap::abandon(c2, s, out) && !ldap::outstanding(c2, s) && ldap::outstanding(c2, b));
    check("abandon twice", !ldap::abandon(c2, s, out));
    var wire: u8[>..] = [];
    wire.append(entry(s, "cn=late"));
    wire.append(message(s, ldap::OP_SEARCH_DONE, result_body(0, "", "", "")));
    wire.append(message(b, ldap::OP_EXTENDED_RESPONSE, result_body(0, "", "", "")));
    let m2, code2 = feed_all(c2, wire);
    var p2 = 0;
    let only, oko = ldap::next_message(m2, p2);
    check("only the live one", code2 == 0 && count(m2) == 1 && oko && only.id == b);

    // An intermediate response for an extended operation, then its result.
    var c3 = ldap::client();
    let x = ldap::extended(c3, "1.2.3", "v", true, out);
    var im: u8[>..] = [];
    asn1::put(im, 0x80, "1.2.3.1");
    asn1::put(im, 0x81, "progress");
    var w3: u8[>..] = [];
    w3.append(message(x, ldap::OP_INTERMEDIATE, im));
    w3.append(message(x, ldap::OP_EXTENDED_RESPONSE, result_body(0, "", "", "")));
    let m3, code3 = feed_all(c3, w3);
    var p3 = 0;
    let i3, oki = ldap::next_message(m3, p3);
    let n3, okn = ldap::response_name(m3, i3);
    let v3, okv = ldap::response_value(m3, i3);
    check("intermediate", code3 == 0 && oki && i3.op == ldap::OP_INTERMEDIATE && okn && n3 == "1.2.3.1" && okv && v3 == "progress");
    check("extended done", !ldap::outstanding(c3, x));
}

fn starttls() {
    var c = ldap::client();
    var out: u8[>..] = [];
    let id = ldap::start_tls(c, out);
    check("starttls sent", id == 1 && c.state == ldap::ST_STARTTLS);
    check("nothing else meanwhile", ldap::who_am_i(c, out) == -1 && c.error == ldap::ERROR_NETWORK);
    var name: u8[>..] = [];
    asn1::put(name, 0x8a, ldap::OID_START_TLS);
    let msgs, code = feed_all(c, message(id, ldap::OP_EXTENDED_RESPONSE, result_body(0, "", "", name)));
    check("tls ready", code == 0 && c.tls_ready && c.state == ldap::ST_OPEN);
    check("requests again", ldap::who_am_i(c, out) == 2);
    check("not twice", ldap::start_tls(c, out) == -1);

    var c2 = ldap::client();
    let id2 = ldap::start_tls(c2, out);
    let m2, code2 = feed_all(c2, message(id2, ldap::OP_EXTENDED_RESPONSE, result_body(ldap::RESULT_PROTOCOL_ERROR, "", "no", "")));
    check("starttls refused", code2 == 0 && !c2.tls_ready && c2.state == ldap::ST_OPEN && ldap::who_am_i(c2, out) == 2);
}

fn failures_close() {
    var out: u8[>..] = [];
    // A notice of disconnection.
    var c = ldap::client();
    let id = ldap::who_am_i(c, out);
    var name: u8[>..] = [];
    asn1::put(name, 0x8a, ldap::OID_NOTICE_OF_DISCONNECTION);
    let msgs, code = feed_all(c, message(0, ldap::OP_EXTENDED_RESPONSE, result_body(ldap::RESULT_UNAVAILABLE, "", "shutting down", name)));
    check("notice", code == ldap::RESULT_UNAVAILABLE && c.notice && ldap::closed(c) && count(msgs) == 1);
    check("closed: no requests", ldap::who_am_i(c, out) == -1 && c.error == ldap::ERROR_NETWORK);

    // A response of the wrong kind.
    var c2 = ldap::client();
    let b = ldap::bind(c2, "cn=x", "pw", out);
    let m2, code2 = feed_all(c2, message(b, ldap::OP_ADD_RESPONSE, result_body(0, "", "", "")));
    check("wrong response", code2 == ldap::ERROR_UNEXPECTED_RESPONSE && ldap::closed(c2) && count(m2) == 0);

    // Malformed: a result without its message, a bad tag, garbage.
    var c3 = ldap::client();
    let b3 = ldap::bind(c3, "cn=x", "pw", out);
    var body: u8[>..] = [];
    asn1::put_i64(body, 0, asn1::ENUMERATED);
    asn1::put_octets(body, "");
    let m3, code3 = feed_all(c3, message(b3, ldap::OP_BIND_RESPONSE, body));
    check("short result", code3 == ldap::RESULT_DECODING_ERROR && ldap::closed(c3));
    var c4 = ldap::client();
    let m4, code4 = feed_all(c4, "\x04\x00");
    check("not a sequence", code4 == ldap::RESULT_DECODING_ERROR);
    var c5 = ldap::client();
    let m5, code5 = feed_all(c5, unhex("300602010164020400"));
    check("entry without attributes", code5 == ldap::RESULT_DECODING_ERROR);

    // An unsolicited message that is not a notification.
    var c6 = ldap::client();
    let m6, code6 = feed_all(c6, message(0, ldap::OP_SEARCH_DONE, result_body(0, "", "", "")));
    check("unsolicited", code6 == ldap::ERROR_UNEXPECTED_MESSAGE);

    // Too long.
    var c7 = ldap::client();
    c7.max_message = 1000;
    let m7, code7 = feed_all(c7, unhex("308400100000"));
    check("too long", code7 == ldap::RESULT_DECODING_ERROR);

    // A message cut short waits; the transport ending then fails it.
    var c8 = ldap::client();
    let b8 = ldap::bind(c8, "cn=x", "pw", out);
    let whole = message(b8, ldap::OP_BIND_RESPONSE, result_body(0, "", "", ""));
    let m8, code8 = feed_all(c8, whole[..whole.len - 1]);
    check("partial waits", code8 == 0 && count(m8) == 0 && !ldap::closed(c8));
    check("eof with requests outstanding", ldap::eof(c8) == ldap::ERROR_NETWORK && ldap::closed(c8));
    var c9 = ldap::client();
    check("eof when idle", ldap::eof(c9) == 0);

    // Refused requests.
    var c10 = ldap::client();
    check("empty password", ldap::bind(c10, "cn=x", "", out) == -1 && c10.error == ldap::ERROR_EMPTY_PASSWORD);
    check("empty password text", ldap::conn_error(c10) == "LDAP Result Code 206 \"Empty password not allowed by the client\": ldap: empty password not allowed by the client");
    check("bad filter", ldap::search(c10, "", 0, "(cn=a", "", out) == -1 && c10.error == ldap::ERROR_FILTER_COMPILE);
    check("bad scope", ldap::search(c10, "", 7, "(cn=a)", "", out) == -1 && c10.error == ldap::RESULT_PARAM_ERROR);
    ldap::unbind(c10, out);
    check("unbind closes", ldap::closed(c10) && ldap::who_am_i(c10, out) == -1);
}

fn main() {
    search_responses();
    results();
    controls();
    framing();
    starttls();
    failures_close();
    print("conn: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
