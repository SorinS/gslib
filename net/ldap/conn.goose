// ldap.conn: an LDAP client connection without I/O. A Conn numbers the
// requests it writes, remembers which await a response, frames the
// messages that arrive out of the byte stream and checks each one whole
// before handing it on:
//
//   var c = ldap::client();
//   let id = ldap::bind(c, "cn=admin,dc=example,dc=com", "secret", out);
//   ... send out, read into input ...
//   ldap::feed(c, input, msgs);                  // appends whole messages
//   var pos = 0;
//   loop {
//       let m, ok = ldap::next_message(msgs, pos);
//       if !ok { break; }
//       if m.id == id { ldap::result_code(msgs, m) ... }
//   }
//
// Requests are refused (-1, with c.error and c.message) once the
// connection is closed and while StartTLS waits for its response; a
// successful StartTLS sets c.tls_ready, after which the caller speaks
// TLS on the transport (tlsgoose does) and goes on feeding the plaintext
// here. Responses to requests no longer outstanding (abandoned ones) are
// dropped, as go-ldap drops them; a response of the wrong kind for its
// request, or a message that is not well formed, fails the connection.
// A Notice of Disconnection (§4.4.1) is handed on and closes it.
// SASL's EXTERNAL, PLAIN and DIGEST-MD5 (RFC 2831, as go-ldap does it)
// have their credentials made here.

namespace ldap;

import std;
import net.ldap;
import net.ldap.filter;
import encoding.asn1;
import crypto.bignum;
import crypto.bignum.md5;

let ST_OPEN: i64 = 0;
let ST_STARTTLS: i64 = 1;      // StartTLS sent; nothing else until its response
let ST_CLOSED: i64 = 2;

let MAX_OUTSTANDING: i64 = 4096;
let MAX_MESSAGE: i64 = 64 << 20;

struct Pending { id: i64, op: u32 }

struct Conn {
    state: i64, next_id: i64,
    error: i64, message: u8[..1024],     // the last failure: a result code and why
    starttls_id: i64, tls_ready: bool,   // StartTLS succeeded: switch the transport to TLS now
    notice: bool, notice_code: i64,      // a Notice of Disconnection came, with this result code
    max_message: i64,
    pending: Pending[..4096],
    inbuf: u8[>..],
}

fn client() -> Conn {
    Conn { state: ST_OPEN, next_id: 1, error: 0, message: [], starttls_id: 0, tls_ready: false, notice: false,
           notice_code: 0, max_message: MAX_MESSAGE, pending: [], inbuf: [] }
}

fn closed(c: const Conn&) -> bool { c.state == ST_CLOSED }

// Whether a request still awaits its response.
fn outstanding(c: const Conn&, id: i64) -> bool {
    for p in c.pending { if p.id == id { return true; } }
    return false;
}

fn fail_request(c: Conn&, code: i64, why: const u8[:]) -> i64 {
    c.error = code;
    c.message.clear();
    c.message.append(why[..if why.len > 1024 { 1024 } else { why.len }]);
    return -1;
}

// The last failure as go-ldap reports it.
fn conn_error(c: const Conn&) -> u8[>..] { error_text(c.error, c.message) }

// Writes a request: its message ID, or -1.
fn send_request(c: Conn&, op: u32, body: const u8[:], controls: const u8[:], out: u8[>..]&) -> i64 {
    if c.state == ST_CLOSED { return fail_request(c, ERROR_NETWORK, "ldap: connection closed"); }
    if c.state == ST_STARTTLS { return fail_request(c, ERROR_NETWORK, "ldap: StartTLS in progress"); }
    let reply = response_op(op);
    if reply != 0 && c.pending.len >= MAX_OUTSTANDING { return fail_request(c, RESULT_LOCAL_ERROR, "ldap: too many outstanding requests"); }
    let id = c.next_id;
    c.next_id = if c.next_id >= 0x7fffffff { 1 } else { c.next_id + 1 };
    put_message(out, id, op, body, controls);
    if reply != 0 { c.pending.push(Pending { id: id, op: op }); }
    return id;
}

// --- Requests ----------------------------------------------------------------------

// A simple bind; an empty password is refused here, as go-ldap's Bind
// refuses it (RFC 4513 §5.1.2: it would be an unauthenticated bind).
fn bind(c: Conn&, dn: const u8[:], password: const u8[:], out: u8[>..]&, controls: const u8[:] = "") -> i64 {
    if password.len == 0 { return fail_request(c, ERROR_EMPTY_PASSWORD, "ldap: empty password not allowed by the client"); }
    return send_request(c, OP_BIND_REQUEST, bind_body(dn, password), controls, out);
}

// The unauthenticated bind (§5.1.2), anonymous with an empty name.
fn unauthenticated_bind(c: Conn&, dn: const u8[:], out: u8[>..]&, controls: const u8[:] = "") -> i64 {
    return send_request(c, OP_BIND_REQUEST, bind_body(dn, ""), controls, out);
}

fn sasl_bind(c: Conn&, mechanism: const u8[:], credentials: const u8[:], has_credentials: bool, out: u8[>..]&,
             controls: const u8[:] = "") -> i64 {
    return send_request(c, OP_BIND_REQUEST, sasl_bind_body(mechanism, credentials, has_credentials), controls, out);
}

// SASL EXTERNAL (RFC 4422 Appendix A): the identity of the transport (a
// TLS client certificate, ldapi's peer); authzid "" to take it as it is.
fn external_bind(c: Conn&, out: u8[>..]&, authzid: const u8[:] = "", controls: const u8[:] = "") -> i64 {
    return sasl_bind(c, "EXTERNAL", authzid, true, out, controls);
}

// SASL PLAIN (RFC 4616): authzid NUL authcid NUL password.
fn plain_bind(c: Conn&, user: const u8[:], password: const u8[:], out: u8[>..]&, authzid: const u8[:] = "",
              controls: const u8[:] = "") -> i64 {
    var cred: u8[>..] = [];
    cred.append(authzid);
    cred.push(0);
    cred.append(user);
    cred.push(0);
    cred.append(password);
    return sasl_bind(c, "PLAIN", cred, true, out, controls);
}

// A search; the filter in its string form, the attributes separated by
// commas or spaces ("" for all user attributes).
fn search(c: Conn&, base: const u8[:], scope: i64, filter: const u8[:], attrs: const u8[:], out: u8[>..]&,
          controls: const u8[:] = "", deref: i64 = DEREF_NEVER, size_limit: i64 = 0, time_limit: i64 = 0,
          types_only: bool = false) -> i64 {
    var f: u8[>..] = [];
    var err: u8[>..] = [];
    if !compile_filter(filter, f, err) { return fail_request(c, ERROR_FILTER_COMPILE, err); }
    if scope < 0 || scope > 3 || deref < 0 || deref > 3 || size_limit < 0 || time_limit < 0 {
        return fail_request(c, RESULT_PARAM_ERROR, "ldap: bad search parameters");
    }
    return send_request(c, OP_SEARCH_REQUEST, search_body(base, scope, deref, size_limit, time_limit, types_only, f, attrs),
                        controls, out);
}

// changes: put_change's, one after another.
fn modify(c: Conn&, dn: const u8[:], changes: const u8[:], out: u8[>..]&, controls: const u8[:] = "") -> i64 {
    return send_request(c, OP_MODIFY_REQUEST, modify_body(dn, changes), controls, out);
}

// attributes: put_attribute's, one after another.
fn add(c: Conn&, dn: const u8[:], attributes: const u8[:], out: u8[>..]&, controls: const u8[:] = "") -> i64 {
    return send_request(c, OP_ADD_REQUEST, add_body(dn, attributes), controls, out);
}

fn delete(c: Conn&, dn: const u8[:], out: u8[>..]&, controls: const u8[:] = "") -> i64 {
    return send_request(c, OP_DELETE_REQUEST, dn, controls, out);
}

fn modify_dn(c: Conn&, dn: const u8[:], new_rdn: const u8[:], delete_old: bool, new_superior: const u8[:], out: u8[>..]&,
             controls: const u8[:] = "") -> i64 {
    return send_request(c, OP_MODDN_REQUEST, moddn_body(dn, new_rdn, delete_old, new_superior), controls, out);
}

// Its response's code is compareTrue or compareFalse when it worked.
fn compare(c: Conn&, dn: const u8[:], attr: const u8[:], value: const u8[:], out: u8[>..]&, controls: const u8[:] = "") -> i64 {
    return send_request(c, OP_COMPARE_REQUEST, compare_body(dn, attr, value), controls, out);
}

fn extended(c: Conn&, oid: const u8[:], value: const u8[:], has_value: bool, out: u8[>..]&, controls: const u8[:] = "") -> i64 {
    return send_request(c, OP_EXTENDED_REQUEST, extended_body(oid, value, has_value), controls, out);
}

fn start_tls(c: Conn&, out: u8[>..]&) -> i64 {
    if c.tls_ready { return fail_request(c, ERROR_NETWORK, "ldap: already encrypted"); }
    let id = extended(c, OID_START_TLS, "", false, out);
    if id > 0 { c.state = ST_STARTTLS; c.starttls_id = id; }
    return id;
}

// RFC 4532: the response's value is the authorization identity ("dn:...", "u:...", or "").
fn who_am_i(c: Conn&, out: u8[>..]&, controls: const u8[:] = "") -> i64 {
    return extended(c, OID_WHO_AM_I, "", false, out, controls);
}

// RFC 3062; "" leaves a field out: the bound user's own password, the
// old one not given, or a new one for the server to make up
// (generated_password reads it).
fn password_modify(c: Conn&, user: const u8[:], old_password: const u8[:], new_password: const u8[:], out: u8[>..]&,
                   controls: const u8[:] = "") -> i64 {
    return extended(c, OID_PASSWORD_MODIFY, password_modify_value(user, old_password, new_password), true, out, controls);
}

// Abandons an outstanding request (§4.11): no response, and none of its
// responses are handed on after this.
fn abandon(c: Conn&, id: i64, out: u8[>..]&, controls: const u8[:] = "") -> bool {
    if !outstanding(c, id) { return false; }
    for i in c.pending.len { if c.pending[i].id == id { let x = remove_at(c.pending, i); break; } }
    return send_request(c, OP_ABANDON_REQUEST, abandon_body(id), controls, out) >= 0;
}

// The Cancel operation (RFC 3909): the request ends with canceled, and
// the cancel with its own result.
fn cancel(c: Conn&, id: i64, out: u8[>..]&) -> i64 {
    return extended(c, OID_CANCEL, cancel_value(id), true, out);
}

// UnbindRequest; the connection is closed after it.
fn unbind(c: Conn&, out: u8[>..]&, controls: const u8[:] = "") {
    if c.state == ST_CLOSED { return; }
    let x = send_request(c, OP_UNBIND_REQUEST, "", controls, out);
    c.state = ST_CLOSED;
    c.pending.clear();
}

// --- Responses ---------------------------------------------------------------------

fn fail_conn(c: Conn&, code: i64, why: const u8[:]) -> i64 {
    let x = fail_request(c, code, why);
    c.state = ST_CLOSED;
    c.pending.clear();
    return code;
}

// Whether a response may come for a request.
fn response_fits(request: u32, op: u32) -> bool {
    if op == OP_INTERMEDIATE { return true; }
    if request == OP_SEARCH_REQUEST { return op == OP_SEARCH_ENTRY || op == OP_SEARCH_REFERENCE || op == OP_SEARCH_DONE; }
    return op == response_op(request);
}

// The bytes that arrived: appends each whole message to msgs (for
// next_message). 0, or the result code that failed the connection.
fn feed(c: Conn&, input: const u8[:], msgs: u8[>..]&) -> i64 {
    c.inbuf.append(input);
    var pos = 0;
    var code: i64 = 0;
    while pos < c.inbuf.len {
        let n = frame_len(c.inbuf[pos..], c.max_message);
        if n == 0 { break; }
        if n < 0 { code = fail_conn(c, RESULT_DECODING_ERROR, "ldap: not an LDAP message"); break; }
        let m, ok = parse_message(c.inbuf, pos, pos + n);
        if !ok { code = fail_conn(c, RESULT_DECODING_ERROR, "ldap: malformed LDAP message"); break; }
        var deliver = true;
        if m.id == 0 {
            // Unsolicited notifications are extended responses.
            if m.op != OP_EXTENDED_RESPONSE { code = fail_conn(c, ERROR_UNEXPECTED_MESSAGE, "ldap: unsolicited message is not a notification"); break; }
            let name, okn = response_name(c.inbuf, m);
            if okn && name == OID_NOTICE_OF_DISCONNECTION {
                msgs.append(c.inbuf[pos..pos + n]);
                c.notice = true;
                c.notice_code = result_code(c.inbuf, m);
                code = fail_conn(c, c.notice_code, result_message(c.inbuf, m));
                pos += n;
                break;
            }
        } else {
            var k = -1;
            for i in c.pending.len { if c.pending[i].id == m.id { k = i; break; } }
            if k < 0 {
                deliver = false;
            } else {
                let req = c.pending[k].op;
                if !response_fits(req, m.op) {
                    code = fail_conn(c, ERROR_UNEXPECTED_RESPONSE, "ldap: response does not match its request");
                    break;
                }
                if m.op == response_op(req) {
                    let x = remove_at(c.pending, k);
                    if m.id == c.starttls_id {
                        c.state = ST_OPEN;
                        c.starttls_id = 0;
                        c.tls_ready = result_code(c.inbuf, m) == RESULT_SUCCESS;
                    }
                }
            }
        }
        if deliver { msgs.append(c.inbuf[pos..pos + n]); }
        pos += n;
    }
    if pos > 0 {
        if pos >= c.inbuf.len {
            c.inbuf.clear();
        } else {
            var rest: u8[>..] = [];
            rest.append(c.inbuf[pos..]);
            c.inbuf.clear();
            c.inbuf.append(rest);
        }
    }
    return code;
}

// The transport ended: what was outstanding never will be answered.
fn eof(c: Conn&) -> i64 {
    if c.state == ST_CLOSED { return 0; }
    let waiting = c.pending.len > 0 || c.inbuf.len > 0;
    let x = fail_conn(c, ERROR_NETWORK, "ldap: connection closed");
    return if waiting { ERROR_NETWORK } else { 0 };
}

// --- SASL ------------------------------------------------------------------------

// The key=value pairs of a DIGEST-MD5 challenge, as go-ldap's
// parseParams reads them: the value of key, and whether it is there.
fn digest_param(s: const u8[:], key: const u8[:]) -> const u8[:], bool {
    var i = 0;
    while i < s.len {
        while i < s.len && (s[i] == ',' || s[i] == ' ') { i++; }
        let k0 = i;
        while i < s.len && s[i] != '=' { i++; }
        if i >= s.len { return "", false; }
        let k = s[k0..i];
        i++;
        var v0 = i;
        var v1 = i;
        if i < s.len && s[i] == '"' {
            i++;
            v0 = i;
            while i < s.len && s[i] != '"' { i++; }
            if i >= s.len { return "", false; }
            v1 = i;
            i++;
        } else {
            while i < s.len && s[i] != ',' { i++; }
            v1 = i;
        }
        if equal_fold(k, key) { return s[v0..v1], true; }
    }
    return "", false;
}

fn hex_into(out: u8[>..]&, b: const u8[:]) {
    for x in b { format_uint(out, x, 16, 2, '0'); }
}

// The DIGEST-MD5 response (RFC 2831 §2.1.2) to a server's challenge, for
// digest-uri <service>/<host>, with this cnonce (go-ldap's is 16 random
// bytes in hex; the caller makes it); computed as go-ldap's
// computeResponse computes it, adding charset=utf-8 when the server
// offers it. false if the challenge has no nonce or does not offer qop
// auth.
fn digest_md5_response(challenge: const u8[:], host: const u8[:], user: const u8[:], password: const u8[:],
                       cnonce: const u8[:], service: const u8[:] = "ldap") -> u8[>..], bool {
    var out: u8[>..] = [];
    let nonce, okn = digest_param(challenge, "nonce");
    if !okn { return out, false; }
    let realm, okr = digest_param(challenge, "realm");
    let qop, okq = digest_param(challenge, "qop");
    if okq {
        var auth = false;
        for q in split(qop, ',') { if trim(q) == "auth" { auth = true; } }
        if !auth { return out, false; }
    }
    let charset, okc = digest_param(challenge, "charset");
    let authzid, oka = digest_param(challenge, "authzid");
    var uri: u8[>..] = [];
    uri.append(service);
    uri.push('/');
    for ch in host { uri.push(lower(ch)); }
    let y = bignum::md5(str(user, ":", realm, ":", password));
    var a1: u8[>..] = [];
    a1.append(y);
    format(a1, ":", nonce, ":", cnonce);
    if authzid.len > 0 { format(a1, ":", authzid); }
    var ha1: u8[>..] = [];
    hex_into(ha1, bignum::md5(a1));
    var ha2: u8[>..] = [];
    hex_into(ha2, bignum::md5(str("AUTHENTICATE:", uri)));
    var resp: u8[>..] = [];
    hex_into(resp, bignum::md5(str(ha1, ":", nonce, ":00000001:", cnonce, ":auth:", ha2)));
    format(out, "username=\"", user, "\",realm=\"", realm, "\",nonce=\"", nonce, "\",cnonce=\"", cnonce,
           "\",nc=00000001,qop=auth,digest-uri=\"", uri, "\",response=", resp);
    if okc && equal_fold(charset, "utf-8") { out.append(",charset=utf-8"); }
    return out, true;
}
