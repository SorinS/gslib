// krb5.ldap: Kerberos for LDAP (gslib's net/ldap): the SASL GSSAPI bind
// (RFC 4752) with its security layer, and the Active Directory lookups a
// service makes with what a PAC tells it: SIDs to names, a user's groups
// (tokenGroups), the domain's naming context.
//
// The bind: our Kerberos token in a SASL bind; the server's AP-REP comes
// back with saslBindInProgress, then (after our empty response) a Wrap
// token offering security layers and a maximum size; we choose one in a
// Wrap of our own, and the bind succeeds. With the integrity or
// confidentiality layer (AD requires signing unless the connection is
// TLS), every LDAP message after the bind travels as a 4-byte big-endian
// length and a Wrap token (RFC 4752 §3.3): sasl_out wraps what the
// ldap::Conn wrote, sasl_in unwraps what arrives before it is fed.

namespace krb5;

import std;
import net.ldap;
import net.ldap.conn;
import net.ldap.filter;
import krb5.crypto;
import krb5.messages;
import krb5.ccache;
import krb5.service;
import krb5.gssapi;
import krb5.ndr;

// Security layers (RFC 4752 §3.3).
let SASL_LAYER_NONE: u8 = 1;
let SASL_LAYER_INTEGRITY: u8 = 2;
let SASL_LAYER_CONFIDENTIALITY: u8 = 4;

let SASL_START: i64 = 0;
let SASL_CONTEXT: i64 = 1;     // our token sent; the AP-REP awaited
let SASL_LAYERS: i64 = 2;      // the context made; the server's offer awaited
let SASL_CHOSEN: i64 = 3;      // our choice sent; success awaited
let SASL_DONE: i64 = 4;

let SASL_MAX_BUFFER: u32 = 0xffffff;

struct SaslGssapi {
    ctx: GssContext,
    state: i64,
    want: u8,              // the layers we would take, best first: conf, integ, none
    layer: u8,             // the layer in force once done
    max_out: u32,          // the largest Wrap token the server takes
    bind_id: i64,
    authzid: u8[..512],
}

// Starts the bind with a service ticket for ldap/host (the GSS name
// "ldap@host"): our Kerberos token in the first SASL bind request.
// `want` is the layers we accept, a mask; the strongest offered is taken.
fn sasl_gssapi_start(c: ldap::Conn&, cred: const Credential&, want: u8, authzid: const u8[:], now: i64, usec: i64,
                     out: u8[>..]&) -> SaslGssapi, i64 {
    var s = SaslGssapi { ctx: empty_gss_context(), state: SASL_START, want: want, layer: 0, max_out: 0, bind_id: -1,
                         authzid: [] };
    if authzid.len > 512 { return s, ERR_NAME; }
    s.authzid.append(authzid);
    var tok: u8[>..] = [];
    // Integrity and confidentiality are what the layers need; mutual
    // authentication is RFC 4752's requirement.
    let g, err = gss_init(cred, GSS_MUTUAL | GSS_SEQUENCE | GSS_INTEG | GSS_CONF, "", false, "", now, usec, tok);
    if err != OK { return s, err; }
    s.ctx = g;
    s.bind_id = ldap::sasl_bind(c, "GSSAPI", tok, true, out);
    if s.bind_id < 0 { return s, ERR_CONTEXT; }
    s.state = SASL_CONTEXT;
    return s, OK;
}

// The next step, with the bind's response (m in msgs): a further bind
// request in `out`, or done. A result other than success or
// saslBindInProgress comes back as the LDAP result code + 2000.
fn sasl_gssapi_step(s: SaslGssapi&, c: ldap::Conn&, msgs: const u8[:], m: const ldap::Message&, out: u8[>..]&) -> bool, i64 {
    if m.id != s.bind_id { return false, ERR_CONTEXT; }
    let code = ldap::result_code(msgs, m);
    let creds, has_creds = ldap::server_sasl_creds(msgs, m);
    if code == ldap::RESULT_SUCCESS {
        // Success only after the layers were agreed (some servers send it
        // with the last token: take that token first).
        if s.state == SASL_CONTEXT && has_creds && creds.len > 0 {
            let err = gss_init_continue(s.ctx, creds);
            if err != OK { return true, err; }
        }
        if s.state != SASL_CHOSEN { return true, ERR_CONTEXT; }
        s.state = SASL_DONE;
        return true, OK;
    }
    if code != ldap::RESULT_SASL_BIND_IN_PROGRESS { return true, 2000 + code; }
    if s.state == SASL_CONTEXT {
        if !s.ctx.established {
            if !has_creds { return true, ERR_TOKEN; }
            let err = gss_init_continue(s.ctx, creds);
            if err != OK { return true, err; }
        }
        // The context is made: an empty response asks for the layers.
        s.bind_id = ldap::sasl_bind(c, "GSSAPI", "", true, out);
        s.state = SASL_LAYERS;
        return false, OK;
    }
    if s.state == SASL_LAYERS {
        if !has_creds { return true, ERR_TOKEN; }
        var offer: u8[>..] = [];
        let sealed, err = gss_unwrap(s.ctx, creds, offer);
        if err != OK { return true, err; }
        if offer.len != 4 { return true, ERR_TOKEN; }
        let offered = offer[0];
        let max: u32 = (offer[1] as u32) << 16 | (offer[2] as u32) << 8 | offer[3];
        var choose: u8 = 0;
        for l in [SASL_LAYER_CONFIDENTIALITY, SASL_LAYER_INTEGRITY, SASL_LAYER_NONE] {
            if choose == 0 && offered & l != 0 && s.want & l != 0 { choose = l; }
        }
        if choose == 0 { return true, ERR_MECH; }
        // A server with no layer to offer sends a size of 0 (§3.1).
        if choose != SASL_LAYER_NONE && max == 0 { return true, ERR_TOKEN; }
        s.layer = choose;
        s.max_out = max;
        var reply: u8[>..] = [choose];
        let ours: u32 = if choose == SASL_LAYER_NONE { 0 } else { SASL_MAX_BUFFER };
        reply.push((ours >> 16) as! u8);
        reply.push((ours >> 8) as! u8);
        reply.push(ours as! u8);
        reply.append(s.authzid);
        var w: u8[>..] = [];
        let werr = gss_wrap(s.ctx, reply, false, w);
        if werr != OK { return true, werr; }
        s.bind_id = ldap::sasl_bind(c, "GSSAPI", w, true, out);
        s.state = SASL_CHOSEN;
        return false, OK;
    }
    return true, ERR_CONTEXT;
}

fn sasl_layer_active(s: const SaslGssapi&) -> bool { s.state == SASL_DONE && s.layer != SASL_LAYER_NONE }

// What to send for `pdu` (bytes an ldap::Conn wrote): as it is, or
// wrapped and framed under a security layer.
fn sasl_out(s: SaslGssapi&, pdu: const u8[:], out: u8[>..]&) -> i64 {
    if !sasl_layer_active(s) { out.append(pdu); return OK; }
    var w: u8[>..] = [];
    let err = gss_wrap(s.ctx, pdu, s.layer == SASL_LAYER_CONFIDENTIALITY, w);
    if err != OK { return err; }
    if s.max_out != 0 && w.len > s.max_out { return ERR_TOKEN; }
    let n = w.len;
    out.push((n >> 24) as! u8);
    out.push((n >> 16) as! u8);
    out.push((n >> 8) as! u8);
    out.push(n as! u8);
    out.append(w);
    return OK;
}

// What arrived (appended to `pending`), unwrapped into `plain` as far as
// whole frames go, the rest kept in `pending`. Without a layer it all
// passes through.
fn sasl_in(s: SaslGssapi&, pending: u8[>..]&, plain: u8[>..]&) -> i64 {
    if !sasl_layer_active(s) { plain.append(pending); pending.clear(); return OK; }
    var pos = 0;
    while pending.len - pos >= 4 {
        let n: i64 = (pending[pos] as i64) << 24 | (pending[pos + 1] as i64) << 16 | (pending[pos + 2] as i64) << 8 | pending[pos + 3];
        if n > SASL_MAX_BUFFER || n < 16 { return ERR_TOKEN; }
        if pending.len - pos - 4 < n { break; }
        let sealed, err = gss_unwrap(s.ctx, pending[pos + 4..pos + 4 + n], plain);
        if err != OK { return err; }
        if s.layer == SASL_LAYER_CONFIDENTIALITY && !sealed { return ERR_TOKEN; }
        pos += 4 + n;
    }
    if pos > 0 {
        var rest: u8[>..] = [];
        rest.append(pending[pos..]);
        pending.clear();
        pending.append(rest);
    }
    return OK;
}

// --- Active Directory ---------------------------------------------------------

// A SID's binary form (MS-DTYP §2.4.2.2) from its text, the inverse of
// sid_from_bytes; ok false for text that is not a SID.
fn sid_to_bytes(text: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if !text.starts_with("S-") { return out, false; }
    var parts: u64[>..] = [];
    var cur: u64 = 0;
    var digits = 0;
    var hex_auth = false;
    var i = 2;
    while i <= text.len {
        if i == text.len || text[i] == '-' {
            if digits == 0 { return out, false; }
            parts.push(cur);
            cur = 0;
            digits = 0;
            i++;
            continue;
        }
        let c = text[i];
        // The authority may be hex (0x...) when it is 2^32 or more.
        if parts.len == 1 && digits == 0 && c == '0' && i + 1 < text.len && (text[i + 1] == 'x' || text[i + 1] == 'X') {
            hex_auth = true;
            i += 2;
            continue;
        }
        var v: u64 = 0;
        if c >= '0' && c <= '9' { v = c - '0'; }
        else if hex_auth && parts.len == 1 && c >= 'a' && c <= 'f' { v = c - 'a' + 10; }
        else if hex_auth && parts.len == 1 && c >= 'A' && c <= 'F' { v = c - 'A' + 10; }
        else { return out, false; }
        cur = cur * (if hex_auth && parts.len == 1 { 16 } else { 10 }) + v;
        digits++;
        if digits > 15 { return out, false; }
        i++;
    }
    if parts.len < 2 || parts.len > 17 || parts[0] > 255 || parts[1] >> 48 != 0 { return out, false; }
    out.push(parts[0] as! u8);
    out.push((parts.len - 2) as! u8);
    for k in 6 { out.push((parts[1] >> ((40 - 8 * k) as! u64)) as! u8); }
    for k in 2..parts.len {
        if parts[k] >> 32 != 0 { out.clear(); return out, false; }
        let v = parts[k];
        out.push(v as! u8);
        out.push((v >> 8) as! u8);
        out.push((v >> 16) as! u8);
        out.push((v >> 24) as! u8);
    }
    return out, true;
}

// The filter (objectSid=\XX\XX...) matching a SID.
fn sid_filter(text: const u8[:]) -> u8[>..], bool {
    var f: u8[>..] = [];
    let b, ok = sid_to_bytes(text);
    if !ok { return f, false; }
    let hex = "0123456789abcdef";
    f.append("(objectSid=");
    for x in b { f.push('\\'); f.push(hex[x >> 4]); f.push(hex[x & 15]); }
    f.push(')');
    return f, true;
}

// The RootDSE's search (its defaultNamingContext, the domain's DN).
fn rootdse_request(c: ldap::Conn&, out: u8[>..]&) -> i64 {
    return ldap::search(c, "", ldap::SCOPE_BASE, "(objectClass=*)", "defaultNamingContext,dnsHostName", out);
}

// A subtree search under `base` for the object with a SID: its DN and
// sAMAccountName come back in the entry.
fn sid_lookup_request(c: ldap::Conn&, base: const u8[:], sid: const u8[:], out: u8[>..]&) -> i64 {
    let f, ok = sid_filter(sid);
    if !ok { return -1; }
    return ldap::search(c, base, ldap::SCOPE_SUB, f, "sAMAccountName,objectClass,objectSid", out);
}

// A base search of a user's (or computer's) DN for tokenGroups: every
// group SID the account has, nested ones included, as AD computes them.
fn token_groups_request(c: ldap::Conn&, dn: const u8[:], out: u8[>..]&) -> i64 {
    return ldap::search(c, dn, ldap::SCOPE_BASE, "(objectClass=*)", "tokenGroups", out);
}

// The SIDs of an entry's binary SID attribute (tokenGroups, objectSid),
// as text.
fn entry_sids(msgs: const u8[:], m: const ldap::Message&, attr: const u8[:]) -> u8[][>..] {
    var out: u8[][>..] = [];
    for v in ldap::get_values(msgs, m, attr) {
        let s, ok = sid_from_bytes(v);
        if ok { out.push(copy(s)); }
    }
    return out;
}
