// goose-ldapsearch: OpenLDAP's ldapsearch on the ldap package.
//
//   goose-ldapsearch [options] [-b base] [-s base|one|sub|children] [-a never|search|find|always]
//                    [-z sizelimit] [-l timelimit] [-A] [-L[L[L]]] [-E [!]pr=<size>[/noprompt]]
//                    [-E [!]sss=[-]attr[:rule][/...]] [filter [attributes...]]
//
// The filter is (objectclass=*) by default, the attributes all user
// attributes; the output is OpenLDAP's: its extended LDIF, -L for LDIFv1
// with comments, -LL without them, -LLL without the version line. The
// common options are cli's.
import std;
import os;
import base64;
import gslib from "../..";
import gslib.ldap;
import gslib.asn1;
import gslib.bignum;
import gslib.x509;
import gslib.tls;
import gslib.ldap.conn;
import gslib.ldap.ldif;
import gslib.ldap.dn;
import gslib.ldap.filter;
import .sysnet;
import .cli;

fn usage(o: const cli::Opts&) -> i32 {
    sysnet::eprint(str("usage: ", o.prog, " [options] [filter [attributes...]]\nSearch options:\n  -b base     base DN\n  -s scope    base, one, sub (the default) or children\n  -a deref    never (the default), search, find or always\n  -z limit    size limit\n  -l limit    time limit, in seconds\n  -A          attribute names only\n  -L[L[L]]    LDIFv1; without comments; without the version\n  -E ext      search control: [!]pr=<size>[/noprompt], [!]sss=[-]attr[:rule][/...]\n", cli::COMMON_USAGE));
    return 2;
}

// The DN in OpenLDAP's user-friendly form, for the comment over an
// entry: the values of each RDN (" + " between an RDN's), ", " between
// RDNs, and the domain components at the end joined by dots.
fn ufn(text: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let d, ok = ldap::parse_dn(text);
    if !ok { out.append(text); return out; }
    // Where the trailing run of single dc= RDNs starts.
    var dc_from = d.rdns;
    var r = d.rdns - 1;
    while r >= 0 {
        let i0, i1 = ldap::rdn_bounds(d, r);
        if i1 - i0 != 1 || !ldap::equal_fold(ldap::ava_type(d, d.avas[i0]), "dc") { break; }
        dc_from = r;
        r--;
    }
    for k in d.rdns {
        let i0, i1 = ldap::rdn_bounds(d, k);
        if k > 0 { out.append(if k > dc_from { "." } else { ", " }); }
        for i in i0..i1 {
            if i > i0 { out.append(" + "); }
            // Its special characters as \XX, as ldap_dn2ufn leaves them.
            let v = ldap::ava_value(d, d.avas[i]);
            for j in v.len {
                let c = v[j];
                if c == ',' || c == '+' || c == '"' || c == '\\' || c == '<' || c == '>' || c == ';' ||
                   (j == 0 && (c == '#' || c == ' ')) || (j == v.len - 1 && c == ' ') {
                    out.push('\\');
                    format_uint(out, c, 16, 2, '0');
                    to_upper(out[out.len - 2..]);
                } else {
                    out.push(c);
                }
            }
        }
    }
    return out;
}

fn scope_name(s: i64) -> const u8[:] {
    if s == ldap::SCOPE_BASE { return "baseObject"; }
    if s == ldap::SCOPE_ONE { return "oneLevel"; }
    if s == ldap::SCOPE_CHILDREN { return "children"; }
    return "subtree";
}

fn header(level: i64, base: const u8[:], scope: i64, filter: const u8[:], attrs: const u8[:], page: i64) {
    if level >= 2 { return; }
    var s: u8[>..] = [];
    if level == 0 { s.append("# extended LDIF\n"); }
    format(s, "#\n# LDAPv3\n# base <", base, "> with scope ", scope_name(scope), "\n# filter: ", filter, "\n# requesting: ");
    if attrs.len == 0 { s.append("ALL"); }
    else { for a in split(attrs, ' ') { if a.len > 0 { format(s, a, " "); } } }
    s.push('\n');
    if page > 0 { format(s, "# with pagedResults control: size=", page, "\n"); }
    s.append("#\n\n");
    write_stdout(s);
}

fn run() -> i32 {
    let a = args();
    var o = cli::opts("goose-ldapsearch");
    var base: u8[>..] = [];
    var lb: u8[>..] = [];
    if env("LDAPBASE", lb) { base.append(lb); }
    var scope = ldap::SCOPE_SUB;
    var deref = ldap::DEREF_NEVER;
    var size_limit: i64 = 0;
    var time_limit: i64 = 0;
    var types_only = false;
    var level: i64 = 0;
    var page: i64 = 0;
    var page_critical = false;
    var sort_keys: u8[>..] = [];
    var sort_critical = false;
    var filter: u8[>..] = [];
    var attrs: u8[>..] = [];
    var positional = 0;
    var i = 1;
    while i < a.len {
        let w = a[i];
        let r = cli::common_flag(o, a, i);
        if r < 0 { return usage(o); }
        if r > 0 { continue; }
        if w == "-A" { types_only = true; i++; continue; }
        if w == "-L" || w == "-LL" || w == "-LLL" { level = level + w.len - 1; i++; continue; }
        if w.len == 2 && w[0] == '-' && w != "-" {
            if i + 1 >= a.len { return usage(o); }
            let v = a[i + 1];
            i += 2;
            if w == "-b" { base.clear(); base.append(v); }
            else if w == "-s" {
                if v == "base" { scope = ldap::SCOPE_BASE; }
                else if v == "one" || v == "onelevel" { scope = ldap::SCOPE_ONE; }
                else if v == "sub" || v == "subtree" { scope = ldap::SCOPE_SUB; }
                else if v == "children" || v == "subordinate" { scope = ldap::SCOPE_CHILDREN; }
                else { return usage(o); }
            } else if w == "-a" {
                if v == "never" { deref = ldap::DEREF_NEVER; }
                else if v == "search" { deref = ldap::DEREF_SEARCHING; }
                else if v == "find" { deref = ldap::DEREF_FINDING; }
                else if v == "always" { deref = ldap::DEREF_ALWAYS; }
                else { return usage(o); }
            } else if w == "-z" || w == "-l" {
                var n: i64 = 0;
                if v != "none" && v != "unlimited" && v != "max" {
                    let x, ok = parse_int(v, 10);
                    if !ok || x < 0 { return usage(o); }
                    n = x;
                }
                if w == "-z" { size_limit = n; } else { time_limit = n; }
            } else if w == "-E" {
                var e: const u8[:] = v;
                var critical = false;
                if e.len > 0 && e[0] == '!' { critical = true; e = e[1..]; }
                if starts_with(e, "pr=") {
                    var num = e[3..];
                    let slash = position(num, '/');
                    if slash >= 0 { num = num[..slash]; }
                    let n, ok = parse_int(num, 10);
                    if !ok || n < 1 { return usage(o); }
                    page = n;
                    page_critical = critical;
                } else if starts_with(e, "sss=") {
                    sort_keys.clear();
                    for c in e[4..] { sort_keys.push(if c == '/' { ',' } else { c }); }
                    sort_critical = critical;
                } else {
                    return usage(o);
                }
            } else { return usage(o); }
            continue;
        }
        if w.len > 0 && w[0] == '-' && w != "-" { return usage(o); }
        // The first operand is the filter if it looks like one, as in ldapsearch.
        if positional == 0 && (starts_with(w, "(") || position(w, '=') >= 0) { filter.append(w); }
        else { if attrs.len > 0 { attrs.push(' '); } attrs.append(w); }
        positional++;
        i++;
    }
    if filter.len == 0 { filter.append("(objectclass=*)"); }
    // A filter without its parentheses gets them, as libldap gives them.
    var sent: u8[>..] = [];
    if filter[0] != '(' { format(sent, "(", filter, ")"); } else { sent.append(filter); }
    if o.dry_run { return 0; }

    var l = cli::link();
    var cfg = tls::client_config("", "");
    var c = ldap::client();
    let code = cli::open(o, l, cfg, c);
    if code != 0 { return code as! i32; }

    var extra: u8[>..] = [];
    if !cli::controls(o, extra) { return 1; }
    if sort_keys.len > 0 { ldap::put_sort(extra, sort_keys, sort_critical); }

    var cookie: u8[>..] = [];
    var responses = 0;
    var entries = 0;
    var references = 0;
    var rc: i64 = 0;
    var out: u8[>..] = [];
    var msgs: u8[>..] = [];
    var text: u8[>..] = [];
    if level == 1 || level == 2 { write_stdout("version: 1\n\n"); }
    loop {
        var ctl: u8[>..] = [];
        ctl.append(extra);
        if page > 0 { ldap::put_paging(ctl, page, cookie, page_critical); }
        header(level, base, scope, filter, attrs, page);
        let id = ldap::search(c, base, scope, sent, attrs, out, ctl, deref, size_limit, time_limit, types_only);
        if id < 0 { cli::report(o, "ldap_search_ext", c.error, "", ""); return cli::status(c.error); }
        if !cli::transmit(l, out) { cli::report(o, "ldap_search_ext", ldap::ERROR_NETWORK, "", ""); return 255; }
        out.clear();
        var done = false;
        var next_cookie: u8[>..] = [];
        while !done {
            msgs.clear();
            let r = cli::receive(o, l, cfg, c, msgs);
            if r != 0 { cli::report(o, "ldap_result", r, "", ""); return 255; }
            var pos = 0;
            loop {
                let m, ok = ldap::next_message(msgs, pos);
                if !ok { break; }
                if m.id != id { continue; }
                text.clear();
                if m.op == ldap::OP_SEARCH_ENTRY {
                    entries++;
                    responses++;
                    if level < 2 {
                        let u = ufn(ldap::entry_dn(msgs, m));
                        text.push('#');
                        if u.len > 0 { format(text, " ", u); }
                        text.push('\n');
                    }
                    ldap::ldif_entry(text, msgs, m, o.wrap, types_only);
                    text.push('\n');
                } else if m.op == ldap::OP_SEARCH_REFERENCE {
                    // As ldapsearch writes them: ref: lines in extended LDIF,
                    // comments in LDIFv1, a blank line without comments.
                    references++;
                    responses++;
                    if level < 2 {
                        text.append("# search reference\n");
                        for u in ldap::referrals(msgs, m) {
                            if level == 0 { ldap::ldif_line(text, "ref", u, o.wrap); } else { format(text, "# ref", u, "\n"); }
                        }
                    }
                    text.push('\n');
                } else if m.op == ldap::OP_SEARCH_DONE {
                    responses++;
                    done = true;
                    rc = ldap::result_code(msgs, m);
                    let message = ldap::result_message(msgs, m);
                    let matched = ldap::matched_dn(msgs, m);
                    if level == 0 {
                        format(text, "# search result\nsearch: ", id, "\nresult: ", rc, " ", cli::err2string(rc), "\n");
                        if matched.len > 0 { format(text, "matchedDN: ", matched, "\n"); }
                        if message.len > 0 { format(text, "text: ", message, "\n"); }
                        for u in ldap::referrals(msgs, m) { format(text, "ref: ", u, "\n"); }
                        for k in ldap::controls(msgs, m) {
                            format(text, "control: ", ldap::bytes(msgs, k.oid), if k.critical { " true" } else { " false" });
                            if k.has_value { text.push(' '); base64::encode(text, ldap::bytes(msgs, k.value)); }
                            text.push('\n');
                        }
                    } else {
                        if level == 1 { text.append("# search result\n"); }
                        var e: u8[>..] = [];
                        if rc != 0 { format(e, cli::err2string(rc), " (", rc, ")\n"); }
                        if matched.len > 0 { format(e, "Matched DN: ", matched, "\n"); }
                        if message.len > 0 { format(e, "Additional information: ", message, "\n"); }
                        for u in ldap::referrals(msgs, m) { format(e, "Referral: ", u, "\n"); }
                        sysnet::eprint(e);
                    }
                    next_cookie.append(ldap::paging_cookie(msgs, m));
                    if page > 0 && level == 0 {
                        text.append("pagedresults: cookie=");
                        base64::encode(text, next_cookie);
                        text.push('\n');
                    } else if page > 0 && rc == 0 {
                        text.append("# pagedresults: cookie=");
                        base64::encode(text, next_cookie);
                        text.push('\n');
                    }
                }
                write_stdout(text);
            }
        }
        cookie.clear();
        cookie.append(next_cookie);
        if page == 0 || rc != 0 || cookie.len == 0 { break; }
    }
    if level < 2 {
        text.clear();
        format(text, "\n# numResponses: ", responses, "\n");
        if entries > 0 { format(text, "# numEntries: ", entries, "\n"); }
        if references > 0 { format(text, "# numReferences: ", references, "\n"); }
        write_stdout(text);
    }
    cli::close(l, c);
    return cli::status(rc);
}

fn main() { exit(run()); }
