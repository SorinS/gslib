// goose-dig: queries from the command line, as miekg's q (and dig) make
// them:
//
//   goose-dig [@server] [-p port] [+tcp] [+dnssec] [+nord] [+cd] [+short]
//             [+bufsize=n] [-y [alg:]name:secret] [-x address] [name] [type] [class]
//
// The server is @server (a name or address, "[v6]:port" too), else the
// first nameserver of /etc/resolv.conf. The type is A unless given (NS
// for no name, PTR with -x); the class IN. AXFR and IXFR (IXFR=serial)
// transfer the zone over TCP. -y signs with TSIG (hmac-sha256 unless an
// algorithm is given; the secret in base64) and checks the reply's
// signature. The reply is printed as miekg's Msg.String(), or with +short
// only each answer's rdata. Exits 1 when no reply came, 2 for bad
// arguments.
import std;
import os;
import gslib from "../..";
import gslib.dns;
import gslib.dns.rdata;
import gslib.dns.msg;
import gslib.dns.edns;
import gslib.dns.zone;
import gslib.dns.client;
import gslib.dns.tsig;

fn usage() -> i32 {
    write_stderr("usage: goose-dig [@server] [-p port] [+tcp] [+dnssec] [+nord] [+cd] [+short] [+bufsize=n]\n");
    write_stderr("                 [-y [alg:]name:secret] [-x address] [name] [type] [class]\n");
    return 2;
}

fn fail(s: const u8[:]) -> i32 {
    write_stderr(str("goose-dig: ", s, "\n"));
    return 1;
}

fn print_short(list: const u8[:]) {
    dns::each_rr(list) { rr =>
        var out: u8[>..] = [];
        dns::rdata_append(out, rr.rtype, rr.rdata(list), time_ns() / 1000000000);
        print(out);
    };
}

fn run() -> i32 {
    let a = args();
    var server: u8[>..] = [];
    var port: i64 = 0;
    var name: u8[>..] = [];
    var qtype: i64 = -1;
    var qclass: i64 = dns::CLASS_INET;
    var tcp = false;
    var dnssec = false;
    var rd = true;
    var cd = false;
    var short = false;
    var bufsize: i64 = 1232;
    var ixfr_serial: i64 = -1;
    var c = dns::Client { .. };
    var i = 1;
    while i < a.len {
        let s = a[i];
        if s.len > 1 && s[0] == '@' { server.clear(); server.append(s[1..]); }
        else if s == "-p" && i + 1 < a.len { i++; let n, ok = parse_int(a[i]); if !ok || n <= 0 || n > 65535 { return usage(); } port = n; }
        else if s == "+tcp" { tcp = true; }
        else if s == "+dnssec" { dnssec = true; }
        else if s == "+nord" { rd = false; }
        else if s == "+cd" { cd = true; }
        else if s == "+short" { short = true; }
        else if s.len > 9 && s[..9] == "+bufsize=" { let n, ok = parse_int(s[9..]); if !ok || n < 0 || n > 65535 { return usage(); } bufsize = n; }
        else if s == "-y" && i + 1 < a.len {
            i++;
            let parts = split(a[i], ':');
            if parts.len == 2 { c.tsig_name.append(parts[0]); c.tsig_secret.append(parts[1]); }
            else if parts.len == 3 {
                c.tsig_alg.clear();
                c.tsig_alg.append(parts[0]);
                if !dns::is_fqdn(parts[0]) { c.tsig_alg.push('.'); }
                c.tsig_name.append(parts[1]);
                c.tsig_secret.append(parts[2]);
            } else { return usage(); }
            if !dns::is_fqdn(c.tsig_name) { c.tsig_name.push('.'); }
        }
        else if s == "-x" && i + 1 < a.len {
            i++;
            let v4, ok4 = dns::ip4_parse(a[i]);
            let v6, ok6 = dns::ip6_parse(a[i]);
            name.clear();
            if ok4 { name.append(dns::reverse_addr(v4)); } else if ok6 { name.append(dns::reverse_addr(v6)); } else { return usage(); }
            if qtype < 0 { qtype = dns::TYPE_PTR; }
        }
        else if s.len > 0 && s[0] == '-' { return usage(); }
        else if s.len > 5 && dns::ascii_eq_fold(s[..5], "IXFR=") {
            let n, ok = parse_int(s[5..]);
            if !ok { return usage(); }
            qtype = dns::TYPE_IXFR;
            ixfr_serial = n;
        }
        else if dns::type_from_string(s) >= 0 && name.len > 0 { qtype = dns::type_from_string(s); }
        else if dns::class_from_string(s) >= 0 && name.len > 0 { qclass = dns::class_from_string(s); }
        else if name.len == 0 { name.append(s); }
        else if dns::type_from_string(s) >= 0 { qtype = dns::type_from_string(s); }
        else { return usage(); }
        i++;
    }
    if name.len == 0 { name.push('.'); if qtype < 0 { qtype = dns::TYPE_NS; } }
    if qtype < 0 { qtype = dns::TYPE_A; }
    if !dns::is_fqdn(name) { name.push('.'); }
    if server.len == 0 {
        let cfg, ok = dns::client_config_file("/etc/resolv.conf");
        if !ok || cfg.servers.len == 0 { return fail("no server: give @server"); }
        server.append(cfg.servers[0]);
    }
    // The port: -p, else the server's own ":port", else 53.
    var target: u8[>..] = [];
    let host, sport, hok = dns::split_host_port(server);
    if !hok { return usage(); }
    var colon = false;
    for ch in host { if ch == ':' { colon = true; } }
    if colon { target.push('['); target.append(host); target.push(']'); } else { target.append(host); }
    target.push(':');
    format(target, if port > 0 { port } else { sport as i64 });

    var m = dns::Msg { .. };
    let e = dns::set_question(m, name, qtype as! u16);
    if e != dns::OK { return fail(str("bad name ", name)); }
    m.question.resize(m.question.len - 2);
    dns::put16(m.question, qclass as! u16);
    m.hdr.recursion_desired = rd;
    m.hdr.checking_disabled = cd;
    if bufsize > 0 || dnssec { dns::set_edns0(m, (if bufsize < 512 { 512 } else { bufsize }) as! u16, dnssec); }
    if dnssec { m.hdr.authenticated_data = true; }
    c.net = if tcp { dns::NET_TCP } else { dns::NET_UDP };
    c.tcp_fallback = !tcp;

    let start = clock_ns();
    if qtype == dns::TYPE_AXFR || qtype == dns::TYPE_IXFR {
        if qtype == dns::TYPE_IXFR {
            var soa: u8[>..] = [];
            dns::rr_append(soa, m.question[.. m.question.len - 4], dns::TYPE_SOA, dns::CLASS_INET, 0,
                           [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let rr = dns::rr_at(soa, 0);
            // Two root names, then the serial.
            let p = rr.rd + 2;
            soa[p] = (ixfr_serial >> 24) as! u8; soa[p + 1] = (ixfr_serial >> 16) as! u8;
            soa[p + 2] = (ixfr_serial >> 8) as! u8; soa[p + 3] = ixfr_serial as! u8;
            m.ns.append(soa);
            m.extra.clear();
        } else {
            m.extra.clear();
        }
        m.hdr.recursion_desired = false;
        var count = 0;
        let te = dns::transfer_in(c, m, target) { r =>
            dns::each_rr(r.answer) { rr =>
                if short { var out: u8[>..] = []; dns::rdata_append(out, rr.rtype, rr.rdata(r.answer), time_ns() / 1000000000); print(out); }
                else { print(dns::rr_string(r.answer, rr)); }
                count++;
            };
        };
        if te != dns::OK { return fail(dns::error_text(te)); }
        if !short { print(str(";; XFR size: ", count, " records\n;; SERVER: ", target)); }
        return 0;
    }
    var r = dns::Msg { .. };
    let xe = dns::exchange(c, m, target, r);
    let ms = (clock_ns() - start) / 1000000;
    if xe != dns::OK { return fail(str(dns::error_text(xe), " (", target, ")")); }
    if short { print_short(r.answer); return 0; }
    print(dns::msg_string(r));
    print(str(";; Query time: ", ms, " msec\n;; SERVER: ", target, if c.tsig_name.len > 0 { "\n;; TSIG: ok" } else { "" }));
    return 0;
}

fn main() { exit(run()); }
