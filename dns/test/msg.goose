// Messages against miekg/dns (vectors/msg.txt, from scripts/oracle): each
// message built from its header and its sections' records, packed with
// name compression into the same bytes as miekg's Pack, and miekg's
// packed message unpacked into the same records and written as miekg's
// Msg.String() writes it. Then hostile messages: rdata over 65535 bytes
// once decompressed, rdata cut short at a field boundary.
import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.server;
import tv;

fn unhex(out: u8[>..]&, s: const u8[:]) {
    var i = 0;
    while i + 1 < s.len { out.push((tv::unhex(s[i]) << 4) | tv::unhex(s[i + 1])); i += 2; }
}

fn check_row(r: tv::Row&) {
    let id = r.next_int();
    let flags = r.next_int();
    let rcode = r.next_int();
    var m = dns::Msg { .. };
    m.hdr = dns::header_from(id as! u16, flags as! u16);
    m.hdr.rcode = rcode as! u16;
    m.compress = true;
    unhex(m.question, r.next());
    unhex(m.answer, r.next());
    unhex(m.ns, r.next());
    unhex(m.extra, r.next());
    r.to_results();
    var want: u8[>..] = [];
    unhex(want, r.next());
    let text = r.next();
    var got: u8[>..] = [];
    let e = dns::pack(m, got);
    tv::check_int(str("pack ", id), e, dns::OK);
    tv::check_eq(str("packed ", id), got, want);

    var back = dns::Msg { .. };
    let ue = dns::unpack(want, back);
    tv::check_int(str("unpack ", id), ue, dns::OK);
    tv::check_eq(str("answer ", id), back.answer, m.answer);
    tv::check_eq(str("ns ", id), back.ns, m.ns);
    tv::check_int(str("rcode ", id), back.hdr.rcode, rcode);
    tv::check_eq(str("string ", id), dns::msg_string(back), text);
    // Uncompressed, it reads back the same too.
    m.compress = false;
    var plain: u8[>..] = [];
    dns::pack(m, plain);
    var back2 = dns::Msg { .. };
    let pe = dns::unpack(plain, back2);
    tv::check_int(str("unpack plain ", id), pe, dns::OK);
    tv::check_eq(str("plain answer ", id), back2.answer, m.answer);
    tv::check_eq(str("plain extra ", id), back2.extra, m.extra);
}

// The vectors' directory: vectors/, or the argument (scripts/differential.py's fresh ones).
fn vectors_dir() -> u8[>..] {
    let a = args();
    return if a.len > 1 { str(a[1]) } else { str("vectors") };
}

// --- Hostile messages -----------------------------------------------------------

// A reply's header with an records in the answer section, no question.
fn reply_head(an: i64) -> u8[>..] {
    var w: u8[>..] = [];
    dns::put16(w, 7); dns::put16(w, 0x8400); dns::put16(w, 0); dns::put16(w, an as! u16); dns::put16(w, 0); dns::put16(w, 0);
    return w;
}

fn wire_rr(w: u8[>..]&, owner: const u8[:], t: u16, class: u16, rd: const u8[:]) {
    let n, e = dns::name_parse(owner, []);
    w.append(n);
    dns::put16(w, t); dns::put16(w, class); dns::put32(w, 300); dns::put16(w, rd.len as! u16);
    w.append(rd);
}

fn name_wire(s: const u8[:]) -> u8[>..] {
    let n, e = dns::name_parse(s, []);
    var out: u8[>..] = [];
    out.append(n);
    return out;
}

fn unpacks(w: const u8[:]) -> i64 {
    var m = dns::Msg { .. };
    let e = dns::unpack(w, m);
    if e != dns::OK { tv::check("nothing kept after an error", m.answer.len == 0); }
    return e;
}

fn hostile() {
    // HIP whose rendezvous servers are 270 pointers to a 249-byte name: its
    // rdata, decompressed, is over 65535 bytes, which its length cannot hold.
    var h: u8[>..] = [];
    dns::put16(h, 7); dns::put16(h, 0x8180); dns::put16(h, 1); dns::put16(h, 1); dns::put16(h, 0); dns::put16(h, 0);
    for l in 4 { h.push(61); for j in 61 { h.push('a'); } }
    h.push(0);
    dns::put16(h, dns::TYPE_HIP); dns::put16(h, 1);
    h.push(0xc0); h.push(12);
    dns::put16(h, dns::TYPE_HIP); dns::put16(h, 1); dns::put32(h, 60);
    dns::put16(h, 4 + 2 * 270);
    dns::put32(h, 0);
    for i in 270 { h.push(0xc0); h.push(12); }
    tv::check_int("HIP over 65535 bytes decompressed", unpacks(h), dns::ERR_BUF);

    // Rdata cut short at a field boundary: miekg takes it, this does not.
    var soa_names: u8[>..] = [];
    soa_names.append(name_wire("ns.example."));
    soa_names.append(name_wire("hm.example."));
    var w = reply_head(1);
    wire_rr(w, "example.", dns::TYPE_SOA, dns::CLASS_INET, soa_names);
    tv::check_int("SOA without its numbers", unpacks(w), dns::ERR_RDATA);
    w = reply_head(1);
    wire_rr(w, "example.", dns::TYPE_SOA, dns::CLASS_INET, []);
    tv::check_int("SOA without rdata", unpacks(w), dns::ERR_RDATA);
    var sig: u8[>..] = [];
    for i in 18 { sig.push(1); }               // RRSIG without its signer and signature
    w = reply_head(1);
    wire_rr(w, "example.", dns::TYPE_RRSIG, dns::CLASS_INET, sig);
    tv::check_int("RRSIG cut short", unpacks(w), dns::ERR_RDATA);
    w = reply_head(1);
    wire_rr(w, "example.", dns::TYPE_RRSIG, dns::CLASS_INET, []);
    tv::check_int("RRSIG without rdata", unpacks(w), dns::ERR_RDATA);
    let n3: u8[4] = [1, 0, 0, 0];              // NSEC3 without salt, next name, bitmap
    w = reply_head(1);
    wire_rr(w, "x.example.", dns::TYPE_NSEC3, dns::CLASS_INET, n3);
    tv::check_int("NSEC3 cut short", unpacks(w), dns::ERR_RDATA);
    let mx: u8[2] = [0, 10];
    w = reply_head(1);
    wire_rr(w, "example.", dns::TYPE_MX, dns::CLASS_INET, mx);
    tv::check_int("MX without its name", unpacks(w), dns::ERR_RDATA);

    // What may be empty still is: dynamic update's deletes (class ANY and
    // NONE), an NSEC's bitmap, a type whose fields run to the end.
    w = reply_head(2);
    wire_rr(w, "example.", dns::TYPE_SOA, dns::CLASS_ANY, []);
    wire_rr(w, "example.", dns::TYPE_A, dns::CLASS_NONE, []);
    tv::check_int("empty rdata in deletes", unpacks(w), dns::OK);
    w = reply_head(2);
    wire_rr(w, "example.", dns::TYPE_NSEC, dns::CLASS_INET, name_wire("b.example."));
    wire_rr(w, "example.", dns::TYPE_APL, dns::CLASS_INET, []);
    tv::check_int("NSEC with no types, empty APL", unpacks(w), dns::OK);
    let isdn: u8[4] = [3, '1', '2', '3'];      // ISDN without its optional subaddress
    w = reply_head(1);
    wire_rr(w, "example.", dns::TYPE_ISDN, dns::CLASS_INET, isdn);
    tv::check_int("ISDN without a subaddress", unpacks(w), dns::OK);

    // list_valid holds records to the same rule.
    var list: u8[>..] = [];
    dns::rr_append(list, name_wire("example."), dns::TYPE_SOA, dns::CLASS_INET, 300, []);
    tv::check("list_valid: SOA without rdata", !dns::list_valid(list));
    list.clear();
    dns::rr_append(list, name_wire("example."), dns::TYPE_SOA, dns::CLASS_INET, 300, soa_names);
    tv::check("list_valid: SOA cut short", !dns::list_valid(list));
    list.clear();
    dns::rr_append(list, name_wire("example."), dns::TYPE_SOA, dns::CLASS_ANY, 0, []);
    tv::check("list_valid: a delete", dns::list_valid(list));

    // SVCB parameters with a structure of their own are checked inside:
    // an alpn id's length past its value, ports and hints of the wrong size.
    // Each is priority 1, target ".", one parameter.
    let svcb_bad: u8[][>..] = [
        "\x00\x01\x00\x00\x01\x00\x06\x02h3\x32h\x00",       // alpn: "h3", then a 0x32-byte id in 3 bytes
        "\x00\x01\x00\x00\x01\x00\x01\x05",                   // alpn: a 5-byte id in none
        "\x00\x01\x00\x00\x00\x00\x01\x00",                   // mandatory: odd
        "\x00\x01\x00\x00\x02\x00\x01\x00",                   // no-default-alpn with a value
        "\x00\x01\x00\x00\x03\x00\x01\x00",                   // port: one byte
        "\x00\x01\x00\x00\x04\x00\x05\x01\x02\x03\x04\x05", // ipv4hint: 5 bytes
        "\x00\x01\x00\x00\x06\x00\x04\x01\x02\x03\x04"];     // ipv6hint: 4 bytes
    for rd in svcb_bad {
        w = reply_head(1);
        wire_rr(w, "example.", 64, dns::CLASS_INET, rd);
        tv::check_int(str("SVCB refused: ", rd.len, " bytes"), unpacks(w), dns::ERR_RDATA);
        w = reply_head(1);
        wire_rr(w, "example.", 65, dns::CLASS_INET, rd);
        tv::check_int(str("HTTPS refused: ", rd.len, " bytes"), unpacks(w), dns::ERR_RDATA);
    }
    let okrd: u8[14] = [0, 1, 0, 0, 1, 0, 7, 2, 'h', '3', 3, 'h', '2', 'c'];
    w = reply_head(1);
    wire_rr(w, "example.", 65, dns::CLASS_INET, okrd);
    tv::check_int("HTTPS alpn=h3,h2c", unpacks(w), dns::OK);
    var m = dns::Msg { .. };
    let _ = dns::unpack(w, m);
    let txt = dns::rr_string(m.answer, dns::rr_at(m.answer, 0));
    tv::check(str("HTTPS text: ", txt), find(txt, "alpn=\"h3,h2c\"") >= 0);

    // A request shorter than a header is dropped unanswered (miekg, BIND),
    // and error_reply makes nothing of one.
    for n in 13 {
        var req: u8[>..] = [];
        for i in n { req.push(1); }
        if n < 12 {
            tv::check(str("accept_check drops ", n, " bytes"), dns::accept_check(req) == 0xFFFF);
            var out: u8[>..] = [];
            dns::error_reply(req, dns::RCODE_FORMAT_ERROR, out);
            tv::check(str("no error reply to ", n, " bytes"), out.len == 0);
        } else {
            tv::check("12 bytes: answered", dns::accept_check(req) != 0xFFFF);
        }
    }
}

fn main() {
    tv::each_row(str(vectors_dir(), "/msg.txt")) { r => check_row(r); };
    hostile();
    tv::done("msg");
}
