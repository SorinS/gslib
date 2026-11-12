// Messages against miekg/dns (vectors/msg.txt, from scripts/oracle): each
// message built from its header and its sections' records, packed with
// name compression into the same bytes as miekg's Pack, and miekg's
// packed message unpacked into the same records and written as miekg's
// Msg.String() writes it.
import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
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

fn main() {
    tv::each_row(str(vectors_dir(), "/msg.txt")) { r => check_row(r); };
    tv::done("msg");
}
