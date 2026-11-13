// parse_zone: reads a zone file (example.zone, or the one given) with its
// $ORIGIN, $TTL, $GENERATE, parentheses, comments and omitted owners, and
// looks at the records: counted by type, the RRsets of one name, the SOA's
// fields read from its rdata. Then a zone given as text with a mistake in
// it, which stops at the line of the mistake.
//
//   goose examples/dns/parse_zone.goose -- [FILE [ORIGIN]]

import std;
import os;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;

fn main() {
    let a = args();
    // example.zone beside this file, unless a zone is given.
    var path: u8[>..] = [];
    if a.len > 1 { path.append(a[1]); } else { path.append(str(resource_dir(), "example.zone")); }
    let origin_text = if a.len > 2 { a[2] } else { "example.com." };
    var text: u8[>..] = [];
    guard read_file(path, text) else { print("parse_zone: cannot read ", path); exit(1); }

    var opts = dns::ZoneOptions { .. };
    let origin, oe = dns::name_parse(origin_text, []);
    guard oe == dns::OK else { print("parse_zone: bad origin ", origin_text); exit(2); }
    opts.origin = origin;
    opts.include = true;          // $INCLUDE allowed (relative to the file)
    opts.file.append(path);
    var zone: u8[>..] = [];
    let r = dns::parse_zone(text, opts, zone);
    guard r.err == dns::OK else { print(path, ":", r.line, ": ", r.msg); exit(1); }
    print(path, ": ", dns::rr_count(zone), " records");

    // Counted by type, in the order the types first appear.
    var types:  u16[>..] = [];
    var counts: i64[>..] = [];
    dns::each_rr(zone) { rr =>
        var k = 0;
        while k < types.len && types[k] != rr.rtype { k++; }
        if k == types.len { types.push(rr.rtype); counts.push(0); }
        counts[k]++;
    };
    var line: u8[>..] = [];
    for k in types.len { format(line, " ", dns::type_string(types[k]), "=", counts[k]); }
    print("by type:", line);

    // The records of one name.
    let www, we = dns::name_parse("www.example.com.", []);
    print("www.example.com.:");
    dns::each_rr(zone) { rr => if dns::name_equal(rr.name(zone), www) { print("  ", dns::rr_string(zone, rr)); } };

    // The SOA: two names (read_name gives each and where it ends), then
    // five 32-bit numbers.
    dns::each_rr(zone) { rr =>
        if rr.rtype == dns::TYPE_SOA {
            let rd = rr.rdata(zone);
            let mname, rest, e1 = dns::read_name(rd, 0);
            let rname, at, e2 = dns::read_name(rd, rest);
            print("SOA: primary ", dns::name_text(mname), ", contact ", dns::name_text(rname), ", serial ",
                  dns::get32(rd, at), ", negative TTL ", dns::get32(rd, at + 16));
        }
    };
    let gen, ge = dns::name_parse("host3.example.com.", []);
    var found = false;
    dns::each_rr(zone) { rr => if dns::name_equal(rr.name(zone), gen) { found = true; } };
    guard found else { print("parse_zone: $GENERATE made no host3"); exit(1); }

    // Zone text with a mistake on its fourth line: the records before it,
    // and where it stopped.
    let broken = "$ORIGIN example.org.\n$TTL 300\n@ IN A 192.0.2.1\nwww IN MX mail.example.org.\nftp IN A 192.0.2.3\n";
    var part: u8[>..] = [];
    let br = dns::parse_zone(broken, dns::ZoneOptions { .. }, part);
    print("broken zone: ", dns::rr_count(part), " record read, then line ", br.line, ": ", br.msg);
    guard br.err != dns::OK && br.line == 4 && dns::rr_count(part) == 1 else { print("parse_zone: the mistake was not found"); exit(1); }
}
