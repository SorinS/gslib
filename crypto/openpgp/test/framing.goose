// openpgp.armor and openpgp.packet: CRC24 and armor both ways (with and
// without the checksum line, CRLF, a changed checksum, a wrong END line);
// packet headers in the old format (1, 2 and 4-octet lengths and the
// indeterminate one) and the new (1, 2 and 5 octets, partial lengths),
// written and read back at the lengths where the encodings change;
// truncated headers refused; the cleartext framework's dash escapes and
// canonical text.
import std;
import gslib from "../../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.armor;
import gslib.crypto.openpgp.packet;
import tv;

fn crc() {
    tv::check_int("crc24 empty", openpgp::crc24(""), 0xB704CE);
    // The RFC's C code gives 0xBA1C7B for "abc".
    tv::check_int("crc24 abc", openpgp::crc24("abc"), 0xBA1C7B);
}

fn armor() {
    var data: u8[>..] = [];
    for i in 200 { data.push((i * 7) as! u8); }
    var text: u8[>..] = [];
    openpgp::armor(text, openpgp::ARMOR_MESSAGE, data, "Comment: test\n");
    tv::check("armor begins", starts_with(text, "-----BEGIN PGP MESSAGE-----\nComment: test\n\n"));
    tv::check("armor ends", ends_with(text, "-----END PGP MESSAGE-----\n"));
    var back: u8[>..] = [];
    let label, e = openpgp::dearmor(text, back);
    tv::check_int("dearmor", e, openpgp::OK);
    tv::check("dearmor label", label[..] == openpgp::ARMOR_MESSAGE);
    tv::check_eq("dearmor data", back, data);
    // CRLF line ends and leading text.
    var crlf: u8[>..] = [];
    crlf.append("some text before\r\n");
    for c in text { if c == '\n' { crlf.append("\r\n"); } else { crlf.push(c); } }
    back.clear();
    let l2, e2 = openpgp::dearmor(crlf, back);
    tv::check("dearmor crlf", e2 == openpgp::OK && back[..] == data[..]);
    // Without the checksum line (RFC 9580 makes it optional).
    let eq = find(text, "\n=");
    var nocrc: u8[>..] = [];
    nocrc.append(text[..eq + 1]);
    let end = find(text, "-----END");
    nocrc.append(text[end..]);
    back.clear();
    let l3, e3 = openpgp::dearmor(nocrc, back);
    tv::check("dearmor without crc", e3 == openpgp::OK && back[..] == data[..]);
    // A wrong checksum.
    var bad = copy(text);
    bad[eq + 2] = if bad[eq + 2] == 'A' { 'B' } else { 'A' };
    back.clear();
    let l4, e4 = openpgp::dearmor(bad, back);
    tv::check_int("dearmor bad crc", e4, openpgp::ERR_CHECKSUM);
    // A changed data character is caught by the checksum too.
    var bad2 = copy(text);
    let first = find(text, "\n\n") + 2;
    bad2[first] = if bad2[first] == 'A' { 'B' } else { 'A' };
    back.clear();
    let l5, e5 = openpgp::dearmor(bad2, back);
    tv::check_int("dearmor changed data", e5, openpgp::ERR_CHECKSUM);
    // END with another label, or none.
    var wrong: u8[>..] = [];
    wrong.append(text[..end]);
    wrong.append("-----END PGP SIGNATURE-----\n");
    back.clear();
    let l6, e6 = openpgp::dearmor(wrong, back);
    tv::check_int("dearmor wrong end", e6, openpgp::ERR_MALFORMED);
    back.clear();
    let l7, e7 = openpgp::dearmor(text[..end], back);
    tv::check_int("dearmor no end", e7, openpgp::ERR_MALFORMED);
    back.clear();
    let l8, e8 = openpgp::dearmor("no armor here", back);
    tv::check_int("dearmor nothing", e8, openpgp::ERR_MALFORMED);
    tv::check("is_armored", openpgp::is_armored("  \n-----BEGIN PGP X-----") && !openpgp::is_armored("\x99\x00"));
}

fn packets() {
    // New format at every length class.
    for n in [0, 1, 191, 192, 193, 8383, 8384, 70000] {
        var body: u8[>..] = [];
        for i in n { body.push((i & 255) as! u8); }
        var out: u8[>..] = [];
        openpgp::put_packet(out, openpgp::TAG_LITERAL, body);
        out.append("\xc2\x00");     // another packet after it
        let p, e = openpgp::next_packet(out, 0);
        tv::check(str("new length ", n), e == openpgp::OK && p.tag == openpgp::TAG_LITERAL && !p.old
                  && p.body_end - p.body == n && out[p.body..p.body_end] == body[..]);
        let q, e2 = openpgp::next_packet(out, p.end);
        tv::check(str("next after ", n), e2 == openpgp::OK && q.tag == openpgp::TAG_SIGNATURE && q.end == out.len);
        // Truncated anywhere: refused, never read past the end.
        for cut in [1, 2, 3, p.body, out.len - 3] {
            if cut >= p.end || cut <= 0 { continue; }
            let r, e3 = openpgp::next_packet(out[..cut], 0);
            tv::check(str("truncated ", n, " at ", cut), e3 == openpgp::ERR_MALFORMED);
        }
    }
    // Old format: 1, 2, 4-octet lengths, and indeterminate.
    let o1 = "\xac\x03abc\x88\x00";
    let p1, e1 = openpgp::next_packet(o1, 0);
    tv::check("old 1-octet", e1 == openpgp::OK && p1.old && p1.tag == 11 && o1[p1.body..p1.body_end] == "abc" && p1.end == 5);
    let o2 = "\xad\x00\x03abc";
    let p2, e2 = openpgp::next_packet(o2, 0);
    tv::check("old 2-octet", e2 == openpgp::OK && p2.tag == 11 && o2[p2.body..p2.body_end] == "abc");
    let o4 = "\xae\x00\x00\x00\x03abc";
    let p4, e4 = openpgp::next_packet(o4, 0);
    tv::check("old 4-octet", e4 == openpgp::OK && o4[p4.body..p4.body_end] == "abc");
    let oi = "\xa3\x01rest of the data";
    let pi, ei = openpgp::next_packet(oi, 0);
    tv::check("old indeterminate", ei == openpgp::OK && pi.tag == 8 && pi.indeterminate && pi.body == 1 && pi.end == oi.len);
    let ob = "\xac\x09abc";
    let pb, eb = openpgp::next_packet(ob, 0);
    tv::check("old too long", eb == openpgp::ERR_MALFORMED);
    let pz, ez = openpgp::next_packet("\x2c\x00", 0);
    tv::check("bit 7 clear", ez == openpgp::ERR_MALFORMED);
    // Partial lengths: 512 (0xE9), then 1 (0xE0), then a last length of 3.
    var part: u8[>..] = [];
    part.push(0xCB);
    part.push(0xE9);
    for i in 512 { part.push('a'); }
    part.push(0xE0);
    part.push('b');
    part.push(3);
    part.append("cde");
    let pp, ep = openpgp::next_packet(part, 0);
    tv::check("partial", ep == openpgp::OK && pp.partial && pp.end == part.len);
    var joined: u8[>..] = [];
    openpgp::packet_body(part, pp, joined);
    tv::check("partial joined", joined.len == 516 && joined[511] == 'a' && joined[512..] == "bcde");
    tv::check_int("partial body_len", openpgp::body_len(part, pp), 516);
    // A partial length on a packet that may not have one, or with its last
    // part missing.
    var bad: u8[>..] = [];
    bad.push(0xC2);
    bad.push(0xE0);
    bad.push(0);
    bad.push(0);
    let pq, eq = openpgp::next_packet(bad, 0);
    tv::check("partial signature", eq == openpgp::ERR_MALFORMED);
    let pr, er = openpgp::next_packet(part[..519], 0);
    tv::check("partial truncated", er == openpgp::ERR_MALFORMED);
}

fn text() {
    var c: u8[>..] = [];
    openpgp::canonical_text(c, "a\nb\r\nc\rd");
    tv::check("canonical", c[..] == "a\r\nb\r\nc\r\nd");
    c.clear();
    openpgp::canonical_text(c, "a  \nb\t\n c ", true);
    tv::check("canonical stripped", c[..] == "a\r\nb\r\n c");
    var d: u8[>..] = [];
    openpgp::dash_escape(d, "-x\nFrom me\nplain\n");
    tv::check("dash escape", d[..] == "- -x\n- From me\nplain\n");
    var msg: u8[>..] = [];
    msg.append("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256, SHA512\n\n");
    msg.append(d);
    msg.append("-----BEGIN PGP SIGNATURE-----\n\nwsA=\n-----END PGP SIGNATURE-----\n");
    var ct = openpgp::Cleartext { .. };
    let e = openpgp::parse_cleartext(msg, ct);
    tv::check("cleartext", e == openpgp::OK && ct.text[..] == "-x\r\nFrom me\r\nplain" && ct.hashes.len == 2
              && ct.hashes[0] == openpgp::HASH_SHA256 && ct.hashes[1] == openpgp::HASH_SHA512 && ct.sigs[..] == "\xc2\xc0");
    var back: u8[>..] = [];
    openpgp::cleartext_body(back, ct);
    tv::check("cleartext body", back[..] == "-x\nFrom me\nplain\n");
    var ct2 = openpgp::Cleartext { .. };
    tv::check("cleartext no signature", openpgp::parse_cleartext(msg[..find(msg, "-----BEGIN PGP SIGNATURE")], ct2) == openpgp::ERR_MALFORMED);
    var ct3 = openpgp::Cleartext { .. };
    var badhash: u8[>..] = [];
    badhash.append("-----BEGIN PGP SIGNED MESSAGE-----\nHash: WHIRLPOOL\n\nx\n-----BEGIN PGP SIGNATURE-----\n\nwsA=\n-----END PGP SIGNATURE-----\n");
    tv::check("cleartext unknown hash", openpgp::parse_cleartext(badhash, ct3) == openpgp::ERR_UNSUPPORTED);
}

fn mpi() {
    var out: u8[>..] = [];
    openpgp::put_mpi(out, "\x00\x00\x01\xff");
    tv::check("mpi bits", out[..] == "\x00\x09\x01\xff");
    let s, e, n, ok = openpgp::read_mpi(out, 0);
    tv::check("mpi read", ok && s == 2 && e == 4 && n == 4);
    let s2, e2, n2, ok2 = openpgp::read_mpi("\x01\x00\x01", 0);
    tv::check("mpi short", !ok2);
    out.clear();
    openpgp::put_mpi(out, "");
    tv::check("mpi zero", out[..] == "\x00\x00");
}

fn main() {
    crc();
    armor();
    packets();
    text();
    mpi();
    tv::done("framing");
}
