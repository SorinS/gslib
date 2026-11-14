// openpgp.packet: packet framing (RFC 9580 §4.2): headers in the old and
// the new format, one-, two- and five-octet lengths, partial body lengths
// and the old format's indeterminate length (to the end of the data).
//
//   var at = 0;
//   while at < data.len {
//       let p, err = openpgp::next_packet(data, at);
//       if err != openpgp::OK { break; }
//       var body: u8[>..] = [];
//       openpgp::packet_body(data, p, body);   // partial chunks joined
//       at = p.end;
//   }
//
// Packets are written in the new format with definite lengths.

namespace openpgp;

import std;
import crypto.openpgp;

// Packet tags.
let TAG_PKESK:          i64 = 1;
let TAG_SIGNATURE:      i64 = 2;
let TAG_SKESK:          i64 = 3;
let TAG_ONE_PASS:       i64 = 4;
let TAG_SECRET_KEY:     i64 = 5;
let TAG_PUBLIC_KEY:     i64 = 6;
let TAG_SECRET_SUBKEY:  i64 = 7;
let TAG_COMPRESSED:     i64 = 8;
let TAG_SED:            i64 = 9;     // encrypted without integrity protection
let TAG_MARKER:         i64 = 10;
let TAG_LITERAL:        i64 = 11;
let TAG_TRUST:          i64 = 12;
let TAG_USER_ID:        i64 = 13;
let TAG_PUBLIC_SUBKEY:  i64 = 14;
let TAG_USER_ATTRIBUTE: i64 = 17;
let TAG_SEIPD:          i64 = 18;
let TAG_MDC:            i64 = 19;
let TAG_AEAD:           i64 = 20;    // LibrePGP's OCB Encrypted Data (gpg 2.3 and later)
let TAG_PADDING:        i64 = 21;

fn tag_name(tag: i64) -> const u8[:] {
    if tag == TAG_PKESK { return "public-key encrypted session key"; }
    if tag == TAG_SIGNATURE { return "signature"; }
    if tag == TAG_SKESK { return "symmetric-key encrypted session key"; }
    if tag == TAG_ONE_PASS { return "one-pass signature"; }
    if tag == TAG_SECRET_KEY { return "secret key"; }
    if tag == TAG_PUBLIC_KEY { return "public key"; }
    if tag == TAG_SECRET_SUBKEY { return "secret subkey"; }
    if tag == TAG_COMPRESSED { return "compressed data"; }
    if tag == TAG_SED { return "symmetrically encrypted data"; }
    if tag == TAG_MARKER { return "marker"; }
    if tag == TAG_LITERAL { return "literal data"; }
    if tag == TAG_TRUST { return "trust"; }
    if tag == TAG_USER_ID { return "user ID"; }
    if tag == TAG_PUBLIC_SUBKEY { return "public subkey"; }
    if tag == TAG_USER_ATTRIBUTE { return "user attribute"; }
    if tag == TAG_SEIPD { return "sym. encrypted integrity protected data"; }
    if tag == TAG_MDC { return "modification detection code"; }
    if tag == TAG_AEAD { return "OCB encrypted data"; }
    if tag == TAG_PADDING { return "padding"; }
    return "unknown";
}

// A packet in some data: where its header and body are, and where the next
// packet starts. A body in partial chunks is not contiguous: packet_body
// joins it.
struct Packet {
    tag:           i64  = 0,
    old:           bool = false,     // old-format header
    at:            i64  = 0,         // the header
    body:          i64  = 0,         // the body, or its first chunk
    body_end:      i64  = 0,         // the end of the body, or of its first chunk
    end:           i64  = 0,         // the next packet
    partial:       bool = false,
    indeterminate: bool = false,     // old format, length type 3: to the end of the data
}

// A new-format length at data[at..]: the length, whether it is a partial
// one, and the position after it.
fn new_length(data: const u8[:], at: i64) -> i64, bool, i64, bool {
    if at >= data.len { return 0, false, at, false; }
    let a: i64 = data[at];
    if a < 192 { return a, false, at + 1, true; }
    if a < 224 {
        if at + 2 > data.len { return 0, false, at, false; }
        return ((a - 192) << 8) + data[at + 1] + 192, false, at + 2, true;
    }
    if a == 255 {
        if at + 5 > data.len { return 0, false, at, false; }
        return be32(data, at + 1), false, at + 5, true;
    }
    return 1 << (a & 31), true, at + 1, true;
}

// The packet whose header starts at data[at].
fn next_packet(data: const u8[:], at: i64) -> Packet, i64 {
    var p = Packet { .. };
    p.at = at;
    if at >= data.len { return p, ERR_MALFORMED; }
    let ctb: i64 = data[at];
    if ctb & 0x80 == 0 { return p, ERR_MALFORMED; }
    if ctb & 0x40 == 0 {
        p.old = true;
        p.tag = (ctb >> 2) & 15;
        let lt = ctb & 3;
        var len: i64 = 0;
        var h = at + 1;
        if lt == 0 {
            if h + 1 > data.len { return p, ERR_MALFORMED; }
            len = data[h];
            h += 1;
        } else if lt == 1 {
            if h + 2 > data.len { return p, ERR_MALFORMED; }
            len = be16(data, h);
            h += 2;
        } else if lt == 2 {
            if h + 4 > data.len { return p, ERR_MALFORMED; }
            len = be32(data, h);
            h += 4;
        } else {
            p.indeterminate = true;
            len = data.len - h;
        }
        if len > data.len - h { return p, ERR_MALFORMED; }
        p.body = h;
        p.body_end = h + len;
        p.end = h + len;
        return p, OK;
    }
    p.tag = ctb & 63;
    let len, partial, h, ok = new_length(data, at + 1);
    if !ok || len > data.len - h { return p, ERR_MALFORMED; }
    p.body = h;
    p.body_end = h + len;
    p.partial = partial;
    if !partial {
        p.end = h + len;
        return p, OK;
    }
    // Only data packets may be partial (§4.2.1.4).
    if p.tag != TAG_LITERAL && p.tag != TAG_COMPRESSED && p.tag != TAG_SED && p.tag != TAG_SEIPD && p.tag != TAG_AEAD {
        return p, ERR_MALFORMED;
    }
    var q = h + len;
    loop {
        let l2, part2, h2, ok2 = new_length(data, q);
        if !ok2 || l2 > data.len - h2 { return p, ERR_MALFORMED; }
        q = h2 + l2;
        if !part2 { break; }
    }
    p.end = q;
    return p, OK;
}

// The body of a packet, its partial chunks joined, appended to out.
fn packet_body(data: const u8[:], p: const Packet&, out: u8[>..]&) {
    out.append(data[p.body..p.body_end]);
    if !p.partial { return; }
    var q = p.body_end;
    while q < p.end {
        let l, part, h, ok = new_length(data, q);
        out.append(data[h..h + l]);
        q = h + l;
    }
}

// The body's length, partial chunks summed.
fn body_len(data: const u8[:], p: const Packet&) -> i64 {
    var n = p.body_end - p.body;
    if !p.partial { return n; }
    var q = p.body_end;
    while q < p.end {
        let l, part, h, ok = new_length(data, q);
        n += l;
        q = h + l;
    }
    return n;
}

// A new-format header for a body of len octets.
fn put_header(out: u8[>..]&, tag: i64, len: i64) {
    out.push((0xC0 | tag) as! u8);
    if len < 192 {
        out.push(len as! u8);
    } else if len < 8384 {
        let l = len - 192;
        out.push(((l >> 8) + 192) as! u8);
        out.push((l & 255) as! u8);
    } else {
        out.push(255);
        put32(out, len);
    }
}

// An old-format header, as gpg writes key, user ID and signature packets
// (tags below 16): the shortest of the 1, 2 and 4-octet lengths.
fn put_old_header(out: u8[>..]&, tag: i64, len: i64) {
    assert(tag < 16);
    if len < 256 {
        out.push((0x80 | tag << 2) as! u8);
        out.push(len as! u8);
    } else if len < 65536 {
        out.push((0x81 | tag << 2) as! u8);
        put16(out, len);
    } else {
        out.push((0x82 | tag << 2) as! u8);
        put32(out, len);
    }
}

fn put_old_packet(out: u8[>..]&, tag: i64, body: const u8[:]) {
    put_old_header(out, tag, body.len);
    out.append(body);
}

fn put_packet(out: u8[>..]&, tag: i64, body: const u8[:]) {
    put_header(out, tag, body.len);
    out.append(body);
}

// The packet that starts at out[mark] with its body already written after
// a placeholder: the header put in front of it. For building a body in
// place: let mark = out.len; ...body...; wrap_packet(out, mark, tag).
fn wrap_packet(out: u8[>..]&, mark: i64, tag: i64) {
    var body: u8[>..] = [];
    body.append(out[mark..]);
    out.resize(mark);
    put_packet(out, tag, body);
}
