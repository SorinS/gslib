// der_record: writes a record in DER and reads it back field by field.
// The record, in ASN.1:
//
//   Record ::= SEQUENCE {
//       version   INTEGER,
//       kind      OBJECT IDENTIFIER,
//       name      UTF8String,
//       serial    INTEGER,                 -- big, unsigned
//       issued    UTCTime,
//       usage     BIT STRING,
//       payload   OCTET STRING,
//       critical  [0] EXPLICIT BOOLEAN,
//       note      [1] IMPLICIT IA5String OPTIONAL }
//
// A SEQUENCE is written by building its content in a buffer of its own and
// wrapping it; reading gives offsets into the buffer, and the typed
// readers decode a field when asked.
//
//   goose examples/asn1/der_record.goose

import std;
import gslib from "../..";
import gslib.encoding.asn1;

fn main() {
    let serial:  u8[] = [0x8f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];  // top bit set: needs a 00
    let payload: u8[] = [0xde, 0xad, 0xbe, 0xef];
    let issued:  i64  = 1700000000;                 // 2023-11-14 22:13:20 UTC

    // Write.
    var body: u8[>..] = [];
    asn1::put_i64(body, 2);
    asn1::put_oid(body, "1.3.6.1.4.1.99999.1");
    asn1::put_utf8_string(body, "Zoë's record");
    asn1::put_uint(body, serial);
    asn1::put_time(body, issued);
    asn1::put_bits(body, [0xa0], 5);                // bits 0 and 2 of 3
    asn1::put_octets(body, payload);
    var crit: u8[>..] = [];
    asn1::put_bool(crit, true);
    asn1::put(body, asn1::ctx(0, true), crit);      // [0] EXPLICIT: a wrapper around a BOOLEAN
    asn1::put(body, asn1::ctx(1, false), "keep me"); // [1] IMPLICIT: the IA5String's tag replaced
    var der: u8[>..] = [];
    asn1::put(der, asn1::SEQUENCE, body);

    // The layout, as `openssl asn1parse -i` would show it.
    let d, okd = asn1::dump(der);
    guard okd else { print("der_record: dump failed"); exit(1); }
    print(der.len, " bytes:");
    print(d[..d.len - 1]);

    // Read.
    let top, ok = asn1::parse(der);
    let f, okf = asn1::children_of(der, top, asn1::SEQUENCE);
    guard ok && okf && f.len >= 8 else { print("der_record: not a Record"); exit(1); }
    let version, ok0 = asn1::read_i64(der, f[0]);
    let kind, ok1 = asn1::read_oid(der, f[1]);
    let name, ok2 = asn1::read_string(der, f[2]);
    let ser, ok3 = asn1::read_uint(der, f[3]);
    let when, ok4 = asn1::read_time(der, f[4]);
    let bits, unused, ok5 = asn1::read_bits(der, f[5]);
    let data, ok6 = asn1::read_octets(der, f[6]);
    guard ok0 && ok1 && ok2 && ok3 && ok4 && ok5 && ok6 else { print("der_record: a field did not decode"); exit(1); }
    guard f[7].tag == asn1::ctx(0, true) else { print("der_record: no [0]"); exit(1); }
    let inner, ok7 = asn1::explicit(der, f[7]);
    let critical, ok8 = asn1::read_bool(der, inner);
    guard ok7 && ok8 else { print("der_record: bad [0]"); exit(1); }

    // The optional [1]: present when the next element has its tag.
    var note: u8[>..] = [];
    if f.len > 8 && f[8].tag == asn1::ctx(1, false) { note.append(der[f[8].off..f[8].end]); }

    print("version ", version, ", kind ", kind, ", name ", name);
    print("serial ", ser.len, " bytes, issued ", when, ", usage bits 0,1,2 = ",
          asn1::bit(bits, 0), ",", asn1::bit(bits, 1), ",", asn1::bit(bits, 2));
    print("payload ", data.len, " bytes, critical ", critical, ", note ", note);
    guard version == 2 && kind == "1.3.6.1.4.1.99999.1" && name == "Zoë's record" && ser[..] == serial[..]
          && when == issued && unused == 5 && asn1::bit(bits, 0) && !asn1::bit(bits, 1) && asn1::bit(bits, 2)
          && data[..] == payload[..] && critical && note == "keep me"
    else { print("der_record: the round trip failed"); exit(1); }
    guard asn1::oid_is(der, f[1], "1.3.6.1.4.1.99999.1") else { print("der_record: oid_is"); exit(1); }

    // DER is strict: a trailing byte, or a length in more octets than it
    // needs, is refused.
    var trailing: u8[>..] = [];
    trailing.append(der);
    trailing.push(0);
    let t1, bad1 = asn1::parse(trailing);
    var padded: u8[>..] = [0x30, 0x81, 0x03, 0x02, 0x01, 0x07];   // 81 03: a long form for 3
    let t2, bad2 = asn1::parse(padded);
    guard !bad1 && !bad2 else { print("der_record: accepted what DER refuses"); exit(1); }
    print("read back whole; trailing bytes and padded lengths refused");
}
