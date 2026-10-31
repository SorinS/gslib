# asn1

ASN.1 DER (X.690) for the Goose language: a strict reader that never
copies, typed decoders, a writer, PEM, and a dump. It has no dependencies.
It is the base of [x509](../x509goose.git), and works as well for keys,
CSRs, CMS or anything else in DER.

```goose
import asn1 from "../asn1goose.git";

let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
for der in ders {
    let cert, okc = asn1::parse(der);                    // the one element filling der
    let parts, okp = asn1::children_of(der, cert, asn1::SEQUENCE);
    let tbs = parts[0];                                  // offsets into der
    let fields, okf = asn1::children(der, tbs);
    let serial, oks = asn1::read_uint(der, fields[1]);
    ...
}
```

## Reading

An element is a `Tlv`: its tag, class, constructed flag and number, plus
the offsets of its header (`start`), content (`off`) and end (`end`) in
your buffer. `read(buf, at, limit)` reads one element, and `parse(buf)`
reads the element that must fill `buf`. `children(buf, t)` and
`children_of(buf, t, tag)` return what a constructed element holds, which
must fill it exactly. `explicit(buf, t)` unwraps an EXPLICIT tag. Tags
compare as `t.tag == asn1::SEQUENCE`, or `asn1::ctx(0, true)` for `[0]`.

The reader refuses BER: indefinite lengths, lengths longer than needed,
lengths past the parent, trailing bytes, and high tag numbers that are
padded or below 31.

For a protocol that sends BER, as LDAP does (RFC 4511 §5.1), `read`,
`parse`, `children`, `children_of`, `explicit`, `read_bool` and
`read_i64` take `ber = true`: lengths in more octets than they need
(Active Directory's `84 00 00 00 nn`), any nonzero BOOLEAN as true,
integers with redundant leading octets. Lengths stay definite, and
`read_bool(buf, t, true, tag)` reads an IMPLICIT one.

| Reader | Gives | Refuses |
|---|---|---|
| `read_bool` | `bool` | anything but 00 and ff |
| `read_i64(buf, t, tag = INTEGER)` | `i64`, also for ENUMERATED | non-minimal, more than 8 bytes |
| `read_uint` | magnitude bytes, no sign octet | negative, non-minimal |
| `read_int_bytes` | two's-complement content | non-minimal |
| `read_bits` | bytes, unused-bit count | unused bits > 7 or not zero |
| `read_octets`, `read_null` | | |
| `read_oid` | dotted text, arcs up to 2^64 − 1 | padded or unfinished arcs, overflow |
| `oid_is(buf, t, "1.2.840...")` | whether t is that OID | |
| `read_time` | seconds since 1970 | anything but RFC 5280's UTCTime (1950–2049) and GeneralizedTime: Z, seconds, no fractions, real dates |
| `read_string` | UTF-8 | invalid UTF-8; PrintableString, IA5String and VisibleString outside their sets; bad BMPString (UCS-2) and UniversalString (UCS-4) |

T61String is read as Latin-1, as most decoders do. PrintableString also
accepts `*` and `&`, which are outside its set but common in real names.

## Writing

The writer appends to a `u8[>..]`. `put_header(out, tag, len)` and
`put(out, tag, content)` are the base. On top of them: `put_bool`,
`put_null`, `put_i64(out, v, tag = INTEGER)`, `put_uint(out, magnitude)`,
`put_bits(out, bytes, unused = 0)`, `put_octets`, `put_oid(out, "1.2.3")`,
`put_utf8_string`, `put_printable`, `put_ia5`, and `put_time(out, unix)`
(UTCTime through 2049, GeneralizedTime after, as RFC 5280 asks). Build a
SEQUENCE by writing its content into a buffer of its own, then
`put(out, asn1::SEQUENCE, content)`. `oid_encode` returns an OID's content
octets.

## PEM and dumps

`pem_decode(text, label)` returns the DER of every block with that label,
or of every block when the label is `""`. The result can be iterated but
not indexed, since its elements have variable sizes. `pem_encode(out,
label, der)` writes a block. `dump(der)` prints one line per element, as
`openssl asn1parse -i` does: offset, depth, header length, content length,
`cons` or `prim`, and class:number.

## Tests

```bash
python3 scripts/run_tests.py [--native]
python3 scripts/gen_vectors.py          # regenerate vectors/der.txt with openssl
```

- `der_vectors`: 11 documents made by openssl (certificates with RSA,
  P-256, P-384 and Ed25519 keys and many extensions, PKCS #8 and SEC 1
  keys, a CSR, and an `asn1parse -genconf` document of the rarer types).
  Each must dump exactly as `openssl asn1parse` parses it. Each integer,
  OID, time and string must decode to openssl's (or Python's) value and
  re-encode to the same bytes. Each document must survive PEM and back.
- `der_reject`: BER framing, non-minimal identifiers, integers and OIDs,
  bad booleans and bit strings, impossible times, strings outside their
  sets, the writer's edge values, and PEM errors.
- `ber`: the same kinds of BER read with `ber`, and refused without it;
  indefinite lengths, lengths past the end and trailing bytes refused
  either way.
