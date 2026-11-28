# hex

Bytes as hexadecimal text and back, as Go's encoding/hex: two digits for
each byte, high nibble first (RFC 4648 §8's base16, written in either
case), and a dump in `hexdump -C`'s layout. Digests, keys, test vectors,
fingerprints and protocol traces are all shown and read this way; before
this package, gslib's libraries each carried their own copy.

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.encoding.hex;
import gslib.entropy;

fn main() {
    var key: u8[32] = [0; 32];
    entropy::random_bytes(key);
    var shown: u8[>..] = [];
    hex::encode_ct(shown, key);                // a secret: constant time
    print("key: ", shown);                     // print alone would write the raw bytes

    var bytes: u8[>..] = [];
    if !hex::decode(bytes, "DEADbeef") { abort("not hex"); }

    var d: u8[>..] = [];
    hex::dump(d, bytes);
    write_stdout(d);                           // 00000000  de ad be ef    |....|
}
```

| Function | What |
|---|---|
| `encode(out: u8[>..]&, src: const u8[:])` | Appends two lowercase digits per byte: `"00ff1a"` |
| `encode_upper(out: u8[>..]&, src: const u8[:])` | The same in uppercase: `"00FF1A"` |
| `encode_ct(out: u8[>..]&, src: const u8[:])` | `encode` in constant time at every length: for keys and other secrets |
| `to_str(src: const u8[:]) -> u8[>..]` | The lowercase hex of `src`, returned |
| `decode(out: u8[>..]&, src: const u8[:]) -> bool` | Appends the bytes; false if `src` is not an even number of hex digits, and then `out` is as it was |
| `dump(out: u8[>..]&, src: const u8[:])` | Appends `hexdump -C`'s lines (less its final offset line), as Go's `hex.Dump` |
| `value(c: u8) -> u8` | A digit's value, either case; `hex::INVALID` (255) for anything else |

`decode` is strict, as std's base64 is: digits only, in either case and
mixed, with no spaces, colons or `0x`. A caller that takes fingerprints
like `AB:CD:EF` drops the separators first.

`decode` and `encode_ct` compute the digits rather than look them up in
a table, and `decode` accumulates validity across the input instead of
returning at the first bad character, so neither has an exit or a memory
access chosen by the bytes: the hex of a key takes the same path whatever
the key is. `encode` and `encode_upper` do the same from 16 bytes on;
below that they take each digit from a 16-byte table, which is faster
for a few bytes, so a secret shorter than 16 bytes goes through
`encode_ct`. The long loops are `simd fn`s (goose spec §7.12), as std's
base64 is, which the C compiler vectorizes.

On an M1, against the table-and-push and per-pair loops gslib's libraries
carry (MB/s, `goose build -O2`, clang):

| Bytes | encode, before → after | decode, before → after |
|---|---|---|
| 1 – 15 | 990 – 1,970 → 1 – 5% slower (the same loop and one length test) | 450 – 520 → 1.1 – 3.5× faster |
| 16 | 1,970 → 2,735 (1.4×) | 520 → 2,415 (4.7×) |
| 64 | 1,980 → 10,050 (5.1×) | 500 → 5,965 (12×) |
| 1 KiB | 1,970 → 12,860 (6.5×) | 525 → 7,760 (15×) |
| 64 KiB | 1,985 → 13,870 (7.0×) | 527 → 8,180 (15.5×) |

## Tests

```bash
python3 scripts/run_tests.py            # under the JIT at -O0, -O2 and --debug, plus examples/hex
python3 scripts/run_tests.py --native   # also built with the C compiler
```

The test has RFC 4648 §10's base16 vectors both ways, every byte value
encoded in both cases and decoded back, every length from 0 to 40 through
`encode`, `encode_upper` and `encode_ct` against a plain reference,
every one of the 256 characters checked against a plain reference in both positions of a pair, odd
lengths, separators, `0x` and a bad character after 1999 good ones
refused with `out` untouched, appending to text already there, and
`dump` against `hexdump -C`'s output. The example
(`examples/hex/tour.goose`) shows a nonce, checks a SHA-256 digest against
its published hex, reads a key, and dumps bytes, or a file given as its
argument.
