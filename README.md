# compressgoose

Compression formats and archives for Goose, after Go's `compress/*` and
`archive/*` packages, plus xz. Pure Goose: no C, and no files read or
written by the package itself — everything works on buffers the caller
owns, fed as the data comes.

| Module | What | Read | Write |
|---|---|---|---|
| `compress` | result codes, CRC-32, Adler-32, CRC-64 | | |
| `compress.flate` | raw DEFLATE (RFC 1951) | yes | |
| `compress.deflate` | DEFLATE compression, levels -2 (HuffmanOnly) to 9 | | yes |
| `compress.gzip` | gzip (RFC 1952), header fields, several members | yes | yes |
| `compress.zlib` | zlib (RFC 1950), preset dictionaries | yes | yes |
| `compress.lzw` | Go's compress/lzw (GIF, TIFF and PDF orders) | yes | yes |
| `compress.bzip2` | bzip2 | yes | yes |
| `compress.xz` | xz, LZMA2, .lzma | (pending) | (pending) |
| `compress.zip` | zip archives | (pending) | (pending) |
| `compress.tar` | tar archives | (pending) | (pending) |

```goose
import compress from "../compressgoose.git";
import compress.gzip;

var out: u8[>..] = [];
compress::gzip_encode(data, out, 6);            // whole buffers
var back: u8[>..] = [];
let e = compress::gzip_decode(out, back, 1 << 30);   // 0, or compress::ERR_* (< 0)
```

## API conventions

Every module is in namespace `compress`, so names carry their format:
`compress::gzip_reader`, `compress::tar_next`, ...

* **Results.** A step returns `0` when it needs more input or more room
  for output, `compress::STREAM_END` (1) when the stream is complete, and
  a negative `compress::ERR_*` code otherwise (`compress::error_text`):
  `ERR_HEADER`, `ERR_DATA`, `ERR_CHECKSUM`, `ERR_TRAILING`,
  `ERR_DICTIONARY`, `ERR_UNSUPPORTED`, `ERR_LIMIT`, `ERR_TRUNCATED`,
  `ERR_ARGUMENT`, `ERR_INSECURE_PATH`, `ERR_FORMAT`, `ERR_TOO_LARGE`.
  After an error a codec takes nothing more; what it decoded before the
  error is handed out first, as Go's readers do, and then the error.
* **Decoders** keep state of a fixed size, fed by the caller:
  `let used, made, st = compress::X_read(d, input, out);` takes what it can
  of `input` and writes at most `out.len` bytes into `out`. A call with
  input left and room in `out` always makes progress. At the end of its
  input the caller asks `compress::X_done(d)` (or `X_finish(d)` for the
  error Go would give there; the whole-buffer helpers return
  `ERR_TRUNCATED`).
* **Encoders** append to a builder the caller owns:
  `compress::X_write(w, input, out)`, `X_flush(w, out)`, `X_close(w, out)`.
* **Whole buffers**: `compress::X_decode(data, out, limit)` and
  `compress::X_encode(data, out, ...)` for when everything is in memory;
  `limit` caps the output (`ERR_LIMIT`), < 0 for none.
* **Memory** is bounded by the state's size (plus, for xz, a dictionary
  capped by a limit the caller can set); output is bounded by the room the
  caller gives, so a decompression bomb costs only what the caller lets it.

## compress.flate and compress.deflate

```goose
var d = compress::inflate_reader();                 // raw DEFLATE; inflate_set_dictionary(d, dict)
let used, made, st = compress::inflate_read(d, input, out);
compress::inflate_done(d)
compress::inflate_decode(data, out, limit)          // 0, ERR_TRUNCATED, ERR_DATA, ERR_LIMIT

var w = compress::deflate_writer(6);                // or deflate_writer_dict(level, dict)
compress::deflate_write(w, data, out);
compress::deflate_flush(w, out);                    // Go's Flush: 00 00 ff ff, all so far decodable
compress::deflate_close(w, out);
compress::deflate_reset(w);
compress::deflate_encode(data, out, level)
```

**Inflate** started from gslib.git's `http/flate.goose`, a fixed-size
streaming decoder, and is now zlib's state machine: a 64-bit bit buffer
that takes input a byte at a time only as a step needs it (so it stops
exactly at the end of the stream, and bytes after it are not taken),
512-entry lookup tables for codes of up to 9 bits with canonical decoding
of the rarer longer ones, and output through the caller's room from a
32 KiB window (some 37 KB of state in all). It refuses what Go refuses:
reserved block types, LEN/NLEN mismatches, more than 286/30 codes,
incomplete or over-subscribed codes (except a single one-bit code, as Go
and zlib allow), repeats with nothing to repeat or past the end, length
symbols 286-287 and distance symbols 30-31, distances before the start of
the output or dictionary. It hands out exactly what Go hands out before an
error or the end of the input, down to Go's habit of reading the
end-of-block code's length ahead of each symbol.

**Deflate** is zlib's matcher: a 64 KiB window, hash chains over 3-byte
strings, greedy matching for levels 1-3 and lazy matching for 4-9 with
zlib's limits per level (good, lazy, nice, chain); level 0 writes stored
blocks, -2 (HuffmanOnly) literals only. Blocks of up to 16,383 tokens are
written stored, with the fixed codes or with their own, whichever is
smallest; codes are optimal (Moffat and Katajainen) and then limited to 15
bits (7 for the code length code) as miniz does, and every code written is
complete. About 390 KB of state. Go makes no promise about its exact bytes
and neither does this; sizes against Go's own are below.

## compress.gzip and compress.zlib

```goose
var r = compress::gzip_reader();                    // gzip_set_multistream(r, false) for one member
let used, made, st = compress::gzip_read(r, input, out);   // STREAM_END at a member's end
compress::gzip_finish(r)                            // at the end of the input: 0 or Go's error
r.name, r.comment, r.extra, r.mtime, r.os, r.xfl    // the first member's header, as in the file
compress::gzip_latin1_to_utf8(r.name, out)          // as Go's Header.Name
compress::gzip_decode(data, out, limit)

var w = compress::gzip_writer(level);
compress::gzip_write_header(w, out, name, comment, extra, mtime, os);   // optional, before writing
compress::gzip_write(w, data, out);  compress::gzip_flush(w, out);  compress::gzip_close(w, out);

var z = compress::zlib_reader();                    // zlib_reader_dict(dict)
let used, made, st = compress::zlib_read(z, input, out);
compress::zlib_writer(level), zlib_writer_dict(level, dict), zlib_write, zlib_flush, zlib_close
compress::zlib_decode(data, out, limit), zlib_decode_dict(data, dict, out, limit), zlib_encode(data, out, level)
```

As Go: gzip members follow one another until the input ends; after a
member, ten bytes that are not a header are `ERR_HEADER` and fewer are
`ERR_TRUNCATED` (Go reads ten first); names and comments of 512 bytes or
more with their NUL are `ERR_HEADER` (Go's buffer); reserved flag bits and
XFL are ignored; FHCRC is checked. The writer writes Go's header (OS 255,
XFL 2 at level 9 and 4 at level 1), converts the name and comment to
Latin-1 and refuses what is not Latin-1 or holds a NUL (`ERR_ARGUMENT`).
zlib: a header with a method other than 8, a window over 32 KiB or bad
check bits is `ERR_HEADER`; a stream that names a dictionary is
`ERR_DICTIONARY` unless the one given has its Adler-32; bytes after the
stream are left alone; the writer's FLEVEL is Go's for each level.

The gzip reader is about 103 KB, most of it room for the first member's
FEXTRA (up to 65,535 bytes, which Go returns whole).

## compress.lzw

Go's compress/lzw: the LZW of GIF (`LZW_LSB`) and of TIFF and PDF
(`LZW_MSB`, without TIFF's "early change", as Go), literal widths 2 to 8,
codes up to 12 bits. Decoding follows Go's Reader exactly: the same codes are
invalid (`ERR_DATA`), a full table keeps its width and adds nothing until a
clear code, and the bytes after the end code are left alone. The writer
writes Go's bytes exactly, including the table clear at code 4095.

    var d = compress::lzw_reader(compress::LZW_LSB, 8);
    let used, made, st = compress::lzw_read(d, input, out);   // 0, STREAM_END or an error
    compress::lzw_done(d)                                      // the end code came
    compress::lzw_decode(data, order, width, out, limit)       // 0, ERR_TRUNCATED, ERR_DATA, ERR_LIMIT

    var w = compress::lzw_writer(compress::LZW_MSB, 8);
    compress::lzw_write(w, data, out);    // ERR_ARGUMENT for a byte wider than the literal width
    compress::lzw_close(w, out);
    compress::lzw_encode(data, order, width, out)

States are fixed-size: about 21 KB for the reader, 64 KB for the writer.
Departures: a stream that ends before its end code is `lzw_done` false
(`ERR_TRUNCATED` from `lzw_decode`) rather than an error from the read; Go's
argument errors and its "byte too large" error are all `ERR_ARGUMENT`.

Tests: `test/lzw.goose` (Go's reader and writer tests, a full-table stream,
Go's encodings of 200 KB inputs at widths 8, 4 and 2, round trips at every
order and width, every chunking), and
`python3 scripts/lzw_differential.py --count 3000` against Go 1.27.1:
3000 encodings byte-identical to Go's in pieces of 1 byte up, and about
9000 decodings (Go's streams, corrupted ones, random ones that fill the table)
fed 1 byte at a time into 1 byte of room up, each giving Go's output and
Go's verdict: 0 mismatches. About 100 MB/s to encode and 180 MB/s to
decode, built native.

## compress.bzip2

bzip2 decompression with Go's compress/bzip2 behaviour, and compression
(Go has none) that writes what bzip2 1.0 writes.

    var d = compress::bzip2_reader();
    let used, made, st = compress::bzip2_read(d, input, out);   // fed any pieces; out is the caller's room
    compress::bzip2_done(d)                                     // ended whole (one or more streams)
    compress::bzip2_decode(data, out, limit)                    // whole buffer: 0, ERR_TRUNCATED, ERR_LIMIT, ...

    var w = compress::bzip2_writer(9);                          // block size 1-9 (x 100 000)
    compress::bzip2_write(w, data, out);  compress::bzip2_flush(w, out);  compress::bzip2_close(w, out);
    compress::bzip2_encode(data, out, 9)

The reader keeps explicit state (a bit buffer, its place in a block's
header, the decoded block), never the input. A block expands into the
caller's room as it is taken, so a block of runs that makes 45 MB costs no
more memory than any other: about 3.7 MB of state in all. Concatenated
streams are read in turn; anything else after a stream is ERR_TRAILING. It
refuses what Go refuses: bad magic or block size, randomised blocks
(ERR_UNSUPPORTED; deprecated, as in Go), no symbols, 2-6 tables, selectors
past the tables, code lengths outside 1-20, unusable Huffman codes, runs
past the block, origPtr past the block, block and stream CRC mismatches.

The writer does bzip2's initial run-length coding, a Burrows-Wheeler
transform by prefix-doubling suffix sorting (O(n log n) on any input,
repetitive or not), MTF with RUNA/RUNB zero runs, and 2-6 Huffman tables
chosen per 50 symbols over four refining passes with bzip2's length-limited
code construction. Its output is byte-identical to bzip2 1.0's in about 97%
of cases and the same size in every case checked; the rest differ only in
the order of equal rotations of periodic data. About 17 MB of state.

Departures from Go: errors are split into ERR_HEADER, ERR_DATA,
ERR_CHECKSUM and ERR_TRAILING where Go has one StructuralError. Huffman
tables that are not complete (bzip2 never writes them) are read as Go reads
them, which differs from libbzip2. Python's bz2 and the bzip2 program then
usually report a CRC error where Go and we decode.

Tests: test/bzip2.goose (Go's reader vectors and testdata, every prefix,
corruptions, byte-exact writer output, round trips at every level);
scripts/bzip2_differential.py (thousands of streams from Python and the
bzip2 program, about a third corrupted, verdicts compared with Go's; our
writer's output read back by Python, Go and bzip2 -dc; --debug builds the
verdict tool with checked arithmetic). Natively, decoding runs about as fast
as the bzip2 program on random data and text, and compressing at -9 within
about 25% of it.

<!-- xz, zip, tar -->

## Tests

    python3 scripts/run_tests.py             # every test/*.goose at -O0, -O2 and --debug
    python3 scripts/run_tests.py --native    # and built with the C compiler

The Go oracle (`tools/gooracle`, Go's own packages run on our inputs; one
subcommand per format) is built by the scripts, or with
`cd tools/gooracle && go build`. Go 1.27.1, Python 3.15.2 and macOS's
command-line tools were the references.

| Script | What it checks |
|---|---|
| `scripts/flate_testdata.py` | every file of Go's `compress/flate/testdata` and `compress/gzip/testdata`, decoded by us and by Go, fed whole, a byte at a time and in pieces: the same output and verdict |
| `scripts/flate_differential.py --count N --seed S` | raw/zlib/gzip streams made by Python's zlib (every level and strategy, small windows, sync and full flushes, dictionaries, gzip header fields long and short, reserved flags, several members), a quarter corrupted, fed 1 byte up into rooms of 1 byte up: output and error class equal to Go's |
| `scripts/deflate_differential.py --count N --seed S` | our compressor at every level, raw/zlib/gzip, with dictionaries, written in pieces from 1 byte with flushes: read back exactly by Go and by Python's zlib, every flush point decodable, sizes against Go's |

Results (macOS, arm64):

* `test/checksum.goose`, `test/flate.goose` (Go's TestStreams, Huffman
  code and truncation tests, the `.golden` streams, Go's gunzipTests and
  zlibTests tables, header fields, errors, a 10 MB bomb through a 4 KB
  buffer), `test/deflate.goose`: pass at -O0, -O2, --debug and native.
* flate_differential: 62,000 streams over 11 seeds (one run of 20,000
  at seed 100), about 1 in 4 refused by Go, some of them the gzip
  program's own output, some noise: 0 differ from Go in output or error
  class (the one deliberate difference, below, is accounted for in the
  script). zlib's own verdict differs from Go's on about 6%: gzip's
  reserved flag bits (Go ignores them), names of 512 bytes or more (Go
  refuses them), and bytes after a gzip stream.
* flate_testdata: 70 files, 0 differ (the `.golden` and `.expect` files
  are Go's bit writer's blocks without a final block: they decode to the
  `.in` file and then end too soon, in Go and here).
* deflate_differential: 21,500 streams over 5 seeds (one run of 10,000 at
  seed 101), 960,000 flush points, 900 streams also read by `gzip -dc`: 0
  failures. Sizes, ours over Go's, per level on the same inputs (no
  flushes), at seed 101: -2 1.002, -1 1.006, 0 1.000, 1 0.903, 2 0.866,
  3 0.912, 4 0.995, 5 1.001, 6 0.993, 7 0.991, 8 1.000, 9 1.030. Go 1.27's
  levels 1-6 are a different design (klauspost's fast encoders) and its
  levels 7-9 look for 4-byte matches; ours is zlib's at every level, and
  within 0.1% of zlib's sizes on text.

Speed, built native (Apple M-series), 3.1 MB of text:

| | ours | zlib (C, via Python) | Go 1.27 |
|---|---|---|---|
| deflate level 1 | 101 MB/s | 119 MB/s | 77 MB/s |
| deflate level 6 | 18 MB/s | 23 MB/s | 73 MB/s |
| deflate level 9 | 8.3 MB/s | 10.3 MB/s | 15.8 MB/s |
| inflate | 280 MB/s | 620 MB/s | 190 MB/s |

## Departures from Go

* Go's gzip.NewReader says io.EOF for no input at all; `gzip_finish` says
  `ERR_TRUNCATED`.
* A dynamic block whose code lengths give the end-of-block symbol no code
  can never end; Go refuses it only when the input runs out, zlib and this
  package when its header is read (`ERR_DATA`).
* Errors are codes, not Go's error values; `CorruptInputError`'s offset is
  not reported.
* Deflate's bytes differ from Go's (Go does not promise them either); see
  the sizes above.

## Not done

* (filled in as the modules land)

## Credits

The inflate began as `http/flate.goose` of gslib.git (and httpgoose.git):
its fixed-size streaming design, gzip header handling, tests and
differential script.
