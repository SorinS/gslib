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
| `compress.xz` | xz, LZMA2, .lzma (checks, BCJ and Delta filters) | yes | yes |
| `compress.zip` | zip archives (ZIP64, data descriptors, Go's checks) | yes | yes |
| `compress.tar` | tar archives (USTAR, PAX, GNU, sparse) | yes | yes |

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

## compress.xz (and lzma.goose)

```goose
var d = compress::xz_reader();            // lzma_reader() for .lzma, lzma2_reader(dict_size) for raw LZMA2
let used, made, st = compress::xz_read(d, input, out);
compress::xz_done(d)  /  compress::xz_finish(d)
compress::xz_set_memlimit(d, 1 << 30);    // default XZ_DEFAULT_MEMLIMIT, 256 MiB of dictionary
compress::xz_set_single_stream(d, true);  // stop after the first stream (xz --single-stream)
compress::xz_decode(data, out, limit)     // a whole .xz file, any number of streams; lzma_decode for .lzma

var w = compress::xz_writer(6);           // xz_writer_opts(level, check, block_size, filter, opt)
compress::xz_write(w, data, out);  compress::xz_flush(w, out);  compress::xz_close(w, out);
compress::xz_encode(data, out, 6)         // lzma_encode (.lzma, size in the header), lzma2_encode (raw)
compress::lzma_writer(level, size)        // -1: unknown size, ended by the end marker
```

**Reading** follows the .xz format 1.2.1 and liblzma's checks: stream
header and footer (flags, CRC-32, backward size), block headers (sizes,
filter flags, reserved bits, padding, CRC-32), block padding, the index
(records against the blocks decoded, padding, CRC-32), several streams with
stream padding. It verifies the None, CRC-32, CRC-64 and SHA-256 checks
(SHA-256 is implemented in the module); reserved check IDs are decoded
without verification, as xz does (`xz_check_unverified`). LZMA2's chunk
rules (dictionary and state resets, new properties, uncompressed chunks, a
chunk that must end exactly with its compressed size). Filters: Delta and
the x86, PowerPC, IA-64, ARM, ARM-Thumb, SPARC and ARM64 BCJ converters, up
to four in a chain. .lzma: known size (an end marker after it allowed) or
unknown (end marker required), lc + lp <= 4 as liblzma requires. State:
about 80 KB, plus the dictionary, grown as output is made up to the
declared size; above the memory limit is `ERR_LIMIT`.

**Writing**: levels 0-9 are xz's presets: 0-3 liblzma's fast mode (HC4
match finder), 4-9 its normal mode (BT4 binary tree and the price-driven
optimal parse), with xz's dictionary sizes (256 KiB to 64 MiB), nice
lengths and depths. LZMA2 chunks of up to 2 MiB in; chunks that do not
compress are written uncompressed. Checks None/CRC-32/CRC-64
(default)/SHA-256, optional block size, one optional Delta or BCJ filter;
a flush ends the LZMA2 chunk so everything so far decodes. Memory is about
xz's (some 650 MB for `xz_writer(9)`; `xz_encode` sizes the dictionary to
the input). On a 6.6 MB source tar: level 1 2,614,332 bytes (xz -1:
2,598,924), level 6 2,237,520 (xz -6: 2,235,036), about 1.7x xz's
single-threaded time at -6; decoding about 2.2x xz's time.

Departures from xz/liblzma: .lzma headers are read as liblzma's .lzma
decoder reads them (the xz command line also refuses dictionary sizes that
are not 2^n or 2^n + 2^(n-1), and known sizes of 2^38 or more); a 256 MiB
default dictionary limit (liblzma has none); bytes after a .lzma stream or
a single stream are not taken, and garbage after an .xz stream is
`ERR_TRAILING` (xz: data error; Python ignores it); blocks are checked
against the index by counts, sums and a CRC-64 hash of the records rather
than liblzma's SHA-256; normal-mode chunks end at 40 KiB of output
(liblzma: about 60 KiB); a flush leaves a BCJ filter's last few
unconverted bytes until more input or the end. Not done: the RISC-V BCJ
filter (`ERR_UNSUPPORTED`), more than one filter when writing,
multithreaded compression, faster range decoding.

Tests: `test/xz.goose` decodes xz Utils' own test files (tests/files,
public domain), good, bad and unsupported, plus .lzma and raw LZMA2
files, whole and a byte at a time, against what xz makes of them
(`test/vectors/xz/expect.txt`), and SHA-256 against FIPS vectors.
`test/lzma.goose` writes at every level, check, block size and filter,
with flushes and pieces, and reads it back. `python3
scripts/xz_differential.py [--count N] [--seed N]`: streams from Python's
lzma and the xz CLI (presets 0-9 and -e, lc/lp/pb, filter chains, several
blocks and streams, .lzma, raw LZMA2, about 30% corrupted), fed from 1 byte
in and 1 byte of room, against `xz -dc`: about 23,500 cases over 10 seeds,
0 differ. `--encode`: about 10,000 of our streams (every level, check,
block size, filter and flush pattern, inputs to 5 MB) read back by
`xz -dc`, Python and us: 0 failures; sizes 100.0% of xz's at -1 and -6.

## compress.zip

Go's archive/zip, both ways. The reader takes the whole archive in memory
(`zip_open`), or only its end (`zip_open_tail(tail, size)`: when the
directory starts earlier, `r.err` is `ERR_TRUNCATED` and `r.need` says
where the tail must start), and keeps one fixed-size record a file, its
name, extra field and comment as positions into the caller's buffer.

```goose
var r = compress::zip_open(archive);            // zip_open(archive, true): GODEBUG=zipinsecurepath=0
for e in r.entries {
    let name = compress::zip_name(r, archive, e);    // e.method, e.modified, e.crc32, sizes, ...
    compress::zip_mode(r, archive, e)                // Go's Mode(): fs.FileMode bits
    var f = compress::zip_file_open(r, archive, e);  // f.err: Go's Open error
    let made, st = compress::zip_file_read_mem(f, archive, r, out);  // STREAM_END: checked
}
compress::zip_extract(r, archive, e, out, limit)
// archive not in memory: zip_file_start(e, local_header, name), zip_file_read(f, input, out)

var w = compress::zip_writer();
compress::zip_create(w, "a.txt", out);            // Deflate (level 5, as Go), data descriptor
compress::zip_write(w, data, out);
compress::zip_create_header(w, compress::ZipHeader { name: "b/", modified: t, .. }, out);
compress::zip_create_raw(w, h, out);  compress::zip_copy(w, r, archive, e, out);
compress::zip_set_comment(w, c);  compress::zip_set_offset(w, n);  compress::zip_close(w, out);
```

What Go does, this does: the end record searched in the last 1 KiB and
then 65 KiB; ZIP64 end records and extra fields by Go's rules; the base
offset of an archive with a prefix (self-extracting) and Go's recovery
when the offsets were right after all; the directory read until it ends,
and the count checked as Go checks it (16 bits); Go's detectUTF8 for
NonUTF8 and for the writer's UTF-8 flag; Modified from the MS-DOS fields
and the NTFS, Unix, Info-ZIP and extended-timestamp extra fields, with
Go's time zone inference (`ZipTime` keeps the zone offset); Mode() from
the Unix or MS-DOS attributes; a file's data inflated into the caller's
room and checked at its end (size, data descriptor's CRC, CRC-32);
ErrInsecurePath with the entries kept when the check is on (off by
default, as in Go 1.27; `r.insecure` says either way). The writer writes
Go's bytes: stored archives, raw files, copies and ZIP64 records are
byte-identical to Go's writer's. A `ZipFile` is about 37 KB (an inflater).

Errors: ErrFormat `ERR_FORMAT`, ErrAlgorithm `ERR_UNSUPPORTED`,
ErrChecksum `ERR_CHECKSUM`, ErrInsecurePath `ERR_INSECURE_PATH`,
io.ErrUnexpectedEOF `ERR_TRUNCATED`, io.EOF `ZIP_ERR_EOF` (-100), the
negative-offset ReadAt error `ZIP_ERR_NEG_OFFSET` (-101), flate's
CorruptInputError `ERR_DATA`. Departures: Go's string errors (write to a
directory, closed twice, too long) are `ERR_ARGUMENT`/`ERR_TOO_LARGE`; a
too-long name or extra fails before the file is added (Go adds it first);
`zip_set_offset` after writing is an error where Go panics; paths are
judged as `filepath.IsLocal` does on Unix; Deflate output is not Go's bytes
(the compressor differs; stored archives are identical). Not done: the
fs.FS view (Open by path, ReadDir, duplicate names), registering other
methods (they are `ERR_UNSUPPORTED`), AddFS and FileInfoHeader (no file
system API in Goose's stdlib), the content of the sparse 5 GB goldens (only
their directory and data offsets are read), and Go's
TestBaseOffsetPlusOverflow, whose ReaderAt claims more bytes than it holds
(its data is tested as an ordinary archive).

Tests: `test/zip.goose` reads Go's testdata, its sparse 5 GB ZIP64 goldens
(from their tail) and the archives of Go's regression tests, and compares
everything with Go 1.27.1's reading (test/vectors/zip/go_dump*.txt, from
gooracle zip, path check off and on), through rooms of 64 KiB and 7 bytes;
and ports Go's writer tests (TestWriter, TestWriterCopy, TestWriterOffset,
TestWriterComment, TestWriterUTF8, TestWriterDir, TestWriterDirAttributes,
TestWriterCreateRaw, TestHeaderTooLongErr, TestInsecurePaths,
TestUnderSize, TestOver65kFiles with 65,578 files; TestWriterTime byte for
byte). `python3 scripts/zip_differential.py --count 1000` reads about 3,000
archives (80,000 files: Python's zipfile, the zip CLI, Go's writer and
ours, Go's testdata, corrupted copies of all) with Go and with us, path
check off and on, output rooms of 64 KiB and of 5 bytes: 0 differences
over seeds 2, 3, 4, 5, 7 (with --debug) and 11, every file-level error
class included (algorithm 1,545, format 580, checksum 265, truncated 262,
data 126, eof 22, negative offset 16). 260 of our archives were read back
by Python's zipfile (testzip and every file) and `unzip -t`; 282 were
byte-identical to Go's writer's. Natively, reading runs at about 160 MB/s;
writing at the compressor's speed (about 22 MB/s at level 5); 10,000 small
deflated files in 0.04 s.

## compress.tar

```goose
var r = compress::tar_reader();                 // tar_reader(true): flag insecure paths, as GODEBUG=tarinsecurepath=0
let used, made, st = compress::tar_read(r, input, out);
//   st == compress::TAR_HEADER: compress::tar_header(r) is the next entry; the calls after it
//   write its contents into out (tar_in_entry(r) turns false at the call that ends them;
//   tar_skip(r) passes over them); 0: more input or room; STREAM_END: two zero blocks
compress::tar_finish(r)                         // at the end of the input: STREAM_END or ERR_TRUNCATED
compress::tar_each(data) { h, contents => ... } // a whole archive in memory

var w = compress::tar_writer();
compress::tar_write_header(w, compress::TarHeader { typeflag: '0', name: "a.txt", size: 5, mtime: compress::tar_time(t), .. }, out);
compress::tar_write(w, "hello", out);
compress::tar_close(w, out);
```

Reads V7, USTAR, PAX (local and global headers), GNU (long names and
links, base-256 numbers, atime/ctime, old sparse files with extension
blocks) and star archives, and GNU sparse 0.0, 0.1 and 1.0 in PAX. Sparse
holes read as zeros, and the map is checked as Go checks it
(`TAR_WHY_MISS_DATA`, `TAR_WHY_UNREF_DATA`). A `TarHeader` is Go's Header:
its strings point into the reader, and `pax` holds the PAX records in
PAX's own encoding, sorted, the last of each key (`tar_pax_get`,
`tar_pax_each`, `tar_pax_append`), so Xattrs are the `SCHILY.xattr.*`
records. Results follow Go exactly: headers and formats; ErrHeader,
ErrFieldTooLong (special files over 1 MiB) and errSparseTooLong (2^20
entries, 1 MiB of map), told apart by `tar_why(r)`; an archive may end at a
header, after one zero block, or anywhere in an entry's padding, and
anywhere else is `ERR_TRUNCATED`; a global header is handed out on its own
and not merged into later headers. Memory stays bounded: only the last PAX
header, long name and long link are kept, each at most 1 MiB.

The writer is Go's Writer: it picks USTAR, then PAX, then GNU (or the
format asked for), writes PAX records for long or non-ASCII names, large
numbers and sub-second times (`PaxHeaders.0/…`, keys sorted) and GNU long
names, and with no format asked for rounds times to the second and drops
atime and ctime. Errors (`tar_writer_why`): a header no format can hold
(`ERR_HEADER`), a write past the size (`ERR_TOO_LARGE`), an entry not all
written (`ERR_ARGUMENT`, "missed writing") — none of which stops the
writer, as in Go — and writing after close.

Departures: no separate Xattrs field (they are the `SCHILY.xattr.*` PAX
records, as Go stores them); PAX records are PAX-encoded text rather than a
map; the insecure-path check uses Unix rules only (Go's `filepath.IsLocal`
on Unix) and, as in Go by default (GODEBUG `tarinsecurepath` unset), is off
unless asked for — when on, the header is still handed out and
`tar_insecure_path(r)` says so, as Go returns the header with
ErrInsecurePath; the writer's errors above do not stop it (Go's behaviour,
where the package's other codecs make errors sticky); sparse files are not
written (Go's sparse writer is disabled too); no FileInfoHeader or AddFS.

Tests: `test/tar.goose` reads Go's testdata archives (whole, and in pieces
of 1, 7 and 513 bytes) against Go's recorded results, rebuilds Go's
TestWriter archives byte for byte, and runs Go's strconv tables, the
writer's errors, insecure paths, bounded memory and where an archive may
end. `python3 scripts/tar_differential.py [--count N]` compares against Go
(`gooracle tar`): Go's testdata (decoded from .base64 and .bz2) every way;
thousands of mutated archives; archives made by Python's tarfile, GNU tar
1.33, bsdtar and by hand (every GNU sparse format, valid and invalid maps)
and mutations of them; random headers written by Go's Writer and ours (same
bytes, same results); our archives read and extracted by tarfile, GNU tar
and bsdtar. At `--count 3000`: 13,367 read comparisons, 1,500 written
archives identical to Go's, 750 read by the three other readers, 450
round-trip extractions, 0 failures. Reading a 200 MB archive natively, CRC
included, takes 0.13 s.


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
| `scripts/deflate_differential.py --count N --seed S` | our compressor at every level, raw/zlib/gzip, with dictionaries, written in pieces from 1 byte with flushes: read back exactly by Go, Python's zlib and `gzip -dc`, every flush point decodable, sizes against Go's |
| `scripts/lzw_differential.py --count N --seed S` | encodings byte-identical to Go's Writer; Go's, corrupted and random streams decoded with Go's output and verdict |
| `scripts/bzip2_differential.py --count N --seed S` | streams from Python's bz2 and the bzip2 program (a third corrupted) decoded with Go's verdicts; our streams read by Python, Go and `bzip2 -dc` |
| `scripts/zip_differential.py --count N --seed S` | archives from Python's zipfile, the zip CLI, Go's writer and ours (and corrupted copies) read by Go and by us, path check off and on; ours read by zipfile and `unzip -t`, and byte-identical to Go's where Go's bytes are defined |
| `scripts/xz_differential.py [--encode] --count N --seed S` | streams from Python's lzma and the xz CLI (corrupted too) against `xz -dc`; ours read back by xz, Python and us, sizes against xz |
| `scripts/tar_differential.py --count N --seed S` | Go's testdata, mutated archives, archives from Python's tarfile, GNU tar, bsdtar and hand-built sparse ones, read by Go and by us; random headers written by Go's Writer and ours (identical bytes); ours read and extracted by tarfile, GNU tar and bsdtar |

Results (macOS, arm64). Every `test/*.goose` passes at -O0, -O2, --debug
and native. Independent reruns at fresh seeds after each module landed:
lzw seed 77 (3,000 encodings, 9,108 decodings, 0 mismatches), bzip2 seed 78
(3,001 streams, 0 differ from Go; 750 encodings, 0 failures), tar seed 79
(9,007 read comparisons, 1,000 written archives identical to Go's, 0
failures), zip seed 81 (1,559 archives three ways, 0 differ; 139 written
byte-identical to Go's). The per-module sections give the full numbers.

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

* zip: the fs.FS view (Open by path, ReadDir, duplicate names), registering
  other compression methods, AddFS/FileInfoHeader (Goose's stdlib has no
  file-system API to build them on).
* tar: writing sparse files (Go's sparse writer is disabled too),
  FileInfoHeader; the insecure-path checks use Unix path rules only.
* xz: the RISC-V BCJ filter, more than one filter when writing,
  multithreaded compression.
* bzip2: multithreaded compression; recovering after a bad block.
* deflate: Go's exact bytes (not promised by Go); level 9 is about 3% larger
  than Go 1.27's on synthetic data (zlib's matcher, not Go's).
* Testing on Linux and Windows: everything here ran on macOS (arm64).

## Credits

The inflate began as `http/flate.goose` of gslib.git (and httpgoose.git):
its fixed-size streaming design, gzip header handling, tests and
differential script.
