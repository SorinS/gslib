# mimegoose

MIME for Goose, at parity with Go's `mime`, `mime/quotedprintable` and
`mime/multipart` (Go 1.27.1), and with the part of `net/textproto` they
use (MIME header sections). Nothing here does network I/O: parsers take
bytes, writers append to the caller's builder, and the multipart reader is
fed as its input comes.

| Module | Namespace | What |
|---|---|---|
| `mime` | `mime` | Media types (RFC 2045, 2046, 2183) and their parameters (RFC 2231): `parse_media_type`, `format_media_type`; the error codes all modules share and Go's messages for them; UTF-8 and the Unicode tables Go's functions use |
| `mime.encodedword` | `mime` | RFC 2047 encoded-words: `encode_word` (Go's WordEncoder, B and Q), `decode_word`, `decode_header` (WordDecoder), with a block for other charsets (CharsetReader) |
| `mime.types` | `mime` | `type_by_extension`, `extensions_by_type`, `add_extension_type`: Go's built-in table, then the system's globs2 or mime.types files as Go reads them |
| `mime.quotedprintable` | `quotedprintable` | RFC 2045 §6.7, Go's Reader (fed, or whole) and Writer (Binary mode, 76-byte lines) |
| `mime.textproto` | `textproto` | MIME header sections as `net/textproto` reads them (`ReadMIMEHeader` and its limits), `MIMEHeader`, `CanonicalMIMEHeaderKey` |
| `mime.multipart` | `multipart` | Multipart bodies: a sans-I/O reader with Go's boundary rules (`NextPart`, `NextRawPart`, quoted-printable parts, `FormName`, `FileName`), the writer (`CreatePart`, form fields and files, random boundaries) |
| `mime.formdata` | `multipart` | RFC 7578 forms: `read_form`, Go's `ReadForm` with its limits, spilling large files to temporary files |

The namespaces follow Go's packages, so `mime::parse_media_type`,
`quotedprintable::decode`, `multipart::next`, `textproto::get`.

```goose
import mime from "../mimegoose.git";
import mime.multipart;

let mt = mime::parse_media_type(content_type);       // mt.err, mt.typ, mt.params
if mt.err == 0 && mt.typ == "multipart/form-data" {
    var r = multipart::Reader { .. };
    multipart::init(r, mime::get_or(mt, "boundary"));
    multipart::feed(r, body);            // as the bytes come; any pieces
    multipart::finish(r);                // at the end of the body
    var data: u8[>..] = [];
    loop {
        let ev = multipart::next(r, data);
        if ev == multipart::EV_PART { data.clear(); print(multipart::form_name(r), " ", multipart::file_name(r)); }
        else if ev == multipart::EV_PART_END { print(data.len, " bytes, error ", r.part_err); }
        else if ev == multipart::EV_END { break; }
        else if ev == multipart::EV_ERROR { var m: u8[>..] = []; multipart::message(r, m); print(m); break; }
        else if ev == multipart::EV_NEED_MORE { break; }      // feed more, then call next again
    }
}
```

## API

Errors are codes (`mime::OK` is 0), named after Go's errors
(`mime::ERR_INVALID_MEDIA_PARAMETER`, `mime::ERR_MULTIPART_TOO_LARGE`, ...);
`mime::error_text(code)` is Go's message. Where Go's message carries a
detail (a byte, an offset, a quoted line or charset), the function beside
the one that failed writes the whole message, `%q` included (Go's
`strconv.Quote`, with `strconv.IsPrint`'s table): `word_error`,
`header_error`, `quotedprintable::error_message`, `multipart::message`,
`textproto::error_message`, `add_extension_type_error`.

### mime

```goose
struct Param { name: u8[varint], value: u8[varint] }
struct MediaType { err: i64, typ: u8[varint], params: Param[>..] }   // params sorted by name
struct KV { key: const u8[:], value: const u8[:] }

fn parse_media_type(v: const u8[:]) -> MediaType       // ParseMediaType
fn param(mt: const MediaType&, name: const u8[:]) -> const u8[:], bool
fn get_or(mt: const MediaType&, name: const u8[:]) -> const u8[:]      // params[name]
fn format_media_type(out: u8[>..]&, t: const u8[:], params: const KV[:]) -> bool   // FormatMediaType
fn format_media_type(t: const u8[:], params: const KV[:]) -> u8[>..]                // "" on failure, as Go
fn format_media_type(out: u8[>..]&, t: const u8[:], mt: const MediaType&) -> bool
```

`parse_media_type` returns the type on `ERR_INVALID_MEDIA_PARAMETER`, as
Go's does, and `""` on its other errors; Go's leniencies are kept (MSIE's
unescaped backslashes in quoted strings, trailing semicolons, a repeated
parameter with the same value) and its grammar exactly (Unicode white
space where Go uses `unicode.IsSpace`, Go's `strings.ToLower` of the type,
RFC 2231 continuations and `utf-8`/`us-ascii` values).

### mime.encodedword

```goose
let B_ENCODING: u8 = 'b';    let Q_ENCODING: u8 = 'q';
fn encode_word(out: u8[>..]&, enc: u8, charset: const u8[:], s: const u8[:])   // WordEncoder.Encode
fn encode_word(enc: u8, charset: const u8[:], s: const u8[:]) -> u8[>..]
fn decode_word(out: u8[>..]&, word: const u8[:]) -> i64                       // WordDecoder.Decode
fn decode_header(out: u8[>..]&, header: const u8[:]) -> i64                  // WordDecoder.DecodeHeader
fn decode_word_charset<F>(out: u8[>..]&, word: const u8[:]) -> i64           // with a CharsetReader block
fn decode_header_charset<F>(out: u8[>..]&, header: const u8[:]) -> i64
fn word_error(out: u8[>..]&, word: const u8[:])        // Go's message ("" if none)
fn header_error(out: u8[>..]&, header: const u8[:])
```

UTF-8, ISO-8859-1 and US-ASCII are built in, as in Go; the block is called
for any other charset as `F(charset, content, out) -> code`, with the
charset in lower case (`strings.ToLower`) and the decoded bytes, and
appends their UTF-8 to `out`. On an error `out` is left as it was.

### mime.types

```goose
fn type_by_extension(ext: const u8[:]) -> const u8[:]                 // TypeByExtension
fn extensions_by_type(out: u8[][>..]&, typ: const u8[:]) -> i64       // ExtensionsByType, sorted
fn add_extension_type(ext: const u8[:], typ: const u8[:]) -> i64      // AddExtensionType
fn types_init()                     // what the first lookup does
fn types_reset(with_builtin: bool)  // an empty table, or Go's built-in one only (for tests)
fn load_mime_globs_file(path: const u8[:]) -> bool   fn load_mime_file(path: const u8[:])
```

### mime.quotedprintable

```goose
struct Reader { .. }      fn new_reader() -> Reader
fn decode(r: Reader&, out: u8[>..]&, data: const u8[:]) -> i64     // feed; 0 or the sticky error
fn finish(r: Reader&, out: u8[>..]&, eof: i64 = mime::ERR_EOF) -> i64
fn error_message(r: const Reader&, out: u8[>..]&)
fn decode_all(out: u8[>..]&, src: const u8[:]) -> i64              // io.Copy from NewReader
fn decode_all(out: u8[>..]&, src: const u8[:], msg: u8[>..]&) -> i64
struct Writer { binary: bool = false, .. }      fn new_writer() -> Writer
fn write(w: Writer&, out: u8[>..]&, p: const u8[:])                // Writer.Write
fn close(w: Writer&, out: u8[>..]&)                               // Writer.Close
fn encode_all(out: u8[>..]&, src: const u8[:], binary: bool = false)
```

### mime.textproto

```goose
struct Field { key: u8[varint], value: u8[varint] }
struct Header { fields: Field[>..] }            // MIMEHeader, in arrival order
fn canonical_mime_header_key(out: u8[>..]&, s: const u8[:])   fn canonical_mime_header_key(s) -> u8[>..]
fn get(h, key) -> const u8[:]    fn has(h, key) -> bool    fn each_value<F>(h, key)    fn count_values(h, key) -> i64
fn add(h, key, value)    fn set(h, key, value)    fn del(h, key)    fn key_count(h) -> i64
fn read_mime_header(data: const u8[:], h: Header&) -> i64, i64      // code, bytes read
fn read_mime_header_at(data, pos, eof: bool, max_memory, max_headers, h: Header&, detail: u8[>..]&) -> i64, i64
struct HeaderReader { pos: i64, .. }     fn header_reader(pos, max_memory, max_headers) -> HeaderReader
fn read_mime_header_step(data, hr: HeaderReader&, eof: bool, h: Header&, detail: u8[>..]&,
                         seen: dictionary<u64, bool>&, gate: bool) -> i64
fn error_message(out: u8[>..]&, code: i64, detail: const u8[:])
```

Both answer `NEED_MORE` while `eof` is false and the bytes there do not
yet decide the result as Go's reader would. `read_mime_header_at` reads
from the start each time; `read_mime_header_step` resumes, keeping the
fields read, and with `gate` set tries a field again only when the bytes
that came can decide it: its first line has ended, the byte after its
last line end is not a space or tab, or it has doubled. The multipart
reader runs it that way, so a part whose header fails (a missing colon, a
malformed line, a limit) fails as soon as Go's `NextPart` would, at a
cost in proportion to the input. The test checks that, fed a byte at a
time, both decide at the same byte with the same result.

### mime.multipart and mime.formdata

```goose
root struct Reader { header: textproto::Header, raw: bool, max_header_bytes: i64, max_headers: i64,
                     part_err: i64, part_err_text: u8[>..], err: i64, .. }
fn init(r: Reader&, boundary: const u8[:])            // NewReader
fn feed(r: Reader&, data: const u8[:])     fn finish(r: Reader&)
fn next(r: Reader&, out: u8[>..]&) -> i64             // EV_NEED_MORE, EV_PART, EV_DATA, EV_PART_END, EV_END, EV_ERROR
fn next_part(r: Reader&) -> i64                       // NextPart: past the rest of the current part
fn form_name(r: const Reader&) -> const u8[:]         // Part.FormName
fn file_name(r: const Reader&) -> const u8[:]         // Part.FileName (filepath.Base)
fn message(r: const Reader&, out: u8[>..]&)

struct Writer { .. }    fn new_writer() -> Writer     // a random boundary from getentropy(3)
fn boundary(w) -> const u8[:]    fn set_boundary(w, b) -> i64    fn form_data_content_type(w) -> u8[>..]
fn create_part(w, out, fields: const mime::KV[:])     fn create_part(w, out, h: const textproto::Header&)
fn create_form_file(w, out, fieldname, filename)      fn create_form_field(w, out, fieldname)
fn write_field(w, out, fieldname, value)               fn close(w, out)
fn file_content_disposition(out, fieldname, filename)  // FileContentDisposition

root struct Form { max_parts: i64 = 1000, max_headers: i64 = 10000, tmp_dir: u8[>..], .. }
fn form_init(f: Form&, max_memory: i64)               // ReadForm(maxMemory)'s limits
fn read_form(r: Reader&, f: Form&) -> i64             // NEED_MORE until the body has ended; 0 or an error
fn read_form_bytes(f: Form&, body, boundary, max_memory: i64) -> i64
fn remove_all(f: Form&) -> bool                       // Form.RemoveAll
fn form_value(f, name) -> const u8[:], bool    fn each_form_value<F>(f, name)    fn value_at(f, i) -> name, value
fn form_file(f, name) -> i64    fn file_filename(f, i)    fn file_size(f, i)    fn file_header_get(f, i, key)
fn file_content(f, i, out: u8[>..]&) -> bool          // FileHeader.Open, read whole
```

The writer appends the boundary lines and headers to `out`; the caller
appends each part's body after its `create_*` call.

## Tests

```sh
python3 scripts/run_tests.py [--native]     # every test/*.goose at -O0, -O2 and --debug (and built with cc)
python3 scripts/gen_vectors.py [--check]    # regenerate (or check) test/vectors/go_* from Go's sources
python3 scripts/differential.py -n 1000 --seed 1          # random cases through Go and Goose
python3 scripts/differential.py --kinds alltypes          # every extension and type of the system's tables
goose run test/fuzz.goose -- 100 12345      # 100 times the suite's fuzzing, from seed 12345
python3 scripts/bench.py                    # the same work in Go and Goose, timed
tools/mimeoracle.sh unicode > unicode.goose # regenerate the Unicode tables from Go
tools/mimeoracle.sh types > types_builtin.goose
```

Results (macOS 26 arm64, goose v2026.3-254; Linux Ubuntu 20.04 x86-64,
goose v2026.3-252; Go 1.27.1 on both):

| | |
|---|---|
| `scripts/run_tests.py --native` | 9 programs, 36 runs passed on both systems: mediatype 428 checks, encodedword 195, quotedprintable 983, textproto 645, multipart 288, writer 79, formdata 60, types 91, fuzz 17379 |
| `scripts/differential.py -n 1000` | 21000 cases a run (seeds 1, 2, 21 on macOS, 11 on Linux), 0 differences; every kind: media types, FormatMediaType, encoded-words both ways, DecodeHeader, quoted-printable both ways, header sections with and without limits, multipart bodies, ReadForm, TypeByExtension, ExtensionsByType, FileContentDisposition, SetBoundary |
| `--kinds alltypes` | macOS: 2834 cases (/etc/apache2/mime.types), Linux: 3233 (/usr/share/mime/globs2), 0 differences |
| `goose --debug test/fuzz.goose -- 100 12345` | 1738956 checks, no abort (Linux: `-- 20 777`, 347488) |
| `scripts/bench.py` (macOS, arm64) | multipart reading 4.5 GB/s (Go 3.9-4.2), ReadForm of 1000 fields 0.42 ms (Go 0.94-1.0), quoted-printable encoding 390 MB/s (Go 420), decoding 550 MB/s (Go 230), ParseMediaType 180 ns (Go 290) |

The differential's multipart cases end in every outcome Go has (clean
ends, truncation in a body or a header, each NextPart error, the 4096-byte
line limit, malformed headers, quoted-printable errors, too-large forms
and their limits); the Goose side feeds each body in pseudo-random pieces.

### Go's tests

Go's test tables are read from `$GOROOT/src` by `tools/mimeoracle.sh
vectors` (go/ast; build constraints applied), and every row carries what
Go's function returns for it; `scripts/gen_vectors.py` checks Go's result
against the row's expectation the way Go's test does, and writes
`test/vectors/go_*.txt`. Bodies that Go's test functions build inline and
Go's testdata files are taken the same way. Tables: mediatype_test.go
(consumeToken, consumeValue, consumeMediaParam, parseMediaTypeTests,
badMediaTypeTests, formatTests), encodedword_test.go (all five tables),
type_test.go and type_unix_test.go (all tables, testdata), quotedprintable
(TestReader, testWriter, testMsg), multipart (parseTests,
TestNameAccessors, TestWriterSetBoundary, TestFileContentDisposition,
TestVariousTextLineEndings, TestReadFormLimits, the bodies of
TestMultipart*, TestMultipartTruncated, TestLineContinuation, TestRawPart,
TestQuotedPrintableEncoding, TestMultipartStreamReadahead, ReadForm's
messages, testdata/nested-mime), net/textproto (canonicalHeaderKeyTests,
TestReadMIMEHeaderMalformed and the inputs of every TestReadMIMEHeader*).
The test functions' logic is ported in test/*.goose. Not ported, and why:

* `TestLookupMallocs`, `TestReadMIMEHeaderAllocations`, the benchmarks:
  they count Go's allocations (Goose has no allocator to count).
* `TestWriterBoundaryGoroutines`: a data race on Go's writer; Goose
  threads share nothing.
* `TestReadForm_ManyFiles_Combined`: Go's default of one temporary file
  for all spilled files is not implemented (see below); the `Distinct`
  variant is ported.
* `TestReaderUpcomingHeaderKeys`: an internal allocation hint with no
  effect on results.
* `roundTripParseTest`'s random boundary: ported as the same round trip.
* net/textproto's tests of what multipart does not use (ReadLine,
  ReadCodeLine, dot encoding): those functions are not implemented.

## Departures from Go

Deliberate, or where Go's own result depends on how its input is read:

* **Errors** are codes, not values; a CharsetReader is a block given the
  decoded bytes, not an `io.Reader`, and returns a code.
* **The multipart reader is fed**, not reading an `io.Reader`; its errors
  are sticky. Go's `NextPart` after an error (or after the final
  boundary) goes on reading lines from wherever its buffer stopped; here
  `EV_ERROR`/`EV_END` stay.
* **A quoted-printable error inside a part** ends that part with the
  error, as in Go; if the caller goes on, this reader skips the rest of the
  part to its boundary, where Go would read on from the point its own
  quoted-printable buffer had reached (which depends on Go's buffering).
* **Go's 4096-byte buffers** are kept as limits where they decide results
  from the bytes alone: a line before a boundary line, and a
  quoted-printable line, longer than 4096 bytes fails with "bufio: buffer
  full", as in Go reading a `strings.Reader`. Where Go's result depends on
  the reader (data arriving with `io.EOF` in the same `Read`), on how its
  buffer happens to be filled (boundaries longer than about 4000 bytes or
  containing CR or LF; a quoted-printable line of exactly 4096 bytes ending
  a part; a header continuation line longer than the remaining 10 MiB
  header budget, which Go stops reading mid-line), this reader takes the
  `strings.Reader` reading, or the whole line.
* **ReadForm's temporary files**: one per spilled file (Go's
  `GODEBUG=multipartfiles=distinct`), named `multipart-` and 16 random hex
  digits in `Form.tmp_dir`, else `$TMPDIR`, else `/tmp`; written with
  `os`'s `write_file`, which has no `O_EXCL` (a name that exists is
  refused; the name is unguessable). File contents are read whole
  (`file_content`), not through Go's `File` (`ReaderAt`, `Seeker`).
* **GODEBUG** is not read: `Form.max_parts`, `Form.max_headers`,
  `Reader.max_headers` and `Reader.max_header_bytes` carry Go's defaults
  and are set by the caller.
* **mime.types**: `bufio.Scanner` stops (and Go panics) on a line of more
  than 64 KiB in a system file; such lines are read here.
* **Windows** is untested: the registry is not read (the built-in table
  only); `getentropy` (random boundaries, temporary file names) comes from
  the C library through an `extern "c"` block and `mime.build` maps no
  Windows library for it, so `new_writer` and spilling a form's files are
  expected to fail there; `FileName` follows Windows' `filepath.Base` there
  (`src/path_windows.h`).

## Not done

* `net/mail` (RFC 5322 addresses and dates): mime and multipart do not use
  it; it needs Go's `time` layouts and zones, a module of its own.
* `net/textproto`'s other readers and writers (lines, codes, dot encoding).
* One temporary file for all of a form's spilled files (Go's default).
* Windows: the registry's types, an entropy source.
