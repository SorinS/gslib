# compressgoose

Compression formats and archives for Goose, after Go's `compress/*` and
`archive/*` packages, plus xz. Pure Goose: no C, no files read or written by
the package itself.

(The sections below grow with each format.)

## API conventions

Every module is in namespace `compress`, so names carry their format:
`compress::gzip_reader`, `compress::tar_next`, ...

* **Results.** A step returns `0` when it needs more input or more room
  for output, `compress::STREAM_END` (1) when the stream is complete, and
  a negative `compress::ERR_*` code otherwise (`compress::error_text`).
  After an error a codec takes nothing more and repeats the error.
* **Decoders** keep fixed-size state, fed by the caller:
  `let used, made, st = compress::X_read(d, input, out);` takes what it can
  of `input` and writes at most `out.len` bytes into `out`. A call with
  input left and room in `out` always makes progress. At the end of its
  input the caller asks `compress::X_done(d)` (or gets `ERR_TRUNCATED` from
  the whole-buffer helpers).
* **Encoders** append to a builder the caller owns:
  `compress::X_write(w, input, out)`, `X_flush(w, out)`, `X_close(w, out)`.
* **Whole buffers**: `compress::X_decode(data, out, limit)` and
  `compress::X_encode(data, out, ...)` for when everything is in memory.
* **Memory** is bounded by the state's size (plus, for xz, a dictionary
  capped by a limit the caller can set); output is bounded by the room the
  caller gives, so a decompression bomb costs only what the caller lets it.

## Tests

    python3 scripts/run_tests.py             # every test/*.goose at -O0, -O2 and --debug
    python3 scripts/run_tests.py --native    # and built with the C compiler

The Go oracle (`tools/gooracle`, Go's own packages on our inputs) is built
with `cd tools/gooracle && go build`.
