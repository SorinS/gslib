# Test vectors and where they come from

| Directory | Origin | License |
|---|---|---|
| `flate/` | `huffman-*.golden`, `huffman-*.in`: Go 1.27.1's `$GOROOT/src/compress/flate/testdata`. `go_streams.txt`: the TestStreams table of `compress/flate/flate_test.go`. `go_gunzip_tests.txt`, `go_zlib_tests.txt`: the gunzipTests and zlibTests tables of `compress/gzip/gunzip_test.go` and `compress/zlib/reader_test.go`, dumped by a copy of Go's tests | Go's BSD-style license (Copyright 2009 The Go Authors; https://go.dev/LICENSE) |
| `bzip2/` | Go 1.27.1's `$GOROOT/src/compress/bzip2/testdata` (`fail-issue5747.bz2` decoded from base64) | Go's BSD-style license |
| `zip/` | Go 1.27.1's `$GOROOT/src/archive/zip/testdata` (the `.base64` one decoded), the archives of `reader_test.go`'s regression tests (`issues/`), and Go's sparse ZIP64 goldens (`zip64/`); `go_dump*.txt` are Go's readings of them (gooracle zip) | Go's BSD-style license |
| `tar/` | Go 1.27.1's `$GOROOT/src/archive/tar/testdata` (see `tar/README.txt`); `*.expect` and `strconv.txt` are Go's results and tables | Go's BSD-style license |
| `xz/` | xz Utils' `tests/files` set (as vendored in github.com/therootcompany/xz's testdata; `good-2-lzma2-corrupt.xz` renamed `bad-2-lzma2-corrupt.xz` since xz refuses it), plus streams made with Python's lzma and the xz program; `expect.txt` is what xz makes of each | xz Utils' test files are in the public domain |
