The *.tar files are Go 1.27.1's $GOROOT/src/archive/tar/testdata (the
.base64 ones decoded; the two large .bz2 ones are left to
scripts/tar_differential.py), under Go's BSD-style license
(Copyright 2009 The Go Authors). read.expect and read-cap100-check.expect
are what Go's archive/tar makes of them (`gooracle tar read -cap 1048576`
and, with GODEBUG=tarinsecurepath=0, `gooracle tar read -cap 100`);
strconv.txt is printed from the tables of Go's strconv_test.go.
