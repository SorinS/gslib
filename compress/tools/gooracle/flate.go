package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
	"strings"
)

// errClass names a Go error the way the Goose verdict tools name ours.
func errClass(err error) string {
	var ce flate.CorruptInputError
	switch {
	case errors.As(err, &ce):
		return "data"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated"
	case errors.Is(err, gzip.ErrChecksum), errors.Is(err, zlib.ErrChecksum):
		return "checksum"
	case errors.Is(err, gzip.ErrHeader), errors.Is(err, zlib.ErrHeader):
		return "header"
	case errors.Is(err, zlib.ErrDictionary):
		return "dictionary"
	case errors.Is(err, io.EOF):
		return "eof"
	}
	return "other:" + err.Error()
}

// decodeOne decodes a stream as Go's readers do; the verdict line.
func decodeOne(format string, data, dict []byte) string {
	var r io.Reader
	var err error
	src := bytes.NewReader(data)
	switch format {
	case "raw":
		r = flate.NewReaderDict(src, dict)
	case "zlib":
		r, err = zlib.NewReaderDict(src, dict)
	case "gzip", "gzip1":
		var z *gzip.Reader
		z, err = gzip.NewReader(src)
		if err == nil && format == "gzip1" {
			z.Multistream(false)
		}
		r = z
	default:
		return "bad format " + format
	}
	if err != nil {
		return "err " + errClass(err) + " 0 00000000"
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return fmt.Sprintf("err %s %d %08x", errClass(err), len(out), crc32.ChecksumIEEE(out))
	}
	return fmt.Sprintf("ok %d %08x", len(out), crc32.ChecksumIEEE(out))
}

func unhex(s string) ([]byte, error) {
	if s == "-" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

func init() {
	register("inflate", "decode each case of a file, `FORMAT HEX [DICTHEX]` a line (raw, zlib, gzip, gzip1 = one member): `ok SIZE CRC32` or `err CLASS SIZE CRC32` (what decoded before the error)", func(args []string) error {
		fs := flag.NewFlagSet("inflate", flag.ContinueOnError)
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: gooracle inflate cases.txt")
		}
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<30)
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			data, err := unhex(fields[1])
			if err != nil {
				return err
			}
			var dict []byte
			if len(fields) > 2 {
				if dict, err = unhex(fields[2]); err != nil {
					return err
				}
			}
			fmt.Fprintln(w, decodeOne(fields[0], data, dict))
		}
		return sc.Err()
	})
	register("deflate", "compress each case of a file, `FORMAT LEVEL HEX [DICTHEX]` a line (raw, zlib, gzip): the stream in hex", func(args []string) error {
		fs := flag.NewFlagSet("deflate", flag.ContinueOnError)
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: gooracle deflate cases.txt")
		}
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<30)
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 3 {
				continue
			}
			level, err := strconv.Atoi(fields[1])
			if err != nil {
				return err
			}
			data, err := unhex(fields[2])
			if err != nil {
				return err
			}
			var dict []byte
			if len(fields) > 3 {
				if dict, err = unhex(fields[3]); err != nil {
					return err
				}
			}
			var buf bytes.Buffer
			var wc io.WriteCloser
			switch fields[0] {
			case "raw":
				wc, err = flate.NewWriterDict(&buf, level, dict)
			case "zlib":
				wc, err = zlib.NewWriterLevelDict(&buf, level, dict)
			case "gzip":
				wc, err = gzip.NewWriterLevel(&buf, level)
			default:
				return fmt.Errorf("bad format %q", fields[0])
			}
			if err != nil {
				return err
			}
			if _, err := wc.Write(data); err != nil {
				return err
			}
			if err := wc.Close(); err != nil {
				return err
			}
			fmt.Fprintln(w, hex.EncodeToString(buf.Bytes()))
		}
		return sc.Err()
	})
}
