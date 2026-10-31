package main

import (
	"bufio"
	"bytes"
	"compress/lzw"
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

// lzw: a batch of cases, one a line, "enc|dec ORDER LITWIDTH HEX" (ORDER
// lsb or msb, HEX "-" for none). Each gives a line:
//
//	enc: "ok HEX" (Go's Writer's output), or "err litwidth" (a byte too large)
//	dec: "ok LEN CRC" (the output's length and CRC-32), or "err KIND LEN CRC"
//	     with KIND unexpected-eof or invalid-code and LEN CRC those of the
//	     output before the error
func init() {
	register("lzw", "batch LZW cases (enc|dec ORDER LITWIDTH HEX per line) from a file or stdin", func(args []string) error {
		fs := flag.NewFlagSet("lzw", flag.ContinueOnError)
		if err := fs.Parse(args); err != nil {
			return err
		}
		in := io.Reader(os.Stdin)
		if fs.NArg() > 0 {
			f, err := os.Open(fs.Arg(0))
			if err != nil {
				return err
			}
			defer f.Close()
			in = f
		}
		sc := bufio.NewScanner(in)
		sc.Buffer(make([]byte, 1<<20), 1<<30)
		out := bufio.NewWriter(os.Stdout)
		defer out.Flush()
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) == 0 {
				continue
			}
			if len(f) != 4 {
				return fmt.Errorf("lzw: bad case line %q", sc.Text())
			}
			order := lzw.LSB
			if f[1] == "msb" {
				order = lzw.MSB
			}
			lw, err := strconv.Atoi(f[2])
			if err != nil {
				return err
			}
			var data []byte
			if f[3] != "-" {
				if data, err = hex.DecodeString(f[3]); err != nil {
					return err
				}
			}
			switch f[0] {
			case "enc":
				var b bytes.Buffer
				w := lzw.NewWriter(&b, order, lw)
				_, werr := w.Write(data)
				cerr := w.Close()
				if werr != nil || cerr != nil {
					fmt.Fprintln(out, "err litwidth")
				} else {
					fmt.Fprintln(out, "ok", hexOrDash(b.Bytes()))
				}
			case "dec":
				r := lzw.NewReader(bytes.NewReader(data), order, lw)
				got, rerr := io.ReadAll(r)
				switch {
				case rerr == nil:
					fmt.Fprintln(out, "ok", lenCRC(got))
				case errors.Is(rerr, io.ErrUnexpectedEOF):
					fmt.Fprintln(out, "err unexpected-eof", lenCRC(got))
				case strings.Contains(rerr.Error(), "invalid code"):
					fmt.Fprintln(out, "err invalid-code", lenCRC(got))
				default:
					return fmt.Errorf("lzw: unexpected error %v", rerr)
				}
			default:
				return fmt.Errorf("lzw: bad case kind %q", f[0])
			}
		}
		return sc.Err()
	})
}

func hexOrDash(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func lenCRC(b []byte) string { return fmt.Sprintf("%d %08x", len(b), crc32.ChecksumIEEE(b)) }
