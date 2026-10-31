package main

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strings"
)

// bzip2 [-cases FILE] [files...]
//
// With files: decodes each (a .base64 file is decoded from base64 first, as
// Go's obscuretestdata does) and prints "ok SIZE SHA256 NAME" or
// "err MESSAGE NAME". With -cases: each line of FILE is a hex stream ("-"
// for none); prints a line each, "ok SIZE CRC32" or "err".
func init() {
	register("bzip2", "decode bzip2 files (ok SIZE SHA256 / err MSG), or -cases FILE of hex lines (ok SIZE CRC32 / err)", func(args []string) error {
		fs := flag.NewFlagSet("bzip2", flag.ContinueOnError)
		cases := fs.String("cases", "", "a file of hex-encoded streams, one a line")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *cases != "" {
			f, err := os.Open(*cases)
			if err != nil {
				return err
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1<<20), 1<<30)
			w := bufio.NewWriter(os.Stdout)
			defer w.Flush()
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				if line == "-" {
					line = ""
				}
				in, err := hex.DecodeString(line)
				if err != nil {
					return err
				}
				out, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(in)))
				if err != nil {
					fmt.Fprintln(w, "err")
				} else {
					fmt.Fprintf(w, "ok %d %08x\n", len(out), crc32.ChecksumIEEE(out))
				}
			}
			return sc.Err()
		}
		for _, name := range fs.Args() {
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			if strings.HasSuffix(name, ".base64") {
				data, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
				if err != nil {
					return err
				}
			}
			out, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(data)))
			if err != nil {
				fmt.Printf("err %s %s\n", strings.ReplaceAll(err.Error(), " ", "_"), name)
			} else {
				fmt.Printf("ok %d %x %s\n", len(out), sha256.Sum256(out), name)
			}
		}
		return nil
	})
}
