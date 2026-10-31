package main

import (
	"flag"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"io"
	"os"
)

func init() {
	register("checksum", "print CRC-32, Adler-32 and CRC-64/ECMA of stdin (or the files given)", func(args []string) error {
		fs := flag.NewFlagSet("checksum", flag.ContinueOnError)
		if err := fs.Parse(args); err != nil {
			return err
		}
		names := fs.Args()
		if len(names) == 0 {
			names = []string{"-"}
		}
		for _, n := range names {
			var data []byte
			var err error
			if n == "-" {
				data, err = io.ReadAll(os.Stdin)
			} else {
				data, err = os.ReadFile(n)
			}
			if err != nil {
				return err
			}
			fmt.Printf("%08x %08x %016x %s\n", crc32.ChecksumIEEE(data), adler32.Checksum(data),
				crc64.Checksum(data, crc64.MakeTable(crc64.ECMA)), n)
		}
		return nil
	})
}
