package main

// gooracle tar: Go's archive/tar on the archives and header lists that
// scripts/tar_differential.py gives it, printed as tools/tarverdict.goose
// prints the Goose package's results.
//
//	gooracle tar read [-cap N] archive...    every header, content CRC-32, final error
//	gooracle tar write spec out.tar          writes the entries a spec lists
//
// Read output, per archive:
//
//	archive NAME
//	hdr type=T name=HEX link=HEX size=N mode=N uid=N gid=N uname=HEX gname=HEX
//	    mtime=TIME atime=TIME ctime=TIME devmajor=N devminor=N format=N   (one line)
//	pax KEYHEX VALUEHEX                  (sorted by key)
//	insecure                             (Next returned ErrInsecurePath)
//	data LEN CRC32 [err CLASS]           (the first -cap bytes of the contents at most)
//	end CLASS                            (the error that ended Next: EOF at a proper end)
//
// TIME is "zero" or SECONDS.NANOSECONDS (9 digits). Set
// GODEBUG=tarinsecurepath=0 for Go's insecure-path check.
//
// A spec has one entry a line:
//
//	TYPE NAMEHEX LINKHEX SIZE MODE UID GID UNAMEHEX GNAMEHEX MTIME ATIME CTIME DEVMAJOR DEVMINOR FORMAT PAXHEX DATALEN SEED
//
// (HEX "-" for empty; PAXHEX is the records in PAX's own encoding) and the
// write prints, per entry, "wh CLASS" for WriteHeader and "w N CLASS" for
// writing DATALEN bytes made from SEED, then "close CLASS".

import (
	"archive/tar"
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() {
	register("tar", "read archives or write a spec with archive/tar (see tar.go)", func(args []string) error {
		if len(args) < 1 {
			return errors.New("tar: read or write")
		}
		switch args[0] {
		case "read":
			return tarRead(args[1:])
		case "write":
			return tarWrite(args[1:])
		}
		return fmt.Errorf("tar: unknown mode %q", args[0])
	})
}

func tarHex(s string) string {
	if s == "" {
		return "-"
	}
	return hex.EncodeToString([]byte(s))
}

func tarTime(t time.Time) string {
	if t.IsZero() {
		return "zero"
	}
	return fmt.Sprintf("%d.%09d", t.Unix(), t.Nanosecond())
}

func tarErrClass(err error) string {
	switch {
	case err == nil:
		return "ok"
	case err == io.EOF:
		return "EOF"
	case err == io.ErrUnexpectedEOF:
		return "unexpected-eof"
	case err == tar.ErrHeader:
		return "header"
	case err == tar.ErrFieldTooLong:
		return "field-too-long"
	case err == tar.ErrWriteTooLong:
		return "write-too-long"
	case err == tar.ErrWriteAfterClose:
		return "after-close"
	case err == tar.ErrInsecurePath:
		return "insecure"
	}
	m := err.Error()
	switch {
	case strings.Contains(m, "sparse map too long"):
		return "sparse-too-long"
	case strings.Contains(m, "references non-existent data"):
		return "miss-data"
	case strings.Contains(m, "contains unreferenced data"):
		return "unref-data"
	case strings.Contains(m, "missed writing"):
		return "missed-writing"
	case strings.Contains(m, "cannot encode header"):
		return "cannot-encode"
	}
	return "other:" + strings.ReplaceAll(m, " ", "_")
}

func tarRead(args []string) error {
	fs := flag.NewFlagSet("tar read", flag.ContinueOnError)
	limit := fs.Int64("cap", 16<<20, "read at most this much of each entry's contents")
	if err := fs.Parse(args); err != nil {
		return err
	}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	buf := make([]byte, 32<<10)
	for _, name := range fs.Args() {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "archive %s\n", name)
		tr := tar.NewReader(bufio.NewReader(f))
		for {
			h, err := tr.Next()
			if h == nil {
				fmt.Fprintf(out, "end %s\n", tarErrClass(err))
				break
			}
			fmt.Fprintf(out, "hdr type=%d name=%s link=%s size=%d mode=%d uid=%d gid=%d uname=%s gname=%s mtime=%s atime=%s ctime=%s devmajor=%d devminor=%d format=%d\n",
				h.Typeflag, tarHex(h.Name), tarHex(h.Linkname), h.Size, h.Mode, h.Uid, h.Gid,
				tarHex(h.Uname), tarHex(h.Gname), tarTime(h.ModTime), tarTime(h.AccessTime), tarTime(h.ChangeTime),
				h.Devmajor, h.Devminor, int(h.Format))
			keys := make([]string, 0, len(h.PAXRecords))
			for k := range h.PAXRecords {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(out, "pax %s %s\n", tarHex(k), tarHex(h.PAXRecords[k]))
			}
			if err == tar.ErrInsecurePath {
				fmt.Fprintf(out, "insecure\n")
			} else if err != nil {
				fmt.Fprintf(out, "end %s\n", tarErrClass(err))
				break
			}
			crc := crc32.NewIEEE()
			var n int64
			var rerr error
			for n < *limit {
				want := int64(len(buf))
				if *limit-n < want {
					want = *limit - n
				}
				k, e := tr.Read(buf[:want])
				crc.Write(buf[:k])
				n += int64(k)
				if e != nil {
					if e != io.EOF {
						rerr = e
					}
					break
				}
			}
			if rerr != nil {
				fmt.Fprintf(out, "data %d %08x err %s\n", n, crc.Sum32(), tarErrClass(rerr))
			} else {
				fmt.Fprintf(out, "data %d %08x\n", n, crc.Sum32())
			}
		}
		f.Close()
	}
	return nil
}

func tarUnhex(s string) (string, error) {
	if s == "-" {
		return "", nil
	}
	b, err := hex.DecodeString(s)
	return string(b), err
}

func tarSpecTime(s string) (time.Time, error) {
	if s == "zero" {
		return time.Time{}, nil
	}
	a, b, _ := strings.Cut(s, ".")
	sec, err := strconv.ParseInt(a, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	var ns int64
	if b != "" {
		if ns, err = strconv.ParseInt(b, 10, 64); err != nil {
			return time.Time{}, err
		}
	}
	return time.Unix(sec, ns), nil
}

// The records of PAX's encoding, the last of a key winning.
func tarPAXRecords(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}
	m := map[string]string{}
	for len(s) > 0 {
		nStr, rest, ok := strings.Cut(s, " ")
		if !ok {
			return nil, errors.New("bad record")
		}
		n, err := strconv.Atoi(nStr)
		if err != nil || n <= len(nStr)+1 || n > len(s) {
			return nil, errors.New("bad record")
		}
		rec := rest[:n-len(nStr)-1]
		k, v, ok := strings.Cut(strings.TrimSuffix(rec, "\n"), "=")
		if !ok {
			return nil, errors.New("bad record")
		}
		m[k] = v
		s = s[n:]
	}
	return m, nil
}

// The contents written for an entry: what tarverdict makes from the same seed.
func tarSpecData(n int, seed uint32) []byte {
	b := make([]byte, n)
	x := seed
	for i := range b {
		x = x*1103515245 + 12345
		b[i] = byte(x >> 16)
	}
	return b
}

func tarWrite(args []string) error {
	if len(args) != 2 {
		return errors.New("tar write: spec out.tar")
	}
	spec, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	f, err := os.Create(args[1])
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(f)
	tw := tar.NewWriter(bw)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for _, line := range strings.Split(string(spec), "\n") {
		fl := strings.Fields(line)
		if len(fl) == 0 {
			continue
		}
		if len(fl) != 18 {
			return fmt.Errorf("tar write: bad spec line %q", line)
		}
		var h tar.Header
		typ, _ := strconv.Atoi(fl[0])
		h.Typeflag = byte(typ)
		var e1, e2, e3, e4 error
		h.Name, e1 = tarUnhex(fl[1])
		h.Linkname, e2 = tarUnhex(fl[2])
		h.Size, _ = strconv.ParseInt(fl[3], 10, 64)
		h.Mode, _ = strconv.ParseInt(fl[4], 10, 64)
		uid, _ := strconv.ParseInt(fl[5], 10, 64)
		gid, _ := strconv.ParseInt(fl[6], 10, 64)
		h.Uid, h.Gid = int(uid), int(gid)
		h.Uname, e3 = tarUnhex(fl[7])
		h.Gname, e4 = tarUnhex(fl[8])
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			return fmt.Errorf("tar write: bad hex in %q", line)
		}
		if h.ModTime, err = tarSpecTime(fl[9]); err != nil {
			return err
		}
		if h.AccessTime, err = tarSpecTime(fl[10]); err != nil {
			return err
		}
		if h.ChangeTime, err = tarSpecTime(fl[11]); err != nil {
			return err
		}
		h.Devmajor, _ = strconv.ParseInt(fl[12], 10, 64)
		h.Devminor, _ = strconv.ParseInt(fl[13], 10, 64)
		format, _ := strconv.Atoi(fl[14])
		h.Format = tar.Format(format)
		pax, err := tarUnhex(fl[15])
		if err != nil {
			return err
		}
		if h.PAXRecords, err = tarPAXRecords(pax); err != nil {
			return err
		}
		dlen, _ := strconv.Atoi(fl[16])
		seed, _ := strconv.ParseUint(fl[17], 10, 32)
		fmt.Fprintf(out, "wh %s\n", tarErrClass(tw.WriteHeader(&h)))
		n, werr := tw.Write(tarSpecData(dlen, uint32(seed)))
		fmt.Fprintf(out, "w %d %s\n", n, tarErrClass(werr))
	}
	fmt.Fprintf(out, "close %s\n", tarErrClass(tw.Close()))
	if err := bw.Flush(); err != nil {
		return err
	}
	return f.Close()
}
