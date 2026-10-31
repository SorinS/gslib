package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"
)

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

// zipErrClass names a Go error as tools/zipverdict.goose names ours.
func zipErrClass(err error) string {
	var ce flate.CorruptInputError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, zip.ErrInsecurePath):
		return "insecure"
	case errors.Is(err, zip.ErrFormat):
		return "format"
	case errors.Is(err, zip.ErrChecksum):
		return "checksum"
	case errors.Is(err, zip.ErrAlgorithm):
		return "algorithm"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.As(err, &ce):
		return "data"
	}
	return "other:" + strings.ReplaceAll(err.Error(), " ", "_")
}

// sparseZip is the (gzipped) .zsparse format of archive/zip/testdata/zip64: a size,
// then spans of non-zero bytes; the rest is zeros.
type sparseZip struct {
	size  int64
	spans []sparseZipSpan
}

type sparseZipSpan struct {
	off  int64
	data []byte
}

func readSparseZip(b []byte) (*sparseZip, error) {
	if len(b) < 12 {
		return nil, errors.New("short zsparse")
	}
	f := &sparseZip{size: int64(binary.LittleEndian.Uint64(b))}
	n := binary.LittleEndian.Uint32(b[8:])
	b = b[12:]
	for i := uint32(0); i < n; i++ {
		if len(b) < 12 {
			return nil, errors.New("short zsparse span")
		}
		off := int64(binary.LittleEndian.Uint64(b))
		l := binary.LittleEndian.Uint32(b[8:])
		b = b[12:]
		if uint32(len(b)) < l {
			return nil, errors.New("short zsparse data")
		}
		f.spans = append(f.spans, sparseZipSpan{off, b[:l]})
		b = b[l:]
	}
	return f, nil
}

func (f *sparseZip) ReadAt(p []byte, off int64) (int, error) {
	if off >= f.size {
		return 0, io.EOF
	}
	end := min(off+int64(len(p)), f.size)
	n := int(end - off)
	clear(p[:n])
	for _, s := range f.spans {
		sEnd := s.off + int64(len(s.data))
		if sEnd <= off || s.off >= end {
			continue
		}
		from, to := max(s.off, off), min(sEnd, end)
		copy(p[from-off:to-off], s.data[from-s.off:to-s.off])
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// zipDump prints what Go's reader makes of an archive.
func zipDump(w io.Writer, r io.ReaderAt, size int64, data bool) {
	zr, err := zip.NewReader(r, size)
	if zr == nil {
		fmt.Fprintf(w, "archive %s\n", zipErrClass(err))
		return
	}
	fmt.Fprintf(w, "archive %s comment=%x files=%d\n", zipErrClass(err), zr.Comment, len(zr.File))
	for i, f := range zr.File {
		_, off := f.Modified.Zone()
		fmt.Fprintf(w, "file %d name=%x comment=%x nonutf8=%t creator=%d reader=%d flags=%d method=%d mtime=%d mdate=%d "+
			"modified=%d.%09d@%d crc=%08x csize=%d usize=%d csize64=%d usize64=%d extra=%x attrs=%d mode=%08x\n",
			i, f.Name, f.Comment, f.NonUTF8, f.CreatorVersion, f.ReaderVersion, f.Flags, f.Method, f.ModifiedTime,
			f.ModifiedDate, f.Modified.Unix(), f.Modified.Nanosecond(), off, f.CRC32, f.CompressedSize,
			f.UncompressedSize, f.CompressedSize64, f.UncompressedSize64, f.Extra, f.ExternalAttrs, uint32(f.Mode()))
		if o, err := f.DataOffset(); err != nil {
			fmt.Fprintf(w, "offset %d err %s\n", i, zipErrClass(err))
		} else {
			fmt.Fprintf(w, "offset %d %d\n", i, o)
		}
		if !data {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			fmt.Fprintf(w, "data %d err %s\n", i, zipErrClass(err))
			continue
		}
		c, a := crc32.NewIEEE(), adler32.New()
		n, err := io.Copy(io.MultiWriter(c, a), rc)
		rc.Close()
		if err != nil {
			fmt.Fprintf(w, "data %d err %s\n", i, zipErrClass(err))
			continue
		}
		fmt.Fprintf(w, "data %d ok %d %08x %08x\n", i, n, c.Sum32(), a.Sum32())
	}
}

func init() {
	register("zip", "dump archives as Go's archive/zip reads them (files given, or -list FILE of paths); "+
		"a path ending in .zsparse is a sparse 64-bit test archive (no data read); "+
		"GODEBUG=zipinsecurepath=0 in the environment turns the path check on", func(args []string) error {
		fs := flag.NewFlagSet("zip", flag.ContinueOnError)
		list := fs.String("list", "", "a file of archive paths, one a line")
		if err := fs.Parse(args); err != nil {
			return err
		}
		paths := fs.Args()
		if *list != "" {
			b, err := os.ReadFile(*list)
			if err != nil {
				return err
			}
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					paths = append(paths, l)
				}
			}
		}
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if strings.HasSuffix(p, ".zsparse") {
				zr, err := gzip.NewReader(bytes.NewReader(b))
				if err != nil {
					return fmt.Errorf("%s: %v", p, err)
				}
				if b, err = io.ReadAll(zr); err != nil {
					return fmt.Errorf("%s: %v", p, err)
				}
				f, err := readSparseZip(b)
				if err != nil {
					return fmt.Errorf("%s: %v", p, err)
				}
				zipDump(w, f, f.size, false)
			} else {
				zipDump(w, bytes.NewReader(b), int64(len(b)), true)
			}
			fmt.Fprintln(w, "end")
		}
		return nil
	})
}

// zipMake writes an archive from tools/zipmake.goose's spec with Go's writer.
func zipMake(specPath, outPath string) error {
	spec, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}
	unhex := func(s string) []byte {
		if s == "-" {
			return nil
		}
		b, err := hexDecode(s)
		if err != nil {
			panic(err)
		}
		return b
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(w io.Writer, path, chunk string) error {
		if path == "-" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(chunk)
		if err != nil {
			return err
		}
		for p := 0; p < len(data); p += n {
			if _, err := w.Write(data[p:min(p+n, len(data))]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, line := range strings.Split(string(spec), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "comment":
			if err := zw.SetComment(string(unhex(f[1]))); err != nil {
				return err
			}
		case "offset":
			n, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				return err
			}
			zw.SetOffset(n)
		case "create":
			w, err := zw.Create(string(unhex(f[1])))
			if err != nil {
				return err
			}
			if err := write(w, f[2], f[3]); err != nil {
				return err
			}
		case "raw":
			method, _ := strconv.Atoi(f[2])
			flags, _ := strconv.Atoi(f[3])
			crc, _ := strconv.ParseUint(f[4], 16, 32)
			cs, _ := strconv.ParseUint(f[5], 10, 64)
			us, _ := strconv.ParseUint(f[6], 10, 64)
			cv, _ := strconv.Atoi(f[7])
			rv, _ := strconv.Atoi(f[8])
			h := &zip.FileHeader{Name: string(unhex(f[1])), Method: uint16(method), Flags: uint16(flags),
				CRC32: uint32(crc), CompressedSize64: cs, UncompressedSize64: us,
				CreatorVersion: uint16(cv), ReaderVersion: uint16(rv)}
			w, err := zw.CreateRaw(h)
			if err != nil {
				return err
			}
			if err := write(w, f[9], "1073741824"); err != nil {
				return err
			}
		case "copy":
			zr, err := zip.OpenReader(f[1])
			if err != nil {
				return err
			}
			for _, zf := range zr.File {
				if err := zw.Copy(zf); err != nil {
					return err
				}
			}
			zr.Close()
		case "file":
			method, _ := strconv.Atoi(f[2])
			h := &zip.FileHeader{Name: string(unhex(f[1])), Method: uint16(method), Comment: string(unhex(f[6])),
				Extra: unhex(f[7]), NonUTF8: f[8] == "1"}
			if f[3] != "-" {
				secs, _ := strconv.ParseInt(f[3], 10, 64)
				off, _ := strconv.Atoi(f[4])
				h.Modified = time.Unix(secs, 0).In(time.FixedZone("", off))
			}
			if f[5] != "-" {
				m, _ := strconv.ParseUint(f[5], 16, 32)
				h.SetMode(fs.FileMode(m))
			}
			w, err := zw.CreateHeader(h)
			if err != nil {
				return err
			}
			if err := write(w, f[9], f[10]); err != nil {
				return err
			}
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(outPath, buf.Bytes(), 0o644)
}

func init() {
	register("zipmake", "write an archive with Go's archive/zip from a tools/zipmake.goose spec: zipmake SPEC OUT", func(args []string) error {
		if len(args) != 2 {
			return errors.New("usage: gooracle zipmake spec.txt out.zip")
		}
		return zipMake(args[0], args[1])
	})
}
