package main

// serve: the Go side of scripts/differential.py. Each line of the input is
// a case, its fields separated by '|' and escaped as the vectors are
// (\xHH; \N nil); the first field is its kind. For each case one line of
// results is written, in the same escaping. tools/mimecheck.goose answers
// the same cases the same way, and the script compares the two.
//
//	mt|v                          ParseMediaType: err | type | n | (k | v)...
//	fmt|t|n|(k|v)...              FormatMediaType: result
//	ew|enc|charset|s              WordEncoder.Encode: result
//	dw|word                       WordDecoder.Decode: result | err
//	dh|header                     WordDecoder.DecodeHeader: result | err
//	qpr|data                      quotedprintable.Reader, read whole: data | err
//	qpw|binary|data               quotedprintable.Writer: output
//	hdr|data                      textproto ReadMIMEHeader: err | header
//	hdrl|maxMemory|maxHeaders|data  readMIMEHeader with limits: err | header
//	mp|boundary|raw|body          multipart.Reader: per part (raw[i] == '1': NextRawPart)
//	                              header | form name | file name | body | read error;
//	                              then the error that ended the loop ("" for io.EOF)
//	form|boundary|maxMemory|body  ReadForm: err | values | files (name, size, content, on disk)
//	type|ext                      TypeByExtension: result
//	exts|type                     ExtensionsByType: err | n | ext...
//	cd|field|file                 FileContentDisposition: result
//	sb|boundary                   Writer.SetBoundary: err | FormDataContentType

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	_ "unsafe" // for go:linkname
)

//go:linkname readMIMEHeader net/textproto.readMIMEHeader
func readMIMEHeader(r *textproto.Reader, maxMemory, maxHeaders int64) (textproto.MIMEHeader, error)

func unescapeField(f string) (string, bool) {
	if f == `\N` {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(f); i++ {
		if f[i] == '\\' && i+3 < len(f) && f[i+1] == 'x' {
			v, err := strconv.ParseUint(f[i+2:i+4], 16, 8)
			if err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(f[i])
	}
	return b.String(), true
}

func serveMode(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for n := 1; ; n++ {
		line, err := in.ReadString('\n')
		if err == io.EOF && line == "" {
			return nil
		}
		if err != nil && err != io.EOF {
			return err
		}
		line = strings.TrimSuffix(line, "\n")
		raw := strings.Split(line, "|")
		var f []string
		for _, x := range raw {
			s, _ := unescapeField(x)
			f = append(f, s)
		}
		res, err := answer(f)
		if err != nil {
			return fmt.Errorf("case %d: %v", n, err)
		}
		var esc []string
		for _, r := range res {
			esc = append(esc, escapeField(r))
		}
		fmt.Fprintln(out, strings.Join(esc, "|"))
	}
}

func atoi(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

// headerFields: the header as the vectors flatten a map of lists.
func headerFields(h textproto.MIMEHeader) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []string{strconv.Itoa(len(keys))}
	for _, k := range keys {
		out = append(out, k, strconv.Itoa(len(h[k])))
		out = append(out, h[k]...)
	}
	return out
}

func answer(f []string) ([]string, error) {
	switch f[0] {
	case "mt":
		mt, params, err := mime.ParseMediaType(f[1])
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []string{errText(err), mt, strconv.Itoa(len(keys))}
		for _, k := range keys {
			out = append(out, k, params[k])
		}
		return out, nil
	case "fmt":
		n := int(atoi(f[2]))
		params := map[string]string{}
		for i := 0; i < n; i++ {
			params[f[3+2*i]] = f[4+2*i]
		}
		return []string{mime.FormatMediaType(f[1], params)}, nil
	case "ew":
		return []string{mime.WordEncoder(f[1][0]).Encode(f[2], f[3])}, nil
	case "dw":
		s, err := new(mime.WordDecoder).Decode(f[1])
		return []string{s, errText(err)}, nil
	case "dh":
		s, err := new(mime.WordDecoder).DecodeHeader(f[1])
		return []string{s, errText(err)}, nil
	case "qpr":
		var b bytes.Buffer
		_, err := io.Copy(&b, quotedprintable.NewReader(strings.NewReader(f[1])))
		return []string{b.String(), errText(err)}, nil
	case "qpw":
		var b bytes.Buffer
		w := quotedprintable.NewWriter(&b)
		w.Binary = f[1] == "1"
		w.Write([]byte(f[2]))
		w.Close()
		return []string{b.String()}, nil
	case "hdr":
		h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(f[1]))).ReadMIMEHeader()
		return append([]string{errText(err)}, headerFields(h)...), nil
	case "hdrl":
		h, err := readMIMEHeader(textproto.NewReader(bufio.NewReader(strings.NewReader(f[3]))), atoi(f[1]), atoi(f[2]))
		return append([]string{errText(err)}, headerFields(h)...), nil
	case "mp":
		return multipartCase(f[1], f[2], f[3]), nil
	case "form":
		return formCase(f[1], atoi(f[2]), f[3])
	case "type":
		return []string{mime.TypeByExtension(f[1])}, nil
	case "exts":
		exts, err := mime.ExtensionsByType(f[1])
		out := []string{errText(err), strconv.Itoa(len(exts))}
		return append(out, exts...), nil
	case "cd":
		return []string{multipart.FileContentDisposition(f[1], f[2])}, nil
	case "sb":
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		err := w.SetBoundary(f[1])
		ct := ""
		if err == nil {
			ct = w.FormDataContentType()
		}
		return []string{errText(err), ct}, nil
	}
	return nil, errors.New("unknown kind " + f[0])
}

func multipartCase(boundary, raw, body string) []string {
	r := multipart.NewReader(strings.NewReader(body), boundary)
	var out []string
	for i := 0; ; i++ {
		var p *multipart.Part
		var err error
		if i < len(raw) && raw[i] == '1' {
			p, err = r.NextRawPart()
		} else {
			p, err = r.NextPart()
		}
		if err == io.EOF {
			return append(out, "")
		}
		if err != nil {
			return append(out, err.Error())
		}
		data, err := io.ReadAll(p)
		out = append(out, headerFields(p.Header)...)
		out = append(out, p.FormName(), p.FileName(), string(data), errText(err))
		if err != nil {
			return append(out, "stopped")
		}
	}
}

func formCase(boundary string, maxMemory int64, body string) ([]string, error) {
	r := multipart.NewReader(strings.NewReader(body), boundary)
	f, err := r.ReadForm(maxMemory)
	if err != nil {
		return []string{err.Error()}, nil
	}
	defer f.RemoveAll()
	out := []string{""}
	names := make([]string, 0, len(f.Value))
	for k := range f.Value {
		names = append(names, k)
	}
	sort.Strings(names)
	out = append(out, strconv.Itoa(len(names)))
	for _, k := range names {
		out = append(out, k, strconv.Itoa(len(f.Value[k])))
		out = append(out, f.Value[k]...)
	}
	names = names[:0]
	for k := range f.File {
		names = append(names, k)
	}
	sort.Strings(names)
	out = append(out, strconv.Itoa(len(names)))
	for _, k := range names {
		out = append(out, k, strconv.Itoa(len(f.File[k])))
		for _, fh := range f.File[k] {
			fd, err := fh.Open()
			if err != nil {
				return nil, err
			}
			data, err := io.ReadAll(fd)
			_, onDisk := fd.(*os.File)
			fd.Close()
			if err != nil {
				return nil, err
			}
			disk := "0"
			if onDisk {
				disk = "1"
			}
			out = append(out, fh.Filename, strconv.FormatInt(fh.Size, 10), string(data), disk)
		}
	}
	return out, nil
}
