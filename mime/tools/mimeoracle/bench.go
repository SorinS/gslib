package main

// bench: the Go side of tools/bench.goose, the same work.

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"os"
	"strings"
	"time"
)

func benchMode(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	boundary := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
	var body bytes.Buffer
	var line []byte
	for i := 0; i < 70; i++ {
		line = append(line, byte('a'+i%26))
	}
	line = append(line, '\r', '\n')
	for p := 0; p < 10; p++ {
		fmt.Fprintf(&body, "--%s\r\nContent-Disposition: form-data; name=\"f%d\"; filename=\"f.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n", boundary, p)
		for n := 0; n < 10<<20; n += len(line) {
			body.Write(line)
		}
		body.WriteString("\r\n")
	}
	fmt.Fprintf(&body, "--%s--\r\n", boundary)
	b := body.Bytes()

	t0 := time.Now()
	r := multipart.NewReader(bytes.NewReader(b), boundary)
	total, parts := 0, 0
	buf := make([]byte, 65536)
	for {
		p, err := r.NextPart()
		if err != nil {
			break
		}
		parts++
		for {
			n, err := p.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
	}
	d := time.Since(t0).Seconds()
	fmt.Printf("multipart read: %d parts, %d bytes, %d MB/s\n", parts, total, int(float64(len(b))/d/1e6))

	var small bytes.Buffer
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&small, "--%s\r\nContent-Disposition: form-data; name=\"field%d\"\r\n\r\nvalue %d\r\n", boundary, i, i)
	}
	fmt.Fprintf(&small, "--%s--\r\n", boundary)
	t2 := time.Now()
	for k := 0; k < 100; k++ {
		f, err := multipart.NewReader(bytes.NewReader(small.Bytes()), boundary).ReadForm(32 << 20)
		if err != nil {
			return err
		}
		f.RemoveAll()
	}
	fmt.Printf("ReadForm, 1000 fields: %d us/form\n", int(time.Since(t2).Seconds()*1e6/100))

	text := make([]byte, 1<<20)
	for i := range text {
		switch {
		case i%7 == 0:
			text[i] = 0xe9
		case i%61 == 0:
			text[i] = '\n'
		default:
			text[i] = byte('a' + i%26)
		}
	}
	var enc bytes.Buffer
	t4 := time.Now()
	for k := 0; k < 10; k++ {
		enc.Reset()
		w := quotedprintable.NewWriter(&enc)
		w.Write(text)
		w.Close()
	}
	t5 := time.Now()
	for k := 0; k < 10; k++ {
		io.ReadAll(quotedprintable.NewReader(bytes.NewReader(enc.Bytes())))
	}
	t6 := time.Now()
	fmt.Printf("QP encode: %d MB/s, decode: %d MB/s\n", int(10*float64(len(text))/t5.Sub(t4).Seconds()/1e6),
		int(10*float64(enc.Len())/t6.Sub(t5).Seconds()/1e6))
	t7 := time.Now()
	n := 0
	for k := 0; k < 100000; k++ {
		_, p, _ := mime.ParseMediaType(`multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW; charset="utf-8"`)
		n += len(p)
	}
	fmt.Printf("ParseMediaType: %d ns/op (%d)\n", int(time.Since(t7).Seconds()*1e9/100000), n)
	_ = strings.ToLower
	return nil
}
