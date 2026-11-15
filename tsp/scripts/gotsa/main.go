// gotsa: a TSA and client on github.com/digitorus/timestamp, for goose-ts's interop.
//
//	gotsa serve -addr 127.0.0.1:PORT -cert tsa.pem -key tsa.key -policy OID
//	gotsa query -data FILE -hash sha256|sha384|sha512 -out FILE
//	gotsa verify -reply FILE -query FILE   (signature by the embedded certificate, imprint, nonce)
package main

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
)

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, "gotsa: "+f+"\n", a...); os.Exit(1) }

func pemBlock(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		die("%v", err)
	}
	p, _ := pem.Decode(b)
	if p == nil {
		die("no PEM in %s", path)
	}
	return p.Bytes
}

func oid(s string) asn1.ObjectIdentifier {
	var o asn1.ObjectIdentifier
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			die("bad OID %s", s)
		}
		o = append(o, n)
	}
	return o
}

func hashOf(n string) crypto.Hash {
	switch n {
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	}
	return crypto.SHA256
}

func main() {
	if len(os.Args) < 2 {
		die("usage: gotsa serve|query|verify ...")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "")
	certf := fs.String("cert", "", "")
	keyf := fs.String("key", "", "")
	policy := fs.String("policy", "1.3.6.1.4.1.99999.1", "")
	data := fs.String("data", "", "")
	hash := fs.String("hash", "sha256", "")
	out := fs.String("out", "", "")
	reply := fs.String("reply", "", "")
	query := fs.String("query", "", "")
	fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "serve":
		cert, err := x509.ParseCertificate(pemBlock(*certf))
		if err != nil {
			die("%v", err)
		}
		kb := pemBlock(*keyf)
		var signer crypto.Signer
		if k, err := x509.ParseECPrivateKey(kb); err == nil {
			signer = k
		} else if k, err := x509.ParsePKCS8PrivateKey(kb); err == nil {
			signer = k.(crypto.Signer)
		} else {
			die("key: %v", err)
		}
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			req, err := timestamp.ParseRequest(body)
			var resp []byte
			if err != nil {
				resp, _ = timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.BadDataFormat)
			} else {
				pol := oid(*policy)
				if len(req.TSAPolicyOID) > 0 {
					pol = req.TSAPolicyOID
				}
				ts := timestamp.Timestamp{HashAlgorithm: req.HashAlgorithm, HashedMessage: req.HashedMessage, Time: time.Now(),
					Nonce: req.Nonce, Policy: pol, Ordering: true, Accuracy: time.Second, AddTSACertificate: req.Certificates}
				resp, err = ts.CreateResponseWithOpts(cert, signer, crypto.SHA256)
				if err != nil {
					die("%v", err)
				}
			}
			w.Header().Set("Content-Type", "application/timestamp-reply")
			w.Write(resp)
		})
		fmt.Println("listening on", *addr)
		die("%v", http.ListenAndServe(*addr, nil))
	case "query":
		f, err := os.Open(*data)
		if err != nil {
			die("%v", err)
		}
		q, err := timestamp.CreateRequest(f, &timestamp.RequestOptions{Hash: hashOf(*hash), Certificates: true})
		if err != nil {
			die("%v", err)
		}
		os.WriteFile(*out, q, 0o644)
	case "verify":
		rb, _ := os.ReadFile(*reply)
		ts, err := timestamp.ParseResponse(rb)
		if err != nil {
			die("parse/verify: %v", err)
		}
		qb, _ := os.ReadFile(*query)
		req, err := timestamp.ParseRequest(qb)
		if err != nil {
			die("query: %v", err)
		}
		if !bytes.Equal(ts.HashedMessage, req.HashedMessage) || ts.HashAlgorithm != req.HashAlgorithm {
			die("imprint differs")
		}
		if req.Nonce != nil && (ts.Nonce == nil || ts.Nonce.Cmp(req.Nonce) != 0) {
			die("nonce differs")
		}
		if req.Certificates && len(ts.Certificates) == 0 {
			die("no certificate")
		}
		fmt.Printf("ok: %s serial %s policy %v ordering %v accuracy %v\n", ts.Time.UTC().Format(time.RFC3339Nano), ts.SerialNumber, ts.Policy, ts.Ordering, ts.Accuracy)
	default:
		die("unknown command")
	}
}
