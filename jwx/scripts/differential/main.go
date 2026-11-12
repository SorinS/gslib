// differential: gslib's jwx against Go's lestrrat-go/jwx (v3), both ways.
//
//	go run . gen [-n N] > ../../test/vectors/go_jwx.txt
//	    tokens made by Go's jwx, for test/go_jwx.goose to verify and decrypt
//	go run . check < tokens.txt
//	    tokens made by gslib (tools/tokens.goose), verified and decrypted here
//
// One message per line, tab-separated: kind (jws, jws-json, jwe, jwe-json),
// algorithm, content encryption ("-" for none), zip (0 or 1), the private
// JWK, the payload, the message.
package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

var sigAlgs = []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512", "EdDSA"}

var keyAlgs = []string{"RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512",
	"A128KW", "A192KW", "A256KW", "dir", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
	"A128GCMKW", "A192GCMKW", "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"}

var encs = []string{"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"}

var cekLen = map[string]int{"A128CBC-HS256": 32, "A192CBC-HS384": 48, "A256CBC-HS512": 64,
	"A128GCM": 16, "A192GCM": 24, "A256GCM": 32}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func random(n int) []byte {
	b := make([]byte, n)
	must(rand.Read(b))
	return b
}

var rsaKey = must(rsa.GenerateKey(rand.Reader, 2048))

// A raw private key for a signature algorithm.
func sigKey(alg string) any {
	switch {
	case strings.HasPrefix(alg, "HS"):
		return random(64)
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return rsaKey
	case alg == "ES256":
		return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	case alg == "ES384":
		return must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	case alg == "ES512":
		return must(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
	default:
		_, k := must2(ed25519.GenerateKey(rand.Reader))
		return k
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

// A raw private key for a key management algorithm; i picks the curve.
func encKey(alg, enc string, i int) any {
	switch {
	case strings.HasPrefix(alg, "RSA"):
		return rsaKey
	case alg == "dir":
		return random(cekLen[enc])
	case strings.HasPrefix(alg, "ECDH-ES"):
		switch i % 4 {
		case 0:
			return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
		case 1:
			return must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
		case 2:
			return must(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
		default:
			return must(ecdh.X25519().GenerateKey(rand.Reader))
		}
	case strings.HasPrefix(alg, "PBES2"):
		return []byte(fmt.Sprintf("password %d", i))
	case strings.HasPrefix(alg, "A128"):
		return random(16)
	case strings.HasPrefix(alg, "A192"):
		return random(24)
	default:
		return random(32)
	}
}

func payload(i int) string {
	return fmt.Sprintf("{\"iss\":\"go\",\"n\":%d,\"text\":\"%s\"}", i, strings.Repeat("goose ", i%7))
}

func line(kind, alg, enc string, zip bool, key jwk.Key, pl string, msg []byte) {
	z := "0"
	if zip {
		z = "1"
	}
	fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", kind, alg, enc, z, must(json.Marshal(key)), pl, msg)
}

func gen(n int) {
	for r := 0; r < n; r++ {
		for i, name := range sigAlgs {
			alg := must1(jwa.LookupSignatureAlgorithm(name))
			key := must(jwk.Import(sigKey(name)))
			pl := payload(r*100 + i)
			line("jws", name, "-", false, key, pl, must(jws.Sign([]byte(pl), jws.WithKey(alg, key))))
			line("jws-json", name, "-", false, key, pl, must(jws.Sign([]byte(pl), jws.WithKey(alg, key), jws.WithJSON())))
		}
		for i, name := range keyAlgs {
			alg := must1(jwa.LookupKeyEncryptionAlgorithm(name))
			for j, encName := range encs {
				enc := must1(jwa.LookupContentEncryptionAlgorithm(encName))
				key := must(jwk.Import(encKey(name, encName, i+j+r)))
				pub := key
				if !strings.HasPrefix(name, "A") && name != "dir" && !strings.HasPrefix(name, "PBES2") {
					pub = must(jwk.PublicKeyOf(key))
				}
				pl := payload(r*1000 + i*10 + j)
				zip := (i+j+r)%3 == 0
				opts := []jwe.EncryptOption{jwe.WithKey(alg, pub), jwe.WithContentEncryption(enc)}
				if zip {
					opts = append(opts, jwe.WithCompress(jwa.Deflate()))
				}
				line("jwe", name, encName, zip, key, pl, must(jwe.Encrypt([]byte(pl), opts...)))
				if (i+j)%4 == 0 {
					line("jwe-json", name, encName, zip, key, pl, must(jwe.Encrypt([]byte(pl), append(opts, jwe.WithJSON())...)))
				}
			}
		}
	}
}

func must1[T any](v T, ok bool) T {
	if !ok {
		panic("unknown algorithm")
	}
	return v
}

func check() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	pass, fail := 0, 0
	for in.Scan() {
		f := strings.Split(in.Text(), "\t")
		if len(f) != 7 {
			continue
		}
		kind, name, pl, msg := f[0], f[1], f[5], []byte(f[6])
		key, err := jwk.ParseKey([]byte(f[4]))
		var got []byte
		if err == nil {
			if strings.HasPrefix(kind, "jws") {
				alg := must1(jwa.LookupSignatureAlgorithm(name))
				pub := key
				if !strings.HasPrefix(name, "HS") {
					pub = must(jwk.PublicKeyOf(key))
				}
				got, err = jws.Verify(msg, jws.WithKey(alg, pub))
			} else {
				alg := must1(jwa.LookupKeyEncryptionAlgorithm(name))
				got, err = jwe.Decrypt(msg, jwe.WithKey(alg, key))
			}
		}
		if err == nil && string(got) != pl {
			err = fmt.Errorf("payload differs: %q", got)
		}
		if err != nil {
			fail++
			if fail <= 20 {
				fmt.Printf("FAIL %s %s %s: %v\n", kind, name, f[2], err)
			}
		} else {
			pass++
		}
	}
	fmt.Printf("go jwx: %d verified or decrypted, %d failed\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: differential gen [-n N] | check")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	n := fs.Int("n", 1, "rounds")
	fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "gen":
		gen(*n)
	case "check":
		check()
	default:
		fmt.Fprintln(os.Stderr, "usage: differential gen [-n N] | check")
		os.Exit(2)
	}
}
