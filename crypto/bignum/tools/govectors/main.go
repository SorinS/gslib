// Govectors writes test vectors from Go's golang.org/x/crypto for the
// packages bignum matches: MD4, RIPEMD-160, Salsa20 and XSalsa20, HSalsa20,
// NaCl secretbox, box (and its anonymous form), sign and auth, bcrypt,
// Blowfish, CAST5, Twofish, TEA, XTEA, AES-XTS and bcrypt_pbkdf.
//
// It prints one line a case: the family's name, then its inputs and
// outputs, byte strings in hex ("-" when empty). The random stream is
// seeded, so the output is always the same, bcrypt's hashes aside: their
// salts come from crypto/rand.
//
// Usage:
//
//	govectors > test/vectors/xcrypto.txt
//	govectors -check test/vectors/xcrypto.txt
//	govectors -version
//
// With -check it compares the file with what it would print instead: every
// line must be the same, except that a bcrypt line's hash need only be one
// bcrypt accepts for that password and cost.
//
// Errors go to stderr: a bad command line exits 2, anything else 1.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/nacl/auth"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/salsa20/salsa"
	"golang.org/x/crypto/tea"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xtea"
	"golang.org/x/crypto/xts"
)

const version = "1.0.0"

// seed fixes the random stream, and with it the vectors.
var seed = [32]byte{'g', 'o', 'o', 's', 'e'}

// hashLengths are message lengths around the 64-byte block boundaries.
var hashLengths = []int{0, 1, 3, 31, 32, 33, 55, 56, 57, 63, 64, 65, 100, 127, 128, 129, 1000}

// maxReported is how many differing lines -check prints.
const maxReported = 10

func main() {
	var checkFile string
	var showVersion bool
	flag.StringVar(&checkFile, "check", "", "compare with this `file` instead of printing the vectors")
	flag.BoolVar(&showVersion, "version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: govectors [-check file | -version]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "govectors: unexpected argument %q\n", flag.Arg(0))
		flag.Usage()
		os.Exit(2)
	}

	if showVersion {
		fmt.Println(versionString())
		return
	}
	var err error
	if checkFile != "" {
		err = check(checkFile)
	} else {
		err = generate(os.Stdout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "govectors: %v\n", err)
		os.Exit(1)
	}
}

// versionString is this program's version, the Go it was built with and,
// when go build stamped it, the commit it was built from.
func versionString() string {
	s := fmt.Sprintf("govectors %s %s %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return s
	}
	var rev string
	var dirty bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			rev = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if rev == "" {
		return s
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "+dirty"
	}
	return s + " " + rev
}

// generate writes every vector to w.
func generate(w io.Writer) error {
	g := &generator{rng: rand.New(rand.NewChaCha8(seed)), w: bufio.NewWriter(w)}
	// The order is the random stream's: changing it changes the vectors.
	steps := []func() error{
		g.hashes, g.salsa20, g.hsalsa20, g.secretbox, g.box, g.sign, g.auth, g.bcrypt,
		g.blockCiphers, g.xts, g.bcryptPBKDF,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return g.w.Flush()
}

// A generator draws its inputs from a seeded stream and writes the cases.
type generator struct {
	rng *rand.Rand
	w   *bufio.Writer // sticky: a write error comes back from Flush
}

// bytes returns n bytes from the stream.
func (g *generator) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(g.rng.Uint32())
	}
	return b
}

// key32 returns 32 bytes from the stream, as the arrays NaCl takes.
func (g *generator) key32() *[32]byte {
	var k [32]byte
	copy(k[:], g.bytes(32))
	return &k
}

// nonce24 returns 24 bytes from the stream.
func (g *generator) nonce24() *[24]byte {
	var n [24]byte
	copy(n[:], g.bytes(24))
	return &n
}

// line writes one case: byte strings in hex, "-" when empty, the rest as fmt prints them.
func (g *generator) line(fields ...any) {
	for i, f := range fields {
		if i > 0 {
			g.w.WriteByte(' ')
		}
		switch v := f.(type) {
		case []byte:
			if len(v) == 0 {
				g.w.WriteByte('-')
			} else {
				g.w.WriteString(hex.EncodeToString(v))
			}
		default:
			fmt.Fprint(g.w, v)
		}
	}
	g.w.WriteByte('\n')
}

func (g *generator) hashes() error {
	for _, n := range hashLengths {
		m := g.bytes(n)
		d4 := md4.New()
		d4.Write(m)
		g.line("md4", m, d4.Sum(nil))
		d160 := ripemd160.New()
		d160.Write(m)
		g.line("ripemd160", m, d160.Sum(nil))
	}
	return nil
}

// salsa20 covers Salsa20 (8-byte nonces) and XSalsa20 (24-byte ones).
func (g *generator) salsa20() error {
	for _, nonceLen := range []int{8, 24} {
		for _, n := range []int{0, 1, 63, 64, 65, 200} {
			key := g.key32()
			nonce := g.bytes(nonceLen)
			m := g.bytes(n)
			out := make([]byte, n)
			salsa20.XORKeyStream(out, m, nonce, key)
			g.line("salsa20", key[:], nonce, m, out)
		}
	}
	return nil
}

func (g *generator) hsalsa20() error {
	for range 3 {
		key := g.key32()
		var in [16]byte
		copy(in[:], g.bytes(16))
		var out [32]byte
		salsa.HSalsa20(&out, &in, key, &salsa.Sigma)
		g.line("hsalsa20", key[:], in[:], out[:])
	}
	return nil
}

func (g *generator) secretbox() error {
	for _, n := range []int{0, 1, 31, 32, 33, 64, 100} {
		key := g.key32()
		nonce := g.nonce24()
		m := g.bytes(n)
		g.line("secretbox", key[:], nonce[:], m, secretbox.Seal(nil, m, nonce, key))
	}
	return nil
}

// box covers box.Seal and box.SealAnonymous, with keys from the stream.
func (g *generator) box() error {
	for _, n := range []int{0, 5, 40, 100} {
		pubA, privA, err := box.GenerateKey(bytes.NewReader(g.bytes(32)))
		if err != nil {
			return fmt.Errorf("box: %w", err)
		}
		pubB, privB, err := box.GenerateKey(bytes.NewReader(g.bytes(32)))
		if err != nil {
			return fmt.Errorf("box: %w", err)
		}
		nonce := g.nonce24()
		m := g.bytes(n)
		g.line("box", privA[:], pubA[:], privB[:], pubB[:], nonce[:], m, box.Seal(nil, m, nonce, pubB, privA))

		ephemeral := g.bytes(32)
		sealed, err := box.SealAnonymous(nil, m, pubB, bytes.NewReader(ephemeral))
		if err != nil {
			return fmt.Errorf("box anonymous: %w", err)
		}
		g.line("anon", privB[:], pubB[:], ephemeral, m, sealed)
	}
	return nil
}

func (g *generator) sign() error {
	for _, n := range []int{0, 1, 64, 100} {
		priv := ed25519.NewKeyFromSeed(g.bytes(32))
		pub := priv.Public().(ed25519.PublicKey)
		m := g.bytes(n)
		g.line("sign", []byte(priv), []byte(pub), m, sign.Sign(nil, m, (*[64]byte)(priv)))
	}
	return nil
}

func (g *generator) auth() error {
	for _, n := range []int{0, 1, 100} {
		key := g.key32()
		m := g.bytes(n)
		g.line("auth", key[:], m, auth.Sum(m, key)[:])
	}
	return nil
}

func (g *generator) bcrypt() error {
	passwords := [][]byte{{}, []byte("U*U"), []byte("password"), g.bytes(40), g.bytes(72)}
	for i, pw := range passwords {
		cost := 4 + i%3
		hash, err := bcrypt.GenerateFromPassword(pw, cost)
		if err != nil {
			return fmt.Errorf("bcrypt: %w", err)
		}
		g.line("bcrypt", pw, cost, string(hash))
	}
	return nil
}

func (g *generator) blockCiphers() error {
	for _, keyLen := range []int{4, 16, 56} {
		key := g.bytes(keyLen)
		c, err := blowfish.NewCipher(key)
		if err != nil {
			return fmt.Errorf("blowfish: %w", err)
		}
		if err := g.blocks("blowfish", c, key); err != nil {
			return err
		}
	}

	key := g.bytes(16)
	c5, err := cast5.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cast5: %w", err)
	}
	if err := g.blocks("cast5", c5, key); err != nil {
		return err
	}

	for _, keyLen := range []int{16, 24, 32} {
		key := g.bytes(keyLen)
		c, err := twofish.NewCipher(key)
		if err != nil {
			return fmt.Errorf("twofish: %w", err)
		}
		if err := g.blocks("twofish", c, key); err != nil {
			return err
		}
	}

	for _, rounds := range []int{64, 32} {
		key := g.bytes(16)
		c, err := tea.NewCipherWithRounds(key, rounds)
		if err != nil {
			return fmt.Errorf("tea: %w", err)
		}
		if err := g.blocks("tea", c, key, rounds); err != nil {
			return err
		}
	}

	key = g.bytes(16)
	cx, err := xtea.NewCipher(key)
	if err != nil {
		return fmt.Errorf("xtea: %w", err)
	}
	return g.blocks("xtea", cx, key)
}

// blocks writes four blocks through c both ways, then three blocks of
// CBC. params go after the key: a cipher's other parameters.
func (g *generator) blocks(name string, c cipher.Block, key []byte, params ...any) error {
	head := append([]any{name, key}, params...)
	for range 4 {
		pt := g.bytes(c.BlockSize())
		ct := make([]byte, len(pt))
		c.Encrypt(ct, pt)
		back := make([]byte, len(pt))
		c.Decrypt(back, ct)
		if !bytes.Equal(back, pt) {
			return fmt.Errorf("%s: decrypting %x gives %x, not %x", name, ct, back, pt)
		}
		g.line(append(head[:len(head):len(head)], pt, ct)...)
	}
	iv := g.bytes(c.BlockSize())
	pt := g.bytes(3 * c.BlockSize())
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(ct, pt)
	head[0] = name + "-cbc"
	g.line(append(head, iv, pt, ct)...)
	return nil
}

// xts covers AES-XTS with AES-128 and AES-256, at random sector numbers
// of every size.
func (g *generator) xts() error {
	for _, keyLen := range []int{32, 64} {
		key := g.bytes(keyLen)
		c, err := xts.NewCipher(aes.NewCipher, key)
		if err != nil {
			return fmt.Errorf("xts: %w", err)
		}
		for _, n := range []int{16, 32, 64, 512} {
			sector := g.rng.Uint64() >> g.rng.IntN(64)
			pt := g.bytes(n)
			ct := make([]byte, n)
			c.Encrypt(ct, pt, sector)
			g.line("xts", key, sector, pt, ct)
		}
	}
	return nil
}

// bcryptPBKDF covers OpenBSD's three vectors (Go's tests), then lengths
// around its 32-byte blocks and the 48 bytes of aes256-ctr's key and IV.
func (g *generator) bcryptPBKDF() error {
	type pbkdfCase struct {
		password, salt []byte
		rounds, keyLen int
	}
	cases := []pbkdfCase{
		{[]byte("password"), []byte("salt"), 12, 32},
		{[]byte("passwordy\x00PASSWORD\x00"), []byte("salty\x00SALT\x00"), 3, 32},
		{[]byte("секретное слово"), []byte("посолить немножко"), 8, 88},
	}
	for i, keyLen := range []int{1, 16, 31, 32, 33, 48, 64, 65, 100} {
		password := g.bytes(1 + g.rng.IntN(40))
		cases = append(cases, pbkdfCase{password, g.bytes(16), 1 + i%3, keyLen})
	}
	cases = append(cases, pbkdfCase{g.bytes(72), g.bytes(1), 16, 48})
	for _, c := range cases {
		key, err := bcryptPBKDF(c.password, c.salt, c.rounds, c.keyLen)
		if err != nil {
			return err
		}
		g.line("bcrypt_pbkdf", c.password, c.salt, c.rounds, key)
	}
	return nil
}

// check compares the vectors in path with the ones generate writes.
func check(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := generate(&buf); err != nil {
		return err
	}
	want := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	got := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(want) != len(got) {
		return fmt.Errorf("%s has %d lines, Go gives %d", path, len(want), len(got))
	}

	differ := 0
	for i := range want {
		if err := sameCase(want[i], got[i]); err != nil {
			if differ < maxReported {
				fmt.Fprintf(os.Stderr, "%s:%d: %v\n", path, i+1, err)
			}
			differ++
		}
	}
	if differ > 0 {
		return fmt.Errorf("%s: %d of %d lines differ from Go's", path, differ, len(want))
	}
	fmt.Printf("%s matches Go's (%d lines)\n", path, len(want))
	return nil
}

// sameCase reports how line, from the file, differs from Go's: a bcrypt
// line by its password and cost, and its hash checked against them.
func sameCase(line, goLine string) error {
	if line == goLine {
		return nil
	}
	fields, goFields := strings.Fields(line), strings.Fields(goLine)
	if len(fields) != 4 || fields[0] != "bcrypt" || len(goFields) != 4 || goFields[0] != "bcrypt" ||
		fields[1] != goFields[1] || fields[2] != goFields[2] {
		return fmt.Errorf("%q, Go gives %q", line, goLine)
	}
	password, err := decodeField(fields[1])
	if err != nil {
		return fmt.Errorf("bcrypt password: %w", err)
	}
	cost, err := strconv.Atoi(fields[2])
	if err != nil {
		return fmt.Errorf("bcrypt cost: %w", err)
	}
	hash := []byte(fields[3])
	if got, err := bcrypt.Cost(hash); err != nil || got != cost {
		return fmt.Errorf("bcrypt hash %s is not of cost %d", hash, cost)
	}
	if err := bcrypt.CompareHashAndPassword(hash, password); err != nil {
		return fmt.Errorf("bcrypt hash %s: %w", hash, err)
	}
	return nil
}

// decodeField reads a byte string as line writes it.
func decodeField(s string) ([]byte, error) {
	if s == "-" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// bcryptPBKDF and bcryptHash are x/crypto/ssh/internal/bcrypt_pbkdf
// (v0.55.0), which cannot be imported from outside x/crypto: bcrypt_pbkdf(3)
// from OpenBSD, as https://flak.tedunangst.com/post/bcrypt-pbkdf describes
// it. Its panic is an error here. Its license:
//
// Copyright 2014 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   - Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   - Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following disclaimer
//     in the documentation and/or other materials provided with the
//     distribution.
//   - Neither the name of Google LLC nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

const pbkdfBlockSize = 32

var pbkdfMagic = []byte("OxychromaticBlowfishSwatDynamite")

// bcryptPBKDF derives keyLen bytes from the password, salt and rounds count.
func bcryptPBKDF(password, salt []byte, rounds, keyLen int) ([]byte, error) {
	if rounds < 1 {
		return nil, errors.New("bcrypt_pbkdf: number of rounds is too small")
	}
	if len(password) == 0 {
		return nil, errors.New("bcrypt_pbkdf: empty password")
	}
	if len(salt) == 0 || len(salt) > 1<<20 {
		return nil, errors.New("bcrypt_pbkdf: bad salt length")
	}
	if keyLen > 1024 {
		return nil, errors.New("bcrypt_pbkdf: keyLen is too large")
	}

	numBlocks := (keyLen + pbkdfBlockSize - 1) / pbkdfBlockSize
	key := make([]byte, numBlocks*pbkdfBlockSize)

	h := sha512.New()
	h.Write(password)
	shapass := h.Sum(nil)

	shasalt := make([]byte, 0, sha512.Size)
	cnt, tmp := make([]byte, 4), make([]byte, pbkdfBlockSize)
	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(salt)
		cnt[0] = byte(block >> 24)
		cnt[1] = byte(block >> 16)
		cnt[2] = byte(block >> 8)
		cnt[3] = byte(block)
		h.Write(cnt)
		if err := bcryptHash(tmp, shapass, h.Sum(shasalt)); err != nil {
			return nil, err
		}

		out := make([]byte, pbkdfBlockSize)
		copy(out, tmp)
		for i := 2; i <= rounds; i++ {
			h.Reset()
			h.Write(tmp)
			if err := bcryptHash(tmp, shapass, h.Sum(shasalt)); err != nil {
				return nil, err
			}
			for j := 0; j < len(out); j++ {
				out[j] ^= tmp[j]
			}
		}

		for i, v := range out {
			key[i*numBlocks+(block-1)] = v
		}
	}
	return key[:keyLen], nil
}

func bcryptHash(out, shapass, shasalt []byte) error {
	c, err := blowfish.NewSaltedCipher(shapass, shasalt)
	if err != nil {
		return fmt.Errorf("bcrypt_pbkdf: %w", err)
	}
	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(shasalt, c)
		blowfish.ExpandKey(shapass, c)
	}
	copy(out, pbkdfMagic)
	for i := 0; i < 32; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	// Swap bytes due to different endianness.
	for i := 0; i < 32; i += 4 {
		out[i+3], out[i+2], out[i+1], out[i] = out[i], out[i+1], out[i+2], out[i+3]
	}
	return nil
}
