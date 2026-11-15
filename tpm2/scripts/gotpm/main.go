// gotpm: go-tpm (github.com/google/go-tpm/tpm2) as an independent oracle for
// tpm2's differential (scripts/differential.py). Each line of the file
// named on the command line is a case; each output line its answer, in hex,
// or "error".
//
//	kdfa HASH KEY LABEL U V BITS      KDFa
//	kdfe HASH Z LABEL U V BITS        KDFe
//	pubname TPMT_PUBLIC               the object's Name (the bytes re-marshalled first)
//	nvname TPMS_NV_PUBLIC             the NV index's Name
//	policy HASH OP...                 a policy digest: pcr:SEL:DIGEST secret:NAME:REF
//	                                  signed:NAME:REF authvalue cc:N or:D1.D2... authorize:NAME:REF
//
// HASH is a TPM_ALG_ID in hex (000b); every other argument is hex, "-" for empty.
package main

import (
	"bufio"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

func hx(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func alg(s string) tpm2.TPMIAlgHash {
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		panic(err)
	}
	return tpm2.TPMIAlgHash(v)
}

func hashOf(a tpm2.TPMIAlgHash) crypto.Hash {
	h, err := a.Hash()
	if err != nil {
		panic(err)
	}
	return h
}

func one(f []string) (string, error) {
	switch f[0] {
	case "kdfa", "kdfe":
		bits, _ := strconv.Atoi(f[6])
		h := hashOf(alg(f[1]))
		if f[0] == "kdfa" {
			return hex.EncodeToString(tpm2.KDFa(h, hx(f[2]), string(hx(f[3])), hx(f[4]), hx(f[5]), bits)), nil
		}
		return hex.EncodeToString(tpm2.KDFe(h, hx(f[2]), string(hx(f[3])), hx(f[4]), hx(f[5]), bits)), nil
	case "pubname":
		p, err := tpm2.Unmarshal[tpm2.TPMTPublic](hx(f[1]))
		if err != nil {
			return "", err
		}
		n, err := tpm2.ObjectName(p)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(n.Buffer) + " " + hex.EncodeToString(tpm2.Marshal(p)), nil
	case "nvname":
		p, err := tpm2.Unmarshal[tpm2.TPMSNVPublic](hx(f[1]))
		if err != nil {
			return "", err
		}
		n, err := tpm2.NVName(p)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(n.Buffer), nil
	case "policy":
		calc, err := tpm2.NewPolicyCalculator(alg(f[1]))
		if err != nil {
			return "", err
		}
		for _, op := range f[2:] {
			a := strings.Split(op, ":")
			named := func(s string) tpm2.NamedHandle { return tpm2.NamedHandle{Name: tpm2.TPM2BName{Buffer: hx(s)}} }
			switch a[0] {
			case "pcr":
				sel, err := tpm2.Unmarshal[tpm2.TPMLPCRSelection](hx(a[1]))
				if err != nil {
					return "", err
				}
				err = tpm2.PolicyPCR{Pcrs: *sel, PcrDigest: tpm2.TPM2BDigest{Buffer: hx(a[2])}}.Update(calc)
			case "secret":
				err = tpm2.PolicySecret{AuthHandle: named(a[1]), PolicyRef: tpm2.TPM2BNonce{Buffer: hx(a[2])}}.Update(calc)
			case "signed":
				err = tpm2.PolicySigned{AuthObject: named(a[1]), PolicyRef: tpm2.TPM2BNonce{Buffer: hx(a[2])}}.Update(calc)
			case "authvalue":
				err = tpm2.PolicyAuthValue{}.Update(calc)
			case "cc":
				n, _ := strconv.ParseUint(a[1], 10, 32)
				err = tpm2.PolicyCommandCode{Code: tpm2.TPMCC(n)}.Update(calc)
			case "or":
				var l tpm2.TPMLDigest
				for _, d := range strings.Split(a[1], ".") {
					l.Digests = append(l.Digests, tpm2.TPM2BDigest{Buffer: hx(d)})
				}
				err = tpm2.PolicyOr{PHashList: l}.Update(calc)
			case "authorize":
				// go-tpm extends the digest it has; the TPM starts PolicyAuthorize
				// from zeros (Part 3 §23.16), so the cases put it first.
				err = tpm2.PolicyAuthorize{KeySign: tpm2.TPM2BName{Buffer: hx(a[1])}, PolicyRef: tpm2.TPM2BDigest{Buffer: hx(a[2])}}.Update(calc)
			default:
				return "", fmt.Errorf("unknown op %q", a[0])
			}
			if err != nil {
				return "", err
			}
		}
		return hex.EncodeToString(calc.Hash().Digest), nil
	}
	return "", fmt.Errorf("unknown case %q", f[0])
}

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		out, err := one(strings.Fields(sc.Text()))
		if err != nil {
			fmt.Fprintln(w, "error")
			continue
		}
		fmt.Fprintln(w, out)
	}
}
