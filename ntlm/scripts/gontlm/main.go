package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Azure/go-ntlmssp"
)

func main() {
	client := &http.Client{Transport: ntlmssp.Negotiator{RoundTripper: &http.Transport{}}}
	req, _ := http.NewRequest("GET", os.Args[1], nil)
	req.SetBasicAuth(os.Args[2], os.Getenv("NTLM_TEST_PW"))
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	b, _ := io.ReadAll(res.Body)
	fmt.Printf("%d %s", res.StatusCode, b)
}
