// crewjam: crewjam/saml's identity provider (samlidp) and service
// provider (samlsp) as small servers for saml/scripts/interop.py, on
// 127.0.0.1 with the keys of saml/test/data.
//
//	crewjam idp -url http://127.0.0.1:8102 -key idp.key -cert idp.crt
//	crewjam sp  -url http://127.0.0.1:8103 -key sp.key -cert sp.crt -idp-metadata FILE [-sign-request] [-post]
//
// The IdP has one user, alice (password hunter2); service providers are
// registered by PUT /services/NAME with their metadata. The SP serves
// /hello (needs a login; prints the session's attributes as JSON),
// /saml/ (metadata, ACS, SLO) and /logout.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
	"github.com/crewjam/saml/samlsp"
	"golang.org/x/crypto/bcrypt"
)

func keyPair(keyFile, certFile string) (*rsa.PrivateKey, *x509.Certificate) {
	kp, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	key, ok := kp.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("the key must be RSA")
	}
	return key, cert
}

func serve(addr string, h http.Handler) {
	server := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func runIDP(args []string) {
	fs := flag.NewFlagSet("idp", flag.ExitOnError)
	base := fs.String("url", "http://127.0.0.1:8102", "the IdP's URL")
	keyFile := fs.String("key", "", "the IdP's key (PEM)")
	certFile := fs.String("cert", "", "the IdP's certificate (PEM)")
	fs.Parse(args)
	u, err := url.Parse(*base)
	if err != nil {
		log.Fatal(err)
	}
	key, cert := keyPair(*keyFile, *certFile)
	s, err := samlidp.New(samlidp.Options{URL: *u, Key: key, Logger: logger.DefaultLogger, Certificate: cert, Store: &samlidp.MemoryStore{}})
	if err != nil {
		log.Fatal(err)
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		log.Fatal(err)
	}
	if err := s.Store.Put("/users/alice", samlidp.User{Name: "alice", HashedPassword: hashed, Groups: []string{"Administrators", "Users"},
		Email: "alice@example.test", CommonName: "Alice Smith", Surname: "Smith", GivenName: "Alice"}); err != nil {
		log.Fatal(err)
	}
	serve(u.Host, s)
}

func runSP(args []string) {
	fs := flag.NewFlagSet("sp", flag.ExitOnError)
	base := fs.String("url", "http://127.0.0.1:8103", "the SP's URL")
	keyFile := fs.String("key", "", "the SP's key (PEM)")
	certFile := fs.String("cert", "", "the SP's certificate (PEM)")
	idpMetadata := fs.String("idp-metadata", "", "the IdP's metadata")
	signRequest := fs.Bool("sign-request", false, "sign AuthnRequests")
	post := fs.Bool("post", false, "send AuthnRequests by HTTP-POST")
	idpInitiated := fs.Bool("idp-initiated", false, "allow IdP-initiated logins")
	fs.Parse(args)
	u, err := url.Parse(*base)
	if err != nil {
		log.Fatal(err)
	}
	key, cert := keyPair(*keyFile, *certFile)
	data, err := os.ReadFile(*idpMetadata)
	if err != nil {
		log.Fatal(err)
	}
	md, err := samlsp.ParseMetadata(data)
	if err != nil {
		log.Fatal(err)
	}
	opts := samlsp.Options{URL: *u, Key: crypto.Signer(key), Certificate: cert, IDPMetadata: md, SignRequest: *signRequest,
		AllowIDPInitiated: *idpInitiated, LogoutBindings: []string{saml.HTTPPostBinding, saml.HTTPRedirectBinding}}
	m, err := samlsp.New(opts)
	if err != nil {
		log.Fatal(err)
	}
	if *post {
		m.Binding = saml.HTTPPostBinding
	}
	mux := http.NewServeMux()
	mux.Handle("/hello", m.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := samlsp.SessionFromContext(r.Context())
		out := map[string]interface{}{"ok": true}
		if sa, ok := s.(samlsp.SessionWithAttributes); ok {
			out["attributes"] = sa.GetAttributes()
		}
		if js, ok := s.(samlsp.JWTSessionClaims); ok {
			out["subject"] = js.Subject
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})))
	mux.Handle("/saml/", m)
	// Where the middleware sends the browser after a logout.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("home\n"))
	})
	mux.HandleFunc("/logout", m.HandleStartLogout)
	serve(u.Host, mux)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: crewjam idp|sp [flags]")
	}
	switch os.Args[1] {
	case "idp":
		runIDP(os.Args[2:])
	case "sp":
		runSP(os.Args[2:])
	default:
		log.Fatal("usage: crewjam idp|sp [flags]")
	}
}
