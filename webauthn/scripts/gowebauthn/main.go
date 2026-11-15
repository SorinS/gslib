// gowebauthn: go-webauthn (github.com/go-webauthn/webauthn) as a relying
// party for webauthn/scripts/interop.py, one ceremony step per run.
//
//	gowebauthn begin-registration RPID ORIGIN USERID_B64URL              -> {"options":..., "session":...}
//	gowebauthn finish-registration RPID ORIGIN SESSION.json RESPONSE.json -> the credential, as JSON
//	gowebauthn begin-login RPID ORIGIN CREDENTIAL.json USERID_B64URL     -> {"options":..., "session":...}
//	gowebauthn finish-login RPID ORIGIN SESSION.json CREDENTIAL.json USERID_B64URL RESPONSE.json -> the credential
//	gowebauthn parse-creation-options OPTIONS.json                        -> a summary of what it read
//	gowebauthn parse-request-options OPTIONS.json
//
// Errors go to stderr, with exit status 1.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type user struct {
	id    []byte
	creds []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.id }
func (u *user) WebAuthnName() string                       { return "alice" }
func (u *user) WebAuthnDisplayName() string                { return "Alice" }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func die(err error) {
	fmt.Fprintln(os.Stderr, "gowebauthn:", err)
	os.Exit(1)
}

func rp(id, origin string) *webauthn.WebAuthn {
	w, err := webauthn.New(&webauthn.Config{RPID: id, RPDisplayName: "interop", RPOrigins: []string{origin},
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore})
	if err != nil {
		die(err)
	}
	return w
}

func read(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		die(err)
	}
	return b
}

func b64(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		die(err)
	}
	return b
}

func out(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		die(err)
	}
	fmt.Println(string(b))
}

func main() {
	a := os.Args[1:]
	if len(a) == 0 {
		die(fmt.Errorf("no command"))
	}
	switch a[0] {
	case "begin-registration":
		w := rp(a[1], a[2])
		u := &user{id: b64(a[3])}
		opts, session, err := w.BeginRegistration(u, webauthn.WithAttestationFormats([]protocol.AttestationFormat{}))
		if err != nil {
			die(err)
		}
		out(map[string]any{"options": opts.Response, "session": session})
	case "finish-registration":
		w := rp(a[1], a[2])
		var session webauthn.SessionData
		if err := json.Unmarshal(read(a[3]), &session); err != nil {
			die(err)
		}
		parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(read(a[4])))
		if err != nil {
			die(err)
		}
		cred, err := w.CreateCredential(&user{id: session.UserID}, session, parsed)
		if err != nil {
			die(err)
		}
		out(cred)
	case "begin-login":
		w := rp(a[1], a[2])
		var cred webauthn.Credential
		if err := json.Unmarshal(read(a[3]), &cred); err != nil {
			die(err)
		}
		u := &user{id: b64(a[4]), creds: []webauthn.Credential{cred}}
		opts, session, err := w.BeginLogin(u)
		if err != nil {
			die(err)
		}
		out(map[string]any{"options": opts.Response, "session": session})
	case "finish-login":
		w := rp(a[1], a[2])
		var session webauthn.SessionData
		if err := json.Unmarshal(read(a[3]), &session); err != nil {
			die(err)
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(read(a[4]), &cred); err != nil {
			die(err)
		}
		parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(read(a[6])))
		if err != nil {
			die(err)
		}
		got, err := w.ValidateLogin(&user{id: b64(a[5]), creds: []webauthn.Credential{cred}}, session, parsed)
		if err != nil {
			die(err)
		}
		out(got)
	case "parse-creation-options":
		var o protocol.PublicKeyCredentialCreationOptions
		if err := json.Unmarshal(read(a[1]), &o); err != nil {
			die(err)
		}
		algs := []int{}
		for _, p := range o.Parameters {
			algs = append(algs, int(p.Algorithm))
		}
		// User.ID is an any: what JSON gave, the base64url text, or bytes.
		uid := ""
		switch v := o.User.ID.(type) {
		case string:
			uid = v
		case []byte:
			uid = base64.RawURLEncoding.EncodeToString(v)
		case protocol.URLEncodedBase64:
			uid = v.String()
		}
		out(map[string]any{"rp": o.RelyingParty.ID, "user": uid,
			"challenge": o.Challenge.String(), "algs": algs, "exclude": len(o.CredentialExcludeList),
			"residentKey": o.AuthenticatorSelection.ResidentKey, "uv": o.AuthenticatorSelection.UserVerification,
			"attestation": o.Attestation})
	case "parse-request-options":
		var o protocol.PublicKeyCredentialRequestOptions
		if err := json.Unmarshal(read(a[1]), &o); err != nil {
			die(err)
		}
		out(map[string]any{"rp": o.RelyingPartyID, "challenge": o.Challenge.String(), "allow": len(o.AllowedCredentials),
			"uv": o.UserVerification})
	default:
		die(fmt.Errorf("unknown command %q", a[0]))
	}
}
