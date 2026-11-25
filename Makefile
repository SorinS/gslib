# gslib Makefile
# The programs, type checks, and every library's tests.

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

ROOT    := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BIN     ?= $(abspath $(ROOT)/../bin)
PYTHON  ?= python3

# The compiler: GOOSE, else goose on PATH, else ../goose.git/build/goose, as
# scripts/run_all.py finds it. The test scripts get the same one.
GOOSE   ?= $(or $(shell command -v goose 2>/dev/null),$(abspath $(ROOT)/../goose.git/build/goose))
export GOOSE

LIBS    := asn1 bignum x509 tls ssh ldap yaml http websocket quic compress mime krb5 jwx pkcs11 dns mail openpgp acme oauth tsp xml est scep saml cbor webauthn ntlm tpm2 radius smb kmip regex

# ------------------------------------------------------------------------------
# Derived values
# ------------------------------------------------------------------------------

# A program is rebuilt when any of the package's sources changes.
SOURCES := $(ROOT)/gslib.goose $(ROOT)/gslib.build $(ROOT)/net.goose $(ROOT)/websocket.goose $(ROOT)/quic.goose $(ROOT)/compress.goose $(ROOT)/mime.goose $(ROOT)/krb5.goose $(ROOT)/jwx.goose $(ROOT)/pkcs11.goose $(ROOT)/dns.goose $(ROOT)/mail.goose $(ROOT)/acme.goose $(ROOT)/oauth.goose $(ROOT)/tsp.goose $(ROOT)/est.goose $(ROOT)/scep.goose $(ROOT)/saml.goose $(ROOT)/webauthn.goose $(ROOT)/ntlm.goose $(ROOT)/tpm2.goose $(ROOT)/radius.goose $(ROOT)/smb.goose $(ROOT)/kmip.goose $(ROOT)/regex.goose \
	$(shell find $(ROOT)/crypto $(ROOT)/encoding $(ROOT)/net $(ROOT)/websocket $(ROOT)/quic $(ROOT)/compress $(ROOT)/mime $(ROOT)/krb5 $(ROOT)/jwx $(ROOT)/pkcs11 $(ROOT)/dns $(ROOT)/mail $(ROOT)/acme $(ROOT)/oauth $(ROOT)/tsp $(ROOT)/est $(ROOT)/scep $(ROOT)/saml $(ROOT)/webauthn $(ROOT)/ntlm $(ROOT)/tpm2 $(ROOT)/radius $(ROOT)/smb $(ROOT)/kmip \
		\( -name '*.goose' -o -name '*.c' -o -name '*.build' \) \
		-not -path '*/test/*' -not -path '*/examples/*')

# name:source for each program; each builds with its .build sidecar.
PROGRAMS := \
	goose-http:net/http/tools/http.goose \
	goose-httpd:net/http/tools/httpd.goose \
	goose-wscat:websocket/tools/wscat.goose \
	goose-wsecho:websocket/tools/wsecho.goose \
	goose-h3:quic/tools/h3.goose \
	goose-h3d:quic/tools/h3d.goose \
	goose-ssh:crypto/ssh/tools/ssh.goose \
	goose-sshd:crypto/ssh/tools/sshd.goose \
	goose-scp:crypto/ssh/tools/scp.goose \
	goose-sftp-server:crypto/ssh/tools/sftp_server.goose \
	goose-ssh-keygen:crypto/ssh/tools/keygen.goose \
	goose-ldapsearch:net/ldap/tools/ldapsearch.goose \
	goose-ldapmodify:net/ldap/tools/ldapmodify.goose \
	goose-ldapdelete:net/ldap/tools/ldapdelete.goose \
	goose-ldapmodrdn:net/ldap/tools/ldapmodrdn.goose \
	goose-ldappasswd:net/ldap/tools/ldappasswd.goose \
	goose-ldapwhoami:net/ldap/tools/ldapwhoami.goose \
	goose-ldapcompare:net/ldap/tools/ldapcompare.goose \
	goose-krb5:krb5/tools/krb5.goose \
	goose-gss:krb5/tools/gss.goose \
	goose-dig:dns/tools/dig.goose \
	goose-dnsd:dns/tools/dnsd.goose \
	goose-pgp:crypto/openpgp/tools/pgp.goose \
	goose-mail:mail/tools/mail.goose \
	goose-acme:acme/tools/acme.goose \
	goose-oauth:oauth/tools/oauth.goose \
	goose-ts:tsp/tools/ts.goose \
	goose-est:est/tools/est.goose \
	goose-scep:scep/tools/scep.goose \
	goose-ntlm:ntlm/tools/ntlm.goose \
	goose-saml:saml/tools/saml.goose \
	goose-webauthn:webauthn/tools/webauthn.goose \
	goose-tpm:tpm2/tools/tpm.goose \
	goose-radtest:radius/tools/radtest.goose \
	goose-radiusd:radius/tools/radiusd.goose \
	goose-smbclient:smb/tools/smbclient.goose \
	goose-kmip:kmip/tools/kmip.goose \
	goose-kmipd:kmip/tools/kmipd.goose

prog_name   = $(word 1,$(subst :, ,$(1)))
prog_source = $(word 2,$(subst :, ,$(1)))
BINARIES    := $(foreach p,$(PROGRAMS),$(BIN)/$(call prog_name,$(p))) $(BIN)/goose-ldapadd

# Every tool and example with a main, for check.
CHECKED := $(shell cd $(ROOT) && grep -l '^fn main' */*/tools/*.goose examples/*/*.goose \
	websocket/tools/*.goose quic/tools/*.goose compress/tools/*.goose mime/tools/*.goose krb5/tools/*.goose jwx/tools/*.goose pkcs11/tools/*.goose dns/tools/*.goose mail/tools/*.goose acme/tools/*.goose oauth/tools/*.goose tsp/tools/*.goose est/tools/*.goose scep/tools/*.goose saml/tools/*.goose webauthn/tools/*.goose ntlm/tools/*.goose tpm2/tools/*.goose radius/tools/*.goose smb/tools/*.goose kmip/tools/*.goose fuzz/targets/*.goose)

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

# Print a message in bold (no commas in it: $(call) splits there)
define echo
	@printf "\033[1m>> %s\033[0m\n" $(1)
endef

# ------------------------------------------------------------------------------
# Default target
# ------------------------------------------------------------------------------

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_%-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  Programs go to $(BIN) (BIN=dir for another); the compiler is $(GOOSE)."

# ------------------------------------------------------------------------------
# Build targets
# ------------------------------------------------------------------------------

.PHONY: all build
all: build ## Build every program into BIN
build: $(BINARIES) ## Build every program into BIN (http, httpd, ssh, sshd, scp, sftp-server, ssh-keygen, the ldap tools, krb5, gss)
	@echo "  -> $(BIN)"

.PHONY: http ssh ldap krb5
http: $(BIN)/goose-http $(BIN)/goose-httpd ## Build goose-http and goose-httpd
ssh: $(filter $(BIN)/goose-s%,$(BINARIES)) ## Build goose-ssh, goose-sshd, goose-scp, goose-sftp-server, goose-ssh-keygen
ldap: $(filter $(BIN)/goose-ldap%,$(BINARIES)) ## Build the goose-ldap* tools
krb5: $(BIN)/goose-krb5 $(BIN)/goose-gss ## Build goose-krb5 (kinit, kvno, klist) and goose-gss

$(BIN):
	@mkdir -p $@

define program
$(BIN)/$(call prog_name,$(1)): $(ROOT)/$(call prog_source,$(1)) $(SOURCES) | $(BIN)
	$$(call echo,"Building $(call prog_name,$(1))")
	$(GOOSE) build -o $$@ $(ROOT)/$(call prog_source,$(1))
endef
$(foreach p,$(PROGRAMS),$(eval $(call program,$(p))))

# ldapmodify -a, by its name.
$(BIN)/goose-ldapadd: $(BIN)/goose-ldapmodify
	cp $< $@

# ------------------------------------------------------------------------------
# Checks
# ------------------------------------------------------------------------------

.PHONY: check
check: ## Type-check every tool, example and fuzz target
	$(call echo,"Type-checking $(words $(CHECKED)) programs")
	@cd $(ROOT) && fail=0; for f in $(CHECKED); do \
		if out=$$($(GOOSE) check $$f 2>&1); then echo "  ok    $$f"; \
		else echo "  FAIL  $$f"; echo "$$out" | grep -v warning; fail=1; fi; \
	done; exit $$fail

.PHONY: fmt
fmt: ## Rewrite every .goose file in goose format's layout
	$(call echo,"Formatting")
	cd $(ROOT) && $(GOOSE) format .

.PHONY: fmt-check
fmt-check: ## List the .goose files goose format would change
	$(call echo,"Checking formatting")
	cd $(ROOT) && $(GOOSE) format --check .

# ------------------------------------------------------------------------------
# Test targets
# ------------------------------------------------------------------------------

.PHONY: test
test: ## Run every library's unit tests (-O0, -O2 and --debug)
	$(call echo,"Running unit tests")
	cd $(ROOT) && $(PYTHON) scripts/run_all.py

.PHONY: test-native
test-native: ## Run the unit tests, also built with the C compiler
	$(call echo,"Running unit tests and native builds")
	cd $(ROOT) && $(PYTHON) scripts/run_all.py --native

# test-asn1, test-bignum, ... (scripts/run_all.py refuses a name not in
# LIBS). Not .PHONY: make looks for no pattern rule for a phony target.
test-%: ## Run one library's unit tests: test-entropy test-asn1 test-bignum test-x509 test-tls test-ssh test-net test-ldap test-yaml test-http test-websocket test-quic test-compress test-mime test-krb5 test-jwx test-pkcs11 test-dns test-mail test-openpgp test-acme test-oauth test-tsp test-xml test-est test-scep test-saml test-cbor test-webauthn test-ntlm test-tpm2 test-radius test-smb test-kmip test-regex test-service test-sys test-sspi
	$(call echo,"Running $* unit tests")
	cd $(ROOT) && $(PYTHON) scripts/run_all.py --only $*

# Live tests: each starts its servers on 127.0.0.1, and stops them. What each
# needs installed is in its library's README; a missing tool is skipped.

.PHONY: interop
interop: interop-http interop-h2spec interop-websocket interop-quic interop-tls interop-ssh interop-ldap interop-krb5 interop-pkcs11 interop-dns interop-mail interop-openpgp interop-acme interop-oauth interop-tsp interop-xml interop-est interop-scep interop-saml interop-webauthn interop-ntlm interop-tpm2 interop-radius interop-smb interop-kmip ## Run every live interop test

.PHONY: interop-http
interop-http: ## HTTP against curl, Go's net/http, Python, nghttp2
	$(call echo,"HTTP interop")
	cd $(ROOT)/net/http && $(PYTHON) scripts/interop.py

.PHONY: interop-h2spec
interop-h2spec: ## h2spec against goose-httpd, TLS and h2c (needs h2spec)
	$(call echo,"h2spec")
	cd $(ROOT)/net/http && $(PYTHON) scripts/h2spec.py

# Docker (Linux): Autobahn|Testsuite and Python's websockets in containers,
# on loopback only.
.PHONY: interop-websocket
interop-websocket: ## goose-wsecho against Autobahn's fuzzingclient and the client against its fuzzingserver (every case, whole and a frame at a time), both against Python's websockets (Docker)
	$(call echo,"WebSocket against Autobahn and websockets")
	cd $(ROOT)/websocket && $(PYTHON) scripts/interop.py

# Docker (Linux): aioquic and quic-go in containers, their servers' UDP
# ports on loopback only.
.PHONY: interop-quic
interop-quic: ## goose-h3 against aioquic (with and without Retry) and quic-go servers, their clients against goose-h3d (Docker)
	$(call echo,"QUIC and HTTP/3 against aioquic and quic-go")
	cd $(ROOT)/quic && $(PYTHON) scripts/interop.py

.PHONY: interop-tls
interop-tls: ## TLS against OpenSSL and Go's crypto/tls
	$(call echo,"TLS interop: OpenSSL")
	cd $(ROOT)/crypto/tls && $(PYTHON) scripts/live_interop.py
	$(call echo,"TLS interop: Go")
	cd $(ROOT)/crypto/tls && $(PYTHON) scripts/go_interop.py

.PHONY: interop-ssh
interop-ssh: ## SSH, SFTP and scp against OpenSSH and Go's x/crypto/ssh
	$(call echo,"SSH interop")
	cd $(ROOT)/crypto/ssh && $(PYTHON) scripts/interop.py

.PHONY: interop-ldap
interop-ldap: ## LDAP against OpenLDAP and go-ldap
	$(call echo,"LDAP interop")
	cd $(ROOT)/net/ldap && $(PYTHON) scripts/interop.py

.PHONY: interop-pkcs11
interop-pkcs11: ## pkcs11 on SoftHSM2 against OpenSC's pkcs11-tool and OpenSSL
	$(call echo,"pkcs11 against pkcs11-tool and openssl")
	cd $(ROOT)/pkcs11 && $(PYTHON) scripts/interop.py

.PHONY: interop-dns
interop-dns: ## dns against dig and miekg/dns, both ways (needs Go; dig if installed)
	$(call echo,"dns against dig and miekg/dns")
	cd $(ROOT)/dns && $(PYTHON) scripts/interop.py

.PHONY: interop-mail
interop-mail: ## SMTP, POP3 and IMAP against scripted servers, mailpit and dovecot; DKIM against dkimpy; S/MIME against openssl cms; PGP/MIME against gpg (each if installed)
	$(call echo,"mail against SMTP/POP3/IMAP servers")
	cd $(ROOT)/mail && $(PYTHON) scripts/interop.py
	$(call echo,"DKIM against dkimpy (DKIMPY_PYTHON) and goose-dnsd")
	cd $(ROOT)/mail && $(PYTHON) scripts/interop_dkim.py
	$(call echo,"S/MIME against openssl cms")
	cd $(ROOT)/mail && $(PYTHON) scripts/interop_smime.py
	$(call echo,"PGP/MIME against gpg")
	cd $(ROOT)/mail && $(PYTHON) scripts/interop_pgp.py

.PHONY: interop-openpgp
interop-openpgp: ## OpenPGP against gpg, both ways (if installed)
	$(call echo,"OpenPGP against gpg")
	cd $(ROOT)/crypto/openpgp && $(PYTHON) scripts/interop.py

.PHONY: interop-acme
interop-acme: ## goose-acme against Pebble and OpenBao/Vault's PKI (each if installed), with goose-dnsd for dns-01
	$(call echo,"ACME against Pebble and OpenBao")
	cd $(ROOT)/acme && $(PYTHON) scripts/interop.py

.PHONY: interop-oauth
interop-oauth: ## goose-oauth against node-oidc-provider (npm ci in oauth/scripts/op; needs node), Keycloak if a container runtime runs
	$(call echo,"OAuth and OpenID Connect against oidc-provider")
	cd $(ROOT)/oauth && $(PYTHON) scripts/interop.py

.PHONY: interop-tsp
interop-tsp: ## goose-ts against openssl ts both ways, over HTTP (curl), CMS signatures time-stamped, and a Go TSA (digitorus/timestamp; needs Go)
	$(call echo,"Time-stamps against openssl ts and digitorus/timestamp")
	cd $(ROOT)/tsp && $(PYTHON) scripts/interop.py

.PHONY: interop-est
interop-est: ## goose-est against its own test CA, hostile servers and GlobalSign's estserver, and GlobalSign's estclient against goose-est serve (each if installed)
	$(call echo,"EST against goose-est serve and GlobalSign's estserver and estclient")
	cd $(ROOT)/est && $(PYTHON) scripts/interop.py

.PHONY: interop-scep
interop-scep: ## goose-scep against its own test CA, hostile servers and micromdm's scepserver, and micromdm's scepclient against goose-scep serve (each if installed)
	$(call echo,"SCEP against goose-scep serve and micromdm's scepserver and scepclient")
	cd $(ROOT)/scep && $(PYTHON) scripts/interop.py

.PHONY: interop-krb5
interop-krb5: ## Kerberos against MIT's KDC, kinit/kvno/klist, gss-client/gss-server and curl --negotiate
	$(call echo,"Kerberos interop")
	cd $(ROOT)/krb5 && $(PYTHON) scripts/interop.py

.PHONY: differential
differential: differential-http differential-x509 differential-compress differential-mime differential-jwx differential-dns differential-xml differential-cbor differential-tpm2 differential-regex ## Run every differential

.PHONY: differential-http
differential-http: ## HTTP/1.1 parsing, URLs and HPACK against Go; gzip and deflate decoding against zlib
	$(call echo,"HTTP/1.1 parsing against Go")
	cd $(ROOT)/net/http && $(PYTHON) scripts/h1_differential.py
	$(call echo,"URLs against Go")
	cd $(ROOT)/net/http && $(PYTHON) scripts/url_differential.py
	$(call echo,"gzip and deflate against zlib")
	cd $(ROOT)/net/http && $(PYTHON) scripts/flate_differential.py
	$(call echo,"HPACK against x/net")
	cd $(ROOT)/net/http && $(PYTHON) scripts/hpack_differential.py

.PHONY: differential-x509
differential-x509: ## Created certificates against openssl and Go; system roots against Go's rules
	$(call echo,"Created certificates against openssl and Go")
	cd $(ROOT)/crypto/x509 && $(PYTHON) scripts/check_created.py
	cd $(ROOT)/crypto/x509 && $(PYTHON) scripts/check_curves.py
	$(call echo,"System roots against Go's rules")
	cd $(ROOT)/crypto/x509 && $(PYTHON) scripts/check_roots.py

.PHONY: differential-compress
differential-compress: ## compress against Go's compress/* and archive/*, zlib, bz2 and bzip2, xz
	@cd $(ROOT)/compress && for d in flate_differential flate_testdata deflate_differential lzw_differential \
			bzip2_differential xz_differential zip_differential tar_differential; do \
		printf "\033[1m>> %s\033[0m\n" "compress: $$d"; \
		$(PYTHON) scripts/$$d.py || exit 1; \
	done

.PHONY: differential-jwx
differential-jwx: ## jwx against Go's lestrrat-go/jwx v4.6.0, both ways (needs Go 1.27)
	$(call echo,"jwx against Go's jwx")
	cd $(ROOT)/jwx && $(PYTHON) scripts/differential.py -n 3

.PHONY: differential-dns
differential-dns: ## dns against miekg/dns v1.1.73 on fresh vectors: records, messages, DNSSEC, TSIG (needs Go)
	$(call echo,"dns against miekg/dns")
	cd $(ROOT)/dns && $(PYTHON) scripts/differential.py -n 2

# XML_PYTHON: a Python with lxml, signxml, xmlsec and cryptography (a venv;
# encoding/xml/README.md says how to make one).
XML_PYTHON ?= $(PYTHON)

.PHONY: interop-xml
interop-xml: ## xml signatures and encryption against signxml and xmlsec, both ways, and wrapping attacks (XML_PYTHON with lxml, signxml, xmlsec)
	$(call echo,"XML Signature and Encryption against signxml and xmlsec")
	cd $(ROOT)/encoding/xml && $(XML_PYTHON) scripts/interop.py

# NTLM_PYTHON: a Python with pyspnego (and impacket, optional) (a venv;
# ntlm/README.md says how to make one). curl, and Go for go-ntlmssp.
NTLM_PYTHON ?= $(PYTHON)

.PHONY: interop-ntlm
interop-ntlm: ## goose-ntlm against pyspnego (NTLM and SPNEGO, both ways, channel bindings, sealing), curl --ntlm and Azure/go-ntlmssp against goose-ntlm serve, goose-ntlm get against a pyspnego HTTP server (NTLM_PYTHON with pyspnego; curl; Go)
	$(call echo,"NTLM against pyspnego and curl and go-ntlmssp")
	cd $(ROOT)/ntlm && $(NTLM_PYTHON) scripts/interop.py

# SAML_PYTHON: a Python with requests, python3-saml and lxml (a venv;
# saml/README.md says how to make one). Go, for crewjam/saml.
SAML_PYTHON ?= $(PYTHON)

.PHONY: interop-saml
interop-saml: ## goose-saml against itself, python3-saml (SP, and Responses signed by xmlsec) and crewjam/saml's SP and IdP, both ways (SAML_PYTHON with requests, python3-saml, lxml; Go)
	$(call echo,"SAML against python3-saml and crewjam/saml")
	cd $(ROOT)/saml && $(SAML_PYTHON) scripts/interop.py

# WEBAUTHN_PYTHON: a Python with fido2 (python-fido2 2.x), webauthn (Duo's
# py_webauthn), cbor2 and cryptography (a venv; webauthn/README.md says how
# to make one). Go, for go-webauthn.
WEBAUTHN_PYTHON ?= $(PYTHON)

.PHONY: interop-webauthn
interop-webauthn: ## goose-webauthn against python-fido2's Fido2Server, py_webauthn and go-webauthn, both ways, with a software authenticator (WEBAUTHN_PYTHON with fido2, webauthn, cbor2; Go)
	$(call echo,"WebAuthn against python-fido2 and py_webauthn and go-webauthn")
	cd $(ROOT)/webauthn && $(WEBAUTHN_PYTHON) scripts/interop.py

# CBOR_PYTHON: a Python with cbor2 (encoding/cbor/README.md).
CBOR_PYTHON ?= $(PYTHON)

.PHONY: differential-cbor
differential-cbor: ## cbor against Python's cbor2 on random items written every way, and mutated (CBOR_PYTHON with cbor2)
	$(call echo,"CBOR against cbor2")
	cd $(ROOT)/encoding/cbor && $(CBOR_PYTHON) scripts/differential.py -n 3000

# TPMEMU: the Sail TPM's tpmemu (else tpmemu on PATH); swtpm on PATH.
.PHONY: interop-tpm2
interop-tpm2: ## tpm2 and goose-tpm against tpmemu (raw TCP and mssim; TPMEMU) and swtpm (with EK certificates when swtpm_setup provisions them), and a fake TPM whose responses lie
	$(call echo,"TPM 2.0 against tpmemu and swtpm")
	cd $(ROOT)/tpm2 && $(PYTHON) scripts/interop.py

# Docker (Linux): FreeRADIUS 3.2 and wpa_supplicant's eapol_test in
# containers, on loopback only.
.PHONY: interop-radius
interop-radius: ## radtest against FreeRADIUS (PAP, CHAP, MS-CHAPv2, EAP-MD5/MS-CHAPv2/TLS, PEAP, TTLS over TLS 1.2 and 1.3, RadSec, accounting), radiusd against eapol_test and radclient, RadSec both ways (Docker)
	$(call echo,"RADIUS against FreeRADIUS and eapol_test")
	cd $(ROOT)/radius && $(PYTHON) scripts/interop.py

# Docker (Linux): Samba 4.17, a file server and an AD DC, in containers on
# loopback only.
.PHONY: interop-smb
interop-smb: ## goose-smbclient against Samba: every dialect 2.0.2-3.1.1, signing (HMAC-SHA256, AES-CMAC, AES-GMAC), encryption (AES-128/256 CCM/GCM), NTLMv2 and Kerberos, anonymous, and a man in the middle refused (Docker)
	$(call echo,"SMB against Samba")
	cd $(ROOT)/smb && $(PYTHON) scripts/interop.py

.PHONY: interop-kmip
interop-kmip: ## gslib's KMIP client against PyKMIP (1.0 to 2.0), goose-kmipd against gslib's client and PyKMIP's, and over HTTPS (Docker)
	$(call echo,"KMIP against PyKMIP")
	cd $(ROOT)/kmip && $(PYTHON) scripts/interop.py

# Not part of interop: it installs a real service (a user's systemd unit or
# launchd agent; on Windows, as an administrator, the system's).

.PHONY: oasis-kmip
oasis-kmip: ## OASIS's KMIP 1.4 to 2.1 test cases (fetched): XML and JSON round trips, and replayed against the in-memory server
	$(call echo,"KMIP against OASIS's test cases")
	cd $(ROOT)/kmip && $(PYTHON) scripts/oasis.py

.PHONY: live-service
live-service: ## service live: examples/service/heartbeat installed, started, killed and restarted by the service manager, stopped, uninstalled
	$(call echo,"service against the platform's service manager")
	cd $(ROOT) && $(PYTHON) service/scripts/service_check.py

.PHONY: live-sspi
live-sspi: ## sspi live (Windows): Schannel against gslib's TLS server and public sites, Negotiate against gslib's NTLM acceptor
	$(call echo,"sspi against Schannel and Negotiate")
	cd $(ROOT) && $(PYTHON) sspi/scripts/sspi_check.py --public

.PHONY: differential-tpm2
differential-tpm2: ## tpm2 against go-tpm on random cases: KDFa, KDFe, Names of random public areas and NV indices, policy digests (needs Go)
	$(call echo,"tpm2 against go-tpm")
	cd $(ROOT)/tpm2 && $(PYTHON) scripts/differential.py -n 3000

.PHONY: differential-regex
differential-regex: ## regex against the Rust regex crate on random patterns with anchors and word boundaries (needs cargo)
	$(call echo,"regex against the regex crate")
	cd $(ROOT)/regex && $(PYTHON) scripts/differential.py -n 2000

.PHONY: differential-xml
differential-xml: ## xml canonicalization against lxml (libxml2) on a corpus and random documents (XML_PYTHON with lxml)
	$(call echo,"XML canonicalization against lxml")
	cd $(ROOT)/encoding/xml && $(XML_PYTHON) scripts/differential.py -n 300

.PHONY: differential-mime
differential-mime: ## mime against Go's mime, mime/quotedprintable, mime/multipart and net/textproto
	$(call echo,"mime against Go")
	cd $(ROOT)/mime && $(PYTHON) scripts/differential.py -n 1000
	$(call echo,"mime types against Go: every extension and type of the system's tables")
	cd $(ROOT)/mime && $(PYTHON) scripts/differential.py --kinds alltypes

.PHONY: test-all
test-all: check test interop differential ## Run check, test, interop and differential

# ------------------------------------------------------------------------------
# Fuzzing (fuzz/README.md)
# ------------------------------------------------------------------------------

TARGET  ?=
SECONDS ?= 600
JOBS    ?= 1

.PHONY: fuzz-build
fuzz-build: ## Build every fuzz target's replay driver (and libFuzzer's, where a clang has it)
	$(call echo,"Building the fuzz targets")
	cd $(ROOT) && $(PYTHON) fuzz/run.py build
	@cd $(ROOT) && if $(PYTHON) -c "import sys; sys.path.insert(0, 'fuzz'); import run; run.fuzzer_cc()" 2>/dev/null; then \
		$(PYTHON) fuzz/run.py build --libfuzzer; else echo "  (no clang with libFuzzer: replay drivers only)"; fi

.PHONY: fuzz-replay
fuzz-replay: ## Replay every fuzz target's corpus and regression inputs (no libFuzzer needed)
	$(call echo,"Replaying the fuzz corpora and regressions")
	cd $(ROOT) && $(PYTHON) fuzz/run.py replay

.PHONY: fuzz
fuzz: ## Run one fuzz target under libFuzzer: make fuzz TARGET=dns_msg SECONDS=600 [JOBS=4]
	@test -n "$(TARGET)" || { echo "make fuzz TARGET=name (python3 fuzz/run.py list)"; exit 2; }
	$(call echo,"Fuzzing $(TARGET) for $(SECONDS) s")
	cd $(ROOT) && $(PYTHON) fuzz/run.py fuzz $(TARGET) --seconds $(SECONDS) --jobs $(JOBS)

# ------------------------------------------------------------------------------
# Clean
# ------------------------------------------------------------------------------

.PHONY: clean
clean: ## Remove the programs from BIN
	$(call echo,"Removing the programs from $(BIN)")
	rm -f $(BINARIES)
