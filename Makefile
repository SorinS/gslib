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

LIBS    := asn1 bignum x509 tls ssh ldap yaml http compress mime krb5

# ------------------------------------------------------------------------------
# Derived values
# ------------------------------------------------------------------------------

# A program is rebuilt when any of the package's sources changes.
SOURCES := $(ROOT)/gslib.goose $(ROOT)/gslib.build $(ROOT)/compress.goose $(ROOT)/mime.goose $(ROOT)/krb5.goose \
	$(shell find $(ROOT)/crypto $(ROOT)/encoding $(ROOT)/net $(ROOT)/compress $(ROOT)/mime $(ROOT)/krb5 \
		\( -name '*.goose' -o -name '*.c' -o -name '*.build' \) \
		-not -path '*/test/*' -not -path '*/examples/*')

# name:source for each program; each builds with its .build sidecar.
PROGRAMS := \
	goose-http:net/http/tools/http.goose \
	goose-httpd:net/http/tools/httpd.goose \
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
	goose-gss:krb5/tools/gss.goose

prog_name   = $(word 1,$(subst :, ,$(1)))
prog_source = $(word 2,$(subst :, ,$(1)))
BINARIES    := $(foreach p,$(PROGRAMS),$(BIN)/$(call prog_name,$(p))) $(BIN)/goose-ldapadd

# Every tool and example with a main, for check.
CHECKED := $(shell cd $(ROOT) && grep -l '^fn main' */*/tools/*.goose */*/examples/*.goose \
	compress/tools/*.goose compress/examples/*.goose mime/tools/*.goose krb5/tools/*.goose)

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
check: ## Type-check every tool and example
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
test-%: ## Run one library's unit tests: test-asn1 test-bignum test-x509 test-tls test-ssh test-ldap test-yaml test-http test-compress test-mime test-krb5
	$(call echo,"Running $* unit tests")
	cd $(ROOT) && $(PYTHON) scripts/run_all.py --only $*

# Live tests: each starts its servers on 127.0.0.1, and stops them. What each
# needs installed is in its library's README; a missing tool is skipped.

.PHONY: interop
interop: interop-http interop-h2spec interop-tls interop-ssh interop-ldap interop-krb5 ## Run every live interop test

.PHONY: interop-http
interop-http: ## HTTP against curl, Go's net/http, Python, nghttp2
	$(call echo,"HTTP interop")
	cd $(ROOT)/net/http && $(PYTHON) scripts/interop.py

.PHONY: interop-h2spec
interop-h2spec: ## h2spec against goose-httpd, TLS and h2c (needs h2spec)
	$(call echo,"h2spec")
	cd $(ROOT)/net/http && $(PYTHON) scripts/h2spec.py

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

.PHONY: interop-krb5
interop-krb5: ## Kerberos against MIT's KDC, kinit/kvno/klist, gss-client/gss-server and curl --negotiate
	$(call echo,"Kerberos interop")
	cd $(ROOT)/krb5 && $(PYTHON) scripts/interop.py

.PHONY: differential
differential: differential-http differential-x509 differential-compress differential-mime ## Run every differential

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
	$(call echo,"System roots against Go's rules")
	cd $(ROOT)/crypto/x509 && $(PYTHON) scripts/check_roots.py

.PHONY: differential-compress
differential-compress: ## compress against Go's compress/* and archive/*, zlib, bz2 and bzip2, xz
	@cd $(ROOT)/compress && for d in flate_differential flate_testdata deflate_differential lzw_differential \
			bzip2_differential xz_differential zip_differential tar_differential; do \
		printf "\033[1m>> %s\033[0m\n" "compress: $$d"; \
		$(PYTHON) scripts/$$d.py || exit 1; \
	done

.PHONY: differential-mime
differential-mime: ## mime against Go's mime, mime/quotedprintable, mime/multipart and net/textproto
	$(call echo,"mime against Go")
	cd $(ROOT)/mime && $(PYTHON) scripts/differential.py -n 1000
	$(call echo,"mime types against Go: every extension and type of the system's tables")
	cd $(ROOT)/mime && $(PYTHON) scripts/differential.py --kinds alltypes

.PHONY: test-all
test-all: check test interop differential ## Run check, test, interop and differential

# ------------------------------------------------------------------------------
# Clean
# ------------------------------------------------------------------------------

.PHONY: clean
clean: ## Remove the programs from BIN
	$(call echo,"Removing the programs from $(BIN)")
	rm -f $(BINARIES)
