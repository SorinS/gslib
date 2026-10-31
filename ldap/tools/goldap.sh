#!/bin/sh
# Builds tools/goldap (go-ldap as the reference) offline from the module cache and runs it with
# these arguments; see tools/goldap/main.go.
#
#	tools/goldap.sh vectors > test/vectors/goldap.txt
#	tools/goldap.sh search ldap://127.0.0.1:3389 dc=example,dc=com '(cn=*)'
set -e
dir=$(cd "$(dirname "$0")/goldap" && pwd)
bin=${TMPDIR:-/tmp}/goldap.$(id -u)
(cd "$dir" && GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go build -o "$bin" .)
exec "$bin" "$@"
