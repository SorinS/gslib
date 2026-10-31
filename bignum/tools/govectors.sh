#!/bin/sh
# Builds tools/govectors (Go's golang.org/x/crypto) offline from the module
# cache and runs it with these arguments; see tools/govectors/main.go.
#
#	tools/govectors.sh > test/vectors/xcrypto.txt         # the vectors
#	tools/govectors.sh -check test/vectors/xcrypto.txt    # compared with Go's instead
#	tools/govectors.sh -version
set -e
dir=$(cd "$(dirname "$0")/govectors" && pwd)
bin=${TMPDIR:-/tmp}/govectors.$(id -u)
(cd "$dir" && GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go build -o "$bin" .)
exec "$bin" "$@"
