#!/bin/sh
# Builds tools/mimeoracle (Go's mime packages as the oracle) offline and runs
# it with these arguments; see tools/mimeoracle/main.go.
#
#	tools/mimeoracle.sh isprint > isprint.goose
#	tools/mimeoracle.sh types > types_builtin.goose
#	tools/mimeoracle.sh vectors -table mediatype
#	tools/mimeoracle.sh serve < cases
#	tools/mimeoracle.sh -version
set -e
dir=$(cd "$(dirname "$0")/mimeoracle" && pwd)
bin=${TMPDIR:-/tmp}/mimeoracle.$(id -u)
(cd "$dir" && GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go build -o "$bin" .)
exec "$bin" "$@"
