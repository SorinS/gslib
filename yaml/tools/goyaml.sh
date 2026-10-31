#!/bin/sh
# Builds tools/goyaml (gopkg.in/yaml.v3 v3.0.1 as the reference) offline from
# the module cache and runs it with these arguments; see tools/goyaml/main.go.
#
#	tools/goyaml.sh -corpus test/corpus.txt -corpus test/corpus-yamlv3.txt -corpus test/corpus-yamlv2.txt > test/vectors/goyaml.txt
#	tools/goyaml.sh -corpus test/corpus.txt -corpus test/corpus-yamlv3.txt -corpus test/corpus-yamlv2.txt -check test/vectors/goyaml.txt
#	tools/goyaml.sh -mine "$(go env GOMODCACHE)/gopkg.in/yaml.v3@v3.0.1" > test/corpus-yamlv3.txt
#	tools/goyaml.sh file.yaml                                           # one file's dump
#	tools/goyaml.sh -version
set -e
dir=$(cd "$(dirname "$0")/goyaml" && pwd)
bin=${TMPDIR:-/tmp}/goyaml.$(id -u)
(cd "$dir" && GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go build -o "$bin" .)
exec "$bin" "$@"
