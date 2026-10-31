// Go's mime, mime/quotedprintable, mime/multipart and net/textproto as the
// oracle for mimegoose:
//
//	mimeoracle unicode
//	    writes mime's unicode.goose: strconv.IsPrint's and unicode.ToLower's tables, from Go itself
//	mimeoracle types [-goroot dir]
//	    writes mime's types_builtin.goose: Go's builtinTypesLower table, read from mime/type.go
//	mimeoracle vectors -table name [-goroot dir]
//	    the test table `name` of Go's own tests (go/ast), each row with what Go's
//	    function returns for it; see vectors.go
//	mimeoracle serve
//	    answers the differential's cases, one per line on stdin; see serve.go
//	mimeoracle -version
//
// Errors go to stderr: a bad command line exits 2, anything else 1.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
)

const version = "1.0.0"

const usage = `usage: mimeoracle unicode
       mimeoracle types [-goroot dir]
       mimeoracle vectors -table name [-goroot dir]
       mimeoracle serve
       mimeoracle -version
`

// printVersion prints this program's version, the Go it was built with and,
// when go build stamped it, the commit it was built from.
func printVersion() {
	rev := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		var dirty bool
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if len(rev) > 12 {
			rev = rev[:12]
		}
		if rev != "" && dirty {
			rev += "+dirty"
		}
	}
	line := fmt.Sprintf("mimeoracle %s %s %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if rev != "" {
		line += " " + rev
	}
	fmt.Println(line)
}

// gorootFlag adds -goroot, defaulting to the GOROOT this program was built with.
func gorootFlag(fs *flag.FlagSet) *string {
	return fs.String("goroot", runtime.GOROOT(), "the Go tree whose sources to read")
}

func main() {
	modes := map[string]func([]string) error{
		"unicode": unicodeMode, "types": typesMode, "vectors": vectorsMode, "serve": serveMode,
	}
	if len(os.Args) == 2 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		printVersion()
		return
	}
	if len(os.Args) < 2 || modes[os.Args[1]] == nil {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := modes[os.Args[1]](os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "mimeoracle %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}
