// Goyaml is gopkg.in/yaml.v3 (v3.0.1) as the reference for the yaml
// package: it reads YAML as yaml.v3's Decoder reads it, one document at a
// time into a yaml.Node, and prints what it read as a canonical dump that
// test/vectors.goose prints too, byte for byte.
//
// Usage:
//
//	goyaml [file ...]                         the dump of each file, or of stdin
//	goyaml -corpus a.txt [-corpus b.txt ...]   the vectors of the cases in the files
//	goyaml -corpus a.txt -check vectors.txt     the vectors file compared with yaml.v3's instead
//	goyaml -mine dir                           yaml.v3's own test inputs as corpus cases
//	goyaml -version
//
// A dump has one line a node, which starts with its depth under its
// document:
//
//	0 doc L:C
//	1 map L:C tag="!!map" style=-
//	2 scalar L:C tag="!!str" style=- value="a" => str
//	2 alias L:C tag="" style=- value="x" -> L:C
//	decode ok
//
// L:C is the node's Line and Column; an anchor follows the style as
// anchor="name", and an alias ends with the line and column of the node it
// names. Strings are quoted, with the bytes outside printable ASCII, '"'
// and '\' written \xHH. After each scalar comes its value as Node.Decode
// gives it into an interface{}: null, bool true, int N, uint N, float and
// the 16 hex digits of its bits (nan for any NaN), str (with the decoded text when that is not
// the node's value, as for !!binary), timestamp in RFC 3339, or error and
// the message. A second line, "as", has what Node.Decode gives into an
// int64, a uint64, a float64, a bool and a string (i= u= f= b= s=): the
// value, or ! and the error (one of a TypeError without its "yaml:
// unmarshal errors:" heading). After each document comes the document decoded whole into
// an interface{}: "decode ok" or "decode error" and the message, the
// details after "invalid map key:" left out, since they are Go syntax;
// then what yaml.Marshal writes of the document node, its comments
// cleared (the yaml package does not keep comments), "marshal" and the
// text, or "marshal error" and the message. A stream that fails ends with
// error and the message; one with more than one document ends with what a
// yaml.Encoder writes of them all, "stream" and the text.
//
// The corpus is cases separated by header lines, "=== name [flags]", each
// case's input the lines up to the next header, each with its newline.
// Flags: noeol drops the last newline; esc reads \t \r \n \\ and \xHH in
// the lines; gen makes the input from its one line instead, pieces "hex"
// or "hex*count" concatenated, for inputs too big to keep. A vector is
// "case name", "input hex" (or "gen" and the line), the dump, then "end";
// of a dump longer than 100 lines, the first 100, then "more", how many
// lines follow, and the 64-bit FNV-1a hash of the whole dump.
//
// With -mine, dir is yaml.v3's source (in the module cache); every string
// constant in its _test.go files, its inputs, outputs and messages, is
// printed once as a case named for the module and the file, as one esc
// noeol line.
//
// Errors go to stderr: a bad command line exits 2, anything else 1.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"hash/fnv"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const version = "1.0.0"

// maxReported is how many differing cases -check prints.
const maxReported = 10

// maxLines is how many lines of a case's dump a vector keeps.
const maxLines = 100

// fileList is a flag that may be given more than once.
type fileList []string

func (l *fileList) String() string { return strings.Join(*l, ",") }

func (l *fileList) Set(s string) error {
	*l = append(*l, s)
	return nil
}

func main() {
	var corpusFiles fileList
	var checkFile, mineDir string
	var showVersion bool
	flag.Var(&corpusFiles, "corpus", "write the vectors of the cases in this `file` (more than once for more files)")
	flag.StringVar(&checkFile, "check", "", "with -corpus, compare with this vectors `file` instead of printing")
	flag.StringVar(&mineDir, "mine", "", "print the string constants of the _test.go files in this `dir` as corpus cases")
	flag.BoolVar(&showVersion, "version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: goyaml [file ...] | -corpus file ... [-check file] | -mine dir | -version")
		flag.PrintDefaults()
	}
	flag.Parse()
	if checkFile != "" && len(corpusFiles) == 0 {
		fmt.Fprintln(os.Stderr, "goyaml: -check needs -corpus")
		flag.Usage()
		os.Exit(2)
	}
	if (len(corpusFiles) > 0 || mineDir != "") && flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "goyaml: unexpected argument %q\n", flag.Arg(0))
		flag.Usage()
		os.Exit(2)
	}
	if mineDir != "" && len(corpusFiles) > 0 {
		fmt.Fprintln(os.Stderr, "goyaml: -mine and -corpus are separate runs")
		flag.Usage()
		os.Exit(2)
	}

	if showVersion {
		fmt.Println(versionString())
		return
	}
	var err error
	switch {
	case mineDir != "":
		err = mine(mineDir, os.Stdout)
	case checkFile != "":
		err = check(corpusFiles, checkFile)
	case len(corpusFiles) > 0:
		err = vectors(corpusFiles, os.Stdout)
	default:
		err = dumpFiles(flag.Args(), os.Stdout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "goyaml: %v\n", err)
		os.Exit(1)
	}
}

// versionString is this program's version, the Go it was built with and,
// when go build stamped it, the commit it was built from.
func versionString() string {
	s := fmt.Sprintf("goyaml %s %s %s/%s", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return s
	}
	for _, dep := range info.Deps {
		if dep.Path == "gopkg.in/yaml.v3" {
			s += " yaml.v3@" + dep.Version
		}
	}
	var rev string
	var dirty bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			rev = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if rev == "" {
		return s
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "+dirty"
	}
	return s + " " + rev
}

// dumpFiles writes the dump of each file, or of stdin when there are none.
func dumpFiles(paths []string, w io.Writer) error {
	out := bufio.NewWriter(w)
	if len(paths) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		dump(out, data)
		return out.Flush()
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(paths) > 1 {
			fmt.Fprintf(out, "file %s\n", path)
		}
		dump(out, data)
	}
	return out.Flush()
}

// A corpusCase is one case of a corpus file: its name, its input, and the
// gen line it was made from, if it was.
type corpusCase struct {
	name  string
	input []byte
	gen   string
}

// readCorpora reads the cases of the corpus files, whose names must differ.
func readCorpora(paths []string) ([]corpusCase, error) {
	var cases []corpusCase
	seen := make(map[string]string)
	for _, path := range paths {
		cs, err := readCorpus(path)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			if other, ok := seen[c.name]; ok {
				return nil, fmt.Errorf("%s: case %s is in %s too", path, c.name, other)
			}
			seen[c.name] = path
		}
		cases = append(cases, cs...)
	}
	return cases, nil
}

// readCorpus reads the cases of a corpus file.
func readCorpus(path string) ([]corpusCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.SplitAfter(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var cases []corpusCase
	seen := make(map[string]bool)
	for i := 0; i < len(lines); {
		header := strings.TrimSuffix(lines[i], "\n")
		fields := strings.Fields(header)
		if len(fields) < 2 || fields[0] != "===" {
			return nil, fmt.Errorf("%s:%d: expected a \"=== name\" line", path, i+1)
		}
		name := fields[1]
		if seen[name] {
			return nil, fmt.Errorf("%s:%d: case %s again", path, i+1, name)
		}
		seen[name] = true
		var noeol, esc, gen bool
		for _, f := range fields[2:] {
			switch f {
			case "noeol":
				noeol = true
			case "esc":
				esc = true
			case "gen":
				gen = true
			default:
				return nil, fmt.Errorf("%s:%d: unknown flag %q", path, i+1, f)
			}
		}
		start := i + 1
		i = start
		for i < len(lines) && !strings.HasPrefix(lines[i], "=== ") {
			i++
		}
		body := lines[start:i]
		c := corpusCase{name: name}
		if gen {
			if len(body) != 1 {
				return nil, fmt.Errorf("%s:%d: a gen case has one line", path, start)
			}
			c.gen = strings.TrimSuffix(body[0], "\n")
			c.input, err = expand(c.gen)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %v", path, start+1, err)
			}
		} else {
			text := strings.Join(body, "")
			if noeol {
				text = strings.TrimSuffix(text, "\n")
			}
			if esc {
				text, err = unescape(text)
				if err != nil {
					return nil, fmt.Errorf("%s:%d: %v", path, start+1, err)
				}
			}
			c.input = []byte(text)
		}
		cases = append(cases, c)
	}
	return cases, nil
}

// expand makes a gen case's input: pieces "hex" or "hex*count".
func expand(spec string) ([]byte, error) {
	var b bytes.Buffer
	for _, piece := range strings.Fields(spec) {
		h, n := piece, 1
		if k := strings.IndexByte(piece, '*'); k >= 0 {
			var err error
			h = piece[:k]
			n, err = strconv.Atoi(piece[k+1:])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("bad count in %q", piece)
			}
		}
		unit, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("bad hex in %q", piece)
		}
		b.Write(bytes.Repeat(unit, n))
	}
	return b.Bytes(), nil
}

// unescape reads \t \r \n \\ and \xHH.
func unescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", errors.New("a \\ at the end")
		}
		i++
		switch s[i] {
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'n':
			b.WriteByte('\n')
		case '\\':
			b.WriteByte('\\')
		case 'x':
			if i+2 >= len(s) {
				return "", errors.New("a short \\x")
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", fmt.Errorf("bad \\x%s", s[i+1:i+3])
			}
			b.WriteByte(byte(v))
			i += 2
		default:
			return "", fmt.Errorf("unknown escape \\%c", s[i])
		}
	}
	return b.String(), nil
}

// vectors writes the vectors of the corpus files' cases to w.
func vectors(corpusFiles []string, w io.Writer) error {
	cases, err := readCorpora(corpusFiles)
	if err != nil {
		return err
	}
	out := bufio.NewWriter(w)
	for _, c := range cases {
		writeCase(out, c)
	}
	return out.Flush()
}

func writeCase(w io.Writer, c corpusCase) {
	fmt.Fprintf(w, "case %s\n", c.name)
	switch {
	case c.gen != "":
		fmt.Fprintf(w, "gen %s\n", c.gen)
	case len(c.input) == 0:
		fmt.Fprintln(w, "input -")
	default:
		fmt.Fprintf(w, "input %x\n", c.input)
	}
	var d bytes.Buffer
	dump(&d, c.input)
	lines := strings.SplitAfter(d.String(), "\n")
	lines = lines[:len(lines)-1] // after the last newline
	if len(lines) <= maxLines {
		w.Write(d.Bytes())
	} else {
		h := fnv.New64a()
		h.Write(d.Bytes())
		fmt.Fprint(w, strings.Join(lines[:maxLines], ""))
		fmt.Fprintf(w, "more %d %016x\n", len(lines)-maxLines, h.Sum64())
	}
	fmt.Fprintln(w, "end")
}

// check compares a vectors file with what the corpus files give now.
func check(corpusFiles []string, vectorsFile string) error {
	cases, err := readCorpora(corpusFiles)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		return err
	}
	have := splitCases(string(data))
	differ := 0
	for _, c := range cases {
		var b strings.Builder
		writeCase(&b, c)
		if have[c.name] != b.String() {
			if differ < maxReported {
				fmt.Fprintf(os.Stderr, "%s: case %s differs from yaml.v3's\n", vectorsFile, c.name)
			}
			differ++
		}
		delete(have, c.name)
	}
	for name := range have {
		if differ < maxReported {
			fmt.Fprintf(os.Stderr, "%s: case %s is in no corpus file\n", vectorsFile, name)
		}
		differ++
	}
	if differ > 0 {
		return fmt.Errorf("%s: %d of %d cases differ", vectorsFile, differ, len(cases))
	}
	fmt.Printf("%s matches yaml.v3 (%d cases)\n", vectorsFile, len(cases))
	return nil
}

// splitCases splits a vectors file into its cases, by name.
func splitCases(s string) map[string]string {
	m := make(map[string]string)
	var name string
	var b strings.Builder
	for _, line := range strings.SplitAfter(s, "\n") {
		if name == "" && strings.HasPrefix(line, "case ") {
			name = strings.TrimSuffix(strings.TrimPrefix(line, "case "), "\n")
		}
		b.WriteString(line)
		if line == "end\n" {
			m[name] = b.String()
			name = ""
			b.Reset()
		}
	}
	return m
}

// dump writes the dump of the documents of data, read as yaml.v3's
// Decoder reads them.
func dump(w io.Writer, data []byte) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []*yaml.Node
	for {
		doc := new(yaml.Node)
		err := dec.Decode(doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(w, "error %s\n", quote(err.Error()))
			return
		}
		docs = append(docs, doc)
		node(w, doc, 0)
		clearComments(doc)
		var v interface{}
		if err := doc.Decode(&v); err != nil {
			fmt.Fprintf(w, "decode error %s\n", quote(decodeMessage(err)))
		} else {
			fmt.Fprintln(w, "decode ok")
		}
		if out, err := yaml.Marshal(doc); err != nil {
			fmt.Fprintf(w, "marshal error %s\n", quote(err.Error()))
		} else {
			fmt.Fprintf(w, "marshal %s\n", quote(string(out)))
		}
	}
	if len(docs) > 1 {
		var b bytes.Buffer
		enc := yaml.NewEncoder(&b)
		for _, doc := range docs {
			if err := enc.Encode(doc); err != nil {
				fmt.Fprintf(w, "stream error %s\n", quote(err.Error()))
				return
			}
		}
		if err := enc.Close(); err != nil {
			fmt.Fprintf(w, "stream error %s\n", quote(err.Error()))
			return
		}
		fmt.Fprintf(w, "stream %s\n", quote(b.String()))
	}
}

// decodeMessage is err's text, without the Go syntax of an invalid map key.
func decodeMessage(err error) string {
	s := err.Error()
	const key = "invalid map key:"
	if i := strings.Index(s, key); i >= 0 {
		return s[:i+len(key)-1]
	}
	return s
}

var kinds = map[yaml.Kind]string{
	yaml.DocumentNode: "doc",
	yaml.SequenceNode: "seq",
	yaml.MappingNode:  "map",
	yaml.ScalarNode:   "scalar",
	yaml.AliasNode:    "alias",
}

var styles = []struct {
	style yaml.Style
	name  string
}{
	{yaml.TaggedStyle, "tagged"},
	{yaml.DoubleQuotedStyle, "double"},
	{yaml.SingleQuotedStyle, "single"},
	{yaml.LiteralStyle, "literal"},
	{yaml.FoldedStyle, "folded"},
	{yaml.FlowStyle, "flow"},
}

func styleName(s yaml.Style) string {
	var names []string
	for _, st := range styles {
		if s&st.style != 0 {
			names = append(names, st.name)
		}
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, "|")
}

// node writes n and the nodes under it, depth levels in.
func node(w io.Writer, n *yaml.Node, depth int) {
	if n.Kind == yaml.DocumentNode {
		fmt.Fprintf(w, "%d doc %d:%d\n", depth, n.Line, n.Column)
	} else {
		fmt.Fprintf(w, "%d %s %d:%d tag=%s style=%s", depth, kinds[n.Kind], n.Line, n.Column, quote(n.Tag), styleName(n.Style))
		if n.Anchor != "" {
			fmt.Fprintf(w, " anchor=%s", quote(n.Anchor))
		}
		switch n.Kind {
		case yaml.ScalarNode:
			fmt.Fprintf(w, " value=%s => %s\n", quote(n.Value), resolved(n))
			fmt.Fprintf(w, "%d as %s\n", depth, typed(n))
		case yaml.AliasNode:
			fmt.Fprintf(w, " value=%s -> %d:%d\n", quote(n.Value), n.Alias.Line, n.Alias.Column)
		default:
			fmt.Fprintln(w)
		}
	}
	for _, c := range n.Content {
		node(w, c, depth+1)
	}
}

// resolved is a scalar's value as Node.Decode gives it into an interface{}.
func resolved(n *yaml.Node) string {
	var v interface{}
	if err := n.Decode(&v); err != nil {
		return "error " + quote(err.Error())
	}
	switch v := v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool " + strconv.FormatBool(v)
	case int:
		return "int " + strconv.Itoa(v)
	case int64:
		return "int " + strconv.FormatInt(v, 10)
	case uint64:
		return "uint " + strconv.FormatUint(v, 10)
	case float64:
		return "float " + floatText(v)
	case string:
		if v == n.Value {
			return "str"
		}
		return "str " + quote(v)
	case time.Time:
		return "timestamp " + v.Format(time.RFC3339Nano)
	default:
		return fmt.Sprintf("other %T", v)
	}
}

// quote is s in double quotes, with the bytes outside printable ASCII, '"'
// and '\' as \xHH.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			fmt.Fprintf(&b, "\\x%02x", c)
		} else {
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// mine writes each string constant of the _test.go files in dir once, as
// a corpus case: the strings concatenated with + as one.
func mine(dir string, w io.Writer) error {
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no _test.go files in %s", dir)
	}
	sort.Strings(files)
	// The cases are named for the module: gopkg.in/yaml.v3@v3.0.1 gives
	// yamlv3, go.yaml.in/yaml/v3@v3.0.4 gives v3.
	prefix := filepath.Base(filepath.Clean(dir))
	if i := strings.IndexByte(prefix, '@'); i >= 0 {
		prefix = prefix[:i]
	}
	prefix = strings.Map(func(r rune) rune {
		if 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' {
			return r
		}
		return -1
	}, prefix)
	out := bufio.NewWriter(w)
	fset := token.NewFileSet()
	seen := make(map[string]bool)
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		base := strings.TrimSuffix(filepath.Base(path), "_test.go")
		n := 0
		ast.Inspect(f, func(node ast.Node) bool {
			e, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			s, ok := constString(e)
			if !ok {
				return true
			}
			if !seen[s] {
				seen[s] = true
				n++
				fmt.Fprintf(out, "=== %s-%s-%d esc noeol\n%s\n", prefix, base, n, escapeLine(s))
			}
			return false
		})
	}
	return out.Flush()
}

// constString is the value of a string constant: a literal, or literals
// joined with +.
func constString(e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return constString(e.X)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		a, ok := constString(e.X)
		if !ok {
			return "", false
		}
		b, ok := constString(e.Y)
		return a + b, ok
	}
	return "", false
}

// escapeLine is s as one line of an esc case: printable ASCII as it is
// (but a leading '='), \\, \n, \t and \r, and \xHH for the rest.
func escapeLine(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\r':
			b.WriteString(`\r`)
		case c < 0x20 || c > 0x7e || (i == 0 && c == '='):
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// typed is what Node.Decode gives of n into an int64, a uint64, a float64,
// a bool and a string.
func typed(n *yaml.Node) string {
	var i int64
	var u uint64
	var f float64
	var b bool
	var s string
	fields := []string{
		"i=" + decodeResult(n.Decode(&i), func() string { return strconv.FormatInt(i, 10) }),
		"u=" + decodeResult(n.Decode(&u), func() string { return strconv.FormatUint(u, 10) }),
		"f=" + decodeResult(n.Decode(&f), func() string { return floatText(f) }),
		"b=" + decodeResult(n.Decode(&b), func() string { return strconv.FormatBool(b) }),
		"s=" + decodeResult(n.Decode(&s), func() string { return quote(s) }),
	}
	return strings.Join(fields, " ")
}

// decodeResult is the value, or ! and the error: one of a TypeError
// without its heading.
func decodeResult(err error, value func() string) string {
	if err == nil {
		return value()
	}
	var te *yaml.TypeError
	if errors.As(err, &te) {
		return "!" + quote(strings.Join(te.Errors, "\n"))
	}
	return "!" + quote(err.Error())
}

// floatText is f's bits in hex, or nan for any NaN.
func floatText(f float64) string {
	if math.IsNaN(f) {
		return "nan"
	}
	return fmt.Sprintf("%016x", math.Float64bits(f))
}

// clearComments clears the comments of n and the nodes under it.
func clearComments(n *yaml.Node) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	for _, c := range n.Content {
		clearComments(c)
	}
}
