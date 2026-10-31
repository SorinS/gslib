package main

// vectors: Go's own test tables, read from $GOROOT/src/mime/**/*_test.go
// with go/ast so that nothing is copied by hand, and each row followed by
// what Go's function returns for it, so that a misread expectation shows.
//
// A table is a composite literal: a package-level variable, one assigned
// in init, or a local of a test function (named by the function). The
// evaluator knows the forms the tables use: string, rune and integer
// literals, +, conversions, strings.Repeat/ReplaceAll/Replace, the tests'
// own helpers m(...) (pairs into a map) and formData(key, value), and
// locals assigned earlier in the function.
//
// Output: one row per line, fields separated by '|'. A field is its bytes
// with every byte outside 0x20..0x7e, and '\' and '|', written \xHH; a nil
// is \N. A map is its size then its keys (sorted) and values; a slice its
// length then its elements; a struct its fields in order. The fields after
// "=>" are Go's actual results, per table (see the actual funcs below).

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type structVal struct {
	names []string
	vals  []any
}

type tableSpec struct {
	dir    string // under $GOROOT/src
	fn     string // the function holding the table; "" for package level or init
	name   string // the variable
	actual func(row any) ([]string, error)
	seed   map[string]any // values for the function's parameters
	calls  string         // instead of a variable: the argument of every call to this function in the functions named fn*
}

var tables = map[string]tableSpec{
	"consume_token":       {dir: "mime", fn: "TestConsumeToken", name: "tests"},
	"consume_value":       {dir: "mime", fn: "TestConsumeValue", name: "tests"},
	"consume_media_param": {dir: "mime", fn: "TestConsumeMediaParam", name: "tests"},
	"parse_media_type":    {dir: "mime", name: "parseMediaTypeTests", actual: actualParseMediaType(0)},
	"bad_media_type":      {dir: "mime", name: "badMediaTypeTests", actual: actualParseMediaType(0)},
	"format_media_type":   {dir: "mime", name: "formatTests", actual: actualFormatMediaType},
	"encode_word":         {dir: "mime", fn: "TestEncodeWord", name: "tests", actual: actualEncodeWord},
	"encoded_word_length": {dir: "mime", fn: "TestEncodedWordLength", name: "tests", actual: actualEncodeWordUTF8},
	"decode_word":         {dir: "mime", fn: "TestDecodeWord", name: "tests", actual: actualDecodeWord},
	"decode_header":       {dir: "mime", fn: "TestDecodeHeader", name: "tests", actual: actualDecodeHeader},
	"charset_decoder":     {dir: "mime", fn: "TestCharsetDecoder", name: "tests"},
	"qp_reader":           {dir: "mime/quotedprintable", fn: "TestReader", name: "tests", actual: actualQPReader},
	"qp_writer":           {dir: "mime/quotedprintable", fn: "testWriter", name: "tests", actual: actualQPWriter},
	"qp_testmsg":          {dir: "mime/quotedprintable", name: "testMsg", actual: actualQPWriter},
	"name_accessors":      {dir: "mime/multipart", fn: "TestNameAccessors", name: "tests", actual: actualNameAccessors},
	"multipart_parse":     {dir: "mime/multipart", name: "parseTests", actual: actualMultipartParse},
	"set_boundary":        {dir: "mime/multipart", fn: "TestWriterSetBoundary", name: "tests", actual: actualSetBoundary},
	"file_disposition":    {dir: "mime/multipart", fn: "TestFileContentDisposition", name: "tests", actual: actualFileDisposition},
	// Bodies that multipart's test functions build inline, with Go's parse of each.
	"line_endings":      {dir: "mime/multipart", fn: "TestVariousTextLineEndings", name: "tests"},
	"truncated_bodies":  {dir: "mime/multipart", fn: "TestMultipartTruncated", name: "body", actual: actualParseCRLF("MyBoundary")},
	"multipart_body":    {dir: "mime/multipart", fn: "testMultipartBody", name: "testBody"},
	"line_continuation": {dir: "mime/multipart", fn: "TestLineContinuation", name: "testBody", actual: actualParse("Apple-Mail-2-292336769")},
	"raw_part":          {dir: "mime/multipart", fn: "TestRawPart", name: "body", actual: actualParse("0016e68ee29c5d515f04cedf6733")},
	"qp_part":           {dir: "mime/multipart", fn: "testQuotedPrintableEncoding", name: "body", actual: actualParse("0016e68ee29c5d515f04cedf6733"), seed: map[string]any{"cte": "quoted-printable"}},
	"readahead_1":       {dir: "mime/multipart", fn: "TestMultipartStreamReadahead", name: "testBody1"},
	"readahead_2":       {dir: "mime/multipart", fn: "TestMultipartStreamReadahead", name: "testBody2"},
	// ReadForm's test messages and TestReadFormLimits.
	"form_message":  {dir: "mime/multipart", name: "message", actual: actualReadForm(25)},
	"form_nameless": {dir: "mime/multipart", name: "messageWithFileWithoutName", actual: actualReadForm(25)},
	"form_filename": {dir: "mime/multipart", name: "messageWithFileName", actual: actualReadForm(math.MaxInt64)},
	"form_textct":   {dir: "mime/multipart", name: "messageWithTextContentType", actual: actualReadForm(25)},
	"form_contents": {dir: "mime/multipart", name: "fileaContents filebContents textaValue textbValue boundary"},
	"form_limits":   {dir: "mime/multipart", fn: "TestReadFormLimits", calls: "range"},
	// net/textproto's tests of what multipart relies on.
	"canonical_key":    {dir: "net/textproto", name: "canonicalHeaderKeyTests", actual: actualCanonicalKey},
	"header_malformed": {dir: "net/textproto", fn: "TestReadMIMEHeaderMalformed", name: "inputs", actual: actualReadMIMEHeader},
	"read_mime_header": {dir: "net/textproto", fn: "TestReadMIMEHeader", actual: actualReadMIMEHeader, calls: "reader"},
}

func vectorsMode(args []string) error {
	fs := flag.NewFlagSet("vectors", flag.ExitOnError)
	goroot := gorootFlag(fs)
	name := fs.String("table", "", "the table: "+tableNames())
	fs.Parse(args)
	spec, ok := tables[*name]
	if fs.NArg() != 0 || !ok {
		fmt.Fprintf(os.Stderr, "vectors: -table must be one of %s\n", tableNames())
		os.Exit(2)
	}
	dir := filepath.Join(*goroot, "src", spec.dir)
	p, err := loadPackage(dir)
	if err != nil {
		return err
	}
	e := &env{p: p, locals: map[string]any{}}
	for k, v := range spec.seed {
		e.locals[k] = v
	}
	var v any
	if strings.Contains(spec.name, " ") { // several package constants: a row each, name and value
		var rows []any
		for _, n := range strings.Fields(spec.name) {
			x, err := p.table(e, "", n)
			if err != nil {
				return err
			}
			rows = append(rows, []any{n, x})
		}
		v = rows
	} else if spec.calls == "range" { // the literal a test function ranges over
		v, err = p.rangeLiteral(e, spec.fn)
	} else if spec.calls != "" {
		v, err = p.callArgs(e, spec.fn, spec.calls)
	} else {
		v, err = p.table(e, spec.fn, spec.name)
	}
	if err != nil {
		return err
	}
	if one, ok := v.(string); ok { // a single value: one row
		v = []any{[]any{one}}
	}
	if list, ok := v.([]any); ok { // a list of strings: a row each
		for i, x := range list {
			if s, ok := x.(string); ok {
				list[i] = []any{s}
			}
		}
	}
	rows, ok := v.([]any)
	if !ok {
		return fmt.Errorf("%s is not a slice or array", spec.name)
	}
	where := spec.name
	if spec.fn != "" {
		where = spec.fn + "." + spec.name
	}
	fmt.Printf("# %s: %d rows of %s in $GOROOT/src/%s, by tools/mimeoracle.sh vectors -table %s\n",
		*name, len(rows), where, spec.dir, *name)
	for _, sk := range e.skips {
		fmt.Printf("# skipped %s\n", sk)
	}
	for i, row := range rows {
		var fields []string
		flatten(row, &fields)
		if spec.actual != nil {
			act, err := spec.actual(row)
			if err != nil {
				return fmt.Errorf("row %d: %v", i, err)
			}
			fields = append(fields, "=>")
			fields = append(fields, act...)
		}
		fmt.Println(strings.Join(fields, "|"))
	}
	return nil
}

func tableNames() string {
	var names []string
	for k := range tables {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// escapeField writes s with \xHH for bytes outside 0x20..0x7e, '\' and '|'.
func escapeField(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '\\' || c == '|' {
			fmt.Fprintf(&b, "\\x%02x", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func flatten(v any, out *[]string) {
	switch x := v.(type) {
	case nil:
		*out = append(*out, `\N`)
	case string:
		*out = append(*out, escapeField(x))
	case bool:
		if x {
			*out = append(*out, "1")
		} else {
			*out = append(*out, "0")
		}
	case int64:
		*out = append(*out, strconv.FormatInt(x, 10))
	case []any:
		*out = append(*out, strconv.Itoa(len(x)))
		for _, e := range x {
			flatten(e, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		*out = append(*out, strconv.Itoa(len(keys)))
		for _, k := range keys {
			*out = append(*out, escapeField(k))
			flatten(x[k], out)
		}
	case *structVal:
		for _, e := range x.vals {
			flatten(e, out)
		}
	default:
		panic(fmt.Sprintf("flatten: %T", v))
	}
}

// --- The evaluator --------------------------------------------------------

type pkg struct {
	files []*ast.File
	types map[string]ast.Expr       // type name -> its type expression
	vars  map[string]*ast.ValueSpec // package-level var or const -> spec
	funcs map[string]*ast.FuncDecl
}

func loadPackage(dir string) (*pkg, error) {
	fset := token.NewFileSet()
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	p := &pkg{types: map[string]ast.Expr{}, vars: map[string]*ast.ValueSpec{}, funcs: map[string]*ast.FuncDecl{}}
	for _, m := range matches {
		f, err := parser.ParseFile(fset, m, nil, 0)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(f.Name.Name, "_test") {
			continue // external test package
		}
		p.files = append(p.files, f)
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						p.types[s.Name.Name] = s.Type
					case *ast.ValueSpec:
						for _, n := range s.Names {
							p.vars[n.Name] = s
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name != "init" {
					p.funcs[d.Name.Name] = d
				}
			}
		}
	}
	return p, nil
}

type env struct {
	p      *pkg
	locals map[string]any
	table  ast.Expr // the table's own literal, whose rows may be skipped
	skips  []string // rows the evaluator cannot read, with the reason
}

// table finds the variable `name`: a local of function fn, or a package
// variable (declared with its value, or assigned in an init function).
func (p *pkg) table(e *env, fn, name string) (any, error) {
	if fn != "" {
		fd := p.funcs[fn]
		if fd == nil {
			return nil, fmt.Errorf("no function %s", fn)
		}
		return e.findIn(fd.Body.List, name)
	}
	if vs := p.vars[name]; vs != nil && len(vs.Values) > 0 {
		e.table = vs.Values[0]
		return e.eval(vs.Values[0], vs.Type)
	}
	for _, f := range p.files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if ok && fd.Name.Name == "init" && fd.Recv == nil {
				e.locals = map[string]any{}
				if v, err := e.findIn(fd.Body.List, name); err == nil {
					return v, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no table %s", name)
}

// callArgs: the first argument of every call to `callee` in the
// functions whose names start with fnPrefix, in source order; arguments
// the evaluator cannot read are skipped (and noted).
func (p *pkg) callArgs(e *env, fnPrefix, callee string) (any, error) {
	var names []string
	for n := range p.funcs {
		if strings.HasPrefix(n, fnPrefix) {
			names = append(names, n)
		}
	}
	sort.Slice(names, func(i, j int) bool { return p.funcs[names[i]].Pos() < p.funcs[names[j]].Pos() })
	out := []any{}
	for _, n := range names {
		ast.Inspect(p.funcs[n].Body, func(x ast.Node) bool {
			c, ok := x.(*ast.CallExpr)
			if !ok || len(c.Args) != 1 {
				return true
			}
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == callee {
				v, err := e.eval(c.Args[0], nil)
				if err != nil {
					e.skips = append(e.skips, fmt.Sprintf("%s: %s(%s): %v", n, callee, exprText(c.Args[0]), err))
					return true
				}
				out = append(out, []any{n, v})
			}
			return true
		})
	}
	return out, nil
}

// rangeLiteral: the composite literal that function fn's first
// `for ... range <literal>` ranges over.
func (p *pkg) rangeLiteral(e *env, fn string) (any, error) {
	fd := p.funcs[fn]
	if fd == nil {
		return nil, fmt.Errorf("no function %s", fn)
	}
	var lit ast.Expr
	ast.Inspect(fd.Body, func(x ast.Node) bool {
		if rs, ok := x.(*ast.RangeStmt); ok && lit == nil {
			if cl, ok := rs.X.(*ast.CompositeLit); ok {
				lit = cl
			}
		}
		return lit == nil
	})
	if lit == nil {
		return nil, fmt.Errorf("%s: no range over a literal", fn)
	}
	e.table = lit
	return e.eval(lit, nil)
}

// findIn evaluates the statements' simple assignments in order, as locals,
// until one assigns `name`.
func (e *env) findIn(stmts []ast.Stmt, name string) (any, error) {
	for _, st := range stmts {
		if rs, ok := st.(*ast.RangeStmt); ok { // for _, name := range <literal>
			if id, ok := rs.Value.(*ast.Ident); ok && id.Name == name {
				e.table = rs.X
				return e.eval(rs.X, nil)
			}
			continue
		}
		as, ok := st.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			continue
		}
		for i, l := range as.Lhs {
			id, ok := l.(*ast.Ident)
			if !ok {
				continue
			}
			typ := ast.Expr(nil)
			if vs := e.p.vars[id.Name]; vs != nil && as.Tok == token.ASSIGN {
				typ = vs.Type
			}
			if id.Name == name {
				e.table = as.Rhs[i]
				return e.eval(as.Rhs[i], typ)
			}
			v, err := e.eval(as.Rhs[i], typ)
			if err == nil {
				e.locals[id.Name] = v
			}
		}
	}
	return nil, fmt.Errorf("no assignment to %s", name)
}

var errUnsupported = errors.New("unsupported expression")

func (e *env) eval(x ast.Expr, typ ast.Expr) (any, error) {
	switch x := x.(type) {
	case *ast.BasicLit:
		switch x.Kind {
		case token.STRING:
			return strconv.Unquote(x.Value)
		case token.CHAR:
			s, err := strconv.Unquote(x.Value)
			if err != nil {
				return nil, err
			}
			r := []rune(s)
			return int64(r[0]), nil
		case token.INT:
			return strconv.ParseInt(x.Value, 0, 64)
		}
	case *ast.ParenExpr:
		return e.eval(x.X, typ)
	case *ast.UnaryExpr:
		v, err := e.eval(x.X, typ)
		if err != nil {
			return nil, err
		}
		if i, ok := v.(int64); ok && x.Op == token.SUB {
			return -i, nil
		}
	case *ast.Ident:
		switch x.Name {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "nil":
			return nil, nil
		}
		if v, ok := e.locals[x.Name]; ok {
			return v, nil
		}
		if vs := e.p.vars[x.Name]; vs != nil {
			for i, n := range vs.Names {
				if n.Name == x.Name && i < len(vs.Values) {
					return (&env{p: e.p, locals: map[string]any{}}).eval(vs.Values[i], vs.Type)
				}
			}
		}
		return nil, fmt.Errorf("unknown name %s", x.Name)
	case *ast.BinaryExpr:
		a, err := e.eval(x.X, nil)
		if err != nil {
			return nil, err
		}
		b, err := e.eval(x.Y, nil)
		if err != nil {
			return nil, err
		}
		if as, ok := a.(string); ok && x.Op == token.ADD {
			if bs, ok := b.(string); ok {
				return as + bs, nil
			}
		}
		ai, ok1 := a.(int64)
		bi, ok2 := b.(int64)
		if !ok1 || !ok2 {
			return nil, errUnsupported
		}
		switch x.Op {
		case token.ADD:
			return ai + bi, nil
		case token.SUB:
			return ai - bi, nil
		case token.MUL:
			return ai * bi, nil
		case token.QUO:
			return ai / bi, nil
		case token.SHL:
			return ai << bi, nil
		}
	case *ast.CallExpr:
		return e.call(x)
	case *ast.CompositeLit:
		t := x.Type
		if t == nil {
			t = typ
		}
		return e.composite(x, t)
	}
	return nil, fmt.Errorf("%w: %T", errUnsupported, x)
}

func (e *env) args(xs []ast.Expr) ([]any, error) {
	var out []any
	for _, a := range xs {
		v, err := e.eval(a, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (e *env) call(x *ast.CallExpr) (any, error) {
	args, err := e.args(x.Args)
	if err != nil {
		return nil, err
	}
	switch f := x.Fun.(type) {
	case *ast.ArrayType: // []byte(s)
		if len(args) == 1 {
			return args[0], nil
		}
	case *ast.SelectorExpr:
		pk, ok := f.X.(*ast.Ident)
		if ok && (pk.Name == "errors" && f.Sel.Name == "New" || pk.Name == "fmt" && f.Sel.Name == "Errorf") && len(args) >= 1 {
			return args[0], nil // an error: its text
		}
		if ok && pk.Name == "strings" {
			switch f.Sel.Name {
			case "Repeat":
				return strings.Repeat(args[0].(string), int(args[1].(int64))), nil
			case "ReplaceAll":
				return strings.ReplaceAll(args[0].(string), args[1].(string), args[2].(string)), nil
			case "Replace":
				return strings.Replace(args[0].(string), args[1].(string), args[2].(string), int(args[3].(int64))), nil
			}
		}
	case *ast.Ident:
		switch {
		case f.Name == "m": // the tests' pairs-into-a-map helper
			mp := map[string]any{}
			for i := 0; i+1 < len(args); i += 2 {
				mp[args[i].(string)] = args[i+1]
			}
			return mp, nil
		case f.Name == "formData": // multipart's formData(key, value) headerBody
			hdr := map[string]any{
				"Content-Type":        []any{"text/plain; charset=ISO-8859-1"},
				"Content-Disposition": []any{"form-data; name=" + args[0].(string)},
			}
			return &structVal{names: []string{"header", "body"}, vals: []any{hdr, args[1]}}, nil
		case e.p.types[f.Name] != nil && len(args) == 1: // a conversion
			return args[0], nil
		case f.Name == "string" && len(args) == 1:
			return args[0], nil
		case f.Name == "len" && len(args) == 1:
			if s, ok := args[0].(string); ok {
				return int64(len(s)), nil
			}
		}
	}
	return nil, fmt.Errorf("%w: call", errUnsupported)
}

// resolve follows named types to their definitions.
func (e *env) resolve(t ast.Expr) ast.Expr {
	for {
		switch tt := t.(type) {
		case *ast.Ident:
			if d := e.p.types[tt.Name]; d != nil {
				t = d
				continue
			}
		case *ast.SelectorExpr:
			if tt.Sel.Name == "MIMEHeader" {
				return &ast.MapType{Key: ast.NewIdent("string"), Value: &ast.ArrayType{Elt: ast.NewIdent("string")}}
			}
		case *ast.ParenExpr:
			t = tt.X
			continue
		}
		return t
	}
}

func (e *env) composite(x *ast.CompositeLit, t ast.Expr) (any, error) {
	switch tt := e.resolve(t).(type) {
	case *ast.ArrayType:
		out := []any{}
		for i, el := range x.Elts {
			v, err := e.eval(el, tt.Elt)
			if err != nil && ast.Expr(x) == e.table {
				e.skips = append(e.skips, fmt.Sprintf("row %d (%s): %v", i, exprText(el), err))
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case *ast.MapType:
		mp := map[string]any{}
		for _, el := range x.Elts {
			kv := el.(*ast.KeyValueExpr)
			k, err := e.eval(kv.Key, tt.Key)
			if err != nil {
				return nil, err
			}
			v, err := e.eval(kv.Value, tt.Value)
			if err != nil {
				return nil, err
			}
			mp[k.(string)] = v
		}
		return mp, nil
	case *ast.StructType:
		sv := &structVal{}
		var ftypes []ast.Expr
		for _, f := range tt.Fields.List {
			for _, n := range f.Names {
				sv.names = append(sv.names, n.Name)
				ftypes = append(ftypes, f.Type)
				sv.vals = append(sv.vals, zero(e.resolve(f.Type)))
			}
		}
		for i, el := range x.Elts {
			idx := i
			val := el
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				name := kv.Key.(*ast.Ident).Name
				idx = -1
				for j, n := range sv.names {
					if n == name {
						idx = j
					}
				}
				if idx < 0 {
					return nil, fmt.Errorf("no field %s", name)
				}
				val = kv.Value
			}
			v, err := e.eval(val, ftypes[idx])
			if err != nil {
				return nil, err
			}
			sv.vals[idx] = v
		}
		return sv, nil
	}
	return nil, fmt.Errorf("%w: composite of %T", errUnsupported, t)
}

// exprText is a short rendering of an expression, for the skip notes.
func exprText(x ast.Expr) string {
	switch x := x.(type) {
	case *ast.CallExpr:
		return exprText(x.Fun) + "()"
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	}
	return fmt.Sprintf("%T", x)
}

func zero(t ast.Expr) any {
	if id, ok := t.(*ast.Ident); ok {
		switch id.Name {
		case "string":
			return ""
		case "bool":
			return false
		case "int", "int64", "byte":
			return int64(0)
		}
	}
	return nil
}

// --- Go's actual results ---------------------------------------------------

func field(row any, i int) any {
	switch r := row.(type) {
	case *structVal:
		return r.vals[i]
	case []any:
		return r[i]
	}
	return nil
}

func str(row any, i int) string { s, _ := field(row, i).(string); return s }

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ParseMediaType of field i: the error's text, the type, the parameters.
func actualParseMediaType(i int) func(any) ([]string, error) {
	return func(row any) ([]string, error) {
		mt, params, err := mime.ParseMediaType(str(row, i))
		out := []string{escapeField(errText(err)), escapeField(mt)}
		mp := map[string]any{}
		for k, v := range params {
			mp[k] = v
		}
		flatten(mp, &out)
		return out, nil
	}
}

func actualFormatMediaType(row any) ([]string, error) {
	params := map[string]string{}
	if mp, ok := field(row, 1).(map[string]any); ok {
		for k, v := range mp {
			params[k] = v.(string)
		}
	}
	return []string{escapeField(mime.FormatMediaType(str(row, 0), params))}, nil
}

func actualEncodeWord(row any) ([]string, error) {
	enc := mime.WordEncoder(field(row, 0).(int64))
	return []string{escapeField(enc.Encode(str(row, 1), str(row, 2)))}, nil
}

func actualEncodeWordUTF8(row any) ([]string, error) {
	enc := mime.WordEncoder(field(row, 0).(int64))
	return []string{escapeField(enc.Encode("utf-8", str(row, 1)))}, nil
}

func actualDecodeWord(row any) ([]string, error) {
	s, err := new(mime.WordDecoder).Decode(str(row, 0))
	return []string{escapeField(s), escapeField(errText(err))}, nil
}

func actualDecodeHeader(row any) ([]string, error) {
	s, err := new(mime.WordDecoder).DecodeHeader(str(row, 0))
	return []string{escapeField(s), escapeField(errText(err))}, nil
}

func actualQPReader(row any) ([]string, error) {
	var b strings.Builder
	_, err := io.Copy(&b, quotedprintable.NewReader(strings.NewReader(str(row, 0))))
	return []string{escapeField(b.String()), escapeField(errText(err))}, nil
}

func actualQPWriter(row any) ([]string, error) {
	if r, ok := row.([]any); ok && len(r) == 1 { // testMsg: the round trip
		var b strings.Builder
		w := quotedprintable.NewWriter(&b)
		w.Write([]byte(r[0].(string)))
		w.Close()
		back, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(b.String())))
		if err != nil || string(back) != r[0].(string) {
			return nil, fmt.Errorf("Go's round trip failed")
		}
		return []string{escapeField(b.String())}, nil
	}
	var out []string
	for _, binary := range []bool{false, true} {
		var b strings.Builder
		w := quotedprintable.NewWriter(&b)
		w.Binary = binary
		if _, err := w.Write([]byte(str(row, 0))); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		out = append(out, escapeField(b.String()))
	}
	return out, nil
}

// A part as the parse rows record it: its header (map of lists) and body.
func partFields(p *multipart.Part, body string) []string {
	mp := map[string]any{}
	for k, vs := range p.Header {
		var l []any
		for _, v := range vs {
			l = append(l, v)
		}
		mp[k] = l
	}
	var out []string
	flatten(mp, &out)
	return append(out, escapeField(body))
}

func actualNameAccessors(row any) ([]string, error) {
	r := multipart.NewReader(strings.NewReader("--b\r\nContent-Disposition: "+str(row, 0)+"\r\n\r\n\r\n--b--\r\n"), "b")
	p, err := r.NextPart()
	if err != nil {
		return nil, err
	}
	return []string{escapeField(p.FormName()), escapeField(p.FileName())}, nil
}

// actualMultipartParse: every part (NextPart, then the body read whole),
// and the error that ended the loop ("" for io.EOF).
func actualMultipartParse(row any) ([]string, error) {
	r := multipart.NewReader(strings.NewReader(str(row, 1)), str(row, 2))
	var parts [][]string
	final := ""
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			final = err.Error()
			break
		}
		body, err := io.ReadAll(p)
		if err != nil {
			final = "body: " + err.Error()
			break
		}
		parts = append(parts, partFields(p, string(body)))
	}
	out := []string{strconv.Itoa(len(parts))}
	for _, p := range parts {
		out = append(out, p...)
	}
	return append(out, escapeField(final)), nil
}

// parseFields: Go's parse of body with the boundary, as actualMultipartParse writes it.
func parseFields(body, boundary string) []string {
	r := multipart.NewReader(strings.NewReader(body), boundary)
	var parts [][]string
	final := ""
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			final = err.Error()
			break
		}
		data, err := io.ReadAll(p)
		if err != nil {
			parts = append(parts, partFields(p, string(data)))
			final = "body: " + err.Error()
			break
		}
		parts = append(parts, partFields(p, string(data)))
	}
	out := []string{strconv.Itoa(len(parts))}
	for _, p := range parts {
		out = append(out, p...)
	}
	return append(out, escapeField(final))
}

// actualParse: Go's parse of a one-string row's body with this boundary.
func actualParse(boundary string) func(any) ([]string, error) {
	return func(row any) ([]string, error) { return parseFields(str(row, 0), boundary), nil }
}

// actualParseCRLF: the same after the test's ReplaceAll(body, "\n", "\r\n").
func actualParseCRLF(boundary string) func(any) ([]string, error) {
	return func(row any) ([]string, error) {
		return parseFields(strings.ReplaceAll(str(row, 0), "\n", "\r\n"), boundary), nil
	}
}

// actualReadForm: Go's ReadForm(maxMemory) of a row's message (its
// newlines made CRLF, as the tests do), boundary "MyBoundary": the error,
// then the values (name, value) and the files (name, file name, size,
// content, whether on disk) in Go's map order sorted by name.
func actualReadForm(maxMemory int64) func(any) ([]string, error) {
	return func(row any) ([]string, error) {
		body := strings.ReplaceAll(str(row, 0), "\n", "\r\n")
		r := multipart.NewReader(strings.NewReader(body), "MyBoundary")
		f, err := r.ReadForm(maxMemory)
		out := []string{escapeField(errText(err))}
		if err != nil {
			return out, nil
		}
		defer f.RemoveAll()
		vals := map[string]any{}
		for k, vs := range f.Value {
			var l []any
			for _, v := range vs {
				l = append(l, v)
			}
			vals[k] = l
		}
		flatten(vals, &out)
		files := map[string]any{}
		for k, fhs := range f.File {
			var l []any
			for _, fh := range fhs {
				fd, err := fh.Open()
				if err != nil {
					return nil, err
				}
				data, err := io.ReadAll(fd)
				_, onDisk := fd.(*os.File)
				fd.Close()
				if err != nil {
					return nil, err
				}
				l = append(l, &structVal{vals: []any{fh.Filename, int64(fh.Size), string(data), onDisk}})
			}
			files[k] = l
		}
		flatten(files, &out)
		return out, nil
	}
}

func actualCanonicalKey(row any) ([]string, error) {
	return []string{escapeField(textproto.CanonicalMIMEHeaderKey(str(row, 0)))}, nil
}

// actualReadMIMEHeader: ReadMIMEHeader of the row's last string field: the
// error's text, then the header as a map of lists.
func actualReadMIMEHeader(row any) ([]string, error) {
	in := ""
	switch r := row.(type) {
	case []any:
		in, _ = r[len(r)-1].(string)
	case string:
		in = r
	}
	m, err := textproto.NewReader(bufio.NewReader(strings.NewReader(in))).ReadMIMEHeader()
	mp := map[string]any{}
	for k, vs := range m {
		var l []any
		for _, v := range vs {
			l = append(l, v)
		}
		mp[k] = l
	}
	out := []string{escapeField(errText(err))}
	flatten(mp, &out)
	return out, nil
}

func actualSetBoundary(row any) ([]string, error) {
	var b strings.Builder
	w := multipart.NewWriter(&b)
	err := w.SetBoundary(str(row, 0))
	ct := ""
	if err == nil {
		ct = w.FormDataContentType()
	}
	return []string{escapeField(errText(err)), escapeField(ct)}, nil
}

func actualFileDisposition(row any) ([]string, error) {
	return []string{escapeField(multipart.FileContentDisposition(str(row, 0), str(row, 1)))}, nil
}
