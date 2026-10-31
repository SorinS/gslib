// go-ldap (github.com/go-ldap/ldap/v3 v3.4.4) as the reference, for
// scripts/gen_vectors.py and by hand:
//
//	goldap vectors
//	    test/vectors/goldap.txt: one case a line, its fields hex-encoded
//	    (an empty field is "-"), as test/goldap.goose reads them:
//	    request <name> <bytes>      a request go-ldap writes, message ID 1
//	    filter <text> <ber|ERR>     CompileFilter
//	    decompile <ber> <text>      DecompileFilter of a compiled filter
//	    escape <value> <escaped>    EscapeFilter
//	    dn <text> <String()|ERR>    ParseDN
//	    dncmp <a> <b> <flags>       Equal, EqualFold, AncestorOf, AncestorOfFold as 0/1
//	goldap search <url> <base> <filter> [binddn password]
//	    a search with go-ldap's client, its entries printed as
//	    "dn: ..." and "attr: value" lines, for the interop script
//
// go-ldap writes BOOLEAN TRUE as 01; RFC 4511 §5.1 says FF, which is
// what ldap sends, so the vectors have go-ldap's booleans as FF. That is
// the one change to its bytes.
package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func h(s string) string {
	if s == "" {
		return "-"
	}
	return hex.EncodeToString([]byte(s))
}

func hb(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

// trueAsFF rewrites, in place, each universal BOOLEAN's content, and an
// extensible match's dnAttributes [4], to FF when true.
func trueAsFF(b []byte, parentTag byte) {
	for len(b) >= 2 {
		tag := b[0]
		n := int(b[1])
		hdr := 2
		if n&0x80 != 0 {
			k := n & 0x7f
			n = 0
			for i := 0; i < k; i++ {
				n = n<<8 | int(b[2+i])
			}
			hdr = 2 + k
		}
		content := b[hdr : hdr+n]
		if tag&0x20 != 0 {
			trueAsFF(content, tag)
		} else if n == 1 && content[0] != 0 && (tag == 0x01 || (tag == 0x84 && parentTag == 0xa9)) {
			content[0] = 0xff
		}
		b = b[hdr+n:]
	}
}

// capture runs op on a client whose server end reads the first message,
// answers it with a success of the right kind, and hands the bytes over.
func capture(op func(c *ldap.Conn)) []byte {
	cl, sv := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		p, err := ber.ReadPacket(sv)
		if err != nil {
			got <- nil
			return
		}
		raw := p.Bytes()
		got <- raw
		if len(p.Children) < 2 {
			sv.Close()
			return
		}
		reply := map[ber.Tag]ber.Tag{0: 1, 3: 5, 6: 7, 8: 9, 10: 11, 12: 13, 14: 15, 23: 24}
		rt, ok := reply[p.Children[1].Tag]
		if !ok {
			sv.Close()
			return
		}
		resp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, p.Children[0].Value, ""))
		r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, rt, nil, "")
		r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
		r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		resp.AppendChild(r)
		sv.Write(resp.Bytes())
		sv.Close()
	}()
	c := ldap.NewConn(cl, false)
	c.Start()
	op(c)
	b := <-got
	c.Close()
	trueAsFF(b, 0)
	return b
}

func requests() {
	const dn = "cn=alice,ou=People,dc=example,dc=com"
	cases := []struct {
		name string
		op   func(c *ldap.Conn)
	}{
		{"bind", func(c *ldap.Conn) { c.Bind("cn=admin,dc=example,dc=com", "secret") }},
		{"unauthenticated_bind", func(c *ldap.Conn) { c.UnauthenticatedBind("cn=nobody") }},
		{"anonymous_bind", func(c *ldap.Conn) { c.UnauthenticatedBind("") }},
		{"external_bind", func(c *ldap.Conn) { c.ExternalBind() }},
		{"digest_md5_bind", func(c *ldap.Conn) { c.MD5Bind("ldap.example.com", "alice", "pw") }},
		{"search", func(c *ldap.Conn) {
			c.Search(ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				"(objectClass=*)", nil, nil))
		}},
		{"search_full", func(c *ldap.Conn) {
			c.Search(ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeSingleLevel, ldap.DerefAlways, 10, 5, true,
				"(&(objectClass=person)(|(cn=a*)(sn~=smith))(!(mail=*))(uidNumber>=1000))", []string{"cn", "mail", "+"}, nil))
		}},
		{"search_controls", func(c *ldap.Conn) {
			p := ldap.NewControlPaging(100)
			p.SetCookie([]byte("cookie\x00\xff"))
			c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
				"(objectClass=*)", []string{"1.1"}, []ldap.Control{p, ldap.NewControlManageDsaIT(true),
					ldap.NewControlString("1.2.3.4", true, "value"), ldap.NewControlString("1.2.3.5", false, ""),
					ldap.NewControlMicrosoftShowDeleted(), ldap.NewControlBeheraPasswordPolicy()}))
		}},
		{"search_paging", func(c *ldap.Conn) {
			c.Search(ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				"(cn=*)", nil, []ldap.Control{ldap.NewControlPaging(2)}))
		}},
		{"add", func(c *ldap.Conn) {
			a := ldap.NewAddRequest(dn, nil)
			a.Attribute("objectClass", []string{"top", "person", "inetOrgPerson"})
			a.Attribute("cn", []string{"alice"})
			a.Attribute("sn", []string{"Liddell"})
			a.Attribute("description", []string{"é\x00\n"})
			c.Add(a)
		}},
		{"modify", func(c *ldap.Conn) {
			m := ldap.NewModifyRequest(dn, nil)
			m.Replace("sn", []string{"Smith"})
			m.Add("mail", []string{"a@example.com", "b@example.com"})
			m.Delete("description", nil)
			m.Delete("telephoneNumber", []string{"+1 555"})
			m.Increment("uidNumber", "5")
			c.Modify(m)
		}},
		{"delete", func(c *ldap.Conn) { c.Del(ldap.NewDelRequest(dn, nil)) }},
		{"delete_subtree", func(c *ldap.Conn) { c.Del(ldap.NewDelRequest(dn, []ldap.Control{ldap.NewControlSubtreeDelete()})) }},
		{"moddn", func(c *ldap.Conn) { c.ModifyDN(ldap.NewModifyDNRequest(dn, "cn=bob", true, "")) }},
		{"moddn_superior", func(c *ldap.Conn) {
			c.ModifyDN(ldap.NewModifyDNRequest(dn, "cn=alice", false, "ou=Staff,dc=example,dc=com"))
		}},
		{"compare", func(c *ldap.Conn) { c.Compare(dn, "sn", "Liddell") }},
		{"password_modify", func(c *ldap.Conn) {
			c.PasswordModify(ldap.NewPasswordModifyRequest("uid=alice,dc=example,dc=com", "old", "new"))
		}},
		{"password_modify_self", func(c *ldap.Conn) { c.PasswordModify(ldap.NewPasswordModifyRequest("", "", "new")) }},
		{"password_modify_generate", func(c *ldap.Conn) { c.PasswordModify(ldap.NewPasswordModifyRequest("", "", "")) }},
		{"who_am_i", func(c *ldap.Conn) { c.WhoAmI(nil) }},
		{"start_tls", func(c *ldap.Conn) { c.StartTLS(nil) }},
		{"unbind", func(c *ldap.Conn) { c.Unbind() }},
	}
	for _, cs := range cases {
		fmt.Println("request", cs.name, hb(capture(cs.op)))
	}
}

var attrs = []string{"cn", "sn", "objectClass", "mail", "uid", "o", "1.2.840.113556.1.4.803", "cn;lang-en", "x-attr"}
var rules = []string{"caseExactMatch", "2.5.13.5", "1.2.840.113556.1.4.803"}

func value(r *rand.Rand) string {
	const alpha = "abcXYZ019 ._-=:<>~&|!*()\\é\x00\x7f#,"
	n := r.Intn(7)
	var b []byte
	for i := 0; i < n; i++ {
		b = append(b, alpha[r.Intn(len(alpha))])
	}
	if r.Intn(5) == 0 {
		b = append(b, "日本"...)
	}
	return string(b)
}

func randomFilter(r *rand.Rand, depth int) string {
	k := r.Intn(12)
	if depth > 3 {
		k = 3 + r.Intn(9)
	}
	switch k {
	case 0, 1:
		op := "&"
		if k == 1 {
			op = "|"
		}
		s := "(" + op
		for i := r.Intn(4); i > 0; i-- {
			s += randomFilter(r, depth+1)
		}
		return s + ")"
	case 2:
		return "(!" + randomFilter(r, depth+1) + ")"
	case 3:
		return "(" + attrs[r.Intn(len(attrs))] + "=*)"
	case 4:
		parts := []string{}
		for i := 1 + r.Intn(3); i > 0; i-- {
			parts = append(parts, ldap.EscapeFilter(value(r)))
		}
		return "(" + attrs[r.Intn(len(attrs))] + "=" + strings.Join(parts, "*") + ")"
	case 5:
		return "(" + attrs[r.Intn(len(attrs))] + ">=" + ldap.EscapeFilter(value(r)) + ")"
	case 6:
		return "(" + attrs[r.Intn(len(attrs))] + "<=" + ldap.EscapeFilter(value(r)) + ")"
	case 7:
		return "(" + attrs[r.Intn(len(attrs))] + "~=" + ldap.EscapeFilter(value(r)) + ")"
	case 8:
		s := "("
		if r.Intn(4) != 0 {
			s += attrs[r.Intn(len(attrs))]
		}
		if r.Intn(2) == 0 {
			s += ":dn"
		}
		if r.Intn(2) == 0 || s == "(" || s == "(:dn" {
			s += ":" + rules[r.Intn(len(rules))]
		}
		return s + ":=" + ldap.EscapeFilter(value(r)) + ")"
	default:
		return "(" + attrs[r.Intn(len(attrs))] + "=" + ldap.EscapeFilter(value(r)) + ")"
	}
}

// Filters go-ldap refuses, which ldap must refuse too.
var badFilters = []string{
	"", "cn=a", "(", "()", "(cn=a", "(cn=a))", "(&(cn=a)", "(|(cn=a)(sn=b)", "(!", "(!(cn=a)",
	"(cn=\\)", "(cn=\\4)", "(cn=\\zz)", "(cn=a\\", "(cn)", "(cn~a)", "(cn>a)", "(&(cn=a))x",
	"(cn=\xff)", "(cn=\xc3)", "(\xe9=a)", "(cn=\xef\xbf\xbd)", "(cn=a)(sn=b)", "((cn=a)", "(cn:=",
}

func filters() {
	r := rand.New(rand.NewSource(1))
	fixed := []string{
		"(objectClass=*)", "(cn=alice)", "(cn=a*)", "(cn=*a)", "(cn=*a*)", "(cn=a*b*c)", "(cn=**)", "(cn=a**b)",
		"(&)", "(|)", "(&(cn=a)(sn=b))", "(|(cn=a)(!(sn=b)))", "(!(!(cn=a)))", "((cn=a))", "(cn>=10)", "(cn<=10)",
		"(cn~=alice)", "(cn:=alice)", "(cn:dn:=alice)", "(cn:caseExactMatch:=Alice)", "(cn:dn:2.5.13.5:=Alice)",
		"(:caseExactMatch:=x)", "(:dn:2.5.13.5:=x)", "(uid=\\2a\\28\\29\\5c\\00)", "(cn=\\c3\\a9)", "(cn=é)",
		"(description=a=b)", "(cn=a(b)", "(=a)", "(cn=)", "(cn=\\C3\\A9)", "(cn= a )",
		"(userAccountControl:1.2.840.113556.1.4.803:=2)", "(&(objectClass=user)(memberOf=CN=Admins,OU=Groups,DC=x))",
		"(cn=" + strings.Repeat("x", 300) + ")",
	}
	var all []string
	all = append(all, fixed...)
	for i := 0; i < 600; i++ {
		all = append(all, randomFilter(r, 0))
	}
	all = append(all, badFilters...)
	for _, f := range all {
		p, err := ldap.CompileFilter(f)
		if err != nil {
			fmt.Println("filter", h(f), "ERR")
			continue
		}
		b := p.Bytes()
		trueAsFF(b, 0)
		fmt.Println("filter", h(f), hb(b))
		back, err := ldap.DecompileFilter(p)
		if err == nil {
			fmt.Println("decompile", hb(b), h(back))
		}
	}
	for _, f := range badFilters {
		if _, err := ldap.CompileFilter(f); err == nil {
			fmt.Fprintln(os.Stderr, "goldap: go-ldap takes the bad filter", f)
			os.Exit(1)
		}
	}
	for _, v := range []string{"", "plain", "a*b", "(x)", "back\\slash", "nul\x00", "é", "\x7f\x80\xff", "日本"} {
		fmt.Println("escape", h(v), h(ldap.EscapeFilter(v)))
	}
}

func escapeDN(v string, r *rand.Rand) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case strings.IndexByte(",+;\"\\<>=#", c) >= 0 || (c == ' ' && (i == 0 || i == len(v)-1)):
			if r.Intn(2) == 0 {
				b.WriteByte('\\')
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "\\%02X", c)
			}
		case c < ' ' || c > '~' || r.Intn(10) == 0:
			fmt.Fprintf(&b, "\\%02x", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func randomDN(r *rand.Rand) string {
	types := []string{"cn", "CN", "ou", "dc", "uid", "O", "2.5.4.3", "sn"}
	var rdns []string
	for i := r.Intn(5); i >= 0; i-- {
		var avas []string
		for j := r.Intn(3); j >= 0; j-- {
			t := types[r.Intn(len(types))]
			v := value(r)
			if v == "" {
				v = "x"
			}
			sp := ""
			if r.Intn(6) == 0 {
				sp = " "
			}
			avas = append(avas, sp+t+sp+"="+sp+escapeDN(v, r))
		}
		rdns = append(rdns, strings.Join(avas, "+"))
	}
	sep := ","
	if r.Intn(8) == 0 {
		sep = ";"
	}
	return strings.Join(rdns, sep)
}

func dns() {
	r := rand.New(rand.NewSource(2))
	fixed := []string{
		"", "cn=alice,dc=example,dc=com", "CN=Alice, OU=People , DC=Example,DC=COM", "cn=a+sn=b,dc=x", "sn=b+cn=a,dc=x",
		"cn=\\ lead,dc=x", "cn=trail\\ ,dc=x", "cn=a\\,b,dc=x", "cn=\\23hash,dc=x", "cn=\\e6\\97\\a5,dc=x", "cn=日本,dc=x",
		"1.3.6.1.4.1.1466.0=#04024869,dc=x", "cn=#04024869", "cn=a;dc=x", "uid=a\\+b+cn=c", "cn=\"quoted\"",
		"cn=a\\\\b", "cn=a\\<b\\>", "cn=  spaced  ", "cn=a ,  dc = x ",
	}
	bad := []string{"cn", "cn=a,dc", "=a,dc=x", "cn=\\4", "cn=\\zz", "cn=#zz", "cn=#0402", "a,cn=b"}
	var all []string
	all = append(all, fixed...)
	for i := 0; i < 300; i++ {
		all = append(all, randomDN(r))
	}
	all = append(all, bad...)
	for _, s := range all {
		d, err := ldap.ParseDN(s)
		if err != nil {
			fmt.Println("dn", h(s), "ERR")
			continue
		}
		fmt.Println("dn", h(s), h(d.String()))
	}
	pairs := [][2]string{
		{"cn=a,dc=x", "CN=a,DC=x"}, {"cn=a,dc=x", "cn=A,dc=x"}, {"cn=a+sn=b,dc=x", "sn=b+cn=a,dc=x"},
		{"dc=x", "cn=a,dc=x"}, {"DC=X", "cn=a,dc=x"}, {"dc=y", "cn=a,dc=x"}, {"cn=a,dc=x", "dc=x"},
		{"", "dc=x"}, {"", ""}, {"cn=a+sn=b", "cn=a"}, {"ou=p,dc=x", "cn=a,ou=p,dc=x"}, {"ou=p,dc=x", "cn=a,ou=P,dc=X"},
	}
	for i := 0; i < 60; i++ {
		a := randomDN(r)
		pairs = append(pairs, [2]string{a, a}, [2]string{a, randomDN(r) + "," + a})
	}
	for _, s := range bad {
		if _, err := ldap.ParseDN(s); err == nil {
			fmt.Fprintln(os.Stderr, "goldap: go-ldap takes the bad DN", s)
			os.Exit(1)
		}
	}
	for _, p := range pairs {
		a, err1 := ldap.ParseDN(p[0])
		b, err2 := ldap.ParseDN(p[1])
		if err1 != nil || err2 != nil {
			continue
		}
		f := func(x bool) string {
			if x {
				return "1"
			}
			return "0"
		}
		fmt.Println("dncmp", h(p[0]), h(p[1]), f(a.Equal(b))+f(a.EqualFold(b))+f(a.AncestorOf(b))+f(a.AncestorOfFold(b)))
	}
}

func search(args []string) {
	c, err := ldap.DialURL(args[0])
	if err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	defer c.Close()
	if len(args) > 4 {
		if err := c.Bind(args[3], args[4]); err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
	}
	res, err := c.Search(ldap.NewSearchRequest(args[1], ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, args[2], nil, nil))
	if err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	for _, e := range res.Entries {
		fmt.Println("dn:", e.DN)
		names := []string{}
		for _, a := range e.Attributes {
			names = append(names, a.Name)
		}
		sort.Strings(names)
		for _, n := range names {
			for _, v := range e.GetRawAttributeValues(n) {
				fmt.Printf("%s: %x\n", n, v)
			}
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: goldap vectors | goldap search <url> <base> <filter> [binddn password]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "vectors":
		requests()
		filters()
		dns()
	case "search":
		if len(os.Args) < 5 {
			fmt.Fprintln(os.Stderr, "usage: goldap search <url> <base> <filter> [binddn password]")
			os.Exit(2)
		}
		search(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: goldap vectors | goldap search <url> <base> <filter> [binddn password]")
		os.Exit(2)
	}
}
