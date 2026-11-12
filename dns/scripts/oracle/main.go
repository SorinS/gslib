// The oracle: miekg/dns v1.1.73 writes the vectors dns's tests check
// against (test/vectors/*.txt) and, with -n, fresh ones for the
// differential.
//
//	go run . rr  ../../test/vectors/rr_corpus.txt  > ../../test/vectors/rr.txt
//	go run . msg ../../test/vectors/rr_corpus.txt  > ../../test/vectors/msg.txt
//	go run . zone ../../test/vectors/zones/example.zone > ../../test/vectors/zone.txt
//	go run . dnssec ../../test/vectors/rr_corpus.txt > ../../test/vectors/dnssec.txt
//	go run . tsig - > ../../test/vectors/tsig.txt
//	go run . misc - > ../../test/vectors/misc.txt
//
// Fields are separated by '|'; bytes outside 0x20..0x7e and '\' '|' are
// written \xHH (tv.goose reads them back).
package main

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func esc(s string) string {
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

// The corpus' entries: lines, an entry with an open '(' joined with the
// lines after it until it closes. '#' lines are comments.
func entries(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var out []string
	var cur string
	depth := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), "\r")
		if depth == 0 && (l == "" || strings.HasPrefix(l, "#")) {
			continue
		}
		if depth > 0 {
			cur += "\n" + l
		} else {
			cur = l
		}
		depth += strings.Count(l, "(") - strings.Count(l, ")")
		if strings.Contains(l, "\"") {
			depth = 0 // parentheses in quotes: the corpus never splits those
		}
		if depth <= 0 {
			out = append(out, cur)
			depth = 0
		}
	}
	return out
}

func wire(rr dns.RR) []byte {
	buf := make([]byte, 65536+512)
	n, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// rr: input | ok | wire | String() of the wire read back   or   input | err
func rrMode(path string) {
	for _, e := range entries(path) {
		rr, err := dns.NewRR(e)
		if err != nil || rr == nil {
			fmt.Printf("%s|err\n", esc(e))
			continue
		}
		w := wire(rr)
		if w == nil {
			fmt.Printf("%s|err\n", esc(e))
			continue
		}
		// The text of the record read back from its wire form, which is
		// what Goose writes text from.
		back, _, err := dns.UnpackRR(w, 0)
		if err != nil {
			fmt.Printf("%s|err\n", esc(e))
			continue
		}
		fmt.Printf("%s|ok|%s|%s\n", esc(e), hex.EncodeToString(w), esc(back.String()))
	}
}

// msg: messages made of the corpus' records, a few per message, in every
// section, with and without EDNS0: the sections' records as uncompressed
// wire, then miekg's packed message (compressed) and its String().
//
//	id | flags | question | answer | ns | extra | => | packed | String()
func msgMode(path string) {
	var rrs []dns.RR
	for _, e := range entries(path) {
		if rr, err := dns.NewRR(e); err == nil && rr != nil && wire(rr) != nil {
			// miekg drops an AMTRELAY's gateway when the D-bit is set: not those.
			if a, ok := rr.(*dns.AMTRELAY); ok && a.GatewayType&0x80 != 0 {
				continue
			}
			rrs = append(rrs, rr)
		}
	}
	for i := 0; i+4 <= len(rrs); i += 3 {
		m := new(dns.Msg)
		m.Id = uint16(i * 7919)
		m.Response = i%2 == 0
		m.Authoritative = i%3 == 0
		m.RecursionDesired = true
		m.RecursionAvailable = i%5 == 0
		m.AuthenticatedData = i%7 == 0
		m.Opcode = []int{0, 0, 0, 4, 5}[i%5]
		m.Rcode = []int{0, 3, 2, 0, 5}[i%5]
		h := rrs[i].Header()
		m.Question = []dns.Question{{Name: h.Name, Qtype: h.Rrtype, Qclass: h.Class}}
		m.Answer = []dns.RR{rrs[i], rrs[i+1]}
		m.Ns = []dns.RR{rrs[i+2]}
		m.Extra = []dns.RR{rrs[i+3]}
		if i%2 == 1 {
			m.SetEdns0(1232, i%4 == 1)
			if i%4 == 3 {
				o := m.IsEdns0()
				o.Option = append(o.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "6e73"},
					&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "24a5ac3c8b6e2c1d"},
					&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: []byte{192, 0, 2, 0}},
					&dns.EDNS0_EDE{InfoCode: 18, ExtraText: "go away"})
			}
			if i%9 == 0 {
				m.Rcode = dns.RcodeBadCookie
			}
		}
		m.Compress = true
		packed, err := m.Pack()
		if err != nil {
			continue
		}
		qw := make([]byte, 512)
		qn, _ := dns.PackDomainName(h.Name, qw, 0, nil, false)
		qw = append(qw[:qn], byte(h.Rrtype>>8), byte(h.Rrtype), byte(h.Class>>8), byte(h.Class))
		sec := func(rs []dns.RR) string {
			var b []byte
			for _, r := range rs {
				b = append(b, wire(r)...)
			}
			return hex.EncodeToString(b)
		}
		// Unpack what was packed: its String() is what Goose must print.
		m2 := new(dns.Msg)
		if err := m2.Unpack(packed); err != nil {
			continue
		}
		flags := packed[2:4]
		fmt.Printf("%d|%d|%d|%s|%s|%s|%s|=>|%s|%s\n", m.Id, int(flags[0])<<8|int(flags[1]), m.Rcode,
			hex.EncodeToString(qw), sec(m.Answer), sec(m.Ns), sec(m.Extra), hex.EncodeToString(packed), esc(m2.String()))
	}
}

// zone: every record of a zone file, as ZoneParser reads it (origin
// "example.org.", $INCLUDE allowed): wire | String().
func zoneMode(path string) {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	zp := dns.NewZoneParser(f, "example.org.", path)
	zp.SetIncludeAllowed(true)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		fmt.Printf("%s|%s\n", hex.EncodeToString(wire(rr)), esc(rr.String()))
	}
	if err := zp.Err(); err != nil {
		fmt.Printf("err|%s\n", esc(err.Error()))
	}
}

// dnssec: keys miekg makes (DNSKEY record | private key file), RRsets it
// signs with each (key index | RRset | RRSIG record), DS records and key
// tags for the corpus' keys, and NSEC3 hashes.
func dnssecMode(path string) {
	sets := [][]string{
		{"www.example.org. 300 IN A 192.0.2.1", "www.example.org. 300 IN A 192.0.2.2", "www.example.org. 300 IN A 192.0.2.1"},
		{"Example.ORG. 3600 IN MX 10 Mail.Example.ORG.", "Example.ORG. 3600 IN MX 20 backup.example.net."},
		{"a.b.example.org. 60 IN TXT \"one\" \"two\""},
		{"*.wild.example.org. 60 IN AAAA 2001:db8::1"},
		{"example.org. 86400 IN SOA NS1.example.org. hostmaster.example.org. 1 2 3 4 5"},
	}
	const inception, expiration = 1700000000, 2000000000
	n := 0
	for _, a := range []struct {
		alg  uint8
		bits int
	}{{dns.RSASHA1, 1024}, {dns.RSASHA1NSEC3SHA1, 1024}, {dns.RSASHA256, 2048}, {dns.RSASHA512, 1024},
		{dns.ECDSAP256SHA256, 256}, {dns.ECDSAP384SHA384, 384}, {dns.ED25519, 256}} {
		k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags: 257, Protocol: 3, Algorithm: a.alg}
		priv, err := k.Generate(a.bits)
		if err != nil {
			panic(err)
		}
		fmt.Printf("key|%d|%s|%s\n", a.alg, hex.EncodeToString(wire(k)), esc(k.PrivateKeyString(priv)))
		for _, set := range sets {
			var rrs []dns.RR
			var w []byte
			for _, t := range set {
				rr, err := dns.NewRR(t)
				if err != nil {
					panic(err)
				}
				rrs = append(rrs, rr)
				w = append(w, wire(rr)...)
			}
			sig := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: 3600}, Algorithm: a.alg, KeyTag: k.KeyTag(),
				SignerName: k.Hdr.Name, Inception: inception, Expiration: expiration}
			if err := sig.Sign(priv.(crypto.Signer), rrs); err != nil {
				panic(err)
			}
			if err := sig.Verify(k, rrs); err != nil {
				panic(err)
			}
			fmt.Printf("sig|%d|%s|%s\n", n, hex.EncodeToString(w), hex.EncodeToString(wire(sig)))
		}
		n++
	}
	for _, e := range entries(path) {
		rr, err := dns.NewRR(e)
		if err != nil {
			continue
		}
		k, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		for _, d := range []uint8{dns.SHA1, dns.SHA256, dns.SHA384} {
			ds := k.ToDS(d)
			fmt.Printf("ds|%s|%d|%d|%s\n", hex.EncodeToString(wire(k)), d, k.KeyTag(), hex.EncodeToString(wire(ds)))
		}
	}
	for _, c := range []struct {
		name, salt string
		iter       uint16
	}{{"example.", "aabbccdd", 12}, {"a.example.", "aabbccdd", 12}, {"Ns1.Example.", "aabbccdd", 12},
		{"example.org.", "", 0}, {"*.w.example.", "aabbccdd", 12}, {"x.y.w.example.", "ff", 100}, {".", "", 1}} {
		fmt.Printf("nsec3|%s|%d|%s|%s\n", esc(c.name), c.iter, c.salt, dns.HashName(c.name, dns.SHA1, c.iter, c.salt))
	}
}

// tsig: for each algorithm, a query signed with TSIG, the reply signed
// over the query's MAC, and a next message signed timers-only over the
// reply's: alg | key | secret | time | unsigned | signed | MAC for each.
// sig0: messages signed with SIG(0) keys: KEY record | message.
func tsigMode() {
	const secret = "c2VjcmV0IGtleSBmb3IgdGVzdGluZyBUU0lHIDEyMzQ1Ng=="
	const t = 1700000000
	for _, alg := range []string{dns.HmacSHA1, dns.HmacSHA224, dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512} {
		key := "Key.Example."
		m := new(dns.Msg)
		m.SetQuestion("www.example.org.", dns.TypeA)
		m.Id = 4242
		m.SetEdns0(1232, false)
		unsigned, _ := m.Pack()
		m.SetTsig(key, alg, 300, t)
		signed, mac, err := dns.TsigGenerate(m, secret, "", false)
		if err != nil {
			panic(err)
		}
		fmt.Printf("tsig|%s|%s|%s|%d|%s|%s|%s|\n", alg, key, secret, t, hex.EncodeToString(unsigned), hex.EncodeToString(signed), mac)
		r := new(dns.Msg)
		r.SetReply(m)
		r.Extra = nil
		a, _ := dns.NewRR("www.example.org. 300 IN A 192.0.2.1")
		r.Answer = []dns.RR{a}
		unsigned, _ = r.Pack()
		r.SetTsig(key, alg, 300, t+1)
		signed2, mac2, err := dns.TsigGenerate(r, secret, mac, false)
		if err != nil {
			panic(err)
		}
		fmt.Printf("tsig|%s|%s|%s|%d|%s|%s|%s|%s\n", alg, key, secret, t+1, hex.EncodeToString(unsigned), hex.EncodeToString(signed2), mac2, mac)
		r.Extra = nil
		r.Answer = []dns.RR{a, a}
		unsigned, _ = r.Pack()
		r.SetTsig(key, alg, 300, t+2)
		signed3, mac3, err := dns.TsigGenerate(r, secret, mac2, true)
		if err != nil {
			panic(err)
		}
		fmt.Printf("timers|%s|%s|%s|%d|%s|%s|%s|%s\n", alg, key, secret, t+2, hex.EncodeToString(unsigned), hex.EncodeToString(signed3), mac3, mac2)
	}
	for _, alg := range []uint8{dns.RSASHA256, dns.ECDSAP256SHA256} {
		k := &dns.KEY{DNSKEY: dns.DNSKEY{Hdr: dns.RR_Header{Name: "sig0.example.", Rrtype: dns.TypeKEY, Class: dns.ClassINET},
			Flags: 512, Protocol: 3, Algorithm: alg}}
		bits := 2048
		if alg == dns.ECDSAP256SHA256 {
			bits = 256
		}
		priv, err := k.Generate(bits)
		if err != nil {
			panic(err)
		}
		m := new(dns.Msg)
		m.SetUpdate("example.")
		a, _ := dns.NewRR("host.example. 300 IN A 192.0.2.7")
		m.Insert([]dns.RR{a})
		m.Id = 777
		sig := &dns.SIG{RRSIG: dns.RRSIG{Algorithm: alg, KeyTag: k.KeyTag(), SignerName: k.Hdr.Name,
			Inception: t - 100, Expiration: 2000000000}}
		w, err := sig.Sign(priv.(crypto.Signer), m)
		if err != nil {
			panic(err)
		}
		fmt.Printf("sig0|%s|%s|%s\n", hex.EncodeToString(wire(k)), hex.EncodeToString(w), esc(k.PrivateKeyString(priv)))
	}
}

// misc: miekg's name functions over names (name | labels | split | fqdn |
// canonical | isdomain), pairs (a | b | compare | subdomain), reverse
// names, resolv.conf's NameList, dynamic update messages and EDNS0
// options packed.
func miscMode() {
	names := []string{"www.example.org.", "www.example.org", ".", "a\\.b.c.", "A.B.", "x", "a..b.", "*.w.example.", "\\000.x.", ""}
	for _, n := range names {
		_, isd := dns.IsDomainName(n)
		fmt.Printf("name|%s|%d|%s|%s|%s|%t\n", esc(n), dns.CountLabel(n), esc(strings.Join(dns.SplitDomainName(n), ",")),
			esc(dns.Fqdn(n)), esc(dns.CanonicalName(n)), isd)
	}
	pairs := [][2]string{{"example.org.", "www.example.org."}, {"www.example.org.", "example.org."}, {"Example.ORG.", "x.example.org."},
		{"org.", "example.com."}, {".", "a.b."}, {"a.b.c.", "x.b.c."}, {"b.c.", "b.c."}}
	for _, p := range pairs {
		fmt.Printf("pair|%s|%s|%d|%t\n", p[0], p[1], dns.CompareDomainName(p[0], p[1]), dns.IsSubDomain(p[0], p[1]))
	}
	for _, a := range []string{"192.0.2.1", "2001:db8::567:89ab", "::1"} {
		r, _ := dns.ReverseAddr(a)
		fmt.Printf("rev|%s|%s\n", a, r)
	}
	conf := "nameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch a.example b.example.\noptions ndots:2 timeout:0 attempts:3 rotate\n"
	cc, _ := dns.ClientConfigFromReader(strings.NewReader(conf))
	for _, n := range []string{"www", "a.b", "a.b.c", "x.y."} {
		fmt.Printf("namelist|%s|%s|%s|%d|%d|%d|%s\n", esc(conf), n, strings.Join(cc.NameList(n), ","), cc.Ndots, cc.Timeout, cc.Attempts, strings.Join(cc.Servers, ","))
	}
	// Updates: one message with every helper.
	rr1, _ := dns.NewRR("a.example. 300 IN A 192.0.2.1")
	rr2, _ := dns.NewRR("b.example. 300 IN TXT \"x\"")
	m := new(dns.Msg)
	m.SetUpdate("example.")
	m.Id = 99
	m.NameUsed([]dns.RR{rr1})
	m.NameNotUsed([]dns.RR{rr2})
	m.RRsetUsed([]dns.RR{rr1})
	m.RRsetNotUsed([]dns.RR{rr2})
	m.Used([]dns.RR{dns.Copy(rr1)})
	m.Insert([]dns.RR{dns.Copy(rr1), dns.Copy(rr2)})
	m.RemoveRRset([]dns.RR{rr1})
	m.RemoveName([]dns.RR{rr2})
	m.Remove([]dns.RR{dns.Copy(rr1)})
	w, _ := m.Pack()
	fmt.Printf("update|%s|%s\n", hex.EncodeToString(w), esc(m.String()))
	// EDNS0 options.
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetUDPSize(4096)
	o.SetDo()
	o.Option = append(o.Option,
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 22, Address: []byte{192, 0, 2, 129}},
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 2, SourceNetmask: 48, Address: []byte{0x20, 1, 0xd, 0xb8, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 1}},
		&dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE, Timeout: 150},
		&dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE},
		&dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeDNSBogus, ExtraText: "bad"},
		&dns.EDNS0_PADDING{Padding: make([]byte, 5)},
		&dns.EDNS0_EXPIRE{Code: dns.EDNS0EXPIRE, Expire: 3600},
		&dns.EDNS0_LOCAL{Code: 65001, Data: []byte{1, 2, 3}})
	// Truncate: answer, authority and additional records, an OPT, cut to sizes.
	for _, size := range []int{512, 700, 1232, 100} {
		t := new(dns.Msg)
		t.SetQuestion("many.example.", dns.TypeA)
		t.Id = 7
		var all []byte
		for i := 0; i < 40; i++ {
			rr, _ := dns.NewRR(fmt.Sprintf("many.example. 60 IN A 192.0.2.%d", i))
			t.Answer = append(t.Answer, rr)
		}
		for i := 0; i < 5; i++ {
			rr, _ := dns.NewRR(fmt.Sprintf("example. 60 IN NS ns%d.example.", i))
			t.Ns = append(t.Ns, rr)
		}
		for i := 0; i < 5; i++ {
			rr, _ := dns.NewRR(fmt.Sprintf("ns%d.example. 60 IN A 192.0.2.%d", i, 100+i))
			t.Extra = append(t.Extra, rr)
		}
		t.SetEdns0(1232, false)
		for _, r := range t.Answer {
			all = append(all, wire(r)...)
		}
		t.Truncate(size)
		w, _ := t.Pack()
		fmt.Printf("truncate|%d|%s\n", size, hex.EncodeToString(w))
	}
	back, _, _ := dns.UnpackRR(wire(o), 0) // the text of what was packed
	fmt.Printf("opt|%s|%s\n", hex.EncodeToString(wire(o)), esc(back.String()))
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "serve" {
		serveMode()
		return
	}
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: oracle rr|msg|zone|dnssec|tsig|misc|client|serve [arg]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "rr":
		rrMode(os.Args[2])
	case "msg":
		msgMode(os.Args[2])
	case "zone":
		zoneMode(os.Args[2])
	case "dnssec":
		dnssecMode(os.Args[2])
	case "tsig":
		tsigMode()
	case "misc":
		miscMode()
	case "client":
		clientMode(os.Args[2])
	case "serve":
		serveMode()
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}
