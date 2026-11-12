// Interop with miekg/dns over the network (scripts/interop.py):
//
//	go run . client <port>   miekg's client against goose-dnsd on 127.0.0.1:<port>
//	go run . serve           a miekg server on a free port, for goose-dig
//
// Both print "ok <what>" or "FAIL <what>: why" for each check; client
// exits 1 if any failed. serve prints "listening on <port>" first.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const interopKey = "xfr.example."
const interopSecret = "c2VjcmV0IGtleSBmb3IgdGVzdGluZyBUU0lHIDEyMzQ1Ng=="

var failed bool

func check(what string, ok bool, why ...any) {
	if ok {
		fmt.Println("ok   " + what)
		return
	}
	failed = true
	fmt.Println("FAIL " + what + ": " + fmt.Sprint(why...))
}

func clientMode(port string) {
	addr := net.JoinHostPort("127.0.0.1", port)
	for _, netw := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: netw, Timeout: 5 * time.Second}
		m := new(dns.Msg)
		m.SetQuestion("mail.example.org.", dns.TypeAAAA)
		m.SetEdns0(1232, true)
		r, _, err := c.Exchange(m, addr)
		check("AAAA over "+netw, err == nil && r != nil && len(r.Answer) == 1 &&
			r.Answer[0].String() == "mail.example.org.\t3600\tIN\tAAAA\t2001:db8::2", err, r)
	}
	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("_sip._udp.example.org.", dns.TypeSRV)
	r, _, err := c.Exchange(m, addr)
	check("SRV with its target's addresses", err == nil && len(r.Answer) == 1 && len(r.Extra) == 2, err, r)
	m.SetQuestion("big.example.org.", dns.TypeTXT)
	r, _, err = c.Exchange(m, addr)
	check("truncated over UDP", err == nil && r.Truncated, err, r)
	ct := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
	r, _, err = ct.Exchange(m, addr)
	check("whole over TCP", err == nil && !r.Truncated && len(r.Answer) == 6, err)
	m.SetQuestion("nope.example.org.", dns.TypeA)
	r, _, err = c.Exchange(m, addr)
	check("NXDOMAIN", err == nil && r.Rcode == dns.RcodeNameError && len(r.Ns) == 1, err, r)

	// TSIG: a signed query, miekg checking the signed reply.
	cs := &dns.Client{Timeout: 5 * time.Second, TsigSecret: map[string]string{interopKey: interopSecret}}
	m = new(dns.Msg)
	m.SetQuestion("ns1.example.org.", dns.TypeA)
	m.SetTsig(interopKey, dns.HmacSHA256, 300, time.Now().Unix())
	r, _, err = cs.Exchange(m, addr)
	check("TSIG-signed query", err == nil && r.IsTsig() != nil && len(r.Answer) == 1, err)

	// AXFR, TSIG-signed: every envelope verified by miekg's Transfer.
	t := &dns.Transfer{TsigSecret: map[string]string{interopKey: interopSecret}}
	m = new(dns.Msg)
	m.SetAxfr("example.org.")
	m.SetTsig(interopKey, dns.HmacSHA512, 300, time.Now().Unix())
	ch, err := t.In(m, addr)
	n, envs := 0, 0
	if err == nil {
		for e := range ch {
			if e.Error != nil {
				err = e.Error
				break
			}
			envs++
			n += len(e.RR)
		}
	}
	check(fmt.Sprintf("AXFR with TSIG (%d records, %d messages)", n, envs), err == nil && n >= 5024 && envs > 1, err)

	// A signed update, then the record seen.
	u := new(dns.Msg)
	u.SetUpdate("example.org.")
	a, _ := dns.NewRR("go.example.org. 60 IN A 198.51.100.66")
	u.Insert([]dns.RR{a})
	u.SetTsig(interopKey, dns.HmacSHA1, 300, time.Now().Unix())
	r, _, err = cs.Exchange(u, addr)
	check("signed update", err == nil && r.Rcode == dns.RcodeSuccess, err, r)
	m = new(dns.Msg)
	m.SetQuestion("go.example.org.", dns.TypeA)
	r, _, err = c.Exchange(m, addr)
	check("the update seen", err == nil && len(r.Answer) == 1 && strings.HasSuffix(r.Answer[0].String(), "198.51.100.66"), err, r)
	if failed {
		os.Exit(1)
	}
}

// A miekg server: A and TXT answers, a TXT set too big for UDP, a zone
// of 3000 records by AXFR (TSIG-signed when asked so), and a name that
// answers only signed queries.
func serveMode() {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		panic(err)
	}
	secrets := map[string]string{interopKey: interopSecret}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		q := req.Question[0]
		r := new(dns.Msg)
		r.SetReply(req)
		r.Authoritative = true
		signed := req.IsTsig() != nil
		if signed && w.TsigStatus() != nil {
			r.SetRcode(req, dns.RcodeNotAuth)
			w.WriteMsg(r)
			return
		}
		switch {
		case q.Qtype == dns.TypeAXFR:
			ch := make(chan *dns.Envelope)
			tr := new(dns.Transfer)
			tr.TsigSecret = secrets
			soa, _ := dns.NewRR("example.com. 3600 IN SOA ns.example.com. h.example.com. 7 3600 600 86400 60")
			go func() {
				var rrs []dns.RR
				rrs = append(rrs, soa)
				for i := 0; i < 3000; i++ {
					rr, _ := dns.NewRR(fmt.Sprintf("h%d.example.com. 60 IN TXT \"record number %d of the zone\"", i, i))
					rrs = append(rrs, rr)
					if len(rrs) == 500 {
						ch <- &dns.Envelope{RR: rrs}
						rrs = nil
					}
				}
				rrs = append(rrs, soa)
				ch <- &dns.Envelope{RR: rrs}
				close(ch)
			}()
			if signed {
				r.SetTsig(interopKey, req.IsTsig().Algorithm, 300, time.Now().Unix())
			}
			tr.Out(w, req, ch)
			w.Hijack()
			return
		case q.Name == "big.example.com.":
			for i := 0; i < 8; i++ {
				rr, _ := dns.NewRR(fmt.Sprintf("big.example.com. 60 IN TXT \"%d%s\"", i, strings.Repeat("x", 99)))
				r.Answer = append(r.Answer, rr)
			}
			if w.RemoteAddr().Network() == "udp" {
				r.Truncate(512)
			}
		case q.Name == "secret.example.com.":
			if !signed {
				r.Rcode = dns.RcodeRefused
				break
			}
			rr, _ := dns.NewRR("secret.example.com. 60 IN TXT \"signed\"")
			r.Answer = append(r.Answer, rr)
		default:
			rr, _ := dns.NewRR(q.Name + " 60 IN A 192.0.2.99")
			r.Answer = append(r.Answer, rr)
		}
		if signed {
			r.SetTsig(interopKey, req.IsTsig().Algorithm, 300, time.Now().Unix())
		}
		w.WriteMsg(r)
	})
	us := &dns.Server{PacketConn: pc, Handler: h, TsigSecret: secrets}
	ts := &dns.Server{Listener: l, Handler: h, TsigSecret: secrets}
	go us.ActivateAndServe()
	go ts.ActivateAndServe()
	fmt.Printf("listening on %d\n", port)
	os.Stdout.Sync()
	time.Sleep(10 * time.Minute)
}
