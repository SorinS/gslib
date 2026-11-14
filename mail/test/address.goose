// Addresses against Go's net/mail: parse_address and parse_address_list
// on RFC 5322's examples, net/mail's own test inputs and its error cases,
// each address written back as (*Address).String writes it. The tables
// are Go's answers (go1.27.1). Then what Go
// does not cover: CR and LF refused, make_address, names past the
// capacity of an Address, and the B and Q choice for display names.
import std;
import gslib from "../..";
import gslib.mail;
import gslib.mail.address;

struct One { input: const u8[:], ok: bool, name: const u8[:], addr: const u8[:], text: const u8[:] }
struct Many { input: const u8[:], ok: bool, text: const u8[:] }

let SINGLE = [
    One { input: "jdoe@machine.example", ok: true, name: "", addr: "jdoe@machine.example", text: "<jdoe@machine.example>" },
    One { input: "John Doe <jdoe@machine.example>", ok: true, name: "John Doe", addr: "jdoe@machine.example", text: "\"John Doe\" <jdoe@machine.example>" },
    One { input: "\"Joe Q. Public\" <john.q.public@example.com>", ok: true, name: "Joe Q. Public", addr: "john.q.public@example.com", text: "\"Joe Q. Public\" <john.q.public@example.com>" },
    One { input: "John (middle) Doe <jdoe@machine.example>", ok: true, name: "John Doe", addr: "jdoe@machine.example", text: "\"John Doe\" <jdoe@machine.example>" },
    One { input: "\"John (middle) Doe\" <jdoe@machine.example>", ok: true, name: "John (middle) Doe", addr: "jdoe@machine.example", text: "\"John (middle) Doe\" <jdoe@machine.example>" },
    One { input: "\"John <middle> Doe\" <jdoe@machine.example>", ok: true, name: "John <middle> Doe", addr: "jdoe@machine.example", text: "\"John <middle> Doe\" <jdoe@machine.example>" },
    One { input: "Mary Smith <mary@x.test>", ok: true, name: "Mary Smith", addr: "mary@x.test", text: "\"Mary Smith\" <mary@x.test>" },
    One { input: "<boss@nil.test>", ok: true, name: "", addr: "boss@nil.test", text: "<boss@nil.test>" },
    One { input: "\"Giant; \\\"Big\\\" Box\" <sysservices@example.net>", ok: true, name: "Giant; \"Big\" Box", addr: "sysservices@example.net", text: "\"Giant; \\\"Big\\\" Box\" <sysservices@example.net>" },
    One { input: "Pete(A nice \\) chap) <pete(his account)@silly.test(his host)>", ok: false, name: "", addr: "", text: "" },
    One { input: "=?iso-8859-1?q?J=F6rg_Doe?= <joerg@example.com>", ok: true, name: "J\xc3\xb6rg Doe", addr: "joerg@example.com", text: "=?utf-8?q?J=C3=B6rg_Doe?= <joerg@example.com>" },
    One { input: "=?us-ascii?q?J=6Frg_Doe?= <joerg@example.com>", ok: true, name: "Jorg Doe", addr: "joerg@example.com", text: "\"Jorg Doe\" <joerg@example.com>" },
    One { input: "=?ISO-8859-1?Q?J=F6rg_Doe?= <joerg@example.com>", ok: true, name: "J\xc3\xb6rg Doe", addr: "joerg@example.com", text: "=?utf-8?q?J=C3=B6rg_Doe?= <joerg@example.com>" },
    One { input: "=?utf-8?q?J=C3=B6rg?=  =?utf-8?q?Doe?= <joerg@example.com>", ok: true, name: "J\xc3\xb6rgDoe", addr: "joerg@example.com", text: "=?utf-8?q?J=C3=B6rgDoe?= <joerg@example.com>" },
    One { input: "=?utf-8?q?J=C3=B6rg?= Doe <joerg@example.com>", ok: true, name: "J\xc3\xb6rg Doe", addr: "joerg@example.com", text: "=?utf-8?q?J=C3=B6rg_Doe?= <joerg@example.com>" },
    One { input: "Doe =?utf-8?b?SsO2cmc=?= <joerg@example.com>", ok: true, name: "Doe J\xc3\xb6rg", addr: "joerg@example.com", text: "=?utf-8?q?Doe_J=C3=B6rg?= <joerg@example.com>" },
    One { input: "=?UTF-8?B?w6Nr?= <a@example.com>", ok: true, name: "\xc3\xa3k", addr: "a@example.com", text: "=?utf-8?q?=C3=A3k?= <a@example.com>" },
    One { input: "=?utf-8?q?Bad=ZZword?= <a@example.com>", ok: true, name: "=?utf-8?q?Bad=ZZword?=", addr: "a@example.com", text: "\"=?utf-8?q?Bad=ZZword?=\" <a@example.com>" },
    One { input: "asjo@example.com (Andy Sjostrom)", ok: true, name: "Andy Sjostrom", addr: "asjo@example.com", text: "\"Andy Sjostrom\" <asjo@example.com>" },
    One { input: "asjo@example.com (=?utf-8?q?Andy_Sj=C3=B6str=C3=B6m?=)", ok: true, name: "Andy Sj\xc3\xb6str\xc3\xb6m", addr: "asjo@example.com", text: "=?utf-8?q?Andy_Sj=C3=B6str=C3=B6m?= <asjo@example.com>" },
    One { input: "jdoe@machine.example (  spaced   out  )", ok: true, name: "spaced out", addr: "jdoe@machine.example", text: "\"spaced out\" <jdoe@machine.example>" },
    One { input: "Group: jdoe@example.org;", ok: true, name: "", addr: "jdoe@example.org", text: "<jdoe@example.org>" },
    One { input: "Group: John Doe <jdoe@example.org>;", ok: true, name: "John Doe", addr: "jdoe@example.org", text: "\"John Doe\" <jdoe@example.org>" },
    One { input: "Group: jdoe@example.org; (comment)", ok: true, name: "", addr: "jdoe@example.org", text: "<jdoe@example.org>" },
    One { input: "\"Ciel\" <\"ciel tech\"@example.com>", ok: true, name: "Ciel", addr: "ciel tech@example.com", text: "\"Ciel\" <\"ciel tech\"@example.com>" },
    One { input: "<\"quoted local\"@example.com>", ok: true, name: "", addr: "quoted local@example.com", text: "<\"quoted local\"@example.com>" },
    One { input: "\"\" <empty@example.com>", ok: true, name: "", addr: "empty@example.com", text: "<empty@example.com>" },
    One { input: "B\xc3\xb6b <bob@example.com>", ok: true, name: "B\xc3\xb6b", addr: "bob@example.com", text: "=?utf-8?q?B=C3=B6b?= <bob@example.com>" },
    One { input: "\"B\xc3\xb6b Jac\xc3\xb6b\" <bob@example.com>", ok: true, name: "B\xc3\xb6b Jac\xc3\xb6b", addr: "bob@example.com", text: "=?utf-8?q?B=C3=B6b_Jac=C3=B6b?= <bob@example.com>" },
    One { input: "bob@[192.168.0.1]", ok: true, name: "", addr: "bob@[192.168.0.1]", text: "<bob@[192.168.0.1]>" },
    One { input: "Bob <bob@[IPv6:fd42::dead:beef:1234]>", ok: true, name: "Bob", addr: "bob@[IPv6:fd42::dead:beef:1234]", text: "\"Bob\" <bob@[IPv6:fd42::dead:beef:1234]>" },
    One { input: "bob@[::ffff:192.168.0.1]", ok: true, name: "", addr: "bob@[::ffff:192.168.0.1]", text: "<bob@[::ffff:192.168.0.1]>" },
    One { input: "jdoe@machine.example  ", ok: true, name: "", addr: "jdoe@machine.example", text: "<jdoe@machine.example>" },
    One { input: "  jdoe@machine.example", ok: true, name: "", addr: "jdoe@machine.example", text: "<jdoe@machine.example>" },
    One { input: "(c1) jdoe@machine.example (c2)", ok: false, name: "", addr: "", text: "" },
    One { input: "John.Doe <jdoe@example.com>", ok: true, name: "John.Doe", addr: "jdoe@example.com", text: "\"John.Doe\" <jdoe@example.com>" },
    One { input: "John..Doe. <jdoe@example.com>", ok: true, name: "John..Doe.", addr: "jdoe@example.com", text: "\"John..Doe.\" <jdoe@example.com>" },
    One { input: "emoji \xf0\x9f\xa6\x86 <duck@example.com>", ok: true, name: "emoji \xf0\x9f\xa6\x86", addr: "duck@example.com", text: "=?utf-8?q?emoji_=F0=9F=A6=86?= <duck@example.com>" },
    One { input: "user+tag@sub.example.com", ok: true, name: "", addr: "user+tag@sub.example.com", text: "<user+tag@sub.example.com>" },
    One { input: "x@y", ok: true, name: "", addr: "x@y", text: "<x@y>" },
    One { input: "=?utf-8?q?=E2=82=AC?= <euro@example.com>", ok: true, name: "\xe2\x82\xac", addr: "euro@example.com", text: "=?utf-8?q?=E2=82=AC?= <euro@example.com>" },
    One { input: "Al \"Bundy\" Jr <al@example.com>", ok: true, name: "Al Bundy Jr", addr: "al@example.com", text: "\"Al Bundy Jr\" <al@example.com>" },
    One { input: "\"Tab\x09In\" <tab@example.com>", ok: true, name: "Tab\x09In", addr: "tab@example.com", text: "\"Tab\x09In\" <tab@example.com>" },
    One { input: "=?iso-8859-2?Q?Bogl=E1rka_Tak=E1cs?= <unknown@gmail.com>", ok: false, name: "", addr: "", text: "" },
    One { input: "a@gmail.com b@gmail.com", ok: false, name: "", addr: "", text: "" },
    One { input: "\xed\xa0\x80 <micro@example.net>", ok: false, name: "", addr: "", text: "" },
    One { input: "\"\xed\xa0\x80\" <half-surrogate@example.com>", ok: false, name: "", addr: "", text: "" },
    One { input: "\"\\\x80\" <escaped-invalid-unicode@example.net>", ok: false, name: "", addr: "", text: "" },
    One { input: "\"\x00\" <null@example.net>", ok: false, name: "", addr: "", text: "" },
    One { input: "\"\\\x00\" <escaped-null@example.net>", ok: false, name: "", addr: "", text: "" },
    One { input: "John Doe", ok: false, name: "", addr: "", text: "" },
    One { input: "<jdoe#machine.example>", ok: false, name: "", addr: "", text: "" },
    One { input: "John <middle> Doe <jdoe@machine.example>", ok: false, name: "", addr: "", text: "" },
    One { input: "cfws@example.com (", ok: false, name: "", addr: "", text: "" },
    One { input: "empty group: ;", ok: false, name: "", addr: "", text: "" },
    One { input: "root group: embed group: null@example.com;", ok: false, name: "", addr: "", text: "" },
    One { input: "group not closed: null@example.com", ok: false, name: "", addr: "", text: "" },
    One { input: "group: first@example.com, second@example.com;", ok: false, name: "", addr: "", text: "" },
    One { input: "john.doe", ok: false, name: "", addr: "", text: "" },
    One { input: "john.doe@", ok: false, name: "", addr: "", text: "" },
    One { input: "John Doe@foo.bar", ok: false, name: "", addr: "", text: "" },
    One { input: " group: null@example.com; (asd", ok: false, name: "", addr: "", text: "" },
    One { input: " group: ; (asd", ok: false, name: "", addr: "", text: "" },
    One { input: "(John) Doe <jdoe@machine.example>", ok: false, name: "", addr: "", text: "" },
    One { input: "<jdoe@[\xed\xa0\x80192.168.0.1]>", ok: false, name: "", addr: "", text: "" },
    One { input: "<jdoe@[[192.168.0.1]>", ok: false, name: "", addr: "", text: "" },
    One { input: "<jdoe@[192.168.0.1>", ok: false, name: "", addr: "", text: "" },
    One { input: "<jdoe@[256.0.0.1]>", ok: false, name: "", addr: "", text: "" },
    One { input: "<jdoe@[fd42::de:ad:be:ef]>", ok: false, name: "", addr: "", text: "" },
    One { input: "<jdoe@[010.0.0.1]>", ok: false, name: "", addr: "", text: "" },
    One { input: "", ok: false, name: "", addr: "", text: "" },
    One { input: "   ", ok: false, name: "", addr: "", text: "" },
    One { input: "<>", ok: false, name: "", addr: "", text: "" },
    One { input: "<@example.com>", ok: false, name: "", addr: "", text: "" },
    One { input: "<a@>", ok: false, name: "", addr: "", text: "" },
    One { input: ".a@example.com", ok: false, name: "", addr: "", text: "" },
    One { input: "a.@example.com", ok: false, name: "", addr: "", text: "" },
    One { input: "a..b@example.com", ok: false, name: "", addr: "", text: "" },
    One { input: "John Doe <jdoe@machine.example", ok: false, name: "", addr: "", text: "" },
    One { input: "\"unclosed <a@example.com>", ok: false, name: "", addr: "", text: "" },
];

let LISTS = [
    Many { input: "jdoe@machine.example, John Doe <jdoe2@machine.example>", ok: true, text: "<jdoe@machine.example>, \"John Doe\" <jdoe2@machine.example>" },
    Many { input: "A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;, Mary Smith <mary@x.test>", ok: true, text: "\"Ed Jones\" <c@a.test>, <joe@where.test>, \"John\" <jdoe@one.test>, \"Mary Smith\" <mary@x.test>" },
    Many { input: "Undisclosed recipients:;", ok: true, text: "" },
    Many { input: ", , a@example.com,,b@example.com, ", ok: true, text: "<a@example.com>, <b@example.com>" },
    Many { input: "a@example.com (one), \"Two, Too\" <b@example.com>", ok: true, text: "\"one\" <a@example.com>, \"Two, Too\" <b@example.com>" },
    Many { input: "=?utf-8?q?J=C3=B6rg?= <j@example.com>, =?utf-8?b?SsO2cmc=?= <k@example.com>", ok: true, text: "=?utf-8?q?J=C3=B6rg?= <j@example.com>, =?utf-8?q?J=C3=B6rg?= <k@example.com>" },
    Many { input: "a@example.com b@example.com", ok: false, text: "" },
    Many { input: "a@example.com,, b@", ok: false, text: "" },
    Many { input: "", ok: false, text: "" },
    Many { input: "g: a@example.com, b@example.com; , c@example.com", ok: true, text: "<a@example.com>, <b@example.com>, <c@example.com>" },
];

var failures = 0;

fn fail(what: const u8[:], input: const u8[:], got: const u8[:], want: const u8[:]) {
    print("FAIL ", what, ": ", input, "\n  got  ", got, "\n  want ", want);
    failures++;
}

fn check_one(t: One) {
    let a, rc = mail::parse_address(t.input);
    if (rc == mail::OK) != t.ok { fail("parse_address ok", t.input, str(rc), str(t.ok)); return; }
    if !t.ok {
        if rc != mail::ERR_ADDRESS { fail("parse_address code", t.input, str(rc), str(mail::ERR_ADDRESS)); }
        return;
    }
    if a.name != t.name { fail("name", t.input, a.name, t.name); }
    if a.addr != t.addr { fail("addr", t.input, a.addr, t.addr); }
    let s = mail::address_string(a);
    if s != t.text { fail("string", t.input, s, t.text); }
    // What is written reads back as the same address.
    let b, rc2 = mail::parse_address(s);
    if rc2 != mail::OK || b.name != a.name || b.addr != a.addr { fail("round trip", t.input, s, t.text); }
}

fn check_many(t: Many) {
    var got: mail::Address[>..] = [];
    got.push(mail::Address { name: "kept", addr: "kept@example.com" });
    let rc = mail::parse_address_list(t.input, got);
    if (rc == mail::OK) != t.ok { fail("parse_address_list ok", t.input, str(rc), str(t.ok)); return; }
    if !t.ok {
        if got.len != 1 { fail("list left as it was", t.input, str(got.len), "1"); }
        return;
    }
    var s: u8[>..] = [];
    for i in 1..got.len {
        if i > 1 { s.append(", "); }
        mail::write_address(s, got[i]);
    }
    if s != t.text { fail("list", t.input, s, t.text); }
}

fn expect_error(input: const u8[:]) {
    let a, rc = mail::parse_address(input);
    if rc != mail::ERR_ADDRESS { fail("refused", input, str(rc), "ERR_ADDRESS"); }
    var l: mail::Address[>..] = [];
    if mail::parse_address_list(input, l) != mail::ERR_ADDRESS || l.len != 0 { fail("list refused", input, str(l.len), "0"); }
}

fn main() {
    for t in SINGLE { check_one(t); }
    for t in LISTS { check_many(t); }

    // CR, LF and NUL, wherever they are: in a comment Go's grammar takes
    // any byte, so only the scan refuses them there.
    expect_error("a@example.com\r\nBcc: x@example.com");
    expect_error("a@example.com (x\r\ny)");
    expect_error("a@example.com (x\ny)");
    expect_error("\"A\rB\" <a@example.com>");
    expect_error("a@example.com (x\x00)");

    // make_address: the name as it is, the address an addr-spec alone.
    let m, mrc = mail::make_address("Zoë \"Z\" Ng", "zoe@example.com");
    if mrc != mail::OK || m.name != "Zoë \"Z\" Ng" || m.addr != "zoe@example.com" { fail("make_address", "", m.name, ""); }
    let ms = mail::address_string(m);
    if ms != "=?utf-8?b?Wm/DqyAiWiIgTmc=?= <zoe@example.com>" { fail("make_address string", "", ms, ""); }
    let back, brc = mail::parse_address(ms);
    if brc != mail::OK || back.name != m.name { fail("make_address round trip", ms, back.name, m.name); }
    let x1, r1 = mail::make_address("", "Name <a@example.com>");
    if r1 != mail::ERR_ADDRESS { fail("make_address not a bare addr-spec", "", str(r1), ""); }
    let x2, r2 = mail::make_address("A\nB", "a@example.com");
    if r2 != mail::ERR_ADDRESS { fail("make_address LF in name", "", str(r2), ""); }
    let x3, r3 = mail::make_address("", "a@example.com\r\n");
    if r3 != mail::ERR_ADDRESS { fail("make_address CRLF in addr", "", str(r3), ""); }

    // Capacity: a 256-byte name fits, 257 does not; so for 320 and 321 in addr.
    var name: u8[>..] = [];
    for i in 256 { name.push('n'); }
    let n1, nr1 = mail::make_address(name, "a@example.com");
    if nr1 != mail::OK || n1.name.len != 256 { fail("256-byte name", "", str(nr1), "0"); }
    name.push('n');
    let n2, nr2 = mail::make_address(name, "a@example.com");
    if nr2 != mail::ERR_ADDRESS { fail("257-byte name", "", str(nr2), "ERR_ADDRESS"); }
    var long: u8[>..] = [];
    for i in 64 { long.push('l'); }
    long.push('@');
    while long.len < 320 { long.append("d."); }
    long.resize(319);
    long.push('x');
    let l1, lr1 = mail::parse_address(long);
    if lr1 != mail::OK || l1.addr.len != 320 { fail("320-byte addr", "", str(lr1), "0"); }
    long.push('y');
    let l2, lr2 = mail::parse_address(long);
    if lr2 != mail::ERR_ADDRESS { fail("321-byte addr", "", str(lr2), "ERR_ADDRESS"); }

    // Q for plain non-ASCII names, B when one holds a character RFC 2047
    // forbids in a phrase's encoded-word; both read back.
    let qa = mail::Address { name: "Jörg", addr: "j@example.com" };
    let q = mail::address_string(qa);
    if q != "=?utf-8?q?J=C3=B6rg?= <j@example.com>" { fail("Q name", "", q, ""); }
    let ba = mail::Address { name: "Müller, Jörg", addr: "j@example.com" };
    let b = mail::address_string(ba);
    if b != "=?utf-8?b?TcO8bGxlciwgSsO2cmc=?= <j@example.com>" { fail("B name", "", b, ""); }
    let bb, brc2 = mail::parse_address(b);
    if brc2 != mail::OK || bb.name != "Müller, Jörg" { fail("B name read back", b, bb.name, ""); }

    if failures > 0 {
        print(failures, " failures");
        exit(1);
    }
    print("address: ok (", SINGLE.len, " addresses, ", LISTS.len, " lists)");
}
