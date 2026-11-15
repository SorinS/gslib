// The parts of mail.imap that need no server: the response parser
// (literals inline, nested lists, quoted escapes, NIL, BODY[...] atoms,
// malformed responses), FETCH items, ENVELOPE and BODYSTRUCTURE, LIST,
// STATUS, SEARCH and ESEARCH, response codes, modified UTF-7, sequence
// sets, how arguments are sent (atom, quoted, literal, refused), and the
// client refusing commands before a connection. scripts/interop.py runs
// the client against servers.
import std;
import gslib from "../..";
import gslib.mail;
import gslib.mail.address;
import gslib.mail.imap;

var failures = 0;

fn check(what: const u8[:], ok: bool) {
    if !ok { print("FAIL ", what); failures++; }
}

fn utf7(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if !imap::utf7_encode(out, s) { out.append("<bad>"); }
    return out;
}

fn unutf7(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if !imap::utf7_decode(out, s) { out.append("<bad>"); }
    return out;
}

fn seqs(nums: const i64[:]) -> u8[>..] {
    var out: u8[>..] = [];
    imap::seq_set(out, nums);
    return out;
}

fn arg(s: const u8[:], utf8: bool, nonsync: bool) -> u8[>..] {
    var out: u8[>..] = [];
    if imap::astring(out, s, utf8, nonsync) == imap::ARG_BAD { out.append("<bad>"); }
    return out;
}

fn item_of(s: const u8[:], name: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if !imap::item(s, name, out) { out.append("<none>"); }
    return out;
}

fn parses(s: const u8[:]) -> bool {
    var nodes: imap::Node[>..] = [];
    return imap::tree(s, nodes);
}

fn main() {
    // --- Literals at the end of a line
    check("literal: plain", imap::literal_at_end("* 1 FETCH (BODY[] {42}") == 42);
    check("literal: non-synchronizing", imap::literal_at_end("x {7+}") == 7);
    check("literal: literal8", imap::literal_at_end("* 1 FETCH (BINARY[] ~{3}") == 3);
    check("literal: zero", imap::literal_at_end("{0}") == 0);
    check("literal: none", imap::literal_at_end("* OK done") == -1);
    check("literal: not digits", imap::literal_at_end("* OK {x}") == -1);
    check("literal: empty braces", imap::literal_at_end("* OK {}") == -1);
    check("literal: too large to say", imap::literal_at_end("{9999999999999999999999}") == -2);

    // --- The tree: a FETCH with literals that hold what would break a
    // line-based parser: ')', '(', '"', CRLF, braces.
    let f = "(UID 7 BODY[HEADER.FIELDS (FROM TO)] {12}\r\nFrom: a\r\n\r\n) FLAGS (\\Seen \\Answered) RFC822.SIZE 4021 INTERNALDATE \"14-Nov-2026 10:00:00 +0000\" BODY[]<0> {9}\r\n) (\"x{1}\n MODSEQ (12345))";
    var nodes: imap::Node[>..] = [];
    check("tree: fetch", imap::tree(f, nodes));
    check("tree: one list on top", nodes[0].count == 1);
    let l = imap::nth(nodes, 0, 0);
    check("tree: 12 items", nodes[l].count == 14);
    check("tree: literal kind", imap::kind_of(nodes, imap::nth(nodes, l, 3)) == imap::K_LITERAL);
    check("tree: bracketed atom", imap::raw(f, nodes, imap::nth(nodes, l, 2)) == "BODY[HEADER.FIELDS (FROM TO)]");
    check("item: header fields", item_of(f, "BODY[HEADER.FIELDS (FROM TO)]") == "From: a\r\n\r\n)");
    check("item: partial answers BODY[]", item_of(f, "BODY[]") == ") (\"x{1}\n");
    check("item: partial by its name", item_of(f, "body[]<0>") == ") (\"x{1}\n");
    check("item: quoted", item_of(f, "INTERNALDATE") == "14-Nov-2026 10:00:00 +0000");
    check("item: list raw", item_of(f, "FLAGS") == "(\\Seen \\Answered)");
    check("item: absent", item_of(f, "ENVELOPE") == "<none>");
    var m = imap::Message { seq: 3, .. };
    check("fetch: parsed", imap::parse_fetch(f, m));
    check("fetch: uid", m.uid == 7);
    check("fetch: size", m.size == 4021);
    check("fetch: flags", m.flags == "\\Seen \\Answered");
    check("fetch: date", m.internaldate == "14-Nov-2026 10:00:00 +0000");
    check("fetch: modseq", m.modseq == 12345);
    check("fetch: NIL body", item_of("(BODY[] NIL)", "BODY[]") == "");
    check("fetch: quoted body", item_of("(BODY[1] \"a \\\"b\\\" \\\\c\")", "BODY[1]") == "a \"b\" \\c");
    check("fetch: empty literal", item_of("(BODY[] {0}\r\n)", "BODY[]") == "");

    // --- Malformed
    check("bad: unclosed quote", !parses("(\"abc)"));
    check("bad: CR in a quote", !parses("(\"a\rb\")"));
    check("bad: unclosed list", !parses("(a (b c)"));
    check("bad: stray close", !parses("a) b"));
    check("bad: literal past the end", !parses("({10}\r\nabc)"));
    check("bad: literal without CRLF", !parses("({3}abc)"));
    check("bad: unclosed bracket", !parses("(BODY[HEADER x)"));
    var deep: u8[>..] = [];
    for i in 70 { deep.push('('); }
    for i in 70 { deep.push(')'); }
    check("bad: nested too deep", !parses(deep));
    check("ok: NIL any case", parses("(nil Nil NIL)"));
    let fetch_bad = "(UID x)";
    var mb = imap::Message { .. };
    check("fetch: UID not a number", !imap::parse_fetch(fetch_bad, mb));
    check("fetch: odd items", !imap::parse_fetch("(UID 1 FLAGS)", mb));

    // --- Status responses and their codes
    let w, code, txt = imap::status_parts("OK [UIDVALIDITY 3857529045] UIDs valid");
    check("status: word", w == "OK");
    check("status: code", code == "UIDVALIDITY 3857529045");
    check("status: text", txt == "UIDs valid");
    let w2, code2, txt2 = imap::status_parts("NO [AUTHENTICATIONFAILED] Authentication failed.");
    check("status: NO code", w2 == "NO" && code2 == "AUTHENTICATIONFAILED" && txt2 == "Authentication failed.");
    let w3, code3, txt3 = imap::status_parts("BAD");
    check("status: bare", w3 == "BAD" && code3 == "" && txt3 == "");
    let w4, code4, txt4 = imap::status_parts("OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited");
    check("status: list in a code", code4 == "PERMANENTFLAGS (\\Deleted \\Seen \\*)" && txt4 == "Limited");

    // --- ENVELOPE: NIL, quoted escapes, an encoded subject, a group, a
    // literal.
    let env_s = "(\"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)\" \"=?UTF-8?Q?Gr=C3=BC=C3=9Fe?= \\\"quoted\\\" \\\\ back\" ((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) NIL NIL ((NIL NIL \"imap\" \"cac.washington.edu\")(NIL NIL \"team\" NIL)(\"=?UTF-8?Q?Zo=C3=AB?=\" NIL \"zoe\" \"example.com\")(NIL NIL NIL NIL)) NIL NIL {5}\r\n<a@b> \"<B27397-0100000@cac.washington.edu>\")";
    var env = imap::Envelope { .. };
    check("envelope: parsed", imap::parse_envelope(env_s, env));
    check("envelope: date", env.date == "Wed, 17 Jul 1996 02:23:25 -0700 (PDT)");
    check("envelope: subject decoded, escapes undone", env.subject == "Grüße \"quoted\" \\ back");
    check("envelope: from", env.from.len == 1 && env.from[0].name == "Terry Gray" && env.from[0].addr == "gray@cac.washington.edu");
    check("envelope: NIL sender", env.sender.len == 0 && env.reply_to.len == 0 && env.cc.len == 0);
    check("envelope: to without the group markers", env.to.len == 2);
    check("envelope: to[0]", env.to[0].name == "" && env.to[0].addr == "imap@cac.washington.edu");
    check("envelope: to[1] decoded name", env.to[1].name == "Zoë" && env.to[1].addr == "zoe@example.com");
    check("envelope: in-reply-to literal", env.in_reply_to == "<a@b>");
    check("envelope: message-id", env.message_id == "<B27397-0100000@cac.washington.edu>");
    check("envelope: too short", !imap::parse_envelope("(NIL NIL)", env));
    check("envelope: bad address", !imap::parse_envelope("(NIL NIL ((\"a\" NIL \"b\")) NIL NIL NIL NIL NIL NIL NIL)", env));

    // --- BODYSTRUCTURE: multipart/mixed holding a multipart/alternative,
    // an attachment, and a message/rfc822 that is itself multipart.
    let bs = "(((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"QUOTED-PRINTABLE\" 120 4 NIL NIL NIL NIL)(\"TEXT\" \"HTML\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 300 10 NIL NIL NIL NIL) \"ALTERNATIVE\" (\"BOUNDARY\" \"b2\") NIL NIL NIL)(\"APPLICATION\" \"PDF\" (\"NAME\" \"=?UTF-8?Q?r=C3=A9sum=C3=A9.pdf?=\") \"<id1@x>\" NIL \"BASE64\" 4096 NIL (\"ATTACHMENT\" (\"FILENAME\" \"résumé.pdf\")) NIL NIL)(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 900 (\"Mon, 1 Jan 2026 00:00:00 +0000\" \"inner\" NIL NIL NIL NIL NIL NIL NIL NIL) ((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 10 1)(\"IMAGE\" \"PNG\" NIL NIL NIL \"BASE64\" 50) \"MIXED\") 20) \"MIXED\" (\"BOUNDARY\" \"b1\") NIL NIL NIL)";
    var parts: imap::Part[>..] = [];
    check("body: parsed", imap::parse_bodystructure(bs, parts));
    check("body: nine parts", parts.len == 9);
    if parts.len == 9 {
        check("body: top", parts[0].multipart && parts[0].section == "" && parts[0].subtype == "mixed" && parts[0].boundary == "b1");
        check("body: alternative", parts[1].multipart && parts[1].section == "1" && parts[1].subtype == "alternative" && parts[1].depth == 1);
        check("body: 1.1", parts[2].section == "1.1" && parts[2].mtype == "text" && parts[2].subtype == "plain" &&
              parts[2].charset == "UTF-8" && parts[2].encoding == "quoted-printable" && parts[2].size == 120 && parts[2].lines == 4 && parts[2].depth == 2);
        check("body: 1.2", parts[3].section == "1.2" && parts[3].subtype == "html" && parts[3].lines == 10);
        check("body: 2 attachment", parts[4].section == "2" && parts[4].mtype == "application" && parts[4].subtype == "pdf" &&
              parts[4].name == "résumé.pdf" && parts[4].id == "<id1@x>" && parts[4].encoding == "base64" &&
              parts[4].size == 4096 && parts[4].lines == -1 && parts[4].disposition == "attachment" && parts[4].filename == "résumé.pdf");
        check("body: 3 message", parts[5].section == "3" && parts[5].mtype == "message" && parts[5].subtype == "rfc822" &&
              parts[5].size == 900 && parts[5].lines == 20);
        check("body: 3 its body", parts[6].multipart && parts[6].section == "3" && parts[6].depth == 2);
        check("body: 3.1", parts[7].section == "3.1" && parts[7].subtype == "plain" && parts[7].lines == 1 && parts[7].depth == 3);
        check("body: 3.2", parts[8].section == "3.2" && parts[8].mtype == "image" && parts[8].size == 50);
    }
    check("body: single part is 1", imap::parse_bodystructure("(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") NIL NIL \"7BIT\" 3028 92)", parts) &&
          parts.len == 1 && parts[0].section == "1" && parts[0].lines == 92 && parts[0].charset == "us-ascii");
    check("body: message with a single part", imap::parse_bodystructure("(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" 50 (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 5 1) 3)", parts) &&
          parts.len == 2 && parts[1].section == "1.1");
    check("body: size not a number", !imap::parse_bodystructure("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" x 1)", parts));
    check("body: too short", !imap::parse_bodystructure("(\"TEXT\" \"PLAIN\")", parts));
    check("body: multipart without a subtype", !imap::parse_bodystructure("((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 1 1))", parts));

    // --- LIST and STATUS
    var mbox = imap::Mailbox { .. };
    check("list: parsed", imap::parse_list("(\\HasNoChildren \\Drafts) \"/\" \"Entw&APw-rfe\"", false, mbox));
    check("list: attrs", mbox.attrs == "\\HasNoChildren \\Drafts");
    check("list: delim", mbox.delim == '/');
    check("list: name decoded", mbox.name == "Entwürfe");
    check("list: NIL delim, atom", imap::parse_list("() NIL INBOX", false, mbox) && mbox.delim == 0 && mbox.name == "INBOX");
    check("list: literal name", imap::parse_list("(\\Noselect) \".\" {7}\r\na \"b\" c", false, mbox) && mbox.name == "a \"b\" c");
    check("list: UTF-8 kept with utf8", imap::parse_list("() \"/\" \"Entwürfe\"", true, mbox) && mbox.name == "Entwürfe");
    check("list: not UTF-7 kept as sent", imap::parse_list("() \"/\" \"a&b\"", false, mbox) && mbox.name == "a&b");
    check("list: extended data", imap::parse_list("(\\Subscribed) \"/\" \"Foo\" (\"CHILDINFO\" (\"SUBSCRIBED\"))", false, mbox) && mbox.name == "Foo");
    check("list: malformed", !imap::parse_list("\\Noselect \"/\" foo", false, mbox));
    var st = imap::Status { .. };
    check("status: parsed", imap::parse_status("\"blurdybloop\" (MESSAGES 231 UIDNEXT 44292 UIDVALIDITY 1 UNSEEN 3 SIZE 9999)", st));
    check("status: values", st.messages == 231 && st.uidnext == 44292 && st.uidvalidity == 1 && st.unseen == 3 && st.size == 9999 && st.recent == -1);
    check("status: odd", !imap::parse_status("INBOX (MESSAGES)", st));

    // --- SEARCH and ESEARCH
    var found: i64[>..] = [];
    check("search: numbers", imap::parse_search("SEARCH", "2 84 882", 100, found) && found == [2, 84, 882]);
    found.clear();
    check("search: none", imap::parse_search("SEARCH", "", 100, found) && found.len == 0);
    check("search: modseq", imap::parse_search("SEARCH", "2 5 (MODSEQ 917162500)", 100, found) && found == [2, 5]);
    found.clear();
    check("esearch: ALL", imap::parse_search("ESEARCH", "(TAG \"A282\") UID MIN 2 ALL 2,10:11 COUNT 3", 100, found) && found == [2, 10, 11]);
    found.clear();
    check("esearch: nothing", imap::parse_search("ESEARCH", "(TAG \"A3\") UID", 100, found) && found.len == 0);
    check("search: bounded", !imap::parse_search("ESEARCH", "(TAG \"A\") ALL 1:1000", 100, found));
    check("search: junk", !imap::parse_search("SEARCH", "1 x", 100, found));
    // An ESEARCH range stands for many numbers: at most MAX_SEARCH (1M).
    check("search: max", imap::search_max(imap::MAX_DATA) == 1 << 20 && imap::search_max(800) == 100);
    found.clear();
    check("search: ALL 1:1048576", imap::parse_search("ESEARCH", "(TAG \"A\") ALL 1:1048576", imap::search_max(imap::MAX_DATA), found) &&
          found.len == 1 << 20);
    found.clear();
    check("search: ALL 1:4294967295", !imap::parse_search("ESEARCH", "(TAG \"A\") ALL 1:4294967295", imap::search_max(imap::MAX_DATA), found));

    // --- Modified UTF-7, RFC 3501 §5.1.3's examples and more
    check("utf7: ascii", utf7("INBOX/Sent") == "INBOX/Sent");
    check("utf7: ampersand", utf7("Tom & Jerry") == "Tom &- Jerry");
    check("utf7: CJK", utf7("~peter/mail/台北/日本語") == "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
    check("utf7: umlaut", utf7("Entwürfe") == "Entw&APw-rfe");
    check("utf7: surrogate pair", utf7("😀") == "&2D3eAA-");
    check("utf7: not UTF-8", utf7("a\xffb") == "<bad>");
    check("unutf7: CJK", unutf7("~peter/mail/&U,BTFw-/&ZeVnLIqe-") == "~peter/mail/台北/日本語");
    check("unutf7: ampersand", unutf7("&-&-") == "&&");
    check("unutf7: surrogate pair", unutf7("&2D3eAA-") == "😀");
    check("unutf7: round trip", unutf7(utf7("Ünïcødé & 日本 😀 x")) == "Ünïcødé & 日本 😀 x");
    check("unutf7: unterminated", unutf7("&ZeVnLIqe") == "<bad>");
    check("unutf7: lone high surrogate", unutf7("&2D0-") == "<bad>");
    check("unutf7: lone low surrogate", unutf7("&3gA-") == "<bad>");
    check("unutf7: bad base64", unutf7("&Ze*n-") == "<bad>");
    check("unutf7: 8-bit", unutf7("Entw\xc3\xbcrfe") == "<bad>");
    check("unutf7: nonzero padding", unutf7("&APx-") == "<bad>");

    // --- Sequence sets
    check("seq: runs", seqs([1, 2, 3, 5, 7, 8]) == "1:3,5,7:8");
    check("seq: one", seqs([42]) == "42");
    check("seq: none", seqs([]) == "");
    check("seq ok: star", imap::seq_set_ok("1:*") && imap::seq_set_ok("*") && imap::seq_set_ok("4,7:9,*:3"));
    check("seq ok: $", imap::seq_set_ok("$"));
    check("seq bad: zero", !imap::seq_set_ok("0") && !imap::seq_set_ok("1:0") && !imap::seq_set_ok("01"));
    check("seq bad: shape", !imap::seq_set_ok("") && !imap::seq_set_ok("1:") && !imap::seq_set_ok("1,,2") &&
          !imap::seq_set_ok("a") && !imap::seq_set_ok("1 2") && !imap::seq_set_ok("1,") && !imap::seq_set_ok("1:2:3"));
    check("seq bad: past 32 bits", !imap::seq_set_ok("4294967296"));
    check("seq bad: injection", !imap::seq_set_ok("1\r\nA2 LOGOUT"));
    var nums: i64[>..] = [];
    check("seq parse: ranges", imap::parse_seq_set("3:1,5,7:*", 8, 100, nums) && nums == [1, 2, 3, 5, 7, 8]);
    nums.clear();
    check("seq parse: bounded", !imap::parse_seq_set("1:4294967295", 0, 1000, nums));
    check("seq parse: bad", !imap::parse_seq_set("1,x", 0, 10, nums));

    // --- Arguments: atom, quoted, literal, refused
    check("arg: atom", arg("INBOX", false, false) == "INBOX");
    check("arg: space quoted", arg("My Box", false, false) == "\"My Box\"");
    check("arg: escapes", arg("a\"b\\c", false, false) == "\"a\\\"b\\\\c\"");
    check("arg: NIL quoted", arg("NIL", false, false) == "\"NIL\"" && arg("nil", false, false) == "\"nil\"");
    check("arg: empty quoted", arg("", false, false) == "\"\"");
    check("arg: wildcard quoted", arg("*", false, false) == "\"*\"" && arg("a]", false, false) == "\"a]\"");
    check("arg: 8-bit literal", arg("pässword", false, false) == "{9}\r\npässword");
    check("arg: 8-bit literal+", arg("pässword", false, true) == "{9+}\r\npässword");
    check("arg: UTF-8 quoted with utf8", arg("pässword", true, false) == "\"pässword\"");
    check("arg: CRLF refused", arg("a\r\nA2 LOGOUT", false, false) == "<bad>");
    check("arg: LF refused", arg("a\nb", true, false) == "<bad>");
    check("arg: NUL refused", arg("a\x00b", false, false) == "<bad>");
    var long: u8[>..] = [];
    for i in 1200 { long.push('a' + (i % 26) as! u8); }
    long[5] = ' ';
    check("arg: long literal", arg(long, false, false).starts_with("{1200}\r\n"));
    check("arg forms", imap::arg_form("x", false) == imap::ARG_ATOM && imap::arg_form("a b", false) == imap::ARG_QUOTED &&
          imap::arg_form("é", false) == imap::ARG_LITERAL && imap::arg_form("é", true) == imap::ARG_QUOTED);

    // --- Before a connection, every command is out of order; bad
    // arguments are refused before that.
    var c = imap::Client { .. };
    check("imap: noop unconnected", imap::noop(c) == mail::ERR_STATE);
    check("imap: logout unconnected", imap::logout(c) == mail::ERR_STATE);
    check("imap: login unconnected", imap::login(c, "u", "p") == mail::ERR_STATE);
    check("imap: authenticate unconnected", imap::authenticate(c, mail::AUTH_PLAIN, "u", "p") == mail::ERR_STATE);
    check("imap: select unconnected", imap::select(c, "INBOX") == mail::ERR_STATE && !c.selected);
    check("imap: idle_wait unconnected", imap::idle_wait(c, 10) == mail::ERR_STATE);
    check("imap: empty host", imap::dial(c, "", 143, imap::TLS_NONE) == mail::ERR_ARG);
    check("imap: bad port", imap::dial(c, "localhost", 70000, imap::TLS_NONE) == mail::ERR_ARG);
    check("imap: CRLF in a mailbox", imap::create(c, "a\r\nA2 LOGOUT") == mail::ERR_LINE);
    check("imap: CRLF in a search", imap::search(c, "ALL\r\nA2 LOGOUT", nums) == mail::ERR_LINE);
    var msgs: imap::Message[>..] = [];
    check("imap: bad set", imap::fetch(c, "1:x", "FLAGS", msgs) == mail::ERR_ARG);
    check("imap: bad store", imap::store(c, "1", "FLAGZ", "\\Seen") == mail::ERR_ARG);
    check("imap: bad flags", imap::store(c, "1", "+FLAGS", "\\Seen) (x") == mail::ERR_ARG);
    check("imap: bad append date", imap::append(c, "INBOX", "", "1-Jan\r\n", "x") == mail::ERR_ARG);
    check("imap: MOVE needs the capability", imap::move(c, "1", "Trash") == mail::ERR_UNSUPPORTED);

    // Review fixes: what a server sends is refused, not cut, and nothing
    // in an ENVELOPE address can split a header written from it.
    var ee = imap::Envelope { .. };
    check("envelope: CRLF in host", !imap::parse_envelope("(\"d\" \"s\" ((\"Eve\" NIL \"eve\" {28}\r\nevil.example>\r\nX-Injected: 1)) NIL NIL NIL NIL NIL NIL NIL)", ee));
    check("envelope: LF in name", !imap::parse_envelope("(NIL NIL ((\"E\nX: 1\" NIL \"eve\" \"example.com\")) NIL NIL NIL NIL NIL NIL NIL)", ee));
    check("envelope: CRLF in an encoded-word name", !imap::parse_envelope("(NIL NIL ((\"=?utf-8?q?a=0D=0AX:_1?=\" NIL \"eve\" \"example.com\")) NIL NIL NIL NIL NIL NIL NIL)", ee));
    var lp: u8[>..] = [];
    lp.append("ceo@bank.example");
    for i in 310 { lp.push('a'); }
    var env2: u8[>..] = [];
    format(env2, "(NIL NIL ((NIL NIL {", lp.len, "}\r\n", lp, " \"evil.example\")) NIL NIL NIL NIL NIL NIL NIL)");
    check("envelope: addr too long refused", !imap::parse_envelope(env2, ee));
    var nm: u8[>..] = [];
    for i in 300 { nm.push('n'); }
    var env3: u8[>..] = [];
    format(env3, "(NIL NIL ((\"", nm, "\" NIL \"a\" \"example.com\")) NIL NIL NIL NIL NIL NIL NIL)");
    check("envelope: name too long refused", !imap::parse_envelope(env3, ee));
    check("envelope: plain still parses", imap::parse_envelope("(NIL NIL ((\"Eve\" NIL \"eve\" \"example.com\")) NIL NIL NIL NIL NIL NIL NIL)", ee) && ee.from.len == 1 && ee.from[0].addr == "eve@example.com");
    // A section number past 64 bytes: the BODYSTRUCTURE does not parse.
    var deep: u8[>..] = [];
    for i in 40 { deep.push('('); }
    deep.append("\"text\" \"plain\" NIL NIL NIL \"7bit\" 1 1");
    for i in 40 { deep.append(") \"mixed\""); }
    var dparts: imap::Part[>..] = [];
    check("bodystructure: section too long refused", !imap::parse_bodystructure(deep, dparts));
    // A LIST name whose decoding passes 1024 bytes: refused, not cut mid-rune.
    var wide: u8[>..] = [];
    for i in 360 { wide.append("日"); }
    var wenc: u8[>..] = [];
    check("list: long name encodes", imap::utf7_encode(wenc, wide) && wenc.len <= 1024);
    var wl: u8[>..] = [];
    format(wl, "() \"/\" ", wenc);
    var wmb = imap::Mailbox { .. };
    check("list: decoded too long refused", !imap::parse_list(wl, false, wmb));

    if failures > 0 { print(failures, " failures"); exit(1); }
    print("imap: ok");
}
