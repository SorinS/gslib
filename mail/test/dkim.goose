// mail.dkim against RFC 6376's canonicalization examples (§3.4.5) and
// empty-body hashes (§3.4.3, §3.4.4), RFC 8463 Appendix A's signed message
// (Ed25519 and RSA) with its published keys, tag-lists, round trips, a
// message changed on the way, h= matching (§5.4.2) and the size limits.
import std;
import base64;
import gslib from "../..";
import gslib.mail;
import gslib.mail.message;
import gslib.mail.dkim;
import gslib.crypto.bignum;
import gslib.crypto.bignum.sha1;
import gslib.crypto.bignum.sha256;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;

var failures = 0;

fn check(what: const u8[:], ok: bool) {
    if !ok { print("FAIL ", what); failures++; }
}

fn b64(data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    base64::encode(out, data);
    return out;
}

// --- RFC 6376 §3.4.5 ----------------------------------------------------------------

let EX_HEADER = "A: X\r\nB : Y\t\r\n\tZ  \r\n";
let EX_BODY = " C \r\nD \t E\r\n\r\n\r\n";

fn canon_headers(canon: i64) -> u8[>..] {
    var fields: dkim::Field[>..] = [];
    let msg = str(EX_HEADER, "\r\n", EX_BODY);
    dkim::split_message(msg, fields);
    var out: u8[>..] = [];
    for f in fields {
        dkim::canon_header(out, dkim::field_text(msg, f), canon);
        out.append("\r\n");
    }
    return out;
}

fn canon_body(body: const u8[:], canon: i64) -> u8[>..] {
    var out: u8[>..] = [];
    dkim::canon_body(out, body, canon);
    return out;
}

fn canonicalization() {
    check("3.4.5 example 1 header", canon_headers(dkim::RELAXED) == "a:X\r\nb:Y Z\r\n");
    check("3.4.5 example 1 body", canon_body(EX_BODY, dkim::RELAXED) == " C\r\nD E\r\n");
    check("3.4.5 example 2 header", canon_headers(dkim::SIMPLE) == EX_HEADER);
    check("3.4.5 example 2 body", canon_body(EX_BODY, dkim::SIMPLE) == " C \r\nD \t E\r\n");
    // Example 3 is the relaxed header with the simple body: both checked above.
    let msg = str(EX_HEADER, "\r\n", EX_BODY);
    var fields: dkim::Field[>..] = [];
    let at = dkim::split_message(msg, fields);
    check("3.4.5 split: two fields", fields.len == 2);
    check("3.4.5 split: the body", msg[at..] == EX_BODY);

    // §3.4.3 and §3.4.4: the hashes of an empty body.
    check("simple empty body is CRLF", canon_body("", dkim::SIMPLE) == "\r\n");
    check("relaxed empty body is empty", canon_body("", dkim::RELAXED).len == 0);
    check("simple empty body sha1", b64(bignum::sha1(canon_body("", dkim::SIMPLE))) == "uoq1oCgLlTqpdDX/iUbLy7J1Wic=");
    check("simple empty body sha256",
          b64(bignum::sha256(canon_body("", dkim::SIMPLE))) == "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=");
    check("relaxed empty body sha1", b64(bignum::sha1(canon_body("", dkim::RELAXED))) == "2jmj7l5rSw0yVb/vlWAYkK/YBwk=");
    check("relaxed empty body sha256",
          b64(bignum::sha256(canon_body("", dkim::RELAXED))) == "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");

    // Edges: only empty lines, no final CRLF, trailing WSP on the last line.
    check("simple: only empty lines", canon_body("\r\n\r\n\r\n", dkim::SIMPLE) == "\r\n");
    check("relaxed: only empty lines", canon_body("\r\n\r\n", dkim::RELAXED).len == 0);
    check("relaxed: only blanks", canon_body("  \r\n\t\r\n", dkim::RELAXED).len == 0);
    check("simple: no final CRLF", canon_body("abc", dkim::SIMPLE) == "abc\r\n");
    check("relaxed: no final CRLF", canon_body("a  b \t", dkim::RELAXED) == "a b\r\n");
    check("relaxed: inner empty lines kept", canon_body("a\r\n\r\nb\r\n\r\n", dkim::RELAXED) == "a\r\n\r\nb\r\n");
    check("simple: WSP kept", canon_body("a  \r\n", dkim::SIMPLE) == "a  \r\n");
    var h: u8[>..] = [];
    dkim::canon_header(h, "SUBJect: AbC", dkim::RELAXED);
    check("relaxed header: RFC's SUBJect", h == "subject:AbC");
    h.clear();
    dkim::canon_header(h, "X-Empty:   \r\n  ", dkim::RELAXED);
    check("relaxed header: empty value", h == "x-empty:");
}

// --- RFC 8463 Appendix A -------------------------------------------------------------

let RFC8463_MSG = str(
    "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r\n",
    " d=football.example.com; i=@football.example.com;\r\n",
    " q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r\n",
    " subject : date : message-id : from : subject : date;\r\n",
    " bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n",
    " b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r\n",
    " Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r\n",
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n",
    " d=football.example.com; i=@football.example.com;\r\n",
    " q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r\n",
    " date : message-id : from : subject : date;\r\n",
    " bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n",
    " b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r\n",
    " DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r\n",
    " dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=\r\n",
    "From: Joe SixPack <joe@football.example.com>\r\n",
    "To: Suzie Q <suzie@shopping.example.net>\r\n",
    "Subject: Is dinner ready?\r\n",
    "Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n",
    "Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n",
    "\r\n",
    "Hi.\r\n",
    "\r\n",
    "We lost the game.  Are you hungry yet?\r\n",
    "\r\n",
    "Joe.\r\n");

let RFC8463_ED_RECORD = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
let RFC8463_RSA_RECORD = str(
    "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR",
    "iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC",
    "DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3",
    "Ip3G+2kryOTIKT+l/K4w3QIDAQAB");

let RFC8463_ED_SEED = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
let RFC8463_RSA_KEY = str(
    "-----BEGIN RSA PRIVATE KEY-----\n",
    "MIICXQIBAAKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi\n",
    "Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM\n",
    "KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB\n",
    "AoGAH0cxOhFZDgzXWhDhnAJDw5s4roOXN4OhjiXa8W7Y3rhX3FJqmJSPuC8N9vQm\n",
    "6SVbaLAE4SG5mLMueHlh4KXffEpuLEiNp9Ss3O4YfLiQpbRqE7Tm5SxKjvvQoZZe\n",
    "zHorimOaChRL2it47iuWxzxSiRMv4c+j70GiWdxXnxe4UoECQQDzJB/0U58W7RZy\n",
    "6enGVj2kWF732CoWFZWzi1FicudrBFoy63QwcowpoCazKtvZGMNlPWnC7x/6o8Gc\n",
    "uSe0ga2xAkEA8C7PipPm1/1fTRQvj1o/dDmZp243044ZNyxjg+/OPN0oWCbXIGxy\n",
    "WvmZbXriOWoSALJTjExEgraHEgnXssuk7QJBALl5ICsYMu6hMxO73gnfNayNgPxd\n",
    "WFV6Z7ULnKyV7HSVYF0hgYOHjeYe9gaMtiJYoo0zGN+L3AAtNP9huqkWlzECQE1a\n",
    "licIeVlo1e+qJ6Mgqr0Q7Aa7falZ448ccbSFYEPD6oFxiOl9Y9se9iYHZKKfIcst\n",
    "o7DUw1/hz2Ck4N5JrgUCQQCyKveNvjzkkd8HjYs0SwM0fPjK16//5qDZ2UiDGnOe\n",
    "uEzxBDAr518Z8VFbR41in3W4Y3yCDgQlLlcETrS+zYcL\n",
    "-----END RSA PRIVATE KEY-----\n");

// The RFC's two key records, by selector.
fn rfc_keys(domain: const u8[:], selector: const u8[:], rec: u8[>..]&) {
    if domain != "football.example.com" { return; }
    if selector == "brisbane" { rec.append(RFC8463_ED_RECORD); }
    else if selector == "test" { rec.append(RFC8463_RSA_RECORD); }
}

fn rfc8463() {
    var res: dkim::Result[>..] = [];
    let e = dkim::verify(RFC8463_MSG, res, rfc_keys);
    check("8463: verify", e == mail::OK);
    check("8463: two results", res.len == 2);
    if res.len == 2 {
        check(str("8463: ed25519 passes: ", res[0].reason), res[0].status == mail::OK);
        check(str("8463: rsa passes: ", res[1].reason), res[1].status == mail::OK);
        check("8463: d=", res[0].d == "football.example.com");
        check("8463: s=", res[0].s == "brisbane" && res[1].s == "test");
        check("8463: algorithms", res[0].alg == dkim::ALG_ED25519_SHA256 && res[1].alg == dkim::ALG_RSA_SHA256);
    }
    // The published keys are the private keys' public halves.
    let ek, ee = dkim::parse_key(RFC8463_ED_SEED);
    var rec: u8[>..] = [];
    check("8463: ed25519 seed parses", ee == mail::OK && dkim::key_record(ek, rec) == mail::OK);
    check("8463: ed25519 record", rec == RFC8463_ED_RECORD);
    let rk, re = dkim::parse_key(RFC8463_RSA_KEY);
    rec.clear();
    check("8463: rsa key parses", re == mail::OK && dkim::key_record(rk, rec) == mail::OK);
    check("8463: rsa record", rec == RFC8463_RSA_RECORD);
}

// --- Tag lists -----------------------------------------------------------------------

fn tags_ok(text: const u8[:]) -> i64 {
    var tags: dkim::Tag[>..] = [];
    if dkim::parse_tags(text, tags) != mail::OK { return -1; }
    return tags.len;
}

fn tag(text: const u8[:], name: const u8[:]) -> const u8[:] {
    var tags: dkim::Tag[>..] = [];
    dkim::parse_tags(text, tags);
    let v, ok = dkim::tag_value(text, tags, name);
    return v;
}

fn tag_lists() {
    check("tags: two", tags_ok("v=1; a=rsa-sha256") == 2);
    check("tags: a ';' at the end", tags_ok("v=1; a=rsa-sha256;") == 2);
    check("tags: empty specs", tags_ok("v=1;; a=x; ;") == 2);
    check("tags: empty", tags_ok("") == 0);
    check("tags: FWS around everything", tags_ok(" v = 1 ;\r\n\ta\t=\r\n x ; ") == 2);
    check("tags: value trimmed", tag(" v = 1 ;\r\n\ta\t=\r\n x ; ", "a") == "x");
    check("tags: WSP inside a value kept", tag("n=two  words ;", "n") == "two  words");
    check("tags: an empty value", tags_ok("p=") == 1 && tag("p=; k=rsa", "p").len == 0);
    check("tags: '=' in a value", tag("b=abc==; x=1", "b") == "abc==");
    check("tags: duplicate", tags_ok("a=1; b=2; a=3") == -1);
    check("tags: names are case-sensitive", tags_ok("a=1; A=2") == 2);
    check("tags: no '='", tags_ok("a=1; b") == -1);
    check("tags: no name", tags_ok("=1") == -1);
    check("tags: a digit first", tags_ok("1a=x") == -1);
    check("tags: '_' first", tags_ok("_a=x") == -1);
    check("tags: digits and '_' after", tags_ok("a_1=x") == 1);
    check("tags: a space in a name", tags_ok("a b=x") == -1);
    check("tags: a control in a value", tags_ok("a=x\x01y") == -1);
    var names: dkim::Span[>..] = [];
    check("names: FWS around", dkim::split_names("from : to :\r\n subject", names) && names.len == 3);
    check("names: an empty one", !dkim::split_names("from::to", names));
    check("names: a trailing colon", !dkim::split_names("from:", names));
}

// --- Signing and verifying ----------------------------------------------------------------

let MSG = str(
    "From: Alice <alice@example.com>\r\n",
    "To: Bob <bob@example.org>\r\n",
    "Subject: The  plans\r\n",
    "Date: Mon, 01 Apr 2024 00:00:00 +0000\r\n",
    "Message-ID: <plans-1@example.com>\r\n",
    "X-Unsigned: yes\r\n",
    "\r\n",
    "Meet at  noon.\r\n",
    "\r\n",
    "Bring the maps.\r\n",
    "\r\n",
    "\r\n");

fn opts(header: i64, body: i64) -> dkim::SignOptions {
    var o = dkim::SignOptions { header_canon: header, body_canon: body, timestamp: 1711929600, .. };
    o.domain.append("example.com");
    o.selector.append("sel");
    return o;
}

fn key_rsa() -> x509::PrivateKey {
    let k, e = dkim::parse_key(RFC8463_RSA_KEY);
    return k;
}

fn key_ed() -> x509::PrivateKey {
    let k, e = dkim::parse_key(RFC8463_ED_SEED);
    return k;
}

fn record_of(k: const x509::PrivateKey&) -> u8[>..] {
    var r: u8[>..] = [];
    dkim::key_record(k, r);
    return r;
}

// The status of the first signature, with record.
fn status(msg: const u8[:], record: const u8[:], o: dkim::VerifyOptions = dkim::VerifyOptions { now: 1711929600, .. })
    -> i64 {
    var res: dkim::Result[>..] = [];
    dkim::verify_record(msg, record, res, o);
    if res.len == 0 { return -1; }
    return res[0].status;
}

fn first_result(msg: const u8[:], record: const u8[:]) -> dkim::Result {
    var res: dkim::Result[>..] = [];
    dkim::verify_record(msg, record, res, dkim::VerifyOptions { now: 1711929600, .. });
    if res.len == 0 { return dkim::Result { status: -1, .. }; }
    return res[0];
}

fn signed(msg: const u8[:], k: const x509::PrivateKey&, o: dkim::SignOptions) -> u8[>..] {
    var out: u8[>..] = [];
    let e = dkim::sign(msg, k, o, out);
    check(str("sign: ", mail::error_text(e)), e == mail::OK);
    return out;
}

// s with the first `from` made `to`.
fn replace(s: const u8[:], from: const u8[:], to: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for i in s.len {
        if s[i..].starts_with(from) {
            out.append(s[..i]);
            out.append(to);
            out.append(s[i + from.len..]);
            return out;
        }
    }
    out.append(s);
    return out;
}

fn has(s: const u8[:], sub: const u8[:]) -> bool {
    for i in s.len { if s[i..].starts_with(sub) { return true; } }
    return false;
}

// s without its folds (CRLF and the WSP after it).
fn unfold(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        if s[i] == '\r' && i + 2 < s.len && s[i + 1] == '\n' && (s[i + 2] == ' ' || s[i + 2] == '\t') { i += 3; continue; }
        out.push(s[i]);
        i++;
    }
    return out;
}

fn round_trips() {
    let rsa = key_rsa();
    let ed = key_ed();
    let rrec = record_of(rsa);
    let erec = record_of(ed);
    for hc in [dkim::SIMPLE, dkim::RELAXED] {
        for bc in [dkim::SIMPLE, dkim::RELAXED] {
            let o = opts(hc, bc);
            let name = str(dkim::canon_name(hc), "/", dkim::canon_name(bc));
            let sr = signed(MSG, rsa, o);
            check(str("round trip rsa ", name), status(sr, rrec) == mail::OK);
            let se = signed(MSG, ed, o);
            check(str("round trip ed25519 ", name), status(se, erec) == mail::OK);
            check(str("round trip: the wrong key ", name), status(se, rrec) == mail::ERR_KEY);
            // Whitespace changed in a signed field: relaxed allows it.
            let ws = replace(se, "Subject: The  plans", "Subject:  The plans ");
            check(str("re-spaced subject ", name), status(ws, erec) == (if hc == dkim::RELAXED { mail::OK } else { mail::ERR_SIGNATURE }));
            let wb = replace(se, "Meet at  noon.", "Meet at noon. ");
            check(str("re-spaced body ", name), status(wb, erec) == (if bc == dkim::RELAXED { mail::OK } else { mail::ERR_SIGNATURE }));
        }
    }

    // The header: its fields, folded under 78 columns, b= last.
    var hdr: u8[>..] = [];
    check("signature", dkim::signature(MSG, rsa, opts(dkim::RELAXED, dkim::RELAXED), hdr) == mail::OK);
    check("signature: a field", hdr.starts_with("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;"));
    check("signature: ends with CRLF", hdr.len > 2 && hdr[hdr.len - 2] == '\r' && hdr[hdr.len - 1] == '\n');
    var start = 0;
    var longest = 0;
    var lines = 0;
    for i in hdr.len {
        if hdr[i] == '\n' {
            longest = max(longest, i - 1 - start);
            lines++;
            start = i + 1;
        }
    }
    check(str("signature: lines under 78 (", longest, ")"), longest <= 78 && lines >= 4);
    check("signature: the default h=",
          has(unfold(hdr), "h=from:to:subject:date:message-id:from;"));
    check("signature: t=", has(hdr, "t=1711929600;"));
    check("signature: the signed message is it and the message", signed(MSG, rsa, opts(dkim::RELAXED, dkim::RELAXED)) == str(hdr, MSG));

    // A message with bare LFs is signed as CRLF.
    var lf: u8[>..] = [];
    for c in MSG { if c != '\r' { lf.push(c); } }
    let slf = signed(lf, ed, opts(dkim::SIMPLE, dkim::SIMPLE));
    check("bare LF: signed as CRLF", status(slf, erec) == mail::OK);
    var back: u8[>..] = [];
    for c in slf { if c != '\r' { back.push(c); } }
    check("bare LF: verified as CRLF", status(back, erec) == mail::OK);

    // i=, x=, a header list given.
    var o = opts(dkim::RELAXED, dkim::SIMPLE);
    o.identity.append("alice@mail.example.com");
    o.expire = 1711929600 + 3600;
    o.headers.append("From:Subject:From:X-Absent");
    let si = signed(MSG, ed, o);
    let ri = first_result(si, erec);
    check(str("i= and x=: ", ri.reason), ri.status == mail::OK && ri.i == "alice@mail.example.com");
    check("x= passed", status(si, erec, dkim::VerifyOptions { now: 1711929600 + 7200, .. }) == mail::ERR_SIGNATURE);
    check("an unsigned To changes nothing", status(replace(si, "To: Bob", "To: Eve"), erec) == mail::OK);
    check("an over-signed absent field, added", status(str("X-Absent: 1\r\n", si), erec) == mail::ERR_SIGNATURE);

    // A field signed twice, the message having two: both taken, bottom-up.
    let two = str("Received: from a\r\nReceived: from b\r\n", MSG);
    var o2 = opts(dkim::RELAXED, dkim::SIMPLE);
    o2.headers.append("from:received:received");
    let s2 = signed(two, ed, o2);
    check("two Received signed", status(s2, erec) == mail::OK);
    check("two Received: the upper changed", status(replace(s2, "from a", "from x"), erec) == mail::ERR_SIGNATURE);
    check("two Received: the lower changed", status(replace(s2, "from b", "from x"), erec) == mail::ERR_SIGNATURE);
    check("two Received: a third added above", status(str("Received: from c\r\n", s2), erec) == mail::OK);
    check("two Received: swapped", status(replace(replace(s2, "from a", "from t"), "from b", "from a"), erec) ==
                                   mail::ERR_SIGNATURE);

    // mail::Msg, written and signed.
    var m = mail::Msg { .. };
    mail::set_from(m, "Alice <alice@example.com>");
    mail::add_to(m, "bob@example.org");
    mail::set_subject(m, "Built");
    mail::set_date(m, 1711929600);
    mail::set_message_id(m, "built-1@example.com");
    mail::set_body(m, mail::TEXT_PLAIN, "From mail.message.\n");
    var sm: u8[>..] = [];
    check("sign_msg", dkim::sign_msg(m, ed, opts(dkim::RELAXED, dkim::RELAXED), sm) == mail::OK);
    check("sign_msg: verifies", status(sm, erec) == mail::OK);
    check("sign_msg: signs MIME-Version and Content-Type",
          has(unfold(sm), "h=from:to:subject:date:message-id:mime-version:content-type:from;"));
}

fn tampering() {
    let ed = key_ed();
    let erec = record_of(ed);
    let s = signed(MSG, ed, opts(dkim::RELAXED, dkim::RELAXED));
    let rb = first_result(replace(s, "Bring the maps.", "Bring the money."), erec);
    check("a changed body fails", rb.status == mail::ERR_SIGNATURE && rb.body_mismatch);
    let rh = first_result(replace(s, "Subject: The  plans", "Subject: The other plans"), erec);
    check("a changed subject fails", rh.status == mail::ERR_SIGNATURE && !rh.body_mismatch);
    check("an added unsigned field passes", status(replace(s, "X-Unsigned: yes\r\n", "X-Unsigned: yes\r\nX-Spam: no\r\n"), erec) == mail::OK);
    check("a changed unsigned field passes", status(replace(s, "X-Unsigned: yes", "X-Unsigned: no"), erec) == mail::OK);
    check("a changed b= fails", status(replace(s, "b=", "b=AAAA"), erec) != mail::OK);
    check("a changed bh= fails", status(replace(s, "bh=", "bh=A"), erec) != mail::OK);

    // A second From, above or below, whether From is over-signed or not:
    // more than one From fails every signature (RFC 6376 §8.15).
    let added = str("From: Mallory <mallory@example.net>\r\n", s);
    check("over-signed From: an added From fails", status(added, erec) == mail::ERR_FORMAT);
    var o = opts(dkim::RELAXED, dkim::RELAXED);
    o.oversign_from = false;
    let s1 = signed(MSG, ed, o);
    check("From signed once: an added From above fails",
          status(str("From: Mallory <mallory@example.net>\r\n", s1), erec) == mail::ERR_FORMAT);
    check("From signed once: a second From below fails",
          status(replace(s1, "X-Unsigned: yes\r\n", "From: Mallory <mallory@example.net>\r\n"), erec) == mail::ERR_FORMAT);

    // l=: what comes after the signed length is not covered.
    o = opts(dkim::RELAXED, dkim::RELAXED);
    o.body_length = dkim::BODY_ALL;
    let sl = signed(MSG, ed, o);
    let more = str(sl, "P.S. Unsigned text.\r\n");
    let rl = first_result(more, erec);
    check("l=: text added after passes", rl.status == mail::OK && rl.body_length == 34);
    check("l=: text changed before fails", status(replace(more, "Meet", "Greet"), erec) == mail::ERR_SIGNATURE);
    check("l=: a body cut short fails", status(replace(sl, "Bring the maps.\r\n", ""), erec) == mail::ERR_SIGNATURE);
    o.body_length = 7;
    let s7 = signed(MSG, ed, o);
    check("l=7: the rest changed passes", status(replace(s7, "Bring the maps.", "Bring nothing."), erec) == mail::OK);
    o.body_length = 1000;
    var out: u8[>..] = [];
    check("l= past the body", dkim::sign(MSG, ed, o, out) == mail::ERR_ARG && out.len == 0);
}

fn header_checks() {
    let ed = key_ed();
    let erec = record_of(ed);
    let s = signed(MSG, ed, opts(dkim::RELAXED, dkim::RELAXED));
    check("v=2", status(replace(s, "v=1;", "v=2;"), erec) == mail::ERR_FORMAT);
    check("no v=", status(replace(s, "v=1;", ""), erec) == mail::ERR_FORMAT);
    check("no d=", status(replace(s, "d=example.com;", ""), erec) == mail::ERR_FORMAT);
    check("no s=", status(replace(s, "s=sel;", ""), erec) == mail::ERR_FORMAT);
    check("no bh=", status(replace(s, "bh=", "xh="), erec) == mail::ERR_FORMAT);
    check("a duplicate tag", status(replace(s, "v=1;", "v=1; s=sel;"), erec) == mail::ERR_FORMAT);
    check("h= without from", status(replace(s, "h=from:to:subject:date:message-id:from;", "h=to:subject;"), erec) == mail::ERR_FORMAT);
    check("a= unknown", status(replace(s, "a=ed25519-sha256", "a=rsa-sha512"), erec) == mail::ERR_UNSUPPORTED);
    check("c= unknown", status(replace(s, "c=relaxed/relaxed", "c=relaxed/loose"), erec) == mail::ERR_UNSUPPORTED);
    check("q= other", status(replace(s, "v=1;", "v=1; q=http;"), erec) == mail::ERR_UNSUPPORTED);
    check("q=dns/txt", status(replace(s, "v=1;", "v=1; q=dns/txt;"), erec) != mail::ERR_UNSUPPORTED);
    check("i= outside d=", status(replace(s, "v=1;", "v=1; i=@example.org;"), erec) == mail::ERR_FORMAT);
    check("i= a lookalike", status(replace(s, "v=1;", "v=1; i=@badexample.com;"), erec) == mail::ERR_FORMAT);
    check("x= before t=", status(replace(s, "v=1;", "v=1; x=1000;"), erec) == mail::ERR_FORMAT);
    check("l= not a number", status(replace(s, "v=1;", "v=1; l=12a;"), erec) == mail::ERR_FORMAT);
    check("an unknown tag is ignored", status(replace(s, "v=1;", "v=1; zz=whatever;"), erec) != mail::ERR_FORMAT);
    var res: dkim::Result[>..] = [];
    check("no signature", dkim::verify_record(MSG, erec, res) == mail::ERR_SIGNATURE && res.len == 0);

    // Signing's own refusals.
    var out: u8[>..] = [];
    var o = opts(dkim::RELAXED, dkim::RELAXED);
    check("sign: no From", dkim::sign(replace(MSG, "From:", "Sender:"), ed, o, out) == mail::ERR_HEADER);
    o.headers.append("to:subject");
    check("sign: h= without from", dkim::sign(MSG, ed, o, out) == mail::ERR_ARG);
    o = opts(dkim::RELAXED, dkim::RELAXED);
    o.domain.clear();
    o.domain.append("exa mple.com");
    check("sign: a bad domain", dkim::sign(MSG, ed, o, out) == mail::ERR_ARG);
    o = opts(dkim::RELAXED, dkim::RELAXED);
    o.identity.append("@example.org");
    check("sign: i= outside d=", dkim::sign(MSG, ed, o, out) == mail::ERR_ARG);
    o = opts(dkim::RELAXED, dkim::RELAXED);
    o.expire = 5;
    check("sign: x= before t=", dkim::sign(MSG, ed, o, out) == mail::ERR_ARG);
    check("sign: nothing written", out.len == 0);
    let none = x509::empty_key();
    check("sign: no key", dkim::sign(MSG, none, opts(dkim::RELAXED, dkim::RELAXED), out) == mail::ERR_KEY);
}

let RSA512_RECORD = "v=DKIM1; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL+fw6GJ5zF7Op8sHZ+HcWSVwR9txlcNu0+4KNoWS865f+LyJkoQnTCD+8qVZN/l1nGuGJvmg8nW0iww2IP5NOECAwEAAQ==";

fn key_records() {
    let rsa = key_rsa();
    let ed = key_ed();
    let rrec = record_of(rsa);
    let erec = record_of(ed);
    let sr = signed(MSG, rsa, opts(dkim::RELAXED, dkim::RELAXED));
    let se = signed(MSG, ed, opts(dkim::RELAXED, dkim::RELAXED));
    check("record: revoked", status(sr, "v=DKIM1; k=rsa; p=") == mail::ERR_KEY);
    let rv = first_result(se, "v=DKIM1; k=ed25519; p=");
    check("record: revoked ed25519", rv.status == mail::ERR_KEY && rv.reason.starts_with("key revoked"));
    check("record: none", status(se, "") == mail::ERR_DNS);
    check("record: no p=", status(se, "v=DKIM1; k=ed25519") == mail::ERR_KEY);
    check("record: v=DKIM2", status(se, replace(erec, "DKIM1", "DKIM2")) == mail::ERR_KEY);
    check("record: v= not first", status(se, "k=ed25519; v=DKIM1; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=") == mail::ERR_KEY);
    check("record: no v=, k= after p=", status(se, "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=; k=ed25519") == mail::OK);
    check("record: k= missing means rsa", status(sr, replace(rrec, "k=rsa; ", "")) == mail::OK);
    check("record: k= not a=", status(sr, erec) == mail::ERR_KEY);
    check("record: k=unknown", status(se, replace(erec, "k=ed25519", "k=dsa")) == mail::ERR_KEY);
    check("record: h=sha256", status(sr, replace(rrec, "k=rsa;", "k=rsa; h=sha1:sha256;")) == mail::OK);
    check("record: h=sha1 only", status(sr, replace(rrec, "k=rsa;", "k=rsa; h=sha1;")) == mail::ERR_KEY);
    check("record: s=email", status(se, replace(erec, "k=ed25519;", "k=ed25519; s=email;")) == mail::OK);
    check("record: s=other", status(se, replace(erec, "k=ed25519;", "k=ed25519; s=other;")) == mail::ERR_KEY);
    let ty = first_result(se, replace(erec, "k=ed25519;", "k=ed25519; t=y;"));
    check("record: t=y", ty.status == mail::OK && ty.testing);
    check("record: p= folded", status(se, replace(erec, "p=11qY", "p=11\r\n qY")) == mail::OK);
    check("record: p= not base64", status(se, replace(erec, "p=11qY", "p=!1qY")) == mail::ERR_KEY);
    check("record: ed25519 p= too short", status(se, "v=DKIM1; k=ed25519; p=AAAA") == mail::ERR_KEY);
    check("record: rsa p= garbage", status(sr, "v=DKIM1; k=rsa; p=AAAA") == mail::ERR_KEY);
    let r512 = first_result(sr, RSA512_RECORD);
    check("record: a 512-bit RSA key is refused", r512.status == mail::ERR_KEY);
    check("record: a 1024-bit key under min_rsa_bits 2048",
          status(sr, rrec, dkim::VerifyOptions { now: 1711929600, min_rsa_bits: 2048, .. }) == mail::ERR_KEY);

    // The bare RSAPublicKey: the SPKI's BIT STRING contents.
    var der: u8[>..] = [];
    base64::decode(der, rrec["v=DKIM1; k=rsa; p=".len..]);
    let bare = str("v=DKIM1; k=rsa; p=", b64(der[22..]));
    check("record: a bare RSAPublicKey", status(sr, bare) == mail::OK);

    // t=s: i= must be d= itself.
    var o = opts(dkim::RELAXED, dkim::RELAXED);
    o.identity.append("@mail.example.com");
    let sub = signed(MSG, ed, o);
    check("record: t=s and a subdomain i=", status(sub, replace(erec, "k=ed25519;", "k=ed25519; t=s;")) == mail::ERR_KEY);
    check("record: t=s and i= is d=", status(se, replace(erec, "k=ed25519;", "k=ed25519; t=s;")) == mail::OK);

    // Keys: PKCS #8 PEM, a seed, junk.
    let k1, e1 = dkim::parse_key("not a key");
    check("key: junk", e1 == mail::ERR_KEY);
    let k2, e2 = dkim::parse_key(" nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=\n");
    check("key: a seed with spaces", e2 == mail::OK && k2.kind == x509::KEY_ED25519);
}

// rsa-sha1, signed by hand: refused unless allow_sha1.
fn sha1() {
    let rsa = key_rsa();
    let rrec = record_of(rsa);
    var body: u8[>..] = [];
    let msg = str("From: alice@example.com\r\nSubject: old\r\n\r\nHello.\r\n");
    var fields: dkim::Field[>..] = [];
    let at = dkim::split_message(msg, fields);
    dkim::canon_body(body, msg[at..], dkim::SIMPLE);
    var hdr = str("DKIM-Signature: v=1; a=rsa-sha1; d=example.com; s=sel; h=from:subject; bh=",
                  b64(bignum::sha1(body)), "; b=");
    var data:  u8[>..]         = [];
    var names: dkim::Span[>..] = [];
    dkim::split_names("from:subject", names);
    dkim::signed_headers(data, msg, fields, "from:subject", names, -1, dkim::SIMPLE);
    data.append(hdr);
    let sig, ok = bignum::rsa_sign_pkcs1_digest(rsa.rsa, bignum::sha1(data), bignum::HASH_SHA1);
    check("sha1: signed", ok);
    let s = str(hdr, b64(sig), "\r\n", msg);
    let r = first_result(s, rrec);
    check("sha1: refused by default", r.status == mail::ERR_UNSUPPORTED && r.alg == dkim::ALG_RSA_SHA1);
    check("sha1: allowed", status(s, rrec, dkim::VerifyOptions { allow_sha1: true, now: 1711929600, .. }) == mail::OK);
    check("sha1: allowed, changed", status(replace(s, "Hello", "Hullo"), rrec,
                                           dkim::VerifyOptions { allow_sha1: true, now: 1711929600, .. }) == mail::ERR_SIGNATURE);
    check("sha1: key h=sha256 only", status(s, replace(rrec, "k=rsa;", "k=rsa; h=sha256;"),
                                            dkim::VerifyOptions { allow_sha1: true, now: 1711929600, .. }) == mail::ERR_KEY);
}

fn multiple() {
    // Two signatures: one over the other, with a lookup by selector.
    let rsa = key_rsa();
    let ed = key_ed();
    var o = opts(dkim::RELAXED, dkim::RELAXED);
    let s1 = signed(MSG, ed, o);
    o.selector.clear();
    o.selector.append("rsa");
    let s2 = signed(s1, rsa, o);
    var res: dkim::Result[>..] = [];
    let e = dkim::verify(s2, res, dkim::VerifyOptions { now: 1711929600, .. }) { d, sel, rec =>
        if sel == "rsa" { rec.append(record_of(rsa)); } else if sel == "sel" { rec.append(record_of(ed)); }
    };
    check("two signatures", e == mail::OK && res.len == 2 && res[0].status == mail::OK && res[1].status == mail::OK);
    check("two signatures: in order", res.len == 2 && res[0].s == "rsa" && res[1].s == "sel");
    res.clear();
    let e2 = dkim::verify(s2, res) { d, sel, rec => if sel == "sel" { rec.append(record_of(ed)); } };
    check("two signatures: one key missing", e2 == mail::OK && res.len == 2 && res[0].status == mail::ERR_DNS);
    var text: u8[>..] = [];
    dkim::result_text(res[0], text);
    check("result_text", text == "dkim=temperror header.d=example.com header.s=rsa header.a=rsa-sha256 (no key record)");
    text.clear();
    dkim::result_text(res[1], text);
    check("result_text: pass", text == "dkim=pass header.d=example.com header.s=sel header.a=ed25519-sha256");
    res.clear();
    check("max_signatures", dkim::verify_record(s2, record_of(ed), res, dkim::VerifyOptions { max_signatures: 1, .. }) ==
                            mail::ERR_KEY && res.len == 1);
}

fn two_froms() {
    // RFC 6376 §8.15: a From above the signed one, not oversigned, would
    // pass; a message with more than one From fails every signature.
    let ed = key_ed();
    var o = opts(dkim::RELAXED, dkim::RELAXED);
    o.oversign_from = false;
    let s = signed(MSG, ed, o);
    check("one From: passes", status(s, record_of(ed)) == mail::OK);
    var forged: u8[>..] = [];
    forged.append("From: CEO <ceo@example.com>\r\n");
    forged.append(s);
    let r = first_result(forged, record_of(ed));
    check("two From: fails", r.status == mail::ERR_FORMAT && r.reason == "not exactly one From field");
}

// --- h= matching and the limits -----------------------------------------------------------

// signed_headers' fields for h= names over msg, simple canonicalization.
fn taken(msg: const u8[:], h: const u8[:], skip: i64) -> u8[>..] {
    var fields: dkim::Field[>..] = [];
    dkim::split_message(msg, fields);
    var names: dkim::Span[>..] = [];
    dkim::split_names(h, names);
    var out: u8[>..] = [];
    dkim::signed_headers(out, msg, fields, h, names, skip, dkim::SIMPLE);
    return out;
}

// A DKIM-Signature with the right bh= for MSG's body and a junk b=, its h=
// from and n names x, then extra fields "y:" and MSG: the reviewer's message.
fn junk_signed(n: i64, extra: i64) -> u8[>..] {
    var body: u8[>..] = [];
    var fields: dkim::Field[>..] = [];
    let at = dkim::split_message(MSG, fields);
    dkim::canon_body(body, MSG[at..], dkim::RELAXED);
    var m: u8[>..] = [];
    m.append("DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=sel; bh=");
    m.append(b64(bignum::sha256(body)));
    m.append("; b=AAAA; h=from");
    for i in n { m.append(":x"); }
    m.append("\r\n");
    for i in extra { m.append("y:\r\n"); }
    m.append(MSG);
    return m;
}

fn h_matching() {
    // §5.4.2: each name takes the lowest instance not yet taken, without
    // case; one with none left, or none at all, adds nothing.
    let msg = "A: 1\r\nB: 1\r\na: 2\r\nc: 1\r\nA: 3\r\n\r\n";
    check("h=: bottom-up, repeated, missing", taken(msg, "a:b:A:a:a:x:C", -1) == "A: 3\r\nB: 1\r\na: 2\r\nA: 1\r\nc: 1\r\n");
    check("h=: the signature's own field skipped", taken(msg, "a:a:a", 4) == "a: 2\r\nA: 1\r\n");
    check("h=: a name of no field", taken(msg, "x:y", -1) == "");
    check("h=: WSP before the colon", taken("Subject : hi\r\n\r\n", "subject", -1) == "Subject : hi\r\n");

    let ed = key_ed();
    let erec = record_of(ed);
    var o = opts(dkim::RELAXED, dkim::RELAXED);
    o.headers.append("FROM:subject:Subject:SUBJECT:to:x-none");
    let two = replace(MSG, "Subject: The  plans\r\n", "Subject: The  plans\r\nSubject: Again\r\n");
    let s = signed(two, ed, o);
    check("h=: names in any case", status(s, erec) == mail::OK);
    check("h=: a third Subject added", status(str("Subject: More\r\n", s), erec) == mail::ERR_SIGNATURE);
    check("h=: a Subject removed", status(replace(s, "Subject: Again\r\n", ""), erec) == mail::ERR_SIGNATURE);
    let swapped = replace(replace(replace(s, "Subject: Again", "Subject: T"), "Subject: The  plans", "Subject: Again"),
                          "Subject: T\r\n", "Subject: The  plans\r\n");
    check("h=: two Subjects swapped", swapped.len == s.len && status(swapped, erec) == mail::ERR_SIGNATURE);

    // A second signature that signs DKIM-Signature twice: the first one,
    // and nothing for the second name, its own field not being a candidate.
    var o2 = opts(dkim::RELAXED, dkim::RELAXED);
    o2.headers.append("from:dkim-signature:dkim-signature");
    let s2 = signed(signed(MSG, ed, opts(dkim::RELAXED, dkim::RELAXED)), ed, o2);
    var res: dkim::Result[>..] = [];
    dkim::verify_record(s2, erec, res, dkim::VerifyOptions { now: 1711929600, .. });
    check("h=: DKIM-Signature signed", res.len == 2 && res[0].status == mail::OK && res[1].status == mail::OK);
}

fn limits() {
    let ed = key_ed();
    let erec = record_of(ed);

    // Tags: MAX_TAGS, then one more.
    var t: u8[>..] = [];
    for i in dkim::MAX_TAGS { format(t, "t", i, "=1;"); }
    check("tags: MAX_TAGS", tags_ok(t) == dkim::MAX_TAGS);
    t.append("u=1");
    check("tags: one more", tags_ok(t) == -1);
    // The reviewer's: 8 signatures of 4000 tags each.
    var many: u8[>..] = [];
    for k in 8 {
        many.append("DKIM-Signature: v=1");
        for i in 4000 { format(many, "; t", i, "=1"); }
        many.append("\r\n");
    }
    many.append(MSG);
    var res: dkim::Result[>..] = [];
    dkim::verify_record(many, erec, res);
    var all = res.len == 8;
    for r in res { if r.status != mail::ERR_FORMAT || r.reason != "malformed tag-list" { all = false; } }
    check("tags: 8 signatures of 4000", all);

    // h=: MAX_H_NAMES signs and verifies; one more is refused both ways.
    var o = opts(dkim::RELAXED, dkim::RELAXED);
    o.headers.append("from");
    for i in dkim::MAX_H_NAMES - 1 { o.headers.append(":x"); }
    check("h=: MAX_H_NAMES names", status(signed(MSG, ed, o), erec) == mail::OK);
    o.headers.append(":x");
    var out: u8[>..] = [];
    check("h=: sign refuses one more", dkim::sign(MSG, ed, o, out) == mail::ERR_ARG && out.len == 0);
    let r1 = first_result(junk_signed(dkim::MAX_H_NAMES, 0), erec);
    check(str("h=: verify refuses one more: ", r1.reason), r1.status == mail::ERR_FORMAT && r1.reason == "h= has more than 256 names");
    let r2 = first_result(junk_signed(50000, 900), erec);
    check("h=: 50000 names", r2.status == mail::ERR_FORMAT && r2.reason == "h= has more than 256 names");
    let r3 = first_result(junk_signed(255, 990), erec);
    check(str("h=: 256 names, 999 fields, junk b=: ", r3.reason), r3.status == mail::ERR_SIGNATURE && !r3.body_mismatch);

    // Fields: MSG has 6, its signature makes 7.
    var relays: u8[>..] = [];
    for i in dkim::MAX_FIELDS - 7 { format(relays, "Received: from relay", i, "\r\n"); }
    let s = signed(str(relays, MSG), ed, opts(dkim::RELAXED, dkim::RELAXED));
    check("fields: MAX_FIELDS", status(s, erec) == mail::OK);
    let r4 = first_result(str("Received: from one more\r\n", s), erec);
    check("fields: one more", r4.status == mail::ERR_FORMAT && r4.reason == "more than 1000 header fields");
    out.clear();
    check("fields: sign refuses", dkim::sign(str("X: 1\r\nX: 2\r\n", relays, MSG), ed, opts(dkim::RELAXED, dkim::RELAXED), out) ==
                                  mail::ERR_HEADER && out.len == 0);
    // The reviewer's: 50000 names against 50000 fields, 8 times.
    let one = junk_signed(50000, 50000);
    var big: u8[>..] = [];
    let sig_end = one.len - 50000 * 4 - MSG.len;
    for k in 8 { big.append(one[..sig_end]); }
    big.append(one[sig_end..]);
    res.clear();
    dkim::verify_record(big, erec, res);
    all = res.len == 8;
    for r in res { if r.status != mail::ERR_FORMAT || r.reason != "more than 1000 header fields" { all = false; } }
    check("fields: 8 signatures, 50000 names and fields", all);
}

fn main() {
    two_froms();
    h_matching();
    limits();
    canonicalization();
    rfc8463();
    tag_lists();
    round_trips();
    tampering();
    header_checks();
    key_records();
    sha1();
    multiple();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("dkim: ok");
}
