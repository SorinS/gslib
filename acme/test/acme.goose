// acme without a server: key authorizations and dns-01 values against RFC
// 7638's thumbprint example, RFC 8555's example directory, order,
// authorization and problem (§7.1.1, §7.1.3, §7.1.4, §6.7), Retry-After,
// identifiers, and the JWS of a request: flattened, verifying with the
// account key, its protected header alg, nonce and url with either kid or
// jwk (never both), and an external account binding by HS256.
import std;
import json;
import gslib from "../..";
import gslib.acme;
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.net.http.client;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

let RFC7638_KEY = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";

let DIRECTORY = "{\"newNonce\":\"https://example.com/acme/new-nonce\",\"newAccount\":\"https://example.com/acme/new-account\",\"newOrder\":\"https://example.com/acme/new-order\",\"newAuthz\":\"https://example.com/acme/new-authz\",\"revokeCert\":\"https://example.com/acme/revoke-cert\",\"keyChange\":\"https://example.com/acme/key-change\",\"meta\":{\"termsOfService\":\"https://example.com/acme/terms/2017-5-30\",\"website\":\"https://www.example.com/\",\"caaIdentities\":[\"example.com\"],\"externalAccountRequired\":false,\"profiles\":{\"classic\":\"The usual\",\"shortlived\":\"Six days\"}}}";

let ORDER = "{\"status\":\"valid\",\"expires\":\"2016-01-20T14:09:07.99Z\",\"identifiers\":[{\"type\":\"dns\",\"value\":\"www.example.org\"},{\"type\":\"dns\",\"value\":\"example.org\"}],\"notBefore\":\"2016-01-01T00:00:00Z\",\"notAfter\":\"2016-01-08T00:00:00Z\",\"authorizations\":[\"https://example.com/acme/authz/PAniVnsZcis\",\"https://example.com/acme/authz/r4HqLzrSrpI\"],\"finalize\":\"https://example.com/acme/order/TOlocE8rfgo/finalize\",\"certificate\":\"https://example.com/acme/cert/mAt3xBGaobw\"}";

let AUTHZ = "{\"status\":\"valid\",\"expires\":\"2015-03-01T14:09:07.99Z\",\"identifier\":{\"type\":\"dns\",\"value\":\"www.example.org\"},\"challenges\":[{\"url\":\"https://example.com/acme/chall/prV_B7yEyA4\",\"type\":\"http-01\",\"status\":\"valid\",\"token\":\"DGyRejmCefe7v4NfDGDKfA\",\"validated\":\"2014-12-01T12:05:58.16Z\"},{\"url\":\"https://example.com/acme/chall/Rg5dV14Gh1Q\",\"type\":\"dns-01\",\"status\":\"invalid\",\"token\":\"DGyRejmCefe7v4NfDGDKfA\",\"error\":{\"type\":\"urn:ietf:params:acme:error:dns\",\"detail\":\"no TXT record\"}}],\"wildcard\":false}";

let PROBLEM = "{\"type\":\"urn:ietf:params:acme:error:malformed\",\"detail\":\"Some of the identifiers requested were rejected\",\"subproblems\":[{\"type\":\"urn:ietf:params:acme:error:malformed\",\"detail\":\"Invalid underscore in DNS name \\\"_example.org\\\"\",\"identifier\":{\"type\":\"dns\",\"value\":\"_example.org\"}},{\"type\":\"urn:ietf:params:acme:error:rejectedIdentifier\",\"detail\":\"This CA will not issue for \\\"example.net\\\"\",\"identifier\":{\"type\":\"dns\",\"value\":\"example.net\"}}]}";

fn challenges() {
    var a = acme::Client { .. };
    let k, err = jwk::parse(RFC7638_KEY);
    check("RFC 7638 key", err == jwx::OK);
    a.key = k;
    let token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    check("key authorization", acme::key_authorization(a, token)
          == "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    check("dns-01 value", acme::dns01_value(a, token) == "ZTRx1Ckl1-tM05o5zaizTTA0yUy5AGereMgSNWC6Ll8");
    check("dns-01 name", acme::dns01_name("example.org") == "_acme-challenge.example.org");
    check("dns-01 name of a wildcard", acme::dns01_name("*.example.org") == "_acme-challenge.example.org");
    check("http-01 path", acme::http01_path(token) == "/.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA");
    check("a public key cannot be set", acme::set_key(a, k) == acme::ERR_KEY);
}

fn documents() {
    let d, ok = acme::read_directory(DIRECTORY);
    check("directory", ok && d.new_nonce == "https://example.com/acme/new-nonce"
          && d.key_change == "https://example.com/acme/key-change"
          && d.terms_of_service == "https://example.com/acme/terms/2017-5-30" && !d.eab_required
          && d.profiles == "classic\nshortlived\n" && d.renewal_info.len == 0);
    let bad, bad_ok = acme::read_directory("{\"newNonce\":\"x\"}");
    check("a directory without newAccount", !bad_ok);

    let o, ook = acme::read_order(ORDER, "https://example.com/acme/order/TOlocE8rfgo");
    check("order", ook && o.status == acme::ST_VALID && o.url == "https://example.com/acme/order/TOlocE8rfgo"
          && o.authz == "https://example.com/acme/authz/PAniVnsZcis\nhttps://example.com/acme/authz/r4HqLzrSrpI"
          && o.finalize == "https://example.com/acme/order/TOlocE8rfgo/finalize"
          && o.certificate == "https://example.com/acme/cert/mAt3xBGaobw" && o.expires == "2016-01-20T14:09:07.99Z");
    var n = 0;
    for url in split(o.authz, '\n') { n++; }
    check("order's authorizations", n == 2);

    let z, zok = acme::read_authz(AUTHZ, "https://example.com/acme/authz/PAniVnsZcis");
    check("authorization", zok && z.status == acme::ST_VALID && z.id_type == "dns" && z.id_value == "www.example.org"
          && !z.wildcard && z.challenges.len == 2);
    let i = acme::find_challenge(z, "dns-01");
    check("dns-01 challenge", i == 1 && z.challenges[i].status == acme::ST_INVALID
          && z.challenges[i].token == "DGyRejmCefe7v4NfDGDKfA" && z.challenges[i].url == "https://example.com/acme/chall/Rg5dV14Gh1Q");
    check("no tls-alpn-01", acme::find_challenge(z, "tls-alpn-01") == -1);
    let e = acme::authz_error(z);
    check("challenge error", e.kind == "urn:ietf:params:acme:error:dns" && e.detail == "no TXT record");

    let p = acme::problem_of(PROBLEM, 400);
    check("problem", p.status == 400 && p.kind == "urn:ietf:params:acme:error:malformed" && p.subproblems == 2
          && p.detail == "Some of the identifiers requested were rejected");
    var a = acme::Client { .. };
    a.problem = p;
    check("is_problem", acme::is_problem(a, "malformed") && !acme::is_problem(a, "badNonce")
          && !acme::is_problem(a, "malforme"));
    let np = acme::problem_of("<html>", 503);
    check("not a problem document", np.status == 503 && np.kind.len == 0);

    check("status names", acme::status_lookup("processing") == acme::ST_PROCESSING
          && acme::status_lookup("nonsense") == acme::ST_UNKNOWN && acme::status_name(acme::ST_READY) == "ready");
}

fn misc() {
    check("Retry-After seconds", acme::retry_after_ms("120", 0) == 120000);
    check("Retry-After none", acme::retry_after_ms("", 0) == 0);
    // Sun, 06 Nov 1994 08:49:37 GMT is 784111777 s.
    check("Retry-After date", acme::retry_after_ms("Sun, 06 Nov 1994 08:49:37 GMT", 784111770000) == 7000);
    check("Retry-After past date", acme::retry_after_ms("Sun, 06 Nov 1994 08:49:37 GMT", 784111780000) == 0);
    check("Retry-After nonsense", acme::retry_after_ms("soon", 0) == 0);
    check("ip identifiers", acme::is_ip("192.0.2.1") && acme::is_ip("2001:db8::1") && !acme::is_ip("example.org")
          && !acme::is_ip("1.example"));
}

// The header of the signature of a flattened JWS.
fn header_has(m: const jws::Message&, name: const u8[:]) -> bool {
    let v, ok = jws::header_string(m, 0, name);
    return ok;
}

fn requests() {
    var a = acme::Client { .. };
    let key = jwk::generate_ec(jwa::CRV_P256);
    check("set_key", acme::set_key(a, key) == acme::OK && a.alg == jwa::ES256);
    a.nonce.append("oFvnlFP1wIhRlYS2jTaXbA");

    // By jwk: newAccount.
    let body, err = acme::sign_request(a, "https://example.com/acme/new-account", "{\"termsOfServiceAgreed\":true}", true);
    check("sign by jwk", err == acme::OK);
    var m = jws::Message { .. };
    check("a JWS", jws::parse(m, body) == jwx::OK && !m.compact && m.sigs.len == 1);
    let pub = jwk::public_key(key);
    check("verifies", jws::verify_signature(m, 0, jwa::ES256, pub) == jwx::OK);
    check("payload", m.payload == "{\"termsOfServiceAgreed\":true}");
    let nonce, nok = jws::header_string(m, 0, "nonce");
    let url, uok = jws::header_string(m, 0, "url");
    check("nonce and url", nok && nonce == "oFvnlFP1wIhRlYS2jTaXbA" && uok && url == "https://example.com/acme/new-account");
    check("jwk, no kid", m.sigs[0].header.has_jwk && m.sigs[0].header.kid.len == 0 && m.sigs[0].header.jwk.d.len == 0);
    check("flattened, no unprotected header", find(body, "\"header\"") < 0 && find(body, "\"signatures\"") < 0);

    // By kid, POST-as-GET: the payload is empty.
    a.account.append("https://example.com/acme/acct/evOfKhNU60wg");
    let get, gerr = acme::sign_request(a, "https://example.com/acme/order/TOlocE8rfgo", "", false);
    var g = jws::Message { .. };
    check("POST-as-GET", gerr == acme::OK && jws::parse(g, get) == jwx::OK && g.payload.len == 0
          && find(get, "\"payload\":\"\"") >= 0);
    check("kid, no jwk", !g.sigs[0].header.has_jwk && g.sigs[0].header.kid == "https://example.com/acme/acct/evOfKhNU60wg");
    check("verifies by kid", jws::verify_signature(g, 0, jwa::ES256, pub) == jwx::OK);

    // An external account binding: HS256 by the CA's key over the account's public key.
    a.dir.new_account.append("https://example.com/acme/new-account");
    let mac_key = "a secret the CA gave out, 32 b!";
    let eab, eerr = acme::eab_jws(a, "kid-1", mac_key);
    var e = jws::Message { .. };
    var mac = jwk::empty();
    mac.kty = jwa::KTY_OCT;
    mac.private = true;
    mac.k.append(mac_key);
    check("eab", eerr == acme::OK && jws::parse(e, eab) == jwx::OK
          && jws::verify_signature(e, 0, jwa::HS256, mac) == jwx::OK);
    let ekid, ekok = jws::header_string(e, 0, "kid");
    let eurl, euok = jws::header_string(e, 0, "url");
    check("eab header", ekok && ekid == "kid-1" && euok && eurl == "https://example.com/acme/new-account"
          && !header_has(e, "nonce"));
    let ek, ekerr = jwk::parse(e.payload);
    check("eab payload is the public key", ekerr == jwx::OK && !ek.private && ek.x == key.x && ek.y == key.y);

    // Without a key, nothing is signed; without an account, nothing by kid.
    var b = acme::Client { .. };
    var hc = http::Client { .. };
    let r, perr = acme::post(b, hc, "https://example.com/", "");
    check("no key", perr == acme::ERR_KEY);
    acme::set_key(b, key);
    let r2, perr2 = acme::post(b, hc, "https://example.com/", "");
    check("no account", perr2 == acme::ERR_NO_ACCOUNT);
}

// What a server sends is refused when it could not be used as it is: a
// token that would name another file, a URL too long to keep, a URL with
// a line end, an identifier too long; and an authorization for a name
// nobody ordered is not published.
fn hostile() {
    check("token ok", acme::valid_token("DGyRejmCefe7v4NfDGDKfA") && acme::valid_token("a-b_c"));
    check("token refused", !acme::valid_token("") && !acme::valid_token("../../victim") && !acme::valid_token("a/b")
          && !acme::valid_token("a.b") && !acme::valid_token("a\nb") && !acme::valid_token("a\x00b")
          && !acme::valid_token("a b") && !acme::valid_token("a%2fb"));
    var long_token: u8[>..] = [];
    for i in 257 { long_token.push('a'); }
    check("token of 257", !acme::valid_token(long_token) && acme::valid_token(long_token[..256]));

    let traversal = "{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"a.example\"},\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://x/c\",\"token\":\"../../victim\"}]}";
    let z1, ok1 = acme::read_authz(traversal, "https://x/a");
    check("authz with a path in its token", !ok1);
    let newline = "{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"a.example\"},\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://x/c\",\"token\":\"ab\\ncd\"}]}";
    let z2, ok2 = acme::read_authz(newline, "https://x/a");
    check("authz with a line end in its token", !ok2);

    var big_url: u8[>..] = [];
    big_url.append("https://example.com/");
    while big_url.len < 513 { big_url.push('a'); }
    let dir = str("{\"newNonce\":\"https://x/n\",\"newAccount\":\"https://x/a\",\"newOrder\":\"", big_url, "\"}");
    let d, dok = acme::read_directory(dir);
    check("directory with a URL of 513", !dok);
    let dir512 = str("{\"newNonce\":\"https://x/n\",\"newAccount\":\"https://x/a\",\"newOrder\":\"", big_url[..512], "\"}");
    let d2, dok2 = acme::read_directory(dir512);
    check("directory with a URL of 512", dok2 && d2.new_order.len == 512);

    let two = "{\"status\":\"pending\",\"finalize\":\"https://x/f\",\"authorizations\":[\"https://x/a1\\nhttps://x/evil\"]}";
    let o, ook = acme::read_order(two, "https://x/o");
    check("order with a line end in an authorization URL", !ook);

    var z = acme::Authz { .. };
    z.id_value.append("Example.ORG");
    check("ordered, any case", acme::ordered(z, "www.example.org\nexample.org"));
    check("not ordered", !acme::ordered(z, "www.example.org"));
    z.wildcard = true;
    check("wildcard ordered", acme::ordered(z, "*.example.org") && !acme::ordered(z, "example.org"));
}

fn main() {
    hostile();
    challenges();
    documents();
    misc();
    requests();
    print("acme: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
