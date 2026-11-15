// oauth without a server: PKCE against RFC 7636 Appendix B; DPoP proofs
// against RFC 9449's examples (§4.1, §7.1: verified with the key they
// carry, the thumbprint of §6.1, ath) and our own, made and checked;
// at_hash and c_hash against OpenID Connect Core's examples; ID tokens
// signed here, valid and with each fault §3.1.3.7 looks for; JWT access
// tokens (RFC 9068) and their binding by cnf; the documents of RFC 8414,
// RFC 6749 §5.1 and §5.2, RFC 8628 §3.2 and RFC 7662 §2.2; the
// authorization request and its callback; client authentication.
import std;
import json;
import gslib from "../..";
import gslib.oauth;
import gslib.oauth.oidc;
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwt;
import gslib.net.http;
import gslib.net.http.client;
import gslib.net.http.url;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

// RFC 9449 §4.1 (Figure 4) and §7.1 (Figure 13), the line wraps undone.
let DPOP_TOKEN_REQ = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";
let DPOP_RESOURCE = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA";
let DPOP_AT = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
let DPOP_JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

let METADATA = "{\"issuer\":\"https://server.example.com\",\"authorization_endpoint\":\"https://server.example.com/authorize\",\"token_endpoint\":\"https://server.example.com/token\",\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"private_key_jwt\",\"tls_client_auth\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"RS256\",\"ES256\"],\"userinfo_endpoint\":\"https://server.example.com/userinfo\",\"jwks_uri\":\"https://server.example.com/jwks.json\",\"registration_endpoint\":\"https://server.example.com/register\",\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"address\",\"phone\",\"offline_access\"],\"response_types_supported\":[\"code\",\"code token\"],\"service_documentation\":\"http://server.example.com/service_documentation.html\",\"ui_locales_supported\":[\"en-US\",\"en-GB\",\"en-CA\",\"fr-FR\",\"fr-CA\"],\"code_challenge_methods_supported\":[\"S256\"],\"pushed_authorization_request_endpoint\":\"https://server.example.com/par\",\"require_pushed_authorization_requests\":true,\"device_authorization_endpoint\":\"https://server.example.com/device_authorization\",\"revocation_endpoint\":\"https://server.example.com/revoke\",\"introspection_endpoint\":\"https://server.example.com/introspect\",\"dpop_signing_alg_values_supported\":[\"ES256\",\"PS256\"],\"authorization_response_iss_parameter_supported\":true,\"tls_client_certificate_bound_access_tokens\":true,\"mtls_endpoint_aliases\":{\"token_endpoint\":\"https://mtls.example.com/token\",\"revocation_endpoint\":\"https://mtls.example.com/revo\",\"introspection_endpoint\":\"https://mtls.example.com/introspect\"}}";

// RFC 6749 §5.1, RFC 8628 §3.2, RFC 7662 §2.2 (with cnf as RFC 8705 §3.2 adds it).
let TOKEN = "{\"access_token\":\"2YotnFZFEjr1zCsicMWpAA\",\"token_type\":\"example\",\"expires_in\":3600,\"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\",\"example_parameter\":\"example_value\"}";
let DEVICE = "{\"device_code\":\"GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"https://example.com/device\",\"verification_uri_complete\":\"https://example.com/device?user_code=WDJB-MJHT\",\"expires_in\":1800,\"interval\":5}";
let INTROSPECTION = "{\"active\":true,\"client_id\":\"l238j323ds-23ij4\",\"username\":\"jdoe\",\"scope\":\"read write dolphin\",\"sub\":\"Z5O3upPC88QrAjx00dis\",\"aud\":\"https://protected.example.net/resource\",\"iss\":\"https://server.example.com/\",\"exp\":1419356238,\"iat\":1419350238,\"extension_field\":\"twenty-seven\",\"cnf\":{\"x5t#S256\":\"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"}}";

let ISS = "https://op.example.test";
let NOW: i64 = 1700000000;

fn pkce() {
    // RFC 7636 Appendix B.
    check("PKCE S256, RFC 7636 B", oauth::pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
          == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    let v = oauth::new_verifier();
    var ok = v.len == 43;
    for ch in v {
        if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') { ok = false; }
    }
    check("verifier: 43 unreserved characters", ok);
    check("verifiers differ", oauth::new_verifier() != v);
}

fn dpop() {
    var c = oauth::Client { .. };
    c.now = 1562262616;
    var p, err = oauth::verify_dpop_proof(c, DPOP_TOKEN_REQ, "POST", "https://server.example.com/token");
    check("RFC 9449 §4.1 proof verifies", err == oauth::OK);
    check("RFC 9449 §6.1 jkt", p.jkt == DPOP_JKT);
    check("its jti", p.jti == "-BwC3ESc6acc2lTc" && p.iat == 1562262616);
    let p2, e2 = oauth::verify_dpop_proof(c, DPOP_TOKEN_REQ, "GET", "https://server.example.com/token");
    check("another method", e2 == oauth::ERR_DPOP);
    let p3, e3 = oauth::verify_dpop_proof(c, DPOP_TOKEN_REQ, "POST", "https://server.example.com/other");
    check("another URL", e3 == oauth::ERR_DPOP);
    let p4, e4 = oauth::verify_dpop_proof(c, DPOP_TOKEN_REQ, "POST", "https://server.example.com/token?x=1#f");
    check("the query and fragment are not part of htu", e4 == oauth::OK);
    let p5, e5 = oauth::verify_dpop_proof(c, DPOP_TOKEN_REQ, "POST", "https://server.example.com/token", "", "a-nonce");
    check("a nonce expected and not there", e5 == oauth::ERR_DPOP);
    c.now = 1562262616 + 3600;
    let p6, e6 = oauth::verify_dpop_proof(c, DPOP_TOKEN_REQ, "POST", "https://server.example.com/token");
    check("an old proof", e6 == oauth::ERR_IAT);

    // §7.1: the proof that goes with an access token.
    c.now = 1562262618;
    check("RFC 9449 §7.1 ath", oauth::dpop_ath(DPOP_AT) == "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
    let r, re = oauth::verify_dpop_proof(c, DPOP_RESOURCE, "GET", "https://resource.example.org/protectedresource", DPOP_AT);
    check("RFC 9449 §7.1 proof verifies with its token", re == oauth::OK && r.ath == "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
    let r2, re2 = oauth::verify_dpop_proof(c, DPOP_RESOURCE, "GET", "https://resource.example.org/protectedresource", "another-token");
    check("another token's proof", re2 == oauth::ERR_DPOP);
    check("binding to the RFC's jkt", oauth::check_dpop_binding(DPOP_JKT, r) == oauth::OK
          && oauth::check_dpop_binding("not-it", r) == oauth::ERR_CNF && oauth::check_dpop_binding("", r) == oauth::ERR_CNF);

    // A tampered signature.
    var bad: u8[>..] = [];
    bad.append(DPOP_TOKEN_REQ);
    bad[bad.len - 2] = if bad[bad.len - 2] == 'A' { 'B' } else { 'A' };
    c.now = 1562262616;
    let pb, eb = oauth::verify_dpop_proof(c, bad, "POST", "https://server.example.com/token");
    check("a tampered proof", eb == oauth::ERR_SIGNATURE);

    // Our own: made, then checked as a server would.
    let key = jwk::generate_ec(jwa::CRV_P256);
    check("set_dpop_key", oauth::set_dpop_key(c, key) == oauth::OK && c.dpop_alg == jwa::ES256);
    c.now = 0;
    let proof, perr = oauth::dpop_proof(c.dpop_key, c.dpop_alg, "GET", "https://api.example.test/r?q=1#x", "srv-nonce", "the-token");
    check("our proof", perr == oauth::OK);
    let q, qe = oauth::verify_dpop_proof(c, proof, "GET", "https://api.example.test/r", "the-token", "srv-nonce");
    check("our proof verifies", qe == oauth::OK && q.htu == "https://api.example.test/r" && q.nonce == "srv-nonce");
    check("its jkt is the key's thumbprint", q.jkt == jwk::thumbprint_b64(key));
    var m = jws::Message { .. };
    check("a compact JWS", jws::parse(m, proof) == jwx::OK && m.compact);
    check("typ dpop+jwt, the public key in the header", m.sigs[0].header.typ == "dpop+jwt" && m.sigs[0].header.has_jwk
          && m.sigs[0].header.jwk.d.len == 0 && !m.sigs[0].header.jwk.private && m.sigs[0].header.jwk.kty == jwa::KTY_EC);
    let proof2, perr2 = oauth::dpop_proof(c.dpop_key, c.dpop_alg, "GET", "https://api.example.test/r");
    let q2, qe2 = oauth::verify_dpop_proof(c, proof2, "GET", "https://api.example.test/r");
    check("a fresh jti each time", qe2 == oauth::OK && q2.jti != q.jti && q2.ath.len == 0);
    let rsa = jwk::generate_rsa(2048);
    let pr, prerr = oauth::dpop_proof(rsa, jwa::PS256, "POST", "https://as.example.test/token");
    let qr, qre = oauth::verify_dpop_proof(c, pr, "POST", "https://as.example.test/token");
    check("a PS256 proof", prerr == oauth::OK && qre == oauth::OK && qr.alg == jwa::PS256);
    let pub = jwk::public_key(key);
    let pn, pnerr = oauth::dpop_proof(pub, jwa::ES256, "GET", "https://x.example.test/");
    check("no proof by a public key", pnerr == oauth::ERR_KEY);
    let hk = jwk::generate_oct(32);
    let ph, pherr = oauth::dpop_proof(hk, jwa::HS256, "GET", "https://x.example.test/");
    check("no proof by HMAC", pherr == oauth::ERR_KEY);
}

fn hashes() {
    // OpenID Connect Core Appendix A.3 and A.4 (RS256).
    check("at_hash, OIDC A.3", oauth::token_hash(jwa::RS256, "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y")
          == "77QmUPtjPfzWtF2AnpK9RQ");
    check("c_hash, OIDC A.4", oauth::token_hash(jwa::RS256, "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk")
          == "LDktKdoQak3Pk0cnXxCltA");
    check("ES384 hashes by SHA-384: 24 bytes", oauth::token_hash(jwa::ES384, "x").len == 32);
    check("EdDSA hashes by SHA-512: 32 bytes", oauth::token_hash(jwa::EDDSA, "x").len == 43);
    // SHAKE256("") (FIPS 202), its first 57 of 114 bytes.
    check("Ed448 hashes by SHAKE256 to 114 bytes: 57", oauth::token_hash(jwa::EDDSA, "", jwa::CRV_ED448).len == 76
          && oauth::token_hash(jwa::ED448, "") == oauth::token_hash(jwa::EDDSA, "", jwa::CRV_ED448)
          && oauth::token_hash(jwa::ED448, "") == "RrndKwuojRMjOz_rdD7rJD_NUupiuBuCtQwnZG7Vdi_XXcTd2MDyAMsFAZ1ntZL2_IIcSUeatIZA");
}

fn documents() {
    let m, ok = oauth::read_metadata(METADATA);
    check("metadata", ok && m.issuer == "https://server.example.com" && m.token_endpoint == "https://server.example.com/token"
          && m.par_endpoint == "https://server.example.com/par" && m.require_par && m.iss_parameter && m.bound_tokens
          && m.device_endpoint == "https://server.example.com/device_authorization"
          && m.mtls_token == "https://mtls.example.com/token" && m.mtls_device.len == 0);
    check("metadata lists", oauth::has_name(m.auth_methods, "private_key_jwt") && !oauth::has_name(m.auth_methods, "none")
          && m.pkce_methods == "S256" && oauth::has_name(m.dpop_algs, "PS256") && oauth::has_name(m.scopes, "offline_access"));
    let none, nok = oauth::read_metadata("{\"token_endpoint\":\"x\"}");
    check("metadata without an issuer", !nok);
    let arr, aok = oauth::read_metadata("[1,2]");
    check("metadata that is not an object", !aok);

    // RFC 8414 §3.1's example, and OpenID Connect's.
    check("RFC 8414 URL with a path", oauth::metadata_url("https://example.com/issuer1", false)
          == "https://example.com/.well-known/oauth-authorization-server/issuer1");
    check("RFC 8414 URL without", oauth::metadata_url("https://example.com", false)
          == "https://example.com/.well-known/oauth-authorization-server");
    check("OIDC discovery URL", oauth::metadata_url("https://example.com/realms/demo/", true)
          == "https://example.com/realms/demo/.well-known/openid-configuration");

    var c = oauth::Client { .. };
    c.meta = m;
    check("plain endpoint", oauth::token_endpoint(c) == "https://server.example.com/token");
    c.use_mtls = true;
    check("mtls alias", oauth::token_endpoint(c) == "https://mtls.example.com/token");
    check("no alias: the plain one", oauth::endpoint(c, m.device_endpoint, m.mtls_device) == "https://server.example.com/device_authorization");

    let t, tok = oauth::read_token(TOKEN, 1000);
    check("token response, RFC 6749 §5.1", tok && t.access_token == "2YotnFZFEjr1zCsicMWpAA" && t.token_type == "example"
          && t.expires_in == 3600 && t.expires_at == 4600 && t.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA" && t.id_token.len == 0);
    let t2, tok2 = oauth::read_token("{\"token_type\":\"Bearer\"}", 0);
    check("no access_token", !tok2);

    let e = oauth::error_of("{\"error\":\"invalid_request\",\"error_description\":\"no grant_type\",\"error_uri\":\"https://e.example/x\"}", 400);
    check("error response, RFC 6749 §5.2", e.status == 400 && e.code == "invalid_request" && e.description == "no grant_type"
          && e.uri == "https://e.example/x");
    let e2 = oauth::error_of("<html>gateway</html>", 502);
    check("not an error response", e2.status == 502 && e2.code.len == 0 && e2.description.len > 0);
    c.error = e;
    check("is_error", oauth::is_error(c, "invalid_request") && !oauth::is_error(c, "invalid_grant"));

    let d, dok = oauth::read_device(DEVICE);
    check("device response, RFC 8628 §3.2", dok && d.user_code == "WDJB-MJHT" && d.expires_in == 1800 && d.interval == 5
          && d.device_code == "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS" && d.verification_uri == "https://example.com/device"
          && d.verification_uri_complete == "https://example.com/device?user_code=WDJB-MJHT");
    let d2, dok2 = oauth::read_device("{\"device_code\":\"a\",\"user_code\":\"b\",\"verification_uri\":\"https://x\",\"expires_in\":600}");
    check("device response: interval 5 by default", dok2 && d2.interval == 5);

    let it, iok = oauth::read_introspection(INTROSPECTION);
    check("introspection, RFC 7662 §2.2", iok && it.active && it.client_id == "l238j323ds-23ij4" && it.username == "jdoe"
          && it.scope == "read write dolphin" && it.exp == 1419356238 && it.aud == "https://protected.example.net/resource"
          && it.cnf_x5t == "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2");
    let ina, inok = oauth::read_introspection("{\"active\":false}");
    check("inactive", inok && !ina.active);
    let inb, inbok = oauth::read_introspection("{\"scope\":\"x\"}");
    check("introspection without active", !inbok);
    let ic, icok = oauth::read_introspection("{\"active\":true,\"aud\":[\"a\",\"b\"],\"cnf\":{\"jkt\":\"J\"}}");
    check("audiences and jkt", icok && ic.aud == "a\nb" && ic.cnf_jkt == "J");

    check("scopes", oauth::has_scope("openid profile email", "profile") && !oauth::has_scope("openid profile", "prof")
          && oauth::has_scopes("a b c", "c a") && !oauth::has_scopes("a b", "a d") && oauth::has_scopes("a", ""));
}

// n bytes of ch.
fn bytes(ch: u8, n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    for i in n { out.push(ch); }
    return out;
}

// Nothing kept in part: a caller's argument over its field's size is
// ERR_ARG, at the size it is taken whole; a server's member over its
// field's size, of another JSON type or holding the separator of the list
// it goes in refuses the whole response; an error's text is cut and
// marked.
fn limits() {
    var c = oauth::Client { .. };
    let m, ok = oauth::read_metadata(METADATA);
    c.meta = m;
    oauth::set_public(c, "native-app");

    // new_auth_request: a redirect URI of 512 bytes and a scope of 1024, not one more.
    let ru512 = str("https://app.example.test/", bytes('r', 512 - 25));
    let ru513 = str(ru512, "x");
    let sc1024 = str("openid ", bytes('s', 1024 - 7));
    let sc1025 = str(sc1024, "x");
    let ar, e1 = oauth::new_auth_request(c, ru512, sc1024);
    let url = oauth::authorization_url(c, ar);
    let qru, h1 = http::query_value(url[position(url, '?') + 1..], "redirect_uri");
    let qsc, h2 = http::query_value(url[position(url, '?') + 1..], "scope");
    check("new_auth_request: 512-byte redirect URI and 1024-byte scope kept whole", e1 == oauth::OK && ru512.len == 512
          && sc1024.len == 1024 && ar.redirect_uri == ru512 && ar.scope == sc1024 && qru == ru512 && qsc == sc1024 && ar.nonce.len > 0);
    let ar2, e2 = oauth::new_auth_request(c, ru513, "openid");
    check("new_auth_request: a 513-byte redirect URI is ERR_ARG", e2 == oauth::ERR_ARG && ar2.state.len == 0);
    let ar3, e3 = oauth::new_auth_request(c, ru512, sc1025);
    check("new_auth_request: a 1025-byte scope is ERR_ARG, no nonce made", e3 == oauth::ERR_ARG && ar3.nonce.len == 0
          && ar3.scope.len == 0);

    // Client ids of 256 bytes, not 257; client_secret_jwt's secret at most jwk::MAX_OCT.
    var k = oauth::Client { .. };
    check("set_public: 256-byte client id", oauth::set_public(k, bytes('i', 256)) == oauth::OK && k.client_id.len == 256);
    check("set_public: 257 is ERR_ARG", oauth::set_public(k, bytes('i', 257)) == oauth::ERR_ARG);
    check("set_secret: 256-byte client id", oauth::set_secret(k, bytes('i', 256), "s") == oauth::OK);
    check("set_secret: 257 is ERR_ARG", oauth::set_secret(k, bytes('i', 257), "s") == oauth::ERR_ARG);
    check("set_secret: a client_secret_jwt secret of MAX_OCT bytes",
          oauth::set_secret(k, "x", bytes('k', jwk::MAX_OCT), oauth::AUTH_SECRET_JWT) == oauth::OK);
    check("set_secret: one more is ERR_ARG",
          oauth::set_secret(k, "x", bytes('k', jwk::MAX_OCT + 1), oauth::AUTH_SECRET_JWT) == oauth::ERR_ARG);
    check("set_secret: a long basic secret is fine", oauth::set_secret(k, "x", bytes('k', 4096)) == oauth::OK);
    let pkey = jwk::generate_ec(jwa::CRV_P256);
    check("set_private_key: 256-byte client id", oauth::set_private_key(k, bytes('i', 256), pkey) == oauth::OK);
    check("set_private_key: 257 is ERR_ARG", oauth::set_private_key(k, bytes('i', 257), pkey) == oauth::ERR_ARG);
    var hc = http::Client { .. };
    check("set_tls_client_auth: 257 is ERR_ARG", oauth::set_tls_client_auth(k, hc, bytes('i', 257), "", "") == oauth::ERR_ARG);

    // A DPoP-Nonce of 512 bytes is kept; one more refuses the response.
    var dn: u8[..512] = [];
    check("DPoP-Nonce of 512 bytes", oauth::keep_dpop_nonce(dn, bytes('n', 512), true) && dn.len == 512);
    check("DPoP-Nonce of 513 refused, the old one not kept as if new",
          !oauth::keep_dpop_nonce(dn, bytes('n', 513), true));
    check("no DPoP-Nonce: nothing changes", oauth::keep_dpop_nonce(dn, "", false) && dn.len == 512);

    // Metadata: endpoints of 512 bytes, not 513; flags booleans; lists of strings without line ends.
    let iss = "https://as.example.test";
    let ep512 = str(iss, "/", bytes('e', 512 - iss.len - 1));
    let ep513 = str(ep512, "e");
    let md, mok = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"token_endpoint\":\"", ep512, "\"}"));
    check("metadata: a 512-byte endpoint", mok && md.token_endpoint == ep512);
    let md2, mok2 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"token_endpoint\":\"", ep513, "\"}"));
    check("metadata: a 513-byte endpoint refused", !mok2);
    let md3, mok3 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"token_endpoint\":\"", iss,
                                              "/t\",\"mtls_endpoint_aliases\":{\"token_endpoint\":\"", ep513, "\"}}"));
    check("metadata: a 513-byte mTLS alias refused (not the plain endpoint instead)", !mok3);
    let md4, mok4 = oauth::read_metadata(str("{\"issuer\":\"", iss, bytes('i', 513 - iss.len), "\"}"));
    check("metadata: a 513-byte issuer refused", !mok4);
    let md5, mok5 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"token_endpoint\":42}"));
    check("metadata: an endpoint that is not a string refused", !mok5);
    let md6, mok6 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"mtls_endpoint_aliases\":\"https://x\"}"));
    check("metadata: mtls_endpoint_aliases not an object refused", !mok6);
    let md7, mok7 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"authorization_response_iss_parameter_supported\":\"true\"}"));
    check("metadata: a flag that is not a boolean refused", !mok7);
    let md8, mok8 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"code_challenge_methods_supported\":[\"plain\\nS256\"]}"));
    check("metadata: a list element with a line end empties that list, flagged (it would be two)",
          mok8 && md8.pkce_methods.len == 0 && md8.lists_truncated);
    // A large provider's scopes_supported: some 5 KB, kept whole.
    var big: u8[>..] = [];
    var want: u8[>..] = [];
    for i in 250 {
        if i > 0 { big.push(','); want.push('\n'); }
        let name = str("api://service-", 1000 + i, "/x");
        big.append(str("\"", name, "\""));
        want.append(name);
    }
    let md9, mok9 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"token_endpoint\":\"", iss, "/t\",\"scopes_supported\":[", big, "],\"code_challenge_methods_supported\":[\"S256\"]}"));
    check("metadata: a 5 KB scopes_supported kept whole", mok9 && want.len > 5000 && md9.scopes == want && !md9.lists_truncated
          && md9.pkce_methods == "S256");
    let md10, mok10 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"token_endpoint\":\"", iss, "/t\",\"scopes_supported\":[\"", bytes('a', 4096), "\",\"",
                                                bytes('b', 4096), "\"],\"code_challenge_methods_supported\":[\"S256\"]}"));
    check("metadata: scopes_supported of 8193 bytes left empty and flagged, not cut; discovery goes on", mok10
          && md10.scopes.len == 0 && md10.lists_truncated && md10.token_endpoint.len > 0 && md10.pkce_methods == "S256");
    let md13, mok13 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"scopes_supported\":[\"", bytes('a', 4095), "\",\"",
                                                bytes('b', 4096), "\"]}"));
    check("metadata: scopes_supported of 8192 bytes kept", mok13 && md13.scopes.len == 8192 && !md13.lists_truncated);
    let md11, mok11 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"dpop_signing_alg_values_supported\":[\"ES256\",7]}"));
    check("metadata: a list with a non-string left empty, flagged", mok11 && md11.dpop_algs.len == 0 && md11.lists_truncated);
    let md14, mok14 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"grant_types_supported\":\"client_credentials\"}"));
    check("metadata: a list that is not an array left empty, flagged", mok14 && md14.grant_types.len == 0 && md14.lists_truncated);
    let md12, mok12 = oauth::read_metadata(str("{\"issuer\":\"", iss, "\",\"userinfo_endpoint\":null,\"scopes_supported\":null}"));
    check("metadata: null members are absent", mok12 && md12.userinfo_endpoint.len == 0);

    // Token responses: each member whole and a string, or refused.
    let t1, tok1 = oauth::read_token(str("{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"scope\":\"", bytes('s', 2048), "\"}"), 0);
    check("token: a 2048-byte scope", tok1 && t1.scope.len == 2048);
    let t2, tok2 = oauth::read_token(str("{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"scope\":\"", bytes('s', 2049), "\"}"), 0);
    check("token: a 2049-byte scope refused (absent would mean the scope asked for)", !tok2);
    let t3, tok3 = oauth::read_token("{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"id_token\":17}", 0);
    check("token: an id_token that is not a string refused", !tok3);
    let t4, tok4 = oauth::read_token("{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"scope\":[\"x\"]}", 0);
    check("token: a scope that is not a string refused", !tok4);
    let t5, tok5 = oauth::read_token(str("{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"refresh_token\":\"", bytes('r', 8193), "\"}"), 0);
    check("token: a 8193-byte refresh token refused", !tok5);
    let t6, tok6 = oauth::read_token(str("{\"access_token\":\"", bytes('a', 12288), "\",\"token_type\":\"", bytes('t', 32), "\"}"), 0);
    check("token: access token and type at their sizes", tok6 && t6.access_token.len == 12288 && t6.token_type.len == 32);
    let t7, tok7 = oauth::read_token(str("{\"access_token\":\"a\",\"token_type\":\"", bytes('t', 33), "\"}"), 0);
    check("token: a 33-byte token_type refused", !tok7);
    let d1, dok1 = oauth::read_device("{\"device_code\":\"a\",\"user_code\":\"b\",\"verification_uri\":\"https://x\",\"verification_uri_complete\":5,\"expires_in\":600}");
    check("device: a verification_uri_complete that is not a string refused", !dok1);

    // Introspection: every member at its size, then one more.
    let names: const u8[:][] = ["scope", "client_id", "username", "token_type", "sub", "iss", "jti"];
    let caps: i64[] = [2048, 256, 256, 64, 256, 512, 256];
    for i in names.len {
        let at_cap, ok_cap = oauth::read_introspection(str("{\"active\":true,\"", names[i], "\":\"", bytes('v', caps[i]), "\"}"));
        let over, ok_over = oauth::read_introspection(str("{\"active\":true,\"", names[i], "\":\"", bytes('v', caps[i] + 1), "\"}"));
        let wrong, ok_wrong = oauth::read_introspection(str("{\"active\":true,\"", names[i], "\":true}"));
        check(str("introspection: ", names[i], " at ", caps[i], " bytes kept, one more refused, not a string refused"),
              ok_cap && at_cap.raw.len > 0 && !ok_over && !over.active && !ok_wrong);
    }
    let ia, iaok = oauth::read_introspection(str("{\"active\":true,\"aud\":\"", bytes('a', 1024), "\"}"));
    check("introspection: a 1024-byte aud", iaok && ia.aud.len == 1024);
    let ib, ibok = oauth::read_introspection(str("{\"active\":true,\"aud\":\"", bytes('a', 1025), "\"}"));
    check("introspection: a 1025-byte aud refused (not left out: a token for anyone)", !ibok && !ib.active);
    let ic, icok = oauth::read_introspection(str("{\"active\":true,\"aud\":[\"", bytes('a', 511), "\",\"", bytes('b', 512), "\"]}"));
    check("introspection: audiences of 1024 bytes, one a line", icok && ic.aud.len == 1024 && oauth::has_name(ic.aud, bytes('b', 512)));
    let id, idok = oauth::read_introspection(str("{\"active\":true,\"aud\":[\"", bytes('a', 512), "\",\"", bytes('b', 512), "\"]}"));
    check("introspection: audiences of 1025 bytes refused, not the first alone", !idok);
    let ie, ieok = oauth::read_introspection("{\"active\":true,\"aud\":\"https://evil.example\\nhttps://rs.example.test\"}");
    check("introspection: an aud with a line end refused (it would forge a second)", !ieok);
    let ig, igok = oauth::read_introspection("{\"active\":true,\"aud\":[\"https://evil.example\\nhttps://rs.example.test\"]}");
    check("introspection: an aud element with a line end refused", !igok);
    let ih, ihok = oauth::read_introspection("{\"active\":true,\"aud\":42}");
    check("introspection: an aud that is neither string nor array refused", !ihok);
    let ii, iiok = oauth::read_introspection(str("{\"active\":true,\"cnf\":{\"jkt\":\"", bytes('j', 64), "\",\"x5t#S256\":\"", bytes('x', 64), "\"}}"));
    check("introspection: cnf thumbprints of 64 bytes", iiok && ii.cnf_jkt.len == 64 && ii.cnf_x5t.len == 64);
    let ij, ijok = oauth::read_introspection(str("{\"active\":true,\"cnf\":{\"jkt\":\"", bytes('j', 65), "\"}}"));
    check("introspection: a 65-byte cnf.jkt refused (not a bearer token instead)", !ijok);
    let ik, ikok = oauth::read_introspection(str("{\"active\":true,\"cnf\":{\"x5t#S256\":\"", bytes('x', 65), "\"}}"));
    check("introspection: a 65-byte cnf x5t#S256 refused", !ikok);
    let il, ilok = oauth::read_introspection("{\"active\":true,\"cnf\":\"bound\"}");
    check("introspection: a cnf that is not an object refused", !ilok);
    let im, imok = oauth::read_introspection("{\"active\":true,\"cnf\":{\"jkt\":7}}");
    check("introspection: a cnf.jkt that is not a string refused", !imok);
    let in1, in1ok = oauth::read_introspection("{\"active\":true,\"exp\":\"1419356238\"}");
    check("introspection: an exp that is not a number refused (0 would be no expiry)", !in1ok);
    let in2, in2ok = oauth::read_introspection("{\"active\":true,\"exp\":1.4e9,\"aud\":null,\"cnf\":null}");
    check("introspection: exp as a float, aud and cnf null", in2ok && in2.exp == 1400000000 && in2.aud.len == 0 && in2.cnf_jkt.len == 0);

    // Error responses: informational text, cut to fit and marked.
    let e0 = oauth::error_of(str("{\"error\":\"invalid_request\",\"error_description\":\"", bytes('d', 1024), "\",\"error_uri\":\"", bytes('u', 512), "\"}"), 400);
    check("error: description of 1024 and URI of 512 whole, not marked", e0.description.len == 1024 && e0.uri.len == 512 && !e0.truncated);
    let ec = oauth::error_of(str("{\"error\":\"invalid_request\",\"error_description\":\"", bytes('d', 1025), "\",\"error_uri\":\"", bytes('u', 513), "\"}"), 400);
    check("error: description cut at 1024, a 513-byte URI left out, marked truncated", ec.code == "invalid_request"
          && ec.description.len == 1024 && ec.uri.len == 0 && ec.truncated);
    let el = oauth::error_of(str("{\"error\":\"", bytes('c', 129), "\"}"), 400);
    check("error: a 129-byte code left out and marked, never matched", el.code.len == 0 && el.truncated);
    let ar4, e4 = oauth::new_auth_request(c, "http://127.0.0.1/cb", "x");
    c.meta.iss_parameter = false;
    let cb, cerr = oauth::parse_callback(c, ar4, str("state=", ar4.state, "&error=", bytes('c', 129), "&error_uri=", bytes('u', 513)));
    check("callback error: code and URI that do not fit left out, marked", cerr == oauth::ERR_OAUTH && c.error.code.len == 0
          && c.error.uri.len == 0 && c.error.truncated);
    let cb2, cerr2 = oauth::parse_callback(c, ar4, str("state=", ar4.state, "&error=access_denied"));
    check("callback error: a fresh error is not marked", cerr2 == oauth::ERR_OAUTH && c.error.code == "access_denied" && !c.error.truncated);
}

fn requests() {
    var c = oauth::Client { .. };
    let m, ok = oauth::read_metadata(METADATA);
    c.meta = m;
    check("public client", oauth::set_public(c, "native-app") == oauth::OK);
    let ar, arerr = oauth::new_auth_request(c, "http://127.0.0.1:8400/cb", "openid profile");
    check("auth request: state, nonce, verifier", arerr == oauth::OK && ar.state.len == 32 && ar.nonce.len == 32 && ar.verifier.len == 43);
    let url = oauth::authorization_url(c, ar, "prompt=consent");
    let q = url[position(url, '?') + 1..];
    let rt, h1 = http::query_value(q, "response_type");
    let ci, h2 = http::query_value(q, "client_id");
    let ru, h3 = http::query_value(q, "redirect_uri");
    let sc, h4 = http::query_value(q, "scope");
    let cc, h5 = http::query_value(q, "code_challenge");
    let cm, h6 = http::query_value(q, "code_challenge_method");
    let st, h7 = http::query_value(q, "state");
    let no, h8 = http::query_value(q, "nonce");
    let pr, h9 = http::query_value(q, "prompt");
    check("authorization URL", url[..position(url, '?')] == "https://server.example.com/authorize" && rt == "code"
          && ci == "native-app" && ru == "http://127.0.0.1:8400/cb" && sc == "openid profile"
          && cc == oauth::pkce_challenge(ar.verifier) && cm == "S256" && st == ar.state && no == ar.nonce && pr == "consent");
    let dj, h10 = http::query_value(q, "dpop_jkt");
    check("no dpop_jkt without a DPoP key", !h10);
    let plain, plerr = oauth::new_auth_request(c, "http://127.0.0.1/cb", "api:read");
    check("no nonce without openid", plerr == oauth::OK && plain.nonce.len == 0);
    let key = jwk::generate_ec(jwa::CRV_P256);
    oauth::set_dpop_key(c, key);
    let url2 = oauth::authorization_url(c, ar);
    let dj2, h11 = http::query_value(url2[position(url2, '?') + 1..], "dpop_jkt");
    check("dpop_jkt is the DPoP key's thumbprint", h11 && dj2 == jwk::thumbprint_b64(key));

    // The callback: state first, then iss (the metadata says it is sent), then error or code.
    let cb = str("http://127.0.0.1:8400/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=", ar.state, "&iss=https%3A%2F%2Fserver.example.com");
    let code, cerr = oauth::parse_callback(c, ar, cb);
    check("callback", cerr == oauth::OK && code == "SplxlOBeZQQYbYS6WxSbIA");
    let c2, e2 = oauth::parse_callback(c, ar, "code=x&state=forged&iss=https%3A%2F%2Fserver.example.com");
    check("callback: another state", e2 == oauth::ERR_STATE);
    let c3, e3 = oauth::parse_callback(c, ar, str("code=x&state=", ar.state));
    check("callback: iss missing though the server sends it", e3 == oauth::ERR_ISSUER);
    let c4, e4 = oauth::parse_callback(c, ar, str("code=x&state=", ar.state, "&iss=https%3A%2F%2Fevil.example"));
    check("callback: another issuer (mix-up)", e4 == oauth::ERR_ISSUER);
    let c5, e5 = oauth::parse_callback(c, ar, str("?error=access_denied&error_description=The+user+said+no&state=", ar.state,
                                                  "&iss=https%3A%2F%2Fserver.example.com"));
    check("callback: an error", e5 == oauth::ERR_OAUTH && c.error.code == "access_denied" && c.error.description == "The user said no");
    c.meta.iss_parameter = false;
    let c6, e6 = oauth::parse_callback(c, ar, str("state=", ar.state));
    check("callback: no code", e6 == oauth::ERR_MALFORMED);

    // Client authentication.
    var basic = oauth::Client { .. };
    basic.meta = m;
    check("secret", oauth::set_secret(basic, "my client", "p@ss w:rd+/", oauth::AUTH_SECRET_BASIC) == oauth::OK);
    var form:   u8[>..] = [];
    var fields: u8[>..] = [];
    check("basic", oauth::add_client_auth(basic, form, fields) == oauth::OK && form.len == 0);
    // RFC 6749 §2.3.1: each form-encoded, then Basic.
    var want: u8[>..] = [];
    http::basic_credentials(want, "my+client", "p%40ss+w%3Ard%2B%2F");
    check("basic: form-encoded first", fields == str("Authorization: ", want, "\r\n"));
    basic.auth = oauth::AUTH_SECRET_POST;
    form.clear();
    fields.clear();
    oauth::add_client_auth(basic, form, fields);
    let pid, hp = http::query_value(form, "client_id");
    let psec, hs = http::query_value(form, "client_secret");
    check("post", fields.len == 0 && pid == "my client" && psec == "p@ss w:rd+/");
    check("a bad method", oauth::set_secret(basic, "x", "y", oauth::AUTH_TLS) == oauth::ERR_ARG);

    var pk = oauth::Client { .. };
    pk.meta = m;
    let ck = jwk::generate_ec(jwa::CRV_P384);
    var ckk = ck;
    ckk.kid.append("client-key-1");
    check("private_key_jwt", oauth::set_private_key(pk, "jwt-client", ckk) == oauth::OK && pk.key_alg == jwa::ES384);
    form.clear();
    fields.clear();
    check("assertion", oauth::add_client_auth(pk, form, fields) == oauth::OK);
    let at, ha = http::query_value(form, "client_assertion_type");
    let a, haa = http::query_value(form, "client_assertion");
    check("assertion type", at == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    var cl = jwt::new_claims();
    var v = jwt::Validator { .. };
    v.issuer.append("jwt-client");
    v.subject.append("jwt-client");
    v.audience.append("https://server.example.com");
    v.required = jwt::CLAIM_EXP | jwt::CLAIM_IAT | jwt::CLAIM_JTI;
    let ck_pub = jwk::public_key(ck);
    check("assertion verifies: iss, sub, aud the issuer, exp, iat, jti",
          jwt::parse(a, jwa::ES384, ck_pub, cl, v) == jwx::OK && cl.exp - cl.iat == 60);
    var mm = jws::Message { .. };
    jws::parse(mm, a);
    check("assertion kid", mm.sigs[0].header.kid == "client-key-1");
    form.clear();
    oauth::add_client_auth(pk, form, fields);
    let a2, haa2 = http::query_value(form, "client_assertion");
    var cl2 = jwt::new_claims();
    jwt::parse_insecure(a2, cl2);
    check("a fresh jti each time", cl2.jti != cl.jti);
    pk.assertion_aud.append("https://server.example.com/token");
    form.clear();
    oauth::add_client_auth(pk, form, fields);
    let a3, haa3 = http::query_value(form, "client_assertion");
    var cl3 = jwt::new_claims();
    jwt::parse_insecure(a3, cl3);
    check("assertion_aud", jwt::audiences(cl3)[0] == "https://server.example.com/token");
    check("no private_key_jwt by a public key", oauth::set_private_key(pk, "x", ck_pub) == oauth::ERR_KEY);

    var sj = oauth::Client { .. };
    sj.meta = m;
    oauth::set_secret(sj, "hs-client", "a shared secret of thirty-two b!", oauth::AUTH_SECRET_JWT);
    form.clear();
    fields.clear();
    oauth::add_client_auth(sj, form, fields);
    let sa, hsa = http::query_value(form, "client_assertion");
    var cl4 = jwt::new_claims();
    var v4 = jwt::Validator { .. };
    v4.issuer.append("hs-client");
    let sk = jwk::from_oct("a shared secret of thirty-two b!");
    check("client_secret_jwt: HS256 by the secret", jwt::parse(sa, jwa::HS256, sk, cl4, v4) == jwx::OK);

    // Nothing to send to: no network is touched.
    var empty = oauth::Client { .. };
    oauth::set_public(empty, "x");
    var hc = http::Client { .. };
    let t, terr = oauth::client_credentials(empty, hc);
    check("no token endpoint", terr == oauth::ERR_ARG);
    let r, rerr = oauth::push_authorization_request(empty, hc, ar);
    check("no PAR endpoint", rerr == oauth::ERR_ARG);
}

// An ID token's payload: the defaults below, with `extra` members
// appended and those named in `drop` left out.
fn payload(aud: const u8[:], extra: const u8[:], drop: const u8[:] = "") -> u8[>..] {
    var p: u8[>..] = [];
    p.push('{');
    if find(drop, "iss") < 0 { p.append(str("\"iss\":\"", ISS, "\",")); }
    if find(drop, "sub") < 0 { p.append("\"sub\":\"248289761001\","); }
    p.append(str("\"aud\":", aud, ","));
    if find(drop, "exp") < 0 { p.append(str("\"exp\":", NOW + 600, ",")); }
    if find(drop, "iat") < 0 { p.append(str("\"iat\":", NOW - 10, ",")); }
    p.append("\"nonce\":\"n-0S6_WzA2Mj\",\"auth_time\":");
    format(p, NOW - 100);
    if extra.len > 0 { p.push(','); p.append(extra); }
    p.push('}');
    return p;
}

fn sign(p: const u8[:], key: const jwk::Key&, alg: i64, kid: const u8[:], typ: const u8[:] = "") -> u8[>..] {
    var h = jws::Header { .. };
    h.alg = alg;
    h.kid.append(kid);
    h.typ.append(typ);
    let out, err = jws::sign_with(p, key, h);
    assert(err == jwx::OK);
    return out;
}

fn fn_err(c: oauth::Client&, hc: http::Client&, token: const u8[:], nonce: const u8[:]) -> i64 {
    let id, err = oauth::validate_id_token(c, hc, token, nonce);
    return err;
}

fn id_tokens() {
    var c = oauth::Client { .. };
    let m, ok = oauth::read_metadata(METADATA);
    c.meta = m;
    c.meta.issuer.clear();
    c.meta.issuer.append(ISS);
    c.meta.jwks_uri.clear();         // keys from set_keys only: nothing fetched
    oauth::set_secret(c, "s6BhdRkqt3", "a shared secret of thirty-two b!", oauth::AUTH_SECRET_BASIC);
    c.now = NOW;
    var rsa = jwk::generate_rsa(2048);
    rsa.kid.append("rsa-1");
    var ec = jwk::generate_ec(jwa::CRV_P256);
    ec.kid.append("ec-1");
    var keys: jwk::Key[>..] = [];
    keys.push(jwk::public_key(rsa));
    keys.push(jwk::public_key(ec));
    check("set_keys", oauth::set_keys(c, jwk::marshal_set(keys, false)) == oauth::OK && c.keys.len == 2);
    var hc = http::Client { .. };
    let aud = "\"s6BhdRkqt3\"";
    let nonce = "n-0S6_WzA2Mj";

    let good = sign(payload(aud, "\"azp\":\"s6BhdRkqt3\""), rsa, jwa::RS256, "rsa-1");
    let id, err = oauth::validate_id_token(c, hc, good, nonce);
    check("a valid ID token (RS256)", err == oauth::OK && id.sub == "248289761001" && id.iss == ISS && id.alg == jwa::RS256
          && id.kid == "rsa-1" && id.aud == "s6BhdRkqt3" && id.auth_time == NOW - 100);
    let em, emok = oauth::claim_string(id.claims, "nonce");
    check("claim_string", emok && em == nonce);
    let es = sign(payload(aud, ""), ec, jwa::ES256, "ec-1");
    let id2, err2 = oauth::validate_id_token(c, hc, es, nonce);
    check("a valid ID token (ES256)", err2 == oauth::OK);
    let nokid = sign(payload(aud, ""), ec, jwa::ES256, "");
    let id3, err3 = oauth::validate_id_token(c, hc, nokid, nonce);
    check("no kid: any key that fits", err3 == oauth::OK);

    check("no iss", fn_err(c, hc, sign(payload(aud, "", "iss"), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_ISSUER);
    let p_iss = str("{\"iss\":\"https://evil.example\",\"sub\":\"1\",\"aud\":", aud, ",\"exp\":", NOW + 600, ",\"iat\":", NOW, "}");
    check("another iss", fn_err(c, hc, sign(p_iss, rsa, jwa::RS256, "rsa-1"), "") == oauth::ERR_ISSUER);
    check("another audience", fn_err(c, hc, sign(payload("\"other-client\"", ""), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_AUDIENCE);
    check("two audiences, no azp", fn_err(c, hc, sign(payload("[\"s6BhdRkqt3\",\"other\"]", ""), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_AZP);
    check("two audiences, azp ours", fn_err(c, hc, sign(payload("[\"s6BhdRkqt3\",\"other\"]", "\"azp\":\"s6BhdRkqt3\""), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::OK);
    check("azp another's", fn_err(c, hc, sign(payload(aud, "\"azp\":\"other\""), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_AZP);
    check("no sub", fn_err(c, hc, sign(payload(aud, "", "sub"), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_CLAIM);
    check("no exp", fn_err(c, hc, sign(payload(aud, "", "exp"), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_CLAIM);
    check("no iat", fn_err(c, hc, sign(payload(aud, "", "iat"), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_CLAIM);
    check("another nonce", fn_err(c, hc, good, "another") == oauth::ERR_NONCE);
    check("no nonce asked for", fn_err(c, hc, good, "") == oauth::OK);
    c.now = NOW + 600 + 59;
    check("expired, within the leeway", fn_err(c, hc, good, nonce) == oauth::OK);
    c.now = NOW + 600 + 60;
    check("expired", fn_err(c, hc, good, nonce) == oauth::ERR_EXPIRED);
    c.now = NOW - 100;
    check("iat ahead", fn_err(c, hc, good, nonce) == oauth::ERR_IAT);
    c.now = NOW;
    let nbf = sign(payload(aud, str("\"nbf\":", NOW + 300)), rsa, jwa::RS256, "rsa-1");
    check("nbf ahead", fn_err(c, hc, nbf, nonce) == oauth::ERR_EXPIRED);

    // max_age: auth_time NOW - 100.
    let ma, mae = oauth::validate_id_token(c, hc, good, nonce, "", "", 3600);
    check("max_age met", mae == oauth::OK);
    let ma2, mae2 = oauth::validate_id_token(c, hc, good, nonce, "", "", 10);
    check("max_age passed", mae2 == oauth::ERR_AUTH_TIME);

    // The signature and its algorithm.
    var tampered: u8[>..] = [];
    tampered.append(good);
    tampered[tampered.len - 3] = if tampered[tampered.len - 3] == 'A' { 'B' } else { 'A' };
    check("a tampered signature", fn_err(c, hc, tampered, nonce) == oauth::ERR_SIGNATURE);
    var other = jwk::generate_rsa(2048);
    check("signed by another key with our kid", fn_err(c, hc, sign(payload(aud, ""), other, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_SIGNATURE);
    check("an unknown kid", fn_err(c, hc, sign(payload(aud, ""), other, jwa::RS256, "rsa-9"), nonce) == oauth::ERR_NO_KEY);
    let none = str(jwx::b64_encode("{\"alg\":\"none\"}"), ".", jwx::b64_encode(payload(aud, "")), ".");
    check("alg none", fn_err(c, hc, none, nonce) == oauth::ERR_ALG);
    let secret_key = jwk::from_oct("a shared secret of thirty-two b!");
    let hs = sign(payload(aud, ""), secret_key, jwa::HS256, "");
    check("HS256 not allowed by default", fn_err(c, hc, hs, nonce) == oauth::ERR_ALG);
    c.algs.push(jwa::HS256);
    c.algs.push(jwa::RS256);
    check("HS256 allowed: verified by the client secret", fn_err(c, hc, hs, nonce) == oauth::OK);
    let other_secret = jwk::from_oct("another secret, thirty-two bytes");
    let hs_bad = sign(payload(aud, ""), other_secret, jwa::HS256, "");
    check("HS256 by another secret", fn_err(c, hc, hs_bad, nonce) == oauth::ERR_SIGNATURE);
    check("ES256 not in the client's list", fn_err(c, hc, es, nonce) == oauth::ERR_ALG);
    c.algs.clear();
    // Ed448 (RFC 8037's EdDSA, and RFC 9864's "Ed448"), its at_hash by SHAKE256.
    var ed = jwk::generate_okp(jwa::CRV_ED448);
    ed.kid.append("ed448-1");
    var eds: jwk::Key[>..] = [];
    eds.push(jwk::public_key(rsa));
    eds.push(jwk::public_key(ec));
    eds.push(jwk::public_key(ed));
    oauth::set_keys(c, jwk::marshal_set(eds, false));
    check("alg_for an Ed448 key: EdDSA", oauth::alg_for(ed) == jwa::EDDSA);
    let ed_at = str("\"at_hash\":\"", oauth::token_hash(jwa::EDDSA, "the access token", jwa::CRV_ED448), "\"");
    let edt = sign(payload(aud, ed_at), ed, jwa::EDDSA, "ed448-1");
    let ide, ede = oauth::validate_id_token(c, hc, edt, nonce, "the access token");
    check("an Ed448 ID token (EdDSA), at_hash by SHAKE256", ede == oauth::OK);
    let ide2, ede2 = oauth::validate_id_token(c, hc, edt, nonce, "another access token");
    check("Ed448 at_hash mismatch", ede2 == oauth::ERR_AT_HASH);
    let ed2 = sign(payload(aud, ""), ed, jwa::ED448, "ed448-1");
    check("an Ed448 ID token (alg Ed448)", fn_err(c, hc, ed2, nonce) == oauth::OK);
    let ps = sign(payload(aud, ""), rsa, jwa::PS256, "rsa-1");
    check("PS256 with an RSA key", fn_err(c, hc, ps, nonce) == oauth::OK);
    check("an access token is not an ID token", fn_err(c, hc, sign(payload(aud, ""), rsa, jwa::RS256, "rsa-1", "at+jwt"), nonce) == oauth::ERR_TYP);
    check("not a JWS", fn_err(c, hc, "not.a-token", nonce) == oauth::ERR_MALFORMED);

    // at_hash and c_hash, for the OIDC examples' values.
    let ath = oauth::token_hash(jwa::RS256, "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");
    let with_hashes = sign(payload(aud, str("\"at_hash\":\"", ath, "\",\"c_hash\":\"LDktKdoQak3Pk0cnXxCltA\"")), rsa, jwa::RS256, "rsa-1");
    let h1, he1 = oauth::validate_id_token(c, hc, with_hashes, nonce, "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
                                           "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk");
    check("at_hash and c_hash", he1 == oauth::OK && h1.at_hash == "77QmUPtjPfzWtF2AnpK9RQ" && h1.c_hash == "LDktKdoQak3Pk0cnXxCltA");
    let h2, he2 = oauth::validate_id_token(c, hc, with_hashes, nonce, "another access token");
    check("at_hash mismatch", he2 == oauth::ERR_AT_HASH);
    let h3, he3 = oauth::validate_id_token(c, hc, with_hashes, nonce, "", "another code");
    check("c_hash mismatch", he3 == oauth::ERR_C_HASH);

    // Members a check depends on, of another type or holding a separator: refused, not read as absent.
    check("at_hash not a string", fn_err(c, hc, sign(payload(aud, "\"at_hash\":42"), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_MALFORMED);
    check("azp not a string", fn_err(c, hc, sign(payload(aud, "\"azp\":[\"s6BhdRkqt3\"]"), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_MALFORMED);
    let p_nn = str("{\"iss\":\"", ISS, "\",\"sub\":\"1\",\"aud\":", aud, ",\"exp\":", NOW + 600, ",\"iat\":", NOW, ",\"nonce\":5}");
    check("nonce not a string", fn_err(c, hc, sign(p_nn, rsa, jwa::RS256, "rsa-1"), "") == oauth::ERR_MALFORMED);
    check("an audience with a line end", fn_err(c, hc, sign(payload("[\"s6BhdRkqt3\",\"evil\\nmore\"]", "\"azp\":\"s6BhdRkqt3\""), rsa, jwa::RS256, "rsa-1"),
                                                nonce) == oauth::ERR_MALFORMED);
    check("c_hash of 129 bytes", fn_err(c, hc, sign(payload(aud, str("\"c_hash\":\"", bytes('h', 129), "\"")), rsa, jwa::RS256, "rsa-1"), nonce) == oauth::ERR_MALFORMED);

    // The JWKS: refetched for an unknown kid at most once a minute.
    var fresh = oauth::Client { .. };
    check("never fetched: may fetch", oauth::jwks_may_refetch(fresh, 5));
    check("just fetched: may not", !oauth::jwks_may_refetch(c, c.jwks_fetched_ns + 1000000000));
    check("a minute on: may", oauth::jwks_may_refetch(c, c.jwks_fetched_ns + 60 * 1000000000));
}

fn access_tokens() {
    var rs = oauth::Client { .. };
    rs.meta.issuer.append(ISS);
    rs.now = NOW;
    var ec = jwk::generate_ec(jwa::CRV_P256);
    ec.kid.append("at-1");
    var keys: jwk::Key[>..] = [];
    keys.push(jwk::public_key(ec));
    oauth::set_keys(rs, jwk::marshal_set(keys, false));
    var hc = http::Client { .. };
    let cert = "a certificate's DER, as the TLS handshake gave it";
    let x5t = oauth::cert_thumbprint(cert);
    let p = str("{\"iss\":\"", ISS, "\",\"sub\":\"5ba552d67\",\"aud\":\"https://rs.example.test/\",\"exp\":", NOW + 300,
                ",\"iat\":", NOW, ",\"jti\":\"dbe39bf3a3ba4238a513f51d6e1691c4\",\"client_id\":\"s6BhdRkqt3\",\"scope\":\"openid profile reademail\",\"cnf\":{\"x5t#S256\":\"",
                x5t, "\",\"jkt\":\"", DPOP_JKT, "\"}}");
    let tok = sign(p, ec, jwa::ES256, "at-1", "at+jwt");
    let at, err = oauth::validate_access_token(rs, hc, tok, "https://rs.example.test/", "reademail");
    check("a JWT access token, RFC 9068", err == oauth::OK && at.client_id == "s6BhdRkqt3" && at.sub == "5ba552d67"
          && at.scope == "openid profile reademail" && at.cnf_x5t == x5t && at.cnf_jkt == DPOP_JKT);
    let at2, e2 = oauth::validate_access_token(rs, hc, sign(p, ec, jwa::ES256, "at-1", "application/at+jwt"), "https://rs.example.test/");
    check("typ application/at+jwt", e2 == oauth::OK);
    let at3, e3 = oauth::validate_access_token(rs, hc, sign(p, ec, jwa::ES256, "at-1", "JWT"), "https://rs.example.test/");
    check("typ JWT is not an access token", e3 == oauth::ERR_TYP);
    let at4, e4 = oauth::validate_access_token(rs, hc, tok, "https://other.example.test/");
    check("another resource", e4 == oauth::ERR_AUDIENCE);
    let at5, e5 = oauth::validate_access_token(rs, hc, tok, "https://rs.example.test/", "reademail writeemail");
    check("a scope it lacks", e5 == oauth::ERR_SCOPE);
    let no_jti = str("{\"iss\":\"", ISS, "\",\"sub\":\"x\",\"aud\":\"r\",\"exp\":", NOW + 300, ",\"iat\":", NOW, ",\"client_id\":\"c\"}");
    let at6, e6 = oauth::validate_access_token(rs, hc, sign(no_jti, ec, jwa::ES256, "at-1", "at+jwt"), "r");
    check("no jti", e6 == oauth::ERR_CLAIM);
    rs.now = NOW + 400;
    let at7, e7 = oauth::validate_access_token(rs, hc, tok, "https://rs.example.test/");
    check("expired", e7 == oauth::ERR_EXPIRED);

    // cnf whole or the token refused: never a bound token that looks unbound.
    rs.now = NOW;
    let base = str("{\"iss\":\"", ISS, "\",\"sub\":\"x\",\"aud\":\"r\",\"exp\":", NOW + 300, ",\"iat\":", NOW,
                   ",\"jti\":\"j\",\"client_id\":\"c\"");
    let cnf64, ec64 = oauth::validate_access_token(rs, hc, sign(str(base, ",\"cnf\":{\"jkt\":\"", bytes('j', 64), "\"}}"), ec, jwa::ES256, "at-1", "at+jwt"), "r");
    check("cnf.jkt of 64 bytes", ec64 == oauth::OK && cnf64.cnf_jkt.len == 64);
    let cnf65, ec65 = oauth::validate_access_token(rs, hc, sign(str(base, ",\"cnf\":{\"jkt\":\"", bytes('j', 65), "\"}}"), ec, jwa::ES256, "at-1", "at+jwt"), "r");
    check("cnf.jkt of 65 bytes refused", ec65 == oauth::ERR_MALFORMED && cnf65.cnf_jkt.len == 0 && cnf65.sub.len == 0);
    let cnfs, ecs = oauth::validate_access_token(rs, hc, sign(str(base, ",\"cnf\":\"bound\"}"), ec, jwa::ES256, "at-1", "at+jwt"), "r");
    check("cnf not an object refused", ecs == oauth::ERR_MALFORMED);
    let cnfx, ecx = oauth::validate_access_token(rs, hc, sign(str(base, ",\"cnf\":{\"x5t#S256\":7}}"), ec, jwa::ES256, "at-1", "at+jwt"), "r");
    check("cnf x5t#S256 not a string refused", ecx == oauth::ERR_MALFORMED);
    let scn, escn = oauth::validate_access_token(rs, hc, sign(str(base, ",\"scope\":[\"read\"]}"), ec, jwa::ES256, "at-1", "at+jwt"), "r");
    check("a scope that is not a string refused", escn == oauth::ERR_MALFORMED);
    let anl = str("{\"iss\":\"", ISS, "\",\"sub\":\"x\",\"aud\":[\"r\",\"evil\\nr2\"],\"exp\":", NOW + 300, ",\"iat\":", NOW,
                  ",\"jti\":\"j\",\"client_id\":\"c\"}");
    let atn, eatn = oauth::validate_access_token(rs, hc, sign(anl, ec, jwa::ES256, "at-1", "at+jwt"), "r");
    check("an audience with a line end refused", eatn == oauth::ERR_MALFORMED);

    check("bound to the certificate", oauth::check_cert_binding(at.cnf_x5t, cert) == oauth::OK);
    check("another certificate", oauth::check_cert_binding(at.cnf_x5t, "another") == oauth::ERR_CNF);
    check("an unbound token", oauth::check_cert_binding("", cert) == oauth::ERR_CNF);
    var c = oauth::Client { .. };
    c.now = 1562262618;
    let pr, pe = oauth::verify_dpop_proof(c, DPOP_RESOURCE, "GET", "https://resource.example.org/protectedresource", DPOP_AT);
    check("bound to the RFC's DPoP key", pe == oauth::OK && oauth::check_dpop_binding(at.cnf_jkt, pr) == oauth::OK);
}

fn main() {
    pkce();
    dpop();
    limits();
    hashes();
    documents();
    requests();
    id_tokens();
    access_tokens();
    print("oauth: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
