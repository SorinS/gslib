// The parts under the profiles: xs:dateTime, IDs; the HTTP-Redirect
// binding (DEFLATE, the query signed over the parameters exactly as they
// came, whatever their order or percent-encoding; tampering, SHA-1, the
// wrong key, duplicate and missing parameters, a DEFLATE bomb); the
// HTTP-POST binding (base64 with line breaks, the form escaped); and
// metadata, written and read back, signed and verified, picked from an
// aggregate, and refused when malformed, expired, tampered or wrapped.
import std;
import os;
import base64;
import gslib from "../..";
import gslib.saml;
import gslib.saml.metadata;
import gslib.saml.logout;
import gslib.saml.sp;
import gslib.saml.idp;
import gslib.encoding.xml;
import gslib.encoding.xml.dsig;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.bignum;
import gslib.crypto.bignum.hmac;
import gslib.crypto.bignum.rsa;
import gslib.compress;
import gslib.compress.deflate;
import gslib.net.http;
import gslib.net.http.url;
import tv;

let MDNS = "urn:oasis:names:tc:SAML:2.0:metadata";

fn times() {
    let t, ok = saml::parse_time("2026-01-02T03:04:05Z");
    tv::check("a time", ok && t == 1767323045);
    let t2, ok2 = saml::parse_time("2026-01-02T03:04:05.999Z");
    tv::check("a fraction dropped", ok2 && t2 == 1767323045);
    let ms, okms = saml::parse_time_ms("2026-01-02T03:04:05.25Z");
    tv::check("milliseconds", okms && ms == 1767323045250);
    let t3, ok3 = saml::parse_time("2026-01-02T05:04:05+02:00");
    tv::check("an offset", ok3 && t3 == 1767323045);
    let t4, ok4 = saml::parse_time("2026-01-02T03:04:05");
    tv::check("no zone: UTC", ok4 && t4 == 1767323045);
    let t5, ok5 = saml::parse_time("2024-02-29T00:00:00Z");
    tv::check("a leap day", ok5);
    for bad in ["2025-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-01-01T24:00:00Z", "2026-01-01 00:00:00Z",
                "2026-01-01T00:00:00ZZ", "2026-01-01T00:00:00.Z", "2026-01-01T00:00:00+0200", "", "tomorrow",
                "2026-01-01T00:00:60Z", "-026-01-01T00:00:00Z"] {
        let tb, okb = saml::parse_time(bad);
        tv::check(str("not a time: ", bad), !okb);
    }
    tv::check("formatted", saml::time_text(1767323045)[..] == "2026-01-02T03:04:05Z");
    tv::check("the epoch", saml::time_text(0)[..] == "1970-01-01T00:00:00Z");
    let back, okb = saml::parse_time(saml::time_text(4102444799));
    tv::check("round trip", okb && back == 4102444799);
    let id = saml::new_id();
    tv::check("an ID: _ and 40 hex digits", id.len == 41 && id[0] == '_' && xml::is_ncname(id));
    tv::check("IDs differ", saml::new_id()[..] != id[..]);
}

fn query_param(q: const u8[:], name: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    each_split(q, '&') {
        let k, v, has = split_once(it, '=');
        if k == name { out.append(v); }
    };
    return out;
}

fn redirect() {
    let none = saml::Signer { .. };
    let msg = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_x\"/>";
    var q: u8[>..] = [];
    tv::check_code("an unsigned query", saml::redirect_query(q, true, msg, "a b&c=d/é", none, false), saml::OK, "");
    var m = saml::Received { .. };
    tv::check_code("read back", saml::read_redirect(m, q, 1 << 20), saml::OK, m.message);
    tv::check("  the XML", m.xml[..] == msg && m.is_request && m.binding == saml::BINDING_REDIRECT);
    tv::check("  RelayState", m.has_relay_state && m.relay_state[..] == "a b&c=d/é");
    tv::check("  not signed", !saml::redirect_signed(m));
    // Signed, RSA and ECDSA.
    let sk, sc = tv::load("sp");
    var s = saml::Signer { has_key: true, key: sk, .. };
    s.cert_der.append(sc);
    let cert = tv::cert("sp");
    var sq: u8[>..] = [];
    tv::check_code("a signed query", saml::redirect_query(sq, true, msg, "state", s, true), saml::OK, "");
    tv::check("  SigAlg rsa-sha256", query_param(sq, "SigAlg")[..] == "http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256");
    tv::check("  the order: message, RelayState, SigAlg, Signature",
              find(sq, "SAMLRequest=") == 0 && find(sq, "&RelayState=") < find(sq, "&SigAlg=") && find(sq, "&SigAlg=") < find(sq, "&Signature="));
    tv::check_code("  read", saml::read_redirect(m, sq, 1 << 20), saml::OK, m.message);
    tv::check_code("  verified", saml::verify_redirect(m, cert, false), saml::OK, "");
    tv::check("  the signed octets", m.signed_octets[..] == sq[..find(sq, "&Signature=")]);
    let other = tv::cert("idp");
    tv::check_code("  with another certificate", saml::verify_redirect(m, other, false), saml::ERR_SIGNATURE, "");
    // The parameters in another order: the signed bytes are rebuilt in the binding's.
    let msgp = query_param(sq, "SAMLRequest");
    let rsp = query_param(sq, "RelayState");
    let sap = query_param(sq, "SigAlg");
    let sgp = query_param(sq, "Signature");
    let reordered = str("Signature=", sgp, "&foo=bar&SigAlg=", sap, "&RelayState=", rsp, "&SAMLRequest=", msgp);
    tv::check_code("reordered, with another parameter", saml::read_redirect(m, reordered, 1 << 20), saml::OK, m.message);
    tv::check_code("  verified", saml::verify_redirect(m, cert, false), saml::OK, "");
    // Tampering: each signed parameter, and RelayState dropped.
    let t1 = str("SAMLRequest=", msgp, "&RelayState=other&SigAlg=", sap, "&Signature=", sgp);
    saml::read_redirect(m, t1, 1 << 20);
    tv::check_code("another RelayState", saml::verify_redirect(m, cert, false), saml::ERR_SIGNATURE, "");
    let t2 = str("SAMLRequest=", msgp, "&SigAlg=", sap, "&Signature=", sgp);
    saml::read_redirect(m, t2, 1 << 20);
    tv::check_code("RelayState dropped", saml::verify_redirect(m, cert, false), saml::ERR_SIGNATURE, "");
    var q2: u8[>..] = [];
    saml::redirect_query(q2, true, "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_y\"/>", "", none, false);
    let t3 = str(q2, "&RelayState=", rsp, "&SigAlg=", sap, "&Signature=", sgp);
    saml::read_redirect(m, t3, 1 << 20);
    tv::check_code("another message", saml::verify_redirect(m, cert, false), saml::ERR_SIGNATURE, "");
    let t4 = str("SAMLRequest=", msgp, "&RelayState=", rsp, "&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512&Signature=", sgp);
    saml::read_redirect(m, t4, 1 << 20);
    tv::check_code("another SigAlg", saml::verify_redirect(m, cert, false), saml::ERR_SIGNATURE, "");
    // Signed over a lowercase percent-encoding (as ADFS sends): the bytes as they came verify.
    var lower: u8[>..] = [];
    lower.append("SAMLRequest=");
    lower.append(msgp);
    lower.append("&RelayState=a%2fb&SigAlg=");
    lower.append(sap);
    for i in lower.len { if i >= 2 && lower[i - 2] == '%' && lower[i] >= 'A' && lower[i] <= 'F' { lower[i] = lower[i] + 32; } }
    for i in lower.len { if i >= 1 && lower[i - 1] == '%' && lower[i] >= 'A' && lower[i] <= 'F' { lower[i] = lower[i] + 32; } }
    let lsig, lok = saml::sign_bytes(s, lower);
    var lb: u8[>..] = [];
    base64::encode(lb, lsig);
    var lq: u8[>..] = [];
    lq.append(lower);
    lq.append("&Signature=");
    http::query_escape(lq, lb);
    tv::check_code("a lowercase percent-encoding, read", saml::read_redirect(m, lq, 1 << 20), saml::OK, m.message);
    tv::check_code("  verified over the bytes as they came", saml::verify_redirect(m, cert, false), saml::OK, "");
    tv::check("  RelayState decoded", m.relay_state[..] == "a/b");
    // ECDSA.
    let pk, pc = tv::load("sp-p256");
    var ps = saml::Signer { has_key: true, key: pk, .. };
    ps.cert_der.append(pc);
    var eq: u8[>..] = [];
    tv::check_code("ECDSA P-256", saml::redirect_query(eq, false, msg, "", ps, true), saml::OK, "");
    saml::read_redirect(m, eq, 1 << 20);
    let pcert = tv::cert("sp-p256");
    tv::check_code("  verified", saml::verify_redirect(m, pcert, false), saml::OK, "");
    tv::check("  r || s", m.signature.len == 64 && !m.is_request);
    // ECDSA as DER (x509's form), as some senders give it: taken too.
    var dq: u8[>..] = [];
    dq.append(eq[..find(eq, "&Signature=")]);
    let dsig, dok = x509::sign(pk, x509::SIG_ECDSA, 256, dq);
    tv::check("  a DER ECDSA signature made", dok && dsig.len > 64 && dsig[0] == 0x30);
    var db: u8[>..] = [];
    base64::encode(db, dsig);
    dq.append("&Signature=");
    http::query_escape(dq, db);
    saml::read_redirect(m, dq, 1 << 20);
    tv::check_code("ECDSA as DER", saml::verify_redirect(m, pcert, false), saml::OK, "");
    var dbad: u8[>..] = [];
    dbad.append(dq);
    dbad.append("&RelayState=added");
    tv::check_code("  read with a RelayState added", saml::read_redirect(m, dbad, 1 << 20), saml::OK, m.message);
    tv::check_code("  then it does not verify", saml::verify_redirect(m, pcert, false), saml::ERR_SIGNATURE, "");
    // SHA-1: refused unless allowed.
    let sha1_uri = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    var sq1: u8[>..] = [];
    sq1.append("SAMLRequest=");
    sq1.append(msgp);
    sq1.append("&SigAlg=");
    http::query_escape(sq1, sha1_uri);
    let dg1 = bignum::hash_bits(160, sq1);
    let sig1, ok1 = bignum::rsa_sign_pkcs1_digest(sk.rsa, dg1, 160);
    tv::check("  an RSA-SHA1 signature made", ok1);
    var b1: u8[>..] = [];
    base64::encode(b1, sig1);
    sq1.append("&Signature=");
    http::query_escape(sq1, b1);
    saml::read_redirect(m, sq1, 1 << 20);
    tv::check_code("SigAlg rsa-sha1 refused", saml::verify_redirect(m, cert, false), saml::ERR_ALGORITHM, "");
    tv::check_code("  allowed with allow_sha1", saml::verify_redirect(m, cert, true), saml::OK, "");
    // Malformed queries.
    tv::check_code("no message", saml::read_redirect(m, "RelayState=x", 1 << 20), saml::ERR_BINDING, m.message);
    tv::check_code("SAMLRequest twice", saml::read_redirect(m, str(q, "&SAMLRequest=", msgp), 1 << 20), saml::ERR_BINDING, m.message);
    tv::check_code("SAMLRequest and SAMLResponse", saml::read_redirect(m, str(q, "&SAMLResponse=", msgp), 1 << 20), saml::ERR_BINDING, m.message);
    tv::check_code("SigAlg without Signature", saml::read_redirect(m, str("SAMLRequest=", msgp, "&SigAlg=", sap), 1 << 20), saml::ERR_BINDING, m.message);
    tv::check_code("Signature without SigAlg", saml::read_redirect(m, str("SAMLRequest=", msgp, "&Signature=", sgp), 1 << 20), saml::ERR_BINDING, m.message);
    tv::check_code("not base64", saml::read_redirect(m, "SAMLRequest=%21%21%21", 1 << 20), saml::ERR_BINDING, m.message);
    tv::check_code("bad percent-encoding", saml::read_redirect(m, "SAMLRequest=%zz", 1 << 20), saml::ERR_BINDING, m.message);
    var nd: u8[>..] = [];
    base64::encode(nd, msg);
    var ndq: u8[>..] = [];
    ndq.append("SAMLRequest=");
    http::query_escape(ndq, nd);
    tv::check_code("not DEFLATE (plain base64)", saml::read_redirect(m, ndq, 1 << 20), saml::ERR_BINDING, m.message);
    // A DEFLATE bomb: 16 MiB of "<" in a few KB.
    var bomb: u8[>..] = [];
    bomb.resize(16 << 20, '<');
    var z: u8[>..] = [];
    compress::deflate_encode(bomb, z, 9);
    var zb: u8[>..] = [];
    base64::encode(zb, z);
    var zq: u8[>..] = [];
    zq.append("SAMLRequest=");
    http::query_escape(zq, zb);
    tv::check("  the bomb is small", zq.len < 100000);
    tv::check_code("a DEFLATE bomb", saml::read_redirect(m, zq, 1 << 20), saml::ERR_LIMIT, m.message);
    tv::check("  nothing kept", m.xml.len == 0);
    var long_rs: u8[>..] = [];
    long_rs.resize(saml::MAX_RELAY_STATE + 1, 'a');
    tv::check_code("RelayState twice", saml::read_redirect(m, str(q, "&RelayState=", long_rs), 1 << 20), saml::ERR_BINDING, m.message);
    var long_q: u8[>..] = [];
    saml::redirect_query(long_q, true, msg, long_rs, none, false);
    tv::check_code("a RelayState over the limit, alone", saml::read_redirect(m, long_q, 1 << 20), saml::ERR_LIMIT, m.message);
    // Our escaping is Python's quote_plus and Go's QueryEscape.
    var esc: u8[>..] = [];
    http::query_escape(esc, "a b+c/d=e~f_g.h-i*j&k%l");
    tv::check("query escaping as quote_plus", esc[..] == "a+b%2Bc%2Fd%3De~f_g.h-i%2Aj%26k%25l");
    // A URL with a query of its own.
    var u: u8[>..] = [];
    saml::redirect_url(u, "https://idp.example.test/sso?tenant=1", true, msg, "", none, false);
    tv::check("a URL with a query: &", starts_with(u, "https://idp.example.test/sso?tenant=1&SAMLRequest="));
}

fn post() {
    let msg = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_r\"/>";
    var body: u8[>..] = [];
    saml::post_body(body, false, msg, "/app?x=1&y=2");
    var m = saml::Received { .. };
    tv::check_code("a POST body", saml::read_post(m, body, 1 << 20), saml::OK, m.message);
    tv::check("  read back", m.xml[..] == msg && !m.is_request && m.relay_state[..] == "/app?x=1&y=2" && m.binding == saml::BINDING_POST);
    // base64 with line breaks (CRLF, %0D%0A in the form).
    var b: u8[>..] = [];
    base64::encode(b, msg);
    var wrapped: u8[>..] = [];
    for i in b.len { wrapped.push(b[i]); if i % 20 == 19 { wrapped.append("\r\n"); } }
    var f: u8[>..] = [];
    http::form_add(f, "SAMLResponse", wrapped);
    tv::check_code("base64 with line breaks", saml::read_post(m, f, 1 << 20), saml::OK, m.message);
    tv::check("  read", m.xml[..] == msg && !m.has_relay_state);
    tv::check_code("SAMLResponse twice", saml::read_post(m, str(f, "&", f), 1 << 20), saml::ERR_BINDING, m.message);
    tv::check_code("no message", saml::read_post(m, "RelayState=x", 1 << 20), saml::ERR_BINDING, m.message);
    tv::check_code("over the limit", saml::read_post(m, body, 10), saml::ERR_LIMIT, m.message);
    // The form: escaped, and self-submitting.
    var page: u8[>..] = [];
    saml::post_form(page, "https://sp.example.test/acs?a=1&b=\"2\"", false, msg, "<script>x</script>");
    tv::check("the form's action escaped", find(page, "action=\"https://sp.example.test/acs?a=1&amp;b=&quot;2&quot;\"") >= 0);
    tv::check("RelayState escaped", find(page, "&lt;script&gt;x&lt;/script&gt;") >= 0 && find(page, "<script>") < 0);
    tv::check("the message", find(page, str("name=\"SAMLResponse\" value=\"", b, "\"")) >= 0);
    tv::check("submits itself", find(page, "onload=\"document.forms[0].submit()\"") >= 0);
}

fn metadata(sp: saml::Sp&, idp: saml::Idp&) {
    // The SP's, written and read back.
    var md: u8[>..] = [];
    tv::check_code("SP metadata written", saml::sp_metadata(sp, false, md), saml::OK, "");
    var e = saml::Entity { .. };
    tv::check_code("  read", saml::parse_metadata(e, md, ""), saml::OK, e.message);
    tv::check("  entityID", e.entity_id[..] == tv::SP_ID && e.is_sp && !e.is_idp);
    tv::check("  ACS", saml::endpoint_location(e, saml::ROLE_SP, saml::EP_ACS, saml::BINDING_POST) == tv::SP_ACS);
    tv::check("  SLO, both bindings", saml::endpoint_location(e, saml::ROLE_SP, saml::EP_SLO, saml::BINDING_REDIRECT) == tv::SP_SLO &&
              saml::endpoint_location(e, saml::ROLE_SP, saml::EP_SLO, saml::BINDING_POST) == tv::SP_SLO);
    tv::check("  certificates", e.sp_signing.len == 1 && e.sp_encryption.len == 1);
    tv::check("  encryption methods", e.encryption_methods.len == 4);
    tv::check("  no SSO", saml::endpoint_location(e, saml::ROLE_IDP, saml::EP_SSO, saml::BINDING_REDIRECT).len == 0);
    // The IdP's, signed.
    idp.want_authn_requests_signed = true;
    idp.name_id_formats.push(str(saml::NAMEID_EMAIL));
    var imd: u8[>..] = [];
    tv::check_code("IdP metadata, signed", saml::idp_metadata(idp, true, imd), saml::OK, "");
    idp.want_authn_requests_signed = false;
    let ic = tv::cert("idp");
    tv::check_code("  verified", saml::parse_metadata_signed(e, imd, "", ic, tv::NOW), saml::OK, e.message);
    tv::check("  read", e.signed && e.is_idp && e.want_authn_requests_signed && e.idp_signing.len == 1 && e.idp_name_id_formats.len == 1);
    tv::check("  SSO", saml::endpoint_location(e, saml::ROLE_IDP, saml::EP_SSO, saml::BINDING_REDIRECT) == tv::IDP_SSO);
    let sc = tv::cert("sp");
    tv::check_code("  with another certificate", saml::parse_metadata_signed(e, imd, "", sc, tv::NOW), saml::ERR_SIGNATURE, e.message);
    tv::check("  nothing kept", e.entity_id.len == 0 && e.endpoints.len == 0);
    var tampered: u8[>..] = [];
    format_replaced(tampered, imd, tv::IDP_SSO, "https://evil.example.test/sso");
    tv::check_code("  an endpoint changed", saml::parse_metadata_signed(e, tampered, "", ic, tv::NOW), saml::ERR_SIGNATURE, e.message);
    tv::check_code("  unsigned, when it must be", saml::parse_metadata_signed(e, md, "", ic, tv::NOW), saml::ERR_NOT_SIGNED, e.message);
    tv::check_code("  read unverified", saml::parse_metadata(e, imd, ""), saml::OK, e.message);
    // Wrapped: the signed EntityDescriptor inside an unsigned aggregate with an evil entity.
    let body = imd[find(imd, "?>") + 2..];
    let agg = str("<md:EntitiesDescriptor xmlns:md=\"", MDNS, "\"><md:EntityDescriptor entityID=\"", tv::IDP_ID,
                  "-evil\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:SingleSignOnService Binding=\"",
                  saml::URI_BINDING_REDIRECT, "\" Location=\"https://evil.example.test/sso\"/></md:IDPSSODescriptor></md:EntityDescriptor>",
                  body, "</md:EntitiesDescriptor>");
    tv::check_code("a signed entity in an unsigned aggregate", saml::parse_metadata_signed(e, agg, tv::IDP_ID, ic, tv::NOW), saml::ERR_NOT_SIGNED, e.message);
    tv::check_code("an aggregate, by entityID", saml::parse_metadata(e, agg, tv::IDP_ID), saml::OK, e.message);
    tv::check("  the right one", saml::endpoint_location(e, saml::ROLE_IDP, saml::EP_SSO, saml::BINDING_REDIRECT) == tv::IDP_SSO);
    tv::check_code("an aggregate, no entityID given", saml::parse_metadata(e, agg, ""), saml::ERR_MALFORMED, e.message);
    tv::check_code("an aggregate, an unknown entityID", saml::parse_metadata(e, agg, "https://nobody.example.test"), saml::ERR_MALFORMED, e.message);
    tv::check_code("an entity, another entityID asked for", saml::parse_metadata(e, md, tv::IDP_ID), saml::ERR_MALFORMED, e.message);
    // validUntil.
    var ent = saml::Entity { .. };
    saml::idp_entity(idp, ent);
    ent.valid_until = tv::NOW + 3600;
    var vmd: u8[>..] = [];
    saml::write_metadata_signed(ent, idp.signer, vmd);
    tv::check_code("validUntil ahead", saml::parse_metadata_signed(e, vmd, "", ic, tv::NOW), saml::OK, e.message);
    tv::check("  kept", e.valid_until == tv::NOW + 3600);
    tv::check_code("validUntil passed", saml::parse_metadata_signed(e, vmd, "", ic, tv::NOW + 3600), saml::ERR_EXPIRED, e.message);
    // Malformed.
    let head = str("<md:EntityDescriptor xmlns:md=\"", MDNS, "\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"https://x.example.test\">",
                   "<md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">");
    let tail = "</md:SPSSODescriptor></md:EntityDescriptor>";
    let acs = str("<md:AssertionConsumerService Binding=\"", saml::URI_BINDING_POST, "\" Location=\"https://x.example.test/acs\" index=\"0\"/>");
    tv::check_code("minimal", saml::parse_metadata(e, str(head, acs, tail), ""), saml::OK, e.message);
    tv::check_code("ACS without index", saml::parse_metadata(e, str(head, "<md:AssertionConsumerService Binding=\"b\" Location=\"https://x.example.test/l\"/>", tail), ""),
                   saml::ERR_MALFORMED, e.message);
    tv::check("  for that reason", find(e.message, "index") >= 0);
    // Locations: absolute http(s) only, no white space or control characters
    // (a javascript: form action on the IdP; CR LF into a Location header).
    for loc in ["javascript:alert(document.domain)//", "JAVASCRIPT:x", "data:text/html,x", "/acs", "acs", "https:///acs", "https://",
                "//x.example.test/acs", "https://x.example.test/a&#13;&#10;Set-Cookie: s=1", "https://x.example.test/a&#10;",
                "https://x.example.test/a b", "https://x.example.test/a&#9;", "https://x.example.test/&#127;"] {
        var le = saml::Entity { .. };
        let rc = saml::parse_metadata(le, str(head, "<md:AssertionConsumerService Binding=\"b\" index=\"0\" Location=\"", loc, "\"/>", tail), "");
        tv::check_code(str("  ACS Location ", loc), rc, saml::ERR_MALFORMED, le.message);
    }
    tv::check_code("  HTTP://, upper case, is taken",
                   saml::parse_metadata(e, str(head, "<md:AssertionConsumerService Binding=\"b\" index=\"0\" Location=\"HTTP://x.example.test/acs?a=b\"/>", tail), ""),
                   saml::OK, e.message);
    tv::check_code("  a bad SLO ResponseLocation",
                   saml::parse_metadata(e, str(head, "<md:SingleLogoutService Binding=\"b\" Location=\"https://x.example.test/slo\" ResponseLocation=\"javascript:x\"/>",
                                               acs, tail), ""),
                   saml::ERR_MALFORMED, e.message);
    var built = saml::Entity { .. };
    tv::check("add_endpoint refuses javascript:", !saml::add_endpoint(built, saml::ROLE_SP, saml::EP_ACS, saml::BINDING_POST, "javascript:x"));
    tv::check("  and CR LF", !saml::add_endpoint(built, saml::ROLE_SP, saml::EP_ACS, saml::BINDING_POST, "https://x.example.test/\r\nX: y"));
    tv::check("  and nothing added", built.endpoints.len == 0);
    var badsp = saml::Sp { .. };
    badsp.entity_id.append(tv::SP_ID);
    badsp.acs_url.append("javascript:alert(1)");
    var md2: u8[>..] = [];
    tv::check("sp_entity refuses a javascript: ACS", !saml::sp_entity(badsp, built));
    tv::check_code("  sp_metadata too", saml::sp_metadata(badsp, false, md2), saml::ERR_ENDPOINT, "");
    var badidp = saml::Idp { .. };
    badidp.entity_id.append(tv::IDP_ID);
    badidp.sso_url.append(tv::IDP_SSO);
    badidp.slo_url.append("https://idp.example.test/slo\r\nSet-Cookie: x=1");
    tv::check("idp_entity refuses CR LF in the SLO URL", !saml::idp_entity(badidp, built));
    tv::check_code("  idp_metadata too", saml::idp_metadata(badidp, false, md2), saml::ERR_ENDPOINT, "");
    tv::check("  a good one passes", saml::idp_entity(idp, built));
    // An endpoint written into an Entity by hand still never reaches a form or a URL.
    var user = saml::Login { .. };
    tv::alice(user);
    var spbad = saml::Entity { .. };
    saml::sp_entity(sp, spbad);
    spbad.endpoints[0].location.clear();
    spbad.endpoints[0].location.append("javascript:alert(document.domain)//");
    var uo = saml::Outgoing { .. };
    tv::check_code("an unsolicited response to a javascript: ACS", saml::idp_unsolicited_response(idp, spbad, user, "", uo), saml::ERR_ENDPOINT, "");
    tv::check("  no form", find(uo.form, "javascript") < 0);
    tv::check_code("no ACS", saml::parse_metadata(e, str(head, tail), ""), saml::ERR_MALFORMED, e.message);
    tv::check_code("a KeyDescriptor use other", saml::parse_metadata(e, str(head, "<md:KeyDescriptor use=\"both\"><ds:KeyInfo/></md:KeyDescriptor>", acs, tail), ""),
                   saml::ERR_MALFORMED, e.message);
    tv::check_code("a certificate that is not one",
                   saml::parse_metadata(e, str(head, "<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>", acs, tail), ""),
                   saml::ERR_MALFORMED, e.message);
    var longloc: u8[>..] = [];
    longloc.resize(3000, 'a');
    tv::check_code("a Location over 2048 bytes",
                   saml::parse_metadata(e, str(head, "<md:AssertionConsumerService Binding=\"b\" index=\"0\" Location=\"", longloc, "\"/>", tail), ""),
                   saml::ERR_LIMIT, e.message);
    tv::check_code("SAML 1.1 only", saml::parse_metadata(e, str("<md:EntityDescriptor xmlns:md=\"", MDNS,
                   "\" entityID=\"x\"><md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:1.1:protocol\">", acs, tail), ""),
                   saml::ERR_MALFORMED, e.message);
    tv::check_code("a DOCTYPE", saml::parse_metadata(e, str("<!DOCTYPE x>", head, acs, tail), ""), saml::ERR_MALFORMED, e.message);
    tv::check_code("not metadata", saml::parse_metadata(e, "<x/>", ""), saml::ERR_MALFORMED, e.message);
    // A KeyDescriptor without use is both; several ACS, the default one picked.
    let two = str(head, "<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>", b64(sp.signer.cert_der),
                  "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>",
                  "<md:AssertionConsumerService Binding=\"", saml::URI_BINDING_POST, "\" Location=\"https://x.example.test/a0\" index=\"0\"/>",
                  "<md:AssertionConsumerService Binding=\"", saml::URI_BINDING_POST, "\" Location=\"https://x.example.test/a1\" index=\"1\" isDefault=\"true\"/>",
                  "<md:AssertionConsumerService Binding=\"", saml::URI_BINDING_ARTIFACT, "\" Location=\"https://x.example.test/a2\" index=\"2\"/>", tail);
    tv::check_code("several ACS", saml::parse_metadata(e, two, ""), saml::OK, e.message);
    tv::check("  the default", saml::endpoint_location(e, saml::ROLE_SP, saml::EP_ACS, saml::BINDING_POST) == "https://x.example.test/a1");
    tv::check("  by index", saml::acs_by_index(e, 0) >= 0 && saml::acs_by_index(e, 2) >= 0 && saml::acs_by_index(e, 3) < 0);
    tv::check("  the other binding kept", e.endpoints.len == 3 && e.endpoints[2].binding == saml::BINDING_OTHER);
    tv::check("  one KeyDescriptor, both uses", e.sp_signing.len == 1 && e.sp_encryption.len == 1);
}

fn b64(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    base64::encode(out, b);
    return out;
}

fn main() {
    var sp = saml::Sp { .. };
    var idp = saml::Idp { .. };
    var spe = saml::Entity { .. };
    var idpe = saml::Entity { .. };
    tv::setup(sp, idp, spe, idpe);
    times();
    redirect();
    post();
    metadata(sp, idp);
    tv::done("bindings");
}
