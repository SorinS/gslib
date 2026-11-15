// offline: a whole WebAuthn registration and sign-in in one process, the
// browser and the authenticator played by this program. The RP makes its
// options; a software authenticator (a P-256 key, packed self
// attestation) answers them as navigator.credentials.create() would; the
// RP verifies the response and keeps the credential record; then the
// same for a sign-in with the record, and a replay of that sign-in under
// a new challenge refused. Prints each step.
//
//   goose examples/webauthn/offline.goose

import std;
import gslib from "../..";
import gslib.webauthn;
import gslib.webauthn.register;
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.bignum;
import gslib.crypto.bignum.sha256;
import gslib.jwx;

let RP_ID = "example.org";
let ORIGIN = "https://example.org";

fn b64(b: const u8[:]) -> u8[>..] { jwx::b64_encode(b) }

fn client_data(ty: const u8[:], challenge: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    format(out, "{\"type\":\"", ty, "\",\"challenge\":\"", b64(challenge), "\",\"origin\":\"", ORIGIN, "\",\"crossOrigin\":false}");
    return out;
}

fn auth_data(flags: u8, count: i64, cred_id: const u8[:], cose_key: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(bignum::sha256(RP_ID));
    out.push(flags);
    for k in 4 { out.push((count >> (24 - 8 * k)) as! u8); }
    if cred_id.len > 0 {
        for i in 16 { out.push(0); }                         // AAGUID: none to tell
        out.push((cred_id.len >> 8) as! u8);
        out.push(cred_id.len as! u8);
        out.append(cred_id);
        out.append(cose_key);
    }
    return out;
}

fn main() {
    // The RP: its policy, and the options for a registration.
    var p = webauthn::Policy { .. };
    let ok1 = webauthn::set_rp(p, RP_ID);
    let ok2 = webauthn::add_origin(p, ORIGIN);
    var o = webauthn::RegistrationOptions { .. };
    o.rp_id.append(RP_ID);
    o.rp_name.append("Example");
    webauthn::new_random(o.user_id);
    o.user_name.append("alice@example.org");
    o.user_display_name.append("Alice");
    o.resident_key = webauthn::REQ_REQUIRED;
    let options, e0 = webauthn::registration_options(o, []);
    print("registration options:\n  ", options);

    // The authenticator: a new key, and a packed self attestation over
    // authData || SHA-256(clientDataJSON).
    let key = x509::generate_key(x509::KEY_EC_P256);
    var ck, ekey = cose::from_spki(x509::marshal_public_key(key));
    ck.alg = cose::ES256;
    let cred_id = "an example credential ID";
    let cdj = client_data("webauthn.create", o.challenge);
    let ad = auth_data(0x45, 0, cred_id, cose::encode(ck));       // UP, UV, AT
    var signed = copy(ad);
    signed.append(bignum::sha256(cdj));
    let sig, oks = x509::sign(key, x509::SIG_ECDSA, 256, signed);
    var ao: u8[>..] = [];
    cbor::put_map(ao, 3);
    cbor::put_text(ao, "fmt"); cbor::put_text(ao, "packed");
    cbor::put_text(ao, "attStmt");
    cbor::put_map(ao, 2);
    cbor::put_text(ao, "alg"); cbor::put_int(ao, cose::ES256);
    cbor::put_text(ao, "sig"); cbor::put_bytes(ao, sig);
    cbor::put_text(ao, "authData"); cbor::put_bytes(ao, ad);
    var response: u8[>..] = [];
    format(response, "{\"id\":\"", b64(cred_id), "\",\"rawId\":\"", b64(cred_id), "\",\"type\":\"public-key\",",
           "\"response\":{\"clientDataJSON\":\"", b64(cdj), "\",\"attestationObject\":\"", b64(ao), "\",\"transports\":[\"internal\"]},",
           "\"authenticatorAttachment\":\"platform\",\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");

    // The RP verifies it and keeps the record.
    var c = webauthn::Credential { .. };
    let e1 = webauthn::verify_registration(p, o.challenge, response, "", c);
    print("registration: ", webauthn::error_text(e1), c.message);
    if e1 != webauthn::OK { exit(1); }
    print("  ", webauthn::format_name(c.fmt), " attestation (", webauthn::attestation_type_name(c.attestation_type), "), ",
          cose::alg_name(c.alg), ", discoverable ", c.rk == 1, ", credential ID ", b64(c.id));
    let record = webauthn::marshal_credential(c);
    print("  the record to store: ", record.len, " bytes");

    // A sign-in: options without allowCredentials (a passkey), the
    // authenticator's assertion with the user handle, the RP's check.
    var ao2 = webauthn::AuthenticationOptions { .. };
    ao2.rp_id.append(RP_ID);
    let aopts, e2 = webauthn::authentication_options(ao2, []);
    print("authentication options:\n  ", aopts);
    let cdj2 = client_data("webauthn.get", ao2.challenge);
    let ad2 = auth_data(0x05, 1, "", "");                             // UP, UV, counter 1
    var signed2 = copy(ad2);
    signed2.append(bignum::sha256(cdj2));
    let sig2, oks2 = x509::sign(key, x509::SIG_ECDSA, 256, signed2);
    var assertion: u8[>..] = [];
    format(assertion, "{\"id\":\"", b64(cred_id), "\",\"rawId\":\"", b64(cred_id), "\",\"type\":\"public-key\",",
           "\"response\":{\"clientDataJSON\":\"", b64(cdj2), "\",\"authenticatorData\":\"", b64(ad2), "\",\"signature\":\"",
           b64(sig2), "\",\"userHandle\":\"", b64(o.user_id), "\"},\"clientExtensionResults\":{}}");
    // The RP finds the record by the credential ID, then checks.
    var id:     u8[>..] = [];
    var handle: u8[>..] = [];
    let e3 = webauthn::response_ids(assertion, id, handle);
    var stored = webauthn::Credential { .. };
    let e4 = webauthn::parse_credential(record, stored);
    var a = webauthn::Assertion { .. };
    let e5 = webauthn::verify_authentication(p, ao2.challenge, assertion, stored, o.user_id, true, a);
    print("sign-in: ", webauthn::error_text(e5), a.message, ", counter ", a.sign_count, ", user verified ", a.uv);
    if e5 != webauthn::OK { exit(1); }
    stored.sign_count = a.sign_count;

    // The same assertion again, for a new challenge: refused.
    var ao3 = webauthn::AuthenticationOptions { .. };
    ao3.rp_id.append(RP_ID);
    let aopts3, e6 = webauthn::authentication_options(ao3, []);
    var a2 = webauthn::Assertion { .. };
    let e7 = webauthn::verify_authentication(p, ao3.challenge, assertion, stored, o.user_id, true, a2);
    print("replayed: ", webauthn::error_text(e7), " (", a2.message, ")");
    if e7 == webauthn::OK { exit(1); }
}
