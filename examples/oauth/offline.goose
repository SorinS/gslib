// offline: what an OAuth client makes and checks, with no server. An
// authorization request with PKCE (RFC 7636) and the code challenge it
// carries; the redirect back, its state checked; a DPoP proof (RFC 9449)
// for the token request, checked as the server would; and an ID token,
// signed here by a stand-in for the issuer's key, validated as OpenID
// Connect Core §3.1.3.7 asks: signature, iss, aud, nonce, exp, at_hash.
//
//   goose examples/oauth/offline.goose

import std;
import gslib from "../..";
import gslib.oauth;
import gslib.oauth.oidc;
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.net.http.client;

fn main() {
    var c = oauth::Client { .. };
    let meta, ok = oauth::read_metadata("{\"issuer\":\"https://login.example.test\",\"authorization_endpoint\":\"https://login.example.test/authorize\",\"token_endpoint\":\"https://login.example.test/token\"}");
    assert(ok);
    c.meta = meta;
    assert(oauth::set_public(c, "native-app") == oauth::OK);

    // The authorization request: state, nonce and a PKCE verifier, kept until the redirect.
    let ar, arerr = oauth::new_auth_request(c, "http://127.0.0.1:8400/callback", "openid email");
    assert(arerr == oauth::OK);
    print("send the user to:\n  ", oauth::authorization_url(c, ar));
    print("code_challenge = base64url(SHA-256(verifier)) = ", oauth::pkce_challenge(ar.verifier));

    // The redirect back: the state must be ours.
    let code, err = oauth::parse_callback(c, ar, str("/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=", ar.state));
    assert(err == oauth::OK);
    print("code from the redirect: ", code);
    let forged, ferr = oauth::parse_callback(c, ar, "/callback?code=x&state=someone-elses");
    assert(ferr == oauth::ERR_STATE);
    print("a redirect with another state: ", oauth::error_text(ferr));

    // DPoP: the proof that goes with the token request, as the server checks it.
    let dk = jwk::generate_ec(jwa::CRV_P256);
    assert(oauth::set_dpop_key(c, dk) == oauth::OK);
    let proof, perr = oauth::dpop_proof(c.dpop_key, c.dpop_alg, "POST", "https://login.example.test/token");
    assert(perr == oauth::OK);
    let p, verr = oauth::verify_dpop_proof(c, proof, "POST", "https://login.example.test/token");
    assert(verr == oauth::OK && p.jkt == jwk::thumbprint_b64(dk));
    print("DPoP proof: ", proof.len, " bytes, key thumbprint ", p.jkt);

    // The ID token: signed here by the "issuer", validated by the client against its key set.
    var issuer_key = jwk::generate_ec(jwa::CRV_P256);
    issuer_key.kid.append("op-1");
    var set: jwk::Key[>..] = [];
    set.push(jwk::public_key(issuer_key));
    assert(oauth::set_keys(c, jwk::marshal_set(set, false)) == oauth::OK);
    let access_token = "an access token from the same response";
    let now = time_ns() / 1000000000;
    let claims = str("{\"iss\":\"https://login.example.test\",\"sub\":\"alice\",\"aud\":\"native-app\",\"exp\":", now + 300,
                     ",\"iat\":", now, ",\"nonce\":\"", ar.nonce, "\",\"at_hash\":\"", oauth::token_hash(jwa::ES256, access_token),
                     "\",\"email\":\"alice@example.test\"}");
    var h = jws::Header { .. };
    h.alg = jwa::ES256;
    h.kid.append("op-1");
    let id_token, serr = jws::sign_with(claims, issuer_key, h);
    assert(serr == jwx::OK);
    var hc = http::Client { .. };
    let id, ierr = oauth::validate_id_token(c, hc, id_token, ar.nonce, access_token);
    assert(ierr == oauth::OK);
    let email, has = oauth::claim_string(id.claims, "email");
    print("ID token valid: sub ", id.sub, ", email ", email);
    let replay, rerr = oauth::validate_id_token(c, hc, id_token, "another request's nonce", access_token);
    assert(rerr == oauth::ERR_NONCE);
    print("the same token for another request: ", oauth::error_text(rerr));
}
