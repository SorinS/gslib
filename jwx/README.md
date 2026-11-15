# jwx

JOSE for Goose, modelled on Go's
[lestrrat-go/jwx](https://github.com/lestrrat-go/jwx): JSON Web
Algorithms, Keys, Signatures, Encryption and Tokens.

| Module | Namespace | What | RFC |
|---|---|---|---|
| `jwx` | `jwx::` | error codes and messages, base64url (no padding, strict) | 7515 §2 |
| `jwx.jwa` | `jwa::` | algorithm, key type and curve identifiers, their names, what each needs | 7518, 8037, 9864, 9964 |
| `jwx.jwk` | `jwk::` | keys and key sets: parsing, writing, validation, thumbprints, generation | 7517, 7638, 8037, 9964 |
| `jwx.pem` | `jwk::` | keys from and to PEM and DER: private keys, public keys, certificates | 5280, 5208, 5915, 8410, 9881 |
| `jwx.jws` | `jws::` | signatures, compact and JSON (general and flattened), detached and unencoded payloads | 7515, 7797, 9964 |
| `jwx.jwe` | `jwe::` | encryption, compact and JSON, every key management and content algorithm of RFC 7518, `zip`, several recipients, AAD | 7516, 7518 |
| `jwx.jwt` | `jwt::` | claims, signed, encrypted and nested tokens, validation | 7519 |

Algorithms: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512,
EdDSA on Ed25519 and Ed448 (and RFC 9864's `Ed25519` and `Ed448`),
ML-DSA-44/65/87 (post-quantum, with `AKP` keys),
`none` by name only; RSA1_5, RSA-OAEP,
RSA-OAEP-256/384/512, A128/192/256KW, dir, ECDH-ES and ECDH-ES+A128/192/256KW
(P-256, P-384, P-521, X25519, X448), A128/192/256GCMKW, PBES2-HS256+A128KW,
PBES2-HS384+A192KW, PBES2-HS512+A256KW; A128/192/256CBC-HS256/384/512,
A128/192/256GCM; `zip: DEF`. The cryptography is crypto/bignum's,
constant time where it handles secrets; AES Key Wrap (RFC 3394, 5649) was
added there for this, as `bignum.keywrap`.

## ML-DSA (post-quantum signatures)

RFC 9964 (ML-DSA for JOSE and COSE, May 2026; draft-ietf-cose-dilithium
until -11) brings FIPS 204's ML-DSA to JWS and JWT as `ML-DSA-44`,
`ML-DSA-65` and `ML-DSA-87`, with keys of a new type, `AKP` (Algorithm
Key Pair): `{"kty":"AKP","alg":"ML-DSA-65","pub":"...","priv":"..."}`,
where `alg` is required and names the algorithm, `pub` is the FIPS 204
public key (1312, 1952 or 2592 bytes) and `priv` the 32-byte seed the
private key is expanded from, never the expanded key. The signature is
ML-DSA's pure form with the empty context, 2420, 3309 or 4627 bytes; the
thumbprint is over `alg`, `kty` and `pub`. The signatures come from
crypto/bignum's ML-DSA (`bignum.mldsa`), hedged when signing.

```goose
let key = jwk::generate_akp(jwa::ML_DSA_65);    // or jwk::akp_from_seed(alg, seed)
let token, e = jwt::sign(claims, jwa::ML_DSA_65, key);
let pub = jwk::public_key(key);
let r = jwt::parse(token, jwa::ML_DSA_65, pub, got, validator);
```

An AKP key fits only the algorithm its `alg` names: an ML-DSA-44 key
neither signs nor verifies ML-DSA-65, EdDSA or anything else, and no other
key type does ML-DSA. A key whose `priv` does not give its `pub`, or whose
`pub` is the wrong length for its `alg`, is refused as RFC 9964 §7.3 and
§7.4 ask. RFC 9964 defines AKP keys for signatures only, so they are no
JWE key (`ERR_KEY`), and an `epk` must be an EC, X25519 or X448 key. In a key
set, an AKP key of an algorithm this package does not know (SLH-DSA, say)
is passed over as RFC 7517 §5 asks. PEM files carry ML-DSA keys as RFC
9881 has them; OpenSSL's seed-and-expanded PKCS #8 reads, and keys are
written seed-only, as OpenSSL writes with `ml-dsa.output_formats=seed-only`.
Go's lestrrat-go/jwx does ML-DSA from v4 with Go 1.27, and the two agree
both ways (see Tests).

## Ed448 and X448

RFC 8037's other two curves are OKP keys like Ed25519's and X25519's,
with longer members: `{"kty":"OKP","crv":"Ed448","x":"...","d":"..."}`
with a 57-byte public key and a 57-byte seed, `{"kty":"OKP","crv":"X448",
...}` with 56 bytes each; the thumbprint is over `crv`, `kty` and `x`.
Ed448 signs (114-byte signatures, RFC 8032's pure Ed448 with the empty
context) under RFC 8037's `EdDSA`, which names no curve, so the key
decides, and under RFC 9864's fully specified `Ed448`, which takes an
Ed448 key only; `Ed25519` takes an Ed25519 key only. X448 does ECDH-ES
and ECDH-ES+A128/192/256KW, its 56-byte Z through the Concat KDF as
X25519's, with the ephemeral key in `epk`; a peer key giving the all-zero
Z (RFC 7748 §6.2) is refused. The curves are crypto/bignum's
(`bignum.ed448`, `bignum.x448`), constant time on secrets.

```goose
let signer = jwk::generate_okp(jwa::CRV_ED448);   // or jwk::okp_from_private(crv, d)
let token, e = jwt::sign(claims, jwa::ED448, signer);
let service = jwk::generate_okp(jwa::CRV_X448);
let service_pub = jwk::public_key(service);
let msg, e2 = jwe::encrypt(secret, jwa::ECDH_ES_A256KW, jwa::A256GCM, service_pub);
```

Go's lestrrat-go/jwx v4 has both in extension modules
(`github.com/jwx-go/ed448/v4` and `github.com/jwx-go/x448/v4`, on
cloudflare/circl), and the two agree both ways (see Tests). It signs
Ed448 only under `Ed448`: an `EdDSA` token with an Ed448 key, which RFC
8037 allows and this package makes and verifies, Go's jwx neither makes
nor verifies, so `Ed448` is the name to use between the two.

Brainpool curves (crypto/bignum has brainpoolP256r1, P384r1 and P512r1)
have no JOSE identifiers: IANA's JOSE registries name no Brainpool curve
or algorithm, and Go's jwx v4 has none either, so they are not here.

## Using it

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.jwx.jwk;
import gslib.jwx.jws;
import gslib.jwx.jwt;

fn main() {
    // Sign and verify.
    let key = jwk::generate_ec(jwa::CRV_P256);
    let pub = jwk::public_key(key);
    let token, err = jws::sign("hello", jwa::ES256, key);
    let payload, err2 = jws::verify(token, jwa::ES256, pub);

    // A token, and its claims checked.
    var c = jwt::new_claims();
    c.iss.append("https://issuer.example");
    jwt::add_audience(c, "api");
    jwt::set_expiry(c, 2000000000);
    let t, e = jwt::sign(c, jwa::ES256, key);

    var got = jwt::new_claims();
    var v = jwt::Validator { .. };
    v.issuer.append("https://issuer.example");
    v.audience.append("api");
    if jwt::parse(t, jwa::ES256, pub, got, v) == jwx::OK { print(got.iss); }
}
```

Every fallible function returns a `jwx::ERR_*` code (`jwx::OK` is 0);
`jwx::error_text(e)` is its message.

## API

### jwk

`jwk::Key` is one key, of any type, as a fixed-size value: `kty` and `crv`
(`jwa::KTY_*`, `jwa::CRV_*`), `private`, `alg`, `key_use`, `key_ops`
(`jwk::OP_*` bits), `kid`, `x5t`, `x5t256`, and the material: `x`, `y`, `d`
for EC and OKP keys, `k` for oct keys, `rsa` (a `bignum::RsaPrivateKey`),
`pub` and `d` (the seed, "priv") for AKP keys, whose `alg` says which
ML-DSA they are.

- `parse(text)`, `from_node(node)`: a key from JWK JSON, checked: an EC
  point on its curve, a private part that gives the public one, an RSA key
  bignum accepts, CRT values that agree. `parse_set(text, keys&)` appends a
  set's keys, passing over keys of types this package does not do (RFC 7517
  §5). `lookup_kid(keys, kid)`.
- `marshal(k, private = true)`, `marshal_to(out, k, private)`,
  `marshal_set(keys, private)`: JSON, members in lexical order.
- `public_key(k)`, `validate(k)`, `fits(k, alg)` (the key's type, curve and
  own `alg` fit the algorithm), `strong_enough(k, alg)` (RFC 7518's
  minimum sizes: HMAC keys as long as the hash, RSA 2048 bits).
- `thumbprint(k, hash = 256)`, `thumbprint_b64(k)`: RFC 7638.
- `generate_rsa(bits)`, `generate_ec(crv)`, `generate_okp(crv)` (Ed25519,
  Ed448, X25519, X448), `generate_akp(alg)` (ML-DSA), `generate_oct(len)`,
  `from_oct(bytes)`, `akp_from_seed(alg, seed)`, `okp_from_private(crv, d)`
  and `okp_public(crv, d)`.
- jwx.pem: `from_pem(text)` (a private key in PKCS #8, SEC 1 or PKCS #1, a
  public key, or a certificate's; Ed448 and X448 keys as OKP JWKs, ML-DSA
  keys as AKP JWKs, brainpool keys `ERR_UNSUPPORTED`), `from_spki(der)`, `from_cert(cert)`
  (with the certificate's `x5t` and `x5t#S256`), `from_private(x509key)`,
  `to_pem(k, public = false)`, `marshal_spki(k)`, `to_private(k)`.

### jws

- `sign(payload, alg, key)`: compact; the key's `kid` goes in the header.
  `sign_with(payload, key, header, extra = "", detached = false)` takes a
  `jws::Header` (`alg`, `kid`, `typ`, `cty`, `jku`, `jwk`, `x5u`, `x5t`,
  `x5t256`, `b64`, `crit`) and members of the caller's own (`extra`, JSON
  without braces). `sign_json(payload, signers, flattened = false)`: one
  signature per `jws::Signer` (key, protected header, the protected header's own
  members in `extra`, as ACME's nonce and url, unprotected members).
- `verify(message, alg, key)`: the payload of a compact or JSON message
  that alg with key verifies (any one signature of several will do).
  `verify_detached(message, payload, alg, key)`. `verify_set(message,
  keys, infer = false)`: by `kid`, with each key's `alg`, or the header's
  when `infer` and the key fits it (jwx's `WithInferAlgorithmFromKey`).
- `parse(m&, message)` into a `jws::Message` (payload, signatures with
  their headers), `verify_signature(m, i, alg, key)`,
  `header_string(m, i, name)`, `header_int(m, i, name)`.
- `sign_bytes(input, alg, key)`, `verify_bytes(input, sig, alg, key)`:
  the signature algorithms alone.

### jwe

- `encrypt(plaintext, alg, enc, key, zip = false)`: compact, to the
  recipient's public key (or the shared key, or the password for PBES2).
  `encrypt_with(plaintext, key, header, extra = "")` takes a `jwe::Header`
  (`alg`, `enc`, `zip`, `kid`, `typ`, `cty`, `apu`, `apv`, ...);
  `encrypt_with_options` also takes `jwe::Options`: the CEK, IV, ephemeral
  key, GCM key-wrap IV and PBES2 salt and count it would otherwise choose.
- `encrypt_json(plaintext, shared, recipients, aad = "", flattened = false)`:
  one `jwe::Recipient` (alg, key, header) or several; `shared` holds `enc`
  and `zip`. `dir` and ECDH-ES (direct) take one recipient only.
- `decrypt(message, alg, key, max_p2c = 1000000, max_inflate = 10 MB,
  min_p2c = 1000, max_recipients = 16)`: the plaintext for the first
  recipient whose `alg` is alg and which the key opens.
  `decrypt_set(message, keys, infer = false, ...)`.
- `parse(m&, message, max_recipients = 16)` into a `jwe::Message`, `header_string(m, name)`,
  and the parts: `key_encrypt`, `key_decrypt`, `content_encrypt`,
  `content_decrypt`, `concat_kdf`, `aad_of`.

### jwt

- `jwt::Claims`: `iss`, `sub`, `jti`, the audiences (`add_audience`,
  `audiences`), `exp`, `nbf`, `iat` (`set_expiry`, `set_not_before`,
  `set_issued_at`, `has(c, CLAIM_* bits)`), and the caller's own
  (`set_string`, `set_int`, `set_raw`; `get_string`, `get_int`, `get_raw`).
- `sign(c, alg, key)`, `encrypt(c, alg, enc, key)`,
  `sign_encrypt(c, sig_alg, sign_key, alg, enc, enc_key)` (nested, `cty:
  JWT`); `marshal(c, flatten = false)`, `parse_claims(text, c&)`.
- `parse(token, alg, key, c&, v)`, `parse_set`, `parse_encrypted`,
  `parse_nested` (and `parse_insecure`): compact tokens only, as RFC 7519
  has them (a JSON JWS or JWE is `ERR_MALFORMED`); verify or decrypt, read
  the claims, then
  `validate(c, v)` with a `jwt::Validator`: `now` (0: the clock), `skew`,
  `issuer`, `subject`, `audience`, `jwt_id`, `max_age`, `required`
  (`CLAIM_*` bits), `validate` (false: skip). As jwx: a token is expired
  once now reaches exp + skew, not yet valid while now + skew is before nbf,
  and refused when iat is ahead of now + skew. `parse_insecure(token, c&)`
  reads claims without verifying.

## Design

**Algorithms are the caller's.** As in jwx, verifying and decrypting take
the algorithm the caller expects (or a key whose `alg` names it) and refuse
a message whose header says otherwise, so a token cannot pick its own: no
HMAC with an RSA public key as the secret (`ERR_ALG_MISMATCH`, and a key
of the wrong type is `ERR_KEY`), no `none` unless asked for by name.

**Keys are fixed-size values.** A `jwk::Key` holds its material inline (an
RSA key in bignum's limbs up to 8192 bits, EC and OKP coordinates up to
P-521's 66 bytes, an ML-DSA public key up to ML-DSA-87's 2592 bytes, an
`oct` key up to `jwk::MAX_OCT`, 512 bytes), so a key set is a plain
`jwk::Key[>..]` that can be indexed and sorted. Members a key has beyond
those RFC 7517, RFC 7518 and RFC 9964 define, and `x5c`, are not kept:
jwx keeps them, Goose's fixed-size structs cannot. `x5t` and `x5t#S256`
are.

**Signed and encrypted bytes are the received ones.** A JWS's signing input
and a JWE's additional authenticated data are made from the base64url text
of the protected header as it arrived, never from a re-serialized header.

**Uniform failures.** Every failure to unwrap a key or open a ciphertext is
`jwx::ERR_DECRYPT`, whatever went wrong; RSA1_5 continues with a random CEK
on bad padding (RFC 7516 §11.5), and RSA-OAEP's checks are bignum's,
constant time.

**Checks on what arrives.** JSON objects with a member twice are refused,
as are base64url with padding or stray bits, `crit` names this package
does not understand (only `b64` is), `crit` or JWE header names holding a
NUL, `b64: false` without `crit`, an ephemeral ECDH key off its curve
(checked when the header is read, so no invalid-curve point reaches the
key agreement), PBES2 salts under 8 bytes. An `aud` string is kept whole,
NUL or empty, and matched whole.

**Limits.** As jwx v4: PBES2 counts outside 1000 to 1000000 are refused
when decrypting (`ERR_LIMIT`; `min_p2c` and `max_p2c` move the bounds, and
`min_p2c = 0` drops the floor), and a `zip` payload may inflate to 10 MB
(`max_inflate`). The PBES2 counts of all the recipients tried share
`max_p2c`, a message may have at most 16 recipients (`max_recipients`),
and `decrypt_set` tries at most `keys.len + max_recipients` keys in all,
so a message costs at most about one PBES2 run at `max_p2c` and a
bounded number of RSA or ECDH operations (`ERR_LIMIT` past those);
a set of several passwords tried against one PBES2 recipient thus needs
`max_p2c` raised to their sum. Encrypting uses OWASP 2023's counts for PBKDF2, as v4
does, unless told otherwise: 600000 for PBES2-HS256+A128KW, 210000 for
PBES2-HS384+A192KW and PBES2-HS512+A256KW (`jwe::default_p2c(alg)`). At
those counts a password costs a fraction of a second to a few seconds per
message, so a service that decrypts PBES2 from untrusted senders should
rate-limit it, or lower `max_p2c`.

## Examples

In gslib's `examples/jwx/`, run from gslib's top as `goose examples/jwx/<name>.goose`
(or from that folder); each checks its own results.

- `keys.goose`: JSON Web Keys: generating, JWK and PEM, thumbprints, key sets.
- `sign_verify.goose`: JWS compact and JSON, HS256, RS256, ES256 and EdDSA, and what is refused.
- `encrypt_decrypt.goose`: JWE with RSA-OAEP, ECDH-ES, AES key wrap, dir and PBES2, zip, several recipients.
- `jwt_tokens.goose`: a JWT issued, then verified against the issuer's JWKS and its claims validated.
- `nested_jwt.goose`: a JWT signed then encrypted, and opened, verified and validated in one call.
- `ed448_x448.goose`: an Ed448 issuer key, its JWK and thumbprint, a JWT signed under `Ed448` and under `EdDSA`, the wrong alg and an Ed25519 key refused; a JWE to an X448 key by ECDH-ES+A256KW and ECDH-ES, and another X448 key refused.
- `mldsa_tokens.goose`: post-quantum JWTs: an ML-DSA-65 AKP key, its public JWK, thumbprint and PEM, RFC 9964's example key's kid, a JWT signed and verified through a JWKS, and a changed token, the wrong algorithm and the wrong key refused.

## Tests

`python3 scripts/run_tests.py` (or `make test-jwx`) runs every test/*.goose
at -O0, -O2 and `--debug`:

| Test | What |
|---|---|
| base64url | RFC 4648's vectors, every length, strict refusals; every jwa name |
| jwk | RFC 7517's keys, RFC 7638 §3.1's and RFC 8037 A.3's thumbprints, inconsistent keys refused, generated keys round-tripped, sets |
| jws | RFC 7520 §4 (the JOSE cookbook, test/vectors/cookbook) in every serialization, signatures remade byte for byte where deterministic (HMAC, PKCS #1 v1.5, Ed25519), RFC 7797, RFC 8037; every algorithm round-tripped; alg confusion, `none`, `crit` |
| jwe | RFC 7520 §5 in every serialization, decrypted, and remade byte for byte: 10 ciphertexts, and 8 encrypted keys (A*KW, A*GCMKW, PBES2, ECDH-ES from the example's ephemeral key); every key management algorithm with every content algorithm; three recipients; PBES2 and inflate limits; invalid-curve points |
| ecdh | RFC 7518 Appendix C: Z from both sides, the Concat KDF with apu and apv, the message; apu or apv changed in an unprotected header refused |
| jwt | RFC 7519 §3.1's token; exp, nbf, iat, iss, sub, aud, jti, max_age and required claims at their edges and with skew; nested and encrypted tokens |
| pem | OpenSSL's RSA, P-256, P-384, P-521, Ed25519, Ed448 and ML-DSA-44/65/87 keys (scripts/gen_pem.sh): private, public and certificate give one key, x5t is OpenSSL's fingerprint, PEM written as OpenSSL writes it (ML-DSA's private key as its seed-only form); OpenSSL's X448 key and public key likewise, and its brainpoolP256r1 key, public key and certificate refused |
| mldsa | RFC 9964 Appendix A.1 (test/vectors/rfc9964): the three keys' kids as thumbprints, the signatures remade byte for byte (they are FIPS 204's deterministic variant) and verified; inconsistent AKP keys refused; every ML-DSA signing and verifying, compact and JSON, and in a JWT; alg and key-type confusion both ways; AKP keys refused for JWE |
| okp448 | RFC 8037 A.7 (ECDH-ES with X448): the keys, Z from both sides, the appendix's header's message; Ed448: a JWS made by Go's jwx with RFC 8032's key remade byte for byte, its thumbprint as Go's; `EdDSA`, `Ed25519` and `Ed448` against Ed25519, Ed448 and X448 keys both ways; Ed448 and X448 JWKs of the wrong lengths or inconsistent refused; X448 with every ECDH-ES algorithm and content algorithm, low-order peers and an Ed448 `epk` refused |
| go_jwx | 176 messages made by Go's lestrrat-go/jwx v4: every algorithm pair, Ed448, X448 and ML-DSA too, compact and JSON, compressed or not |

`python3 scripts/differential.py -n N` (`make differential-jwx`, needs Go)
(Go 1.27 or later, for crypto/mldsa) runs fresh keys both ways: Go's jwx
v4.6.0, with its Ed448 and X448 extension modules (jwx-go/ed448 and
jwx-go/x448 v4.0.5), makes N rounds of messages that
test/go_jwx.goose verifies and decrypts, and tools/tokens.goose makes as
many for Go's jwx to verify and decrypt.

The cookbook vectors are https://github.com/ietf-jose/cookbook (public
domain), copied as they are; `test/vectors/cookbook/SOURCE` names the
commit. `test/vectors/rfc9964/SOURCE` says where the ML-DSA ones are from.

## Departures from Go's jwx

- Go's jwx v3 (not v4) writes a JSON JWE's `alg` in both the protected
  header and the recipient's, which RFC 7516 §7.2.1 forbids (the headers
  must be disjoint). This package reads such messages, a parameter in two
  headers being allowed when both hold the same value; different values
  are refused. It writes disjoint headers.
- Keys keep only the members RFC 7517, RFC 7518 and RFC 9964 define (see
  Design).
- There is no automatic fetching of `jku` or `x5u` (no I/O in jwx), and no
  certificate chain checking of `x5c`: crypto/x509 does that for a caller
  who wants it.

## Not supported

Brainpool curves (no JOSE identifiers), Ed448ph and Ed448 contexts
(RFC 8037 has neither), ES256K (no secp256k1 in bignum), the `oth` member
of multi-prime RSA keys, RSA private keys without their primes, and HMAC keys
longer than `MAX_OCT`. Of ML-DSA: HashML-DSA (RFC 9964 §7.2 leaves it
out), contexts (RFC 9964's is always empty), expanded private keys in
JWKs (RFC 9964 §4 allows the seed only; a PKCS #8 key with no seed is
refused), and AKP keys for algorithms other than ML-DSA (SLH-DSA has no
JOSE registration yet). COSE is not in this package.
