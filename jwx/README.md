# jwx

JOSE for Goose, modelled on Go's
[lestrrat-go/jwx](https://github.com/lestrrat-go/jwx): JSON Web
Algorithms, Keys, Signatures, Encryption and Tokens.

| Module | Namespace | What | RFC |
|---|---|---|---|
| `jwx` | `jwx::` | error codes and messages, base64url (no padding, strict) | 7515 §2 |
| `jwx.jwa` | `jwa::` | algorithm, key type and curve identifiers, their names, what each needs | 7518, 8037, 9864 |
| `jwx.jwk` | `jwk::` | keys and key sets: parsing, writing, validation, thumbprints, generation | 7517, 7638, 8037 |
| `jwx.pem` | `jwk::` | keys from and to PEM and DER: private keys, public keys, certificates | 5280, 5208, 5915 |
| `jwx.jws` | `jws::` | signatures, compact and JSON (general and flattened), detached and unencoded payloads | 7515, 7797 |
| `jwx.jwe` | `jwe::` | encryption, compact and JSON, every key management and content algorithm of RFC 7518, `zip`, several recipients, AAD | 7516, 7518 |
| `jwx.jwt` | `jwt::` | claims, signed, encrypted and nested tokens, validation | 7519 |

Algorithms: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512,
EdDSA (and `Ed25519`), `none` by name only; RSA1_5, RSA-OAEP,
RSA-OAEP-256/384/512, A128/192/256KW, dir, ECDH-ES and ECDH-ES+A128/192/256KW
(P-256, P-384, P-521, X25519), A128/192/256GCMKW, PBES2-HS256+A128KW,
PBES2-HS384+A192KW, PBES2-HS512+A256KW; A128/192/256CBC-HS256/384/512,
A128/192/256GCM; `zip: DEF`. The cryptography is crypto/bignum's,
constant time where it handles secrets; AES Key Wrap (RFC 3394, 5649) was
added there for this, as `bignum.keywrap`.

## Using it

```goose
import gslib from "SorinS/gslib@v0.1";
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
for EC and OKP keys, `k` for oct keys, `rsa` (a `bignum::RsaPrivateKey`).

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
- `generate_rsa(bits)`, `generate_ec(crv)`, `generate_okp(crv)`,
  `generate_oct(len)`, `from_oct(bytes)`.
- jwx.pem: `from_pem(text)` (a private key in PKCS #8, SEC 1 or PKCS #1, a
  public key, or a certificate's), `from_spki(der)`, `from_cert(cert)`
  (with the certificate's `x5t` and `x5t#S256`), `from_private(x509key)`,
  `to_pem(k, public = false)`, `marshal_spki(k)`, `to_private(k)`.

### jws

- `sign(payload, alg, key)`: compact; the key's `kid` goes in the header.
  `sign_with(payload, key, header, extra = "", detached = false)` takes a
  `jws::Header` (`alg`, `kid`, `typ`, `cty`, `jku`, `jwk`, `x5u`, `x5t`,
  `x5t256`, `b64`, `crit`) and members of the caller's own (`extra`, JSON
  without braces). `sign_json(payload, signers, flattened = false)`: one
  signature per `jws::Signer` (key, protected header, unprotected members).
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
- `decrypt(message, alg, key, max_p2c = 10000, max_inflate = 10 MB)`: the
  plaintext for the first recipient whose `alg` is alg and which the key
  opens. `decrypt_set(message, keys, infer = false, ...)`.
- `parse(m&, message)` into a `jwe::Message`, `header_string(m, name)`,
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
  `parse_nested`: verify or decrypt, read the claims, then
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
P-521's 66 bytes, an `oct` key up to `jwk::MAX_OCT`, 512 bytes), so a key
set is a plain `jwk::Key[>..]` that can be indexed and sorted. Members a
key has beyond those RFC 7517 and RFC 7518 define, and `x5c`, are not kept:
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
does not understand (only `b64` is), `b64: false` without `crit`, an
ephemeral ECDH key off its curve (checked when the header is read, so no
invalid-curve point reaches the key agreement), PBES2 salts under 8 bytes.

**Limits.** As jwx: PBES2 counts above 10000 are refused when decrypting
(`ERR_LIMIT`; `max_p2c` raises it), and a `zip` payload may inflate to 10
MB (`max_inflate`). Encrypting uses a count of 10000 unless told otherwise.

## Examples

In gslib's `examples/jwx/`, run from gslib's top as `goose examples/jwx/<name>.goose`
(or from that folder); each checks its own results.

- `keys.goose`: JSON Web Keys: generating, JWK and PEM, thumbprints, key sets.
- `sign_verify.goose`: JWS compact and JSON, HS256, RS256, ES256 and EdDSA, and what is refused.
- `encrypt_decrypt.goose`: JWE with RSA-OAEP, ECDH-ES, AES key wrap, dir and PBES2, zip, several recipients.
- `jwt_tokens.goose`: a JWT issued, then verified against the issuer's JWKS and its claims validated.
- `nested_jwt.goose`: a JWT signed then encrypted, and opened, verified and validated in one call.

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
| pem | OpenSSL's RSA, P-256, P-384, P-521 and Ed25519 keys (scripts/gen_pem.sh): private, public and certificate give one key, x5t is OpenSSL's fingerprint, PEM written as OpenSSL writes it |
| go_jwx | 168 messages made by Go's lestrrat-go/jwx v3: every algorithm pair, compact and JSON, compressed or not |

`python3 scripts/differential.py -n N` (`make differential-jwx`, needs Go)
runs fresh keys both ways: Go's jwx makes N rounds of messages that
test/go_jwx.goose verifies and decrypts, and tools/tokens.goose makes as
many for Go's jwx to verify and decrypt.

The cookbook vectors are https://github.com/ietf-jose/cookbook (public
domain), copied as they are; `test/vectors/cookbook/SOURCE` names the
commit.

## Departures from Go's jwx

- Go's jwx writes a JSON JWE's `alg` in both the protected header and the
  recipient's, which RFC 7516 §7.2.1 forbids (the headers must be
  disjoint). This package reads such messages, a parameter in two headers
  being allowed when both hold the same value; different values are
  refused. It writes disjoint headers.
- Keys keep only the members RFC 7517 and RFC 7518 define (see Design).
- There is no automatic fetching of `jku` or `x5u` (no I/O in jwx), and no
  certificate chain checking of `x5c`: crypto/x509 does that for a caller
  who wants it.

## Not supported

Ed448 and X448, ES256K (no secp256k1 in bignum), the `oth` member of
multi-prime RSA keys, RSA private keys without their primes, and HMAC keys
longer than `MAX_OCT`.
