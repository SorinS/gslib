# cbor

CBOR (RFC 8949) for Goose, decoded strictly for data from strangers and
encoded deterministically, and COSE_Key public keys (RFC 9052, RFC 9053,
RFC 8230) with the signature algorithms WebAuthn and CTAP use. Two
modules: `encoding/cbor.goose` (namespace `cbor`) and
`encoding/cbor/cose.goose` (namespace `cose`), apart so that `cbor`
alone brings in no cryptography. WebAuthn (`webauthn`) is built on both.

| Module | What |
|---|---|
| `encoding/cbor.goose` | `decode`, `decode_at` into `Node`s, with `Options`; the readers (`as_i64`, `as_u64`, `as_bytes`, `as_text`, `string_into`, `as_f64`, `as_bool`, `as_tag`, `element`, `each`, `each_pair`, `map_get_int`, `map_get_text`, `raw`); the writers (`put_uint`, `put_int`, `put_negint`, `put_bytes`, `put_text`, `put_array`, `put_map`, `put_tag`, `put_bool`, `put_null`, `put_undefined`, `put_simple`, `put_float`, `put_double`); `sort_map`; `canonical`, `to_canonical`; `diag`; `valid_utf8` |
| `encoding/cbor/cose.goose` | `Key` (EC2 P-256/384/521, OKP Ed25519/Ed448, RSA to 8192 bits); `decode`, `decode_at`, `from_cbor`, `encode`, `validate`; `fits`, `verify`; `to_jwk`, `from_jwk`, `to_spki`, `from_spki`, `from_cert` (through `jwx` and `crypto/x509`); the algorithm names and ids |

### What the decoder takes

A decode fills a `Node[>..]`, one fixed-size `Node` per data item in the
order they appear, each holding its major type, its head's argument and
offsets into the caller's buffer (nothing is copied; a definite string is
a slice of the input). Children follow their parent; `count` and `next`
walk them. By default (`cbor::Options { .. }`):

- definite lengths only: an indefinite string, array or map is
  `ERR_INDEFINITE` unless `indefinite` is set; then chunks must be
  definite strings of the parent's type, and a map's items must pair up;
- no map with two equal keys, compared by value (their deterministic
  encodings), so `1` and `1` written in two bytes are the same key, and
  a key inside an indefinite string is joined first: `ERR_DUPLICATE_KEY`;
- text strings must be well-formed UTF-8 (no overlong forms, surrogates,
  or code points past U+10FFFF), chunk by chunk;
- the reserved additional information values 28 to 30, a break outside
  an indefinite container, an indefinite integer or tag, and a simple
  value below 32 in two bytes are `ERR_MALFORMED`;
- at most 16 levels of arrays, maps and tags (`max_depth`), 4096 items
  (`max_items`, chunks counted), 1 MiB from the item's start
  (`max_bytes`); a length or count longer than what is left of the input
  is `ERR_TRUNCATED` at once, before anything is read for it;
- `decode` refuses bytes after the item (`ERR_TRAILING`); `decode_at`
  says where the item ended (WebAuthn's authenticator data has a COSE key
  and then, maybe, an extensions map);
- `require_shortest` refuses heads longer than their value needs
  (`ERR_NOT_SHORTEST`), and `deterministic` anything that is not the core
  deterministic encoding of §4.2.1 (`ERR_NOT_DETERMINISTIC`): shortest
  heads, shortest floats that keep the value, definite lengths, map keys
  in the bytewise order of their encodings.

Tags are kept with the item they enclose and not interpreted: tag 2's
bignum is a tag around a byte string, tag 0's date a tag around text.

### What the encoder writes

The core deterministic encoding (§4.2.1): `put_*` write the shortest
head; `put_float` the shortest of half, single and double that holds the
value exactly (every NaN as half `7e00`, `-0.0` as `f98000`); `sort_map`
sorts the pairs of a map just written (its head at `out[at..]`) by their
keys' encodings, bytewise, or length-first as RFC 7049 §3.9 and CTAP2's
canonical form have it, and refuses two equal keys. `canonical`
re-encodes a decoded item deterministically, joining chunks and sorting
every map; `diag` writes RFC 8949 §8's diagnostic notation.

### COSE keys

`cose::decode` reads a COSE_Key map and checks it: kty 1 (OKP), 2 (EC2)
or 3 (RSA); EC2 on P-256, P-384 or P-521 with x and y at the curve's
length and the point on the curve (a y given as a bool, point
compression, is `ERR_UNSUPPORTED`); OKP on Ed25519 or Ed448 with a point
that decodes; RSA n and e without leading zeros, 2048 to 8192 bits by
default (`min_rsa_bits`); no private parts (d, RSA's d, p, q, ...:
`ERR_KEY`); an alg, when there, one this package knows
(`ERR_UNKNOWN_ALG` otherwise). Labels it does not use are ignored, as
RFC 9052 §7 asks; duplicate labels are the decoder's `ERR_DUPLICATE_KEY`.

`cose::verify(key, alg, msg, sig)` takes ES256, ES384, ES512 and RFC
9864's ESP256, ESP384, ESP512; EdDSA (either curve, by the key) and
Ed25519 and Ed448 by name; PS256, PS384, PS512 (salt as long as the
hash, RFC 8230); RS256, RS384, RS512; and RS1 only with `allow_sha1`
(`ERR_FORBIDDEN` otherwise). The algorithm must fit the key (ES256 is
P-256 only, Ed448 an Ed448 key, PS and RS an RSA key) and be the key's
own alg when it has one: `ERR_ALG_MISMATCH`. ECDSA signatures are DER,
as WebAuthn and X.509 have them, or r || s (COSE_Sign1's) with
`raw_ecdsa`.

## Using it

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;

var doc: cbor::Node[>..] = [];
let root, e = cbor::decode(bytes, cbor::Options { .. }, doc);
if e != cbor::OK { print(cbor::error_text(e)); return; }
let fmt, ok = cbor::as_text(bytes, doc, cbor::map_get_text(bytes, doc, root, "fmt"));
cbor::each_pair(doc, root) { k, v => /* ... */ };

var out: u8[>..] = [];
cbor::put_map(out, 2);
cbor::put_int(out, 3); cbor::put_int(out, -7);
cbor::put_int(out, 1); cbor::put_int(out, 2);
cbor::sort_map(out, 0);                     // {1: 2, 3: -7}

let key, ek = cose::decode(cose_key_bytes);
let ev = cose::verify(key, cose::ES256, signed, der_signature);
let spki, es = cose::to_spki(key);          // for crypto/x509
```

A `Node` array may be indexed (`doc[i]`); `element`, `map_get_int` and
`map_get_text` give an index or -1, which every reader takes (and
answers false for). `Options` is a small struct passed by value, so
`cbor::Options { indefinite: true, .. }` can be written at the call.

## Tools and examples

`encoding/cbor/tools/cbor.goose` shows CBOR from a file or stdin: `diag`
(diagnostic notation), `canonical` (the deterministic encoding, `--hex`
for text), `batch` (a line of hex in, `ok CANONICAL DIAG` or `err CODE`
out: the differential's), with `--hex-in`, `--indefinite`, `--shortest`,
`--deterministic`, `--length-first`, `--depth N`, `--items N`.

`examples/cbor/tour.goose`: a map written and sorted, the strict decoder
refusing a duplicate key, an indefinite array, bad UTF-8, a long head and
a cut item, and the WebAuthn spec's ES256 COSE key read and shown as a
SubjectPublicKeyInfo. With a file, its CBOR in diagnostic notation.

## Tests

`make test-cbor` (`python3 encoding/cbor/scripts/run_tests.py`) runs each
`test/*.goose` at -O0, -O2 and with `--debug`, and the example:

- `decode.goose` (739 checks): all 81 examples of RFC 8949 Appendix A
  (`test/data/appendix_a.txt`, checked against cbor2 when it was
  written) decoded with indefinite lengths allowed, shown in diagnostic
  notation exactly as the RFC has them, written again deterministically
  (as given there, or as the RFC's deterministic form of the same value),
  refused by the strict defaults exactly when indefinite, taken by
  `deterministic` exactly when already deterministic; every strict prefix
  of each one `ERR_TRUNCATED` and each one with a byte more
  `ERR_TRAILING`; and the hostile inputs: reserved additional
  information in all eight major types, breaks alone and in definite
  containers, indefinite integers and tags, two-byte simple values below
  32, chunks of the wrong type or indefinite, an odd indefinite map,
  lengths and counts past the input (up to 2^64-1), duplicate keys
  (integers, text, two forms of one integer, chunked text, floats of two
  widths, maps as keys in two orders, nested), malformed, overlong,
  surrogate and too-large UTF-8, depth, item and size limits, long heads,
  unsorted maps, non-shortest floats and NaN payloads.
- `encode.goose` (110 checks): integers at every head size and the ends
  of i64 and u64, floats at every width's edges (the half and single
  subnormals, 65504 and 65505, infinities, -0.0, NaNs), strings, arrays,
  tags and simple values, `sort_map` both ways and its errors,
  `to_canonical` from an indefinite, unsorted, non-shortest input, and
  the readers.
- `cose.goose` (365 checks): the WebAuthn spec's ES256 key read and
  written back byte for byte, and its §16.2 assertion verified; keys of
  every kind (P-256, P-384, P-521, Ed25519, Ed448, RSA 2048) through
  SubjectPublicKeyInfo, JWK and COSE and back, every algorithm signing
  (crypto/x509) and verifying, signatures changed, every other
  algorithm refused on each key; and hostile keys: private parts, a
  compressed point, a point off the curve, short coordinates, a P-256
  point labelled P-384, no kty, a symmetric key, kty as text, an unknown
  curve and alg, alg as text, a label twice, OKP with a y, an X25519 key,
  RSA with a leading zero, under a minimum, with d.

### Against cbor2

`make differential-cbor` (`encoding/cbor/scripts/differential.py -n
3000`, needing cbor2 in `CBOR_PYTHON`: `python3 -m venv /tmp/cborvenv &&
/tmp/cborvenv/bin/pip install cbor2`):

1. random values (integers of every size to -2^64, byte and text
   strings with characters of every UTF-8 length, floats from random
   bits, simple values, tags, nested arrays and maps), written by the
   script's own encoder in random non-deterministic forms (longer heads,
   indefinite lengths in random chunks, wider floats, maps shuffled),
   must decode and come back exactly as cbor2's `dumps(canonical=True)`
   writes the value (cbor2 sorts length-first: `--length-first`), and,
   bytewise, as the same with every map's pairs sorted by encoding;
2. the same encodings mutated (a byte changed, cut, inserted, or one of
   the bytes that start indefinite items or breaks put in) must be taken
   or refused by both, with the same value when taken.

3000 values and 3000 mutations: 9000 checks, none failed. Differences
that are rules cbor2 does not have are counted, not failed: duplicate
keys (cbor2 keeps the last) and cbor2's semantic tags (it decodes tags
0 to 5, 21 to 37, 256 to 270 and others by their content, and refuses
some; cbor passes every tag through).

## Quirks

- Map keys are compared, and the deterministic order computed, on each
  key's deterministic encoding: a map with many large keys costs a
  re-encoding of each. `max_items` bounds it.
- cbor2's `canonical=True` is RFC 7049's length-first order, not RFC
  8949's bytewise one (they differ when keys of different lengths
  compare the other way bytewise: `{10, -1, 100, "b", "aa"}`).
- A COSE key's alg -65535 (RS1) is a known algorithm, so the key reads,
  but `verify` refuses it unless asked (old TPMs sign attestations with
  it; no credential key should use it).

## Not done

- Indefinite-length items in what the encoder writes (it never needs
  them); streaming decoding (the item must be in memory).
- Tags interpreted (dates, bignums, decimal fractions, CBOR sequences
  in byte strings): the caller reads the enclosed item.
- COSE messages (COSE_Sign1, COSE_Encrypt, COSE_Mac) and COSE_Key for
  symmetric keys, X25519/X448 and ML-DSA (`AKP`).
- Preferred serialization that is not deterministic (unsorted maps with
  shortest heads) as an encoder mode.
