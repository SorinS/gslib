# xml

XML for Goose, built for documents that carry signatures and come from
strangers: SAML's above all. A parser into a document of numbered nodes, a
builder and a writer (`encoding/xml.goose`, namespace `xml`), and three
modules on it, in the same namespace:

| Module | What |
|---|---|
| `encoding.xml` | XML 1.0 (fifth edition) and Namespaces 1.0: `parse`, `parse_fragment`; the document's nodes and their accessors; IDs (`by_id`); the builder; `write` |
| `encoding.xml.c14n` | Canonical XML 1.0 and 1.1, Exclusive XML Canonicalization 1.0 (with and without comments, InclusiveNamespaces PrefixList), of a document or of an element's subtree, a subtree left out |
| `encoding.xml.dsig` | XML Signature 1.1: enveloped signatures over same-document references, signed and verified against wrapping; RSA PKCS #1 v1.5 and PSS, ECDSA, Ed25519 |
| `encoding.xml.enc` | XML Encryption 1.1: EncryptedData and EncryptedKey, AES-GCM (and AES-CBC to decrypt), RSA-OAEP (and RSA PKCS #1 v1.5 to decrypt), ECDH-ES with ConcatKDF and AES key wrap |

Keys and certificates are gslib's `x509` (`x509::PrivateKey`,
`x509::Cert`), the cryptography `crypto/bignum`'s.

## The parser

Security first, then the spec:

- **No DTDs.** A DOCTYPE is an error (`ERR_DOCTYPE`). With
  `Options.allow_doctype` one without an internal subset is let through and
  ignored; its external subset is never read, and an internal subset is
  still an error. No entity is ever declared, so none is expanded or
  fetched: no XXE, no billion laughs. Only `&lt; &gt; &amp; &apos; &quot;`
  and character references (to a legal character) are read; any other
  reference is `ERR_ENTITY`.
- **Limits**, each an error (`ERR_LIMIT`), never a cut: `max_size` bytes
  of input (16 MiB), `max_depth` elements open (256), `max_attrs`
  attributes and declarations on one element (64), `max_name` bytes of a
  name (1024), `max_nodes` nodes (2^20), `max_namespaces` declarations in
  scope at once (256). Canonicalization takes linear time in the
  document: each element below a subset's apex looks only at its own
  declarations, which matters because SignedInfo is canonicalized, by the
  method the document names, before its signature can be checked.
- **Well-formed, strictly:** UTF-8 only (a UTF-8 BOM is passed over, a
  UTF-16 one or another declared encoding is `ERR_ENCODING`; a document
  declared US-ASCII must be ASCII, as libxml2 has it), every
  character legal (`ERR_CHAR`, also for overlong UTF-8, surrogates,
  `&#0;`), names, one root element, matched tags (`ERR_TAG`), no text
  outside the root, `--` not in comments, `]]>` not in text, the XML
  declaration only first and only version 1.0.
- **Namespaces 1.0:** every prefix bound, `xmlns:p=""` refused, `xml` and
  `xmlns` and their namespaces reserved, a namespace URI with white space
  in it refused, for a URI reference has none (`xmlns:p=" "`; libxml2
  refuses these too) (`ERR_NAMESPACE`); an attribute
  twice is `ERR_DUP_ATTR` by its name and also by namespace and local
  name, so `p:a` and `q:a` with p and q bound to one namespace are refused.
- **Normalized as the spec says:** line ends (CR LF and CR to LF) in
  content, and attribute values (white space to spaces; every attribute
  is CDATA, there being no DTD).
- **IDs:** the unprefixed attributes named in `Options.id_attrs` (`ID Id
  id`, separated by single spaces) and `xml:id` are IDs, and a value seen
  twice in a document is `ERR_DUP_ID` (`Options.unique_ids`, on by
  default): an attacker's second element with the signed element's ID
  never reaches the signature code. `by_id` returns the element and how
  many attached elements have the ID, to trust only a count of 1. The
  builder's `set_attr` marks `ID`, `Id`, `id` and `xml:id` as IDs, by the
  default list.

An error says what and where: `Error { code, offset, line, column, message }`.

## Using it

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.encoding.xml;
import gslib.encoding.xml.dsig;
import gslib.encoding.xml.enc;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;

var d = xml::Doc { .. };                       // a root struct: a local
let e = xml::parse(d, text);                   // or xml::parse(d, text, o) with xml::Options
if e.code != xml::OK { print(e.message); return; }

// The service provider: decrypt the assertion in place, then verify it
// with the IdP's certificate, from metadata (not from KeyInfo).
var eds: i64[>..<] = [];
xml::find_encrypted(d, eds);
for ed in eds { if xml::decrypt_replace(d, ed, sp_key) != xml::OK { return; } }
let a, count = xml::by_id(d, assertion_id);    // or walk to it: root_element, child, ...
let v = xml::verify_enveloped(d, a, idp_cert); // its own Signature child, over itself
if v.code != xml::OK { print(v.message); return; }
// Read only what v says was signed.
let nid = xml::child(d, xml::child(d, v.refs[0], SAML, "Subject"), SAML, "NameID");
assert(xml::is_signed(d, v, nid));
```

The identity provider's side:

```goose
let sig, err = xml::sign_enveloped(d, assertion, after_issuer, idp_key, idp_cert.der);
let ed, eerr = xml::encrypt_element(d, assertion, sp_cert);   // AES-256-GCM, RSA-OAEP or ECDH-ES
var out: u8[>..] = [];
xml::write_document(d, out);
```

### The document

A `Doc` is a root struct of nodes (`Node[>..]`) and the text they point
into; a node is an index, -1 for none, the document node 0. Kinds:
`DOCUMENT ELEMENT ATTRIBUTE NAMESPACE TEXT CDATA COMMENT PI`. An element's
attributes and namespace declarations are a chain of their own, in the
order written.

```goose
fn parse(d: Doc&, text: const u8[:], o: const Options&) -> Error
fn parse(d: Doc&, text: const u8[:]) -> Error
fn parse_fragment(d: Doc&, parent: i64, before: i64, text: const u8[:], o: const Options&) -> Error
fn kind(d, n) -> u8        fn parent(d, n) -> i64       fn first_child(d, n) -> i64   fn next_sibling(d, n) -> i64
fn local_name(d, n)        fn prefix(d, n)              fn ns_uri(d, n)               fn value(d, n)   // const u8[:]
fn root_element(d) -> i64  fn first_element(d, n)       fn next_element(d, n)         fn child(d, el, ns, local) -> i64
fn is(d, n, ns, local) -> bool                          fn count_children(d, el, ns, local) -> i64
fn attr(d, el, ns, local) -> const u8[:], bool          fn attr(d, el, local) -> const u8[:], bool
fn each_element<F>(d, el)  fn each_attr<F>(d, el)       fn walk<F>(d, n)    // F(node, entering) -> bool: go in
fn text_content(d, el, out: u8[>..]&)                   fn lookup_ns(d, el, prefix) -> const u8[:], bool
fn by_id(d, id) -> i64, i64        // the element, and how many have the ID
fn id_of(d, el) -> const u8[:], bool                    fn within(d, a, n) -> bool   fn attached(d, n) -> bool
```

The builder (each returns -1 or false for names, characters or places XML
cannot have, and declares a prefix where its scope does not bind it):

```goose
fn new_document(d: Doc&)
fn element(d, parent, prefix, local, ns) -> i64             fn insert_element(d, parent, before, prefix, local, ns) -> i64
fn set_attr(d, el, prefix, local, ns, value) -> bool        fn set_attr(d, el, local, value) -> bool
fn declare_ns(d, el, prefix, uri) -> bool                   fn text(d, parent, value) -> i64
fn comment(d, parent, value) -> i64     fn pi(d, parent, target, data) -> i64    fn set_text(d, el, value) -> bool
fn detach(d, n)                         fn move_to(d, n, parent, before) -> bool
fn write(d, n, out: u8[>..]&)           fn write_document(d, out: u8[>..]&)    // with the XML declaration
```

`set_attr` refuses an unprefixed attribute named `xmlns` (a declaration
is `declare_ns`), and `declare_ns` (also as `set_attr` calls it for a
prefixed attribute) refuses a binding that would change the namespace of
the element, of one of its attributes or of something in its subtree
with that prefix (a descendant that declares the prefix itself is not
told apart, and refused too): what is built is what parses back.
`move_to` keeps a moved element's namespaces the same way: where its new
scope binds a prefix it uses (or the default namespace) otherwise, or
not at all, the element declares it, as `insert_element` does.
`write` of a subtree declares the namespaces its ancestors bound, so it
parses on its own; escaping keeps every character the parser would
normalize (`&#x9;`, `&#xA;`, `&#xD;` in attributes, `&#xD;` in text), so
what is written parses back to the same document.

### Canonicalization

```goose
struct C14n { method: i64 = EXC_C14N, comments: bool = false, inclusive: u8[..1024], exclude: i64 = -1 }
fn canonicalize(d: const Doc&, n: i64, m: const C14n&, out: u8[>..]&) -> bool   // n 0: the document
fn c14n_uri(method, comments) -> const u8[:]     fn c14n_of_uri(uri) -> i64, bool, bool
```

`method` is `C14N_10`, `C14N_11` or `EXC_C14N`; `inclusive` is the
PrefixList (`#default` for the default namespace); `exclude` a subtree
left out, which is how the enveloped-signature transform works. The
subtree of an element is a document subset as XPath selects it: its
namespace axis holds every namespace in scope; Canonical XML 1.0 carries
the ancestors' xml: attributes onto it, 1.1 only xml:lang and xml:space,
and joins the xml:base values into it (RFC 3986 with 1.1's change to keep
leading `..`); exclusive canonicalization carries none.

### Signatures

```goose
fn verify(d: const Doc&, sig: i64, cert: const x509::Cert&, o: const VerifyOptions&) -> Verified
fn verify_enveloped(d: const Doc&, el: i64, cert: const x509::Cert&, o: const VerifyOptions&) -> Verified
fn is_signed(d, v: const Verified&, n: i64) -> bool
fn keyinfo_cert(d, sig) -> u8[>..], bool            // DER, to compare with what you trust
fn find_signatures(d, out: i64[>..<]&)
fn sign_enveloped(d: Doc&, el: i64, before: i64, key: const x509::PrivateKey&, cert_der: const u8[:],
                  o: const SignOptions&) -> i64, i64     // the Signature, OK or an error
fn sig_of_uri(uri: const u8[:], allow_sha1: bool) -> i64, i64  // SignatureMethod URI to x509 alg and hash (x509::SIG_UNKNOWN if refused)
fn sig_uri(alg: i64, h: i64) -> const u8[:]         // and back; "" for none
fn verify_value(cert: const x509::Cert&, alg: i64, h: i64, msg: const u8[:], sig: const u8[:],
                o: const VerifyOptions&) -> i64      // a raw signature as XML-DSig encodes it (ECDSA r||s), OK or an error
struct VerifyOptions { allow_sha1 = false, max_references = 4, min_rsa_bits = 2048 }
struct SignOptions { alg = 0 (the key's), hash = 256, digest = 256, c14n = EXC_C14N, inclusive, prefix = "ds", include_cert = true }
struct Verified { code, message, refs: i64[..16], signature }
```

Verification is built against signature wrapping (Somorovsky et al., "On
Breaking SAML", 2012):

- It verifies the one Signature it is given, with a certificate the
  caller trusts; KeyInfo is never used to verify (`keyinfo_cert` hands
  its certificate over to be matched or path-checked).
- The Signature is read strictly: ds: elements in the order the schema
  has, no stray text, no unknown attributes or children (`ERR_DSIG_MALFORMED`).
- SignatureMethod is from a fixed list (`ERR_DSIG_ALGORITHM` for HMAC, for
  SHA-1 without `allow_sha1`, for anything else); the SignatureValue over
  SignedInfo is checked before any Reference is looked at.
- A Reference URI is `""` (the document) or `#` and an NCName that exactly
  one element of the document has as an ID (`ERR_DSIG_REFERENCE`,
  `ERR_DSIG_ID`); XPointer, other documents and a missing URI are refused.
  Each is resolved once, and that node is what is digested and returned.
- Transforms are enveloped-signature and then one canonicalization, both
  optional, nothing else (`ERR_DSIG_TRANSFORM`: no XPath, no XSLT, no
  Base64, no second canonicalization).
- `Verified.refs` is the node of each Reference: what was signed is its
  subtree (less the Signature, when inside it). Read from those nodes;
  `is_signed` says whether a node is in one, and never for a node inside
  the Signature itself (a ds:Object is not signed content).
- `verify_enveloped(d, el, …)` is SAML's check: el has exactly one
  ds:Signature child, with exactly one Reference, which is el (by its ID,
  or `""` when el is the document element). A signature moved into an evil
  element, a Reference to a sibling and a second Signature are each
  `ERR_DSIG_WRAPPING`.

Signature methods: RSA PKCS #1 v1.5 (`rsa-sha256`, `-384`, `-512`),
RSA-PSS (`sha256-rsa-MGF1`, `-384`, `-512`; salt as long as the hash, RFC
9231), ECDSA on P-256, P-384, P-521 (`ecdsa-sha256`, `-384`, `-512`; r ||
s), Ed25519 (`eddsa-ed25519`, RFC 9231); `rsa-sha1` and `ecdsa-sha1` to
verify with `allow_sha1`. Digests SHA-256, -384, -512 (SHA-1 to verify
with `allow_sha1`). An RSA key under `min_rsa_bits` (2048) is
`ERR_DSIG_KEY`. Same-document references drop comments (XML Signature
§4.4.3.3), whatever the canonicalization says.

### Encryption

```goose
fn decrypt(d: const Doc&, ed: i64, key: const x509::PrivateKey&, o: const DecryptOptions&) -> u8[>..], i64
fn decrypt_replace(d: Doc&, ed: i64, key: const x509::PrivateKey&, o: const DecryptOptions&) -> i64
fn encrypt_element(d: Doc&, el: i64, cert: const x509::Cert&, o: const EncryptOptions&) -> i64, i64
fn find_encrypted(d, out: i64[>..<]&)
struct DecryptOptions { allow_cbc = false, allow_rsa15 = false, min_rsa_bits = 2048, max_keys = 4, parse: Options }
struct EncryptOptions { alg = ENC_AES256_GCM, key_alg = 0 (by the key), oaep_digest, oaep_mgf, kw = 256, kdf_digest = 256, prefix, ds_prefix }
```

The key of an EncryptedData is found in its KeyInfo (an EncryptedKey, or
a RetrievalMethod naming one by ID), or beside it (SAML's
EncryptedAssertion holds EncryptedKeys next to the EncryptedData).
At most `max_keys` (4) EncryptedKeys are tried, each an RSA or ECDH
operation made before any signature can be checked; more is `ERR_LIMIT`,
and the search stops there (RetrievalMethods' IDs are looked up in one
pass over the document, so 20000 of them cost no more than one).
`decrypt_replace` parses the plaintext in the scope of where the
EncryptedData was (its prefixes resolve as the sender's did), with the
parser's options and limits; an `Element` must be exactly one element; an
ID the document already has is refused (`ERR_ENC_CONTENT`, the document
left as it was).

- Content: `aes128-gcm`, `aes192-gcm`, `aes256-gcm`; `aes128-cbc`,
  `-192-`, `-256-` to decrypt only, with `allow_cbc`. CBC has no
  integrity: a decrypter that tells a well-formed plaintext from a bad one
  is an oracle that gives the plaintext up (Jager and Somorovsky, "How to
  Break XML Encryption", 2011). ADFS and older Shibboleth still send it;
  take it only from such senders, and only where the plaintext is signed.
- Key transport: `rsa-oaep-mgf1p` (SHA-1, or the DigestMethod's hash; MGF1
  with SHA-1), xmlenc11's `rsa-oaep` with any of SHA-1/256/384/512 for the
  digest and for MGF1 (the `MGF` element, SHA-1 when absent), an
  `OAEPparams` label; `rsa-1_5` to decrypt only, with `allow_rsa15`: it is
  decrypted with implicit rejection (a random key stands in for a badly
  padded one, so the failure shows only later, as a content error), but
  Bleichenbacher's attack is the reason to refuse it wherever you can.
- Key agreement: ECDH-ES (P-256, P-384, P-521; the originator's key as a
  dsig11:ECKeyValue) with ConcatKDF (SHA-256, -384, -512) and `kw-aes128`,
  `-192`, `-256`.
- Every failure to decrypt (a wrong key, a bad tag, bad padding, an
  unwrap that fails) is the one error `ERR_ENC_DECRYPT`.

Encrypting writes AES-GCM (a random 96-bit IV before the ciphertext, the
tag after) with the EncryptedKey in the EncryptedData's KeyInfo: RSA-OAEP
for an RSA certificate, ECDH-ES for an EC one.

## Examples

In gslib's `examples/xml/`, run from gslib's top as `goose examples/xml/<name>.goose`:

- `sign_verify.goose`: a SAML-shaped response built, its assertion
  signed, written, parsed and verified as a service provider would, the
  signed NameID read; then a wrapped copy refused.
- `encrypt_decrypt.goose`: an assertion signed and encrypted to an RSA
  and to an EC certificate, decrypted in place and verified.
- `canonicalize.goose`: the three canonical forms of a subset (Exclusive
  XML Canonicalization's example), or of a file's document.
- `hostile.goose`: billion laughs, XXE, deep nesting, a duplicate
  attribute under two prefixes, a duplicate ID, bad characters: refused.

## Tests

`make test-xml` (`python3 encoding/xml/scripts/run_tests.py`) runs each
`encoding/xml/test/*.goose` at -O0, -O2 and with `--debug`, and the
examples. Nothing outside gslib is needed: the keys and self-signed
certificates (for the tests only) and the documents other implementations
signed and encrypted are in `test/data`, made by `scripts/make_vectors.py`
(`--keys` for new keys).

- `parse.goose` (160 checks): well-formed documents and their nodes; every
  hostile input with its error (DOCTYPEs, billion laughs, XXE, parameter
  entities, undeclared entities; nesting past max_depth, 100000 open
  elements, 65 attributes, a 16 MiB attribute, a long name, too many
  nodes, too many namespaces in scope; duplicate attributes, also by namespace; duplicate IDs under
  ID, Id and xml:id; every namespace misuse; UTF-16, other encodings,
  bad and overlong UTF-8, surrogates, control characters and references
  to them; structure); line-end and attribute normalization; the builder
  and the writer, round trips; fragments; non-ASCII characters in a
  DOCTYPE's literals, US-ASCII declared with UTF-8 in it, namespace URIs
  with white space, `set_attr` of `xmlns` and `declare_ns` rebinding a
  prefix the element, an attribute or a descendant uses.
- `c14n.goose` (66): Canonical XML 1.0's examples §3.1-3.4 and §3.6 (the
  DTD ones without their DTD), Exclusive XML Canonicalization's §2.2
  (inclusive and exclusive, with PrefixLists), 1.1's xml:base fix-up and
  which xml: attributes each method carries onto a subset, namespace
  undeclaration and redeclaration, attribute order, an excluded subtree,
  200 namespaces over 20000 elements, and RFC 3986 §5.4's reference resolution examples.
- `dsig.goose` (108): sign and verify every method, hash, digest and
  canonicalization, an element and a whole document (URI ""); signatures
  signxml and xmlsec made (RSA, PSS, ECDSA, C14N 1.0 and 1.1 with
  xml:lang on the signed element, SHA-1 refused and then allowed);
  tampering (content, white space, attributes, xml:lang, the
  SignatureValue, the DigestValue, another key, RSA 1024, a key of
  another type); every refusal (HMAC, HMACOutputLength, SHA-1 digests,
  unknown canonicalization, XPath, XSLT, a third transform, two
  canonicalizations, enveloped out of order, stray elements and text,
  references to elsewhere, XPointer, no URI, unknown IDs, too many
  references, a DOCTYPE); and wrapping: an evil copy with the signed ID
  (before it, as a ds:Object's Id, as xml:id), the signature moved into an
  evil assertion with the original under ds:Object, a sibling's
  signature, two signatures, a document signature moved into an element,
  two References.
- `enc.goose` (69): round trips of AES-128/192/256-GCM with rsa-oaep-mgf1p
  and rsa-oaep (SHA-256 with MGF1-SHA256, SHA-512 with MGF1-SHA1), ECDH-ES
  on P-256 (every key wrap and KDF hash), P-384 and P-521; xmlsec's
  AES-GCM, AES-CBC and RSA 1.5, refused without their opt-ins; a SHA-256
  OAEP with MGF1-SHA1 found by RetrievalMethod; flipped and shortened
  ciphertexts, keys and tags, wrong keys, other KDFs (one error for every
  decryption failure); plaintexts that are two elements, text, an ID
  already in the document, an unbound prefix, a DOCTYPE; 20000
  RetrievalMethods and 20000 sibling EncryptedKeys refused quickly, a
  RetrievalMethod to no ID or to another element; and SAML's whole
  path: sign, encrypt, write, parse, decrypt in place, verify, read the
  signed NameID.

`make test-xml` passes at -O0, -O2, `--debug` and natively
(`run_tests.py --native`).

### Against other implementations

The live checks need a Python with lxml, signxml, xmlsec and
cryptography, in a venv (nothing system-wide; xmlsec's wheel carries
libxmlsec1):

```bash
python3 -m venv /tmp/xmlvenv && /tmp/xmlvenv/bin/pip install lxml signxml xmlsec cryptography
XML_PYTHON=/tmp/xmlvenv/bin/python make interop-xml differential-xml
```

- `scripts/interop.py` (`make interop-xml`, 244 checks): we sign with
  every method (RSA, PSS, ECDSA on each curve, Ed25519), digest and
  canonicalization, the assertion and the whole response, and signxml
  5.3 and xmlsec 1.3 (libxmlsec1) verify; signxml signs with every method,
  digest and canonicalization and we verify, and so for xmlsec; wrapping
  and tampering of a signxml-signed response, refused; xmlsec encrypts
  (AES-128/256-GCM and -CBC; RSA-OAEP and RSA 1.5) and we decrypt (and
  refuse CBC and 1.5 without the opt-in); we encrypt (AES-GCM; RSA-OAEP
  both forms; ECDH-ES on P-256, P-384, P-521) and xmlsec decrypts, or for
  ECDH-ES, cryptography does.
- `scripts/differential.py` (`make differential-xml`; about 3200 checks
  for 300 random documents): our canonicalization of a
  corpus of tricky namespace cases and of random documents (namespaces
  declared, redeclared and undeclared at every level, prefixed attributes,
  escapes, comments, PIs, CDATA, xml:lang, xml:space, xml:base) against
  libxml2's: whole documents by Canonical XML 1.0, 1.1 and exclusive, with
  and without comments, against lxml; every element with an ID by
  exclusive canonicalization (with and without a PrefixList) against
  lxml; and by 1.0, 1.1 and exclusive against the digest xmlsec gives a
  Reference to it.
- `scripts/make_vectors.py` remakes `test/data`'s signed and encrypted
  documents.

What they found about the others, kept in the tests:

- signxml canonicalizes SignedInfo through lxml's subtree serialization,
  which does not carry the ancestors' xml: attributes onto it, so a
  signature by C14N 1.0 or 1.1 under an element with `xml:lang` does not
  verify between signxml and the spec (xmlsec and we agree with each
  other and the spec). signxml's tests use a document without xml:lang
  on the signed element's ancestors; xmlsec's use one with it.
- lxml's `method="c14n"` of a subtree likewise is no oracle for inclusive
  subsets, and its `"c14n2"` is Canonical XML 2.0, not 1.1; subsets by
  1.0 and 1.1 are checked against xmlsec's digests.
- python-xmlsec cannot raise libxmlsec1's maxEncryptedKeyLevel, which
  ECDH-ES's EncryptedKey needs, so our ECDH-ES output is decrypted by a
  few lines of cryptography instead (ConcatKDF, AES key unwrap, AES-GCM).
- signxml no longer makes SHA-1 signatures; the SHA-1 vector is xmlsec's.
- libxml2 refuses a namespace URI with non-ASCII characters ("not a valid
  URI"), which XML allows and we accept; the random documents use
  percent-encoded ones.

## Not done

- DTDs: no internal subset, no default attributes, no ID-typed attributes
  by declaration (IDs come from `id_attrs` and xml:id), no entities but
  the predefined five. On purpose.
- XML 1.1, encodings other than UTF-8 (and ASCII).
- XML Signature: detached and enveloping signatures (References to
  ds:Object or elsewhere), XPath, XPath Filter 2.0, XSLT and Base64
  transforms, HMAC, DSA, SHA-224 and SHA-3, RSASSA-PSS with explicit
  RSAPSSParams (the MGF1 URIs are done), Ed448, Brainpool curves,
  KeyValue and other KeyInfo forms than X509Data/X509Certificate,
  certificate chains in KeyInfo (checking the certificate is the
  caller's), XAdES.
- XML Encryption: CipherReference, encrypting with CBC or RSA 1.5 (on
  purpose), key transport by other EncryptedKeys or by AES key wrap with
  a shared key, ECDH-ES with X25519/X448 or Brainpool, PBKDF2 and HKDF key
  derivation, EncryptionProperties, the Decryption Transform for
  signatures over encrypted parts.
- Canonical XML 2.0 and arbitrary XPath document subsets (a subset here
  is an element's subtree, less one subtree).
- A streaming parser; the whole document is held, within `max_size`.
