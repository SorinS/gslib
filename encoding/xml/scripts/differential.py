#!/usr/bin/env python3
"""Differential test of xml's canonicalization against libxml2, on a
corpus of tricky namespace cases and random documents:

  - whole documents, Canonical XML 1.0 and Exclusive XML
    Canonicalization, with and without comments, against lxml's
    etree.tostring(method="c14n") (libxml2's xmlC14NDocSaveTo); Canonical
    XML 1.1 of a whole document is 1.0's, so it is checked against that;
  - the subtree of every element with an ID, exclusively (with and
    without an InclusiveNamespaces PrefixList), against lxml;
  - the same subtrees by Canonical XML 1.0 and 1.1, against the digest
    xmlsec (libxmlsec1 over libxml2's node-set canonicalization) makes of
    a Reference to the ID with that transform: lxml serializes a subtree
    without the xml: attributes its ancestors would lend it, so it is not
    an oracle for inclusive subsets; xmlsec is, and is for 1.1's xml:base
    fix-up too.

Every random document is also one our parser must accept. Differences
are printed with the document.

It needs a Python with lxml (and xmlsec for the subset digests); see
scripts/interop.py for a venv.

    python3 scripts/differential.py [-n DOCS] [--seed S] [--goose PATH]
"""

import argparse
import base64
import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TOOL = os.path.join(ROOT, "tools", "xmltool.goose")
DATA = os.path.join(ROOT, "test", "data")

try:
    from lxml import etree
except ImportError as e:
    print(f"skipped: {e} (see scripts/interop.py for a venv)")
    sys.exit(0)
try:
    import xmlsec
except ImportError:
    xmlsec = None

CORPUS = [
    # Namespaces: redeclared, undeclared, unused, shadowed, on attributes.
    '<a xmlns="urn:a"><b xmlns="" ID="i1"><c/></b><d xmlns="urn:a" ID="i2"/></a>',
    '<p:a xmlns:p="urn:p" xmlns:q="urn:q" xmlns:r="urn:r"><p:b q:x="1" ID="i1"><r:c/><p:d xmlns:p="urn:p2"/></p:b></p:a>',
    '<a xmlns:p="urn:p"><b xmlns:p="urn:p" ID="i1"><p:c xmlns:p="urn:p"/></b></a>',
    '<a xmlns="urn:x"><b xmlns="urn:y" ID="i1"><c xmlns="urn:x"><d xmlns=""/></c></b></a>',
    '<a xmlns:p="urn:p" xmlns:q="urn:p"><b p:x="1" q:y="2" ID="i1"/></a>',
    '<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en" ID="i1"><n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n0:local>',
    '<n2:pdu xmlns:n1="http://example.com" xmlns:n2="http://foo.example" xml:lang="fr" xml:space="retain"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en" ID="i1"><n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n2:pdu>',
    # xml: attributes on ancestors, xml:base to join.
    '<a xml:lang="en" xml:space="preserve" xml:base="http://example.org/a/b/"><b xml:base="c/" ID="i1"><c xml:base="../d" ID="i2"/></b></a>',
    '<a xml:base="http://example.org/x/y"><b ID="i1"><c xml:base="z" ID="i2"/></b></a>',
    '<a xml:base="../one/"><b xml:base="../two/"><c ID="i1"/></b></a>',
    # Escapes, white space, comments and PIs at every level.
    '<?pi a?><!--c0--><a b="&#9;&#10;&#13;&amp;&lt;&quot;&gt;\'" ID="i1">&#13;&amp;&lt;&gt;"\'<![CDATA[]]&gt;]]><!--c1--><?p d ?></a><!--c2--><?q?>',
    '<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n   </mixed>\n</doc>',
    # Attribute order by namespace URI, not prefix.
    '<a xmlns:z="urn:a" xmlns:y="urn:b" b="1" a="2" y:a="3" z:b="4" z:a="5" ID="i1"/>',
    # SAML-shaped.
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="i1"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="i2"><saml:AttributeStatement><saml:Attribute Name="x"><saml:AttributeValue xsi:type="xs:string">v</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>',
]

PREFIXES = ["", "a", "b", "c", "ns1"]
URIS = ["urn:x", "urn:y", "http://example.org/ns", "urn:z:%C3%A9", "urn:x"]
TEXT = ["t", " ", "\n", "&amp;", "&lt;", "&gt;", "&#13;", "&#9;", "\"", "'", "\u00e9", "\U0001F600", "]]&gt;", "x y"]
ATTRV = ["v", " ", "&#9;", "&#10;", "&#13;", "&amp;", "&lt;", "&quot;", "'", ">", "\u00e9", "a  b"]


class Gen:
    def __init__(self, r):
        self.r = r
        self.ids = 0

    def text(self, pool):
        return "".join(self.r.choice(pool) for _ in range(self.r.randrange(0, 4)))

    def element(self, depth, scope):
        r = self.r
        scope = dict(scope)
        decls = []
        # Declarations: new, redeclared, or the default undeclared.
        for _ in range(r.randrange(0, 3)):
            p = r.choice(PREFIXES)
            if p == "" and scope.get("") and r.random() < 0.3:
                u = ""
            else:
                u = r.choice(URIS)
            if p in [d[0] for d in decls]:
                continue
            decls.append((p, u))
            scope[p] = u
        bound = [p for p, u in scope.items() if p and u]
        prefix = r.choice(bound + [""] * 2) if bound else ""
        name = (prefix + ":" if prefix else "") + r.choice(["e", "f", "g", "Assertion"])
        attrs = []
        seen = set()
        for _ in range(r.randrange(0, 4)):
            ap = r.choice(bound + [""] * 3) if bound else ""
            an = r.choice(["x", "y", "z", "Name"])
            key = (scope.get(ap) if ap else None, an)
            if key in seen:
                continue
            seen.add(key)
            attrs.append(((ap + ":" if ap else "") + an, self.text(ATTRV)))
        if r.random() < 0.15:
            attrs.append(("xml:lang", r.choice(["en", "fr", ""])))
        if r.random() < 0.08:
            attrs.append(("xml:space", r.choice(["preserve", "default"])))
        if r.random() < 0.1:
            attrs.append(("xml:base", r.choice(["http://example.org/a/", "b/", "../c", "/d/e"])))
        if r.random() < 0.4:
            self.ids += 1
            attrs.append(("ID", f"id{self.ids}"))
        out = "<" + name
        for p, u in decls:
            out += f' xmlns{":" + p if p else ""}="{u}"'
        for an, av in attrs:
            out += f' {an}="{av}"'
        kids = []
        if depth < 5:
            for _ in range(r.randrange(0, 4)):
                c = r.random()
                if c < 0.45:
                    kids.append(self.element(depth + 1, scope))
                elif c < 0.7:
                    kids.append(self.text(TEXT))
                elif c < 0.8:
                    kids.append("<!--" + r.choice(["", " c ", "x\ny"]) + "-->")
                elif c < 0.9:
                    kids.append("<?" + r.choice(["p", "q-r"]) + r.choice(["", " d", " d e "]) + "?>")
                else:
                    kids.append("<![CDATA[" + r.choice(["", "<&>", "]]", "a\r\nb"]) + "]]>")
        if not kids and r.random() < 0.5:
            return out + "/>"
        return out + ">" + "".join(kids) + "</" + name + ">"

    def document(self):
        r = self.r
        pre = "".join(r.choice(["<!--top-->", "<?top x?>", "\n"]) for _ in range(r.randrange(0, 3)))
        post = "".join(r.choice(["<!--end-->", "<?end?>", "\n"]) for _ in range(r.randrange(0, 3)))
        return pre + self.element(0, {}) + post


def ids_of(data):
    root = etree.fromstring(data)
    return [el.get("ID") for el in root.iter() if isinstance(el.tag, str) and el.get("ID")], root


def lxml_c14n(data, exclusive, comments, element_id=None, prefixes=None):
    tree = etree.fromstring(data).getroottree()
    if element_id is None:
        return etree.tostring(tree, method="c14n", exclusive=exclusive, with_comments=comments)
    el = tree.getroot().xpath(f'//*[@ID="{element_id}"]')[0]
    return etree.tostring(el, method="c14n", exclusive=exclusive, with_comments=comments,
                          inclusive_ns_prefixes=prefixes)


def xmlsec_digest(data, element_id, transform):
    """The SHA-256 digest xmlsec gives a Reference to #element_id with one
    canonicalization transform; None when the element is the root (the
    Signature would be inside what it digests)."""
    root = etree.fromstring(data)
    if root.get("ID") == element_id:
        return None
    for el in root.iter():
        if isinstance(el.tag, str) and el.get("ID"):
            xmlsec.tree.add_ids(el, ["ID"])
    C = xmlsec.constants
    sig = xmlsec.template.create(root, C.TransformExclC14N, C.TransformRsaSha256)
    root.append(sig)
    ref = xmlsec.template.add_reference(sig, C.TransformSha256, uri="#" + element_id)
    xmlsec.template.add_transform(ref, transform)
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(os.path.join(DATA, "rsa2048.key"), C.KeyDataFormatPem)
    ctx.sign(sig)
    dv = sig.find(".//{http://www.w3.org/2000/09/xmldsig#}DigestValue").text
    return base64.b64decode(dv)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=300)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--goose")
    args = ap.parse_args()
    seed = args.seed if args.seed is not None else random.randrange(1 << 30)
    goose = None
    for cand in [args.goose, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            goose = cand
            break
    if goose is None:
        sys.exit("no goose compiler found: pass --goose or set GOOSE")
    print(f"seed {seed}; lxml {etree.LXML_VERSION}, libxml2 {etree.LIBXML_VERSION}"
          + (f", xmlsec {xmlsec.get_libxmlsec_version()}" if xmlsec else ", no xmlsec (subset digests skipped)"))
    gen = Gen(random.Random(seed))
    docs = [c.encode() for c in CORPUS] + [gen.document().encode() for _ in range(args.n)]
    counts = {}
    bad = []

    def count(kind, ok, detail):
        counts.setdefault(kind, [0, 0])
        counts[kind][0 if ok else 1] += 1
        if not ok and len(bad) < 20:
            bad.append(f"{kind}\n  doc: {detail[0]!r}\n  ours:   {detail[1]!r}\n  theirs: {detail[2]!r}")

    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "xmltool")
        p = subprocess.run([goose, "build", "-o", exe, TOOL], capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("cannot build xmltool:\n" + p.stdout + p.stderr)
        path = os.path.join(tmp, "doc.xml")

        def ours(*a):
            p = subprocess.run([exe, "c14n", *a], capture_output=True)
            return p.stdout if p.returncode == 0 else b"ERROR " + p.stdout + p.stderr.encode()

        for data in docs:
            open(path, "wb").write(data)
            try:
                ids, _ = ids_of(data)
            except etree.XMLSyntaxError as e:
                count("lxml refuses a generated document", False, (data, b"", str(e)))
                continue
            for comments in (False, True):
                c = "1" if comments else "0"
                t = lxml_c14n(data, False, comments)
                count("whole document, c14n 1.0" + (" with comments" if comments else ""), ours("c14n10", c, path) == t,
                      (data, ours("c14n10", c, path), t))
                count("whole document, c14n 1.1 (as 1.0)", ours("c14n11", c, path) == t, (data, ours("c14n11", c, path), t))
                t = lxml_c14n(data, True, comments)
                count("whole document, exclusive" + (" with comments" if comments else ""), ours("exc", c, path) == t,
                      (data, ours("exc", c, path), t))
            for i in ids:
                t = lxml_c14n(data, True, False, i)
                count("subset, exclusive", ours("exc", "0", path, i) == t, (data + f" #{i}".encode(), ours("exc", "0", path, i), t))
                t = lxml_c14n(data, True, False, i, ["a", "c"])
                count("subset, exclusive with PrefixList a c", ours("exc", "0", path, i, "a c") == t,
                      (data + f" #{i}".encode(), ours("exc", "0", path, i, "a c"), t))
                if xmlsec is not None:
                    for (name, tr) in [("c14n10", xmlsec.constants.TransformInclC14N),
                                       ("c14n11", xmlsec.constants.TransformInclC14N11),
                                       ("exc", xmlsec.constants.TransformExclC14N)]:
                        want = xmlsec_digest(data, i, tr)
                        if want is None:
                            continue
                        got = ours(name, "0", path, i)
                        count(f"subset digest, {name}, against xmlsec", hashlib.sha256(got).digest() == want,
                              (data + f" #{i}".encode(), got, want.hex()))
    total_bad = 0
    for kind, (ok, no) in counts.items():
        print(f"{'ok  ' if no == 0 else 'FAIL'}  {kind}: {ok} agree, {no} differ")
        total_bad += no
    for b in bad:
        print(b)
    print(f"\n{sum(v[0] for v in counts.values())} passed, {total_bad} failed")
    sys.exit(1 if total_bad else 0)


if __name__ == "__main__":
    main()
