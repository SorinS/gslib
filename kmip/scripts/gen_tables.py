#!/usr/bin/env python3
"""Generate kmip/tables.goose from KMIP 2.1's specification and PyKMIP.

    python3 kmip/scripts/gen_tables.py PATH/TO/pykmip/kmip/core/enums.py \
        [PATH/TO/kmip-spec-v2.1-os.html [PATH/TO/kmip-spec-v1.4-os.html]] \
        > kmip/tables.goose

Two sources, merged:

- PyKMIP's kmip/core/enums.py (parsed, not imported): the constants' names
  (TAG_UNIQUE_IDENTIFIER, ALG_TRIPLE_DES), every tag and enumeration of
  KMIP 1.0 to 2.0, and the attribute names of KMIP 1.x's Attribute Name.
  PyKMIP 4815637 (2026-09-10), Apache License 2.0.
- KMIP 2.1's specification (OASIS Standard, 14 December 2020; downloaded
  from docs.oasis-open.org when not given): its Tag Enumeration and the
  enumerations' tables, which bring 2.1's tags and values, and the names
  KMIP's XML and JSON encodings write, normalized as the KMIP Profiles
  (§5.4.1.1) say: "3DES" is DES3, "PKCS#1" PKCS_1, "On-line storage"
  OnLineStorage. KMIP 1.4's specification adds the values 2.x dropped
  (1.x's Profile Names).

A constant PyKMIP names keeps PyKMIP's name; the others are named from
the specification's text. What comes out: the tags (TAG_*), the
enumerations with a prefix each, the masks' bits, TAG_NAMES (each tag's
normalized name, by tag) and TAG_BY_NAME (the same, by name),
ENUM_NAMES (an Enumeration's values and names under each tag that holds
one, by tag and value) and ENUM_ALIASES (other spellings read, never
written), MASK_NAMES (the masks' bits by tag), and ATTRIBUTE_NAMES.
"""

import ast
import os
import re
import sys
import urllib.request
from html.parser import HTMLParser

SPEC_URL = "https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html"
SPEC14_URL = "https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html"

# PyKMIP's enumerations given constants: class, prefix, a suffix or prefix
# the member names repeat that is dropped, and the specification's name.
ENUMS = [
    ("ObjectType",                   "OBJ_",      None,      "Object Type"),
    ("Operation",                    "OP_",       None,      "Operation"),
    ("ResultStatus",                 "STATUS_",   None,      "Result Status"),
    ("ResultReason",                 "REASON_",   None,      "Result Reason"),
    ("BatchErrorContinuationOption", "BATCH_",    None,      "Batch Error Continuation Option"),
    ("CryptographicAlgorithm",       "ALG_",      None,      "Cryptographic Algorithm"),
    ("BlockCipherMode",              "MODE_",     None,      "Block Cipher Mode"),
    ("PaddingMethod",                "PAD_",      None,      "Padding Method"),
    ("HashingAlgorithm",             "HASH_",     None,      "Hashing Algorithm"),
    ("DigitalSignatureAlgorithm",    "SIG_",      None,      "Digital Signature Algorithm"),
    ("MaskGenerator",                "MGF_",      None,      "Mask Generator"),
    ("KeyRoleType",                  "ROLE_",     None,      "Key Role Type"),
    ("RecommendedCurve",             "CURVE_",    None,      "Recommended Curve"),
    ("KeyFormatType",                "FMT_",      None,      "Key Format Type"),
    ("KeyCompressionType",           "COMPRESS_", None,      "Key Compression Type"),
    ("WrappingMethod",               "WRAP_",     None,      "Wrapping Method"),
    ("EncodingOption",               "ENCODING_", None,      "Encoding Option"),
    ("NameType",                     "NAME_",     None,      "Name Type"),
    ("State",                        "STATE_",    None,      "State"),
    ("LinkType",                     "LINK_",     "_LINK",   "Link Type"),
    ("RevocationReasonCode",         "REVOKE_",   None,      "Revocation Reason Code"),
    ("QueryFunction",                "QUERY_",    "QUERY_",  "Query Function"),
    ("CertificateType",              "CERT_",     None,      "Certificate Type"),
    ("SecretDataType",               "SECRET_",   None,      "Secret Data Type"),
    ("CredentialType",               "CRED_",     None,      "Credential Type"),
    ("DerivationMethod",             "DERIVE_",   None,      "Derivation Method"),
    ("ValidityIndicator",            "VALIDITY_", None,      "Validity Indicator"),
    ("AlternativeNameType",          "ALTNAME_",  None,      "Alternative Name Type"),
    ("UniqueIdentifier",             "UID_",      None,      "Unique Identifier"),
    ("CryptographicUsageMask",       "USAGE_",    None,      "Cryptographic Usage Mask"),
    ("StorageStatusMask",            "STORAGE_",  None,      "Storage Status Mask"),
    ("ProtectionStorageMask",        "PSM_",      None,      "Protection Storage Mask"),
]

# The specification's enumerations PyKMIP has no constants for: name,
# prefix, and the drop as above.
SPEC_ENUMS = [
    ("Adjustment Type",            "ADJUST_",      None),
    ("Asynchronous Indicator",     "ASYNC_",       None),
    ("Attestation Type",           "ATTEST_",      None),
    ("Cancellation Result",        "CANCEL_",      None),
    ("Certificate Request Type",   "CSR_",         None),
    ("Client Registration Method", "REGISTER_",    None),
    ("Data",                       "DATA_",        None),
    ("Destroy Action",             "DESTROY_",     None),
    ("DRBG Algorithm",             "DRBG_",        None),
    ("Endpoint Role",              "ENDPOINT_",    None),
    ("FIPS186 Variation",          "FIPS186_",     None),
    ("Interop Function",           "INTEROP_",     None),
    ("Item Type",                  "ITEM_",        None),
    ("Key Value Location Type",    "LOCATION_",    None),
    ("Key Wrap Type",              "KEY_WRAP_",    None),
    ("NIST Key Type",              "NIST_",        None),
    ("Object Group Member",        "GROUP_",       "GROUP_MEMBER_"),
    ("Processing Stage",           "STAGE_",       None),
    ("Profile Name",               "PROFILE_",     None),
    ("Protection Level",           "PROTECTION_",  None),
    ("Put Function",               "PUT_",         None),
    ("RNG Algorithm",              "RNG_",         None),
    ("RNG Mode",                   "RNG_MODE_",    None),
    ("Rotate Name Type",           "ROTATE_NAME_", None),
    ("Shredding Algorithm",        "SHRED_",       None),
    ("Split Key Method",           "SPLIT_",       None),
    ("Ticket Type",                "TICKET_",      None),
    ("Unwrap Mode",                "UNWRAP_",      None),
    ("Usage Limits Unit",          "LIMITS_",      None),
    ("Validation Authority Type",  "AUTHORITY_",   None),
    ("Validation Type",            "VALIDATION_",  None),
]

MASKS = {"Cryptographic Usage Mask", "Storage Status Mask", "Protection Storage Mask"}

# The specification's section headings that are cut short or misspelt.
HEADINGS = {
    "Batch Error Continuation": "Batch Error Continuation Option",
    "Digital Signature": "Digital Signature Algorithm",
    "DRGB Algorithm": "DRBG Algorithm",
}

# Tags whose Enumeration is not the one of their own name.
EXTRA_ENUM_TAGS = {
    "Mask Generator Hashing Algorithm": "Hashing Algorithm",
}

# The specification's text where the HTML lost a superscript or has a typo.
FIXES = {
    "Polynomial Sharing GF (216)": "Polynomial Sharing GF (2^16)",
    "Polynomial Sharing GF (28)": "Polynomial Sharing GF (2^8)",
    "MFG1": "MGF1",
}
# Other spellings read, never written: the specification's typo, and OASIS's
# test cases' American spelling of 2.1's Not Authorised.
ALIASES = {"MGF1": ["MFG1"], "Not Authorised": ["Not Authorized"]}

# PKCS#11 Function: the 1-based place of the function in PKCS#11 3.0's
# CK_FUNCTION_LIST_3_0 (pkcs11f.h's order).
PKCS11_FUNCTIONS = """
C_Initialize C_Finalize C_GetInfo C_GetFunctionList C_GetSlotList C_GetSlotInfo
C_GetTokenInfo C_GetMechanismList C_GetMechanismInfo C_InitToken C_InitPIN
C_SetPIN C_OpenSession C_CloseSession C_CloseAllSessions C_GetSessionInfo
C_GetOperationState C_SetOperationState C_Login C_Logout C_CreateObject
C_CopyObject C_DestroyObject C_GetObjectSize C_GetAttributeValue
C_SetAttributeValue C_FindObjectsInit C_FindObjects C_FindObjectsFinal
C_EncryptInit C_Encrypt C_EncryptUpdate C_EncryptFinal C_DecryptInit C_Decrypt
C_DecryptUpdate C_DecryptFinal C_DigestInit C_Digest C_DigestUpdate C_DigestKey
C_DigestFinal C_SignInit C_Sign C_SignUpdate C_SignFinal C_SignRecoverInit
C_SignRecover C_VerifyInit C_Verify C_VerifyUpdate C_VerifyFinal
C_VerifyRecoverInit C_VerifyRecover C_DigestEncryptUpdate C_DecryptDigestUpdate
C_SignEncryptUpdate C_DecryptVerifyUpdate C_GenerateKey C_GenerateKeyPair
C_WrapKey C_UnwrapKey C_DeriveKey C_SeedRandom C_GenerateRandom
C_GetFunctionStatus C_CancelFunction C_WaitForSlotEvent
C_GetInterfaceList C_GetInterface C_LoginUser C_SessionCancel
C_MessageEncryptInit C_EncryptMessage C_EncryptMessageBegin C_EncryptMessageNext
C_MessageEncryptFinal C_MessageDecryptInit C_DecryptMessage C_DecryptMessageBegin
C_DecryptMessageNext C_MessageDecryptFinal C_MessageSignInit C_SignMessage
C_SignMessageBegin C_SignMessageNext C_MessageSignFinal C_MessageVerifyInit
C_VerifyMessage C_VerifyMessageBegin C_VerifyMessageNext C_MessageVerifyFinal
""".split()


def normalize(text):
    """KMIP Profiles 2.1 §5.4.1.1: KMIP's text to its CamelCase form."""
    s = re.sub(r"[()]", " ", text)                                    # 1
    s = re.sub(r"[^\w\s](?=[A-Za-z][a-z])", " ", s)                   # 2
    s = re.sub(r"[^\w\s]", "_", s)                                    # 3
    words = s.split()
    if words and words[0][0].isdigit():                               # 4
        m = re.match(r"\d+", words[0])
        words[0] = words[0][m.end():] + m.group(0)
    return "".join(w[0].upper() + w[1:] for w in words if w)          # 5, 6


def const_name(text):
    """A constant's name from the specification's text: "Set Defaults" -> SET_DEFAULTS."""
    s = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").upper()
    if s[:1].isdigit():
        s = "_" + s
    return s


def defined_elsewhere(root):
    """The constants kmip's other modules declare: name -> value."""
    out = {}
    d = os.path.join(root, "kmip")
    for f in [os.path.join(root, "kmip.goose")] + [os.path.join(d, x) for x in sorted(os.listdir(d))]:
        if not f.endswith(".goose") or f.endswith("tables.goose"):
            continue
        for m in re.finditer(r"^let ([A-Z][A-Z0-9_]*): u32 = (0x[0-9A-Fa-f]+);", open(f).read(), re.M):
            out[m.group(1)] = int(m.group(2), 16)
    return out


def camel(upper):
    return "".join(w.capitalize() for w in upper.split("_"))


def number(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def read_pykmip(path):
    tree = ast.parse(open(path, encoding="utf-8").read(), path)
    classes, attr_table = {}, []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            members = []
            for st in node.body:
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    v = number(st.value)
                    if v is not None:
                        members.append((st.targets[0].id, v))
            classes[node.name] = members
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "attribute_name_tag_table":
            for elt in node.value.elts:
                attr_table.append((elt.elts[0].value, elt.elts[1].attr))
    return classes, attr_table


class Tables(HTMLParser):
    """The specification's top-level tables, each with where it starts in the text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables, self.text, self.n = [], [], 0
        self.depth, self.row, self.cell = 0, None, None

    def handle_starttag(self, t, a):
        if t == "table":
            self.depth += 1
            if self.depth == 1:
                self.cur, self.start = [], self.n
        elif t == "tr" and self.depth == 1:
            self.row = []
        elif t in ("td", "th") and self.depth == 1:
            self.cell = []

    def handle_endtag(self, t):
        if t == "table":
            if self.depth == 1:
                self.tables.append((self.start, self.cur))
            self.depth -= 1
        elif t == "tr" and self.depth == 1 and self.row is not None:
            self.cur.append(self.row)
            self.row = None
        elif t in ("td", "th") and self.depth == 1 and self.cell is not None:
            self.row.append(re.sub(r"\s+", " ", "".join(self.cell).replace("\xa0", " ")).strip())
            self.cell = None

    def handle_data(self, d):
        if self.cell is not None:
            self.cell.append(d)
        self.text.append(d)
        self.n += len(d)


def read_spec(path):
    """The Tag Enumeration's rows, and each enumeration's (name, value) rows by its name."""
    raw = open(path, "rb").read().decode("windows-1252", errors="replace")
    p = Tables()
    p.feed(raw)
    full = "".join(p.text).replace("\xa0", " ")
    heads = [(m.start(), re.sub(r"\s+", " ", m.group(2)).strip())
             for m in re.finditer(r"\n\s*(\d+\.\d+(?:\.\d+)*)\s+([^\n]{3,80})", full)]
    enums, tags = {}, []
    for start, rows in p.tables:
        if len(rows) < 2 or rows[1][:2] != ["Name", "Value"]:
            continue
        h = None
        for a, t in heads:
            if a < start:
                h = t
            else:
                break
        h = re.sub(r"\s*Enumerations?$", "", h.strip())
        h = re.sub(r"\s*Enumeration for .*$", "", h)
        h = HEADINGS.get(h, h)
        body = []
        for r in rows[2:]:
            if len(r) < 2:
                continue
            name, val = r[0].strip(), r[1].replace(" ", "")
            if val[:2] in ("0x", "0X"):
                val = val[2:]
            if not re.fullmatch(r"[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8}", val):
                continue          # Extensions 8XXXXXXX, (Reserved) ranges
            if name.startswith("("):
                continue          # (Reserved), (Unused)
            name = FIXES.get(name, name)
            body.append((name, int(val, 16)))
        if h == "Tag":
            tags = body
        else:
            enums[h] = body
    return tags, enums


def pkcs11_return_codes(root):
    path = os.path.join(root, "pkcs11", "constants.goose")
    out = []
    for m in re.finditer(r"^let CKR_([A-Z0-9_]+): u64 = (0x[0-9A-Fa-f]+);", open(path).read(), re.M):
        out.append((m.group(1), int(m.group(2), 16)))
    return out


def main():
    pykmip = sys.argv[1]

    def fetch(i, url):
        if len(sys.argv) > i:
            return sys.argv[i]
        path = os.path.join(os.environ.get("TMPDIR", "/tmp"), os.path.basename(url))
        if not os.path.exists(path):
            urllib.request.urlretrieve(url, path)
        return path
    spec = fetch(2, SPEC_URL)
    spec14 = fetch(3, SPEC14_URL)
    root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

    classes, attr_table = read_pykmip(pykmip)
    spec_tags, spec_enums = read_spec(spec)
    # KMIP 1.4's values 2.x dropped or reserved (1.x's Profile Names) keep
    # their names.
    tags14, enums14 = read_spec(spec14)
    for name, rows in enums14.items():
        if name in spec_enums:
            have = {v for _, v in spec_enums[name]}
            spec_enums[name] = spec_enums[name] + [(n, v) for n, v in rows if v not in have]
    have = {v for _, v in spec_tags}
    spec_tags = spec_tags + [(n, v) for n, v in tags14 if v not in have]

    # --- tags: PyKMIP's names, then 2.1's
    py_tags = [(n, v) for n, v in classes["Tags"] if n != "DEFAULT"]
    tag_of = dict(py_tags)
    const_of_tag = {}
    for n, v in py_tags:
        const_of_tag.setdefault(v, n)
    taken = set(tag_of)
    tag_consts = list(py_tags)
    norm_of_tag = {}
    for name, v in spec_tags:
        norm_of_tag.setdefault(v, normalize(name))
        if v not in const_of_tag:
            c = const_name(name)
            if c in taken:
                sys.exit(f"tag constant {c} taken")
            taken.add(c)
            tag_consts.append((c, v))
            const_of_tag[v] = c
    tag_by_spec = {}
    for name, v in spec_tags:
        tag_by_spec.setdefault(name, v)
    # Names: the specification's normalized one; PyKMIP's in CamelCase for a
    # tag 2.1 does not have.
    tag_names = {}
    for v, c in const_of_tag.items():
        tag_names[v] = norm_of_tag.get(v) or camel(c)

    def spec_tag(enum_name):
        """The tag an enumeration of the specification is held under."""
        for name, v in spec_tags:
            if name == enum_name:
                return v
        for name, v in spec_tags:
            if normalize(name) == normalize(enum_name):
                return v
        return None

    out = []
    w = out.append
    w("// kmip.tables: KMIP's tags, enumerations and masks, their names in KMIP's")
    w("// XML and JSON encodings, and the attribute names of KMIP 1.x. Generated by")
    w("// kmip/scripts/gen_tables.py from KMIP 2.1's specification (OASIS Standard,")
    w("// 14 December 2020) and PyKMIP's kmip/core/enums.py (PyKMIP 4815637, Apache")
    w("// License 2.0); do not edit.")
    w("")
    w("namespace kmip;")
    w("")
    w("// --- Tags ----------------------------------------------------------------------")
    w("")
    width = max(len(n) for n, _ in tag_consts) + 4
    for n, v in tag_consts:
        w(f"let {('TAG_' + n + ':').ljust(width + 1)} u32 = 0x{v:06X};")
    w("")

    names = set()       # (tag, value, name)
    masks = []          # (tag, bit, name)
    aliases = []        # (tag, value, alias)
    all_consts = {"TAG_" + n for n, _ in tag_consts}

    elsewhere = defined_elsewhere(root)

    def emit(title, consts):
        # A constant another kmip module declares is left to it.
        mine = []
        for c, v in consts:
            if c in elsewhere:
                if elsewhere[c] != v:
                    sys.exit(f"{c} is 0x{elsewhere[c]:X} elsewhere in kmip, 0x{v:X} here")
                print(f"note: {c} is declared elsewhere in kmip", file=sys.stderr)
                continue
            mine.append((c, v))
        w(f"// --- {title} " + "-" * max(3, 76 - len(title)))
        w("")
        cw = max(len(c) for c, _ in mine) + 1 if mine else 0
        for c, v in mine:
            w(f"let {(c + ':').ljust(cw)} u32 = 0x{v:08X};")
        w("")

    def add_names(spec_name, rows):
        tags = []
        t = spec_tag(spec_name)
        if t is not None:
            tags.append(t)
        for extra, base in EXTRA_ENUM_TAGS.items():
            if base == spec_name:
                tags.append(tag_by_spec[extra])
        for t in tags:
            for n, v in rows:
                if spec_name in MASKS:
                    masks.append((t, v, normalize(n)))
                else:
                    names.add((t, v, normalize(n)))
                for a in ALIASES.get(n, []):
                    aliases.append((t, v, normalize(a)))
        return tags

    def strip_member(n, strip):
        if strip and n.endswith(strip):
            return n[: -len(strip)]
        if strip and n.startswith(strip):
            return n[len(strip):]
        return n

    for cls, prefix, strip, spec_name in ENUMS:
        members = classes[cls]
        rows = spec_enums.get(spec_name)
        if rows is None:
            sys.exit(f"no table for {spec_name}")
        consts, have = [], set()
        for n, v in members:
            consts.append((prefix + strip_member(n, strip).upper(), v))
            have.add(v)
        for n, v in rows:
            if v not in have:
                c = prefix + strip_member(const_name(n), strip)
                if c in {x for x, _ in consts} or c in all_consts:
                    c = f"{c}_{v:X}"
                consts.append((c, v))
                have.add(v)
        all_consts.update(c for c, _ in consts)
        # PyKMIP's values the specification no longer lists keep a name.
        spec_vals = {v for _, v in rows}
        extra = [(camel(n), v) for n, v in members if v not in spec_vals]
        if not add_names(spec_name, rows + extra):
            sys.exit(f"no tag for {spec_name}")
        emit(spec_name, consts)

    for spec_name, prefix, strip in SPEC_ENUMS:
        rows = spec_enums.get(spec_name)
        if rows is None:
            sys.exit(f"no table for {spec_name}")
        consts = []
        for n, v in rows:
            c = prefix + strip_member(const_name(n), strip)
            if c in all_consts or c in {x for x, _ in consts}:
                c = f"{c}_{v:X}"
            consts.append((c, v))
        all_consts.update(c for c, _ in consts)
        if not add_names(spec_name, rows):
            print(f"note: no tag holds {spec_name}; constants only", file=sys.stderr)
        emit(spec_name, consts)

    # Enumerations named only: PKCS#11's functions and return codes.
    t = tag_by_spec["PKCS#11 Function"]
    for i, f in enumerate(PKCS11_FUNCTIONS):
        names.add((t, i + 1, f))
    t = tag_by_spec["PKCS#11 Return Code"]
    for n, v in pkcs11_return_codes(root):
        names.add((t, v, n))

    # One name a tag and value: the first table's.
    seen, enum_rows = set(), []
    for tg, v, n in sorted(names):
        if (tg, v) not in seen:
            seen.add((tg, v))
            enum_rows.append((tg, v, n))

    w("// --- Names -----------------------------------------------------------------------")
    w("")
    w("struct TagName { tag: u32, name: const u8[:] }")
    w("struct EnumName { tag: u32, value: u32, name: const u8[:] }")
    w("")
    w("// Every tag and its name in KMIP's XML and JSON encodings, by tag.")
    by_tag = sorted(tag_names.items())
    w(f"let TAG_NAMES: TagName[{len(by_tag)}] = [")
    for v, n in by_tag:
        w(f'    TagName {{ tag: 0x{v:06X}, name: "{n}" }},')
    w("];")
    w("")
    w("// The same, by name (bytewise).")
    w(f"let TAG_BY_NAME: TagName[{len(by_tag)}] = [")
    for v, n in sorted(by_tag, key=lambda t: t[1].encode()):
        w(f'    TagName {{ tag: 0x{v:06X}, name: "{n}" }},')
    w("];")
    w("")
    w("// The values of the Enumeration under each tag that holds one, and their")
    w("// names, by tag then value.")
    w(f"let ENUM_NAMES: EnumName[{len(enum_rows)}] = [")
    for tg, v, n in enum_rows:
        w(f'    EnumName {{ tag: 0x{tg:06X}, value: 0x{v:08X}, name: "{n}" }},')
    w("];")
    w("")
    w("// Other spellings of enumeration values, read and never written.")
    w(f"let ENUM_ALIASES: EnumName[{len(aliases)}] = [")
    for tg, v, n in sorted(aliases):
        w(f'    EnumName {{ tag: 0x{tg:06X}, value: 0x{v:08X}, name: "{n}" }},')
    w("];")
    w("")
    w("// The bits of the Integer masks and their names, by tag then bit.")
    masks.sort()
    w(f"let MASK_NAMES: EnumName[{len(masks)}] = [")
    for tg, v, n in masks:
        w(f'    EnumName {{ tag: 0x{tg:06X}, value: 0x{v:08X}, name: "{n}" }},')
    w("];")
    w("")
    w("// KMIP 1.x's Attribute Names, as the specification spells them, and their tags.")
    w(f"let ATTRIBUTE_NAMES: TagName[{len(attr_table)}] = [")
    for n, tg in attr_table:
        w(f'    TagName {{ tag: 0x{tag_of[tg]:06X}, name: "{n}" }},')
    w("];")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
