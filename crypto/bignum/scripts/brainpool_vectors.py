#!/usr/bin/env python3
"""Vectors for bignum.ec's Brainpool curves: test/vectors/brainpool.txt.

brainpoolP256r1, P384r1 and P512r1 (RFC 5639) on Python integers: affine
arithmetic for y^2 = x^3 + ax + b, SEC 1 encodings and RFC 6979
deterministic ECDSA with SHA-256, SHA-384 and SHA-512. The ECDH vectors of
RFC 7027 Appendix A and RFC 6932 Appendix A.2-A.4 are checked against it.
Then every vector is checked by others where they are installed: openssl
(ECDH, and verifying each signature), and, under a Python that has them
(a venv: pip install ecdsa cryptography), the ecdsa package (RFC 6979
signatures byte for byte, compressed points) and cryptography (ECDH,
verification). openssl also signs some messages itself (random nonces);
those signatures, and cryptography's when it is there (else a second of
openssl's), are written for bignum to verify, so they change from run to
run; test/expected/brainpool_vectors.txt counts the checks, so a run with
neither openssl nor cryptography needs `run_tests.py --update -k
brainpool`. Lines:

    mul <curve> <k hex> <k G, 04 || x || y>
    ecdh <curve> <private> <peer's public> <shared x>
    ecdsa <curve> <private> <public> <msg> <r || s> <DER>   (RFC 6979)
    verify <curve> <public> <msg> <DER>                     (made elsewhere)
    comp <curve> <02 or 03 || x> <04 || x || y>

    python3 scripts/brainpool_vectors.py
"""

import hashlib
import hmac
import os
import random
import shutil
import subprocess
import sys
import tempfile
from collections import Counter

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
rng = random.Random(5639)

# RFC 5639 §3.4, §3.6 and §3.7; oid is the curve's OID's DER contents.
CURVES = {
    "bp256": dict(
        p=0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377,
        a=0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9,
        b=0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6,
        gx=0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262,
        gy=0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997,
        n=0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7,
        size=32, hash="sha256", oid="2b2403030208010107", name="brainpoolP256r1"),
    "bp384": dict(
        p=int("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123"
              "ACD3A729901D1A71874700133107EC53", 16),
        a=int("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F"
              "8AA5814A503AD4EB04A8C7DD22CE2826", 16),
        b=int("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D5"
              "7CB4390295DBC9943AB78696FA504C11", 16),
        gx=int("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8"
               "E826E03436D646AAEF87B2E247D4AF1E", 16),
        gy=int("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF9912928"
               "0E4646217791811142820341263C5315", 16),
        n=int("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7"
              "CF3AB6AF6B7FC3103B883202E9046565", 16),
        size=48, hash="sha384", oid="2b240303020801010b", name="brainpoolP384r1"),
    "bp512": dict(
        p=int("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330871"
              "7D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16),
        a=int("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC"
              "2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", 16),
        b=int("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A7"
              "2BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", 16),
        gx=int("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098E"
               "FF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", 16),
        gy=int("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111"
               "B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", 16),
        n=int("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870"
              "553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16),
        size=64, hash="sha512", oid="2b240303020801010d", name="brainpoolP512r1"),
}

# RFC 7027 Appendix A and RFC 6932 Appendix A.2-A.4: dA, x_qA, y_qA, dB,
# x_qB, y_qB, x_Z (the y_Z of the shared point is checked here only).
DH = [
    ("bp256", "RFC 7027 A.1",
     "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
     "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
     "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
     "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3",
     "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B",
     "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A",
     "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B",
     "49C27868F4ECA2179BFD7D59B1E3BF34C1DBDE61AE12931648F43E59632504DE"),
    ("bp384", "RFC 7027 A.2",
     "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042",
     "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885AB698C852D4A6E77A252D6380FCAF068",
     "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493E0D038FF2FD30C2AB67D15C85F7FAA59",
     "032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F8BA5E0324309DB6A9831497ABAC96670",
     "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE6AD18E404B15738B2086DF37E71D1EB4",
     "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329B5B275903D192F8D4E1F32FE9CC78C48",
     "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BBADF6403715C35D4FB2A5444F575D4F42",
     "0DF213417EBE4D8E40A5F76F66C56470C489A3478D146DECF6DF0D94BAE9E598157290F8756066975F1DB34B2324B7BD"),
    ("bp512", "RFC 7027 A.3",
     "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422",
     "0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C6149999397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD09FD",
     "72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472A0FCEF3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147FDE7",
     "230E18E1BCC88A362FA54E4EA3902009292F7F8033624FD471B5D8ACE49D12CFABBC19963DAB8E2F1EBA00BFFB29E4D72D13F2224562F405CB80503666B25429",
     "9D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FCE8CCBAAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A5473199F",
     "2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB481961D365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B71876285FA",
     "A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF3226244B76D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD1F",
     "7DB71C3DEF63212841C463E881BDCF055523BD368240E6C3143BD8DEF8B3B3223B95E0F53082FF5E412F4222537A43DF1C6D25729DDB51620A832BE6A26680A2"),
    ("bp256", "RFC 6932 A.2",
     "041EB8B1E2BC681BCE8E39963B2E9FC415B05283313DD1A8BCC055F11AE49699",
     "78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",
     "A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",
     "06F5240EACDB9837BC96D48274C8AA834B6C87BA9CC3EEDD81F99A16B8D804D3",
     "8E07E219BA588916C5B06AA30A2F464C2F2ACFC1610A3BE2FB240B635341F0DB",
     "148EA1D7D1E7E54B9555B6C9AC90629C18B63BEE5D7AA6949EBBF47B24FDE40D",
     "05E940915549E9F6A4A75693716E37466ABA79B4BF2919877A16DD2CC2E23708",
     "6BC23B6702BC5A019438CEEA107DAAD8B94232FFBBC350F3B137628FE6FD134C"),
    ("bp384", "RFC 6932 A.3",
     "014EC0755B78594BA47FB0A56F6173045B4331E74BA1A6F47322E70D79D828D97E095884CA72B73FDABD5910DF0FA76A",
     "45CB26E4384DAF6FB776885307B9A38B7AD1B5C692E0C32F0125332778F3B8D3F50CA358099B30DEB5EE69A95C058B4E",
     "8173A1C54AFFA7E781D0E1E1D12C0DC2B74F4DF58E4A4E3AF7026C5D32DC530A2CD89C859BB4B4B768497F49AB8CC859",
     "6B461CB79BD0EA519A87D6828815D8CE7CD9B3CAA0B5A8262CBCD550A015C90095B976F3529957506E1224A861711D54",
     "01BF92A92EE4BE8DED1A911125C209B03F99E3161CFCC986DC7711383FC30AF9CE28CA3386D59E2C8D72CE1E7B4666E8",
     "3289C4A3A4FEE035E39BDB885D509D224A142FF9FBCC5CFE5CCBB30268EE47487ED8044858D31D848F7A95C635A347AC",
     "04CC4FF3DCCCB07AF24E0ACC529955B36D7C807772B92FCBE48F3AFE9A2F370A1F98D3FA73FD0C0747C632E12F1423EC",
     "7F465F90BD69AFB8F828A214EB9716D66ABC59F17AF7C75EE7F1DE22AB5D05085F5A01A9382D05BF72D96698FE3FF64E"),
    ("bp512", "RFC 6932 A.4",
     "636B6BE0482A6C1C41AA7AE7B245E983392DB94CECEA2660A379CFE159559E357581825391175FC195D28BAC0CF03A7841A383B95C262B983782874CCE6FE333",
     "0562E68B9AF7CBFD5565C6B16883B777FF11C199161ECC427A39D17EC2166499389571D6A994977C56AD8252658BA8A1B72AE42F4FB7532151AFC3EF0971CCDA",
     "A7CA2D8191E21776A89860AFBC1F582FAA308D551C1DC6133AF9F9C3CAD59998D70079548140B90B1F311AFB378AA81F51B275B2BE6B7DEE978EFC7343EA642E",
     "0AF4E7F6D52EDD52907BB8DBAB3992A0BB696EC10DF11892FF205B66D381ECE72314E6A6EA079CEA06961DBA5AE6422EF2E9EE803A1F236FB96A1799B86E5C8B",
     "5A7954E32663DFF11AE24712D87419F26B708AC2B92877D6BFEE2BFC43714D89BBDB6D24D807BBD3AEB7F0C325F862E8BADE4F74636B97EAACE739E11720D323",
     "96D14621A9283A1BED84DE8DD64836B2C0758B11441179DC0C54C0D49A47C03807D171DD544B72CAAEF7B7CE01C7753E2CAD1A861ECA55A71954EE1BA35E04BE",
     "1EE8321A4BBF93B9CF8921AB209850EC9B7066D1984EF08C2BB723236208AC8F1A483E79461A00E0D5F6921CE9D360502F85C812BEDEE23AC5B210E5811B191E",
     "2632095B7B936174B41FD2FAF369B1D18DCADEED7E410A7E251F0831097C50D02CFED02607B6A2D5ADB4C00060085622"
     "08631875B58B54ECDA5A4F9FE9EAABA6"),
]


def ec_add(c, P, Q):
    p = c["p"]
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        l = (3 * x1 * x1 + c["a"]) * pow(2 * y1, -1, p) % p
    else:
        l = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (l * l - x1 - x2) % p
    return x3, (l * (x1 - x3) - y1) % p


def ec_mul(c, k, P):
    R = None
    for bit in bin(k)[2:] if k else "":
        R = ec_add(c, R, R)
        if bit == "1":
            R = ec_add(c, R, P)
    return R


def on_curve(c, P):
    x, y = P
    return (y * y - x ** 3 - c["a"] * x - c["b"]) % c["p"] == 0


def gen(c):
    return c["gx"], c["gy"]


def ec_check(c):
    assert on_curve(c, gen(c))
    assert pow(2, c["p"] - 1, c["p"]) == 1 and pow(3, c["n"] - 1, c["n"]) == 1
    assert c["p"] % 4 == 3 and c["n"] < c["p"] < 2 * c["n"]
    assert c["n"].bit_length() == 8 * c["size"]
    assert ec_mul(c, c["n"], gen(c)) is None


def enc(c, P):
    return b"\4" + P[0].to_bytes(c["size"], "big") + P[1].to_bytes(c["size"], "big")


def enc_comp(c, P):
    return bytes([2 | (P[1] & 1)]) + P[0].to_bytes(c["size"], "big")


def dec_comp(c, s):
    p = c["p"]
    x = int.from_bytes(s[1:], "big")
    v = (x ** 3 + c["a"] * x + c["b"]) % p
    y = pow(v, (p + 1) // 4, p)
    assert y * y % p == v
    if y & 1 != s[0] & 1:
        y = p - y
    return x, y


def bits2int(c, b):
    x = int.from_bytes(b, "big")
    if 8 * len(b) > c["n"].bit_length():
        x >>= 8 * len(b) - c["n"].bit_length()
    return x


def rfc6979_k(c, d, h):
    size, hn, n = c["size"], c["hash"], c["n"]
    x = d.to_bytes(size, "big")
    h1 = (bits2int(c, h) % n).to_bytes(size, "big")
    v, k = b"\1" * len(h), b"\0" * len(h)
    for sep in (b"\0", b"\1"):
        k = hmac.new(k, v + sep + x + h1, hn).digest()
        v = hmac.new(k, v, hn).digest()
    while True:
        t = b""
        while len(t) < size:
            v = hmac.new(k, v, hn).digest()
            t += v
        cand = bits2int(c, t)
        if 1 <= cand < n:
            yield cand
        k = hmac.new(k, v + b"\0", hn).digest()
        v = hmac.new(k, v, hn).digest()


def ecdsa_sign(c, d, msg):
    n = c["n"]
    h = hashlib.new(c["hash"], msg).digest()
    e = bits2int(c, h)
    for k in rfc6979_k(c, d, h):
        r = ec_mul(c, k, gen(c))[0] % n
        s = pow(k, -1, n) * (e + r * d) % n
        if r and s:
            return r.to_bytes(c["size"], "big") + s.to_bytes(c["size"], "big")


def ecdsa_verify(c, Q, msg, r, s):
    n = c["n"]
    if not (0 < r < n and 0 < s < n):
        return False
    e = bits2int(c, hashlib.new(c["hash"], msg).digest())
    w = pow(s, -1, n)
    R = ec_add(c, ec_mul(c, e * w % n, gen(c)), ec_mul(c, r * w % n, Q))
    return R is not None and R[0] % n == r


def der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_sig(raw):
    def i(b):
        b = b.lstrip(b"\0") or b"\0"
        if b[0] & 0x80:
            b = b"\0" + b
        return b"\2" + bytes([len(b)]) + b
    half = len(raw) // 2
    body = i(raw[:half]) + i(raw[half:])
    return b"\x30" + der_len(len(body)) + body


def der_unsig(c, der):
    """r and s from a DER signature (only as strictly as openssl writes them)."""
    assert der[0] == 0x30
    at = 3 if der[1] == 0x81 else 2
    out = []
    for _ in range(2):
        assert der[at] == 2
        ln = der[at + 1]
        out.append(int.from_bytes(der[at + 2:at + 2 + ln], "big"))
        at += 2 + ln
    assert at == len(der)
    return out


# --- independent checks -----------------------------------------------------

OPENSSL = shutil.which("openssl")


class OpenSSL:
    def __init__(self):
        self.tmp = tempfile.mkdtemp()
        self.count = 0

    def path(self, name, data=None):
        p = os.path.join(self.tmp, name)
        if data is not None:
            with open(p, "wb") as f:
                f.write(data)
        return p

    def run(self, args, data=None):
        p = subprocess.run([OPENSSL, *args], input=data, capture_output=True)
        if p.returncode != 0:
            raise RuntimeError(f"openssl {' '.join(args)}: {p.stderr.decode()}")
        return p.stdout

    def keys(self, name, d):
        c = CURVES[name]
        oid = bytes.fromhex("06" + format(len(c["oid"]) // 2, "02x") + c["oid"])
        pub = enc(c, ec_mul(c, d, gen(c)))
        bits = b"\3" + der_len(len(pub) + 1) + b"\0" + pub
        body = (b"\2\1\1" + b"\4" + bytes([c["size"]]) + d.to_bytes(c["size"], "big")
                + b"\xa0" + der_len(len(oid)) + oid + b"\xa1" + der_len(len(bits)) + bits)
        der = self.path("k.der", b"\x30" + der_len(len(body)) + body)
        pem = self.path(f"{name}-{d % 100000}.pem")
        self.run(["pkey", "-inform", "DER", "-in", der, "-out", pem])
        pubpem = pem + ".pub"
        self.run(["pkey", "-in", pem, "-pubout", "-out", pubpem])
        return pem, pubpem

    def ecdh(self, name, d1, d2, shared):
        pem, _ = self.keys(name, d1)
        _, pub2 = self.keys(name, d2)
        assert self.run(["pkeyutl", "-derive", "-inkey", pem, "-peerkey", pub2]) == shared, \
            "openssl disagrees on ECDH"
        self.count += 1

    def verify(self, name, d, msg, der):
        _, pub = self.keys(name, d)
        out = self.run(["dgst", "-" + CURVES[name]["hash"], "-verify", pub, "-signature",
                        self.path("sig.der", der), self.path("msg", msg)])
        assert b"Verified OK" in out, "openssl rejects an ECDSA signature"
        self.count += 1

    def sign(self, name, d, msg):
        pem, _ = self.keys(name, d)
        return self.run(["dgst", "-" + CURVES[name]["hash"], "-sign", pem, self.path("msg", msg)])

    def done(self):
        shutil.rmtree(self.tmp)


def optional(module):
    try:
        return __import__(module)
    except ImportError:
        return None


def main():
    ecdsa_pkg = optional("ecdsa")
    crypto = optional("cryptography")
    if crypto:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec as cec
        CC = {"bp256": cec.BrainpoolP256R1(), "bp384": cec.BrainpoolP384R1(), "bp512": cec.BrainpoolP512R1()}
        CH = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}
    if ecdsa_pkg:
        from ecdsa.util import sigencode_string
        EC = {"bp256": ecdsa_pkg.BRAINPOOLP256r1, "bp384": ecdsa_pkg.BRAINPOOLP384r1,
              "bp512": ecdsa_pkg.BRAINPOOLP512r1}
    ossl = OpenSSL() if OPENSSL else None
    others = Counter()
    lines = []

    for name, c in CURVES.items():
        ec_check(c)
    for name, src, da, xa, ya, db, xb, yb, xz, yz in DH:
        c = CURVES[name]
        da, xa, ya, db, xb, yb, xz, yz = (int(v, 16) for v in (da, xa, ya, db, xb, yb, xz, yz))
        assert ec_mul(c, da, gen(c)) == (xa, ya), src
        assert ec_mul(c, db, gen(c)) == (xb, yb), src
        assert ec_mul(c, da, (xb, yb)) == (xz, yz) == ec_mul(c, db, (xa, ya)), src
        size = c["size"]
        lines.append(f"ecdh {name} {da.to_bytes(size, 'big').hex()} {enc(c, (xb, yb)).hex()} "
                     f"{xz.to_bytes(size, 'big').hex()}")
        lines.append(f"ecdh {name} {db.to_bytes(size, 'big').hex()} {enc(c, (xa, ya)).hex()} "
                     f"{xz.to_bytes(size, 'big').hex()}")

    for name, c in CURVES.items():
        n, size, G = c["n"], c["size"], gen(c)
        ks = [1, 2, 3, n - 2, n - 1] + [rng.randrange(1, n) for _ in range(5)]
        for k in ks:
            P = ec_mul(c, k, G)
            lines.append(f"mul {name} {format(k, 'x')} {enc(c, P).hex()}")
            assert dec_comp(c, enc_comp(c, P)) == P
            lines.append(f"comp {name} {enc_comp(c, P).hex()} {enc(c, P).hex()}")
            if ecdsa_pkg:
                vk = ecdsa_pkg.SigningKey.from_secret_exponent(k, curve=EC[name]).get_verifying_key()
                assert vk.to_string("compressed") == enc_comp(c, P)
                assert vk.to_string("uncompressed") == enc(c, P)
                others["ecdsa: points"] += 1
        for _ in range(4):
            d1, d2 = rng.randrange(1, n), rng.randrange(1, n)
            shared = ec_mul(c, d1, ec_mul(c, d2, G))[0].to_bytes(size, "big")
            p2 = enc(c, ec_mul(c, d2, G))
            if ossl:
                ossl.ecdh(name, d1, d2, shared)
            if crypto:
                k1 = cec.derive_private_key(d1, CC[name])
                k2 = cec.derive_private_key(d2, CC[name])
                assert k1.exchange(cec.ECDH(), k2.public_key()) == shared
                others["cryptography: ECDH"] += 1
            lines.append(f"ecdh {name} {d1.to_bytes(size, 'big').hex()} {p2.hex()} {shared.hex()}")
        msgs = [b"", b"sample", b"test", bytes(rng.getrandbits(8) for _ in range(100))]
        for i, msg in enumerate(msgs):
            d = rng.randrange(1, n)
            pub = enc(c, ec_mul(c, d, G))
            raw = ecdsa_sign(c, d, msg)
            der = der_sig(raw)
            assert ecdsa_verify(c, ec_mul(c, d, G), msg, int.from_bytes(raw[:size], "big"),
                                int.from_bytes(raw[size:], "big"))
            if ossl:
                ossl.verify(name, d, msg, der)
            if ecdsa_pkg:
                sk = ecdsa_pkg.SigningKey.from_secret_exponent(d, curve=EC[name],
                                                               hashfunc=getattr(hashlib, c["hash"]))
                assert sk.sign_deterministic(msg, sigencode=sigencode_string) == raw, \
                    "the ecdsa package's RFC 6979 signature differs"
                others["ecdsa: RFC 6979 signatures"] += 1
            if crypto:
                pk = cec.derive_private_key(d, CC[name]).public_key()
                pk.verify(der, msg, cec.ECDSA(CH[c["hash"]]))
                others["cryptography: verify"] += 1
            lines.append(f"ecdsa {name} {d.to_bytes(size, 'big').hex()} {pub.hex()} {msg.hex() or '-'} "
                         f"{raw.hex()} {der.hex()}")
            # Signatures made by openssl and cryptography, with random nonces.
            made = []
            if ossl:
                made.append(ossl.sign(name, d, msg))
            if crypto:
                made.append(cec.derive_private_key(d, CC[name]).sign(msg, cec.ECDSA(CH[c["hash"]])))
                others["cryptography: signatures"] += 1
            elif ossl:
                made.append(ossl.sign(name, d, msg))      # as many lines either way
            for sig in made:
                r, s = der_unsig(c, sig)
                assert ecdsa_verify(c, ec_mul(c, d, G), msg, r, s)
                lines.append(f"verify {name} {pub.hex()} {msg.hex() or '-'} {sig.hex()}")

    out = os.path.join(ROOT, "test", "vectors", "brainpool.txt")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {os.path.relpath(out, ROOT)}: {len(lines)} lines; RFC 7027 and RFC 6932 ECDH vectors match")
    if ossl:
        print(f"openssl agreed on {ossl.count} vectors")
        ossl.done()
    else:
        print("no openssl: not cross-checked by it")
    for k, v in sorted(others.items()):
        print(f"{k}: {v} agreed")
    if not ecdsa_pkg or not crypto:
        print("(the ecdsa and cryptography packages were not both importable: those checks skipped)",
              file=sys.stderr)


if __name__ == "__main__":
    main()
