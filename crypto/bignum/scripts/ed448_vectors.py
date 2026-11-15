#!/usr/bin/env python3
"""Vectors for X448 (RFC 7748) and Ed448 (RFC 8032 §5.2): test/vectors/x448.txt
and test/vectors/ed448.txt.

Transcriptions of both RFCs on Python integers, checked here against the
RFCs' own vectors (RFC 7748 §5.2 and §6.2; all of RFC 8032 §7.4 and §7.5).
The random vectors are then checked against the openssl command when it
is installed: keys from openssl genpkey and from Python's random stream,
signatures (Ed448 and Ed448ph, with and without contexts) remade by
openssl pkeyutl -sign -rawin, and X448 secrets by pkeyutl -derive. Without
openssl the transcriptions alone make the files. The keys from genpkey are
fresh each run, so the files change when regenerated.

x448.txt:

    x448 <scalar> <u> <result>          56-byte little-endian hex

ed448.txt (ph 1 is Ed448ph; the message is the message itself, which the
test prehashes with SHAKE256 to 64 bytes):

    ed448 <ph> <seed> <msg|-> <ctx|-> <public key> <signature>

    python3 scripts/ed448_vectors.py
"""

import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile

rng = random.Random(20261114)
OPENSSL = shutil.which("openssl")


def hx(b):
    return b.hex() if b else "-"


def rbytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


# --- X448 (RFC 7748 §5) -----------------------------------------------------

P = 2 ** 448 - 2 ** 224 - 1


def x448(k, u):
    k = bytearray(k)
    k[0] &= 252
    k[55] |= 128
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") % P
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(448)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 39081 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(56, "little")


X448_RFC = [
    ("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
     "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
     "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"),
    ("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
     "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
     "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"),
]
for k, u, r in X448_RFC:
    assert x448(bytes.fromhex(k), bytes.fromhex(u)).hex() == r
_FIVE = bytes([5]) + bytes(55)
assert x448(_FIVE, _FIVE).hex() == ("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a"
                                    "4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113")
_ALICE = bytes.fromhex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
                       "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
_BOB_PUB = bytes.fromhex("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
                         "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609")
assert x448(_ALICE, _BOB_PUB).hex() == ("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
                                        "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")


# --- Ed448 (RFC 8032 §5.2) --------------------------------------------------

ED_D = P - 39081
ED_L = 2 ** 446 - 13818066809895115352007386748515426880336692474882178609894547503885
ED_GY = 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660


def ed_recover_x(y, sign):
    xx = (y * y - 1) * pow(ED_D * y * y - 1, P - 2, P) % P
    x = pow(xx, (P + 1) // 4, P)
    if x * x % P != xx:
        return None
    if x == 0 and sign:
        return None
    return P - x if x & 1 != sign else x


ED_G = (ed_recover_x(ED_GY, 0), ED_GY, 1)


def ed_add(p, q):
    # Projective (X : Y : Z), RFC 8032 §5.2.4; complete, so it doubles too.
    (x1, y1, z1), (x2, y2, z2) = p, q
    a = z1 * z2 % P
    b = a * a % P
    c = x1 * x2 % P
    d = y1 * y2 % P
    e = ED_D * c * d % P
    f, g = (b - e) % P, (b + e) % P
    h = (x1 + y1) * (x2 + y2) % P
    return (a * f * (h - c - d) % P, a * g * (d - c) % P, f * g % P)


def ed_mul(k, p):
    r = (0, 1, 1)
    while k:
        if k & 1:
            r = ed_add(r, p)
        p = ed_add(p, p)
        k >>= 1
    return r


def ed_affine(p):
    zi = pow(p[2], P - 2, P)
    return (p[0] * zi % P, p[1] * zi % P)


def ed_encode(p):
    x, y = ed_affine(p)
    return (y | (x & 1) << 455).to_bytes(57, "little")


def ed_decode(s):
    if len(s) != 57:
        return None
    v = int.from_bytes(s, "little")
    y, sign = v & ((1 << 455) - 1), v >> 455
    if y >= P:
        return None
    x = ed_recover_x(y, sign)
    return None if x is None else (x, y, 1)


def shake(data, n):
    return hashlib.shake_256(data).digest(n)


def dom4(ph, ctx):
    return b"SigEd448" + bytes([ph, len(ctx)]) + ctx


def ed_secret(seed):
    h = shake(seed, 114)
    a = bytearray(h[:57])
    a[0] &= 252
    a[56] = 0
    a[55] |= 128
    return int.from_bytes(a, "little"), h[57:]


def ed448_public(seed):
    return ed_encode(ed_mul(ed_secret(seed)[0], ED_G))


def ed448_sign(seed, msg, ctx=b"", ph=0):
    if ph:
        msg = shake(msg, 64)
    a, prefix = ed_secret(seed)
    A = ed_encode(ed_mul(a, ED_G))
    dom = dom4(ph, ctx)
    r = int.from_bytes(shake(dom + prefix + msg, 114), "little") % ED_L
    R = ed_encode(ed_mul(r, ED_G))
    k = int.from_bytes(shake(dom + R + A + msg, 114), "little") % ED_L
    return R + ((r + k * a) % ED_L).to_bytes(57, "little")


def ed448_verify(pk, msg, sig, ctx=b"", ph=0):
    if len(sig) != 114 or len(ctx) > 255:
        return False
    A, R = ed_decode(pk), ed_decode(sig[:57])
    s = int.from_bytes(sig[57:], "little")
    if A is None or R is None or s >= ED_L:
        return False
    if ph:
        msg = shake(msg, 64)
    k = int.from_bytes(shake(dom4(ph, ctx) + sig[:57] + pk + msg, 114), "little") % ED_L
    lhs = ed_mul(4 * s, ED_G)
    rhs = ed_mul(4, ed_add(R, ed_mul(k, A)))
    return ed_affine(lhs) == ed_affine(rhs)


assert ed_affine(ed_mul(ED_L, ED_G)) == (0, 1)


# RFC 8032 §7.4 (Ed448) and §7.5 (Ed448ph): name, ph, secret key,
# public key, message, context, signature.
RFC8032 = [
    ('Blank', 0,
     "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f"
     "032e7549a20098f95b",
     "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6c"
     "d1fa1abeafe8256180",
     "",
     "",
     "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d78"
     "28c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db"
     "b61149f05a7363268c71d95808ff2e652600"),
    ('1 octet', 0,
     "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949e"
     "f8021e954e0a12274e",
     "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c"
     "235160627b4c3a9480",
     "03",
     "",
     "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633"
     "fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f"
     "f3348ab21aa4adafd1d234441cf807c03a00"),
    ('1 octet (with context)', 0,
     "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949e"
     "f8021e954e0a12274e",
     "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c"
     "235160627b4c3a9480",
     "03",
     "666f6f",
     "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d60721"
     "7fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d"
     "5428407e85dcbc98a49155c13764e66c3c00"),
    ('11 octets', 0,
     "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4cc"
     "d67e187951267eb328",
     "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f"
     "1d8b00696447001400",
     "0c3e544074ec63b0265e0c",
     "",
     "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d"
     "961a29fe0109941e00b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5"
     "028961c9bf8ffd973fe5d5c206492b140e00"),
    ('12 octets', 0,
     "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dc"
     "cb52c1c5fd2ff7e21b",
     "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726b"
     "d75e149ef09817f580",
     "64a65f3cdedcdd66811e2915",
     "",
     "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07"
     "fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861"
     "e72003cbae6d6b8b827e4e6c143064ff3c00"),
    ('13 octets', 0,
     "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eeb"
     "c0266a11a93970100e",
     "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c0"
     "7b174be65dfa578e80",
     "64a65f3cdedcdd66811e2915e7",
     "",
     "6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a8317"
     "6c0d7323a2ccde2d80efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf5"
     "6b4e7e0ba5519234d047155ac727a1053100"),
    ('64 octets', 0,
     "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fa"
     "b4fa135d5542ea3f01",
     "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb5"
     "0906cb28bd8a081f00",
     "bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb31"
     "12182da3005835461113718d1a5ef944",
     "",
     "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058"
     "efc9f40d2ca033a0801b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba"
     "5f30e88e36ec2703b349ca229c2670833900"),
    ('256 octets', 0,
     "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590a"
     "a9cebca9014c636df5",
     "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e"
     "7690862ef3d4ed3a00",
     "15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f31745041"
     "07ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072f"
     "c1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a6039c3c2a39f0e4d832be432dfa9a706a6"
     "e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce0"
     "12d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7"
     "a69ccce38fabdf86f3bef6044819de11",
     "",
     "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28"
     "743954e3a44a23f880e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc6"
     "0987fd08527c1a8e80d5823e65cafe2a3d00"),
    ('1023 octets', 0,
     "872d093780f5d3730df7c212664b37b8a0f24f56810daa8382cd4fa3f77634ec44dc54f1c2ed9bea86fafb7632d8be19"
     "9ea165f5ad55dd9ce8",
     "a81b2e8a70a5ac94ffdbcc9badfc3feb0801f258578bb114ad44ece1ec0e799da08effb81c5d685c0c56f64eecaef8cd"
     "f11cc38737838cf400",
     "6ddf802e1aae4986935f7f981ba3f0351d6273c0a0c22c9c0e8339168e675412a3debfaf435ed651558007db4384b650"
     "fcc07e3b586a27a4f7a00ac8a6fec2cd86ae4bf1570c41e6a40c931db27b2faa15a8cedd52cff7362c4e6e23daec0fbc"
     "3a79b6806e316efcc7b68119bf46bc76a26067a53f296dafdbdc11c77f7777e972660cf4b6a9b369a6665f02e0cc9b6e"
     "dfad136b4fabe723d2813db3136cfde9b6d044322fee2947952e031b73ab5c603349b307bdc27bc6cb8b8bbd7bd32321"
     "9b8033a581b59eadebb09b3c4f3d2277d4f0343624acc817804728b25ab797172b4c5c21a22f9c7839d64300232eb66e"
     "53f31c723fa37fe387c7d3e50bdf9813a30e5bb12cf4cd930c40cfb4e1fc622592a49588794494d56d24ea4b40c89fc0"
     "596cc9ebb961c8cb10adde976a5d602b1c3f85b9b9a001ed3c6a4d3b1437f52096cd1956d042a597d561a596ecd3d173"
     "5a8d570ea0ec27225a2c4aaff26306d1526c1af3ca6d9cf5a2c98f47e1c46db9a33234cfd4d81f2c98538a09ebe76998"
     "d0d8fd25997c7d255c6d66ece6fa56f11144950f027795e653008f4bd7ca2dee85d8e90f3dc315130ce2a00375a318c7"
     "c3d97be2c8ce5b6db41a6254ff264fa6155baee3b0773c0f497c573f19bb4f4240281f0b1f4f7be857a4e59d416c06b4"
     "c50fa09e1810ddc6b1467baeac5a3668d11b6ecaa901440016f389f80acc4db977025e7f5924388c7e340a732e554440"
     "e76570f8dd71b7d640b3450d1fd5f0410a18f9a3494f707c717b79b4bf75c98400b096b21653b5d217cf3565c9597456"
     "f70703497a078763829bc01bb1cbc8fa04eadc9a6e3f6699587a9e75c94e5bab0036e0b2e711392cff0047d0d6b05bd2"
     "a588bc109718954259f1d86678a579a3120f19cfb2963f177aeb70f2d4844826262e51b80271272068ef5b3856fa8535"
     "aa2a88b2d41f2a0e2fda7624c2850272ac4a2f561f8f2f7a318bfd5caf9696149e4ac824ad3460538fdc25421beec2cc"
     "6818162d06bbed0c40a387192349db67a118bada6cd5ab0140ee273204f628aad1c135f770279a651e24d8c14d75a605"
     "9d76b96a6fd857def5e0b354b27ab937a5815d16b5fae407ff18222c6d1ed263be68c95f32d908bd895cd76207ae7264"
     "87567f9a67dad79abec316f683b17f2d02bf07e0ac8b5bc6162cf94697b3c27cd1fea49b27f23ba2901871962506520c"
     "392da8b6ad0d99f7013fbc06c2c17a569500c8a7696481c1cd33e9b14e40b82e79a5f5db82571ba97bae3ad3e0479515"
     "bb0e2b0f3bfcd1fd33034efc6245eddd7ee2086ddae2600d8ca73e214e8c2b0bdb2b047c6a464a562ed77b73d2d841c4"
     "b34973551257713b753632efba348169abc90a68f42611a40126d7cb21b58695568186f7e569d2ff0f9e745d0487dd2e"
     "b997cafc5abf9dd102e62ff66cba87",
     "",
     "e301345a41a39a4d72fff8df69c98075a0cc082b802fc9b2b6bc503f926b65bddf7f4c8f1cb49f6396afc8a70abe6d8a"
     "ef0db478d4c6b2970076c6a0484fe76d76b3a97625d79f1ce240e7c576750d295528286f719b413de9ada3e8eb78ed57"
     "3603ce30d8bb761785dc30dbc320869e1a00"),
    ('TEST abc', 1,
     "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3"
     "ab2cec7c867c6e2c49",
     "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276"
     "d5ed3d5d01c0f53880",
     "616263",
     "",
     "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd"
     "78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3"
     "ad203df7dc7ce360c3cd3696d9d9fab90f00"),
    ('TEST abc (with context)', 1,
     "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3"
     "ab2cec7c867c6e2c49",
     "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276"
     "d5ed3d5d01c0f53880",
     "616263",
     "666f6f",
     "c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa481065b1580423ef927ecf0af5888f90da"
     "0f6a9a85ad5dc3f280d91224ba9911a3653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab7128"
     "4f8d0704a608c54a6b62d97beb511d132100"),
]
for _name, _ph, _sk, _pk, _msg, _ctx, _sig in RFC8032:
    _sk, _msg, _ctx = bytes.fromhex(_sk), bytes.fromhex(_msg), bytes.fromhex(_ctx)
    assert ed448_public(_sk).hex() == _pk, _name
    assert ed448_sign(_sk, _msg, _ctx, _ph).hex() == _sig, _name
    assert ed448_verify(bytes.fromhex(_pk), _msg, bytes.fromhex(_sig), _ctx, _ph), _name


# --- openssl ----------------------------------------------------------------

ED448_PKCS8 = bytes.fromhex("3047020100300506032b6571043b0439")
X448_PKCS8 = bytes.fromhex("3046020100300506032b656f043a0438")
X448_SPKI = bytes.fromhex("3042300506032b656f033900")


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

    def run(self, args):
        p = subprocess.run([OPENSSL, *args], capture_output=True)
        if p.returncode != 0:
            raise RuntimeError(f"openssl {' '.join(args)}: {p.stderr.decode()}")
        return p.stdout

    def genkey(self, alg, prefix):
        der = self.run(["genpkey", "-algorithm", alg, "-outform", "DER"])
        assert der.startswith(prefix)
        return der[len(prefix):]

    def pem(self, name, der):
        out = self.path(name + ".pem")
        self.run(["pkey", "-inform", "DER", "-in", self.path(name + ".der", der), "-out", out])
        return out

    def ed448(self, seed, pk, msg, ctx, ph, sig):
        key = self.pem("ed", ED448_PKCS8 + seed)
        assert self.run(["pkey", "-in", key, "-pubout", "-outform", "DER"])[-57:] == pk, "openssl: Ed448 key"
        opts = ["-pkeyopt", "instance:" + ("Ed448ph" if ph else "Ed448")]
        if ctx:
            opts += ["-pkeyopt", f"hexcontext-string:{ctx.hex()}"]
        got = self.run(["pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", self.path("m", msg), *opts])
        assert got == sig, "openssl disagrees on Ed448"
        self.count += 1

    def x448(self, k, u, r):
        key = self.pem("x", X448_PKCS8 + k)
        peer = self.path("peer.pem")
        self.run(["pkey", "-pubin", "-inform", "DER", "-in", self.path("peer.der", X448_SPKI + u), "-out", peer])
        got = self.run(["pkeyutl", "-derive", "-inkey", key, "-peerkey", peer])
        assert got == r, "openssl disagrees on X448"
        self.count += 1


# --- the files --------------------------------------------------------------

def generate():
    chk = OpenSSL() if OPENSSL else None
    xs = []
    for k, u, r in X448_RFC:
        xs.append(f"x448 {k} {u} {r}")
    # u at and past p (taken mod p, RFC 7748 §5), and random ones; scalars
    # from openssl and from the random stream.
    specials = [P - 1, P, P + 1, P + 5, 2 ** 448 - 1, 2 ** 224, 2 ** 447]
    for i in range(32):
        if chk and i % 4 == 0:
            k = chk.genkey("x448", X448_PKCS8)
        else:
            k = rbytes(56)
        if i < len(specials):
            u = specials[i].to_bytes(56, "little")
        elif i % 3 == 0:
            u = x448(rbytes(56), _FIVE)                  # a public key
        else:
            u = rbytes(56)
        r = x448(k, u)
        if chk and any(r):
            chk.x448(k, u, r)
        xs.append(f"x448 {k.hex()} {u.hex()} {r.hex()}")
    eds = []
    for name, ph, sk, pk, msg, ctx, sig in RFC8032:
        eds.append(f"ed448 {ph} {sk} {msg or '-'} {ctx or '-'} {pk} {sig}")
    for i in range(32):
        seed = chk.genkey("ed448", ED448_PKCS8) if chk and i % 4 == 0 else rbytes(57)
        msg = rbytes(rng.choice([0, 1, 31, 57, 64, 113, 114, 136, 137, 300]))
        ctx = rbytes(rng.choice([0, 0, 1, 8, 255])) if i % 2 else b""
        ph = 1 if i % 5 == 2 else 0
        pk = ed448_public(seed)
        sig = ed448_sign(seed, msg, ctx, ph)
        assert ed448_verify(pk, msg, sig, ctx, ph)
        if chk:
            chk.ed448(seed, pk, msg, ctx, ph, sig)
        eds.append(f"ed448 {ph} {seed.hex()} {hx(msg)} {hx(ctx)} {pk.hex()} {sig.hex()}")
    if chk:
        print(f"openssl agreed on {chk.count} vectors")
    else:
        print("no openssl: vectors from the transcriptions alone")
    return {"x448.txt": xs, "ed448.txt": eds}


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(__file__))
    import gen_vectors
    for name, lines in generate().items():
        gen_vectors.write(name, lines)
