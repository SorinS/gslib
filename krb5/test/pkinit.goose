// krb5.pkinit's parts that need no KDC: octetstring2key against RFC 4556
// Appendix B's four sets; RFC 8636's KDF against its §8 vectors (SHA-1,
// SHA-256, SHA-512); Diffie-Hellman in each group, both sides agreeing,
// and the KDC values refused (0, 1, p-1, outside the subgroup, too long,
// not a point); the groups of a TD-DH-PARAMETERS list; PA-PK-AS-REP and
// KDCDHKeyInfo decoding, refusals included; TYPED-DATA. Then replies
// signed here as a KDC would sign them, with the certificates and key of
// vectors/pkinit.txt (scripts/pkinit_vectors.py, from OpenSSL): the reply
// key must be the KDC's, by each KDF and by octetstring2key; a wrong
// nonce, content type, signer, realm, time or KDF must be refused, the
// KDC named by host only with pkinit_kdc_hostname and its EKU; and
// PA-PKINIT-KX checked. The exchange itself is scripts/interop.py's,
// against MIT's KDC.

import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.pkinit;
import gslib.encoding.asn1;
import gslib.crypto.bignum;
import gslib.crypto.bignum.ffdh;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.cms;
import tv;

fn repeat(b: u8, n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.resize(n, b);
    return out;
}

// 00 01 .. 10 00 01 ..: Appendix B's sets 3 and 4.
fn cycle17(n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    for i in n { out.push((i % 17) as! u8); }
    return out;
}

fn octetstring2key_vectors() {
    let k1 = krb5::pkinit_octetstring2key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, repeat(0, 256));
    tv::check_hex("octetstring2key set 1", k1.value, "5ee50d675c809fe59e4a7762c54b65837547eafb159bd8cdc75ffca5911e4c41");
    let k2 = krb5::pkinit_octetstring2key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, repeat(0, 128));
    tv::check_hex("octetstring2key set 2", k2.value, "acf7707c08973ddfdb27cd361442ccfba355c8884cb472f37da636d07d56787e");
    let k3 = krb5::pkinit_octetstring2key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, cycle17(128));
    tv::check_hex("octetstring2key set 3", k3.value, "c442da585fcb80e43b47946f254093e37329d99001380db78371db3acf5c797e");
    let k4 = krb5::pkinit_octetstring2key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, cycle17(77));
    tv::check_hex("octetstring2key set 4", k4.value, "0053953b84c896f4eb385c3f2e751c4a590ed6ffadca6ff64f47ebeb8d780ffc");
    // An AES128 key is the first 16 bytes of the same stream.
    let k5 = krb5::pkinit_octetstring2key(krb5::ETYPE_AES128_CTS_HMAC_SHA1_96, repeat(0, 256));
    tv::check_hex("octetstring2key aes128", k5.value, "5ee50d675c809fe59e4a7762c54b6583");
}

fn kdf_vectors() {
    let z = repeat(0, 256);
    let client = krb5::principal_name(krb5::NT_PRINCIPAL, "lha");
    let server = krb5::principal_name(krb5::NT_PRINCIPAL, krb5::name_join("krbtgt", "SU.SE"));
    let as_req = repeat(0xaa, 10);
    let rep = repeat(0xbb, 9);
    let oi1 = krb5::pkinit_other_info(160, client, "SU.SE", server, "SU.SE", 18, as_req, rep);
    let k1 = krb5::pkinit_kdf(160, krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, z, oi1);
    tv::check_hex("RFC 8636 SHA-1, aes256", k1.value, "e6ab38c9413e035bb079201ed0b6b73d8d49a814a737c04ee6649614206f73ad");
    let oi2 = krb5::pkinit_other_info(256, client, "SU.SE", server, "SU.SE", 18, as_req, rep);
    let k2 = krb5::pkinit_kdf(256, krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, z, oi2);
    tv::check_hex("RFC 8636 SHA-256, aes256", k2.value, "77ef4e48c420ae3fec75109d7981697eed5d295c90c62564f7bfd101fa9bc1d5");
    // des3: the vector's "key-material" is the key itself (random-to-key
    // of the stream's first 21 bytes), 24 bytes; the "32" it states is wrong.
    let oi3 = krb5::pkinit_other_info(512, client, "SU.SE", server, "SU.SE", 16, as_req, rep);
    let k3 = krb5::pkinit_kdf(512, krb5::ETYPE_DES3_CBC_SHA1_KD, z, oi3);
    tv::check_hex("RFC 8636 SHA-512, des3", k3.value, "d3c78a79d65213efe9a826f75dfb01f72362fb16fb01dad6");
}

// The public value our SPKI carries (the BIT STRING's content).
fn spki_value(spki: const u8[:]) -> u8[>..] {
    let t, ok = asn1::parse(spki);
    let p, okp = asn1::children(spki, t);
    let bits, unused, okb = asn1::read_bits(spki, p[1]);
    return bits;
}

fn spki_alg(spki: const u8[:]) -> u8[>..] {
    let t, ok = asn1::parse(spki);
    let p, okp = asn1::children(spki, t);
    var out: u8[>..] = [];
    out.append(spki[p[0].start..p[0].end]);
    return out;
}

fn int_der(mag: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    asn1::put_uint(out, mag);
    return out;
}

fn dh_groups() {
    let gs: i64[5] = [krb5::PKINIT_MODP2048, krb5::PKINIT_P256, krb5::PKINIT_MODP4096, krb5::PKINIT_P384, krb5::PKINIT_P521];
    let names: const u8[:][5] = ["2048", "P-256", "4096", "P-384", "P-521"];
    for i in 5 {
        let g = gs[i];
        tv::check_int(str("group named ", names[i]), krb5::pkinit_group_named(names[i]), g);
        let a = krb5::pkinit_dh_new(g);
        let b = krb5::pkinit_dh_new(g);
        // The SPKI's algorithm names the group.
        let alg = spki_alg(a.spki);
        let at, okat = asn1::parse(alg);
        tv::check_int(str("group of SPKI ", names[i]), krb5::pkinit_group_of(alg, at), g);
        let za, oka = krb5::pkinit_dh_shared(a, spki_value(b.spki));
        let zb, okb = krb5::pkinit_dh_shared(b, spki_value(a.spki));
        tv::check(str("shared secret ", names[i]), oka && okb && za == zb && za.len > 0);
        if krb5::pkinit_is_ec(g) {
            tv::check_int(str("x-coordinate length ", names[i]), za.len, if g == krb5::PKINIT_P256 { 32 } else if g == krb5::PKINIT_P384 { 48 } else { 66 });
            var bad = spki_value(b.spki);
            bad[bad.len - 1] ^= 1;
            let zx, okx = krb5::pkinit_dh_shared(a, bad);
            tv::check(str("point off the curve ", names[i]), !okx);
            continue;
        }
        let p = krb5::pkinit_prime(g);
        tv::check_int(str("secret padded ", names[i]), za.len, p.len);
        let one: u8[1] = [1];
        let zero: u8[1] = [0];
        var pm1: u8[>..] = [];
        pm1.append(p);
        pm1[pm1.len - 1] -= 1;
        var pm2: u8[>..] = [];
        pm2.append(p);
        pm2[pm2.len - 1] -= 2;
        var long: u8[>..] = [];
        long.push(1);
        long.append(p);
        let z1, ok1 = krb5::pkinit_dh_shared(a, int_der(one));
        let z0, ok0 = krb5::pkinit_dh_shared(a, int_der(zero));
        let zp1, okp1 = krb5::pkinit_dh_shared(a, int_der(pm1));
        let zp2, okp2 = krb5::pkinit_dh_shared(a, int_der(pm2));
        let zl, okl = krb5::pkinit_dh_shared(a, int_der(long));
        tv::check(str("KDC values refused ", names[i]), !ok1 && !ok0 && !okp1 && !okl);
        // p - 2 = -2: -1 is not a square mod p (p = 3 mod 4) and 2 is, so
        // -2 is outside the subgroup of order q.
        tv::check(str("outside the subgroup ", names[i]), !okp2);
        // Not an INTEGER.
        var octets: u8[>..] = [];
        asn1::put_octets(octets, spki_value(b.spki)[2..]);
        let zo, oko = krb5::pkinit_dh_shared(a, octets);
        tv::check(str("not an INTEGER ", names[i]), !oko);
    }
    tv::check_int("1024 taken as 2048", krb5::pkinit_group_named("1024"), krb5::PKINIT_MODP2048);
    // TD-DH-PARAMETERS: the KDC's order, our minimum.
    var list: u8[>..] = [];
    list.append(spki_alg(krb5::pkinit_dh_new(krb5::PKINIT_MODP2048).spki));
    list.append(spki_alg(krb5::pkinit_dh_new(krb5::PKINIT_P521).spki));
    list.append(spki_alg(krb5::pkinit_dh_new(krb5::PKINIT_MODP4096).spki));
    var td: u8[>..] = [];
    asn1::put(td, asn1::SEQUENCE, list);
    tv::check_int("TD-DH-PARAMETERS first", krb5::pkinit_pick_group(td, krb5::PKINIT_MODP2048), krb5::PKINIT_MODP2048);
    tv::check_int("TD-DH-PARAMETERS at least P-256", krb5::pkinit_pick_group(td, krb5::PKINIT_P256), krb5::PKINIT_P521);
    tv::check_int("TD-DH-PARAMETERS none strong enough", krb5::pkinit_pick_group("\x30\x00", krb5::PKINIT_P256), 0);
}

// DHRepInfo, built as a KDC would.
fn pk_as_rep(signed: const u8[:], nonce: bool, kdf: const u8[:]) -> u8[>..] {
    var body: u8[>..] = [];
    asn1::put(body, asn1::ctx(0, false), signed);
    if nonce {
        var n: u8[>..] = [];
        asn1::put_octets(n, "nonce");
        asn1::put(body, asn1::ctx(1, true), n);
    }
    if kdf.len > 0 {
        var oid: u8[>..] = [];
        asn1::put_oid(oid, kdf);
        var id: u8[>..] = [];
        asn1::put(id, asn1::ctx(0, true), oid);
        var ids: u8[>..] = [];
        asn1::put(ids, asn1::SEQUENCE, id);
        asn1::put(body, asn1::ctx(2, true), ids);
    }
    var seq: u8[>..] = [];
    asn1::put(seq, asn1::SEQUENCE, body);
    var out: u8[>..] = [];
    asn1::put(out, asn1::ctx(0, true), seq);
    return out;
}

fn messages() {
    let r1, e1 = krb5::decode_pa_pk_as_rep(pk_as_rep("signed", false, ""));
    tv::check("PA-PK-AS-REP, no KDF", e1 == krb5::OK && r1.signed_data == "signed" && r1.kdf == -1);
    let r2, e2 = krb5::decode_pa_pk_as_rep(pk_as_rep("signed", false, "1.3.6.1.5.2.3.6.2"));
    tv::check("PA-PK-AS-REP, SHA-256 KDF", e2 == krb5::OK && r2.kdf == 256);
    let r3, e3 = krb5::decode_pa_pk_as_rep(pk_as_rep("signed", false, "1.3.6.1.5.2.3.6.9"));
    tv::check("PA-PK-AS-REP, unknown KDF", e3 == krb5::OK && r3.kdf == -3);
    let r4, e4 = krb5::decode_pa_pk_as_rep(pk_as_rep("signed", true, ""));
    tv::check("PA-PK-AS-REP, serverDHNonce refused", e4 == krb5::ERR_MALFORMED);
    var ekp: u8[>..] = [];
    asn1::put(ekp, asn1::ctx(1, false), "enveloped");
    let r5, e5 = krb5::decode_pa_pk_as_rep(ekp);
    tv::check("PA-PK-AS-REP, encKeyPack", e5 == krb5::KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED);
    let r6, e6 = krb5::decode_pa_pk_as_rep("\x30\x00");
    tv::check("PA-PK-AS-REP, not a choice", e6 == krb5::ERR_MALFORMED);

    // KDCDHKeyInfo.
    var bits: u8[>..] = [];
    asn1::put_bits(bits, "\x02\x01\x07");
    var body: u8[>..] = [];
    asn1::put(body, asn1::ctx(0, true), bits);
    var n: u8[>..] = [];
    asn1::put_i64(n, 0xfedcba98);
    asn1::put(body, asn1::ctx(1, true), n);
    var info: u8[>..] = [];
    asn1::put(info, asn1::SEQUENCE, body);
    let v, nonce, ie = krb5::decode_kdc_dh_key_info(info);
    tv::check("KDCDHKeyInfo", ie == krb5::OK && v == "\x02\x01\x07" && nonce == 0xfedcba98);
    var exp: u8[>..] = [];
    exp.append(body);
    var t: u8[>..] = [];
    krb5::put_ktime(t, 1700000000);
    asn1::put(exp, asn1::ctx(2, true), t);
    var info2: u8[>..] = [];
    asn1::put(info2, asn1::SEQUENCE, exp);
    let v2, n2, ie2 = krb5::decode_kdc_dh_key_info(info2);
    tv::check("KDCDHKeyInfo with dhKeyExpiration refused", ie2 == krb5::ERR_MALFORMED);

    // TYPED-DATA: [0] type, [1] value.
    var td: u8[>..] = [];
    var e: u8[>..] = [];
    var ty: u8[>..] = [];
    asn1::put_i64(ty, 109);
    asn1::put(e, asn1::ctx(0, true), ty);
    var val: u8[>..] = [];
    asn1::put_octets(val, "params");
    asn1::put(e, asn1::ctx(1, true), val);
    asn1::put(td, asn1::SEQUENCE, e);
    var tds: u8[>..] = [];
    asn1::put(tds, asn1::SEQUENCE, td);
    let got, found = krb5::find_typed_data(tds, krb5::TD_DH_PARAMETERS);
    tv::check("TYPED-DATA", found && got == "params");
    let got2, found2 = krb5::find_typed_data(tds, krb5::TD_TRUSTED_CERTIFIERS);
    tv::check("TYPED-DATA, other type", !found2);
}

fn vector(kind: const u8[:], name: const u8[:]) -> u8[>..] {
    for line in split(embed_file("vectors/pkinit.txt"), '\n') {
        let w = words(line);
        if w.len == 3 && w[0] == kind && w[1] == name { return tv::hex(w[2]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

fn vector_now() -> i64 {
    for line in split(embed_file("vectors/pkinit.txt"), '\n') {
        let w = words(line);
        if w.len == 2 && w[0] == "now" { let v, ok = parse_int(w[1], 10); return v; }
    }
    return 0;
}

// A KDC's PA-PK-AS-REP: KDCDHKeyInfo (its value, the nonce) signed by
// `signer`'s key as content `ctype`, and the KDF named (empty: none).
fn kdc_reply(signer: const u8[:], kdc_value: const u8[:], nonce: u32, ctype: const u8[:], kdf: const u8[:]) -> u8[>..] {
    var body: u8[>..] = [];
    var bits: u8[>..] = [];
    asn1::put_bits(bits, kdc_value);
    asn1::put(body, asn1::ctx(0, true), bits);
    var n: u8[>..] = [];
    asn1::put_i64(n, nonce);
    asn1::put(body, asn1::ctx(1, true), n);
    var info: u8[>..] = [];
    asn1::put(info, asn1::SEQUENCE, body);
    let cert, e = x509::parse(vector("cert", signer));
    let key, ok = x509::parse_private_key(vector("key", signer));
    assert(e == x509::OK && ok);
    let alg, h = krb5::pkinit_sig_alg(key);
    let signed, oks = x509::cms_sign(ctype, info, key, cert, "", alg, h);
    assert(oks);
    return pk_as_rep(signed, false, kdf);
}

fn trust(anchor: const u8[:], hosts: const u8[:], eku: i64) -> krb5::PkinitTrust {
    return krb5::PkinitTrust { anchors: vector("cert", anchor), pool: "", kdc_hostnames: hosts, eku: eku };
}

fn kdc_replies() {
    let now = vector_now();
    let client = krb5::principal_name(krb5::NT_PRINCIPAL, "pat");
    let tgs = krb5::principal_name(krb5::NT_SRV_INST, krb5::name_join("krbtgt", "P.TEST"));
    let kdfs = krb5::pkinit_default_kdfs();
    let t = trust("ca", "", krb5::PKINIT_EKU_KDC);
    let gs: i64[2] = [krb5::PKINIT_P256, krb5::PKINIT_MODP2048];
    for g in gs {
        let dh = krb5::pkinit_dh_new(g);
        let kdh = krb5::pkinit_dh_new(g);
        let kv = spki_value(kdh.spki);
        let zk, okz = krb5::pkinit_dh_shared(kdh, spki_value(dh.spki));
        let what = if g == krb5::PKINIT_P256 { " (P-256)" } else { " (2048)" };
        let hs: i64[4] = [160, 256, 384, 512];
        for h in hs {
            let rep = kdc_reply("kdc", kv, 77, krb5::OID_PKINIT_DH_KEY_DATA, krb5::pkinit_kdf_oid(h));
            let k, e = krb5::pkinit_reply_key(rep, t, dh, 77, kdfs, 18, client, "P.TEST", tgs, "P.TEST", "the request", now);
            let want = krb5::pkinit_kdf(h, 18, zk, krb5::pkinit_other_info(h, client, "P.TEST", tgs, "P.TEST", 18, "the request", rep));
            tv::check(str("reply key, KDF ", h, what), e == krb5::OK && k.value == want.value);
        }
        let rep0 = kdc_reply("kdc", kv, 77, krb5::OID_PKINIT_DH_KEY_DATA, "");
        let k0, e0 = krb5::pkinit_reply_key(rep0, t, dh, 77, kdfs, 17, client, "P.TEST", tgs, "P.TEST", "the request", now);
        let want0 = krb5::pkinit_octetstring2key(17, zk);
        tv::check(str("reply key, octetstring2key", what), e0 == krb5::OK && k0.value == want0.value);
    }

    let dh = krb5::pkinit_dh_new(krb5::PKINIT_P256);
    let kv = spki_value(krb5::pkinit_dh_new(krb5::PKINIT_P256).spki);
    let sha256 = krb5::pkinit_kdf_oid(256);
    let rep = kdc_reply("kdc", kv, 77, krb5::OID_PKINIT_DH_KEY_DATA, sha256);
    let k1, e1 = krb5::pkinit_reply_key(rep, t, dh, 78, kdfs, 18, client, "P.TEST", tgs, "P.TEST", "", now);
    tv::check_int("another nonce", e1, krb5::ERR_NONCE);
    let k2, e2 = krb5::pkinit_reply_key(rep, t, dh, 77, kdfs, 18, client, "P.TEST", tgs, "X.TEST", "", now);
    tv::check_int("another realm's KDC", e2, krb5::KDC_ERR_KDC_NAME_MISMATCH);
    let k3, e3 = krb5::pkinit_reply_key(rep, t, dh, 77, kdfs, 18, client, "Q.TEST", tgs, "Q.TEST", "", now);
    tv::check_int("the KDC's second realm", e3, krb5::OK);
    let k4, e4 = krb5::pkinit_reply_key(rep, t, dh, 77, kdfs, 18, client, "P.TEST", tgs, "P.TEST", "", now + 2 * 366 * 86400);
    tv::check_int("KDC certificate expired", e4, krb5::KDC_ERR_KDC_NOT_TRUSTED);
    let tr = trust("rogue", "", krb5::PKINIT_EKU_KDC);
    let k5, e5 = krb5::pkinit_reply_key(rep, tr, dh, 77, kdfs, 18, client, "P.TEST", tgs, "P.TEST", "", now);
    tv::check_int("another CA", e5, krb5::KDC_ERR_KDC_NOT_TRUSTED);
    let only1: i64[1] = [160];
    let k6, e6 = krb5::pkinit_reply_key(rep, t, dh, 77, only1, 18, client, "P.TEST", tgs, "P.TEST", "", now);
    tv::check_int("a KDF we did not offer", e6, krb5::KDC_ERR_NO_ACCEPTABLE_KDF);
    let repu = kdc_reply("kdc", kv, 77, krb5::OID_PKINIT_DH_KEY_DATA, "1.3.6.1.5.2.3.6.99");
    let k7, e7 = krb5::pkinit_reply_key(repu, t, dh, 77, kdfs, 18, client, "P.TEST", tgs, "P.TEST", "", now);
    tv::check_int("an unknown KDF", e7, krb5::KDC_ERR_NO_ACCEPTABLE_KDF);
    let rept = kdc_reply("kdc", kv, 77, krb5::OID_PKINIT_AUTH_DATA, sha256);
    let k8, e8 = krb5::pkinit_reply_key(rept, t, dh, 77, kdfs, 18, client, "P.TEST", tgs, "P.TEST", "", now);
    tv::check_int("content type id-pkinit-authData", e8, krb5::ERR_MALFORMED);
    // Unsigned: no signer.
    var ub: u8[>..] = [];
    asn1::put_bits(ub, kv);
    var unsigned_rep = pk_as_rep(x509::cms_unsigned(krb5::OID_PKINIT_DH_KEY_DATA, ub), false, "");
    let k9, e9 = krb5::pkinit_reply_key(unsigned_rep, t, dh, 77, kdfs, 18, client, "P.TEST", tgs, "P.TEST", "", now);
    tv::check_int("unsigned", e9, krb5::KDC_ERR_INVALID_SIG);
    // A value not on the curve, signed.
    var bad = spki_value(krb5::pkinit_dh_new(krb5::PKINIT_P256).spki);
    bad[bad.len - 1] ^= 1;
    let repb = kdc_reply("kdc", bad, 77, krb5::OID_PKINIT_DH_KEY_DATA, sha256);
    let k10, e10 = krb5::pkinit_reply_key(repb, t, dh, 77, kdfs, 18, client, "P.TEST", tgs, "P.TEST", "", now);
    tv::check_int("KDC value not a point", e10, krb5::KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED);

    // KDCs named by host: R.TEST's certificate (dNSName kdc.r.test, EKU
    // id-pkinit-KPKdc), N.TEST's (id-pkinit-san, EKU serverAuth).
    let repd = kdc_reply("kdc-dns", kv, 77, krb5::OID_PKINIT_DH_KEY_DATA, sha256);
    let k11, e11 = krb5::pkinit_reply_key(repd, t, dh, 77, kdfs, 18, client, "R.TEST", tgs, "R.TEST", "", now);
    tv::check_int("named by host, no pkinit_kdc_hostname", e11, krb5::KDC_ERR_KDC_NAME_MISMATCH);
    let th = trust("ca", "other.r.test\nKDC.R.TEST\n", krb5::PKINIT_EKU_KDC);
    let k12, e12 = krb5::pkinit_reply_key(repd, th, dh, 77, kdfs, 18, client, "R.TEST", tgs, "R.TEST", "", now);
    tv::check_int("named by host, pkinit_kdc_hostname (case ignored)", e12, krb5::OK);
    let ts = trust("ca", "kdc.r.test\n", krb5::PKINIT_EKU_SERVER_AUTH);
    let k13, e13 = krb5::pkinit_reply_key(repd, ts, dh, 77, kdfs, 18, client, "R.TEST", tgs, "R.TEST", "", now);
    tv::check_int("named by host, kpServerAuth wanted", e13, krb5::KDC_ERR_INCONSISTENT_KEY_PURPOSE);
    let tn = trust("ca", "kdc.r.test\n", krb5::PKINIT_EKU_NONE);
    let k14, e14 = krb5::pkinit_reply_key(repd, tn, dh, 77, kdfs, 18, client, "R.TEST", tgs, "R.TEST", "", now);
    tv::check_int("named by host, EKU not checked", e14, krb5::OK);
    let repn = kdc_reply("kdc-noeku", kv, 77, krb5::OID_PKINIT_DH_KEY_DATA, sha256);
    let k15, e15 = krb5::pkinit_reply_key(repn, t, dh, 77, kdfs, 18, client, "N.TEST", tgs, "N.TEST", "", now);
    tv::check_int("id-pkinit-san, EKU serverAuth (as MIT)", e15, krb5::OK);

    // PA-PKINIT-KX: the contribution key, encrypted in the reply key.
    let reply_key = krb5::random_key(18);
    let contribution = krb5::random_key(18);
    var ek: u8[>..] = [];
    krb5::put_key(ek, contribution);
    var c: u8[>..] = [];
    let ee = krb5::encrypt(reply_key, krb5::USAGE_PA_PKINIT_KX, ek, c);
    var kx: u8[>..] = [];
    let ed = krb5::EncryptedData { etype: 18, has_kvno: false, kvno: 0, cipher: copy(c) };
    krb5::encode_enc_data(kx, ed);
    let session, se = krb5::fx_cf2(contribution, "PKINIT", reply_key, "KEYEXCHANGE");
    tv::check_int("PA-PKINIT-KX", krb5::pkinit_check_kx(kx, reply_key, session), krb5::OK);
    tv::check("PA-PKINIT-KX, another session key", krb5::pkinit_check_kx(kx, reply_key, contribution) != krb5::OK);
    tv::check("PA-PKINIT-KX, another reply key", krb5::pkinit_check_kx(kx, contribution, session) != krb5::OK);
}

fn main() {
    octetstring2key_vectors();
    kdf_vectors();
    dh_groups();
    messages();
    kdc_replies();
    tv::done("pkinit");
}
