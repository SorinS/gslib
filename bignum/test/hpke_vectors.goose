// vectors/hpke.txt: HPKE (RFC 9180) from RFC 9180's test vectors (all
// four modes, DHKEM over P-256, P-521 and X25519, HKDF-SHA256 and -SHA512,
// every AEAD and export-only) and Go's post-quantum ones (ML-KEM-512, -768
// and -1024, the three hybrids, the SHAKE KDFs, DHKEM P-384). Each suite:
// the derived key pairs, encapsulation and decapsulation, the key
// schedule's key, nonce and exporter secret, the first ten seals and the
// 255th and 256th, and the exports. Then fresh key pairs through every
// KEM, and the refusals: tampered messages and encapsulated keys, wrong
// info or PSK, inconsistent modes.
import std;
import bignum from "..";
import bignum.hpke;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn num(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s, 10);
    assert(ok);
    return v;
}

fn count_aad(i: i64) -> u8[>..] {
    var a: u8[>..] = [];
    a.append("Count-");
    format_int(a, i, 10, 0, 32);
    return a;
}

fn main() {
    var kem: i64 = 0;
    var kdf: i64 = 0;
    var aead: i64 = 0;
    var tx = bignum::hpke_empty_context();
    var rx = bignum::hpke_empty_context();
    var next_seq: i64 = 0;
    var pt0: u8[>..] = [];
    for line in split(embed_file("vectors/hpke.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "suite" {
            let mode = num(w[1]);
            kem = num(w[2]);
            kdf = num(w[3]);
            aead = num(w[4]);
            let info = unhex(w[5]);
            let ikm_e = unhex(w[6]);
            let ikm_r = unhex(w[7]);
            let ikm_s = unhex(w[8]);
            let sk_r = unhex(w[9]);
            let pk_r = unhex(w[10]);
            let sk_s = unhex(w[11]);
            let pk_s = unhex(w[12]);
            let psk = unhex(w[13]);
            let psk_id = unhex(w[14]);
            let enc = unhex(w[15]);
            let ss = unhex(w[16]);
            let sk2, pk2 = bignum::hpke_derive_key_pair(kem, ikm_r);
            check("derive recipient", sk2 == sk_r && pk2 == pk_r);
            let pk3, okp = bignum::hpke_public_key(kem, sk_r);
            check("public key", okp && pk3 == pk_r);
            if ikm_s.len > 0 {
                let sk4, pk4 = bignum::hpke_derive_key_pair(kem, ikm_s);
                check("derive sender", sk4 == sk_s && pk4 == pk_s);
            }
            let ss2, enc2, oke = bignum::hpke_encap(kem, pk_r, ikm_e, sk_s);
            check("encap", oke && ss2 == ss && enc2 == enc);
            let ss3, okd = bignum::hpke_decap(kem, enc, sk_r, pk_s);
            check("decap", okd && ss3 == ss);
            let enc4, t, okt = bignum::hpke_sender_with(kem, kdf, aead, pk_r, info, ikm_e, psk, psk_id, sk_s);
            check("sender", okt && enc4 == enc && t.key == unhex(w[17]) && t.nonce == unhex(w[18]) &&
                  t.exporter == unhex(w[19]) && bignum::hpke_mode(kem, kdf, psk, psk_id, sk_s.len > 0) == mode);
            let r, okr = bignum::hpke_recipient(kem, kdf, aead, sk_r, enc, info, psk, psk_id, pk_s);
            check("recipient", okr && r.key == t.key && r.nonce == t.nonce && r.exporter == t.exporter);
            tx = t;
            rx = r;
            next_seq = 0;
            pt0.clear();
            // Another info, or no PSK where one was used, gives other keys.
            var info2: u8[>..] = [];
            info2.append(info);
            info2.push(1);
            let r2, ok2 = bignum::hpke_recipient(kem, kdf, aead, sk_r, enc, info2, psk, psk_id, pk_s);
            check("other info", ok2 && r2.exporter != t.exporter);
            if psk.len > 0 {
                var psk2: u8[>..] = [];
                psk2.append(psk);
                psk2[0] ^= 1;
                let r3, ok3 = bignum::hpke_recipient(kem, kdf, aead, sk_r, enc, info, psk2, psk_id, pk_s);
                check("other psk", ok3 && r3.exporter != t.exporter);
                let r4, ok4 = bignum::hpke_recipient(kem, kdf, aead, sk_r, enc, info, psk, "", pk_s);
                check("psk without id", !ok4);
            }
            // A changed encapsulated key: refused, or (ML-KEM's implicit
            // rejection) other keys.
            var enc5: u8[>..] = [];
            enc5.append(enc);
            enc5[enc5.len - 1] ^= 0x40;
            let r5, ok5 = bignum::hpke_recipient(kem, kdf, aead, sk_r, enc5, info, psk, psk_id, pk_s);
            check("changed enc", !ok5 || r5.exporter != t.exporter);
            if aead == bignum::HPKE_EXPORT_ONLY {
                let c, oks = bignum::hpke_seal(tx, "", "x");
                check("export only", !oks);
            }
        } else if w[0] == "seal" {
            let seq = num(w[1]);
            let pt = unhex(w[3]);
            if pt0.len == 0 { pt0.append(pt); }
            while next_seq < seq {
                let aad = count_aad(next_seq);
                let c, ok = bignum::hpke_seal(tx, aad, pt0);
                let p, okp = bignum::hpke_open(rx, aad, c);
                next_seq++;
            }
            let ct = unhex(w[4]);
            let c, ok = bignum::hpke_seal(tx, unhex(w[2]), pt);
            check("seal", ok && c == ct);
            var bad: u8[>..] = [];
            bad.append(ct);
            bad[0] ^= 1;
            let pb, okb = bignum::hpke_open(rx, unhex(w[2]), bad);
            check("tampered", !okb);
            let p, okp = bignum::hpke_open(rx, unhex(w[2]), ct);
            check("open", okp && p == pt);
            next_seq++;
        } else if w[0] == "export" {
            let ctx = unhex(w[1]);
            let n = num(w[2]);
            check("export", bignum::hpke_export(tx, ctx, n) == unhex(w[3]) && bignum::hpke_export(rx, ctx, n) == unhex(w[3]));
        }
    }
    // Fresh keys through every KEM, single-shot and with contexts.
    let kems: i64[10] = [bignum::HPKE_DHKEM_P256, bignum::HPKE_DHKEM_P384, bignum::HPKE_DHKEM_P521, bignum::HPKE_DHKEM_X25519,
                         bignum::HPKE_MLKEM512, bignum::HPKE_MLKEM768, bignum::HPKE_MLKEM1024, bignum::HPKE_MLKEM768_P256,
                         bignum::HPKE_MLKEM1024_P384, bignum::HPKE_MLKEM768_X25519];
    let kdfs: i64[5] = [bignum::HPKE_HKDF_SHA256, bignum::HPKE_HKDF_SHA384, bignum::HPKE_HKDF_SHA512, bignum::HPKE_SHAKE128,
                        bignum::HPKE_SHAKE256];
    let aeads: i64[3] = [bignum::HPKE_AES128GCM, bignum::HPKE_AES256GCM, bignum::HPKE_CHACHA20POLY1305];
    for i in 10 {
        let k = kems[i];
        let f = kdfs[i % 5];
        let a = aeads[i % 3];
        let sk, pk = bignum::hpke_keygen(k);
        check("sizes", sk.len == bignum::hpke_nsk(k) && pk.len == bignum::hpke_npk(k));
        let sealed, ok = bignum::hpke_seal_once(k, f, a, pk, "info", "a secret message");
        check("seal once", ok && sealed.len == bignum::hpke_nenc(k) + 16 + 16);
        let opened, oko = bignum::hpke_open_once(k, f, a, sk, "info", sealed);
        check("open once", oko && opened == "a secret message");
        let o2, oko2 = bignum::hpke_open_once(k, f, a, sk, "infp", sealed);
        check("open once, other info", !oko2);
        let sk2, pk2 = bignum::hpke_keygen(k);
        let o3, oko3 = bignum::hpke_open_once(k, f, a, sk2, "info", sealed);
        check("open once, other key", !oko3);
        let o4, oko4 = bignum::hpke_open_once(k, f, a, sk, "info", sealed[..10]);
        check("open once, short", !oko4);
        // The modes each KEM and KDF allow.
        let e1, c1, okm = bignum::hpke_sender(k, bignum::HPKE_HKDF_SHA256, a, pk, "", "psk-value-32-bytes-long-.......", "id");
        check("psk mode", okm);
        let e2, c2, oka = bignum::hpke_sender(k, bignum::HPKE_HKDF_SHA256, a, pk, "", "", "", sk2);
        check("auth needs a DHKEM", oka == bignum::hpke_is_dh(k));
        let e3, c3, oks = bignum::hpke_sender(k, bignum::HPKE_SHAKE256, a, pk, "", "psk", "id");
        check("SHAKE in base mode only", !oks);
        let e4, c4, okb = bignum::hpke_sender(k, f, a, pk[..pk.len - 1], "");
        check("short public key", !okb);
    }
    let e5, c5, oku = bignum::hpke_sender(0x0021, 1, 1, "", "");
    check("unknown KEM", !oku);
    print("hpke vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
