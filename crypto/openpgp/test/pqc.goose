// Post-quantum OpenPGP: gpg 2.5's LibrePGP Kyber keys (test/vectors/pqc*,
// from scripts/gen_pqc_vectors.py) and RFC 9980's Appendix A
// (rfc9980_a*), and keys made here of both kinds.
//
// KMAC256 against NIST SP 800-185's samples. gpg: its v5 Kyber subkey's
// fingerprint as gpg lists it, the binding over a v5 key, the secret in
// gpg's mode 1003 (the agent's S-expression) unprotected and under the
// agent's OCB protection, messages gpg encrypted to it (its OCB packet)
// opened, the public export identical to gpg's, encryption to it read
// back. RFC 9980: the fingerprints, each message's session key and the
// key combiner's output as Appendix A gives them, v3 and v6 PKESKs with
// SEIPD v1 and v2, ML-DSA-65+Ed25519 signatures (detached and inline;
// either half changed is refused), ML-KEM-1024+X448 and ML-DSA-87+Ed448
// keys listed but not used.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.kmac;
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.armor;
import gslib.crypto.openpgp.packet;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.pqc;
import gslib.crypto.openpgp.sig;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import gslib.crypto.openpgp.keygen;
import tv;

let V = "vectors/";

fn vec(name: const u8[:]) -> u8[>..] { tv::read(str(V, name)) }

fn passphrase() -> u8[>..] {
    var p = vec("passphrase.txt");
    while p.len > 0 && p[p.len - 1] == '\n' { p.resize(p.len - 1); }
    return p;
}

fn kmac() {
    // SP 800-185's KMAC samples 4, 5 and 6 (KMAC256, 512-bit output).
    var key: u8[>..] = [];
    for i in 32 { key.push((0x40 + i) as! u8); }
    var d4: u8[>..] = [];
    for i in 4 { d4.push(i as! u8); }
    var d200: u8[>..] = [];
    for i in 200 { d200.push(i as! u8); }
    tv::check_eq("KMAC256 sample 4", bignum::kmac(256, key, d4, 64, "My Tagged Application"),
                 tv::unhex("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"));
    tv::check_eq("KMAC256 sample 5", bignum::kmac(256, key, d200, 64),
                 tv::unhex("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"));
    tv::check_eq("KMAC256 sample 6", bignum::kmac(256, key, d200, 64, "My Tagged Application"),
                 tv::unhex("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"));
    // gpg's use: a 37-octet key, 32 octets out (openssl mac KMAC256).
    var d100: u8[>..] = [];
    for i in 100 { d100.push(i as! u8); }
    tv::check_eq("KMAC256 gpg's key", bignum::kmac(256, openpgp::LIBREPGP_KMAC_KEY, d100, 32, "KDF"),
                 tv::unhex("432C8CE2F121AB86D11F662BCE7C930BF131CA84A86CEC2FC832A033FA2EBC8D"));
}

fn sos() {
    // gpg's sos_write: a leading zero octet keeps all 32 octets (256 bits).
    var z: u8[>..] = [];
    z.resize(32, 7);
    z[0] = 0;
    var out: u8[>..] = [];
    openpgp::put_sos(out, z);
    tv::check("SOS of 00...", out.len == 34 && out[0] == 1 && out[1] == 0);
    z[0] = 0x01;
    out.clear();
    openpgp::put_sos(out, z);
    tv::check("SOS of 01...", out.len == 34 && out[0] == 0 && out[1] == 249);
}

// gpg's fingerprints in keys_pqc.txt's order.
fn gpg_fingerprints() -> u8[>..] {
    var out: u8[>..] = [];
    for line in split(vec("keys_pqc.txt"), '\n') {
        if !starts_with(line, "fpr:") { continue; }
        let f = split(line, ':');
        out.append(f[9]);
        out.push(' ');
    }
    return out;
}

fn read_ok(what: const u8[:], kr: const openpgp::Keyring&, msg: const u8[:], want: const u8[:], signed: bool) {
    var m = openpgp::Message { .. };
    let e = openpgp::read_message(kr, msg, m, openpgp::ReadOptions { .. });
    tv::check_int(str(what, ": read"), e, openpgp::OK);
    tv::check(str(what, ": data"), m.data[..] == want && m.encrypted);
    if signed { tv::check_int(str(what, ": signature"), openpgp::signature_status(m), openpgp::OK); }
}

fn gpg() {
    let all = gpg_fingerprints();
    let fprs = split(all, ' ');
    let msg = vec("msg.txt");
    var kr = openpgp::Keyring { .. };
    tv::check_int("add pqc.pub", openpgp::add_keys(kr, vec("pqc.pub")), openpgp::OK);
    tv::check_int("pqc keys", kr.keys.len, 2);
    for i in 2 {
        tv::check(str("pqc fingerprint ", i), openpgp::hex(kr.keys[i].fpr)[..] == fprs[i]);
        tv::check(str("pqc valid ", i), kr.keys[i].valid);
    }
    let sub = kr.keys[1];
    tv::check("v5 Kyber subkey", sub.version == 5 && sub.algo == openpgp::PK_KYBER && sub.curve == openpgp::CURVE_X25519
              && sub.pq_len == 1184 && sub.subkey && sub.flags == openpgp::FLAG_ENCRYPT);
    tv::check("its name", openpgp::key_type_name(sub)[..] == "ky768_cv25519");
    tv::check("its key ID", sub.keyid[..] == sub.fpr[..8]);
    tv::check_int("encryption key", openpgp::encryption_key(kr, 0), 1);

    // Encrypting needs only the public key; reading it back, the secret.
    var enc: u8[>..] = [];
    tv::check_int("encrypt to Kyber", openpgp::encrypt(kr, [0], "", msg, enc, openpgp::WriteOptions { .. }), openpgp::OK);
    var m0 = openpgp::Message { .. };
    tv::check_int("no secret", openpgp::read_message(kr, enc, m0, openpgp::ReadOptions { .. }), openpgp::ERR_NO_KEY);

    var ks = openpgp::Keyring { .. };
    tv::check_int("add pqc.sec", openpgp::add_keys(ks, vec("pqc.sec")), openpgp::OK);
    tv::check("secret in mode 1003, unprotected", ks.keys[1].has_secret && ks.keys[1].sexp && !ks.keys[1].locked
              && ks.keys[1].pq_sec.len == 64);
    read_ok("gpg's to pqc", ks, vec("enc_pqc.gpg"), msg, false);
    read_ok("gpg's to both, signed", ks, vec("enc_pqc_signed.gpg"), msg, true);
    read_ok("ours to pqc", ks, enc, msg, false);
    var m1 = openpgp::Message { .. };
    let e1 = openpgp::read_message(ks, vec("enc_pqc.gpg"), m1, openpgp::ReadOptions { .. });
    tv::check("gpg's OCB packet", m1.aead == openpgp::AEAD_OCB && m1.cipher == openpgp::CIPHER_AES256 && m1.decrypted_with == 1);

    // The public export is gpg's, byte for byte.
    var pub: u8[>..] = [];
    tv::check_int("export public", openpgp::export_public(ks, 0, pub), openpgp::OK);
    tv::check("export public is gpg's", pub[..] == vec("pqc.pub")[..]);

    // Exported again, unprotected and protected (mode 1003 both), read back.
    for pass in ["", "another passphrase"] {
        var sec: u8[>..] = [];
        let r1 = openpgp::export_secret(ks, 0, sec, true, pass, 96);
        tv::check_int(str("export secret '", pass, "'"), r1, openpgp::OK);
        var k2 = openpgp::Keyring { .. };
        tv::check_int("re-read", openpgp::add_keys(k2, sec), openpgp::OK);
        tv::check("re-read: mode 1003", k2.keys[1].sexp && k2.keys[1].locked == (pass.len > 0));
        if pass.len > 0 {
            tv::check_int("re-read: wrong passphrase", openpgp::unlock(k2, 0, "nope"), openpgp::ERR_PASSPHRASE);
            tv::check_int("re-read: unlock", openpgp::unlock(k2, 0, pass), openpgp::OK);
        }
        read_ok("re-read: decrypt", k2, vec("enc_pqc.gpg"), msg, false);
    }

    // The protected one: the X25519 half under the agent's OCB.
    var kp = openpgp::Keyring { .. };
    tv::check_int("add pqc_prot.sec", openpgp::add_keys(kp, vec("pqc_prot.sec")), openpgp::OK);
    tv::check("pqc_prot fingerprints", openpgp::hex(kp.keys[0].fpr)[..] == fprs[2] && openpgp::hex(kp.keys[1].fpr)[..] == fprs[3]);
    tv::check("pqc_prot locked", kp.keys[1].locked && kp.keys[1].sexp);
    var mp = openpgp::Message { .. };
    tv::check_int("locked: no", openpgp::read_message(kp, vec("enc_pqc_prot.asc"), mp, openpgp::ReadOptions { .. }),
                  openpgp::ERR_PASSPHRASE);
    tv::check_int("wrong passphrase", openpgp::unlock(kp, 0, "wrong"), openpgp::ERR_PASSPHRASE);
    tv::check_int("unlock", openpgp::unlock(kp, 0, passphrase()), openpgp::OK);
    read_ok("gpg's to pqc_prot", kp, vec("enc_pqc_prot.asc"), msg, false);

    // Changed: the AES key wrap's check fails, or the KEM gives another key.
    var bin: u8[>..] = [];
    let ed = openpgp::decode_input(vec("enc_pqc.gpg"), bin);
    for at in [20, 40, 600, 1170] {
        var bad: u8[>..] = [];
        bad.append(bin);
        bad[at] ^= 0x10;
        var mb = openpgp::Message { .. };
        let label_170 = str("changed PKESK at ", at);
        tv::check(label_170, openpgp::read_message(ks, bad, mb, openpgp::ReadOptions { .. }) != openpgp::OK);
    }
}

// The tags and bodies of the packets of data, whatever their headers.
fn packets(data: const u8[:]) -> u8[>..] {
    var bin: u8[>..] = [];
    let e = openpgp::decode_input(data, bin);
    var out: u8[>..] = [];
    var at = 0;
    while at < bin.len {
        let p, ep = openpgp::next_packet(bin, at);
        if ep != openpgp::OK { break; }
        out.push(p.tag as! u8);
        out.append(bin[p.body..p.body_end]);
        at = p.end;
    }
    return out;
}

// The fields of a message's first packet (a PKESK) after its algorithm.
fn pkesk_fields(msg: const u8[:]) -> u8[>..] {
    var bin: u8[>..] = [];
    let e = openpgp::decode_input(msg, bin);
    let p, ep = openpgp::next_packet(bin, 0);
    let body = bin[p.body..p.body_end];
    let at = if body[0] == 6 { 2 + body[1] } else { 9 };
    var out: u8[>..] = [];
    out.append(body[at + 1..]);
    return out;
}

// One of Appendix A's messages: the combiner's output from its key shares,
// the session key the subkey (index sub) finds, and the message read.
fn rfc_message(what: const u8[:], kr: const openpgp::Keyring&, sub: i64, msg: const u8[:], mlkem_ss: const u8[:],
               ecdh_ss: const u8[:], kek: const u8[:], session: const u8[:]) {
    let k = kr.keys[sub];
    let mat = pkesk_fields(msg);
    let v6 = mat.len == 32 + 1088 + 1 + 40;
    tv::check_eq(str(what, ": multiKeyCombine"), openpgp::ietf_kek(tv::unhex(mlkem_ss), tv::unhex(ecdh_ss), mat[..32],
                 k.point, openpgp::PK_MLKEM768_X25519), tv::unhex(kek));
    var m: u8[>..] = [];
    let r2 = openpgp::decrypt_session(k, mat, m, v6);
    tv::check_int(str(what, ": decrypt_session"), r2, openpgp::OK);
    let key = if v6 { m[..] } else { m[1..] };
    tv::check_eq(str(what, ": session key"), key, tv::unhex(session));
    read_ok(what, kr, msg, "Testing\n", true);
}

fn rfc9980() {
    // A.1: v6 Ed25519 with a v6 ML-KEM-768+X25519 subkey.
    var k1 = openpgp::Keyring { .. };
    tv::check_int("A.1.1", openpgp::add_keys(k1, vec("rfc9980_a1_secret.asc")), openpgp::OK);
    tv::check("A.1 fingerprints", openpgp::hex(k1.keys[0].fpr, false)[..] == "c789e17d9dbdca7b3c833a3c063feb0353f80ad911fe27868fb0645df803e947"
              && openpgp::hex(k1.keys[1].fpr, false)[..] == "dafe0eebb2675ecfcdc20a23fe89ca5d12e83f527dfa354b6dcf662131a48b9d");
    tv::check("A.1 valid", k1.keys[0].valid && k1.keys[1].valid && k1.keys[1].algo == openpgp::PK_MLKEM768_X25519
              && !k1.keys[1].locked && k1.keys[1].version == 6);
    rfc_message("A.1.3", k1, 1, vec("rfc9980_a1_msg.asc"),
                "b0e45408d8c713f3941cd27276f879e557df013e05bcf43e37d4c60266a4b797",
                "9d994741e0db5eacee44cb028c2ec48b1346feae2576aaac383bbcd64138c932",
                "5bf078bf7977109db6dead92d3578b62d0ab0487ef84e8e0af08f4b4b229e590",
                "94a3b8c9784463bb96b682cddf549adb23579b75bcb646f989d7cfe3e6e14435");
    var c1 = openpgp::Keyring { .. };
    tv::check_int("A.1.2", openpgp::add_keys(c1, vec("rfc9980_a1_cert.asc")), openpgp::OK);
    tv::check("A.1.2 is A.1.1's", c1.keys.len == 2 && c1.keys[1].fpr[..] == k1.keys[1].fpr[..] && c1.keys[1].valid);

    // A.2: v4 Ed25519 with a v4 ML-KEM-768+X25519 subkey; v3 PKESK and
    // SEIPD v1, v6 PKESK and SEIPD v2.
    var k2 = openpgp::Keyring { .. };
    tv::check_int("A.2.1", openpgp::add_keys(k2, vec("rfc9980_a2_secret.asc")), openpgp::OK);
    tv::check("A.2 fingerprints", openpgp::hex(k2.keys[0].fpr, false)[..] == "342e5db2de345215cb2c944f7102ffed3b9cf12d"
              && openpgp::hex(k2.keys[1].fpr, false)[..] == "e51dbfea51936988b5428fffa4f95f985ed61a51");
    tv::check("A.2 v4 subkey", k2.keys[1].valid && k2.keys[1].version == 4 && k2.keys[1].algo == openpgp::PK_MLKEM768_X25519);
    rfc_message("A.2.3", k2, 1, vec("rfc9980_a2_msg_seipd1.asc"),
                "16f2aea8ec1ca277c04cc7b87681d7d38511a38f554775a8fc4de41aa76eb586",
                "2fc0c8fcace9636c86d1ee1715a302819ad48c549579a462a33eed36627c532e",
                "c1591d7511f9f0213bfd57cf316e5ec0d40c4ea826fa989ab606aa3b8a1a2c1f",
                "b4dc7197e1519822ca689da484643edf272934d98ae1974b5d88317a7a6a3c4f");
    rfc_message("A.2.4", k2, 1, vec("rfc9980_a2_msg_seipd2.asc"),
                "16a22adbeced91ada60b5561611748edd2fedc51e0770f86d7394870062e7322",
                "5ac67eab192f25ac99d87543e6fcd3a4769cb02c9d1afdc79354c2baa2289e29",
                "5c5652a690b55d1e9545fbd722f838cd8ff4d3657af5a9026d02f3185ca74993",
                "160867d96032b640208c1c92174d0270bb89189d72320711acd221bbea2a26b6");
    var c2 = openpgp::Keyring { .. };
    tv::check_int("A.2.2", openpgp::add_keys(c2, vec("rfc9980_a2_cert.asc")), openpgp::OK);
    var pub2: u8[>..] = [];
    tv::check_int("A.2 export", openpgp::export_public(k2, 0, pub2), openpgp::OK);
    tv::check("A.2 public export is A.2.2", packets(pub2)[..] == packets(vec("rfc9980_a2_cert.asc"))[..]);

    // A.3: v6 ML-DSA-65+Ed25519 with ML-KEM-768+X25519.
    var k3 = openpgp::Keyring { .. };
    tv::check_int("A.3.1", openpgp::add_keys(k3, vec("rfc9980_a3_secret.asc")), openpgp::OK);
    tv::check("A.3 fingerprint", openpgp::hex(k3.keys[0].fpr, false)[..] == "a3e2e14b6a493ff930fb27321f125e9a6880338be9fb7da3ae065ea65793242f");
    tv::check("A.3 valid", k3.keys.len == 2 && k3.keys[0].valid && k3.keys[1].valid && k3.keys[0].algo == openpgp::PK_MLDSA65_ED25519
              && k3.keys[0].pq_len == 1952 && !k3.keys[0].locked);
    rfc_message("A.3.3", k3, 1, vec("rfc9980_a3_msg.asc"),
                "0987fe72ad5ea58e73344f9a2a543f4131d9fdb7cf07474f501430a20f705b4d",
                "88f3e9a8de1917127b4b758f6e83bd4ce00faaae01bd8b6e412a43a710b26012",
                "a4904982f7caa9c9de690afd772d8bfe027a1ad6a5bbda00db68963fe303ae8e",
                "adee68618b302d4bfd7ae3d432bc63a1c1ad7f5fd6e7fd7bdedbb0d0b14a5c9a");
    var c3 = openpgp::Keyring { .. };
    tv::check_int("A.3.2", openpgp::add_keys(c3, vec("rfc9980_a3_cert.asc")), openpgp::OK);
    var md = openpgp::Message { .. };
    tv::check_int("A.3.4 detached", openpgp::verify_detached(c3, "Testing\n", vec("rfc9980_a3_sig.asc"), md), openpgp::OK);
    tv::check("A.3.4 by the primary", md.sigs[0].key == 0 && md.sigs[0].pk_algo == openpgp::PK_MLDSA65_ED25519);
    var md2 = openpgp::Message { .. };
    tv::check_int("A.3.4 other data", openpgp::verify_detached(c3, "Testing!\n", vec("rfc9980_a3_sig.asc"), md2),
                  openpgp::ERR_BAD_SIGNATURE);
    // Either half changed: refused. The material is the packet's tail:
    // Ed25519's 64 octets, then ML-DSA-65's 3309.
    var sig: u8[>..] = [];
    let es = openpgp::decode_input(vec("rfc9980_a3_sig.asc"), sig);
    for back in [3309 + 10, 100] {
        var bad: u8[>..] = [];
        bad.append(sig);
        bad[bad.len - back] ^= 1;
        var mb = openpgp::Message { .. };
        let label_287 = str("A.3.4 changed ", back, " from the end");
        tv::check_int(label_287, openpgp::verify_detached(c3, "Testing\n", bad, mb),
                      openpgp::ERR_BAD_SIGNATURE);
    }

    // A.4: ML-DSA-87+Ed448 with ML-KEM-1024+X448, which this package lists
    // and fingerprints but does not use.
    var c4 = openpgp::Keyring { .. };
    tv::check_int("A.4.2", openpgp::add_keys(c4, vec("rfc9980_a4_cert.asc")), openpgp::OK);
    tv::check("A.4 fingerprints", c4.keys.len == 2
              && openpgp::hex(c4.keys[0].fpr, false)[..] == "0d7a8be1410cd68eed4845ab487b4b4cfaecd8ebad1a1166a84230499200ee20"
              && openpgp::hex(c4.keys[1].fpr, false)[..] == "65090e147a8116ab7f62ab4ec7aae59d9e6532feb2af230c73cdc869fbc60c8f");
    tv::check("A.4 names", openpgp::key_type_name(c4.keys[0])[..] == "mldsa87_ed448"
              && openpgp::key_type_name(c4.keys[1])[..] == "mlkem1024_x448");
    var e4: u8[>..] = [];
    tv::check("A.4 not used", openpgp::encrypt(c4, [0], "", "x", e4, openpgp::WriteOptions { .. }) != openpgp::OK);
}

// Keys made here, both kinds: exported (protected and not), read back,
// used both ways.
fn generated() {
    let msg = "Post-quantum test message.\n";
    for kind in 2 {
        let what = if kind == 0 { "gpg's kind" } else { "RFC 9980" };
        var kr = openpgp::Keyring { .. };
        let e = if kind == 0 { openpgp::generate_pqc_key(kr, "PQ <pq@example.com>", 1794000000) }
                else { openpgp::generate_rfc9980_key(kr, "PQ <pq@example.com>", 1794000000) };
        tv::check_int(str(what, ": generate"), e, openpgp::OK);
        tv::check(str(what, ": valid"), kr.keys.len == 2 && kr.keys[0].valid && kr.keys[1].valid);
        if kind == 0 {
            tv::check("gpg's kind: v4 + v5", kr.keys[0].version == 4 && kr.keys[1].version == 5
                      && kr.keys[1].algo == openpgp::PK_KYBER && kr.keys[1].sexp);
        } else {
            tv::check("RFC 9980: v6 + v6", kr.keys[0].version == 6 && kr.keys[0].algo == openpgp::PK_MLDSA65_ED25519
                      && kr.keys[1].version == 6 && kr.keys[1].algo == openpgp::PK_MLKEM768_X25519);
        }
        var w = openpgp::WriteOptions { .. };
        var enc: u8[>..] = [];
        let r3 = openpgp::encrypt(kr, [0], "", msg, enc, w, 0);
        tv::check_int(str(what, ": encrypt, signed"), r3, openpgp::OK);
        read_ok(str(what, ": read"), kr, enc, msg, true);
        var sig: u8[>..] = [];
        let r4 = openpgp::sign_detached(kr, 0, msg, sig, w);
        tv::check_int(str(what, ": sign"), r4, openpgp::OK);
        var pub: u8[>..] = [];
        let r5 = openpgp::export_public(kr, 0, pub, true);
        tv::check_int(str(what, ": export public"), r5, openpgp::OK);
        var kp = openpgp::Keyring { .. };
        tv::check_int(str(what, ": public read"), openpgp::add_keys(kp, pub), openpgp::OK);
        var mv = openpgp::Message { .. };
        let label_336 = str(what, ": verify");
        tv::check_int(label_336, openpgp::verify_detached(kp, msg, sig, mv), openpgp::OK);
        var enc2: u8[>..] = [];
        let r6 = openpgp::encrypt(kp, [0], "", msg, enc2, w);
        tv::check_int(str(what, ": encrypt to public"), r6, openpgp::OK);
        var sec: u8[>..] = [];
        let r7 = openpgp::export_secret(kr, 0, sec, false, "pw", 96);
        tv::check_int(str(what, ": export secret"), r7, openpgp::OK);
        var ks = openpgp::Keyring { .. };
        tv::check_int(str(what, ": secret read"), openpgp::add_keys(ks, sec), openpgp::OK);
        tv::check(str(what, ": locked"), ks.keys[0].locked && ks.keys[1].locked);
        tv::check_int(str(what, ": unlock"), openpgp::unlock(ks, 0, "pw"), openpgp::OK);
        read_ok(str(what, ": read with the re-read key"), ks, enc2, msg, false);
        // Another key of the same kind does not open it.
        var other = openpgp::Keyring { .. };
        let eo = if kind == 0 { openpgp::generate_pqc_key(other, "Other <o@example.com>") }
                 else { openpgp::generate_rfc9980_key(other, "Other <o@example.com>") };
        var mo = openpgp::Message { .. };
        let label_356 = str(what, ": other key");
        tv::check(label_356, openpgp::read_message(other, enc2, mo, openpgp::ReadOptions { .. }) != openpgp::OK);
    }
}

fn main() {
    kmac();
    sos();
    gpg();
    rfc9980();
    generated();
    tv::done("pqc");
}
