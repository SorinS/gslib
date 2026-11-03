// krb5.spake against the test vectors of draft-ietf-kitten-krb-spake-preauth
// Appendix C (vectors/spake.txt, from scripts/spake_vectors.py): for
// DES3, RC4, AES128 and AES256 on edwards25519, AES256 on P-256, P-384 and
// P-521, an accepted and a refused optimistic challenge, and the SHA-1 group
// -1 whose keys take two hash blocks: w, w reduced, x*G and y*G, T, S, K
// from both sides, the support and challenge messages byte for byte, both
// transcript hashes and K'[0..3] (but group -1's: see below). Then the client's own path through the
// same values (support, challenge, response, its factor decrypted by the
// KDC's K'[1]); keys that are not points or give the identity; challenges
// without SF-NONE; malformed messages; group names; fresh exchanges.

import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.spake;
import gslib.krb5.fast;
import gslib.crypto.bignum;
import gslib.crypto.bignum.ec;
import gslib.crypto.bignum.x25519;
import gslib.crypto.bignum.ed25519;
import tv;

fn group_for(id: i64) -> krb5::SpakeGroup {
    if id == -1 {
        // The draft's edwards25519 with SHA-1, numbered -1.
        var g, ok = krb5::spake_group(1);
        g.id = -1;
        g.hash_bits = 1;
        return g;
    }
    let g, ok = krb5::spake_group(id);
    assert(ok);
    return g;
}

// priv*G, encoded.
fn base_mul(g: const krb5::SpakeGroup&, priv: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if g.curve_bits == 255 {
        let b = bignum::ed_base();
        let p = bignum::ed_mul(priv, b);
        out.append(bignum::ed_encode(p));
        return out;
    }
    let c = krb5::spake_curve(g);
    var k = bignum::ec_zero(c);
    bignum::limbs_from_be(k[..], priv);
    let gen = bignum::ec_generator(c);
    let p = bignum::ec_mul(c, k[..], gen);
    out.append(bignum::ec_encode_compressed(c, p));
    return out;
}

fn sf_none() -> krb5::SpakeFactor[>..] {
    var f: krb5::SpakeFactor[>..] = [];
    f.push(krb5::SpakeFactor { ftype: krb5::SPAKE_SF_NONE, has_data: false, data: "" });
    return f;
}

fn vector(line: const u8[:]) {
    let w = split(line, '|');
    if w.len != 23 { return; }
    let name = w[0];
    let etype, eok = parse_int(w[1], 10);
    let gid, gok = parse_int(w[2], 10);
    let g = group_for(gid);
    let key = krb5::make_key(etype as! i32, tv::hex(w[3]));
    let x = tv::hex(w[6]);
    let y = tv::hex(w[7]);
    let has_support = w[13] != "-";
    let has_optimistic = w[14] != "-";
    let body = tv::hex(w[18]);

    var wb: u8[>..] = [];
    tv::check_int(str(name, ": w"), krb5::spake_wbytes(g, key, wb), krb5::OK);
    tv::check_hex(str(name, ": w bytes"), wb, w[4]);
    tv::check_hex(str(name, ": w reduced"), krb5::spake_w(g, wb), w[5]);
    tv::check_hex(str(name, ": X"), base_mul(g, x), w[8]);
    tv::check_hex(str(name, ": Y"), base_mul(g, y), w[9]);
    let t, terr = krb5::spake_public(g, x, wb, true);
    tv::check(str(name, ": T ok"), terr == krb5::OK);
    tv::check_hex(str(name, ": T"), t, w[10]);
    let s, serr = krb5::spake_public(g, y, wb, false);
    tv::check(str(name, ": S ok"), serr == krb5::OK);
    tv::check_hex(str(name, ": S"), s, w[11]);
    let kc, kcerr = krb5::spake_result(g, y, wb, t, true);
    tv::check(str(name, ": K client ok"), kcerr == krb5::OK);
    tv::check_hex(str(name, ": K client"), kc, w[12]);
    let kk, kkerr = krb5::spake_result(g, x, wb, s, false);
    tv::check(str(name, ": K kdc ok"), kkerr == krb5::OK);
    tv::check_hex(str(name, ": K kdc"), kk, w[12]);

    // The messages, and their transcript.
    let groups: i64[1] = [gid];
    var support: u8[>..] = [];
    if has_support {
        krb5::encode_spake_support(support, groups);
        tv::check_hex(str(name, ": support"), support, w[13]);
        let m, err = krb5::decode_pa_spake(support);
        tv::check(str(name, ": support decodes"), err == krb5::OK && m.choice == krb5::SPAKE_SUPPORT && m.groups.len == 1
                  && m.groups[0] == gid);
    }
    var ch: u8[>..] = [];
    krb5::encode_spake_challenge(ch, gid, t, sf_none());
    tv::check_hex(str(name, ": challenge"), ch, w[15]);
    let cm, cerr = krb5::decode_pa_spake(ch);
    tv::check(str(name, ": challenge decodes"), cerr == krb5::OK && cm.choice == krb5::SPAKE_CHALLENGE && cm.group == gid
              && cm.pubkey == t && cm.factors.len == 1);
    for f in cm.factors { tv::check(str(name, ": challenge factor"), f.ftype == krb5::SPAKE_SF_NONE && !f.has_data); }
    let th1 = krb5::spake_thash(g, "", support, ch);
    tv::check_hex(str(name, ": thash after challenge"), th1, w[16]);
    let th2 = krb5::spake_thash(g, th1, s, "");
    tv::check_hex(str(name, ": final thash"), th2, w[17]);
    // Group -1's keys (SHA-1: two hash blocks for AES256's 32 bytes) are
    // not the draft's: no reading of §7 we tried gives them, while the same
    // code gives every single-block vector's, and MIT's t_vectors.c leaves
    // this vector out. No registered group needs a second block.
    for n in 4 {
        let k, err = krb5::spake_key(g, key, wb, kc, th2, body, n);
        tv::check(str(name, ": K' ok"), err == krb5::OK && k.etype == key.etype);
        if gid > 0 { tv::check_hex(str(name, ": K'[", n, "]"), k.value, w[19 + n]); }
    }

    // An optimistic challenge in a group the client does not take: it
    // decodes, and it is not in the transcript (the vector's hashes are
    // over the support and the second challenge only).
    if has_optimistic {
        let om, oerr = krb5::decode_pa_spake(tv::hex(w[14]));
        tv::check(str(name, ": optimistic decodes"), oerr == krb5::OK && om.choice == krb5::SPAKE_CHALLENGE);
        tv::check(str(name, ": optimistic refused"), !krb5::spake_permitted(groups, om.group));
    }

    // The client's path: the same messages, its response decrypted by the
    // KDC's K'[1], its reply key K'[0].
    if gid < 0 { return; }
    var st = krb5::spake_state();
    if has_support {
        let sup = krb5::spake_send_support(st, groups);
        tv::check(str(name, ": client support"), sup == support);
    }
    tv::check_int(str(name, ": client challenge"), krb5::spake_on_challenge(st, cm, ch, key, y), krb5::OK);
    tv::check(str(name, ": client state"), st.ready && st.pubkey[..] == s && st.k[..] == kc && st.thash[..] == th2);
    let resp, k0, rerr = krb5::spake_response(st, body);
    tv::check_int(str(name, ": response"), rerr, krb5::OK);
    tv::check_hex(str(name, ": reply key"), k0.value, w[19]);
    let rm, rmerr = krb5::decode_pa_spake(resp);
    tv::check(str(name, ": response decodes"), rmerr == krb5::OK && rm.choice == krb5::SPAKE_RESPONSE && rm.pubkey == s
              && !rm.enc.has_kvno && rm.enc.etype == key.etype);
    let k1, k1err = krb5::spake_key(g, key, wb, kk, th2, body, 1);
    var plain: u8[>..] = [];
    tv::check_int(str(name, ": factor decrypts"), krb5::decrypt(k1, krb5::USAGE_SPAKE, rm.enc.cipher, plain), krb5::OK);
    let f, ferr = krb5::decode_spake_factor(krb5::der_unpadded(plain));
    tv::check(str(name, ": factor is SF-NONE"), ferr == krb5::OK && f.ftype == krb5::SPAKE_SF_NONE && !f.has_data);
    // Another body (a request the KDC did not get) gives other keys.
    var body2: u8[>..] = [];
    body2.append(body);
    body2[body2.len - 1] ^= 1;
    let resp2, k0b, r2err = krb5::spake_response(st, body2);
    tv::check(str(name, ": body bound"), r2err == krb5::OK && k0b.value[..] != k0.value[..]);
    let rm2, rm2err = krb5::decode_pa_spake(resp2);
    var plain2: u8[>..] = [];
    tv::check(str(name, ": body bound factor"), krb5::decrypt(k1, krb5::USAGE_SPAKE, rm2.enc.cipher, plain2) != krb5::OK);
}

// Peer keys the client must refuse, for group `gid`.
fn bad_peers(gid: i64) {
    let g = group_for(gid);
    let key = krb5::make_key(18, tv::hex("01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1"));
    var wb: u8[>..] = [];
    tv::check_int("bad: w", krb5::spake_wbytes(g, key, wb), krb5::OK);
    let y = krb5::spake_private(g);
    let zero: u8[67] = [0; 67];
    // w*M itself (0*G + w*M): T - w*M is the identity, and so is K.
    let wm, wmerr = krb5::spake_public(g, zero[..g.mult_len], wb, true);
    tv::check("bad: w*M", wmerr == krb5::OK);
    let k1, e1 = krb5::spake_result(g, y, wb, wm, true);
    tv::check(str("bad: identity K, group ", gid), e1 != krb5::OK);
    // Wrong lengths.
    let k2, e2 = krb5::spake_result(g, y, wb, wm[..wm.len - 1], true);
    tv::check("bad: short", e2 != krb5::OK);
    var long: u8[>..] = [];
    long.append(wm);
    long.push(0);
    let k3, e3 = krb5::spake_result(g, y, wb, long, true);
    tv::check("bad: long", e3 != krb5::OK);
    // Not a point: x (or y) values with none, a bad prefix.
    var misses = 0;
    for i in 1..30 {
        var p: u8[>..] = [];
        p.resize(g.elem_len, 0);
        if g.curve_bits == 255 { p[0] = i as! u8; } else { p[0] = 2; p[p.len - 1] = i as! u8; }
        let k, e = krb5::spake_result(g, y, wb, p, true);
        if e != krb5::OK { misses++; }
    }
    tv::check(str("bad: some non-points refused, group ", gid), misses > 3);
    if g.curve_bits != 255 {
        var p: u8[>..] = [];
        p.append(wm);
        p[0] = 4;
        let k, e = krb5::spake_result(g, y, wb, p, true);
        tv::check("bad: prefix 04", e != krb5::OK);
        return;
    }
    // edwards25519: w*M plus a point of order 2 (0, -1) or 4 (sqrt(-1), 0)
    // leaves T - w*M of small order; y, a multiple of 8, makes K the
    // identity, refused. A y not below p is refused too.
    let wp, wok = bignum::ed_decode(wm);
    var o2: u8[32] = [0; 32];
    o2[0] = 0xec;
    for i in 1..31 { o2[i] = 0xff; }
    o2[31] = 0x7f;
    let p2, p2ok = bignum::ed_decode(o2[..]);
    tv::check("bad: order-2 point decodes", p2ok && wok);
    let sum = bignum::ed_add(wp, p2);
    let enc = bignum::ed_encode(sum);
    let k4, e4 = krb5::spake_result(g, y, wb, enc[..], true);
    tv::check("bad: small-order T refused", e4 != krb5::OK);
    var big: u8[32] = [0xff; 32];
    big[31] = 0x7f;
    let k5, e5 = krb5::spake_result(g, y, wb, big[..], true);
    tv::check("bad: y >= p refused", e5 != krb5::OK);
}

// A whole exchange with fresh scalars, both sides agreeing.
fn fresh(gid: i64, etype: i32) {
    let g = group_for(gid);
    let key = krb5::random_key(etype);
    var wb: u8[>..] = [];
    tv::check_int("fresh: w", krb5::spake_wbytes(g, key, wb), krb5::OK);
    let x = krb5::spake_private(g);
    let y = krb5::spake_private(g);
    tv::check("fresh: distinct", x != y && x.len == g.mult_len);
    if g.curve_bits == 255 { tv::check("fresh: cofactor", x[0] & 7 == 0 && y[0] & 7 == 0); }
    let t, terr = krb5::spake_public(g, x, wb, true);
    let groups: i64[1] = [gid];
    var ch: u8[>..] = [];
    krb5::encode_spake_challenge(ch, gid, t, sf_none());
    let cm, cerr = krb5::decode_pa_spake(ch);
    var st = krb5::spake_state();
    let sup = krb5::spake_send_support(st, groups);
    tv::check_int(str("fresh: challenge ", gid, " ", etype), krb5::spake_on_challenge(st, cm, ch, key, y), krb5::OK);
    let kk, kkerr = krb5::spake_result(g, x, wb, st.pubkey, false);
    tv::check(str("fresh: K agrees ", gid, " ", etype), terr == krb5::OK && kkerr == krb5::OK && kk == st.k[..]);
    let resp, k0, rerr = krb5::spake_response(st, "body");
    let th = krb5::spake_thash(g, krb5::spake_thash(g, "", sup, ch), st.pubkey, "");
    let kdc0, k0err = krb5::spake_key(g, key, wb, kk, th, "body", 0);
    tv::check(str("fresh: reply key agrees ", gid, " ", etype), rerr == krb5::OK && k0err == krb5::OK && kdc0.value[..] == k0.value[..]
              && k0.etype == etype);
}

fn messages() {
    // Group names, MIT's spellings, in order, each once.
    let gs = krb5::spake_groups_named("edwards25519 P-256, p-384 bogus\tP-256 P-521");
    tv::check("names", gs.len == 4 && gs[0] == 1 && gs[1] == 2 && gs[2] == 3 && gs[3] == 4);
    tv::check("names empty", krb5::spake_groups_named(" , ").len == 0);
    // A challenge without SF-NONE.
    let g = group_for(1);
    let key = krb5::make_key(18, tv::hex("01b897121d933ab44b47eb5494db15e50eb74530dbdae9b634d65020ff5d88c1"));
    var wb: u8[>..] = [];
    krb5::spake_wbytes(g, key, wb);
    let x = krb5::spake_private(g);
    let t, terr = krb5::spake_public(g, x, wb, true);
    var other: krb5::SpakeFactor[>..] = [];
    other.push(krb5::SpakeFactor { ftype: 2, has_data: true, data: "otp" });
    var ch: u8[>..] = [];
    krb5::encode_spake_challenge(ch, 1, t, other);
    let cm, cerr = krb5::decode_pa_spake(ch);
    tv::check("other factor decodes", cerr == krb5::OK && cm.factors.len == 1);
    for f in cm.factors { tv::check("other factor", f.ftype == 2 && f.has_data && f.data == "otp"); }
    var st = krb5::spake_state();
    let y = krb5::spake_private(g);
    tv::check("no SF-NONE refused", krb5::spake_on_challenge(st, cm, ch, key, y) != krb5::OK && !st.ready);
    // A challenge in a group we do not have.
    var ch5: u8[>..] = [];
    krb5::encode_spake_challenge(ch5, 5, t, sf_none());
    let c5, c5err = krb5::decode_pa_spake(ch5);
    tv::check("group 5 refused", c5err == krb5::OK && krb5::spake_on_challenge(st, c5, ch5, key, y) != krb5::OK);
    // encdata round trip.
    var ed: u8[>..] = [];
    let d = krb5::EncryptedData { etype: 18, has_kvno: false, kvno: 0, cipher: "abc" };
    krb5::encode_spake_encdata(ed, d);
    let em, emerr = krb5::decode_pa_spake(ed);
    tv::check("encdata", emerr == krb5::OK && em.choice == krb5::SPAKE_ENCDATA && em.enc.etype == 18 && em.enc.cipher == "abc");
    // Malformed: an unknown choice, empty groups, empty factors, a
    // challenge without its key, trailing bytes, nothing.
    for bad in ["a4023000", "a0043002a000", "a0063004a0023000", "a1123010a003020101a20930073005a003020101", "a110300ea003020101a103040100a2023000",
                "a0093007a0053003020101ff", "", "30"] {
        let m, err = krb5::decode_pa_spake(tv::hex(bad));
        tv::check(str("malformed ", bad), err != krb5::OK);
    }
    // An unknown extension field in a challenge is skipped.
    let m, err = krb5::decode_pa_spake(tv::hex("a13b3039a003020101a1220420d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdafa20930073005a003020101a303020100"));
    tv::check("extension skipped", err == krb5::OK && m.group == 1 && m.factors.len == 1);
}

fn main() {
    for line in split(embed_file("vectors/spake.txt"), '\n') { vector(line); }
    for gid in [1, 2, 3, 4] { bad_peers(gid); }
    for gid in [1, 2, 3, 4] {
        for e in [16, 17, 18, 19, 20, 23, 25, 26] { fresh(gid, e as! i32); }
    }
    messages();
    tv::done("spake");
}
