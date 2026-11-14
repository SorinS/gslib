// openpgp.ocb against RFC 7253 Appendix A: the sixteen AES-128 samples,
// each decrypted back and refused with a changed byte, and the iterative
// test for AES-128, AES-192 and AES-256.
import std;
import gslib from "../../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.ocb;
import tv;

// N's last byte, A's and P's lengths, C.
let SAMPLES = [
    "00||", "785407BFFFC8AD9EDCC5520AC9111EE6",
    "01|8|8", "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009",
    "02|8|", "81017F8203F081277152FADE694A0A00",
    "03||8", "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9",
    "04|16|16", "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358",
    "05|16|", "8CF761B6902EF764462AD86498CA6B97",
    "06||16", "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D",
    "07|24|24", "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F",
    "08|24|", "6DC225A071FC1B9F7C69F93B0F1E10DE",
    "09||24", "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF",
    "0A|32|32", "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240",
    "0B|32|", "FE80690BEE8A485D11F32965BC9D2A32",
    "0C||32", "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF",
    "0D|40|40", "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60",
    "0E|40|", "C5CD9D1850C141E358649994EE701B68",
    "0F||40", "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479",
];

fn seq(n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    for i in n { out.push(i as! u8); }
    return out;
}

fn int_or_zero(s: const u8[:]) -> i64 {
    if s.len == 0 { return 0; }
    let v, ok = parse_int(s);
    return v;
}

fn samples() {
    let o = openpgp::ocb_init(seq(16));
    var i = 0;
    while i < SAMPLES.len {
        let f = split(SAMPLES[i], '|');
        let want = tv::unhex(SAMPLES[i + 1]);
        var nonce = tv::unhex("BBAA998877665544332211");
        nonce.append(tv::unhex(f[0]));
        let ad = seq(int_or_zero(f[1]));
        var data = seq(int_or_zero(f[2]));
        let tag = openpgp::ocb_encrypt(o, nonce, ad, data);
        var got: u8[>..] = [];
        got.append(data);
        got.append(tag);
        tv::check_eq(str("sample ", f[0]), got, want);
        tv::check(str("sample ", f[0], " opens"), openpgp::ocb_decrypt(o, nonce, ad, data, tag));
        tv::check_eq(str("sample ", f[0], " plaintext"), data, seq(int_or_zero(f[2])));
        // A changed ciphertext, AD or tag is refused.
        var bad = copy(tag);
        bad[3] ^= 1;
        let e1 = openpgp::ocb_encrypt(o, nonce, ad, data);
        tv::check(str("sample ", f[0], " bad tag"), !openpgp::ocb_decrypt(o, nonce, ad, data, bad));
        if data.len > 0 {
            let e2 = openpgp::ocb_encrypt(o, nonce, ad, data);
            data[0] ^= 0x80;
            tv::check(str("sample ", f[0], " bad data"), !openpgp::ocb_decrypt(o, nonce, ad, data, e2));
        }
        i += 2;
    }
}

fn num96(v: i64) -> u8[>..] {
    var out: u8[>..] = [];
    for i in 4 { out.push(0); }
    for i in 8 { out.push((v >> (56 - 8 * i) & 255) as! u8); }
    return out;
}

// RFC 7253 §A's iterative test, TAGLEN 128.
fn iterative(keylen: i64, want: const u8[:]) {
    var key: u8[>..] = [];
    for i in keylen - 1 { key.push(0); }
    key.push(128);
    let o = openpgp::ocb_init(key);
    var c: u8[>..] = [];
    for i in 128 {
        var s: u8[>..] = [];
        for j in i { s.push(0); }
        var p = copy(s);
        let t1 = openpgp::ocb_encrypt(o, num96(3 * i + 1), s, p);
        c.append(p); c.append(t1);
        var p2 = copy(s);
        let t2 = openpgp::ocb_encrypt(o, num96(3 * i + 2), "", p2);
        c.append(p2); c.append(t2);
        var e: u8[0] = [];
        let t3 = openpgp::ocb_encrypt(o, num96(3 * i + 3), s, e);
        c.append(t3);
    }
    var e: u8[0] = [];
    let t = openpgp::ocb_encrypt(o, num96(385), c, e);
    tv::check_eq(str("iterative AES-", 8 * keylen), t, tv::unhex(want));
}

fn main() {
    samples();
    iterative(16, "67E944D23256C5E0B6C61FA22FDF1EA2");
    iterative(24, "F673F2C3E7174AAE7BAE986CA9F29E17");
    iterative(32, "D90EB8E9C977C88B79DD793D7FFA161C");
    tv::done("ocb");
}
