// bignum.kmac against NIST SP 800-185's KMAC samples 1 to 6 (KMAC128 and
// KMAC256, with and without a customization string), and two lengths the
// samples do not have (17 bytes, and 1 byte of an empty message), from
// openssl's KMAC; then a tag of one length is not a prefix of another's.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.kmac;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        var v = 0;
        for j in 2 {
            let c = s[i + j];
            let d = if c >= '0' && c <= '9' { c - '0' } else if c >= 'a' && c <= 'f' { c - 'a' + 10 } else { c - 'A' + 10 };
            v = v * 16 + d;
        }
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn main() {
    var key: u8[>..] = [];
    for i in 32 { key.push((0x40 + i) as! u8); }
    var d4: u8[>..] = [];
    for i in 4 { d4.push(i as! u8); }
    var d200: u8[>..] = [];
    for i in 200 { d200.push(i as! u8); }
    let tagged = "My Tagged Application";

    check("sample 1", bignum::kmac(128, key, d4, 32)
          == unhex("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"));
    check("sample 2", bignum::kmac(128, key, d4, 32, tagged)
          == unhex("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"));
    check("sample 3", bignum::kmac(128, key, d200, 32, tagged)
          == unhex("1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230"));
    check("sample 4", bignum::kmac(256, key, d4, 64, tagged)
          == unhex("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"));
    check("sample 5", bignum::kmac(256, key, d200, 64)
          == unhex("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"));
    check("sample 6", bignum::kmac(256, key, d200, 64, tagged)
          == unhex("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"));
    check("KMAC128, 17 bytes", bignum::kmac(128, key, d200, 17, tagged) == unhex("B32EAD046C675F8660E22640522E0202D2"));
    check("KMAC256, 1 byte of nothing", bignum::kmac(256, key, "", 1) == unhex("D2"));

    // The length is part of the input: 16 bytes are not the first 16 of 32.
    let short = bignum::kmac(128, key, d4, 16);
    let long = bignum::kmac(128, key, d4, 32);
    check("lengths", short.len == 16 && long.len == 32 && short[..] != long[..16]);

    print("kmac vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
