// RFC 7748 test vectors for X448: §5.2 (two single calls and the 1 and
// 1000 iteration chain) and §6.2 (Alice and Bob's key agreement).
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.x448;

fn unhex(s: const u8[:]) -> u8[56] {
    assert(s.len == 112);
    var out: u8[56] = [0; 56];
    for i in 56 {
        let v, ok = parse_int(s[2 * i..2 * i + 2], 16);
        assert(ok);
        out[i] = v as! u8;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn expect(name: const u8[:], got: const u8[:], want: const u8[:]) {
    let g = hex(got);
    print(name, ": ", if g == want { "ok" } else { "FAIL" });
    if g != want { print("  got  ", g, "\n  want ", want); }
    assert(g == want);
}

fn main() {
    expect("5.2 vector 1",
        bignum::x448(unhex("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"),
                     unhex("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086")),
        "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
    expect("5.2 vector 2",
        bignum::x448(unhex("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"),
                     unhex("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db")),
        "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d");

    var k: u8[56] = [0; 56];
    k[0] = 5;
    var u = k;
    for i in 1000 {
        let r = bignum::x448(k, u);
        u = k;
        k = r;
        if i == 0 { expect("5.2 after 1 iteration", k, "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"); }
    }
    expect("5.2 after 1000 iterations", k, "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38");

    let alice = unhex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    let bob = unhex("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
    let alice_pub = bignum::x448_base(alice);
    let bob_pub = bignum::x448_base(bob);
    expect("6.2 Alice's public key", alice_pub, "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
    expect("6.2 Bob's public key", bob_pub, "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
    let shared = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";
    let s1, ok1 = bignum::x448_shared(alice, bob_pub);
    let s2, ok2 = bignum::x448_shared(bob, alice_pub);
    assert(ok1 && ok2);
    expect("6.2 Alice's shared secret", s1, shared);
    expect("6.2 Bob's shared secret", s2, shared);
}
