// RFC 7748 test vectors: §5.2 (two single calls and the 1 and 1000
// iteration chain) and §6.1 (Alice and Bob's key agreement).
import std;
import bignum from "..";
import bignum.x25519;

fn unhex(s: const u8[:]) -> u8[32] {
    assert(s.len == 64);
    var out: u8[32] = [0; 32];
    for i in 32 {
        let hi, ok1 = parse_int(s[2 * i..2 * i + 1], 16);
        let lo, ok2 = parse_int(s[2 * i + 1..2 * i + 2], 16);
        assert(ok1 && ok2);
        out[i] = (hi * 16 + lo) as u8;
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
        bignum::x25519(unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                       unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    expect("5.2 vector 2",
        bignum::x25519(unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                       unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")),
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

    var k: u8[32] = [0; 32];
    k[0] = 9;
    var u = k;
    for i in 1000 {
        let r = bignum::x25519(k, u);
        u = k;
        k = r;
        if i == 0 { expect("5.2 after 1 iteration", k, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"); }
    }
    expect("5.2 after 1000 iterations", k, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

    let alice = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let alice_pub = bignum::x25519_base(alice);
    let bob_pub = bignum::x25519_base(bob);
    expect("6.1 Alice's public key", alice_pub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    expect("6.1 Bob's public key", bob_pub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    expect("6.1 Alice's shared secret", bignum::x25519(alice, bob_pub), shared);
    expect("6.1 Bob's shared secret", bignum::x25519(bob, alice_pub), shared);
}
