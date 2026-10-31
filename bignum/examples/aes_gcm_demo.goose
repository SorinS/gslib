// AES-256-GCM: seal a message with associated data, open it, see a
// tampered copy refused, and measure throughput.
//
//   goose examples/aes_gcm_demo.goose
import std;
import os;
import bignum from "..";
import bignum.gcm;
import bignum.entropy;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn main() {
    var key: u8[32] = [0; 32];
    var nonce: u8[12] = [0; 12];
    bignum::random_bytes(key);
    bignum::random_bytes(nonce);                         // never reuse one under a key
    let header = "record 1";
    let sealed = bignum::aes_gcm_seal(key, nonce, header, "meet me at the usual place");
    print("sealed: ", hex(sealed));
    let opened, ok = bignum::aes_gcm_open(key, nonce, header, sealed);
    print("opened: ", ok, " \"", opened, "\"");
    var tampered = copy(sealed);
    tampered[0] ^= 1;
    let none, ok2 = bignum::aes_gcm_open(key, nonce, header, tampered);
    print("tampered copy accepted: ", ok2);

    let g = bignum::gcm_init(key);
    var data: u8[>..] = [];
    data.resize(1 << 20, 0);
    let reps = 8;
    let t0 = clock();
    for i in reps { let tag = bignum::gcm_encrypt(g, nonce, header, data); }
    let mbs = reps / (clock() - t0);
    print("AES-256-GCM: ", (mbs * 10.0) as i64 / 10.0, " MB/s");
}
