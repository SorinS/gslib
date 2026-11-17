// Storing passwords: Argon2id (RFC 9106) with a random salt, kept as
// salt and hash and checked in constant time; bcrypt, whose string holds
// its own salt and cost; and bcrypt_pbkdf, OpenSSH's key derivation for
// encrypted private keys. The costs here are kept low so the example runs
// fast; see the comments for real settings.
//
//   goose examples/bignum/password_hash.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.argon2;
import gslib.crypto.bignum.bcrypt;
import gslib.crypto.bignum.ct;
import gslib.entropy;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

// What a server keeps for one user.
struct Stored { salt: u8[16], hash: u8[>..] }

// Argon2id with t = 1 pass over 8 MiB, one lane. RFC 9106 recommends
// t = 1, m = 2 GiB, or t = 3, m = 64 MiB where memory is short.
fn enroll(password: const u8[:]) -> Stored {
    var s = Stored { salt: [0; 16], hash: [] };
    entropy::random_bytes(s.salt);
    s.hash = bignum::argon2id_key(password, s.salt, 1, 8 * 1024, 1, 32);
    return s;
}

fn login(s: const Stored&, password: const u8[:]) -> bool {
    let h = bignum::argon2id_key(password, s.salt, 1, 8 * 1024, 1, 32);
    return bignum::ct_eq_bytes(h, s.hash) == 1;
}

fn main() {
    let alice = enroll("correct horse battery staple");
    print("argon2id salt ", hex(alice.salt), " hash ", hex(alice.hash));
    guard login(alice, "correct horse battery staple") && !login(alice, "Correct horse battery staple") else {
        print("password_hash: argon2id login check failed");
        exit(1);
    }
    // The general form also takes a secret key (a "pepper" kept apart
    // from the database) and associated data.
    let full = bignum::argon2(bignum::ARGON2ID, "password", "somesalt", "pepper", "", 2, 64, 1, 32);
    print("argon2id with a pepper ", hex(full));

    // bcrypt: "$2a$" strings with the cost and salt inside, as stored by
    // most web frameworks. Cost 10 is the default; 8 keeps this quick.
    let h, ok = bignum::bcrypt_hash("hunter2", 8);
    guard ok else { print("password_hash: bcrypt_hash failed"); exit(1); }
    print("bcrypt ", h, " (cost ", bignum::bcrypt_cost(h), ")");
    guard bignum::bcrypt_verify(h, "hunter2") && !bignum::bcrypt_verify(h, "hunter3") else {
        print("password_hash: bcrypt verify failed");
        exit(1);
    }
    // A hash made elsewhere (OpenBSD's test vector; "$2b$" and "$2y$"
    // read too).
    let known = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    guard bignum::bcrypt_verify(known, "U*U") else { print("password_hash: known bcrypt hash refused"); exit(1); }
    // Past 72 bytes bcrypt would ignore the rest, so it refuses.
    var long: u8[>..] = [];
    for i in 80 { long.push('a'); }
    let lh, lok = bignum::bcrypt_hash(long, 4);
    guard !lok else { print("password_hash: bcrypt took 80 bytes"); exit(1); }

    // bcrypt_pbkdf: the key and IV of an OpenSSH private key from its
    // passphrase (16 rounds is ssh-keygen's default).
    let kiv, okp = bignum::bcrypt_pbkdf("passphrase", "sixteen byte slt", 16, 48);
    guard okp && kiv.len == 48 else { print("password_hash: bcrypt_pbkdf failed"); exit(1); }
    print("bcrypt_pbkdf key ", hex(kiv[..32]), " iv ", hex(kiv[32..]));
    print("all password checks passed");
}
