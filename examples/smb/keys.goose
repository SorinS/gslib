// keys: SMB 3.1.1's cryptography without a server, on Microsoft's own
// example (the "SMB 3.1.1 Encryption in Windows 10" test vector): the
// session's keys from its session key and preauth integrity hash, then a
// WRITE request encrypted with AES-128-GCM into the transformed message
// Windows sent, decrypted again, and a message signed with AES-128-GMAC
// and checked.
//
//   goose examples/smb/keys.goose

import std;
import gslib from "../..";
import gslib.smb;
import gslib.smb.crypto;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn main() {
    let session_key = unhex("419fddf34c1e001909d362ae7fb6af79");
    let preauth = unhex("b23f3cbfd69487d9832b79b1594a367cdd950909b774c3a4c412b4fcea9edddba7db256ba2ea30e977f11f9b113247578e0e915c6d2a513b8f2fca5707dc8770");
    let k = smb::derive_keys(smb::SMB311, session_key, preauth, smb::AES128_GCM);
    print("signing key    ", hex(k.signing));          // 8765949dfeaee105ce9118b45be988f0
    print("encryption key ", hex(k.enc[..16]));         // a2f5e80e5d59103034f32e52f698e5ec
    print("decryption key ", hex(k.dec[..16]));         // 748c50868c90f302962a5c35f5f9a8bf

    let write = unhex(str("fe534d4240000100000000000900010008000000000000000500000000000000fffe000001000000",
                          "25000000001000000000000000000000000000000000000031007000170000000000000000000000",
                          "0600000004000000010000000400000000000000000000007000000000000000536d623320656e63",
                          "72797074696f6e2074657374696e67"));
    let nonce = unhex("c7d6822d269caf48904c664c");
    let tm = smb::encrypt_message(smb::AES128_GCM, k.enc[..16], nonce, 0x100000000025, write);
    print("transformed    ", tm.len, " bytes, tag ", hex(tm[4..20]));   // bd73d97d2bc9001bcafac0fdff5feebc
    let back, ok = smb::decrypt_message(smb::AES128_GCM, k.enc[..16], tm);
    print("decrypted      ", if ok && back == write { "the same WRITE" } else { "FAILED" });

    var m = copy(write);
    smb::sign(smb::AES_GMAC, k.signing, m);
    print("GMAC signature ", hex(m[48..64]), if smb::verify(smb::AES_GMAC, k.signing, m) { " (verifies)" } else { " (BAD)" });
}
