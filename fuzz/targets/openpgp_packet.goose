// Fuzz target: openpgp_packet. Binary OpenPGP data (or armored: the
// readers take both) through every reader:
//   - the packets walked (next_packet, packet_body), each key and
//     signature packet parsed, and a signature's trailer and digest;
//   - add_keys into a fresh keyring, then the lookups (find_key,
//     signing_key, encryption_key, usable, primary_uid), the keys exported
//     again, and secret keys unlocked with "fuzz" when their S2K is cheap
//     (iterated up to 2^20 octets, Argon2 up to 2^10 KiB and 2 passes);
//   - read_message against a fixed keyring (gpg's ed25519 secret key,
//     unprotected, and public keys of other types), with no passphrase,
//     or with "fuzz" when the first byte is odd and every SKESK's S2K is
//     cheap as above;
//   - verify_detached of msg.txt (what the detached vectors sign), and
//     list_packets.

import std;
import gslib from "../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.armor;
import gslib.crypto.openpgp.packet;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.sig;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import gslib.crypto.openpgp.dump;

let V = "../../crypto/openpgp/test/vectors/";
var KR = openpgp::Keyring { .. };
let MSG = embed_file("../../crypto/openpgp/test/vectors/msg.txt");   // what the det*.sig vectors sign

// Whether an S2K at data[at..] is cheap to run.
fn cheap_s2k(data: const u8[:], at: i64) -> bool {
    let s, next, err = openpgp::read_s2k(data, at);
    if err != openpgp::OK { return true; }      // refused before any work
    if s.kind == openpgp::S2K_ARGON2 { return s.m <= 10 && s.t <= 2; }
    if s.kind == openpgp::S2K_ITERATED { return s.count <= 1 << 20; }
    return true;
}

fn walk(data: const u8[:]) {
    var at = 0;
    var n = 0;
    while at < data.len && n < 4096 {
        let p, err = openpgp::next_packet(data, at);
        if err != openpgp::OK { break; }
        n++;
        at = p.end;
        var body: u8[>..] = [];
        openpgp::packet_body(data, p, body);
        let bl = openpgp::body_len(data, p);
        let t = p.tag;
        if t == openpgp::TAG_PUBLIC_KEY || t == openpgp::TAG_PUBLIC_SUBKEY || t == openpgp::TAG_SECRET_KEY ||
           t == openpgp::TAG_SECRET_SUBKEY {
            let k, ke = openpgp::parse_key(t, body);
            if ke == openpgp::OK {
                let nm = openpgp::key_type_name(k);
                let bits = openpgp::rsa_key_bits(k);
                if k.has_secret && !k.locked { let c = openpgp::check_secret(k); }
            }
        } else if t == openpgp::TAG_SIGNATURE {
            let s, se = openpgp::parse_signature(body);
            if se == openpgp::OK {
                let tr = openpgp::sig_trailer(s);
                // sig_digest asserts a known hash: its callers check first.
                if openpgp::hash_known(s.hash) { let d = openpgp::sig_digest(s, "data"); }
            }
        }
    }
}

fn keyring(data: const u8[:]) {
    var kr = openpgp::Keyring { .. };
    let e = openpgp::add_keys(kr, data);
    let q = openpgp::find_key(kr, "alice");
    for i in kr.keys.len {
        if !openpgp::is_primary(kr, i) { continue; }
        let u = openpgp::primary_uid(kr, i);
        let s = openpgp::signing_key(kr, i);
        let c = openpgp::encryption_key(kr, i);
        let us = openpgp::usable(kr, i, openpgp::FLAG_SIGN, 1700000000);
        var out: u8[>..] = [];
        let ee = openpgp::export_public(kr, i, out);
        let id = openpgp::key_by_id(kr, kr.keys[i].keyid);
        let fp = openpgp::key_by_fpr(kr, kr.keys[i].fpr);
    }
    // Unlock what is cheap to unlock.
    for i in kr.keys.len {
        if !kr.keys[i].has_secret || !kr.keys[i].locked || kr.keys[i].stub { continue; }
        if kr.keys[i].sexp { continue; }
        let s2k, iv_at, perr = openpgp::protection_of(kr.keys[i]);
        if perr != openpgp::OK { continue; }
        if s2k.kind == openpgp::S2K_ARGON2 && (s2k.m > 10 || s2k.t > 2) { continue; }
        if s2k.kind == openpgp::S2K_ITERATED && s2k.count > 1 << 20 { continue; }
        let ue = openpgp::unlock_key(kr.keys[i], "fuzz");
    }
}

fn skesks_cheap(data: const u8[:]) -> bool {
    var bin: u8[>..] = [];
    if openpgp::decode_input(data, bin) != openpgp::OK { return true; }
    var at = 0;
    var n = 0;
    while at < bin.len && n < 4096 {
        let p, err = openpgp::next_packet(bin, at);
        if err != openpgp::OK { break; }
        n++;
        at = p.end;
        if p.tag == openpgp::TAG_SKESK && p.body + 2 < p.body_end && !cheap_s2k(bin[p.body..p.body_end], 2) { return false; }
    }
    return true;
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let rest = data[1..];
    walk(rest);
    keyring(rest);
    var m = openpgp::Message { .. };
    var o = openpgp::ReadOptions { .. };
    o.max_size = 1 << 20;
    if data[0] % 2 == 1 && skesks_cheap(rest) { o.passphrase.append("fuzz"); }
    let e1 = openpgp::read_message(KR, rest, m, o);
    var md = openpgp::Message { .. };
    let e2 = openpgp::verify_detached(KR, MSG, rest, md);
    var t: u8[>..] = [];
    let e3 = openpgp::list_packets(rest, t);
    return 0;
}

fn main() {
    let e1 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/ed.sec"));
    let e2 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/rsa.pub"));
    let e3 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/nist.pub"));
    let e4 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/bp256.pub"));
    let e5 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/ed448.pub"));
}
