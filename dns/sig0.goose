// dns.sig0: SIG(0) (RFC 2931), a message signed with a KEY's private key,
// as miekg's SIG.Sign and SIG.Verify do it: RSA and ECDSA keys, as
// dns.dnssec holds them.

namespace dns;

import std;
import dns;
import dns.rdata;
import dns.msg;
import dns.dnssec;
import dns.tsig;
import crypto.bignum;
import crypto.bignum.rsa;
import crypto.bignum.ec;

// Signs the packed message w with a KEY's private key (miekg's SIG.Sign):
// a SIG record at the end of the additional section, owner the root,
// class ANY, its signature over its own rdata and the message before it.
// RSA and ECDSA, as in miekg.
fn sig0_sign(w: u8[>..]&, key: const PrivateKey&, signer: const u8[:], key_rd: const u8[:], inception: i64, expiration: i64) -> i64 {
    if !is_rsa(key.alg) && !is_ecdsa(key.alg) { return ERR_ALG; }
    if w.len < 12 { return ERR_BUF; }
    var rd: u8[>..] = [];
    put16(rd, 0);
    rd.push(key.alg);
    rd.push(0);
    put32(rd, 0);
    put32(rd, (expiration & 0xffffffff) as! u32);
    put32(rd, (inception & 0xffffffff) as! u32);
    put16(rd, key_tag(key_rd));
    rd.append(signer);
    var data: u8[>..] = [];
    data.append(rd);
    data.append(w);
    var sig: u8[>..] = [];
    let e = sign_data(key, data, sig);
    if e != OK { return e; }
    rd.append(sig);
    rr_append(w, [0], TYPE_SIG, CLASS_ANY, 0, rd);
    set16(w, 10, get16(w, 10) + 1);
    return OK;
}

// Verifies a packed message's SIG(0) with the KEY (owner and rdata), as
// miekg's SIG.Verify: the validity period against now, the signer the
// key's owner, the signature.
fn sig0_verify(w: const u8[:], key_owner: const u8[:], key_rd: const u8[:], now: i64) -> i64 {
    if w.len < 12 || get16(w, 10) == 0 { return ERR_NO_SIG; }
    let off = last_record_offset(w);
    if off < 0 { return ERR_RDATA; }
    let n, next, e = read_name(w, off);
    if get16(w, next) != TYPE_SIG { return ERR_NO_SIG; }
    let rdstart = next + 10;
    let rdend = rdstart + get16(w, next + 8);
    if rdend - rdstart < 20 { return ERR_RDATA; }
    let rd = w[rdstart..rdend];
    let expire = get32(rd, 8) as i64;
    let incept = get32(rd, 12) as i64;
    let t = now & 0xffffffff;
    if t < incept || t > expire { return ERR_TIME; }
    let signer, sp, se = read_name(w, rdstart + 18);
    if se != OK || !name_equal(signer, key_owner) { return ERR_AUTH; }
    if key_tag(key_rd) != get16(rd, 16) || key_rd.len < 5 || dnskey_alg(key_rd) != rd[2] { return ERR_KEY; }
    var data: u8[>..] = [];
    data.append(w[rdstart..sp]);
    data.append(w[..off]);
    set16(data, sp - rdstart + 10, get16(w, 10) - 1);
    let sig = w[sp..rdend];
    let alg = rd[2];
    let pk = dnskey_public(key_rd);
    if is_rsa(alg) {
        let k, ok = rsa_public_of(pk);
        if !ok { return ERR_KEY; }
        let h = alg_hash(alg);
        return if bignum::rsa_verify_pkcs1_digest(k, hash_of(h, data), sig, h) { OK } else { ERR_SIG };
    }
    if is_ecdsa(alg) {
        let c = curve_of(alg);
        if pk.len != 2 * c.len { return ERR_KEY; }
        var full: u8[>..] = [4];
        full.append(pk);
        let h = alg_hash(alg);
        return if bignum::ecdsa_verify_digest(c, full, hash_of(h, data), sig) { OK } else { ERR_SIG };
    }
    return ERR_ALG;
}
