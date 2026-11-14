// openpgp.keyring: transferable public and secret keys (RFC 9580 §10.1,
// §10.2): a primary key, its user IDs and their self-signatures, its
// subkeys and their binding signatures, all checked as they are read.
//
//   var kr = openpgp::Keyring { .. };
//   let err = openpgp::add_keys(kr, armored_or_binary);   // any number of keys
//   let k = openpgp::find_key(kr, "test@example.com");    // a primary's index, or -1
//   let err = openpgp::unlock(kr, k, passphrase);         // its protected secrets
//   var out: u8[>..] = [];
//   openpgp::export_public(kr, k, out, true);             // armored
//
// A keyring holds keys (Key, fixed-size), user IDs (Uid) and every packet
// it read, so a key can be written back as it came. A key is referred to
// by its index in kr.keys; a subkey's `primary` is its primary's index.
//
// What is checked: each user ID's self-certification (types 0x10-0x13)
// by the primary, each subkey's binding (0x18) by the primary, and, for a
// subkey that can sign, its back-signature (0x19, embedded) by the subkey;
// revocations (0x20, 0x28, 0x30) by the key itself. The newest valid
// self-signature gives the key flags and the expiry, as in gpg. Third-party
// certifications are kept but not checked: there is no web of trust here.

namespace openpgp;

import std;
import crypto.openpgp;
import crypto.openpgp.armor;
import crypto.openpgp.packet;
import crypto.openpgp.key;
import crypto.openpgp.pqc;
import crypto.openpgp.sig;

struct Uid {
    key:          i64        = -1,   // the primary's index
    text:         u8[..1024] = [],
    valid:        bool       = false, // a valid self-certification
    revoked:      bool       = false,
    primary:      bool       = false, // its self-certification says it is the primary user ID
    certified_at: i64        = 0,
}

// A packet of the keyring: its tag, whose transferable key it is part of,
// and where it is in raw.
struct Rec { tag: i64, key: i64, start: i64, end: i64 }

root struct Keyring {
    keys: Key[>..] = [],
    uids: Uid[>..] = [],
    raw:  u8[>..]  = [],             // the packets read, back to back
    recs: Rec[>..] = [],
}

let MAX_KEY_PACKETS: i64 = 100000;

// What applies a self-signature's key data to a key: flags and expiry.
fn take_self_sig(k: Key&, s: const Signature&) {
    if s.created < k.bound_at { return; }
    k.bound_at = s.created;
    k.has_flags = s.has_flags;
    k.flags = s.flags;
    k.expires = s.key_expires;
}

// The state of reading: the current primary, subkey and user ID.
struct ReadState { primary: i64 = -1, sub: i64 = -1, uid: i64 = -1, primary_uid_seen: bool = false }

fn handle_signature(kr: Keyring&, st: ReadState&, body: const u8[:]) {
    if st.primary < 0 { return; }
    let s, err = parse_signature(body);
    if err != OK { return; }
    let pk = kr.keys[st.primary];
    if !issued_by(s, pk) { return; }
    var data: u8[>..] = [];
    put_key_hash(data, pk);
    let t = s.sigtype;
    if st.sub < 0 && st.uid < 0 {
        // Directly on the primary: direct-key signatures and revocations.
        if t != SIG_DIRECT_KEY && t != SIG_KEY_REVOCATION { return; }
        if verify_signature(pk, s, data) != OK { return; }
        if t == SIG_KEY_REVOCATION { kr.keys[st.primary].revoked = true; return; }
        kr.keys[st.primary].valid = true;
        if s.has_flags || s.key_expires > 0 { take_self_sig(kr.keys[st.primary], s); }
        return;
    }
    if st.sub < 0 {
        // On a user ID.
        if !(t >= SIG_CERT_GENERIC && t <= SIG_CERT_POSITIVE) && t != SIG_CERT_REVOCATION { return; }
        put_uid_hash(data, kr.uids[st.uid].text);
        if verify_signature(pk, s, data) != OK { return; }
        if t == SIG_CERT_REVOCATION { kr.uids[st.uid].revoked = true; return; }
        if s.created < kr.uids[st.uid].certified_at { return; }
        kr.uids[st.uid].valid = true;
        kr.uids[st.uid].certified_at = s.created;
        kr.uids[st.uid].primary = s.primary_uid;
        kr.keys[st.primary].valid = true;
        // The primary user ID's self-signature, else the newest, says
        // what the primary key may do.
        if s.primary_uid || !st.primary_uid_seen {
            if s.primary_uid && !st.primary_uid_seen { kr.keys[st.primary].bound_at = 0; }
            if s.primary_uid { st.primary_uid_seen = true; }
            take_self_sig(kr.keys[st.primary], s);
        }
        return;
    }
    // On a subkey.
    if t != SIG_SUBKEY_BINDING && t != SIG_SUBKEY_REVOCATION { return; }
    let sk = kr.keys[st.sub];
    // RFC 9980 §7.2: a post-quantum subkey's binding is not by SHA-1 or
    // RIPEMD-160.
    if (is_pq_kem(sk.algo) || is_pq_sig(sk.algo)) && (s.hash == HASH_SHA1 || s.hash == HASH_RIPEMD160) { return; }
    put_key_hash(data, sk);
    if verify_signature(pk, s, data) != OK { return; }
    if t == SIG_SUBKEY_REVOCATION { kr.keys[st.sub].revoked = true; return; }
    // A subkey that may sign must sign back (§5.2.1, 0x19).
    if s.has_flags && s.flags & FLAG_SIGN != 0 {
        if s.embedded.len == 0 { return; }
        let b, eb = parse_signature(s.embedded);
        if eb != OK || b.sigtype != SIG_PRIMARY_BINDING || verify_signature(sk, b, data) != OK { return; }
    }
    if s.created < kr.keys[st.sub].bound_at { return; }
    kr.keys[st.sub].valid = true;
    take_self_sig(kr.keys[st.sub], s);
}

// Reads transferable keys (armored, any number of armored blocks, or
// binary) into kr. Keys whose version or algorithm is not supported are
// skipped with their subkeys and signatures; ERR_MALFORMED if the framing
// is broken, and ERR_NO_KEY if no key was read at all.
fn add_keys(kr: Keyring&, data: const u8[:]) -> i64 {
    var bin: u8[>..] = [];
    if is_armored(data) {
        var at = 0;
        loop {
            let b, l = find_begin(data, at);
            if b < 0 { break; }
            var hashes: u8[>..] = [];
            let label, next, err = dearmor_at(data, b, bin, hashes);
            if err != OK { return err; }
            at = next;
        }
    } else {
        bin.append(data);
    }
    let before = kr.keys.len;
    var st = ReadState { .. };
    var skip = false;                // inside a key that could not be read
    var at = 0;
    var count = 0;
    while at < bin.len {
        let p, err = next_packet(bin, at);
        if err != OK { return ERR_MALFORMED; }
        count++;
        if count > MAX_KEY_PACKETS { return ERR_LIMIT; }
        at = p.end;
        if p.partial { return ERR_MALFORMED; }
        let body = bin[p.body..p.body_end];
        let t = p.tag;
        if t == TAG_PUBLIC_KEY || t == TAG_SECRET_KEY {
            let k, e = parse_key(t, body);
            st = ReadState { .. };
            if e != OK { skip = true; continue; }
            skip = false;
            kr.keys.push(k);
            st.primary = kr.keys.len - 1;
            kr.keys[st.primary].primary = st.primary;
        } else if skip || st.primary < 0 {
            continue;
        } else if t == TAG_PUBLIC_SUBKEY || t == TAG_SECRET_SUBKEY {
            let k, e = parse_key(t, body);
            st.uid = -1;
            if e != OK { st.sub = -2; continue; }
            kr.keys.push(k);
            st.sub = kr.keys.len - 1;
            kr.keys[st.sub].primary = st.primary;
        } else if t == TAG_USER_ID {
            if st.sub != -1 { continue; }
            var u = Uid { .. };
            u.key = st.primary;
            u.text.append(body[.. ::min(body.len, u.text.cap)]);
            kr.uids.push(u);
            st.uid = kr.uids.len - 1;
        } else if t == TAG_USER_ATTRIBUTE {
            st.uid = -1;
            if st.sub == -1 { st.sub = -2; }      // its signatures are not ours to check
            continue;
        } else if t == TAG_SIGNATURE {
            if st.sub == -2 { continue; }
            handle_signature(kr, st, body);
        } else {
            continue;                    // trust, marker, padding
        }
        let start = kr.raw.len;
        kr.raw.append(bin[p.at..p.end]);
        kr.recs.push(Rec { tag: t, key: st.primary, start: start, end: kr.raw.len });
    }
    if kr.keys.len == before { return ERR_NO_KEY; }
    return OK;
}

// --- Finding keys ------------------------------------------------------------------

fn is_primary(kr: const Keyring&, i: i64) -> bool { i >= 0 && i < kr.keys.len && kr.keys[i].primary == i }

// The primary's user ID to show: the one marked primary, else the first
// valid one, else the first.
fn primary_uid(kr: const Keyring&, key: i64) -> const u8[:] {
    var first = -1;
    var valid = -1;
    for i in kr.uids.len {
        let u = kr.uids[i];
        if u.key != key { continue; }
        if first < 0 { first = i; }
        if u.valid && !u.revoked {
            if u.primary { return kr.uids[i].text[..]; }
            if valid < 0 { valid = i; }
        }
    }
    if valid >= 0 { return kr.uids[valid].text[..]; }
    if first >= 0 { return kr.uids[first].text[..]; }
    return "";
}

fn lower(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }

fn contains_fold(s: const u8[:], sub: const u8[:]) -> bool {
    if sub.len == 0 { return true; }
    if sub.len > s.len { return false; }
    for i in s.len - sub.len + 1 {
        var ok = true;
        for j in sub.len { if lower(s[i + j]) != lower(sub[j]) { ok = false; break; } }
        if ok { return true; }
    }
    return false;
}

// The key (primary or subkey) with this key ID; with secret, one whose
// secret is here. -1 if none.
fn key_by_id(kr: const Keyring&, keyid: const u8[:], secret: bool = false) -> i64 {
    for i in kr.keys.len {
        if kr.keys[i].keyid[..] == keyid && (!secret || kr.keys[i].has_secret && !kr.keys[i].stub) { return i; }
    }
    return -1;
}

fn key_by_fpr(kr: const Keyring&, fpr: const u8[:], secret: bool = false) -> i64 {
    for i in kr.keys.len {
        if kr.keys[i].fpr[..] == fpr && (!secret || kr.keys[i].has_secret && !kr.keys[i].stub) { return i; }
    }
    return -1;
}

// A primary key by what a user names it with: a fingerprint or key ID in
// hex (with or without "0x" and spaces), or text found in a user ID
// (without case). A key with its secret here is preferred. -1 if none.
fn find_key(kr: const Keyring&, query: const u8[:], secret: bool = false) -> i64 {
    var q = query;
    if starts_with(q, "0x") || starts_with(q, "0X") { q = q[2..]; }
    let bytes, is_hex = unhex(q);
    if is_hex && (bytes.len == 8 || bytes.len == 20 || bytes.len == 32) {
        for pass in 2 {
            for i in kr.keys.len {
                let k = kr.keys[i];
                if pass == 0 && !k.has_secret { continue; }
                if secret && (!k.has_secret || k.stub) { continue; }
                let hit = if bytes.len == 8 { k.keyid[..] == bytes[..] } else { k.fpr[..] == bytes[..] };
                if hit { return k.primary; }
            }
        }
    }
    for pass in 2 {
        for u in kr.uids {
            let k = kr.keys[u.key];
            if pass == 0 && !k.has_secret { continue; }
            if secret && (!k.has_secret || k.stub) { continue; }
            if contains_fold(u.text, query) { return u.key; }
        }
    }
    return -1;
}

// Whether a key may be used at time t (0: now) for what `flag` says.
fn usable(kr: const Keyring&, i: i64, flag: u32, t: i64 = 0) -> bool {
    let k = kr.keys[i];
    let pk = kr.keys[k.primary];
    if !k.valid || k.revoked || pk.revoked || !pk.valid { return false; }
    let when = if t > 0 { t } else { now() };
    if k.expires > 0 && k.created + k.expires <= when { return false; }
    if pk.expires > 0 && pk.created + pk.expires <= when { return false; }
    if k.created > when + 60 { return false; }
    if k.has_flags { return k.flags & flag != 0; }
    // No flags: what the algorithm can do, the primary signing.
    if flag & FLAG_SIGN != 0 { return can_sign_algo(k.algo) && !k.subkey; }
    if flag & FLAG_ENCRYPT != 0 { return can_encrypt_algo(k.algo); }
    return false;
}

// The key of a primary to sign with: the newest usable signing subkey
// whose secret is here, else the primary itself. -1 if neither.
fn signing_key(kr: const Keyring&, primary: i64) -> i64 {
    var best = -1;
    for i in kr.keys.len {
        let k = kr.keys[i];
        if k.primary != primary || !k.subkey || !k.has_secret || k.stub { continue; }
        if !usable(kr, i, FLAG_SIGN) || !can_sign_algo(k.algo) { continue; }
        if best < 0 || k.created > kr.keys[best].created { best = i; }
    }
    if best >= 0 { return best; }
    let p = kr.keys[primary];
    if p.has_secret && !p.stub && usable(kr, primary, FLAG_SIGN) && can_sign_algo(p.algo) { return primary; }
    return -1;
}

// The key of a primary to encrypt to: the newest usable encryption subkey,
// else the primary. -1 if neither.
fn encryption_key(kr: const Keyring&, primary: i64) -> i64 {
    var best = -1;
    for i in kr.keys.len {
        let k = kr.keys[i];
        if k.primary != primary || !k.subkey { continue; }
        if !usable(kr, i, FLAG_ENCRYPT) || !can_encrypt_algo(k.algo) { continue; }
        if best < 0 || k.created > kr.keys[best].created { best = i; }
    }
    if best >= 0 { return best; }
    if usable(kr, primary, FLAG_ENCRYPT) && can_encrypt_algo(kr.keys[primary].algo) { return primary; }
    return -1;
}

// --- Secrets ------------------------------------------------------------------------

// Unlocks the protected secrets of a primary and its subkeys with a
// passphrase: OK when every secret of it is unlocked afterwards (stubs
// aside), ERR_PASSPHRASE when the passphrase opened none, ERR_KEY when it
// has no secret.
fn unlock(kr: Keyring&, primary: i64, pass: const u8[:]) -> i64 {
    var any = false;
    var failed = OK;
    for i in kr.keys.len {
        if kr.keys[i].primary != primary || !kr.keys[i].has_secret || kr.keys[i].stub { continue; }
        any = true;
        if !kr.keys[i].locked { continue; }
        let e = unlock_key(kr.keys[i], pass);
        if e != OK { failed = e; }
    }
    if !any { return ERR_KEY; }
    return failed;
}

// Unlocks every locked secret of the keyring that the passphrase opens.
fn unlock_all(kr: Keyring&, pass: const u8[:]) -> i64 {
    var failed = OK;
    for i in kr.keys.len {
        if !kr.keys[i].has_secret || kr.keys[i].stub || !kr.keys[i].locked { continue; }
        let e = unlock_key(kr.keys[i], pass);
        if e != OK { failed = e; }
    }
    return failed;
}

// --- Export ------------------------------------------------------------------------

// A primary's packets as they were read, secret key packets made public
// ones; appended to out, armored if asked.
fn export_public(kr: const Keyring&, primary: i64, out: u8[>..]&, armored: bool = false) -> i64 {
    var bin: u8[>..] = [];
    var ki = primary;
    for r in kr.recs {
        if r.key != primary { continue; }
        if r.tag == TAG_SECRET_KEY || r.tag == TAG_PUBLIC_KEY || r.tag == TAG_SECRET_SUBKEY || r.tag == TAG_PUBLIC_SUBKEY {
            // The key packets of a primary are in kr.keys in the same order.
            while ki < kr.keys.len && kr.keys[ki].primary != primary { ki++; }
            if ki >= kr.keys.len { return ERR_KEY; }
            let k = kr.keys[ki];
            put_old_packet(bin, if k.subkey { TAG_PUBLIC_SUBKEY } else { TAG_PUBLIC_KEY }, k.body);
            ki++;
            continue;
        }
        bin.append(kr.raw[r.start..r.end]);
    }
    if bin.len == 0 { return ERR_NO_KEY; }
    if armored { armor(out, ARMOR_PUBLIC_KEY, bin); } else { out.append(bin); }
    return OK;
}

// A primary with its secrets: unprotected when unlocked and pass is "",
// protected anew by pass (iterated SHA-256 S2K of the coded count s2k,
// AES-256, the SHA-1 check) when given, or as they were read when still
// locked. ERR_KEY if it has no secret here.
fn export_secret(kr: const Keyring&, primary: i64, out: u8[>..]&, armored: bool = false, pass: const u8[:] = "",
                 s2k: i64 = 255) -> i64 {
    if !kr.keys[primary].has_secret { return ERR_KEY; }
    var bin: u8[>..] = [];
    var ki = primary;
    for r in kr.recs {
        if r.key != primary { continue; }
        if r.tag == TAG_SECRET_KEY || r.tag == TAG_PUBLIC_KEY || r.tag == TAG_SECRET_SUBKEY || r.tag == TAG_PUBLIC_SUBKEY {
            while ki < kr.keys.len && kr.keys[ki].primary != primary { ki++; }
            if ki >= kr.keys.len { return ERR_KEY; }
            let k = kr.keys[ki];
            ki++;
            if !k.has_secret {
                put_old_packet(bin, if k.subkey { TAG_PUBLIC_SUBKEY } else { TAG_PUBLIC_KEY }, k.body);
                continue;
            }
            var body: u8[>..] = [];
            let e = put_secret_body(body, k, pass, false, s2k);
            if e != OK { return e; }
            put_old_packet(bin, if k.subkey { TAG_SECRET_SUBKEY } else { TAG_SECRET_KEY }, body);
            continue;
        }
        bin.append(kr.raw[r.start..r.end]);
    }
    if armored { armor(out, ARMOR_PRIVATE_KEY, bin); } else { out.append(bin); }
    return OK;
}
