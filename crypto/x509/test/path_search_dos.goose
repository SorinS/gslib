// x509.verify: certificates sent to be verified must not buy unbounded
// work before anything about them is trusted. A peer's intermediates can
// all share one subject and one key, distinct only by subjectAltName (so
// that no two are the same CA to the search), each signed by that key:
// then each issues every other. Path building parses each certificate
// once, considers at most MAX_ISSUERS_PER_NAME CAs of one name, and looks
// at MAX_CANDIDATE_VISITS candidates in all; a certificate names at most
// MAX_POLICIES policies, and their duplicates are found in n log n.
import std;
import gslib from "../../..";
import gslib.crypto.x509;
import gslib.encoding.asn1;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.pool;
import gslib.crypto.x509.verify;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

let NOW:  i64 = 1793000000;
let YEAR: i64 = 31536000;

// Each hostile verify or parse must end within this many seconds, at -O0
// and --debug too; before the fix the ones here took seconds to minutes.
let BUDGET: f64 = 2.0;

// x509.create makes no certificate that would not parse, so those with
// too many policies carry them under this OID, as long as
// certificatePolicies' (2.5.29.32) in DER, and hostile() renames it.
let STAND_IN = "2.5.29.99";

// A certificatePolicies extension (or one under `oid`) of n distinct
// policies 1.2.i, or of policy 1.2.0 n times.
fn policies_ext(n: i64, distinct: bool, oid: const u8[:] = "2.5.29.32") -> u8[>..] {
    var list: u8[>..] = [];
    for i in n {
        var id: u8[>..] = [];
        format(id, "1.2.", if distinct { i } else { 0 });
        var pi: u8[>..] = [];
        asn1::put_oid(pi, id);
        asn1::put(list, asn1::SEQUENCE, pi);
    }
    var val: u8[>..] = [];
    asn1::put(val, asn1::SEQUENCE, list);
    var out: u8[>..] = [];
    x509::put_ext(out, oid, false, val);
    return out;
}

// The certificate with the first OID `from` (DER, tag and length
// included) changed in its last byte to `to`: by default its STAND_IN
// extension renamed certificatePolicies. Its signature no longer
// verifies, but nothing here is parsed that far.
fn hostile(der: const u8[:], from: const u8[:] = [0x06 as u8, 0x03, 0x55, 0x1d, 0x63], to: u8 = 0x20) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(der);
    for i in 0..out.len - from.len + 1 {
        if out[i..i + from.len] == from { out[i + from.len - 1] = to; return out; }
    }
    assert(false);
    return out;
}

// n CAs named "CN=Loop", all for key k and signed by it, told apart by
// their SAN (from n<first>.x on); the first with `policies` policies
// unless 0; expired a year ago if `expired`.
fn loop_cas(n: i64, k: const x509::PrivateKey&, seed: const u8[:], policies: i64, first: i64 = 0,
            expired: bool = false) -> u8[>..] {
    var out: u8[>..] = [];
    for j in n {
        let i = first + j;
        let end = if expired { NOW - YEAR } else { NOW + YEAR };
        var t, ok = x509::template("CN=Loop", NOW - 2 * YEAR, end);
        t.is_ca = true;
        var name: u8[>..] = [];
        format(name, "n", i, ".x");
        x509::add_dns(t.san, name);
        if j == 0 && policies > 0 { t.extra = policies_ext(policies, true, STAND_IN); }
        let der, e = x509::create_certificate(t, x509::marshal_public_key(k), seed, k);
        assert(ok && e == x509::OK);
        if j == 0 && policies > 0 { out.append(hostile(der)); } else { out.append(der); }
    }
    return out;
}

fn leaf_with(extra: const u8[:], issuer: const u8[:], issuer_key: const x509::PrivateKey&) -> u8[>..] {
    var t, ok = x509::template("CN=www.example.com", NOW - YEAR, NOW + YEAR);
    x509::add_dns(t.san, "www.example.com");
    t.extra.append(extra);
    let k = x509::generate_key(x509::KEY_ED25519);
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), issuer, issuer_key);
    assert(ok && e == x509::OK);
    return der;
}

// verify_chain's result, and whether it came within the budget.
fn timed_verify(leaf: const u8[:], inters: const u8[:], root: const u8[:]) -> i64, bool {
    let t0 = clock();
    let e = x509::verify_chain(leaf, inters, root, NOW, "www.example.com");
    return e, clock() - t0 < BUDGET;
}

fn main() {
    let ed = x509::KEY_ED25519;
    let root_key = x509::generate_key(ed);
    var rt, okr = x509::template("CN=Real Root", NOW - YEAR, NOW + YEAR);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    check("root", okr && er == x509::OK);

    // The issuer argument for the "CN=Loop" CAs, and their leaf.
    let k = x509::generate_key(ed);
    var st, oks = x509::template("CN=Loop", NOW - YEAR, NOW + YEAR);
    st.is_ca = true;
    let seed, es = x509::create_certificate(st, x509::marshal_public_key(k), "", k);
    check("seed", oks && es == x509::OK);
    let leaf = leaf_with("", seed, k);

    // More CAs of the name than the search considers: it stops at once.
    let many = loop_cas(40, k, seed, 0);
    let e1, in1 = timed_verify(leaf, many, root);
    check("40 CAs of one name: too many candidates", e1 == x509::ERR_TOO_MANY_CANDIDATES);
    check("40 CAs of one name: within the budget", in1);

    // Fewer, under the cap: they still issue each other, and the search
    // walks their arrangements until it has checked 100 signatures.
    let some = loop_cas(24, k, seed, 0);
    let e2, in2 = timed_verify(leaf, some, root);
    check("24 CAs of one name: signatures capped", e2 == x509::ERR_TOO_MANY_SIGNATURES);
    check("24 CAs of one name: within the budget", in2);

    // Most of them expired: each is looked at, and turned down before its
    // signature, at every step; the search stops after looking at
    // MAX_CANDIDATE_VISITS of them.
    var mixed = loop_cas(8, k, seed, 0);
    mixed.append(loop_cas(24, k, seed, 0, 100, true));
    let em, inm = timed_verify(leaf, mixed, root);
    check("expired CAs of one name: too many candidates", em == x509::ERR_TOO_MANY_CANDIDATES);
    check("expired CAs of one name: within the budget", inm);

    // One of them names many policies: it does not parse, so neither does
    // the list.
    let heavy = loop_cas(24, k, seed, 2000);
    let e3, in3 = timed_verify(leaf, heavy, root);
    check("a CA with 2000 policies: malformed", e3 == x509::ERR_MALFORMED);
    check("a CA with 2000 policies: within the budget", in3);

    // A leaf with 8000 policies (56 KB, under a TLS handshake message's
    // 64 KiB) parses no longer than any other certificate of its size.
    let big = hostile(leaf_with(policies_ext(8000, true, STAND_IN), root, root_key));
    let t0 = clock();
    let c4, e4 = x509::parse(big);
    check("8000 policies: malformed", e4 == x509::ERR_MALFORMED && clock() - t0 < BUDGET);
    let e5, in5 = timed_verify(big, "", root);
    check("8000 policies: verify malformed", e5 == x509::ERR_MALFORMED && in5);

    // The cap, and duplicates found among those under it.
    let at_cap = leaf_with(policies_ext(x509::MAX_POLICIES, true), root, root_key);
    let c6, e6 = x509::parse(at_cap);
    check("64 policies parse", e6 == x509::OK && c6.has_policies);
    let e7, in7 = timed_verify(at_cap, "", root);
    check("64 policies verify", e7 == x509::OK);
    let over = hostile(leaf_with(policies_ext(x509::MAX_POLICIES + 1, true, STAND_IN), root, root_key));
    let c8, e8 = x509::parse(over);
    check("65 policies: malformed", e8 == x509::ERR_MALFORMED);
    let twice = hostile(leaf_with(policies_ext(2, false, STAND_IN), root, root_key));
    let c9, e9 = x509::parse(twice);
    check("a policy twice: malformed", e9 == x509::ERR_MALFORMED);

    // An extension twice is still malformed (1.2.3.5 renamed 1.2.3.4).
    var ext: u8[>..] = [];
    var v:   u8[>..] = [];
    asn1::put(v, asn1::NULL, "");
    x509::put_ext(ext, "1.2.3.4", false, v);
    x509::put_ext(ext, "1.2.3.6", false, v);
    x509::put_ext(ext, "1.2.3.5", false, v);
    let dup = hostile(leaf_with(ext, root, root_key), [0x06 as u8, 0x03, 0x2a, 0x03, 0x05], 0x04);
    let c11, e11 = x509::parse(leaf_with(ext, root, root_key));
    check("distinct extensions parse", e11 == x509::OK);
    let c10, e10 = x509::parse(dup);
    check("an extension twice: malformed", e10 == x509::ERR_MALFORMED);

    print("path search: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
