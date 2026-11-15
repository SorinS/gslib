// tpm2's side of the differential against go-tpm (scripts/differential.py):
// the same cases as scripts/gotpm/main.go, the same answers expected.
//
//   goose scripts/oracle.goose -- CASES
//
//   kdfa HASH KEY LABEL U V BITS      KDFa
//   kdfe HASH Z LABEL U V BITS        KDFe
//   pubname TPMT_PUBLIC               the object's Name, and the area re-marshalled
//   nvname TPMS_NV_PUBLIC             the NV index's Name
//   policy HASH OP...                 a policy digest (ops as main.go's)
import std;
import os;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.commands;
import gslib.tpm2.policy;

fn hx(s: const u8[:]) -> u8[>..], bool {
    var none: u8[>..] = [];
    if s == "-" { return none, true; }
    return tpm2::unhex(s);
}

fn alg(s: const u8[:]) -> u16 {
    let b, ok = tpm2::unhex(s);
    if !ok || b.len != 2 { return 0; }
    return tpm2::be16(b, 0);
}

fn one(line: const u8[:]) -> u8[>..] {
    var out: u8[>..]          = [];
    var f:   const u8[:][>..] = [];
    each_split(line, ' ') { if it.len > 0 { f.push(it); } };
    if f.len == 0 { out.append("error"); return out; }
    if (f[0] == "kdfa" || f[0] == "kdfe") && f.len == 7 {
        let a, ok1 = hx(f[2]);
        let l, ok2 = hx(f[3]);
        let u, ok3 = hx(f[4]);
        let v, ok4 = hx(f[5]);
        let bits, ok5 = parse_int(f[6]);
        let h = alg(f[1]);
        if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || tpm2::hash_id(h) == 0 { out.append("error"); return out; }
        let k = if f[0] == "kdfa" { tpm2::kdfa(h, a, l, u, v, bits) } else { tpm2::kdfe(h, a, l, u, v, bits) };
        out.append(tpm2::hex(k));
        return out;
    }
    if f[0] == "pubname" && f.len == 2 {
        let b, ok = hx(f[1]);
        let p, okp = tpm2::parse_public(b);
        let n = tpm2::public_name(p);
        if !ok || !okp || n.len == 0 { out.append("error"); return out; }
        format(out, tpm2::hex(n), " ", tpm2::hex(tpm2::marshal_public(p)));
        return out;
    }
    if f[0] == "nvname" && f.len == 2 {
        let b, ok = hx(f[1]);
        var r = tpm2::reader(b);
        let n = tpm2::read_nv_public(r);
        let name = tpm2::nv_name(n);
        if !ok || !r.ok || tpm2::left(r) != 0 || name.len == 0 { out.append("error"); return out; }
        out.append(tpm2::hex(name));
        return out;
    }
    if f[0] == "policy" && f.len >= 2 {
        let h = alg(f[1]);
        if tpm2::digest_size(h) == 0 { out.append("error"); return out; }
        var p = tpm2::policy(h);
        var i = 2;
        while i < f.len {
            let a = split(f[i], ':');
            var bad = false;
            if a[0] == "pcr" && a.len == 3 {
                let sb, oks = hx(a[1]);
                let d, okd = hx(a[2]);
                var r = tpm2::reader(sb);
                let sel = tpm2::read_pcr_selection(r);
                if !oks || !okd || !r.ok || tpm2::left(r) != 0 { bad = true; }
                else { tpm2::policy_pcr(p, sel, d); }
            } else if (a[0] == "secret" || a[0] == "signed" || a[0] == "authorize") && a.len == 3 {
                let n, okn = hx(a[1]);
                let ref, okr = hx(a[2]);
                if !okn || !okr { bad = true; }
                else if a[0] == "secret" { tpm2::policy_secret(p, n, ref); }
                else if a[0] == "signed" { tpm2::policy_signed(p, n, ref); }
                else { tpm2::policy_authorize(p, n, ref); }
            } else if a[0] == "authvalue" {
                tpm2::policy_auth_value(p);
            } else if a[0] == "cc" && a.len == 2 {
                let n, okn = parse_int(a[1]);
                if !okn || n < 0 || n > 0xffffffff { bad = true; } else { tpm2::policy_command_code(p, n as u32); }
            } else if a[0] == "or" && a.len == 2 {
                var ds: u8[..64][>..] = [];
                each_split(a[1], '.') {
                    let d, okd = hx(it);
                    var v: u8[..64] = [];
                    if !okd || d.len > 64 { bad = true; } else { v.append(d); }
                    ds.push(v);
                };
                if !bad && !tpm2::policy_or(p, ds) { bad = true; }
            } else {
                bad = true;
            }
            if bad { out.append("error"); return out; }
            i++;
        }
        out.append(tpm2::hex(p.digest));
        return out;
    }
    out.append("error");
    return out;
}

fn main() {
    let a = args();
    var text: u8[>..] = [];
    if a.len != 2 || !read_file(a[1], text) { write_stderr("usage: oracle.goose -- CASES\n"); exit(2); }
    var out: u8[>..] = [];
    each_split(text, '\n') {
        if it.len > 0 {
            out.append(one(it));
            out.push('\n');
        }
    };
    write_stdout(out);
}
