// krb5.pac against go-krb5: every PAC vector of test/vectors/pac.txt read
// and printed in the form tools/krb5oracle prints go-krb5's reading in;
// the two must agree line for line (test/vectors/pac_oracle.txt). Then the
// server signature of go-krb5's test PAC checked with sysHTTP's key (and
// refused when anything changes), the KDC signature checked with a wrong
// key refused, extended UPN_DNS_INFO and PAC_REQUESTOR made here, and
// malformed PACs.

import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.ndr;
import gslib.krb5.pac;
import tv;

fn groups(out: u8[>..]&, g: const krb5::GroupMembership[:]) {
    var first = true;
    for x in g {
        if !first { out.push(','); }
        format_int(out, x.rid, 10, 0, ' ');
        out.push(':');
        format_int(out, x.attributes, 10, 0, ' ');
        first = false;
    }
}

fn sid_attrs(out: u8[>..]&, s: const krb5::SidAttr[:]) {
    var first = true;
    for x in s {
        if !first { out.push(','); }
        out.append(x.sid);
        out.push(':');
        format_int(out, x.attributes, 10, 0, ' ');
        first = false;
    }
}

fn dump_logon(out: u8[>..]&, b: const u8[:]) {
    let k, err = krb5::decode_logon_info(b);
    if err != krb5::OK { out.append("kvi.error\n"); return; }
    out.append(str("kvi.times=", k.logon_time, ",", k.logoff_time, ",", k.kickoff_time, ",", k.password_last_set, ",",
                   k.password_can_change, ",", k.password_must_change, "\n"));
    out.append(str("kvi.names=", k.effective_name, "|", k.full_name, "|", k.logon_script, "|", k.profile_path, "|",
                   k.home_directory, "|", k.home_directory_drive, "\n"));
    out.append(str("kvi.counts=", k.logon_count, ",", k.bad_password_count, "\n"));
    out.append(str("kvi.ids=", k.user_id, ",", k.primary_group_id, "\n"));
    out.append("kvi.groups=");
    groups(out, k.group_ids);
    out.push('\n');
    out.append(str("kvi.user_flags=", k.user_flags, "\n"));
    out.append(str("kvi.session_key=", tv::to_hex(k.user_session_key), "\n"));
    out.append(str("kvi.server=", k.logon_server, "|", k.logon_domain_name, "\n"));
    out.append(str("kvi.domain_id=", k.logon_domain_id, "\n"));
    out.append(str("kvi.uac=", k.user_account_control, ",", k.sub_auth_status, "\n"));
    out.append(str("kvi.ilogon=", k.last_successful_ilogon, ",", k.last_failed_ilogon, ",", k.failed_ilogon_count, "\n"));
    out.append("kvi.extra_sids=");
    sid_attrs(out, k.extra_sids);
    out.push('\n');
    out.append(str("kvi.resource=", k.resource_group_domain_sid, "|"));
    groups(out, k.resource_group_ids);
    out.push('\n');
}

fn dump_sig(out: u8[>..]&, name: const u8[:], b: const u8[:]) {
    let s, err = krb5::decode_signature(b);
    if err != krb5::OK { out.append(str(name, ".error\n")); return; }
    out.append(str(name, "=", s.sig_type, "|", tv::to_hex(s.signature), "|", s.rodc_id, "\n"));
}

fn dump_pac(out: u8[>..]&, b: const u8[:]) {
    let bufs, err = krb5::pac_buffers(b);
    if err != krb5::OK { out.append("pac.error\n"); return; }
    out.append(str("pac.buffers=", bufs.len, "\n"));
    for x in bufs {
        out.append(str("buffer=", x.ul_type, ",", x.size, ",", x.offset, "\n"));
        let off = x.offset as! i64;
        let end = off + x.size;
        let d = b[off..end];
        if x.ul_type == 1 { dump_logon(out, d); }
        if x.ul_type == 6 { dump_sig(out, "server_sig", d); }
        if x.ul_type == 7 { dump_sig(out, "kdc_sig", d); }
        if x.ul_type == 10 {
            let c, cerr = krb5::decode_client_info(d);
            out.append(if cerr != krb5::OK { str("client_info.error\n") } else { str("client_info=", c.client_id, "|", c.name, "\n") });
        }
        if x.ul_type == 11 {
            let s, serr = krb5::decode_delegation_info(d);
            if serr != krb5::OK { out.append("s4u.error\n"); }
            else {
                out.append(str("s4u=", s.proxy_target, "|"));
                var first = true;
                for t in s.transited { if !first { out.push(','); } out.append(t); first = false; }
                out.push('\n');
            }
        }
        if x.ul_type == 12 {
            let u, uerr = krb5::decode_upn_dns_info(d);
            out.append(if uerr != krb5::OK { str("upn.error\n") } else { str("upn=", u.upn, "|", u.dns_domain, "|", u.flags, "\n") });
        }
    }
}

fn dump(name: const u8[:], b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(str("== ", name, "\n"));
    if name.starts_with("MarshaledPAC_AuthorizationData") {
        let ad, err = krb5::decode_authdata(b);
        if err != krb5::OK { out.append("ad.error\n"); return out; }
        let p, ok = krb5::pac_from_authz(ad);
        if ok { dump_pac(out, p); }
    } else if name == "MarshaledPAC_AD_WIN2K_PAC" {
        dump_pac(out, b);
    } else if name.starts_with("MarshaledPAC_Kerb_Validation_Info") {
        dump_logon(out, b);
    } else if name == "MarshaledPAC_Client_Info" {
        let c, err = krb5::decode_client_info(b);
        out.append(str("client_info=", c.client_id, "|", c.name, "\n"));
    } else if name == "MarshaledPAC_UPN_DNS_Info" {
        let u, err = krb5::decode_upn_dns_info(b);
        out.append(str("upn=", u.upn, "|", u.dns_domain, "|", u.flags, "\n"));
    } else if name == "MarshaledPAC_Server_Signature" {
        dump_sig(out, "server_sig", b);
    } else if name == "MarshaledPAC_KDC_Signature" {
        dump_sig(out, "kdc_sig", b);
    }
    return out;
}

fn against_oracle() {
    var ours: u8[>..] = [];
    tv::each_row("vectors/pac.txt") { r: tv::Row& =>
        let name = r.next();
        ours.append(dump(name, tv::hex(r.next())));
    };
    var theirs: u8[>..] = [];
    tv::check("read pac_oracle.txt", read_file("vectors/pac_oracle.txt", theirs));
    // Line by line, the oracle's comment line skipped.
    var t_lines: u8[][>..] = [];
    var s = 0;
    for i in theirs.len { if theirs[i] == '\n' { if theirs[s] != '#' { t_lines.push(theirs[s..i]); } s = i + 1; } }
    var o_lines: u8[][>..] = [];
    s = 0;
    for i in ours.len { if ours[i] == '\n' { o_lines.push(ours[s..i]); s = i + 1; } }
    var n = 0;
    for t in t_lines {
        var k = 0;
        var o: u8[>..] = [];
        for x in o_lines { if k == n { o.append(x); } k++; }
        tv::check_eq(str("oracle line ", n + 1), o, t);
        n++;
    }
    var m = 0;
    for x in o_lines { m++; }
    tv::check_int("oracle lines", m, n);
}

fn signatures() {
    var pac_hex: u8[>..] = [];
    var kt_hex: u8[>..] = [];
    tv::each_row("vectors/pac.txt") { r: tv::Row& =>
        let name = r.next();
        if name == "MarshaledPAC_AD_WIN2K_PAC" { pac_hex.append(r.next()); }
    };
    tv::each_row("vectors/files.txt") { r: tv::Row& =>
        let name = r.next();
        if name == "KEYTAB_SYSHTTP_TEST_GOKRB5" { kt_hex.append(r.next()); }
    };
    let b = tv::hex(pac_hex);
    let kt, kerr = krb5::keytab_parse(tv::hex(kt_hex));
    let key, kv, err = krb5::keytab_key(kt, "sysHTTP", "TEST.GOKRB5", 18, 2);
    tv::check_int("sysHTTP key", err, krb5::OK);
    let p, perr = krb5::decode_pac(b);
    tv::check_int("decode pac", perr, krb5::OK);
    tv::check("pac parts", p.has_logon_info && p.has_client_info && p.has_upn_dns_info && p.has_server_sig && p.has_kdc_sig);
    tv::check_int("server signature", krb5::pac_verify_server(b, p, key), krb5::OK);
    tv::check_eq("upn", p.upn_dns_info.upn, "testuser1@test.gokrb5");
    // The SIDs of the user, as a token would have them.
    let sids = krb5::logon_sids(p.logon_info);
    var first: u8[>..] = [];
    var n = 0;
    for s in sids { if n == 0 { first.append(s); } n++; }
    tv::check_eq("user sid", first, "S-1-5-21-3167651404-3865080224-2280184895-1105");
    tv::check_int("sids", n, 2 + 4 + 2);
    // Any changed byte breaks the server signature (outside the signatures).
    var changed = 0;
    for at in [100, 300, 650, 700] {
        var c: u8[>..] = [];
        c.append(b);
        c[at] = c[at] ^ 1;
        let q, qerr = krb5::decode_pac(c);
        if qerr == krb5::OK {
            tv::check_int(str("tampered at ", at), krb5::pac_verify_server(c, q, key), krb5::ERR_PAC_SIGNATURE);
            changed++;
        }
    }
    tv::check("tampering checked", changed >= 3);
    tv::check_int("wrong key", krb5::pac_verify_server(b, p, krb5::random_key(18)), krb5::ERR_PAC_SIGNATURE);
    tv::check_int("kdc signature with a wrong key", krb5::pac_verify_kdc(p, krb5::random_key(23)), krb5::ERR_PAC_SIGNATURE);
}

fn le16(out: u8[>..]&, v: i64) { out.push(v as! u8); out.push((v >> 8) as! u8); }
fn le32(out: u8[>..]&, v: i64) { le16(out, v & 0xffff); le16(out, v >> 16); }

fn utf16(out: u8[>..]&, s: const u8[:]) { for c in s { out.push(c); out.push(0); } }

fn upn_extended() {
    // UPN_DNS_INFO with the S flag: UPN, DNS domain, SAM name, SID.
    var sid: u8[>..] = [1, 4, 0, 0, 0, 0, 0, 5];
    for v in [21, 1, 2, 1105] { le32(sid, v); }
    var b: u8[>..] = [];
    let upn = "u@x.test";
    let dns = "X.TEST";
    let sam = "u";
    let base = 20;
    le16(b, upn.len * 2); le16(b, base);
    le16(b, dns.len * 2); le16(b, base + upn.len * 2);
    le32(b, 3);
    le16(b, sam.len * 2); le16(b, base + (upn.len + dns.len) * 2);
    le16(b, sid.len); le16(b, base + (upn.len + dns.len + sam.len) * 2);
    utf16(b, upn);
    utf16(b, dns);
    utf16(b, sam);
    b.append(sid);
    let u, err = krb5::decode_upn_dns_info(b);
    tv::check("extended upn", err == krb5::OK && u.has_sam && u.upn == upn && u.dns_domain == dns && u.sam_name == sam &&
              u.sid == "S-1-5-21-1-2-1105");
    let s2, ok = krb5::sid_from_bytes(sid[..10]);
    tv::check("short sid refused", !ok);
    let big: u8[8] = [1, 0, 1, 2, 3, 4, 5, 6];
    let s3, ok3 = krb5::sid_from_bytes(big);
    tv::check_eq("large authority", s3, "S-1-0x010203040506");
}

fn malformed() {
    tv::each_row("vectors/pac.txt") { r: tv::Row& =>
        let name = r.next();
        let b = tv::hex(r.next());
        if name == "MarshaledPAC_AD_WIN2K_PAC" {
            for n in [0, 7, 8, 30, 100, 500, b.len - 5] {
                let p, err = krb5::decode_pac(b[..n]);
                tv::check(str("truncated pac ", n), err != krb5::OK);
            }
        }
        if name.starts_with("MarshaledPAC_Kerb_Validation_Info") {
            for n in [0, 15, 16, 40, 200, b.len / 2, b.len - 4] {
                let k, err = krb5::decode_logon_info(b[..n]);
                tv::check(str("truncated logon info ", n), err != krb5::OK);
            }
        }
    };
}

fn main() {
    against_oracle();
    signatures();
    upn_extended();
    malformed();
    tv::done("pac");
}
