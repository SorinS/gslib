// read_pac: the PAC, the authorization data Active Directory puts in its
// tickets, as a service reads it after accepting a ticket. Uses go-krb5's
// published test vectors (a PAC a Windows KDC made, and the service key
// that signed it, from krb5/test/vectors): the PAC decoded, its server
// signature checked with the service's key (and refused once a byte is
// changed), the user's name, UPN, groups and SIDs read, with the LDAP
// filter that finds the user by SID; then the user's claims, from a plain
// claims buffer and from one compressed with MS-XCA's LZ77+Huffman.
//
//   goose examples/krb5/read_pac.goose
import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;
import gslib.krb5.pac;
import gslib.krb5.claims;
import gslib.krb5.ldap;

// A vector by name from a "name|hex" file of krb5/test/vectors.
fn vector(file: const u8[:], name: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    var out:  u8[>..] = [];
    guard read_file(str(resource_dir(), "../../krb5/test/vectors/", file), text) else { print("read_pac: cannot read ", file); exit(1); }
    for line in split(text, '\n') {
        if !line.starts_with(str(name, "|")) { continue; }
        let h = line[name.len + 1..];
        for i in h.len / 2 { out.push((ascii::hex_value(h[2 * i]) * 16 + ascii::hex_value(h[2 * i + 1])) as! u8); }
    }
    guard out.len > 0 else { print("read_pac: no ", name, " in ", file); exit(1); }
    return out;
}

fn print_claims(what: const u8[:], arrays: const krb5::ClaimsArray[:]) {
    for a in arrays {
        for c in a.claims {
            var v: u8[>..] = [];
            for s in c.strings { v.append(str(" \"", s, "\"")); }
            for n in c.ints { v.append(str(" ", n)); }
            print(what, ": ", c.id, " =", v);
        }
    }
}

fn main() {
    let raw = vector("pac.txt", "MarshaledPAC_AD_WIN2K_PAC");
    let kt, ke = krb5::keytab_parse(vector("files.txt", "KEYTAB_SYSHTTP_TEST_GOKRB5"));
    let key, kvno, kerr = krb5::keytab_key(kt, "sysHTTP", "TEST.GOKRB5", krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 2);
    guard ke == krb5::OK && kerr == krb5::OK else { print("read_pac: no service key"); exit(1); }

    // Decode it, then check the server signature before believing it. (A
    // service with the ticket calls pac_verify(ctx, ctx.service_key),
    // which finds the PAC in the ticket and checks the client info too.)
    let p, err = krb5::decode_pac(raw);
    guard err == krb5::OK && p.has_logon_info && p.has_server_sig else { print("read_pac: ", krb5::error_text(err)); exit(1); }
    let ve = krb5::pac_verify_server(raw, p, key);
    guard ve == krb5::OK else { print("read_pac: ", krb5::error_text(ve)); exit(1); }
    print("PAC of ", raw.len, " bytes, ", p.buffers.len, " buffers; server signature good (", krb5::etype_name(key.etype), " key)");
    var changed: u8[>..] = [];
    changed.append(raw);
    changed[700] ^= 1;
    let q, qe = krb5::decode_pac(changed);
    guard qe != krb5::OK || krb5::pac_verify_server(changed, q, key) == krb5::ERR_PAC_SIGNATURE else {
        print("read_pac: a changed PAC verified"); exit(1);
    }
    print("one byte changed: ", krb5::error_text(krb5::ERR_PAC_SIGNATURE));

    // Who the user is.
    let li = p.logon_info;
    print("user ", li.logon_domain_name, "\\", li.effective_name, " (", li.full_name, "), RID ", li.user_id,
          ", primary group ", li.primary_group_id, ", ", li.logon_count, " logons");
    print("client info: ", p.client_info.name, ", authenticated at ", krb5::filetime_to_unix(p.client_info.client_id),
          " (Unix time)");
    if p.has_upn_dns_info { print("UPN ", p.upn_dns_info.upn, ", DNS domain ", p.upn_dns_info.dns_domain); }

    // The SIDs an access check uses: the user's, then its groups'.
    let sids = krb5::logon_sids(li);
    var n = 0;
    for s in sids {
        if n == 0 {
            let filter, okf = krb5::sid_filter(s);
            guard okf && s == "S-1-5-21-3167651404-3865080224-2280184895-1105" else { print("read_pac: user SID ", s); exit(1); }
            print("user SID ", s, "; LDAP filter ", filter);
        } else {
            print("  group SID ", s);
        }
        n++;
    }

    // Claims (Dynamic Access Control): the user's attributes as the KDC
    // put them, from a plain buffer and a compressed one.
    let a1, e1 = krb5::decode_claims(vector("pac.txt", "MarshaledPAC_ClientClaimsInfoStr"));
    let a2, e2 = krb5::decode_claims(vector("pac.txt", "MarshaledPAC_ClientClaimsInfo_XPRESS_HUFF"));
    guard e1 == krb5::OK && e2 == krb5::OK else { print("read_pac: claims: ", krb5::error_text(if e1 != krb5::OK { e1 } else { e2 })); exit(1); }
    print_claims("claim", a1);
    print_claims("compressed claim", a2);
}
