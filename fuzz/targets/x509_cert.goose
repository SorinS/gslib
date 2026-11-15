// Fuzz target: x509_cert. A certificate parsed (DER, or PEM when the
// input starts with '-'), then every accessor: the names as text and by
// attribute, the serial, SAN DNS names and IPs, host matching, CRL
// distribution points, policies, the RSA key, the key as COSE/JWK, name
// constraints (its own over itself, and a fixed CA's with permitted and
// excluded subtrees over it), policy processing, the self-signature, and
// a whole path check with the certificate as its own root.

import std;
import gslib from "../..";
import gslib.crypto.x509;
import gslib.crypto.x509.constraints;
import gslib.crypto.x509.policy;
import gslib.crypto.x509.crl;
import gslib.crypto.x509.pool;
import gslib.crypto.x509.verify;
import gslib.encoding.asn1;
import gslib.encoding.cbor.cose;

// int_nc of crypto/x509/test/vectors/certs.txt: a CA with name constraints.
let NC_CA_HEX: const u8[:] = "308202e9308201d1a0030201020202101b300d06092a864886f70d01010b0500303a310b300906035504061302555331133011060355040a0c0a476f6f736520546573743116301406035504030c0d476f6f736520526f6f74205231301e170d3236303932363037333332305a170d3336313032333037333332305a302e31133011060355040a0c0a476f6f736520546573743117301506035504030c0e436f6e73747261696e65642043413059301306072a8648ce3d020106082a8648ce3d03010703420004472d108e177f2cd2436cc67369d77e32cb1790c4e2100fe6ab11e351b8728ff878ea6eb357dfd306ce73a0bbb39cea458f0908e5e99033d760f3a77a7ec15ae3a381cf3081cc300f0603551d130101ff040530030101ff300e0603551d0f0101ff04040302010630690603551d1e0101ff045f305da046300d820b6578616d706c652e636f6d300a8708c0000200ffffff00300e810c2e6578616d706c652e636f6d3019a417301531133011060355040a0c0a476f6f73652054657374a1133011820f6261642e6578616d706c652e636f6d301d0603551d0e04160414bf4f11b3ea9ec168a8eb9fbdf9c99676a1f634d7301f0603551d2304183016801476c1f11c962222f324de3f767e19e1761cea922e300d06092a864886f70d01010b050003820101004afc142e23c0fd69c7fd0fcacfac63e7b3f503317c29ffc9ab9e94be47e89f865b42aabc21912de3582db9b01d4b87ab1acc66af2d1a7beb08411a474820fb2a0a3c76a401eb437cbaff4aff3ce3e9dee5aac7b9a93138e7d4f898b38b805ef4c255b9408fa992b23422c14746ddf63554d649320549763b70e3bc6cfe58755b4d98475a9d09fde4afe0c260fc56fe968c5be5675d0d812b38e6c27a3e32bc74851e58080987e3bf1d4a90540917dadb677c4591213283c331eaafe231ffbf0103f3c94eb548184d246b5e9b14d5d96dafd5f1f696bc9eac83500f6667bc2eec5da5baaa91aae21b6c8e982277e4a9974dd4c728f40d0989138288a6d24ffa27";

let NOW: i64 = 1793000000;

var nc_ca = x509::empty_cert();

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((ascii::hex_value(s[i]) * 16 + ascii::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn exercise(c: const x509::Cert&) {
    let der = c.der[..];
    let _ = x509::subject_text(c);
    let _ = x509::issuer_text(c);
    let _ = x509::serial_hex(c);
    let _ = x509::self_issued(c);
    let _ = x509::name_values(der, c.subject, "2.5.4.3");
    let _ = x509::name_values(der, c.issuer, "2.5.4.10");
    let _ = x509::dns_names(c);
    let _ = x509::ip_addresses(c);
    let _ = x509::crl_urls(c);
    let _ = x509::matches_host(c, "www.example.com");
    let _ = x509::matches_host(c, "192.0.2.7");
    let _ = x509::cert_policies(c);
    let _ = x509::rsa_public_key(c);
    let _ = x509::check_common(c, NOW);
    let _ = cose::from_cert(c);
    let _ = x509::check_name_constraints(c, c);
    let _ = x509::check_name_constraints(nc_ca, c);
    var opts = x509::options();
    let _ = x509::check_policies(der, 1, opts);
    opts.require_explicit_policy = true;
    opts.inhibit_policy_mapping = true;
    opts.inhibit_any_policy = true;
    opts.policies.append("1.2.3.4 2.5.29.32.0");
    let _ = x509::check_policies(der, 1, opts);
    let _ = x509::check_signature(c, c);
    let _ = x509::verify_chain(der, "", der, NOW, "www.example.com");
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len > 0 && data[0] == '-' {
        let c, e = x509::parse_pem(data);
        if e == x509::OK { exercise(c); }
        var p = x509::new_pool();
        let _ = x509::pool_append_pem(p, data);
        return 0;
    }
    let c, e = x509::parse(data);
    if e == x509::OK { exercise(c); }
    return 0;
}

fn main() {
    let c, e = x509::parse(unhex(NC_CA_HEX));
    assert(e == x509::OK && c.has_name_constraints);
    nc_ca = copy(c);
}
