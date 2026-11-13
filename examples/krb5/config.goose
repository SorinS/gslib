// config: krb5.conf, in MIT's profile syntax. Parses a configuration for
// two realms (given here as text; a program reads its own with
// default_config, which honours $KRB5_CONFIG) and asks it what a client
// asks: the default realm and its settings, the KDCs of a realm (UDP or
// TCP, ports), which realm a host is in, the path to a realm across
// trusts, the encryption types allowed, and values of an application's
// own section.
//
//   goose examples/krb5/config.goose
import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.config;

let KRB5_CONF = """
    # The client's view of two realms that trust each other.
    [libdefaults]
        default_realm = EXAMPLE.COM
        ticket_lifetime = 10h
        renew_lifetime = 7d
        clockskew = 300
        forwardable = true
        udp_preference_limit = 1465
        permitted_enctypes = aes256-cts-hmac-sha384-192 aes256-cts aes128-cts
        spake_preauth_groups = edwards25519

    [realms]
        EXAMPLE.COM = {
            kdc = kdc.example.com
            kdc = kdc2.example.com:8888
            admin_server = kdc.example.com
        }
        PARTNER.EXAMPLE.ORG = {
            kdc = tcp/kdc.partner.example.org:88
            pkinit_anchors = FILE:/etc/krb5/partner-ca.pem
        }

    [domain_realm]
        .example.com = EXAMPLE.COM
        example.com = EXAMPLE.COM
        .partner.example.org = PARTNER.EXAMPLE.ORG

    [capaths]
        EXAMPLE.COM = {
            PARTNER.EXAMPLE.ORG = .
        }

    [appdefaults]
        webapp = {
            keytab = /etc/webapp/http.keytab
            max_retries = 3
        }
    """;

fn main() {
    let cfg, err = krb5::config_parse(KRB5_CONF);
    guard err == krb5::OK else { print("config: ", krb5::error_text(err)); exit(1); }

    let realm, ok = krb5::default_realm(cfg);
    let lifetime = krb5::conf_duration(cfg, "libdefaults/ticket_lifetime", 86400);
    let renew = krb5::conf_duration(cfg, "libdefaults/renew_lifetime", 0);
    let skew = krb5::conf_duration(cfg, "libdefaults/clockskew", 300);
    let forwardable = krb5::conf_bool(cfg, "libdefaults/forwardable", false);
    let rdns = krb5::conf_bool(cfg, "libdefaults/rdns", true);        // absent: the default
    guard ok && realm == "EXAMPLE.COM" && lifetime == 36000 && renew == 604800 && forwardable && rdns else {
        print("config: libdefaults read wrong"); exit(1);
    }
    print("default realm ", realm, ": tickets for ", lifetime, " s, renewable for ", renew, " s, skew ", skew,
          " s, forwardable ", forwardable);

    // Encryption types: names, MIT's short aliases (aes256-cts) included,
    // as type numbers in the order given.
    let et = krb5::conf_etypes(cfg, "permitted_enctypes");
    var names: u8[>..] = [];
    for e in et { names.append(str(" ", krb5::etype_name(e))); }
    guard et.len == 3 && et[0] == krb5::ETYPE_AES256_CTS_HMAC_SHA384_192 && et[1] == krb5::ETYPE_AES256_CTS_HMAC_SHA1_96 else {
        print("config: enctypes read wrong"); exit(1);
    }
    print("permitted enctypes:", names);

    // KDCs: the default port is 88; tcp/ means TCP only.
    for r in ["EXAMPLE.COM", "PARTNER.EXAMPLE.ORG"] {
        for k in krb5::realm_kdcs(cfg, r) {
            print(r, " KDC ", k.host, " port ", k.port, if k.tcp_only { " (TCP only)" } else { "" });
        }
    }
    var ports: i64[>..] = [];
    for k in krb5::realm_kdcs(cfg, "EXAMPLE.COM") { ports.push(k.port); }
    guard ports.len == 2 && ports[1] == 8888 && krb5::realm_kdcs(cfg, "NOWHERE.EXAMPLE").len == 0 else {
        print("config: KDCs read wrong"); exit(1);
    }

    // Hosts to realms, by [domain_realm]: the service ticket for a host's
    // service is asked of that host's realm.
    for host in ["web.example.com", "example.com", "db.partner.example.org", "www.example.net"] {
        let hr = krb5::realm_for_host(cfg, host);
        print(host, " is in ", if hr.len == 0 { "no realm we know" } else { hr });
    }
    guard krb5::realm_for_host(cfg, "db.partner.example.org") == "PARTNER.EXAMPLE.ORG" else {
        print("config: domain_realm read wrong"); exit(1);
    }

    // The path across realms: direct by [capaths], else the hierarchy.
    let via, direct = krb5::capath(cfg, "EXAMPLE.COM", "PARTNER.EXAMPLE.ORG");
    guard direct && via.len == 0 else { print("config: capaths read wrong"); exit(1); }
    print("EXAMPLE.COM to PARTNER.EXAMPLE.ORG: directly, by [capaths]");
    var hops: u8[>..] = [];
    for r in krb5::hierarchical_path("SALES.EXAMPLE.COM", "DEV.EXAMPLE.COM") { hops.append(str(" ", r)); }
    print("SALES.EXAMPLE.COM to DEV.EXAMPLE.COM by the hierarchy, through:", hops);

    // A realm's own settings, and an application's section.
    let anchors, oka = krb5::conf_get(cfg, "realms/PARTNER.EXAMPLE.ORG/pkinit_anchors");
    let keytab, okk = krb5::conf_get(cfg, "appdefaults/webapp/keytab");
    let retries = krb5::conf_int(cfg, "appdefaults/webapp/max_retries", 1);
    guard oka && okk && retries == 3 else { print("config: values read wrong"); exit(1); }
    print("partner's pkinit_anchors ", anchors, "; webapp keytab ", keytab, ", max_retries ", retries);
}
