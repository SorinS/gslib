// keytab: a service's keytab, in MIT's file format. Makes the keys of
// HTTP/web.example.com@EXAMPLE.COM from its password (as ktutil's addent
// -password does), adds a later key version, writes the file readable by
// its owner only, reads it back and lists it as klist -k does, and looks
// up the key a ticket of a given type and version needs.
//
//   goose examples/krb5/keytab.goose
import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.keytab;

fn temp_path(suffix: const u8[:]) -> u8[>..] {
    var dir: u8[>..] = [];
    if !env("TMPDIR", dir) || dir.len == 0 { dir.append("/tmp"); }
    if dir[dir.len - 1] != '/' { dir.push('/'); }
    return str(dir, "goose-example-", time_ns(), suffix);
}

fn fail(what: const u8[:], err: i64) {
    print("keytab: ", what, ": ", krb5::error_text(err));
    exit(1);
}

fn main() {
    let service = "HTTP/web.example.com";
    let realm = "EXAMPLE.COM";
    let etypes: i32[3] = [krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, krb5::ETYPE_AES128_CTS_HMAC_SHA1_96,
                          krb5::ETYPE_AES256_CTS_HMAC_SHA384_192];

    // Key version 2 from the old password, version 3 from the new one: a
    // service keeps both until tickets under the old key have expired.
    var kt, err = krb5::keytab_entries_from_password(krb5::NT_SRV_HST, service, realm, "old password", 2, etypes, 1700000000);
    if err != krb5::OK { fail("keys", err); }
    let newer, err2 = krb5::keytab_entries_from_password(krb5::NT_SRV_HST, service, realm, "new password", 3, etypes, 1800000000);
    if err2 != krb5::OK { fail("keys", err2); }
    kt.append(newer);

    // To a file (0600) and back.
    let path = temp_path(".keytab");
    let serr = krb5::keytab_save_private(path, kt);
    if serr != krb5::OK { fail(path, serr); }
    let back, lerr = krb5::keytab_load(path);
    delete_file(path);
    if lerr != krb5::OK { fail(path, lerr); }
    guard back.len == kt.len else { print("keytab: ", back.len, " entries read, ", kt.len, " written"); exit(1); }

    print("Keytab name: FILE:", path, " (removed)");
    print("KVNO Principal");
    for e in back {
        print(" ", e.kvno, "   ", krb5::principal_string(e.name, e.realm), " (", krb5::etype_name(e.key.etype), ")");
    }

    // A ticket arrives encrypted in aes256 under key version 3: the
    // service's key for it. Version 0 asks for the latest.
    let k3, kv3, e3 = krb5::keytab_key(back, service, realm, krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 3);
    let kl, kvl, el = krb5::keytab_key(back, service, realm, krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 0);
    guard e3 == krb5::OK && el == krb5::OK && kvl == 3 && kl.value == k3.value else { fail("keytab_key", e3); }

    // That key is the password's string-to-key with the default salt
    // (realm, then the name's components).
    let want, we = krb5::string_to_key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, "new password",
                                       krb5::default_salt(realm, krb5::name_parts(service)));
    guard we == krb5::OK && want.value == k3.value else { print("keytab: the key is not the password's"); exit(1); }
    print("aes256 key for kvno 3 found; it is string_to_key(\"new password\", \"EXAMPLE.COMHTTPweb.example.com\")");

    // What it can decrypt, in the order the service prefers; nothing for
    // another realm or a version it never had.
    let have = krb5::keytab_etypes(back, service, realm, etypes);
    print("types it has keys of: ", have.len);
    let x, xv, xe = krb5::keytab_key(back, service, "OTHER.EXAMPLE.COM", krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 0);
    let y, yv, ye = krb5::keytab_key(back, service, realm, krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, 7);
    guard xe == krb5::ERR_NO_KEY && ye == krb5::ERR_NO_KEY else { print("keytab: found a key that is not there"); exit(1); }
    print("another realm, or kvno 7: ", krb5::error_text(ye));
}
