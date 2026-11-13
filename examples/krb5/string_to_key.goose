// string_to_key: Kerberos keys and encryption types. Turns a password into
// a key for each encryption type (the salt is the realm and the name, as
// a KDC makes it), checks one against RFC 3962's published vector, then
// encrypts and decrypts with a key usage, shows that a changed ciphertext
// and another usage are refused, makes and checks a keyed checksum, and
// derives keys with the PRF and KRB-FX-CF2 (what FAST combines keys with).
//
//   goose examples/krb5/string_to_key.goose
import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn fail(what: const u8[:], err: i64) {
    print("string_to_key: ", what, ": ", krb5::error_text(err));
    exit(1);
}

fn main() {
    // RFC 3962 Appendix B: "password", salt "ATHENA.MIT.EDUraeburn", 1200
    // PBKDF2 iterations (the parameter is the count, big-endian).
    let iter: u8[4] = [0, 0, 0x04, 0xb0];
    let rfc, e = krb5::string_to_key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, "password", "ATHENA.MIT.EDUraeburn", iter);
    guard e == krb5::OK && hex(rfc.value) == "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a" else {
        fail("RFC 3962 vector", e);
    }
    print("RFC 3962 aes256 key at 1200 iterations: ", hex(rfc.value));

    // alice@EXAMPLE.COM's keys: the default salt is the realm followed by
    // the name's components.
    var parts: u8[][>..] = [];
    parts.push("alice");
    let salt = krb5::default_salt("EXAMPLE.COM", parts);
    let types = [krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, krb5::ETYPE_AES128_CTS_HMAC_SHA1_96,
                 krb5::ETYPE_AES256_CTS_HMAC_SHA384_192, krb5::ETYPE_AES128_CTS_HMAC_SHA256_128,
                 krb5::ETYPE_CAMELLIA256_CTS_CMAC, krb5::ETYPE_DES3_CBC_SHA1_KD, krb5::ETYPE_RC4_HMAC];
    let secret = "a secret only alice and the service know";
    for t in types {
        let key, err = krb5::string_to_key(t, "correct horse battery staple", salt);
        if err != krb5::OK { fail(krb5::etype_name(t), err); }

        // Encrypt with a key usage (here a KRB-PRIV's): a confounder makes
        // every ciphertext different, and an integrity check is appended.
        var c: u8[>..] = [];
        let ee = krb5::encrypt(key, krb5::USAGE_KRB_PRIV_ENCPART, secret, c);
        if ee != krb5::OK { fail("encrypt", ee); }
        var p: u8[>..] = [];
        let de = krb5::decrypt(key, krb5::USAGE_KRB_PRIV_ENCPART, c, p);
        if de != krb5::OK || p != secret { fail("decrypt", de); }

        // One bit changed, or the ciphertext offered for another usage.
        var bad: u8[>..] = [];
        bad.append(c);
        bad[c.len / 2] ^= 1;
        var x: u8[>..] = [];
        let te = krb5::decrypt(key, krb5::USAGE_KRB_PRIV_ENCPART, bad, x);
        var y: u8[>..] = [];
        let ue = krb5::decrypt(key, krb5::USAGE_KRB_SAFE_CKSUM, c, y);
        guard te != krb5::OK && ue != krb5::OK else { print("string_to_key: a bad ciphertext was accepted"); exit(1); }

        // A keyed checksum of the type that goes with the key.
        let ctype = krb5::cksum_type_for(t);
        var sum: u8[>..] = [];
        let ce = krb5::checksum(key, ctype, krb5::USAGE_KRB_SAFE_CKSUM, secret, sum);
        if ce != krb5::OK { fail("checksum", ce); }
        guard krb5::verify_checksum(key, ctype, krb5::USAGE_KRB_SAFE_CKSUM, secret, sum) == krb5::OK
              && krb5::verify_checksum(key, ctype, krb5::USAGE_KRB_SAFE_CKSUM, "another message", sum) != krb5::OK else {
            print("string_to_key: checksum check failed"); exit(1);
        }
        print(krb5::etype_name(t), ": key ", key.value.len, " bytes, ", secret.len, " bytes encrypt to ", c.len,
              ", checksum ", sum.len, " bytes; tampering: ", krb5::error_text(te));
    }

    // Keys derived from keys: the PRF (RFC 3961), and KRB-FX-CF2 (RFC
    // 6113), which joins two keys into one that needs both.
    let k1 = krb5::random_key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96);
    let k2 = krb5::random_key(krb5::ETYPE_AES128_CTS_HMAC_SHA256_128);
    var out1: u8[>..] = [];
    var out2: u8[>..] = [];
    guard krb5::prf(k1, "label", out1) == krb5::OK && krb5::prf(k1, "label", out2) == krb5::OK && out1 == out2 else {
        print("string_to_key: the PRF is not deterministic"); exit(1);
    }
    let cf, cerr = krb5::fx_cf2(k1, "pepper1", k2, "pepper2");
    let cf2, cerr2 = krb5::fx_cf2(k1, "pepper1", k2, "pepper2");
    guard cerr == krb5::OK && cerr2 == krb5::OK && cf.value == cf2.value && cf.etype == k1.etype else { fail("KRB-FX-CF2", cerr); }
    print("PRF: ", out1.len, " bytes; KRB-FX-CF2 of an aes256 and an aes128-sha256 key: an ", krb5::etype_name(cf.etype), " key");
}
