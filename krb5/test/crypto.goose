// krb5.crypto against the RFCs' vectors: n-fold and DES3's DR and DK and
// string-to-key (RFC 3961 Appendix A), AES string-to-key and CTS (RFC 3962
// Appendix B), the SHA-2 types (RFC 8009 Appendix A), RC4-HMAC's
// string-to-key; then every type's encrypt, decrypt and checksum round
// trips, and tampering caught.

import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import tv;

fn nfold_vectors() {
    tv::check_hex("64-fold 012345", krb5::nfold("012345", 64), "be072631276b1955");
    tv::check_hex("56-fold password", krb5::nfold("password", 56), "78a07b6caf85fa");
    tv::check_hex("64-fold Rough", krb5::nfold("Rough Consensus, and Running Code", 64), "bb6ed30870b7f0e0");
    tv::check_hex("168-fold password", krb5::nfold("password", 168), "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e");
    tv::check_hex("192-fold MASSACHVSETTS", krb5::nfold("MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 192),
                  "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b");
    tv::check_hex("168-fold Q", krb5::nfold("Q", 168), "518a54a215a8452a518a54a215a8452a518a54a215");
    tv::check_hex("168-fold ba", krb5::nfold("ba", 168), "fb25d531ae8974499f52fd92ea9857c4ba24cf297e");
    tv::check_hex("64-fold kerberos", krb5::nfold("kerberos", 64), "6b65726265726f73");
    tv::check_hex("128-fold kerberos", krb5::nfold("kerberos", 128), "6b65726265726f737b9b5b2b93132b93");
    tv::check_hex("168-fold kerberos", krb5::nfold("kerberos", 168), "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4");
    tv::check_hex("256-fold kerberos", krb5::nfold("kerberos", 256),
                  "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4");
}

fn des3_dr_dk(key: const u8[:], usage: const u8[:], dr: const u8[:], dk: const u8[:]) {
    let k = krb5::make_key(krb5::ETYPE_DES3_CBC_SHA1_KD, tv::hex(key));
    let r = krb5::derive_random(k, tv::hex(usage));
    tv::check_hex(str("DES3 DR ", key), r, dr);
    let d = krb5::random_to_key(krb5::ETYPE_DES3_CBC_SHA1_KD, r);
    tv::check_hex(str("DES3 DK ", key), d.value, dk);
}

fn des3_vectors() {
    des3_dr_dk("dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92", "0000000155",
               "935079d14490a75c3093c4a6e8c3b049c71e6ee705", "925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd");
    des3_dr_dk("5e13d31c70ef765746578531cb51c15bf11ca82c97cee9f2", "00000001aa",
               "9f58e5a047d894101c469845d67ae3c5249ed812f2", "9e58e5a146d9942a101c469845d67a20e3c4259ed913f207");
    des3_dr_dk("98e6fd8a04a4b6859b75a176540b9752bad3ecd610a252bc", "0000000155",
               "12fff90c773f956d13fc2ca0d0840349dbd39908eb", "13fef80d763e94ec6d13fd2ca1d085070249dad39808eabf");
    des3_dr_dk("622aec25a2fe2cad7094680b7c64940280084c1a7cec92b5", "00000001aa",
               "f8debf05b097e7dc0603686aca35d91fd9a5516a70", "f8dfbf04b097e6d9dc0702686bcb3489d91fd9a4516b703e");
    des3_dr_dk("d3f8298ccb166438dcb9b93ee5a7629286a491f838f802fb", "6b65726265726f73",
               "2270db565d2a3d64cfbfdc5305d4f778a6de42d9da", "2370da575d2a3da864cebfdc5204d56df779a7df43d9da43");
    des3_dr_dk("c1081649ada74362e6a1459d01dfd30d67c2234c940704da", "0000000155",
               "348056ec98fcc517171d2b4d7a9493af482d999175", "348057ec98fdc48016161c2a4c7a943e92ae492c989175f7");
    des3_dr_dk("5d154af238f46713155719d55e2f1f790dd661f279a7917c", "00000001aa",
               "a8818bc367dadacbe9a6c84627fb60c294b01215e5", "a8808ac267dada3dcbe9a7c84626fbc761c294b01315e5c1");
    des3_dr_dk("798562e049852f57dc8c343ba17f2ca1d97394efc8adc443", "0000000155",
               "c813f88b3be2b2f75424ce9175fbc8483b88c8713a", "c813f88a3be3b334f75425ce9175fbe3c8493b89c8703b49");
    des3_dr_dk("26dce334b545292f2feab9a8701a89a4b99eb9942cecd016", "00000001aa",
               "f58efc6f83f93e55e695fd252cf8fe59f7d5ba37ec", "f48ffd6e83f83e7354e694fd252cf83bfe58f7d5ba37ec5d");

    let e = krb5::ETYPE_DES3_CBC_SHA1_KD;
    fn s2k(pw: const u8[:], salt: const u8[:], want: const u8[:]) {
        let k, err = krb5::string_to_key(e, pw, salt);
        tv::check_int(str("DES3 s2k err ", salt), err, krb5::OK);
        tv::check_hex(str("DES3 s2k ", salt), k.value, want);
    }
    s2k("password", "ATHENA.MIT.EDUraeburn", "850bb51358548cd05e86768c313e3bfef7511937dcf72c3e");
    s2k("potatoe", "WHITEHOUSE.GOVdanny", "dfcd233dd0a43204ea6dc437fb15e061b02979c1f74f377a");
    s2k("penny", "EXAMPLE.COMbuckaroo", "6d2fcdf2d6fbbc3ddcadb5da5710a23489b0d3b69d5d9d4a");
    s2k("\xc3\x9f", "ATHENA.MIT.EDUJuri\xc5\xa1i\xc4\x87", "16d5a40e1ce3bacb61b9dce00470324c831973a7b952feb0");
    s2k("\xf0\x9d\x84\x9e", "EXAMPLE.COMpianist", "85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19");
}

fn iter_params(n: i64) -> u8[4] { [(n >> 24) as! u8, (n >> 16) as! u8, (n >> 8) as! u8, n as! u8] }

fn aes_s2k(iter: i64, pw: const u8[:], salt: const u8[:], k128: const u8[:], k256: const u8[:]) {
    let a, e1 = krb5::string_to_key(krb5::ETYPE_AES128_CTS_HMAC_SHA1_96, pw, salt, iter_params(iter));
    tv::check_int("aes128 s2k err", e1, krb5::OK);
    tv::check_hex(str("aes128 s2k ", iter, " ", salt), a.value, k128);
    let b, e2 = krb5::string_to_key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, pw, salt, iter_params(iter));
    tv::check_int("aes256 s2k err", e2, krb5::OK);
    tv::check_hex(str("aes256 s2k ", iter, " ", salt), b.value, k256);
}

fn aes_vectors() {
    aes_s2k(1, "password", "ATHENA.MIT.EDUraeburn", "42263c6e89f4fc28b8df68ee09799f15",
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161");
    aes_s2k(2, "password", "ATHENA.MIT.EDUraeburn", "c651bf29e2300ac27fa469d693bdda13",
            "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff");
    aes_s2k(1200, "password", "ATHENA.MIT.EDUraeburn", "4c01cd46d632d01e6dbe230a01ed642a",
            "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a");
    aes_s2k(5, "password", tv::hex("1234567878563412"), "e9b23d52273747dd5c35cb55be619d8e",
            "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31");
    aes_s2k(1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase equals block size",
            "59d1bb789a828b1aa54ef9c2883f69ed", "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34");
    aes_s2k(1200, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "pass phrase exceeds block size",
            "cb8005dc5f90179a7f02104c0018751d", "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b");
    aes_s2k(50, "\xf0\x9d\x84\x9e", "EXAMPLE.COMpianist", "f149c1f2e154a73452d43e7fe62a56e5",
            "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e");

    // CTS (RFC 3962 Appendix B): 17, 31, 32, 47, 48 and 64 bytes.
    let key = "chicken teriyaki";
    let iv: u8[16] = [0; 16];
    let input = "I would like the General Gau's Chicken, please, and wonton soup.";
    fn cts(n: i64, want: const u8[:]) {
        let c = krb5::aes_cts_encrypt(key, iv, input[..n]);
        tv::check_hex(str("cts encrypt ", n), c, want);
        let p = krb5::aes_cts_decrypt(key, iv, c);
        tv::check(str("cts decrypt ", n), p == input[..n]);
    }
    cts(17, "c6353568f2bf8cb4d8a580362da7ff7f97");
    cts(31, "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5");
    cts(32, "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584");
    cts(47, "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5");
    cts(48, "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8");
    cts(64, "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8");
}

fn rfc8009_vectors() {
    var salt = tv::hex("10DF9DD783E5BC8ACEA1730E74355F61");
    salt.append("ATHENA.MIT.EDUraeburn");
    let a, e1 = krb5::string_to_key(krb5::ETYPE_AES128_CTS_HMAC_SHA256_128, "password", salt);
    tv::check_int("8009 s2k 128 err", e1, krb5::OK);
    tv::check_hex("8009 s2k 128", a.value, "089BCA48B105EA6EA77CA5D2F39DC5E7");
    let b, e2 = krb5::string_to_key(krb5::ETYPE_AES256_CTS_HMAC_SHA384_192, "password", salt);
    tv::check_int("8009 s2k 256 err", e2, krb5::OK);
    tv::check_hex("8009 s2k 256", b.value, "45BD806DBF6A833A9CFFC1C94589A222367A79BC21C413718906E9F578A78467");

    let k128 = krb5::make_key(krb5::ETYPE_AES128_CTS_HMAC_SHA256_128, tv::hex("3705D96080C17728A0E800EAB6E0D23C"));
    tv::check_hex("8009 Kc 128", krb5::derive_key(k128, 2, 0x99), "B31A018A48F54776F403E9A396325DC3");
    tv::check_hex("8009 Ke 128", krb5::derive_key(k128, 2, 0xaa), "9B197DD1E8C5609D6E67C3E37C62C72E");
    tv::check_hex("8009 Ki 128", krb5::derive_key(k128, 2, 0x55), "9FDA0E56AB2D85E1569A688696C26A6C");
    let k256 = krb5::make_key(krb5::ETYPE_AES256_CTS_HMAC_SHA384_192,
                              tv::hex("6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52"));
    tv::check_hex("8009 Kc 256", krb5::derive_key(k256, 2, 0x99), "EF5718BE86CC84963D8BBB5031E9F5C4BA41F28FAF69E73D");
    tv::check_hex("8009 Ke 256", krb5::derive_key(k256, 2, 0xaa),
                  "56AB22BEE63D82D7BC5227F6773F8EA7A5EB1C825160C38312980C442E5C7E49");
    tv::check_hex("8009 Ki 256", krb5::derive_key(k256, 2, 0x55), "69B16514E3CD8E56B82010D5C73012B622C4D00FFC23ED1F");

    let p = tv::hex("000102030405060708090A0B0C0D0E0F1011121314");
    fn enc(k: krb5::Key, conf: const u8[:], n: i64, want: const u8[:]) {
        var c: u8[>..] = [];
        tv::check_int("8009 encrypt err", krb5::encrypt_with(k, 2, tv::hex(conf), p[..n], c), krb5::OK);
        tv::check_hex(str("8009 encrypt ", k.etype, " ", n), c, want);
        var back: u8[>..] = [];
        tv::check_int("8009 decrypt err", krb5::decrypt(k, 2, c, back), krb5::OK);
        tv::check(str("8009 decrypt ", k.etype, " ", n), back == p[..n]);
    }
    enc(k128, "7E5895EAF2672435BAD817F545A37148", 0, "EF85FB890BB8472F4DAB20394DCA781DAD877EDA39D50C870C0D5A0A8E48C718");
    enc(k128, "7BCA285E2FD4130FB55B1A5C83BC5B24", 6,
        "84D7F30754ED987BAB0BF3506BEB09CFB55402CEF7E6877CE99E247E52D16ED4421DFDF8976C");
    enc(k128, "56AB21713FF62C0A1457200F6FA9948F", 16,
        "3517D640F50DDC8AD3628722B3569D2AE07493FA8263254080EA65C1008E8FC295FB4852E7D83E1E7C48C37EEBE6B0D3");
    enc(k128, "A7A4E29A4728CE10664FB64E49AD3FAC", 21,
        "720F73B18D9859CD6CCB4346115CD336C70F58EDC0C4437C5573544C31C813BCE1E6D072C186B39A413C2F92CA9B8334A287FFCBFC");
    enc(k256, "F764E9FA15C276478B2C7D0C4E5F58E4", 0,
        "41F53FA5BFE7026D91FAF9BE959195A058707273A96A40F0A01960621AC612748B9BBFBE7EB4CE3C");
    enc(k256, "B80D3251C1F6471494256FFE712D0B9A", 6,
        "4ED7B37C2BCAC8F74F23C1CF07E62BC7B75FB3F637B9F559C7F664F69EAB7B6092237526EA0D1F61CB20D69D10F2");
    enc(k256, "53BF8A0D105265D4E276428624CE5E63", 16,
        "BC47FFEC7998EB91E8115CF8D19DAC4BBBE2E163E87DD37F49BECA92027764F68CF51F14D798C2273F35DF574D1F932E40C4FF255B36A266");
    enc(k256, "763E65367E864F02F55153C7E3B58AF1", 21,
        "40013E2DF58E8751957D2878BCD2D6FE101CCFD556CB1EAE79DB3C3EE86429F2B2A602AC86FEF6ECB647D6295FAE077A1FEB517508D2C16B4192E01F62");

    var s1: u8[>..] = [];
    tv::check_int("8009 cksum err", krb5::checksum(k128, 0, 2, p, s1), krb5::OK);
    tv::check_hex("8009 checksum 128", s1, "D78367186643D67B411CBA9139FC1DEE");
    var s2: u8[>..] = [];
    tv::check_int("8009 cksum err", krb5::checksum(k256, 0, 2, p, s2), krb5::OK);
    tv::check_hex("8009 checksum 256", s2, "45EE791567EEFCA37F4AC1E0222DE80D43C3BFA06699672A");

    var f1: u8[>..] = [];
    tv::check_int("8009 prf err", krb5::prf(k128, "test", f1), krb5::OK);
    tv::check_hex("8009 prf 128", f1, "9D188616F63852FE86915BB840B4A886FF3E6BB0F819B49B893393D393854295");
    var f2: u8[>..] = [];
    tv::check_int("8009 prf err", krb5::prf(k256, "test", f2), krb5::OK);
    tv::check_hex("8009 prf 256", f2,
                  "9801F69A368C2BF675E59521E177D9A07F67EFE1CFDE8D3C8D6F6A0256E3B17DB3C1B62AD1B8553360D17367EB1514D2");
}

fn rc4_vectors() {
    let k, err = krb5::string_to_key(krb5::ETYPE_RC4_HMAC, "foo", "");
    tv::check_int("rc4 s2k err", err, krb5::OK);
    tv::check_hex("rc4 s2k foo", k.value, "ac8e657f83df82beea5d43bdaf7800cc");
    // A character outside the BMP is a surrogate pair in UTF-16.
    let u, ok = krb5::utf16le("a\xf0\x9d\x84\x9e\xc3\x9f");
    tv::check("utf16le ok", ok);
    tv::check_hex("utf16le", u, "610034d81edddf00");
    let bad, ok2 = krb5::utf16le("\xc3");
    tv::check("utf16le refuses a cut sequence", !ok2 && bad.len == 0);
}

let ETYPES: i32[6] = [16, 17, 18, 19, 20, 23];

fn round_trips() {
    for e in ETYPES {
        let k = krb5::random_key(e);
        tv::check_int(str("random key len ", e), k.value.len, krb5::key_len(e));
        for n in [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 100, 1000] {
            var plain: u8[>..] = [];
            for i in n { plain.push((i * 7 + e) as! u8); }
            for usage in [1, 3, 9, 23, 1026] {
                var c: u8[>..] = [];
                tv::check_int("encrypt err", krb5::encrypt(k, usage, plain, c), krb5::OK);
                var p: u8[>..] = [];
                tv::check_int(str("decrypt err ", e, " ", n), krb5::decrypt(k, usage, c, p), krb5::OK);
                // DES3 keeps its padding.
                tv::check(str("round trip ", e, " ", n, " ", usage), p[..n] == plain && (p.len == n || e == 16));
                // Another usage's key fails the integrity check.
                var q: u8[>..] = [];
                tv::check_int(str("wrong usage ", e, " ", n), krb5::decrypt(k, usage + 1, c, q), krb5::ERR_INTEGRITY);
                // So does any flipped bit.
                var t: u8[>..] = [];
                t.append(c);
                t[(n * 13) % t.len] = t[(n * 13) % t.len] ^ 0x10;
                var r: u8[>..] = [];
                tv::check_int(str("tampered ", e, " ", n), krb5::decrypt(k, usage, t, r), krb5::ERR_INTEGRITY);
            }
            var s: u8[>..] = [];
            tv::check_int("checksum err", krb5::checksum(k, 0, 17, plain, s), krb5::OK);
            tv::check_int(str("checksum len ", e), s.len, krb5::cksum_len(krb5::cksum_type_for(e)));
            tv::check_int("verify", krb5::verify_checksum(k, krb5::cksum_type_for(e), 17, plain, s), krb5::OK);
            tv::check_int("verify other usage", krb5::verify_checksum(k, krb5::cksum_type_for(e), 18, plain, s),
                          krb5::KRB_AP_ERR_MODIFIED);
        }
        // Too short to hold a confounder and a MAC.
        var p: u8[>..] = [];
        let short: u8[10] = [0; 10];
        tv::check_int(str("short ", e), krb5::decrypt(k, 1, short, p), krb5::ERR_CIPHERTEXT);
    }
    // HMAC-MD5 takes any key (the PAC's KDC signature with an AES krbtgt key
    // is HMAC-SHA1-96, but an RC4 server's is HMAC-MD5).
    let a = krb5::random_key(18);
    var s: u8[>..] = [];
    tv::check_int("hmac-md5 with aes key", krb5::checksum(a, krb5::CKSUM_HMAC_MD5, 17, "x", s), krb5::OK);
    var s2: u8[>..] = [];
    tv::check_int("aes cksum with rc4 key", krb5::checksum(krb5::random_key(23), krb5::CKSUM_HMAC_SHA1_96_AES256, 17, "x", s2),
                  krb5::ERR_CKSUMTYPE);
}

fn names() {
    for e in ETYPES { tv::check_int(str("name ", e), krb5::etype_by_name(krb5::etype_name(e)), e); }
    tv::check_int("rc4-hmac", krb5::etype_by_name("RC4-HMAC"), 23);
    tv::check_int("aes256-cts", krb5::etype_by_name("aes256-cts"), 18);
    tv::check_int("number", krb5::etype_by_name("20"), 20);
    tv::check_int("unknown", krb5::etype_by_name("des-cbc-crc"), 0);
}

fn main() {
    nfold_vectors();
    des3_vectors();
    aes_vectors();
    rfc8009_vectors();
    rc4_vectors();
    round_trips();
    names();
    tv::done("crypto");
}
