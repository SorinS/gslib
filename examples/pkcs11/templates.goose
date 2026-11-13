// templates: what a PKCS#11 program builds before it talks to a module, and
// reads after: attribute templates (an AES key's, a find template), the
// mechanisms with their parameters (GCM, PSS, OAEP), the constants'
// names, error texts, and the EC helpers. No module is needed.
//
//   goose examples/pkcs11/templates.goose

import std;
import gslib from "../..";
import gslib.pkcs11;

// Each attribute of a template (or of a get_attribute_value result, the
// same encoding), with its name.
fn show(what: const u8[:], t: const u8[:]) {
    print(what, ":");
    pkcs11::each_attr(t) { kind, v, ok =>
        var line: u8[>..] = [];
        format(line, "  ", pkcs11::cka_name(kind), " = ");
        if kind == pkcs11::CKA_CLASS { line.append(pkcs11::cko_name(pkcs11::as_ulong(v))); }
        else if kind == pkcs11::CKA_KEY_TYPE { line.append(pkcs11::ckk_name(pkcs11::as_ulong(v))); }
        else if v.len == 1 { format(line, pkcs11::as_bool(v)); }
        else if kind == pkcs11::CKA_VALUE_LEN { format(line, pkcs11::as_ulong(v)); }
        else if v.len == 0 { line.append("(empty: to match or to read)"); }
        else { format(line, "\"", v, "\""); }
        print(line);
    };
}

fn hex(v: u64) -> u8[>..] {
    var out: u8[>..] = "0x";
    format_uint(out, v, 16, 1, '0');
    return out;
}

fn main() {
    // An AES-256 key to keep on the token, usable for encryption only and
    // never to be read out.
    var key: u8[>..] = [];
    pkcs11::attr(key, pkcs11::CKA_CLASS, pkcs11::CKO_SECRET_KEY);
    pkcs11::attr(key, pkcs11::CKA_KEY_TYPE, pkcs11::CKK_AES);
    pkcs11::attr(key, pkcs11::CKA_VALUE_LEN, 32);
    pkcs11::attr(key, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(key, pkcs11::CKA_SENSITIVE, true);
    pkcs11::attr(key, pkcs11::CKA_EXTRACTABLE, false);
    pkcs11::attr(key, pkcs11::CKA_ENCRYPT, true);
    pkcs11::attr(key, pkcs11::CKA_DECRYPT, true);
    pkcs11::attr(key, pkcs11::CKA_LABEL, "backup key");
    pkcs11::attr_date(key, pkcs11::CKA_END_DATE, 2030, 12, 31);
    show("an AES key template", key);
    let vl, okl = pkcs11::attr_value(key, pkcs11::CKA_VALUE_LEN);
    guard okl && pkcs11::as_ulong(vl) == 32 else { print("templates: CKA_VALUE_LEN not read back"); exit(1); }
    let lab, oklab = pkcs11::attr_value(key, pkcs11::CKA_LABEL);
    guard oklab && lab == "backup key" else { print("templates: CKA_LABEL not read back"); exit(1); }

    // A find template: every private key with this ID.
    var find: u8[>..] = [];
    pkcs11::attr(find, pkcs11::CKA_CLASS, pkcs11::CKO_PRIVATE_KEY);
    pkcs11::attr(find, pkcs11::CKA_ID, "key-1");
    pkcs11::attr_empty(find, pkcs11::CKA_MODULUS);
    show("a find template", find);

    // Mechanisms: a name for each, and the parameters some take.
    let gcm = pkcs11::mechanism_gcm(pkcs11::CKM_AES_GCM, "twelve bytes", "header", 128);
    let pss = pkcs11::mechanism_pss(pkcs11::CKM_SHA256_RSA_PKCS_PSS, pkcs11::CKM_SHA256, pkcs11::CKG_MGF1_SHA256, 32);
    let oaep = pkcs11::mechanism_oaep(pkcs11::CKM_RSA_PKCS_OAEP, pkcs11::CKM_SHA_1, pkcs11::CKG_MGF1_SHA1);
    let cbc = pkcs11::mechanism(pkcs11::CKM_AES_CBC_PAD, "sixteen byte IV!");
    for m in [pkcs11::CKM_AES_GCM, pkcs11::CKM_SHA256_RSA_PKCS_PSS, pkcs11::CKM_RSA_PKCS_OAEP, pkcs11::CKM_AES_CBC_PAD,
              pkcs11::CKM_ECDSA_SHA256, pkcs11::CKM_EDDSA] {
        print(pkcs11::ckm_name(m), " = ", hex(m));
    }
    print("encoded: GCM ", gcm.len, " bytes, PSS ", pss.len, ", OAEP ", oaep.len, ", CBC ", cbc.len);
    guard pkcs11::ckm_name(pkcs11::CKM_EDDSA) == "CKM_EDDSA" else { print("templates: CKM name"); exit(1); }

    // Results: every call gives a CK_RV, CKR_OK (0) for success.
    print(pkcs11::error_text(pkcs11::CKR_OK));
    print(pkcs11::error_text(pkcs11::CKR_PIN_INCORRECT));
    print(pkcs11::error_text(pkcs11::ERR_LOAD));
    guard pkcs11::error_text(0xA0) == "pkcs11: 0xA0: CKR_PIN_INCORRECT" else { print("templates: error text"); exit(1); }

    // EC: the curve as CKA_EC_PARAMS wants it, and a point in and out of
    // CKA_EC_POINT's OCTET STRING.
    var point: u8[>..] = [4];
    for i in 64 { point.push(i as! u8); }
    let der = pkcs11::ec_point_der(point);
    guard pkcs11::ec_point(der) == point[..] else { print("templates: EC point round trip"); exit(1); }
    print("P-256 params ", pkcs11::EC_PARAMS_P256.len, " bytes; a 65-byte point is ", der.len, " in DER");
    print("CK_ULONG is ", pkcs11::ulong_size(), " bytes here");
}
