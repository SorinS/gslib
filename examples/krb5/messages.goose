// messages: the messages of RFC 4120, built, encoded and decoded, here the
// first round of a password login played by both sides in memory. The
// client asks for a TGT without pre-authentication; the KDC answers with a
// KRB-ERROR (PREAUTH_REQUIRED) whose e-data says which key type and salt
// to use (ETYPE-INFO2); the client makes its key from the password and
// asks again with an encrypted timestamp (PA-ENC-TIMESTAMP), which the KDC
// decrypts with its copy of the key and checks against its clock. Also
// principal names: parsed, split and escaped as MIT writes them.
//
//   goose examples/krb5/messages.goose
import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.service;

let NOW: i64 = 1800000000;

fn fail(what: const u8[:], err: i64) {
    print("messages: ", what, ": ", krb5::error_text(err));
    exit(1);
}

// The client's AS-REQ for alice's TGT, with the pre-authentication given.
fn as_req(padata: const krb5::PaData[:], nonce: u32) -> u8[>..] {
    let body = krb5::KdcReqBody {
        kdc_options:   krb5::flag(krb5::KDC_OPT_FORWARDABLE) | krb5::flag(krb5::KDC_OPT_RENEWABLE_OK),
        has_cname:     true, cname: krb5::principal_name(krb5::NT_PRINCIPAL, "alice"), realm: "EXAMPLE.COM",
        has_sname:     true, sname: krb5::principal_name(krb5::NT_SRV_INST, krb5::name_join("krbtgt", "EXAMPLE.COM")),
        has_from:      false, from: 0, till: NOW + 36000, has_rtime: false, rtime: 0, nonce: nonce,
        etypes:        [krb5::ETYPE_AES256_CTS_HMAC_SHA384_192, krb5::ETYPE_AES256_CTS_HMAC_SHA1_96],
        has_addresses: false, addresses: [], has_enc_authz: false, enc_authz: krb5::no_enc_data(), has_tickets: false, tickets: [],
    };
    var out: u8[>..] = [];
    let req = krb5::KdcReq { msg_type: krb5::MSG_AS_REQ, has_padata: padata.len > 0, padata: padata, body: copy(body) };
    krb5::encode_kdc_req(out, req);
    return out;
}

fn main() {
    // Names: "service/host@REALM"; '/' and '@' inside a component escaped.
    let name, realm, has_realm, ok = krb5::parse_principal("HTTP/web.example.com@EXAMPLE.COM");
    let parts = krb5::name_parts(name);
    guard ok && has_realm && parts.len == 2 && krb5::name_part(name, 1) == "web.example.com" else { print("messages: name"); exit(1); }
    let odd = krb5::name_join("a/b", "c@d");
    print("principal ", name, " in ", realm, ": ", parts.len, " components; one with escapes: ", krb5::principal_string(odd, realm));

    // The KDC's record of alice: her aes256 key, from her password.
    let salt = "EXAMPLE.COMalice";
    let kdc_key, kerr = krb5::string_to_key(krb5::ETYPE_AES256_CTS_HMAC_SHA1_96, "alice's password", salt);
    if kerr != krb5::OK { fail("key", kerr); }

    // 1. Client: an AS-REQ without pre-authentication.
    var none: krb5::PaData[>..] = [];
    let req1 = as_req(none, 12345);

    // 2. KDC: it decodes the request and wants pre-authentication.
    guard krb5::message_type(req1) == krb5::MSG_AS_REQ else { print("messages: not an AS-REQ"); exit(1); }
    let r1, e1 = krb5::decode_kdc_req(req1);
    if e1 != krb5::OK || r1.has_padata { fail("AS-REQ", e1); }
    var info:  u8[>..]               = [];
    var infos: krb5::EtypeInfo2[>..] = [];
    infos.push(krb5::EtypeInfo2 { etype: kdc_key.etype, has_salt: true, salt: salt, has_s2kparams: false, s2kparams: "" });
    krb5::encode_etype_info(info, infos, false);
    var method: krb5::PaData[>..] = [];
    method.push(krb5::PaData { pa_type: krb5::PA_ETYPE_INFO2, value: copy(info) });
    method.push(krb5::PaData { pa_type: krb5::PA_ENC_TIMESTAMP, value: "" });
    var edata: u8[>..] = [];
    krb5::encode_padata(edata, method);
    var err_msg: u8[>..] = [];
    let kerror = krb5::KrbError {
        has_ctime:  false, ctime: 0, has_cusec: false, cusec: 0, stime: NOW, susec: 0,
        error_code: krb5::KDC_ERR_PREAUTH_REQUIRED, has_crealm: true, crealm: "EXAMPLE.COM", has_cname: true,
        cname:      copy(r1.body.cname), realm: "EXAMPLE.COM", sname: copy(r1.body.sname), has_etext: false, etext: "", has_edata: true, edata: copy(edata),
    };
    krb5::encode_krb_error(err_msg, kerror);
    print("AS-REQ ", req1.len, " bytes for ", krb5::principal_string(r1.body.cname.name, r1.body.realm), " -> KRB-ERROR ", err_msg.len, " bytes");

    // 3. Client: reads the error and the hints in it.
    guard krb5::message_type(err_msg) == krb5::MSG_KRB_ERROR else { print("messages: not a KRB-ERROR"); exit(1); }
    let ke, ee = krb5::decode_krb_error(err_msg);
    if ee != krb5::OK || ke.error_code != krb5::KDC_ERR_PREAUTH_REQUIRED { fail("KRB-ERROR", ee); }
    print("  ", krb5::error_text(ke.error_code));
    let pa, pe = krb5::decode_padata(ke.edata);
    if pe != krb5::OK { fail("METHOD-DATA", pe); }
    var etype:    i32     = 0;
    var got_salt: u8[>..] = [];
    for p in pa {
        if p.pa_type != krb5::PA_ETYPE_INFO2 { continue; }
        let list, le = krb5::decode_etype_info(p.value, false);
        for i in list { if etype == 0 { etype = i.etype; got_salt.append(i.salt); } }
    }
    guard etype != 0 else { print("messages: no ETYPE-INFO2"); exit(1); }
    print("  use ", krb5::etype_name(etype), " with salt \"", got_salt, "\"");
    let key, ske = krb5::string_to_key(etype, "alice's password", got_salt);
    var ts: u8[>..] = [];
    krb5::encode_pa_enc_ts(ts, NOW + 2, true, 123456);
    var c: u8[>..] = [];
    let ce = krb5::encrypt(key, krb5::USAGE_AS_REQ_PA_ENC_TIMESTAMP, ts, c);
    if ske != krb5::OK || ce != krb5::OK { fail("PA-ENC-TIMESTAMP", ce); }
    var enc: u8[>..] = [];
    let ed = krb5::EncryptedData { etype: key.etype, has_kvno: false, kvno: 0, cipher: copy(c) };
    krb5::encode_enc_data(enc, ed);
    var pre: krb5::PaData[>..] = [];
    pre.push(krb5::PaData { pa_type: krb5::PA_ENC_TIMESTAMP, value: copy(enc) });
    let req2 = as_req(pre, 67890);

    // 4. KDC: decrypts the timestamp with its key and checks the time.
    let r2, e2 = krb5::decode_kdc_req(req2);
    if e2 != krb5::OK { fail("AS-REQ", e2); }
    var checked = false;
    for p in r2.padata {
        if p.pa_type != krb5::PA_ENC_TIMESTAMP { continue; }
        let d, de = krb5::decode_enc_data(p.value);
        var plain: u8[>..] = [];
        let xe = krb5::decrypt(kdc_key, krb5::USAGE_AS_REQ_PA_ENC_TIMESTAMP, d.cipher, plain);
        if de != krb5::OK || xe != krb5::OK { fail("the client's timestamp", xe); }
        let t, has_us, us, te = krb5::decode_pa_enc_ts(plain);
        guard te == krb5::OK && t - NOW < 300 && NOW - t < 300 else { print("messages: timestamp out of skew"); exit(1); }
        print("AS-REQ ", req2.len, " bytes with PA-ENC-TIMESTAMP: the client's time ", t, ".", us, " is within the skew");
        checked = true;
    }
    guard checked && r2.body.nonce == 67890 else { print("messages: no timestamp"); exit(1); }

    // A wrong password makes a key the KDC cannot decrypt with.
    let wrong, we = krb5::string_to_key(etype, "not alice's password", got_salt);
    var c2: u8[>..] = [];
    krb5::encrypt(wrong, krb5::USAGE_AS_REQ_PA_ENC_TIMESTAMP, ts, c2);
    var p2: u8[>..] = [];
    let xe2 = krb5::decrypt(kdc_key, krb5::USAGE_AS_REQ_PA_ENC_TIMESTAMP, c2, p2);
    guard xe2 != krb5::OK else { print("messages: a wrong password was accepted"); exit(1); }
    var e3: u8[>..] = [];
    krb5::make_krb_error(krb5::KDC_ERR_PREAUTH_FAILED, krb5::name_join("krbtgt", "EXAMPLE.COM"), "EXAMPLE.COM", NOW, 0, e3);
    let k3, ee3 = krb5::decode_krb_error(e3);
    print("a wrong password: ", krb5::error_text(k3.error_code));
}
