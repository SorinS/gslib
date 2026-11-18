// Packets: RFC 2865 §7.1's Access-Request and Access-Accept (the hidden
// password, the Response Authenticator), round trips of every hidden
// attribute, the authenticators of each kind of request, the
// Message-Authenticator first and checked, malformed packets refused;
// and MS-CHAPv2 against RFC 2759 §9.2 and RFC 3079 §3.5.3.
import std;
import gslib from "../..";
import gslib.radius;
import gslib.radius.mschap;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        if s[i] == ' ' { i++; continue; }
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn rfc2865() {
    let secret = "xyzzy5461";
    let req = unhex("01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d 93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8 01 10 05 06 00 00 00 03");
    let p, e = radius::parse(req);
    check("RFC 2865: the request parses", e == radius::OK && p.code == radius::ACCESS_REQUEST && radius::attr_count(p) == 4);
    check("RFC 2865: User-Name", radius::get_text(p, radius::USER_NAME) == "nemo");
    let pw, okp = radius::password(p, secret);
    check("RFC 2865: the password unhidden", okp && pw == "arctangent");
    let port, okn = radius::get_u32(p, radius::NAS_PORT);
    check("RFC 2865: NAS-Port", okn && port == 3);
    // Hidden again with the same authenticator, the same bytes.
    var q = radius::Packet { code: p.code, id: p.id, auth: p.auth, attrs: [] };
    radius::add(q, radius::USER_NAME, "nemo");
    radius::add_password(q, "arctangent", secret);
    let nas: u8[4] = [192, 168, 1, 16];
    radius::add_ipv4(q, radius::NAS_IP_ADDRESS, nas);
    radius::add_u32(q, radius::NAS_PORT, 3);
    check("RFC 2865: the request rebuilt byte for byte", radius::encode(q) == req);
    // A request without a Message-Authenticator: taken unless required.
    let c1, ec1 = radius::check_request(req, secret, false);
    check("RFC 2865: taken without Message-Authenticator", ec1 == radius::OK);
    let c2, ec2 = radius::check_request(req, secret, true);
    check("RFC 2865: refused when one is required", ec2 == radius::ERR_MESSAGE_AUTH);

    let acc = unhex("02 00 00 26 86 fe 22 0e 76 24 ba 2a 10 05 f6 bf 9b 55 e0 b2 06 06 00 00 00 01 0f 06 00 00 00 00 0e 06 c0 a8 01 03");
    let r, er = radius::check_response(acc, p, secret, false);
    check("RFC 2865: the Access-Accept's Response Authenticator", er == radius::OK && r.code == radius::ACCESS_ACCEPT);
    let r2, er2 = radius::check_response(acc, p, "wrong", false);
    check("RFC 2865: a wrong secret", er2 == radius::ERR_AUTHENTICATOR);
    let r3, er3 = radius::check_response(acc, p, secret, true);
    check("RFC 2865: no Message-Authenticator where one is required", er3 == radius::ERR_MESSAGE_AUTH);
    // The answer made here is the RFC's.
    var a = radius::response(p, radius::ACCESS_ACCEPT);
    radius::add_u32(a, radius::SERVICE_TYPE, 1);
    radius::add_u32(a, 15, 0);
    let host: u8[4] = [192, 168, 1, 3];
    radius::add_ipv4(a, 14, host);
    a.auth = radius::packet_md5(a, p.auth, secret);
    check("RFC 2865: the answer rebuilt byte for byte", radius::encode(a) == acc);
}

fn round_trips() {
    let secret = "testing123";
    for n in [0, 1, 15, 16, 17, 100, 128] {
        var pw: u8[>..] = [];
        for i in n { pw.push(('a' + (i % 26)) as! u8); }
        var p = radius::request(radius::ACCESS_REQUEST);
        let ok = radius::add_password(p, pw, secret);
        let back, okb = radius::password(p, secret);
        check(str("password of ", n, " bytes"), ok && okb && back == pw);
    }
    var p = radius::request(radius::ACCESS_REQUEST);
    var long: u8[129] = [0x41; 129];
    check("a password over 128 bytes refused", !radius::add_password(p, long, secret));

    // CHAP.
    var c = radius::request(radius::ACCESS_REQUEST);
    radius::add_chap(c, "pw");
    check("CHAP right", radius::chap_ok(c, "pw"));
    check("CHAP wrong", !radius::chap_ok(c, "px"));
    var c2 = radius::request(radius::ACCESS_REQUEST);
    let chal: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    radius::add(c2, radius::CHAP_CHALLENGE, chal);
    radius::add_chap(c2, "pw");
    check("CHAP with a CHAP-Challenge", radius::chap_ok(c2, "pw"));

    // Salt-encryption: Tunnel-Password and the MPPE keys.
    let req = radius::request(radius::ACCESS_REQUEST);
    var a = radius::response(req, radius::ACCESS_ACCEPT);
    radius::add_tunnel_password(a, 1, "tunnel-secret", secret, req.auth);
    let tp, tag, okt = radius::tunnel_password(a, secret, req.auth);
    check("Tunnel-Password", okt && tag == 1 && tp == "tunnel-secret");
    var msk: u8[64] = [0; 64];
    for i in 64 { msk[i] = i as! u8; }
    check("MPPE keys added", radius::add_mppe_keys(a, msk, secret, req.auth));
    let keys, okk = radius::mppe_keys(a, secret, req.auth);
    check("MPPE keys back", okk && keys == msk);
    let keys2, okk2 = radius::mppe_keys(a, "other", req.auth);
    check("MPPE keys under another secret", !okk2 || keys2 != msk);
    check("VSA", radius::count(a, radius::VENDOR_SPECIFIC) == 2);
}

fn signing() {
    let secret = "s3cret";
    // Access-Request: Message-Authenticator first, checked.
    var p = radius::request(radius::ACCESS_REQUEST);
    p.id = 7;
    radius::add(p, radius::USER_NAME, "bob");
    let w = radius::sign_request(p, secret);
    check("Message-Authenticator first", w[20] == radius::MESSAGE_AUTHENTICATOR && w[21] == 18);
    let q, e = radius::check_request(w, secret, true);
    check("the request checks", e == radius::OK && q.id == 7);
    let q2, e2 = radius::check_request(w, "nope", true);
    check("under another secret it does not", e2 == radius::ERR_MESSAGE_AUTH);
    var bad = copy(w);
    bad[bad.len - 1] ^= 1;
    let q3, e3 = radius::check_request(bad, secret, false);
    check("a changed byte", e3 == radius::ERR_MESSAGE_AUTH);

    // The answer: Message-Authenticator first, then the Response Authenticator.
    var r = radius::response(q, radius::ACCESS_CHALLENGE);
    radius::add(r, radius::STATE, "st");
    radius::set_eap(r, "\x01\x02\x00\x05\x01");
    let rw = radius::sign_response(r, q, secret);
    check("the answer's Message-Authenticator first", rw[20] == radius::MESSAGE_AUTHENTICATOR);
    let back, eb = radius::check_response(rw, q, secret, true);
    check("the answer checks", eb == radius::OK && radius::get_text(back, radius::STATE) == "st");
    var other = copy(q);
    other.id = 8;
    let b2, eb2 = radius::check_response(rw, other, secret, true);
    check("another request's answer", eb2 == radius::ERR_ID);
    var rbad = copy(rw);
    rbad[25] ^= 1;
    let b3, eb3 = radius::check_response(rbad, q, secret, true);
    check("a changed Message-Authenticator", eb3 != radius::OK);

    // Accounting-Request, CoA-Request: the authenticator over zeros.
    for code in [radius::ACCOUNTING_REQUEST, radius::COA_REQUEST, radius::DISCONNECT_REQUEST] {
        var ar = radius::request(code);
        radius::add_u32(ar, radius::ACCT_STATUS_TYPE, radius::ACCT_START);
        radius::add(ar, radius::ACCT_SESSION_ID, "s-1");
        if code == radius::COA_REQUEST { radius::ensure_message_auth(ar); }
        let aw = radius::sign_request(ar, secret);
        let ap, ea = radius::check_request(aw, secret, false);
        check(str(radius::code_name(code), " checks"), ea == radius::OK);
        let ap2, ea2 = radius::check_request(aw, "x", false);
        check(str(radius::code_name(code), " under another secret"), ea2 != radius::OK);
        var resp = radius::response(ap, code + 1);
        let rw2 = radius::sign_response(resp, ap, secret);
        let rr, er = radius::check_response(rw2, ap, secret, false);
        check(str(radius::code_name(code), "'s answer"), er == radius::OK && rr.code == code + 1);
    }

    // Proxy-State echoed in order.
    var ps = radius::request(radius::ACCESS_REQUEST);
    radius::add(ps, radius::PROXY_STATE, "one");
    radius::add(ps, radius::USER_NAME, "u");
    radius::add(ps, radius::PROXY_STATE, "two");
    let pr = radius::response(ps, radius::ACCESS_REJECT);
    let k0, v0, ok0 = radius::attr_at(pr, 0);
    let k1, v1, ok1 = radius::attr_at(pr, 1);
    check("Proxy-State copied", radius::attr_count(pr) == 2 && v0 == "one" && v1 == "two");

    // EAP-Message in pieces of 253.
    var big: u8[>..] = [];
    for i in 600 { big.push(i as! u8); }
    var ep = radius::request(radius::ACCESS_REQUEST);
    check("EAP in pieces", radius::set_eap(ep, big) && radius::count(ep, radius::EAP_MESSAGE) == 3);
    check("EAP joined", radius::eap_message(ep) == big);
    // An EAP-Message without a Message-Authenticator is refused.
    var noma = radius::request(radius::ACCESS_REQUEST);
    radius::set_eap(noma, "\x02\x01\x00\x05\x01");
    let nm, enm = radius::check_request(radius::encode(noma), secret, false);
    check("EAP without Message-Authenticator", enm == radius::ERR_MESSAGE_AUTH);
}

fn malformed() {
    let short: u8[19] = [1; 19];
    let a, e1 = radius::parse(short);
    check("too short", e1 == radius::ERR_MALFORMED);
    var p = radius::request(radius::ACCESS_REQUEST);
    radius::add(p, radius::USER_NAME, "x");
    var w = radius::encode(p);
    var w1 = copy(w);
    w1[3] = 255;
    let b, e2 = radius::parse(w1);
    check("length past the datagram", e2 == radius::ERR_MALFORMED);
    var w2 = copy(w);
    w2[21] = 1;
    let c, e3 = radius::parse(w2);
    check("an attribute of length 1", e3 == radius::ERR_MALFORMED);
    var w3 = copy(w);
    w3[21] = 9;
    let d, e4 = radius::parse(w3);
    check("an attribute past the packet", e4 == radius::ERR_MALFORMED);
    var w4 = copy(w);
    w4.push(0);
    w4.push(0);
    let f, e5 = radius::parse(w4);
    check("padding after the length dropped", e5 == radius::OK && radius::encode(f) == w);
    check("an empty attribute refused", !radius::add(p, radius::CLASS, ""));
    var v254: u8[254] = [0; 254];
    check("a 254-byte attribute refused", !radius::add(p, radius::CLASS, v254));
}

fn mschapv2() {
    // RFC 2759 §9.2.
    let auth_ch = unhex("5B5D7C7D7B3F2F3E3C2C602132262628");
    let peer_ch = unhex("21402324255E262A28295F2B3A337C7E");
    let ch = radius::challenge_hash(peer_ch, auth_ch, "User");
    check("ChallengeHash", ch[..] == unhex("D02E4386BCE91226")[..]);
    let h, ok = radius::nt_password_hash("clientPass");
    check("NtPasswordHash", ok && h[..] == unhex("44EBBA8D5312B8D611474411F56989AE")[..]);
    let nt = radius::nt_response(auth_ch, peer_ch, "User", h);
    check("NT-Response", nt[..] == unhex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")[..]);
    let ar = radius::authenticator_response(h, nt, peer_ch, auth_ch, "User");
    check("AuthenticatorResponse", ar[..] == "S=407A5589115FD0D6209F510FE9C04566932CDA56");
    check("its check", radius::authenticator_response_ok("S=407a5589115fd0d6209f510fe9c04566932cda56 M=ok", h, nt, peer_ch, auth_ch, "User"));
    check("a wrong one", !radius::authenticator_response_ok("S=407A5589115FD0D6209F510FE9C04566932CDA57", h, nt, peer_ch, auth_ch, "User"));
    // RFC 3079 §3.5.3.
    let mk = radius::master_key(h, nt);
    check("MasterKey", mk[..] == unhex("FDECE3717A8C838CB388E527AE3CDD31")[..]);
    // The RFC's sample is the server's send key, the client's receive key.
    let sk = radius::start_key(mk, true, true);
    check("SendStartKey128", sk[..] == unhex("8B7CDC149B993A1BA118CB153F56DCCB")[..]);
    check("the client's receive key is the server's send key", radius::start_key(mk, false, false)[..] == sk[..]);
    check("and not the client's send key", radius::start_key(mk, true, false)[..] != sk[..]);

    // The RADIUS attributes, both sides.
    let secret = "testing123";
    var req = radius::request(radius::ACCESS_REQUEST);
    let m, okm = radius::add_mschap2(req, "alice", "alice-pw");
    let h2, ok2 = radius::nt_password_hash("alice-pw");
    check("MS-CHAP2-Response right", okm && radius::check_mschap2(req, "alice", h2));
    let h3, ok3 = radius::nt_password_hash("other");
    check("MS-CHAP2-Response wrong", !radius::check_mschap2(req, "alice", h3));
    var acc = radius::response(req, radius::ACCESS_ACCEPT);
    check("MS-CHAP2-Success made", radius::add_mschap2_success(acc, req, "alice", h2, secret, true));
    check("MS-CHAP2-Success checked", radius::mschap2_success_ok(acc, m, "alice"));
    var acc2 = radius::response(req, radius::ACCESS_ACCEPT);
    radius::add_mschap2_success(acc2, req, "alice", h3, secret, false);
    check("MS-CHAP2-Success of another password", !radius::mschap2_success_ok(acc2, m, "alice"));
    let keys, okk = radius::mppe_keys(acc, secret, req.auth);
    check("MPPE keys of MS-CHAPv2", okk && keys.len == 32);
}

fn main() {
    rfc2865();
    round_trips();
    signing();
    malformed();
    mschapv2();
    print("packets: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
