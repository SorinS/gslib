// goose-kmip: a KMIP client on the command line, over TLS with a client
// certificate.
//
//   goose-kmip [options] COMMAND [ARGS]
//
//   versions                      the versions the server speaks
//   query                         its operations, object types, vendor
//   create aes|hmac-sha256 BITS   a new key; prints its identifier
//   create-pair rsa BITS | ec p256|p384|p521
//                                 a new key pair; the private key's, then the public key's
//   register-secret TEXT          secret data (a password)
//   get UID                       the object, its material in hex
//   attrs UID                     its attributes
//   locate [NAME]                 the identifiers of the objects (with that Name)
//   activate|destroy UID
//   revoke UID                    revoked as no longer used (Cessation of Operation)
//   encrypt UID TEXT              AES-GCM: nonce, ciphertext and tag in hex
//   decrypt UID NONCE CT TAG      the plaintext
//   sign UID TEXT                 the signature in hex (RSA PKCS #1 v1.5 or ECDSA, SHA-256, by the key)
//   verify UID TEXT SIG           valid or invalid
//   mac UID TEXT                  the MAC in hex
//   rng N                         N random bytes in hex
//   dump FILE                     a message in a file (TTLV, XML or JSON), decoded;
//                                 with --xml or --json, in that encoding
//   convert FILE ttlv|xml|json OUT
//                                 a message in a file written in another encoding
//
//   --host H --port N             the server (127.0.0.1, 5696)
//   --https [PATH]                KMIP over HTTPS, POSTs to PATH (/kmip)
//   --encoding ttlv|xml|json      the messages' encoding over HTTPS (ttlv)
//   --name N                      the name in its certificate (the host)
//   --ca F --cert F --key F       PEM: the CA, the client's certificate and key
//   --kmip V                      1.0 ... 2.0, or auto (Discover Versions): auto
//   --usage MASK                  the usage mask for create, register, create-pair (decimal)
//   --key-name N                  a Name for what create, create-pair or register make

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.kmip.https;
import gslib.kmip.xml;
import gslib.kmip.json;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.encoding.asn1;
import gslib.entropy;

fn die(what: const u8[:]) { print("goose-kmip: ", what); exit(2); }

fn pem_der(path: const u8[:], label: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { die(str("cannot read ", path)); }
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(text, label);
    for d in ders { out.append(d); }
    if out.len == 0 { die(str("no ", label, " in ", path)); }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let digits = "0123456789abcdef";
    for c in b { out.push(digits[(c >> 4) as i64]); out.push(digits[(c & 15) as i64]); }
    return out;
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s.len % 2 != 0 { die("odd hex"); }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        if !ok { die("bad hex"); }
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn need<C>(c: const C&, what: const u8[:], e: i64) {
    if e != kmip::OK { die(str(what, ": ", kmip::describe(c, e))); }
}

// Signature parameters for the key: RSA PKCS #1 v1.5 or ECDSA, SHA-256,
// by its Cryptographic Algorithm, spelled out (as PyKMIP wants them).
fn sig_params<C>(c: C&, uid: const u8[:]) -> kmip::CryptoParams {
    let at, e = kmip::get_attributes(c, uid, [kmip::TAG_CRYPTOGRAPHIC_ALGORITHM]);
    need(c, "get attributes", e);
    let alg, ok = kmip::get_enum(at, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM);
    if ok && alg == kmip::ALG_RSA {
        return kmip::CryptoParams { alg: kmip::ALG_RSA, padding: kmip::PAD_PKCS1V15, hash: kmip::HASH_SHA_256,
                                    sig: kmip::SIG_SHA256_WITH_RSA_ENCRYPTION };
    }
    return kmip::CryptoParams { alg: alg, hash: kmip::HASH_SHA_256, sig: kmip::SIG_ECDSA_WITH_SHA256 };
}

// A message in a file as TTLV: the file's TTLV, or its XML or JSON
// (text whose first byte, past white space, is '<' or '{').
fn read_message(path: const u8[:]) -> u8[>..] {
    var data: u8[>..] = [];
    if !read_file(path, data) { die(str("cannot read ", path)); }
    var k = 0;
    while k < data.len && (data[k] == ' ' || data[k] == '\t' || data[k] == '\n' || data[k] == '\r') { k++; }
    if k < data.len && (data[k] == '<' || data[k] == '{') {
        var t: u8[>..] = [];
        var why: u8[>..] = [];
        let e = if data[k] == '<' { kmip::from_xml(data, t, kmip::Options { .. }, why) }
                else { kmip::from_json(data, t, kmip::Options { .. }, why) };
        if e != kmip::OK { die(str(path, ": ", kmip::error_text(e), ": ", why)); }
        return t;
    }
    return data;
}

fn dump_file(path: const u8[:], form: const u8[:]) {
    let data = read_message(path);
    var doc: kmip::Node[>..] = [];
    let r, e = kmip::decode(data, kmip::Options { .. }, doc);
    if e != kmip::OK { die(str("not TTLV: ", kmip::error_text(e))); }
    if form == "xml" || form == "json" {
        var out: u8[>..] = [];
        let ee = if form == "xml" { kmip::to_xml(out, data, doc, r, 0) } else { kmip::ttlv_to_json(data, out) };
        if ee != kmip::OK { die(str("cannot write it as ", form, ": ", kmip::error_text(ee))); }
        if out.len > 0 && out[out.len - 1] == '\n' { out.pop(); }
        print(out);
        return;
    }
    print(kmip::dump(data, doc, r));
}

fn convert_file(path: const u8[:], form: const u8[:], dest: const u8[:]) {
    let data = read_message(path);
    let enc = if form == "xml" { kmip::MSG_XML } else if form == "json" { kmip::MSG_JSON } else if form == "ttlv" { kmip::MSG_TTLV } else { 0 };
    if enc == 0 { die("convert: ttlv, xml or json"); }
    var out: u8[>..] = [];
    let e = kmip::encode_as(enc, data, out);
    if e != kmip::OK { die(str("convert: ", kmip::error_text(e))); }
    if !write_file(dest, out) { die(str("cannot write ", dest)); }
}

fn main() {
    let a = args();
    var host: u8[>..] = [];
    host.append("127.0.0.1");
    var port: i64 = 5696;
    var name: u8[>..] = [];
    var ca: u8[>..] = [];
    var cert: u8[>..] = [];
    var key: u8[>..] = [];
    var ver: u8[>..] = [];
    ver.append("auto");
    var usage: u32 = 0;
    var key_name: u8[>..] = [];
    var https = false;
    var path: u8[>..] = [];
    path.append("/kmip");
    var encoding: u8 = kmip::MSG_TTLV;
    var form: u8[>..] = [];
    var pos: i64[>..] = [];
    var i = 1;
    while i < a.len {
        let o = a[i];
        let more = i + 1 < a.len;
        if o == "--host" && more { host.clear(); host.append(a[i + 1]); i += 2; }
        else if o == "--port" && more { let v, ok = parse_int(a[i + 1], 10); port = v; i += 2; }
        else if o == "--name" && more { name.append(a[i + 1]); i += 2; }
        else if o == "--ca" && more { ca.append(a[i + 1]); i += 2; }
        else if o == "--cert" && more { cert.append(a[i + 1]); i += 2; }
        else if o == "--key" && more { key.append(a[i + 1]); i += 2; }
        else if o == "--kmip" && more { ver.clear(); ver.append(a[i + 1]); i += 2; }
        else if o == "--usage" && more { let v, ok = parse_int(a[i + 1], 10); usage = v as! u32; i += 2; }
        else if o == "--key-name" && more { key_name.append(a[i + 1]); i += 2; }
        else if o == "--https" {
            https = true;
            if more && a[i + 1].len > 0 && a[i + 1][0] == '/' { path.clear(); path.append(a[i + 1]); i += 2; } else { i++; }
        }
        else if o == "--encoding" && more {
            let w = a[i + 1];
            encoding = if w == "xml" { kmip::MSG_XML } else if w == "json" { kmip::MSG_JSON } else if w == "ttlv" { kmip::MSG_TTLV } else { 0 };
            if encoding == 0 { die("--encoding: ttlv, xml or json"); }
            i += 2;
        }
        else if o == "--xml" || o == "--json" { form.clear(); form.append(o[2..]); i++; }
        else { pos.push(i); i++; }
    }
    guard pos.len >= 1 else { die("usage: goose-kmip [options] COMMAND [ARGS] (see the source's head)"); }
    let cmd = a[pos[0]];
    fn arg(k: i64) -> const u8[:] {
        if k >= pos.len { die(str(cmd, ": too few arguments")); }
        return a[pos[k]];
    }
    if cmd == "dump" { dump_file(arg(1), form); return; }
    if cmd == "convert" { convert_file(arg(1), arg(2), arg(3)); return; }

    var roots: u8[>..] = [];
    if ca.len > 0 { roots.append(pem_der(ca, "CERTIFICATE")); }
    var cc = kmip::tls_config(if name.len > 0 { name[..] } else { host[..] }, roots);
    if cert.len > 0 && !tls::set_client_certificate(cc, pem_der(cert, "CERTIFICATE"), pem_der(key, "PRIVATE KEY")) {
        die("the client certificate and key");
    }
    if https {
        var c, e = kmip::https_dial(host, port, path, encoding, cc);
        if e != kmip::OK { die(str("cannot connect: ", kmip::error_text(e))); }
        run(c, ver, a, pos, usage, key_name);
        kmip::close(c);
    } else {
        var c, e = kmip::dial(host, port, cc);
        if e != kmip::OK { die(str("cannot connect: ", kmip::error_text(e))); }
        run(c, ver, a, pos, usage, key_name);
        kmip::close(c);
    }
}

// The command, over a client of either kind.
fn run<C>(c: C&, ver: const u8[:], a: u8[:][:], pos: const i64[:], usage: u32, key_name: const u8[:]) {
    let cmd = a[pos[0]];
    fn arg(k: i64) -> const u8[:] {
        if k >= pos.len { die(str(cmd, ": too few arguments")); }
        return a[pos[k]];
    }
    if ver == "auto" {
        let v, ev = kmip::negotiate(c);
        need(c, "discover versions", ev);
    } else {
        if ver.len != 3 || ver[1] != '.' { die("--kmip: 1.0 to 2.0, or auto"); }
        let mj, ok1 = parse_int(ver[..1], 10);
        let mn, ok2 = parse_int(ver[2..], 10);
        if !ok1 || !ok2 { die("--kmip: 1.0 to 2.0, or auto"); }
        c.version = kmip::Version { major: mj as! i32, minor: mn as! i32 };
    }

    if cmd == "versions" {
        let vs, ev = kmip::discover_versions(c, kmip::ALL_VERSIONS);
        need(c, "discover versions", ev);
        for v in vs { print(v.major, ".", v.minor); }
    } else if cmd == "query" {
        let fns: u32[3] = [kmip::QUERY_OPERATIONS, kmip::QUERY_OBJECTS, kmip::QUERY_SERVER_INFORMATION];
        let q, eq = kmip::query(c, fns);
        need(c, "query", eq);
        if q.vendor.len > 0 { print("vendor: ", q.vendor); }
        for op in q.operations { print("operation: ", kmip::enum_name(kmip::TAG_OPERATION, op)); }
        for t in q.object_types { print("object type: ", kmip::enum_name(kmip::TAG_OBJECT_TYPE, t)); }
    } else if cmd == "create" {
        let alg = arg(1);
        let bits, ok = parse_int(arg(2), 10);
        if !ok { die("create: bits"); }
        var at = kmip::attrs();
        if alg == "aes" {
            kmip::attr_enum(at, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_AES);
            kmip::attr_usage(at, if usage != 0 { usage } else { kmip::USAGE_ENCRYPT | kmip::USAGE_DECRYPT });
        } else if alg == "hmac-sha256" {
            kmip::attr_enum(at, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_HMAC_SHA256);
            kmip::attr_usage(at, if usage != 0 { usage } else { kmip::USAGE_MAC_GENERATE | kmip::USAGE_MAC_VERIFY });
        } else { die("create: aes or hmac-sha256"); }
        kmip::attr_int(at, kmip::TAG_CRYPTOGRAPHIC_LENGTH, bits as! i32);
        if key_name.len > 0 { kmip::attr_name(at, key_name); }
        let uid, ec = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, at);
        need(c, "create", ec);
        print(uid);
    } else if cmd == "create-pair" {
        let alg = arg(1);
        var common = kmip::attrs();
        if alg == "rsa" {
            let bits, ok = parse_int(arg(2), 10);
            kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_RSA);
            kmip::attr_int(common, kmip::TAG_CRYPTOGRAPHIC_LENGTH, bits as! i32);
        } else if alg == "ec" {
            let curve = arg(2);
            kmip::attr_enum(common, kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, kmip::ALG_EC);
            if curve == "p256" { kmip::attr_curve(common, kmip::CURVE_P_256); kmip::attr_int(common, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 256); }
            else if curve == "p384" { kmip::attr_curve(common, kmip::CURVE_P_384); kmip::attr_int(common, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 384); }
            else if curve == "p521" { kmip::attr_curve(common, kmip::CURVE_P_521); kmip::attr_int(common, kmip::TAG_CRYPTOGRAPHIC_LENGTH, 521); }
            else { die("create-pair ec: p256, p384 or p521"); }
        } else { die("create-pair: rsa or ec"); }
        if key_name.len > 0 { kmip::attr_name(common, key_name); }
        var pa = kmip::attrs();
        kmip::attr_usage(pa, kmip::USAGE_SIGN);
        var pb = kmip::attrs();
        kmip::attr_usage(pb, kmip::USAGE_VERIFY);
        let priv, pubk, ek = kmip::create_key_pair(c, common, pa, pb);
        need(c, "create key pair", ek);
        print(priv);
        print(pubk);
    } else if cmd == "register-secret" {
        var at = kmip::attrs();
        kmip::attr_usage(at, if usage != 0 { usage } else { kmip::USAGE_DERIVE_KEY });
        if key_name.len > 0 { kmip::attr_name(at, key_name); }
        let o = kmip::secret_data(kmip::SECRET_PASSWORD, arg(1));
        let uid, er = kmip::register(c, o, at);
        need(c, "register", er);
        print(uid);
    } else if cmd == "get" {
        let o, eg = kmip::get(c, arg(1), 0);
        need(c, "get", eg);
        print("type: ", kmip::enum_name(kmip::TAG_OBJECT_TYPE, o.obj_type));
        if o.key_format != 0 { print("format: ", kmip::enum_name(kmip::TAG_KEY_FORMAT_TYPE, o.key_format)); }
        if o.alg != 0 { print("algorithm: ", kmip::enum_name(kmip::TAG_CRYPTOGRAPHIC_ALGORITHM, o.alg), ", ", o.length, " bits"); }
        print("material: ", hex(o.material));
    } else if cmd == "attrs" {
        let none: u32[0] = [];
        let at, ea = kmip::get_attributes(c, arg(1), none);
        need(c, "get attributes", ea);
        var out: u8[>..] = [];
        let s = kmip::begin(out, kmip::TAG_ATTRIBUTES);
        out.append(at.enc);
        kmip::end(out, s);
        var doc: kmip::Node[>..] = [];
        let r, ed = kmip::decode(out, kmip::Options { .. }, doc);
        kmip::each(doc, r) { k => print(kmip::dump(out, doc, k)); };
    } else if cmd == "locate" {
        var at = kmip::attrs();
        if pos.len > 1 { kmip::attr_name(at, arg(1)); }
        let uids, el = kmip::locate(c, at, 0);
        need(c, "locate", el);
        for u in uids { print(u); }
    } else if cmd == "activate" {
        need(c, "activate", kmip::activate(c, arg(1)));
    } else if cmd == "destroy" {
        need(c, "destroy", kmip::destroy(c, arg(1)));
    } else if cmd == "revoke" {
        need(c, "revoke", kmip::revoke(c, arg(1), kmip::REVOKE_CESSATION_OF_OPERATION, "", 0));
    } else if cmd == "encrypt" {
        let gcm = kmip::CryptoParams { alg: kmip::ALG_AES, mode: kmip::MODE_GCM, tag_length: 16 };
        var nonce: u8[12] = [0; 12];
        entropy::random_bytes(nonce);
        let s, ee = kmip::encrypt(c, arg(1), gcm, arg(2), nonce, "");
        need(c, "encrypt", ee);
        print(hex(nonce), " ", hex(s.data), " ", hex(s.tag));
    } else if cmd == "decrypt" {
        let gcm = kmip::CryptoParams { alg: kmip::ALG_AES, mode: kmip::MODE_GCM, tag_length: 16 };
        let n = unhex(arg(2));
        let ct = unhex(arg(3));
        let tg = unhex(arg(4));
        let p, ed = kmip::decrypt(c, arg(1), gcm, ct, n, "", tg);
        need(c, "decrypt", ed);
        print(p);
    } else if cmd == "sign" {
        let sp = sig_params(c, arg(1));
        let sig, es = kmip::sign(c, arg(1), sp, arg(2));
        need(c, "sign", es);
        print(hex(sig));
    } else if cmd == "verify" {
        let sig = unhex(arg(3));
        let sp = sig_params(c, arg(1));
        let good, ev = kmip::verify(c, arg(1), sp, arg(2), sig);
        need(c, "verify", ev);
        print(if good { "valid" } else { "invalid" });
        if !good { exit(1); }
    } else if cmd == "mac" {
        let m, em = kmip::mac(c, arg(1), kmip::CryptoParams { .. }, arg(2));
        need(c, "mac", em);
        print(hex(m));
    } else if cmd == "rng" {
        let n, ok = parse_int(arg(1), 10);
        let r, er = kmip::rng_retrieve(c, n as! i32);
        need(c, "rng retrieve", er);
        print(hex(r));
    } else {
        die(str("unknown command ", cmd));
    }
}
