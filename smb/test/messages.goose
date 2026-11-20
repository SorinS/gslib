// Messages: requests built byte for byte as Windows built the ones in
// Microsoft's vectors (vectors/ms.txt: NEGOTIATE, SESSION_SETUP, WRITE,
// READ), the responses there read (NEGOTIATE with its contexts,
// SESSION_SETUP, READ, WRITE); the header both ways; directory listings,
// file information and the space of a share; paths and UNC names; and
// what does not add up refused: truncations, offsets outside the message,
// misaligned or repeated negotiate contexts, a preauth hash other than
// SHA-512, directory entries that run past their buffer.
import std;
import gslib from "../..";
import gslib.smb;
import gslib.smb.messages;
import gslib.smb.client;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        if s[i] == ' ' { i++; continue; }
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

// The vectors' messages: the n-th "preauth" line's message, the n-th
// "transform" line's plaintext.
fn vector(kind: const u8[:], n: i64, field: i64) -> u8[>..] {
    var k = 0;
    for line in split(embed_file("vectors/ms.txt"), '\n') {
        if line.len == 0 || line[0] == '#' { continue; }
        let w = words(line);
        if w[0] != kind { continue; }
        if k == n { return unhex(w[field]); }
        k++;
    }
    assert(false);
    return [];
}

fn header_both_ways() {
    var h = smb::header(smb::READ);
    h.credit_charge = 3;
    h.status = smb::STATUS_PENDING;
    h.credits = 64;
    h.flags = smb::FLAGS_SERVER_TO_REDIR | smb::FLAGS_ASYNC_COMMAND;
    h.message_id = 0x1122334455667788;
    h.async_id = 0x99;
    h.session_id = 0x100000000025;
    var m: u8[>..] = [];
    smb::put_header(m, h);
    check("header: 64 bytes", m.len == 64 && smb::is_smb2(m));
    let g, ok = smb::parse_header(m);
    check("header: read back", ok && g.credit_charge == 3 && g.status == smb::STATUS_PENDING && g.command == smb::READ &&
          g.credits == 64 && g.message_id == 0x1122334455667788 && g.async_id == 0x99 && g.tree_id == 0 &&
          g.session_id == 0x100000000025);
    var bad = copy(m);
    bad[4] = 65;
    let b2, ok2 = smb::parse_header(bad);
    check("header: StructureSize 65 refused", !ok2);
    let b3, ok3 = smb::parse_header(m[..63]);
    check("header: short refused", !ok3);
    var t: u8[>..] = [];
    smb::put_transport(t, 0x123456);
    let n, tok = smb::transport_len(t);
    check("transport length", tok && n == 0x123456 && t[0] == 0);
    t[0] = 0x85;                                        // a NetBIOS session keep-alive is not ours
    let n2, tok2 = smb::transport_len(t);
    check("transport: not a message", !tok2);
}

// Windows's NEGOTIATE request in the 3.1.1 GCM vector, built again.
fn negotiate_request() {
    let want = vector("preauth", 0, 2);
    var r = smb::NegotiateRequest { dialects: [], security_mode: smb::SIGNING_ENABLED, capabilities: 0x66, guid: [0; 16],
                                    salt: [0; 32], ciphers: [], signing: [], netname: [] };
    let ds: u16[5] = [smb::SMB202, smb::SMB21, smb::SMB30, smb::SMB302, smb::SMB311];
    for d in ds { r.dialects.push(d); }
    for i in 16 { r.guid[i] = want[64 + 12 + i]; }
    for i in 32 { r.salt[i] = want[want.len - 48 + i]; }
    r.ciphers.push(smb::AES128_GCM);
    r.ciphers.push(smb::AES128_CCM);
    var m: u8[>..] = [];
    m.append(want[..64]);
    check("NEGOTIATE request builds", smb::negotiate_request(m, r));
    check("NEGOTIATE request as Windows sent it", m == want);
    // Without 3.1.1 there are no contexts, and the start time is zero.
    var r2 = copy(r);
    r2.dialects.clear();
    r2.dialects.push(smb::SMB21);
    var m2: u8[>..] = [];
    m2.append(want[..64]);
    smb::negotiate_request(m2, r2);
    check("NEGOTIATE without 3.1.1", m2.len == 64 + 36 + 2 && smb::get64(m2, 64 + 28) == 0);
}

fn negotiate_response() {
    let m = vector("preauth", 1, 2);
    let n, ok = smb::parse_negotiate_response(m);
    check("NEGOTIATE response read", ok && n.dialect == smb::SMB311 && n.security_mode == smb::SIGNING_ENABLED &&
          n.preauth && n.cipher == smb::AES128_GCM && !n.has_signing && n.max_read == 0x800000 && n.max_write == 0x800000);
    let blob = smb::span_bytes(m, n.blob);
    check("NEGOTIATE response: SPNEGO's NegTokenInit2", blob.len == 0x140 && blob[0] == 0x60);
    // Each truncation is refused.
    var cut = 0;
    for k in m.len - 1 {
        let x, okx = smb::parse_negotiate_response(m[..k]);
        if okx { cut++; }
    }
    check("NEGOTIATE response: every truncation refused", cut == 0);
    // The contexts: where they are, what they say.
    let ctx_off = smb::get32(m, 64 + 60) as i64;
    var bad = copy(m);
    smb::set32(bad, 64 + 60, (ctx_off + 4) as! u32);
    let b1, ok1 = smb::parse_negotiate_response(bad);
    check("contexts misaligned: refused", !ok1);
    var b = copy(m);
    smb::set16(b, ctx_off + 8 + 4, 2);                  // the hash: SHA-256's id, not SHA-512
    let b2, ok2 = smb::parse_negotiate_response(b);
    check("preauth other than SHA-512: refused", !ok2);
    var c = copy(m);
    smb::set16(c, 64 + 6, 0);                           // no contexts at all
    let b3, ok3 = smb::parse_negotiate_response(c);
    check("3.1.1 without contexts: refused", !ok3);
    var d = copy(m);
    smb::set16(d, ctx_off + 48 + 8, 2);                 // two ciphers chosen
    let b4, ok4 = smb::parse_negotiate_response(d);
    check("two ciphers chosen: refused", !ok4);
    var e = copy(m);
    smb::set16(e, 64 + 56, 10);                         // the security buffer inside the fixed part
    let b5, ok5 = smb::parse_negotiate_response(e);
    check("security buffer offset inside the body: refused", !ok5);
    var f = copy(m);
    smb::set16(f, ctx_off + 48, smb::PREAUTH_INTEGRITY_CAPABILITIES);   // the preauth context twice
    let b6, ok6 = smb::parse_negotiate_response(f);
    check("two preauth contexts: refused", !ok6);
}

fn session_setup() {
    let req = vector("preauth", 2, 2);
    var m: u8[>..] = [];
    m.append(req[..64]);
    let blob = req[64 + 24..];
    smb::session_setup_request(m, smb::SIGNING_ENABLED as! u8, smb::CAP_DFS, 0, blob);
    check("SESSION_SETUP request as Windows sent it", m == req);
    let resp = vector("preauth", 3, 2);
    let flags, span, ok = smb::parse_session_setup_response(resp);
    let tok = smb::span_bytes(resp, span);
    check("SESSION_SETUP response: the challenge", ok && flags == 0 && tok.len == 0xb3 && tok[0] == 0xa1);
    let h, hok = smb::parse_header(resp);
    check("SESSION_SETUP response: MORE_PROCESSING_REQUIRED", hok && h.status == smb::STATUS_MORE_PROCESSING_REQUIRED &&
          h.session_id == 0x100000000025);
    var bad = copy(resp);
    smb::set16(bad, 64 + 6, 0xb4);                      // one byte past the end
    let f2, s2, ok2 = smb::parse_session_setup_response(bad);
    check("SESSION_SETUP response: buffer past the end refused", !ok2);
}

fn read_write() {
    // The GCM vector's WRITE request, READ request, and their responses.
    let wreq = vector("transform", 0, 4);
    let fid = wreq[64 + 16..64 + 32];
    var m: u8[>..] = [];
    m.append(wreq[..64]);
    smb::write_request(m, fid, 0, "Smb3 encryption testing");
    m[64 + 40] = 0x70;                                  // Windows points its empty WriteChannelInfo at the data
    check("WRITE request as Windows sent it", m == wreq);
    let wresp = vector("transform", 1, 4);
    let count, wok = smb::parse_write_response(wresp);
    check("WRITE response: 23 bytes written", wok && count == 23);
    let rreq = vector("transform", 2, 4);
    var r: u8[>..] = [];
    r.append(rreq[..64]);
    smb::read_request(r, fid, 0, 23, 0);
    r[64 + 2] = 0;                                      // Windows sent no Padding hint
    check("READ request as Windows sent it", r == rreq);
    let rresp = vector("transform", 3, 4);
    let span, rok = smb::parse_read_response(rresp);
    check("READ response: the data", rok && smb::span_bytes(rresp, span) == "Smb3 encryption testing");
    var bad = copy(rresp);
    bad[64 + 2] = 0x40;                                 // the data inside the fixed part
    let s2, ok2 = smb::parse_read_response(bad);
    check("READ response: data offset inside the body refused", !ok2);
    var big = copy(rresp);
    smb::set32(big, 64 + 4, 24);
    let s3, ok3 = smb::parse_read_response(big);
    check("READ response: length past the end refused", !ok3);
}

fn dir_entry(out: u8[>..]&, name: const u8[:], size: u64, attrs: u32, last: bool) {
    let start = out.len;
    var n: u8[>..] = [];
    assert(smb::utf16(n, name));
    smb::put32(out, 0);
    smb::put32(out, 0);
    for i in 4 { smb::put64(out, 132000000000000000 + i as u64); }
    smb::put64(out, size);
    smb::put64(out, (size + 4095) / 4096 * 4096);
    smb::put32(out, attrs);
    smb::put32(out, n.len as! u32);
    out.append(n);
    if !last {
        while (out.len - start) % 8 != 0 { out.push(0); }
        smb::set32(out, start, (out.len - start) as! u32);
    }
}

fn directories() {
    var b: u8[>..] = [];
    dir_entry(b, ".", 0, smb::ATTR_DIRECTORY, false);
    dir_entry(b, "notes.txt", 1234, smb::ATTR_ARCHIVE, false);
    dir_entry(b, "été", 0, smb::ATTR_DIRECTORY, true);
    var es: smb::DirEntry[>..] = [];
    check("directory read", smb::parse_directory(b, es) && es.len == 3);
    var k = 0;
    for e in es {
        if k == 1 { check("entry: name, size, attributes", e.name[..] == "notes.txt" && e.info.size == 1234 && !smb::is_dir(e.info)); }
        if k == 2 { check("entry: UTF-16 name", e.name[..] == "été" && smb::is_dir(e.info)); }
        k++;
    }
    var cut = 0;
    for n in b.len {
        var x: smb::DirEntry[>..] = [];
        if n > 0 && smb::parse_directory(b[..n], x) { cut++; }
    }
    check("directory: every truncation refused", cut == 0);
    var bad = copy(b);
    smb::set32(bad, 0, 4);                              // NextEntryOffset inside the entry
    var x1: smb::DirEntry[>..] = [];
    check("directory: next entry inside this one refused", !smb::parse_directory(bad, x1));
    var odd = copy(b);
    smb::set32(odd, 60, 3);                             // an odd UTF-16 length
    var x2: smb::DirEntry[>..] = [];
    check("directory: odd name length refused", !smb::parse_directory(odd, x2));
}

fn info_and_paths() {
    var b: u8[>..] = [];
    for i in 4 { smb::put64(b, smb::filetime_of(1700000000 + i)); }
    smb::put64(b, 8192);
    smb::put64(b, 5000);
    smb::put32(b, smb::ATTR_ARCHIVE);
    smb::put32(b, 0);
    let i, ok = smb::parse_network_open(b);
    check("network open information", ok && i.size == 5000 && i.alloc == 8192 && smb::unix_time(i.written) == 1700000002);
    let i2, ok2 = smb::parse_network_open(b[..55]);
    check("network open information: short refused", !ok2);
    var fs: u8[>..] = [];
    smb::put64(fs, 1000); smb::put64(fs, 400); smb::put64(fs, 500); smb::put32(fs, 8); smb::put32(fs, 512);
    let s, sok = smb::parse_fs_full_size(fs);
    check("full size information", sok && s.total_units == 1000 && s.caller_free_units == 400 && s.bytes_per_sector == 512);

    let p1, ok1 = smb::share_path("/dir//sub/./file.txt");
    check("path: separators", ok1 && p1 == "dir\\sub\\file.txt");
    let p2, okp2 = smb::share_path("dir\\..\\..\\etc");
    check("path: .. refused", !okp2);
    let p3, okp3 = smb::share_path("");
    check("path: the root", okp3 && p3.len == 0);
    let server, share, uok = smb::split_unc("\\\\fs.example.test\\data");
    check("UNC", uok && server == "fs.example.test" && share == "data");
    let s2, sh2, uok2 = smb::split_unc("//fs/data/more");
    check("UNC with a path: refused", !uok2);
    let s3, sh3, uok3 = smb::split_unc("\\\\fs\\");
    check("UNC without a share: refused", !uok3);
    check("FILETIME", smb::unix_time(smb::filetime_of(1234567890)) == 1234567890 && smb::unix_time(0) == 0);

    // Renames carry the new name in UTF-16, 24 bytes at least.
    var r: u8[>..] = [];
    check("rename information", smb::rename_info(r, "a", true) && r.len == 24 && r[0] == 1 && smb::get32(r, 16) == 2);
    // CREATE with an empty name (the share's root) still has a buffer byte.
    var c: u8[>..] = [];
    var h = smb::header(smb::CREATE);
    smb::put_header(c, h);
    check("CREATE of the root", smb::create_request(c, "", smb::FILE_READ_ATTRIBUTES, 0, smb::FILE_SHARE_ALL, smb::FILE_OPEN, 0) &&
          c.len == 64 + 57 && smb::get16(c, 64 + 46) == 0);
}

// A login with a credential that the final response calls a guest (or
// null) session is refused: those flags come before any signature can be
// checked, so a man in the middle could set them to drop signing. A
// session with no credential may still be anonymous.
fn guest_flag() {
    var o = smb::options();
    o.require_signing = false;
    var c = smb::no_conn(o);
    c.session_flags = smb::SESSION_FLAG_IS_GUEST;
    let key: u8[16] = [1; 16];
    let final: u8[64] = [0; 64];
    check("a credential's login called a guest: refused", smb::finish_session(c, key, final) == smb::ERR_AUTH && !c.have_keys);
    var a = smb::no_conn(o);
    a.session_flags = smb::SESSION_FLAG_IS_NULL;
    check("no credential: anonymous", smb::finish_session(a, "", final) == smb::OK && !a.have_keys);
}

fn main() {
    header_both_ways();
    negotiate_request();
    negotiate_response();
    session_setup();
    read_write();
    directories();
    info_and_paths();
    guest_flag();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
