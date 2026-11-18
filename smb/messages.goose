// smb.messages: each request's body built (after its 64-byte header) and
// each response read ([MS-SMB2] §2.2). Offsets in a message count from the
// start of its SMB2 header, as the protocol's do. A response's buffers
// come back as spans of the message, checked to lie inside it; a response
// whose sizes do not add up is refused whole.

namespace smb;

import std;

// A part of a message: [off, off + len).
struct Span { off: i64, len: i64 }

fn no_span() -> Span { Span { off: 0, len: 0 } }

fn span_bytes(m: const u8[:], s: Span) -> const u8[:] { m[s.off..s.off + s.len] }

// A buffer's span from its 16- or 32-bit offset and length, if it lies
// in the message past the fixed part of the body (an empty one anywhere).
fn read_span(m: const u8[:], off: i64, len: i64, fixed_end: i64) -> Span, bool {
    if len == 0 { return no_span(), true; }
    if off < fixed_end || off > m.len || len > m.len - off { return no_span(), false; }
    return Span { off: off, len: len }, true;
}

// Whether the body has the structure size wanted (and its fixed part fits).
fn body_is(m: const u8[:], size: u16) -> bool {
    let fixed = (size as i64) & ~1;
    return m.len >= HEADER_LEN + fixed && get16(m, HEADER_LEN) == size;
}

// The ERROR response's data (§2.2.2), for a failed request.
fn error_data(m: const u8[:]) -> Span, bool {
    if !body_is(m, 9) { return no_span(), false; }
    let n = get32(m, HEADER_LEN + 4);
    return read_span(m, HEADER_LEN + 8, n, HEADER_LEN + 8);
}

// --- NEGOTIATE (§2.2.3, §2.2.4) ---------------------------------------------------------------

struct NegotiateRequest {
    dialects:      u16[..8],
    security_mode: u16,
    capabilities:  u32,
    guid:          u8[16],
    salt:          u8[32],       // 3.1.1's preauth integrity salt
    ciphers:       u16[..4],     // 3.1.1's, most preferred first; none: no ENCRYPTION_CAPABILITIES
    signing:       u16[..3],     // 3.1.1's signing algorithms; none: no SIGNING_CAPABILITIES
    netname:       u8[..512],    // the server's name, UTF-8; empty: no NETNAME context
}

fn offers_311(r: const NegotiateRequest&) -> bool {
    for d in r.dialects { if d == SMB311 { return true; } }
    return false;
}

fn put_context(out: u8[>..]&, kind: u16, data: const u8[:]) {
    pad_to(out, 8);
    put16(out, kind);
    put16(out, data.len as! u16);
    put32(out, 0);
    out.append(data);
}

// The whole NEGOTIATE request but its header: out holds the 64 header
// bytes already, so offsets and padding come out right.
fn negotiate_request(out: u8[>..]&, r: const NegotiateRequest&) -> bool {
    assert(out.len == HEADER_LEN);
    put16(out, 36);
    put16(out, r.dialects.len as! u16);
    put16(out, r.security_mode);
    put16(out, 0);
    put32(out, r.capabilities);
    out.append(r.guid);
    let ctx_at = out.len;
    put64(out, 0);                     // NegotiateContextOffset and count, or ClientStartTime
    for d in r.dialects { put16(out, d); }
    if !offers_311(r) { return true; }
    pad_to(out, 8);
    set32(out, ctx_at, out.len as! u32);
    var count: u16 = 0;
    var pre: u8[>..] = [];
    put16(pre, 1);
    put16(pre, 32);
    put16(pre, HASH_SHA512);
    pre.append(r.salt);
    put_context(out, PREAUTH_INTEGRITY_CAPABILITIES, pre);
    count++;
    if r.ciphers.len > 0 {
        var enc: u8[>..] = [];
        put16(enc, r.ciphers.len as! u16);
        for c in r.ciphers { put16(enc, c); }
        put_context(out, ENCRYPTION_CAPABILITIES, enc);
        count++;
    }
    if r.signing.len > 0 {
        var sg: u8[>..] = [];
        put16(sg, r.signing.len as! u16);
        for a in r.signing { put16(sg, a); }
        put_context(out, SIGNING_CAPABILITIES, sg);
        count++;
    }
    if r.netname.len > 0 {
        var nn: u8[>..] = [];
        if !utf16(nn, r.netname) { return false; }
        put_context(out, NETNAME_NEGOTIATE_CONTEXT_ID, nn);
        count++;
    }
    set16(out, ctx_at + 4, count);
    return true;
}

struct NegotiateResponse {
    security_mode: u16,
    dialect:       u16,
    guid:          u8[16],
    capabilities:  u32,
    max_transact:  u32,
    max_read:      u32,
    max_write:     u32,
    system_time:   u64,
    blob:          Span,         // the security buffer (SPNEGO's NegTokenInit2)
    preauth:       bool,         // 3.1.1: a PREAUTH_INTEGRITY_CAPABILITIES with SHA-512
    cipher:        u16,          // 3.1.1: the cipher chosen (0: none)
    signing:       u16,          // 3.1.1: the signing algorithm chosen
    has_signing:   bool,
}

// A NEGOTIATE response. 3.1.1's contexts are read: exactly one preauth
// context (SHA-512 alone), at most one cipher and one signing algorithm,
// each where its offset and length say, 8-aligned.
fn parse_negotiate_response(m: const u8[:]) -> NegotiateResponse, bool {
    var r = NegotiateResponse { security_mode: 0, dialect: 0, guid: [0; 16], capabilities: 0, max_transact: 0, max_read: 0,
                                max_write: 0, system_time: 0, blob: no_span(), preauth: false, cipher: 0, signing: AES_CMAC,
                                has_signing: false };
    if !body_is(m, 65) { return r, false; }
    let b = HEADER_LEN;
    r.security_mode = get16(m, b + 2);
    r.dialect = get16(m, b + 4);
    let ctx_count = get16(m, b + 6);
    for i in 16 { r.guid[i] = m[b + 8 + i]; }
    r.capabilities = get32(m, b + 24);
    r.max_transact = get32(m, b + 28);
    r.max_read = get32(m, b + 32);
    r.max_write = get32(m, b + 36);
    r.system_time = get64(m, b + 40);
    let blob, ok = read_span(m, get16(m, b + 56), get16(m, b + 58), b + 64);
    if !ok { return r, false; }
    r.blob = blob;
    if r.dialect != SMB311 { return r, true; }
    var at: i64 = get32(m, b + 60);
    if ctx_count == 0 || at < b + 64 || at % 8 != 0 { return r, false; }
    var seen_enc = false;
    for k in ctx_count {
        if k > 0 { at = (at + 7) & ~7; }
        if at + 8 > m.len { return r, false; }
        let kind = get16(m, at);
        let len: i64 = get16(m, at + 2);
        let d = at + 8;
        if d + len > m.len { return r, false; }
        if kind == PREAUTH_INTEGRITY_CAPABILITIES {
            if r.preauth || len < 6 { return r, false; }
            let algs: i64 = get16(m, d);
            let salt: i64 = get16(m, d + 2);
            if algs != 1 || 6 + salt > len || get16(m, d + 4) != HASH_SHA512 { return r, false; }
            r.preauth = true;
        } else if kind == ENCRYPTION_CAPABILITIES {
            if seen_enc || len < 4 || get16(m, d) != 1 { return r, false; }
            seen_enc = true;
            r.cipher = get16(m, d + 2);
        } else if kind == SIGNING_CAPABILITIES {
            if r.has_signing || len < 4 || get16(m, d) != 1 { return r, false; }
            r.has_signing = true;
            r.signing = get16(m, d + 2);
        }
        at = d + len;
    }
    return r, r.preauth;
}

// --- SESSION_SETUP, LOGOFF (§2.2.5 - §2.2.8) ---------------------------------------------------------

fn session_setup_request(out: u8[>..]&, security_mode: u8, capabilities: u32, previous: u64, blob: const u8[:]) {
    put16(out, 25);
    out.push(0);                       // Flags: no binding
    out.push(security_mode);
    put32(out, capabilities);
    put32(out, 0);                     // Channel
    put16(out, (HEADER_LEN + 24) as! u16);
    put16(out, blob.len as! u16);
    put64(out, previous);
    out.append(blob);
}

fn parse_session_setup_response(m: const u8[:]) -> u16, Span, bool {
    if !body_is(m, 9) { return 0, no_span(), false; }
    let flags = get16(m, HEADER_LEN + 2);
    let blob, ok = read_span(m, get16(m, HEADER_LEN + 4), get16(m, HEADER_LEN + 6), HEADER_LEN + 8);
    return flags, blob, ok;
}

// LOGOFF, TREE_DISCONNECT and ECHO: StructureSize 4 and nothing else.
fn empty_request(out: u8[>..]&) { put16(out, 4); put16(out, 0); }

// --- TREE_CONNECT (§2.2.9, §2.2.10) --------------------------------------------------------------

fn tree_connect_request(out: u8[>..]&, unc: const u8[:]) -> bool {
    var path: u8[>..] = [];
    if !utf16(path, unc) || path.len > 0xffff { return false; }
    put16(out, 9);
    put16(out, 0);
    put16(out, (HEADER_LEN + 8) as! u16);
    put16(out, path.len as! u16);
    out.append(path);
    return true;
}

struct TreeInfo { share_type: u8, share_flags: u32, capabilities: u32, maximal_access: u32 }

fn parse_tree_connect_response(m: const u8[:]) -> TreeInfo, bool {
    var t = TreeInfo { share_type: 0, share_flags: 0, capabilities: 0, maximal_access: 0 };
    if !body_is(m, 16) { return t, false; }
    t.share_type = m[HEADER_LEN + 2];
    t.share_flags = get32(m, HEADER_LEN + 4);
    t.capabilities = get32(m, HEADER_LEN + 8);
    t.maximal_access = get32(m, HEADER_LEN + 12);
    return t, true;
}

// --- CREATE, CLOSE, FLUSH (§2.2.13 - §2.2.18) ----------------------------------------------------------

let IMPERSONATION: u32 = 2;            // Impersonation
let OPLOCK_NONE: u8 = 0;

fn create_request(out: u8[>..]&, name: const u8[:], access: u32, attributes: u32, share: u32, disposition: u32, options: u32) -> bool {
    var n: u8[>..] = [];
    if !utf16(n, name) || n.len > 0xffff { return false; }
    put16(out, 57);
    out.push(0);                       // SecurityFlags
    out.push(OPLOCK_NONE);
    put32(out, IMPERSONATION);
    put64(out, 0);                     // SmbCreateFlags
    put64(out, 0);
    put32(out, access);
    put32(out, attributes);
    put32(out, share);
    put32(out, disposition);
    put32(out, options);
    put16(out, (HEADER_LEN + 56) as! u16);
    put16(out, n.len as! u16);
    put32(out, 0);                     // no create contexts
    put32(out, 0);
    out.append(n);
    if n.len == 0 { out.push(0); }     // the buffer is never empty
    return true;
}

// What CREATE, CLOSE (with POSTQUERY_ATTRIB) and QUERY_INFO's network open
// information tell of a file. Times are FILETIMEs.
struct FileInfo {
    created:    u64,
    accessed:   u64,
    written:    u64,
    changed:    u64,
    alloc:      u64,
    size:       u64,
    attributes: u32,
}

fn no_info() -> FileInfo { FileInfo { created: 0, accessed: 0, written: 0, changed: 0, alloc: 0, size: 0, attributes: 0 } }

fn is_dir(i: const FileInfo&) -> bool { i.attributes & ATTR_DIRECTORY != 0 }

fn read_times(m: const u8[:], at: i64) -> FileInfo {
    var i = no_info();
    i.created = get64(m, at);
    i.accessed = get64(m, at + 8);
    i.written = get64(m, at + 16);
    i.changed = get64(m, at + 24);
    i.alloc = get64(m, at + 32);
    i.size = get64(m, at + 40);
    i.attributes = get32(m, at + 48);
    return i;
}

// CreateAction, the file's information, and its FileId.
fn parse_create_response(m: const u8[:]) -> u32, FileInfo, u8[16], bool {
    var id: u8[16] = [0; 16];
    if !body_is(m, 89) { return 0, no_info(), id, false; }
    let action = get32(m, HEADER_LEN + 4);
    let info = read_times(m, HEADER_LEN + 8);
    for i in 16 { id[i] = m[HEADER_LEN + 64 + i]; }
    return action, info, id, true;
}

let CLOSE_POSTQUERY_ATTRIB: u16 = 1;

fn close_request(out: u8[>..]&, id: const u8[:], flags: u16) {
    put16(out, 24);
    put16(out, flags);
    put32(out, 0);
    out.append(id);
}

fn parse_close_response(m: const u8[:]) -> FileInfo, bool {
    if !body_is(m, 60) { return no_info(), false; }
    return read_times(m, HEADER_LEN + 8), true;
}

fn flush_request(out: u8[>..]&, id: const u8[:]) {
    put16(out, 24);
    put16(out, 0);
    put32(out, 0);
    out.append(id);
}

// --- READ, WRITE (§2.2.19 - §2.2.22) ------------------------------------------------------------------

fn read_request(out: u8[>..]&, id: const u8[:], offset: u64, length: u32, minimum: u32) {
    put16(out, 49);
    out.push(0x50);                    // Padding: the data right after the response's fixed part
    out.push(0);
    put32(out, length);
    put64(out, offset);
    out.append(id);
    put32(out, minimum);
    put32(out, 0);                     // Channel
    put32(out, 0);                     // RemainingBytes
    put16(out, 0);
    put16(out, 0);
    out.push(0);                       // the one-byte buffer
}

// The data of a READ response.
fn parse_read_response(m: const u8[:]) -> Span, bool {
    if !body_is(m, 17) { return no_span(), false; }
    return read_span(m, m[HEADER_LEN + 2], get32(m, HEADER_LEN + 4), HEADER_LEN + 16);
}

fn write_request(out: u8[>..]&, id: const u8[:], offset: u64, data: const u8[:]) {
    put16(out, 49);
    put16(out, (HEADER_LEN + 48) as! u16);
    put32(out, data.len as! u32);
    put64(out, offset);
    out.append(id);
    put32(out, 0);                     // Channel
    put32(out, 0);                     // RemainingBytes
    put16(out, 0);
    put16(out, 0);
    put32(out, 0);                     // Flags
    out.append(data);
}

fn parse_write_response(m: const u8[:]) -> u32, bool {
    if !body_is(m, 17) { return 0, false; }
    return get32(m, HEADER_LEN + 4), true;
}

// --- QUERY_DIRECTORY (§2.2.33, §2.2.34) ---------------------------------------------------------------

fn query_directory_request(out: u8[>..]&, id: const u8[:], class: u8, flags: u8, pattern: const u8[:], out_len: u32) -> bool {
    var p: u8[>..] = [];
    if !utf16(p, pattern) || p.len > 0xffff { return false; }
    put16(out, 33);
    out.push(class);
    out.push(flags);
    put32(out, 0);                     // FileIndex
    out.append(id);
    put16(out, (HEADER_LEN + 32) as! u16);
    put16(out, p.len as! u16);
    put32(out, out_len);
    out.append(p);
    if p.len == 0 { out.push(0); }
    return true;
}

// QUERY_DIRECTORY, QUERY_INFO: the output buffer.
fn parse_output_response(m: const u8[:]) -> Span, bool {
    if !body_is(m, 9) { return no_span(), false; }
    return read_span(m, get16(m, HEADER_LEN + 2), get32(m, HEADER_LEN + 4), HEADER_LEN + 8);
}

// One entry of FileDirectoryInformation ([MS-FSCC] §2.4.10).
struct DirEntry {
    info: FileInfo,
    name: u8[..1024],          // UTF-8
}

// The entries of a FileDirectoryInformation buffer, appended to out;
// false if an entry's offsets or name do not fit, or a name is not UTF-16.
fn parse_directory(b: const u8[:], out: DirEntry[>..]&) -> bool {
    var at = 0;
    while at < b.len {
        if b.len - at < 64 { return false; }
        let next: i64 = get32(b, at);
        let name_len: i64 = get32(b, at + 60);
        if name_len > b.len - at - 64 || (next != 0 && (next < 64 + name_len || next >= b.len - at || next % 8 != 0)) { return false; }
        var e = DirEntry { info: no_info(), name: [] };
        e.info.created = get64(b, at + 8);
        e.info.accessed = get64(b, at + 16);
        e.info.written = get64(b, at + 24);
        e.info.changed = get64(b, at + 32);
        e.info.size = get64(b, at + 40);
        e.info.alloc = get64(b, at + 48);
        e.info.attributes = get32(b, at + 56);
        var n: u8[>..] = [];
        if !utf8(n, b[at + 64..at + 64 + name_len]) || n.len > e.name.cap { return false; }
        e.name.append(n);
        out.push(e);
        if next == 0 { break; }
        at += next;
    }
    return true;
}

// --- QUERY_INFO, SET_INFO (§2.2.37 - §2.2.40) -----------------------------------------------------------

fn query_info_request(out: u8[>..]&, id: const u8[:], info_type: u8, class: u8, out_len: u32, additional: u32) {
    put16(out, 41);
    out.push(info_type);
    out.push(class);
    put32(out, out_len);
    put16(out, 0);                     // InputBufferOffset
    put16(out, 0);
    put32(out, 0);                     // InputBufferLength
    put32(out, additional);
    put32(out, 0);                     // Flags
    out.append(id);
    out.push(0);
}

// FileNetworkOpenInformation ([MS-FSCC] §2.4.29): 56 bytes.
fn parse_network_open(b: const u8[:]) -> FileInfo, bool {
    if b.len < 56 { return no_info(), false; }
    var i = no_info();
    i.created = get64(b, 0);
    i.accessed = get64(b, 8);
    i.written = get64(b, 16);
    i.changed = get64(b, 24);
    i.alloc = get64(b, 32);
    i.size = get64(b, 40);
    i.attributes = get32(b, 48);
    return i, true;
}

// The space of a share: FileFsFullSizeInformation ([MS-FSCC] §2.5.4).
struct FsSize { total_units: u64, caller_free_units: u64, free_units: u64, sectors_per_unit: u32, bytes_per_sector: u32 }

fn parse_fs_full_size(b: const u8[:]) -> FsSize, bool {
    var s = FsSize { total_units: 0, caller_free_units: 0, free_units: 0, sectors_per_unit: 0, bytes_per_sector: 0 };
    if b.len < 32 { return s, false; }
    s.total_units = get64(b, 0);
    s.caller_free_units = get64(b, 8);
    s.free_units = get64(b, 16);
    s.sectors_per_unit = get32(b, 24);
    s.bytes_per_sector = get32(b, 28);
    return s, true;
}

fn set_info_request(out: u8[>..]&, id: const u8[:], info_type: u8, class: u8, buf: const u8[:]) {
    put16(out, 33);
    out.push(info_type);
    out.push(class);
    put32(out, buf.len as! u32);
    put16(out, (HEADER_LEN + 32) as! u16);
    put16(out, 0);
    put32(out, 0);                     // AdditionalInformation
    out.append(id);
    out.append(buf);
}

// FileBasicInformation: the times (0: unchanged) and attributes (0: unchanged).
fn basic_info(out: u8[>..]&, created: u64, accessed: u64, written: u64, changed: u64, attributes: u32) {
    put64(out, created);
    put64(out, accessed);
    put64(out, written);
    put64(out, changed);
    put32(out, attributes);
    put32(out, 0);
}

// FileRenameInformation for SMB2 (§2.2.39: RootDirectory 8 bytes).
fn rename_info(out: u8[>..]&, new_name: const u8[:], replace: bool) -> bool {
    var n: u8[>..] = [];
    if !utf16(n, new_name) { return false; }
    out.push(if replace { 1 } else { 0 });
    for i in 7 { out.push(0); }
    put64(out, 0);
    put32(out, n.len as! u32);
    out.append(n);
    while out.len < 24 { out.push(0); }
    return true;
}

// --- IOCTL (§2.2.31, §2.2.32) ---------------------------------------------------------------------------

fn ioctl_request(out: u8[>..]&, ctl: u32, id: const u8[:], input: const u8[:], max_output: u32) {
    put16(out, 57);
    put16(out, 0);
    put32(out, ctl);
    out.append(id);
    put32(out, (HEADER_LEN + 56) as! u32);
    put32(out, input.len as! u32);
    put32(out, 0);                     // MaxInputResponse
    put32(out, 0);                     // OutputOffset
    put32(out, 0);                     // OutputCount
    put32(out, max_output);
    put32(out, IOCTL_IS_FSCTL);
    put32(out, 0);
    out.append(input);
}

// The control code and output of an IOCTL response.
fn parse_ioctl_response(m: const u8[:]) -> u32, Span, bool {
    if !body_is(m, 49) { return 0, no_span(), false; }
    let ctl = get32(m, HEADER_LEN + 4);
    let out, ok = read_span(m, get32(m, HEADER_LEN + 32), get32(m, HEADER_LEN + 36), HEADER_LEN + 48);
    return ctl, out, ok;
}

// The FileId of an IOCTL that names no file.
fn no_file_id() -> u8[16] { [0xff; 16] }
