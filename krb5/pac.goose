// krb5.pac: Microsoft's Privilege Attribute Certificate (MS-PAC), which an
// AD KDC (and MIT's since 1.20) puts in tickets inside AD-IF-RELEVANT as
// AD-WIN2K-PAC: the user's logon information (SIDs, groups, names),
// client info, UPN and DNS info, S4U delegation info, device info,
// attributes, requestor, and signatures.
//
// A service checks the server signature with its own key (pac_verify,
// which also checks the client info against the ticket); the KDC
// signature needs the krbtgt key, so only a KDC (or a test) checks it.
// Claims (types 13 and 15) are in krb5.claims.
//
// Times are FILETIMEs: 100 ns since 1601; filetime_to_unix converts.

namespace krb5;

import std;
import krb5.crypto;
import krb5.messages;
import krb5.ndr;
import krb5.service;

// Buffer types (MS-PAC §2.4).
let PAC_LOGON_INFO: u32 = 1;
let PAC_CREDENTIALS_INFO: u32 = 2;
let PAC_SERVER_CHECKSUM: u32 = 6;
let PAC_PRIVSVR_CHECKSUM: u32 = 7;
let PAC_CLIENT_INFO: u32 = 10;
let PAC_DELEGATION_INFO: u32 = 11;
let PAC_UPN_DNS_INFO: u32 = 12;
let PAC_CLIENT_CLAIMS_INFO: u32 = 13;
let PAC_DEVICE_INFO: u32 = 14;
let PAC_DEVICE_CLAIMS_INFO: u32 = 15;
let PAC_TICKET_CHECKSUM: u32 = 16;
let PAC_ATTRIBUTES_INFO: u32 = 17;
let PAC_REQUESTOR: u32 = 18;
let PAC_FULL_CHECKSUM: u32 = 19;

struct PacBuffer { ul_type: u32, size: u32, offset: u64 }
struct GroupMembership { rid: u32, attributes: u32 }
struct SidAttr { sid: u8[], attributes: u32 }

// KERB_VALIDATION_INFO (§2.5): names as UTF-8, SIDs as text.
struct LogonInfo {
    logon_time: u64,
    logoff_time: u64,
    kickoff_time: u64,
    password_last_set: u64,
    password_can_change: u64,
    password_must_change: u64,
    effective_name: u8[],
    full_name: u8[],
    logon_script: u8[],
    profile_path: u8[],
    home_directory: u8[],
    home_directory_drive: u8[],
    logon_count: u32,
    bad_password_count: u32,
    user_id: u32,
    primary_group_id: u32,
    group_ids: GroupMembership[],
    user_flags: u32,
    user_session_key: u8[],
    logon_server: u8[],
    logon_domain_name: u8[],
    logon_domain_id: u8[],
    user_account_control: u32,
    sub_auth_status: u32,
    last_successful_ilogon: u64,
    last_failed_ilogon: u64,
    failed_ilogon_count: u32,
    extra_sids: SidAttr[],
    resource_group_domain_sid: u8[],
    resource_group_ids: GroupMembership[],
}

struct ClientInfo { client_id: u64, name: u8[] }

// UPN_DNS_INFO (§2.10); the SAM name and SID when flags has 2 (the "S"
// extension, Windows 2016 and later).
struct UpnDnsInfo { upn: u8[], dns_domain: u8[], flags: u32, has_sam: bool, sam_name: u8[], sid: u8[] }

// PAC_SIGNATURE_DATA (§2.8); rodc_id when the KDC was a read-only one.
struct PacSignature { sig_type: i32, signature: u8[], has_rodc: bool, rodc_id: u32 }

// S4U_DELEGATION_INFO (§2.9).
struct S4uDelegationInfo { proxy_target: u8[], transited: u8[][] }

struct DomainGroup { domain_id: u8[], groups: GroupMembership[] }

// PAC_DEVICE_INFO (§2.12).
struct DeviceInfo {
    user_id: u32,
    primary_group_id: u32,
    account_domain_id: u8[],
    account_groups: GroupMembership[],
    extra_sids: SidAttr[],
    domain_groups: DomainGroup[],
}

struct Pac {
    version: u32,
    buffers: PacBuffer[],
    has_logon_info: bool,
    logon_info: LogonInfo,
    has_client_info: bool,
    client_info: ClientInfo,
    has_upn_dns_info: bool,
    upn_dns_info: UpnDnsInfo,
    has_server_sig: bool,
    server_sig: PacSignature,
    has_kdc_sig: bool,
    kdc_sig: PacSignature,
    has_ticket_sig: bool,
    ticket_sig: PacSignature,
    has_full_sig: bool,
    full_sig: PacSignature,
    has_delegation_info: bool,
    delegation_info: S4uDelegationInfo,
    has_device_info: bool,
    device_info: DeviceInfo,
    has_attributes: bool,
    attributes: u32,          // PAC_ATTRIBUTES_INFO's flags: 1 not requested, 2 given as asked
    has_requestor: bool,
    requestor: u8[],          // the requestor's SID
}

fn filetime_to_unix(ft: u64) -> i64 { (ft as! i64 - 116444736000000000) / 10000000 }
fn unix_to_filetime(t: i64) -> u64 { (t * 10000000 + 116444736000000000) as! u64 }

fn le16(b: const u8[:], at: i64) -> u32 {
    let lo: u32 = b[at];
    let hi: u32 = b[at + 1];
    return lo | hi << 8;
}
fn le32v(b: const u8[:], at: i64) -> u32 { le16(b, at) | le16(b, at + 2) << 16 }
fn le64v(b: const u8[:], at: i64) -> u64 {
    let lo: u64 = le32v(b, at);
    let hi: u64 = le32v(b, at + 4);
    return lo | hi << 32;
}

// --- NDR types ----------------------------------------------------------------------

fn ndr_groups(b: const u8[:], n: Ndr&, count: u32) -> GroupMembership[>..] {
    var out: GroupMembership[>..] = [];
    let max = ndr_u32(b, n);
    if max != count || max > 65536 { n.bad = true; return out; }
    for i in max {
        let rid = ndr_u32(b, n);
        let attr = ndr_u32(b, n);
        out.push(GroupMembership { rid: rid, attributes: attr });
    }
    return out;
}

// KERB_SID_AND_ATTRIBUTES[count]: the fixed parts, then each SID.
fn ndr_sid_attrs(b: const u8[:], n: Ndr&, count: u32) -> SidAttr[>..] {
    var out: SidAttr[>..] = [];
    let max = ndr_u32(b, n);
    if max != count || max > 65536 { n.bad = true; return out; }
    var ptrs: u32[>..] = [];
    var attrs: u32[>..] = [];
    for i in max {
        ptrs.push(ndr_u32(b, n));
        attrs.push(ndr_u32(b, n));
    }
    for i in max {
        var sid: u8[>..] = [];
        if ptrs[i] != 0 { sid = ndr_sid(b, n); }
        out.push(SidAttr { sid: copy(sid), attributes: attrs[i] });
    }
    return out;
}

fn empty_logon_info() -> LogonInfo {
    return LogonInfo {
        logon_time: 0, logoff_time: 0, kickoff_time: 0, password_last_set: 0, password_can_change: 0,
        password_must_change: 0, effective_name: "", full_name: "", logon_script: "", profile_path: "", home_directory: "",
        home_directory_drive: "", logon_count: 0, bad_password_count: 0, user_id: 0, primary_group_id: 0, group_ids: [],
        user_flags: 0, user_session_key: "", logon_server: "", logon_domain_name: "", logon_domain_id: "",
        user_account_control: 0, sub_auth_status: 0, last_successful_ilogon: 0, last_failed_ilogon: 0,
        failed_ilogon_count: 0, extra_sids: [], resource_group_domain_sid: "", resource_group_ids: [],
    };
}

// A deferred string, when its pointer was set.
fn deferred_string(b: const u8[:], n: Ndr&, has: bool, len: i64) -> u8[>..] {
    if has { return ndr_ustring_body(b, n, len); }
    var e: u8[>..] = [];
    return e;
}

fn decode_logon_info(b: const u8[:]) -> LogonInfo, i64 {
    var n = ndr_open(b);
    if n.bad { return empty_logon_info(), ERR_NDR; }
    let top = ndr_u32(b, n);
    if top == 0 { return empty_logon_info(), ERR_NDR; }
    let logon_time = ndr_filetime(b, n);
    let logoff_time = ndr_filetime(b, n);
    let kickoff_time = ndr_filetime(b, n);
    let pw_last = ndr_filetime(b, n);
    let pw_can = ndr_filetime(b, n);
    let pw_must = ndr_filetime(b, n);
    var lens: i64[8] = [0; 8];
    var has: bool[8] = [false; 8];
    for i in 6 {
        let l, h = ndr_ustring_head(b, n);
        lens[i] = l;
        has[i] = h;
    }
    let logon_count = ndr_u16(b, n);
    let bad_count = ndr_u16(b, n);
    let user_id = ndr_u32(b, n);
    let pgid = ndr_u32(b, n);
    let group_count = ndr_u32(b, n);
    let groups_ptr = ndr_u32(b, n);
    let user_flags = ndr_u32(b, n);
    let session_key = ndr_bytes(b, n, 16);
    let l6, h6 = ndr_ustring_head(b, n);
    let l7, h7 = ndr_ustring_head(b, n);
    lens[6] = l6;
    has[6] = h6;
    lens[7] = l7;
    has[7] = h7;
    let domain_id_ptr = ndr_u32(b, n);
    let r1 = ndr_u32(b, n);
    let r2 = ndr_u32(b, n);
    let uac = ndr_u32(b, n);
    let sub_auth = ndr_u32(b, n);
    let last_ok = ndr_filetime(b, n);
    let last_failed = ndr_filetime(b, n);
    let failed_count = ndr_u32(b, n);
    let r3 = ndr_u32(b, n);
    let sid_count = ndr_u32(b, n);
    let extra_ptr = ndr_u32(b, n);
    let res_dom_ptr = ndr_u32(b, n);
    let res_count = ndr_u32(b, n);
    let res_ptr = ndr_u32(b, n);
    // The deferred data, in the order of the pointers.
    let effective = deferred_string(b, n, has[0], lens[0]);
    let full = deferred_string(b, n, has[1], lens[1]);
    let script = deferred_string(b, n, has[2], lens[2]);
    let profile = deferred_string(b, n, has[3], lens[3]);
    let home = deferred_string(b, n, has[4], lens[4]);
    let drive = deferred_string(b, n, has[5], lens[5]);
    var groups: GroupMembership[>..] = [];
    if groups_ptr != 0 { groups = ndr_groups(b, n, group_count); } else if group_count != 0 { n.bad = true; }
    let server = deferred_string(b, n, has[6], lens[6]);
    let domain = deferred_string(b, n, has[7], lens[7]);
    var domain_id: u8[>..] = [];
    if domain_id_ptr != 0 { domain_id = ndr_sid(b, n); }
    var extra: SidAttr[>..] = [];
    if extra_ptr != 0 { extra = ndr_sid_attrs(b, n, sid_count); } else if sid_count != 0 { n.bad = true; }
    var res_dom: u8[>..] = [];
    if res_dom_ptr != 0 { res_dom = ndr_sid(b, n); }
    var res: GroupMembership[>..] = [];
    if res_ptr != 0 { res = ndr_groups(b, n, res_count); } else if res_count != 0 { n.bad = true; }
    let li = LogonInfo {
        logon_time: logon_time, logoff_time: logoff_time, kickoff_time: kickoff_time, password_last_set: pw_last,
        password_can_change: pw_can, password_must_change: pw_must, effective_name: copy(effective), full_name: copy(full),
        logon_script: copy(script), profile_path: copy(profile), home_directory: copy(home), home_directory_drive: copy(drive),
        logon_count: logon_count, bad_password_count: bad_count, user_id: user_id, primary_group_id: pgid,
        group_ids: copy(groups), user_flags: user_flags, user_session_key: copy(session_key), logon_server: copy(server),
        logon_domain_name: copy(domain), logon_domain_id: copy(domain_id), user_account_control: uac, sub_auth_status: sub_auth,
        last_successful_ilogon: last_ok, last_failed_ilogon: last_failed, failed_ilogon_count: failed_count,
        extra_sids: copy(extra), resource_group_domain_sid: copy(res_dom), resource_group_ids: copy(res),
    };
    return li, if n.bad { ERR_NDR } else { OK };
}

fn empty_device_info() -> DeviceInfo {
    return DeviceInfo { user_id: 0, primary_group_id: 0, account_domain_id: "", account_groups: [], extra_sids: [],
                        domain_groups: [] };
}

fn decode_device_info(b: const u8[:]) -> DeviceInfo, i64 {
    var n = ndr_open(b);
    if n.bad { return empty_device_info(), ERR_NDR; }
    let top = ndr_u32(b, n);
    if top == 0 { return empty_device_info(), ERR_NDR; }
    let user_id = ndr_u32(b, n);
    let pgid = ndr_u32(b, n);
    let dom_ptr = ndr_u32(b, n);
    let acct_count = ndr_u32(b, n);
    let acct_ptr = ndr_u32(b, n);
    let sid_count = ndr_u32(b, n);
    let sid_ptr = ndr_u32(b, n);
    let dg_count = ndr_u32(b, n);
    let dg_ptr = ndr_u32(b, n);
    var dom: u8[>..] = [];
    if dom_ptr != 0 { dom = ndr_sid(b, n); }
    var acct: GroupMembership[>..] = [];
    if acct_ptr != 0 { acct = ndr_groups(b, n, acct_count); }
    var sids: SidAttr[>..] = [];
    if sid_ptr != 0 { sids = ndr_sid_attrs(b, n, sid_count); }
    var dgs: DomainGroup[>..] = [];
    if dg_ptr != 0 {
        let max = ndr_u32(b, n);
        if max != dg_count || max > 4096 { n.bad = true; }
        var dptrs: u32[>..] = [];
        var counts: u32[>..] = [];
        var gptrs: u32[>..] = [];
        for i in (if n.bad { 0 } else { max }) {
            dptrs.push(ndr_u32(b, n));
            counts.push(ndr_u32(b, n));
            gptrs.push(ndr_u32(b, n));
        }
        for i in dptrs.len {
            var did: u8[>..] = [];
            if dptrs[i] != 0 { did = ndr_sid(b, n); }
            var gs: GroupMembership[>..] = [];
            if gptrs[i] != 0 { gs = ndr_groups(b, n, counts[i]); }
            dgs.push(DomainGroup { domain_id: copy(did), groups: copy(gs) });
        }
    }
    let d = DeviceInfo { user_id: user_id, primary_group_id: pgid, account_domain_id: copy(dom), account_groups: copy(acct),
                         extra_sids: copy(sids), domain_groups: copy(dgs) };
    return d, if n.bad { ERR_NDR } else { OK };
}

fn decode_delegation_info(b: const u8[:]) -> S4uDelegationInfo, i64 {
    var n = ndr_open(b);
    if n.bad { return S4uDelegationInfo { proxy_target: "", transited: [] }, ERR_NDR; }
    let top = ndr_u32(b, n);
    if top == 0 { return S4uDelegationInfo { proxy_target: "", transited: [] }, ERR_NDR; }
    let tl, th = ndr_ustring_head(b, n);
    let count = ndr_u32(b, n);
    let ptr = ndr_u32(b, n);
    let target = deferred_string(b, n, th, tl);
    var list: u8[][>..] = [];
    if ptr != 0 {
        let max = ndr_u32(b, n);
        if max != count || max > 4096 { n.bad = true; }
        var lens: i64[>..] = [];
        var hs: bool[>..] = [];
        for i in (if n.bad { 0 } else { max }) {
            let l, h = ndr_ustring_head(b, n);
            lens.push(l);
            hs.push(h);
        }
        for i in lens.len { list.push(deferred_string(b, n, hs[i], lens[i])); }
    }
    let d = S4uDelegationInfo { proxy_target: copy(target), transited: copy(list) };
    return d, if n.bad { ERR_NDR } else { OK };
}

// --- Plain buffers --------------------------------------------------------------------

fn decode_client_info(b: const u8[:]) -> ClientInfo, i64 {
    if b.len < 10 { return ClientInfo { client_id: 0, name: "" }, ERR_PAC; }
    let id = le64v(b, 0);
    let len = le16(b, 8) as i64;
    if 10 + len > b.len || len % 2 != 0 { return ClientInfo { client_id: id, name: "" }, ERR_PAC; }
    return ClientInfo { client_id: id, name: utf16_to_utf8(b[10..10 + len]) }, OK;
}

fn utf16_at(b: const u8[:], off: i64, len: i64, bad: bool&) -> u8[>..] {
    if off < 0 || len < 0 || off + len > b.len || len % 2 != 0 { bad = true; var e: u8[>..] = []; return e; }
    return utf16_to_utf8(b[off..off + len]);
}

fn decode_upn_dns_info(b: const u8[:]) -> UpnDnsInfo, i64 {
    var bad = b.len < 12;
    if bad { return UpnDnsInfo { upn: "", dns_domain: "", flags: 0, has_sam: false, sam_name: "", sid: "" }, ERR_PAC; }
    let flags = le32v(b, 8);
    let has_sam = flags & 2 != 0 && b.len >= 20;
    var sid: u8[>..] = [];
    if has_sam {
        let sl = le16(b, 16) as i64;
        let so = le16(b, 18) as i64;
        if so + sl > b.len { bad = true; }
        else {
            let s, ok = sid_from_bytes(b[so..so + sl]);
            if !ok { bad = true; }
            sid.append(s);
        }
    }
    let u = UpnDnsInfo {
        upn: utf16_at(b, le16(b, 2), le16(b, 0), bad), dns_domain: utf16_at(b, le16(b, 6), le16(b, 4), bad), flags: flags,
        has_sam: has_sam, sam_name: if has_sam { utf16_at(b, le16(b, 14), le16(b, 12), bad) } else { utf16_at(b, 0, 0, bad) },
        sid: copy(sid),
    };
    return u, if bad { ERR_PAC } else { OK };
}

fn no_signature() -> PacSignature { PacSignature { sig_type: 0, signature: "", has_rodc: false, rodc_id: 0 } }

fn decode_signature(b: const u8[:]) -> PacSignature, i64 {
    if b.len < 4 { return no_signature(), ERR_PAC; }
    let t = le32v(b, 0) as! i32;
    let n = cksum_len(t);
    if n == 0 || 4 + n > b.len { return no_signature(), ERR_PAC; }
    var sig: u8[>..] = [];
    sig.append(b[4..4 + n]);
    let rodc = b.len >= 4 + n + 2;
    return PacSignature { sig_type: t, signature: sig, has_rodc: rodc, rodc_id: if rodc { le16(b, 4 + n) } else { 0 } }, OK;
}

// --- The PAC --------------------------------------------------------------------------

// The bytes of the first buffer of a type, and whether there is one.
fn pac_buffer(b: const u8[:], bufs: const PacBuffer[:], t: u32) -> const u8[:], bool {
    for x in bufs {
        if x.ul_type == t {
            let off = x.offset as! i64;
            let end = off + x.size;
            return b[off..end], true;
        }
    }
    return b[0..0], false;
}

fn pac_buffers(b: const u8[:]) -> PacBuffer[>..], i64 {
    var out: PacBuffer[>..] = [];
    if b.len < 8 { return out, ERR_PAC; }
    let count = le32v(b, 0) as i64;
    let version = le32v(b, 4);
    if version != 0 || count < 1 || count > 1000 || 8 + 16 * count > b.len { return out, ERR_PAC; }
    for i in count {
        let p = 8 + 16 * i;
        let t = le32v(b, p);
        let size = le32v(b, p + 4);
        let off = le64v(b, p + 8);
        // Buffers lie after the header, 8-byte aligned (§2.3), inside the PAC.
        if off < (8 + 16 * count) as u64 || off % 8 != 0 || off > b.len as u64 || size > b.len as u64 - off {
            return out, ERR_PAC;
        }
        out.push(PacBuffer { ul_type: t, size: size, offset: off });
    }
    return out, OK;
}

fn sig_of(b: const u8[:], bufs: const PacBuffer[:], t: u32, bad: bool&) -> PacSignature {
    let raw, ok = pac_buffer(b, bufs, t);
    if !ok { return no_signature(); }
    let s, err = decode_signature(raw);
    if err != OK { bad = true; }
    return s;
}

fn decode_pac(b: const u8[:]) -> Pac, i64 {
    let bufs, err = pac_buffers(b);
    var bad = err != OK;
    var ndr_bad = false;
    let li_raw, has_li = pac_buffer(b, bufs, PAC_LOGON_INFO);
    let ci_raw, has_ci = pac_buffer(b, bufs, PAC_CLIENT_INFO);
    let up_raw, has_up = pac_buffer(b, bufs, PAC_UPN_DNS_INFO);
    let dl_raw, has_dl = pac_buffer(b, bufs, PAC_DELEGATION_INFO);
    let dv_raw, has_dv = pac_buffer(b, bufs, PAC_DEVICE_INFO);
    let at_raw, has_at = pac_buffer(b, bufs, PAC_ATTRIBUTES_INFO);
    let rq_raw, has_rq = pac_buffer(b, bufs, PAC_REQUESTOR);
    // Absent buffers decode as empty ones; their errors are not counted.
    let li, lerr0 = decode_logon_info(li_raw);
    let ci, cerr0 = decode_client_info(ci_raw);
    let up, uerr0 = decode_upn_dns_info(up_raw);
    let dl, derr0 = decode_delegation_info(dl_raw);
    let dv, verr0 = decode_device_info(dv_raw);
    let lerr = if has_li { lerr0 } else { OK };
    let cerr = if has_ci { cerr0 } else { OK };
    let uerr = if has_up { uerr0 } else { OK };
    let derr = if has_dl { derr0 } else { OK };
    let verr = if has_dv { verr0 } else { OK };
    if lerr != OK || derr != OK || verr != OK { ndr_bad = true; }
    if cerr != OK || uerr != OK { bad = true; }
    // PAC_ATTRIBUTES_INFO: FlagsLength (bits), Flags.
    var attrs: u32 = 0;
    if has_at { if at_raw.len < 8 { bad = true; } else { attrs = le32v(at_raw, 4); } }
    var req: u8[>..] = [];
    if has_rq {
        // PAC_REQUESTOR is an RPC_SID marshaled as plain bytes.
        let s, ok = sid_from_bytes(rq_raw);
        if !ok { bad = true; }
        req.append(s);
    }
    let p = Pac {
        version: 0, buffers: copy(bufs), has_logon_info: has_li, logon_info: copy(li), has_client_info: has_ci, client_info: copy(ci),
        has_upn_dns_info: has_up, upn_dns_info: copy(up),
        has_server_sig: pac_buffer_has(bufs, PAC_SERVER_CHECKSUM), server_sig: sig_of(b, bufs, PAC_SERVER_CHECKSUM, bad),
        has_kdc_sig: pac_buffer_has(bufs, PAC_PRIVSVR_CHECKSUM), kdc_sig: sig_of(b, bufs, PAC_PRIVSVR_CHECKSUM, bad),
        has_ticket_sig: pac_buffer_has(bufs, PAC_TICKET_CHECKSUM), ticket_sig: sig_of(b, bufs, PAC_TICKET_CHECKSUM, bad),
        has_full_sig: pac_buffer_has(bufs, PAC_FULL_CHECKSUM), full_sig: sig_of(b, bufs, PAC_FULL_CHECKSUM, bad),
        has_delegation_info: has_dl, delegation_info: copy(dl), has_device_info: has_dv, device_info: copy(dv),
        has_attributes: has_at, attributes: attrs, has_requestor: has_rq, requestor: copy(req),
    };
    return p, if bad { ERR_PAC } else if ndr_bad { ERR_NDR } else { OK };
}

fn pac_buffer_has(bufs: const PacBuffer[:], t: u32) -> bool {
    for x in bufs { if x.ul_type == t { return true; } }
    return false;
}

// The PAC with the signatures of the server and KDC checksums zeroed
// (§2.8.1), over which the server signature is made.
fn pac_zeroed(b: const u8[:], bufs: const PacBuffer[:]) -> u8[>..] {
    var z: u8[>..] = [];
    z.append(b);
    for x in bufs {
        if x.ul_type != PAC_SERVER_CHECKSUM && x.ul_type != PAC_PRIVSVR_CHECKSUM { continue; }
        let off = x.offset as! i64;
        if x.size < 4 { continue; }
        let n = cksum_len(le32v(b, off) as! i32);
        let size: i64 = x.size;
        for i in 4..(if 4 + n <= size { 4 + n } else { size }) { z[off + i] = 0; }
    }
    return z;
}

// Checks the server signature with the service's key (usage 17,
// KERB_NON_KERB_CKSUM_SALT): OK, ERR_PAC_SIGNATURE, or ERR_PAC when it
// has none.
fn pac_verify_server(b: const u8[:], p: const Pac&, key: Key) -> i64 {
    if !p.has_server_sig { return ERR_PAC; }
    let z = pac_zeroed(b, p.buffers);
    let err = verify_checksum(key, p.server_sig.sig_type, USAGE_KERB_NON_KERB_CKSUM_SALT, z, p.server_sig.signature);
    return if err == OK { OK } else { ERR_PAC_SIGNATURE };
}

// Checks the KDC signature (over the server signature) with the krbtgt
// key, as a KDC does.
fn pac_verify_kdc(p: const Pac&, krbtgt_key: Key) -> i64 {
    if !p.has_kdc_sig || !p.has_server_sig { return ERR_PAC; }
    let err = verify_checksum(krbtgt_key, p.kdc_sig.sig_type, USAGE_KERB_NON_KERB_CKSUM_SALT, p.server_sig.signature,
                              p.kdc_sig.signature);
    return if err == OK { OK } else { ERR_PAC_SIGNATURE };
}

// The PAC in a ticket's authorization data: AD-WIN2K-PAC, at the top or
// inside AD-IF-RELEVANT.
fn pac_from_authz(authz: const AuthData[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    for a in authz {
        if a.ad_type == AD_WIN2K_PAC { out.append(a.data); return out, true; }
        if a.ad_type == AD_IF_RELEVANT {
            let inner, err = decode_authdata(a.data);
            if err != OK { continue; }
            for x in inner {
                if x.ad_type == AD_WIN2K_PAC { out.append(x.data); return out, true; }
            }
        }
    }
    return out, false;
}

// A service's check of the PAC of a ticket it accepted (MS-KILE 3.4.5.3,
// MIT's krb5_pac_verify): the server signature with the service key, and
// the client info against the ticket's authtime and client name (the
// name's components joined, without the realm, or the principal with
// it, as MIT accepts). Returns the decoded PAC.
fn pac_verify(ctx: const ApContext&, service_key: Key) -> Pac, bool, i64 {
    let raw, found = pac_from_authz(ctx.authz);
    if !found {
        let e, err = decode_pac("");
        return e, false, OK;
    }
    let p, err = decode_pac(raw);
    if err != OK { return p, true, err; }
    let serr = pac_verify_server(raw, p, service_key);
    if serr != OK { return p, true, serr; }
    if !p.has_client_info { return p, true, ERR_PAC; }
    if p.client_info.client_id != unix_to_filetime(ctx.authtime) { return p, true, ERR_PAC; }
    var plain: u8[>..] = [];
    var first = true;
    for part in name_parts(ctx.client) {
        if !first { plain.push('/'); }
        plain.append(part);
        first = false;
    }
    var with_realm: u8[>..] = [];
    with_realm.append(plain);
    with_realm.push('@');
    with_realm.append(ctx.client_realm);
    if p.client_info.name != plain && p.client_info.name != with_realm { return p, true, ERR_PAC; }
    return p, true, OK;
}

fn sid_plus_rid(domain: const u8[:], rid: u32) -> u8[>..] {
    var s: u8[>..] = [];
    s.append(domain);
    s.push('-');
    format_int(s, rid, 10, 0, ' ');
    return s;
}

// The SIDs a logon info grants, as Windows builds a token from it: the
// user's, the primary group's and each group's (the domain SID and the
// RID), each extra SID, and the resource groups'.
fn logon_sids(li: const LogonInfo&) -> u8[][>..] {
    var out: u8[][>..] = [];
    if li.logon_domain_id.len == 0 { return out; }
    out.push(sid_plus_rid(li.logon_domain_id, li.user_id));
    out.push(sid_plus_rid(li.logon_domain_id, li.primary_group_id));
    for g in li.group_ids {
        if g.rid != li.primary_group_id { out.push(sid_plus_rid(li.logon_domain_id, g.rid)); }
    }
    for e in li.extra_sids { out.push(copy(e.sid)); }
    if li.resource_group_domain_sid.len > 0 {
        for g in li.resource_group_ids { out.push(sid_plus_rid(li.resource_group_domain_sid, g.rid)); }
    }
    return out;
}
