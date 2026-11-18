// smb: an SMB2 and SMB3 client for the Goose language ([MS-SMB2]), as
// Windows and Samba speak it: dialects 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1
// over direct TCP (port 445); NEGOTIATE with 3.1.1's negotiate contexts
// (pre-authentication integrity with SHA-512, the ciphers, the signing
// algorithms) and 3.0's validate-negotiate; SESSION_SETUP through SPNEGO
// with NTLMv2 (gslib's ntlm) or Kerberos (gslib's krb5); signing with
// HMAC-SHA256 (2.x), AES-128-CMAC (3.x) and AES-128-GMAC (3.1.1), keys
// from SP 800-108's KDF; encryption, the TRANSFORM_HEADER, with
// AES-128-CCM, AES-128-GCM, AES-256-CCM and AES-256-GCM; then shares,
// files and directories: TREE_CONNECT, CREATE, READ and WRITE (several
// credits per request for large ones), QUERY_DIRECTORY, QUERY_INFO and
// SET_INFO (times and attributes, size, rename, delete), FLUSH, CLOSE,
// ECHO, LOGOFF.
//
//   smb                 this module: commands, status codes, flags, the
//                       SMB2 header, little-endian and UTF-16 helpers
//   smb.crypto          the KDF, the session's keys, signing, the
//                       transform (encryption) and the preauth hash
//   smb.messages        each request built, each response read
//   smb.client          a connection: negotiate, login, trees, files
//
// All are in the namespace smb. A connection carries one session; its
// trees and open files are values the calls take back.
//
//   var c, e = smb::dial("fs.example.test", 445, smb::options());
//   e = smb::login_ntlm(c, "alice", "EXAMPLE", "password");
//   var t, te = smb::tree_connect(c, "\\\\fs.example.test\\share");
//   var data, re = smb::read_file(c, t, "dir\\notes.txt");
//   smb::write_file(c, t, "dir\\copy.txt", data);
//   smb::logoff(c); smb::hangup(c);
//
// Signing and encryption follow the server and the options: a server
// that requires signing gets it, one that requires encryption (for the
// session or a share) gets it, and options() asks for both to be checked
// on 3.x. Nothing is accepted that should have been signed or encrypted
// and was not.

namespace smb;

import std;
import ntlm;

// --- Errors ---------------------------------------------------------------------------

let OK:              i64 = 0;
let ERR_ARG:         i64 = 1;    // an argument that cannot be used (a name too long, a bad path)
let ERR_NETWORK:     i64 = 2;    // the connection failed or closed
let ERR_TIMEOUT:     i64 = 3;    // no answer in time
let ERR_MALFORMED:   i64 = 4;    // a response whose sizes or offsets do not add up
let ERR_STATUS:      i64 = 5;    // the server said no: the NT status is in Conn.status
let ERR_SIGNATURE:   i64 = 6;    // a response not signed, or not signed right, where it must be
let ERR_DECRYPT:     i64 = 7;    // an encrypted response that does not decrypt, or a plain one where encryption is on
let ERR_DIALECT:     i64 = 8;    // no dialect in common, or a negotiation that was tampered with
let ERR_AUTH:        i64 = 9;    // the login failed (NTLM, Kerberos, SPNEGO)
let ERR_UNSUPPORTED: i64 = 10;   // something the server cannot do that was required (encryption, signing)
let ERR_STATE:       i64 = 11;   // out of order: no session, no tree
let ERR_CREDITS:     i64 = 12;   // the server granted no credits to go on with

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "bad argument"; }
    if e == ERR_NETWORK { return "network error"; }
    if e == ERR_TIMEOUT { return "no response"; }
    if e == ERR_MALFORMED { return "malformed response"; }
    if e == ERR_STATUS { return "server error"; }
    if e == ERR_SIGNATURE { return "bad or missing signature"; }
    if e == ERR_DECRYPT { return "bad or missing encryption"; }
    if e == ERR_DIALECT { return "dialect negotiation failed"; }
    if e == ERR_AUTH { return "authentication failed"; }
    if e == ERR_UNSUPPORTED { return "not supported by the server"; }
    if e == ERR_STATE { return "out of order"; }
    if e == ERR_CREDITS { return "out of credits"; }
    return "unknown error";
}

// --- Commands (§2.2.1.2) --------------------------------------------------------------------

let NEGOTIATE:       u16 = 0;
let SESSION_SETUP:   u16 = 1;
let LOGOFF:          u16 = 2;
let TREE_CONNECT:    u16 = 3;
let TREE_DISCONNECT: u16 = 4;
let CREATE:          u16 = 5;
let CLOSE:           u16 = 6;
let FLUSH:           u16 = 7;
let READ:            u16 = 8;
let WRITE:           u16 = 9;
let LOCK:            u16 = 10;
let IOCTL:           u16 = 11;
let CANCEL:          u16 = 12;
let ECHO:            u16 = 13;
let QUERY_DIRECTORY: u16 = 14;
let CHANGE_NOTIFY:   u16 = 15;
let QUERY_INFO:      u16 = 16;
let SET_INFO:        u16 = 17;
let OPLOCK_BREAK:    u16 = 18;

fn command_name(c: u16) -> const u8[:] {
    if c == NEGOTIATE { return "NEGOTIATE"; }
    if c == SESSION_SETUP { return "SESSION_SETUP"; }
    if c == LOGOFF { return "LOGOFF"; }
    if c == TREE_CONNECT { return "TREE_CONNECT"; }
    if c == TREE_DISCONNECT { return "TREE_DISCONNECT"; }
    if c == CREATE { return "CREATE"; }
    if c == CLOSE { return "CLOSE"; }
    if c == FLUSH { return "FLUSH"; }
    if c == READ { return "READ"; }
    if c == WRITE { return "WRITE"; }
    if c == LOCK { return "LOCK"; }
    if c == IOCTL { return "IOCTL"; }
    if c == CANCEL { return "CANCEL"; }
    if c == ECHO { return "ECHO"; }
    if c == QUERY_DIRECTORY { return "QUERY_DIRECTORY"; }
    if c == CHANGE_NOTIFY { return "CHANGE_NOTIFY"; }
    if c == QUERY_INFO { return "QUERY_INFO"; }
    if c == SET_INFO { return "SET_INFO"; }
    if c == OPLOCK_BREAK { return "OPLOCK_BREAK"; }
    return "unknown";
}

// --- Dialects ----------------------------------------------------------------------------------

let SMB202: u16 = 0x0202;
let SMB21:  u16 = 0x0210;
let SMB30:  u16 = 0x0300;
let SMB302: u16 = 0x0302;
let SMB311: u16 = 0x0311;

fn dialect_name(d: u16) -> const u8[:] {
    if d == SMB202 { return "2.0.2"; }
    if d == SMB21 { return "2.1"; }
    if d == SMB30 { return "3.0"; }
    if d == SMB302 { return "3.0.2"; }
    if d == SMB311 { return "3.1.1"; }
    return "unknown";
}

// "2.0.2", "2.1", "3.0", "3.0.2", "3.1.1" (also "202", "210", "300", "302", "311").
fn parse_dialect(s: const u8[:]) -> u16, bool {
    if s == "2.0.2" || s == "202" { return SMB202, true; }
    if s == "2.1" || s == "210" { return SMB21, true; }
    if s == "3.0" || s == "300" { return SMB30, true; }
    if s == "3.0.2" || s == "302" { return SMB302, true; }
    if s == "3.1.1" || s == "311" { return SMB311, true; }
    return 0, false;
}

// --- Header (§2.2.1) ---------------------------------------------------------------------------

let HEADER_LEN: i64 = 64;

let FLAGS_SERVER_TO_REDIR:    u32 = 0x00000001;
let FLAGS_ASYNC_COMMAND:      u32 = 0x00000002;
let FLAGS_RELATED_OPERATIONS: u32 = 0x00000004;
let FLAGS_SIGNED:             u32 = 0x00000008;
let FLAGS_DFS_OPERATIONS:     u32 = 0x10000000;

// The MessageId of an unsolicited message (an oplock or lease break).
let UNSOLICITED_ID: u64 = 0xffffffffffffffff;

struct Header {
    credit_charge: u16,
    status:        u32,          // requests: ChannelSequence and Reserved
    command:       u16,
    credits:       u16,          // requested, or granted
    flags:         u32,
    next_command:  u32,
    message_id:    u64,
    async_id:      u64,          // FLAGS_ASYNC_COMMAND: in place of Reserved and TreeId
    tree_id:       u32,
    session_id:    u64,
    signature:     u8[16],
}

fn header(command: u16) -> Header {
    return Header { credit_charge: 0, status: 0, command: command, credits: 0, flags: 0, next_command: 0, message_id: 0,
                    async_id: 0, tree_id: 0, session_id: 0, signature: [0; 16] };
}

fn put_header(out: u8[>..]&, h: const Header&) {
    out.push(0xfe); out.push('S'); out.push('M'); out.push('B');
    put16(out, 64);
    put16(out, h.credit_charge);
    put32(out, h.status);
    put16(out, h.command);
    put16(out, h.credits);
    put32(out, h.flags);
    put32(out, h.next_command);
    put64(out, h.message_id);
    if h.flags & FLAGS_ASYNC_COMMAND != 0 {
        put64(out, h.async_id);
    } else {
        put32(out, 0);
        put32(out, h.tree_id);
    }
    put64(out, h.session_id);
    out.append(h.signature);
}

fn is_smb2(m: const u8[:]) -> bool { m.len >= HEADER_LEN && m[0] == 0xfe && m[1] == 'S' && m[2] == 'M' && m[3] == 'B' }

fn parse_header(m: const u8[:]) -> Header, bool {
    var h = header(0);
    if !is_smb2(m) || get16(m, 4) != 64 { return h, false; }
    h.credit_charge = get16(m, 6);
    h.status = get32(m, 8);
    h.command = get16(m, 12);
    h.credits = get16(m, 14);
    h.flags = get32(m, 16);
    h.next_command = get32(m, 20);
    h.message_id = get64(m, 24);
    if h.flags & FLAGS_ASYNC_COMMAND != 0 {
        h.async_id = get64(m, 32);
    } else {
        h.tree_id = get32(m, 36);
    }
    h.session_id = get64(m, 40);
    for i in 16 { h.signature[i] = m[48 + i]; }
    return h, true;
}

// --- NT status codes ([MS-ERREF] §2.3) -----------------------------------------------------------

let STATUS_SUCCESS:                  u32 = 0x00000000;
let STATUS_PENDING:                  u32 = 0x00000103;
let STATUS_NOTIFY_ENUM_DIR:          u32 = 0x0000010c;
let STATUS_BUFFER_OVERFLOW:          u32 = 0x80000005;
let STATUS_NO_MORE_FILES:            u32 = 0x80000006;
let STATUS_INVALID_PARAMETER:        u32 = 0xc000000d;
let STATUS_NO_SUCH_FILE:             u32 = 0xc000000f;
let STATUS_END_OF_FILE:              u32 = 0xc0000011;
let STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xc0000016;
let STATUS_ACCESS_DENIED:            u32 = 0xc0000022;
let STATUS_BUFFER_TOO_SMALL:         u32 = 0xc0000023;
let STATUS_OBJECT_NAME_INVALID:      u32 = 0xc0000033;
let STATUS_OBJECT_NAME_NOT_FOUND:    u32 = 0xc0000034;
let STATUS_OBJECT_NAME_COLLISION:    u32 = 0xc0000035;
let STATUS_OBJECT_PATH_NOT_FOUND:    u32 = 0xc000003a;
let STATUS_SHARING_VIOLATION:        u32 = 0xc0000043;
let STATUS_DELETE_PENDING:           u32 = 0xc0000056;
let STATUS_PRIVILEGE_NOT_HELD:       u32 = 0xc0000061;
let STATUS_LOGON_FAILURE:            u32 = 0xc000006d;
let STATUS_ACCOUNT_RESTRICTION:      u32 = 0xc000006e;
let STATUS_PASSWORD_EXPIRED:         u32 = 0xc0000071;
let STATUS_ACCOUNT_DISABLED:         u32 = 0xc0000072;
let STATUS_DISK_FULL:                u32 = 0xc000007f;
let STATUS_INSUFFICIENT_RESOURCES:   u32 = 0xc000009a;
let STATUS_FILE_IS_A_DIRECTORY:      u32 = 0xc00000ba;
let STATUS_NOT_SUPPORTED:            u32 = 0xc00000bb;
let STATUS_NETWORK_NAME_DELETED:     u32 = 0xc00000c9;
let STATUS_BAD_NETWORK_NAME:         u32 = 0xc00000cc;
let STATUS_REQUEST_NOT_ACCEPTED:     u32 = 0xc00000d0;
let STATUS_DIRECTORY_NOT_EMPTY:      u32 = 0xc0000101;
let STATUS_NOT_A_DIRECTORY:          u32 = 0xc0000103;
let STATUS_CANCELLED:                u32 = 0xc0000120;
let STATUS_CANNOT_DELETE:            u32 = 0xc0000121;
let STATUS_FILE_CLOSED:              u32 = 0xc0000128;
let STATUS_USER_SESSION_DELETED:     u32 = 0xc0000203;
let STATUS_NOT_FOUND:                u32 = 0xc0000225;
let STATUS_NETWORK_SESSION_EXPIRED:  u32 = 0xc000035c;

fn status_name(s: u32) -> const u8[:] {
    if s == STATUS_SUCCESS { return "STATUS_SUCCESS"; }
    if s == STATUS_PENDING { return "STATUS_PENDING"; }
    if s == STATUS_NOTIFY_ENUM_DIR { return "STATUS_NOTIFY_ENUM_DIR"; }
    if s == STATUS_BUFFER_OVERFLOW { return "STATUS_BUFFER_OVERFLOW"; }
    if s == STATUS_NO_MORE_FILES { return "STATUS_NO_MORE_FILES"; }
    if s == STATUS_INVALID_PARAMETER { return "STATUS_INVALID_PARAMETER"; }
    if s == STATUS_NO_SUCH_FILE { return "STATUS_NO_SUCH_FILE"; }
    if s == STATUS_END_OF_FILE { return "STATUS_END_OF_FILE"; }
    if s == STATUS_MORE_PROCESSING_REQUIRED { return "STATUS_MORE_PROCESSING_REQUIRED"; }
    if s == STATUS_ACCESS_DENIED { return "STATUS_ACCESS_DENIED"; }
    if s == STATUS_BUFFER_TOO_SMALL { return "STATUS_BUFFER_TOO_SMALL"; }
    if s == STATUS_OBJECT_NAME_INVALID { return "STATUS_OBJECT_NAME_INVALID"; }
    if s == STATUS_OBJECT_NAME_NOT_FOUND { return "STATUS_OBJECT_NAME_NOT_FOUND"; }
    if s == STATUS_OBJECT_NAME_COLLISION { return "STATUS_OBJECT_NAME_COLLISION"; }
    if s == STATUS_OBJECT_PATH_NOT_FOUND { return "STATUS_OBJECT_PATH_NOT_FOUND"; }
    if s == STATUS_SHARING_VIOLATION { return "STATUS_SHARING_VIOLATION"; }
    if s == STATUS_DELETE_PENDING { return "STATUS_DELETE_PENDING"; }
    if s == STATUS_PRIVILEGE_NOT_HELD { return "STATUS_PRIVILEGE_NOT_HELD"; }
    if s == STATUS_LOGON_FAILURE { return "STATUS_LOGON_FAILURE"; }
    if s == STATUS_ACCOUNT_RESTRICTION { return "STATUS_ACCOUNT_RESTRICTION"; }
    if s == STATUS_PASSWORD_EXPIRED { return "STATUS_PASSWORD_EXPIRED"; }
    if s == STATUS_ACCOUNT_DISABLED { return "STATUS_ACCOUNT_DISABLED"; }
    if s == STATUS_DISK_FULL { return "STATUS_DISK_FULL"; }
    if s == STATUS_INSUFFICIENT_RESOURCES { return "STATUS_INSUFFICIENT_RESOURCES"; }
    if s == STATUS_FILE_IS_A_DIRECTORY { return "STATUS_FILE_IS_A_DIRECTORY"; }
    if s == STATUS_NOT_SUPPORTED { return "STATUS_NOT_SUPPORTED"; }
    if s == STATUS_NETWORK_NAME_DELETED { return "STATUS_NETWORK_NAME_DELETED"; }
    if s == STATUS_BAD_NETWORK_NAME { return "STATUS_BAD_NETWORK_NAME"; }
    if s == STATUS_REQUEST_NOT_ACCEPTED { return "STATUS_REQUEST_NOT_ACCEPTED"; }
    if s == STATUS_DIRECTORY_NOT_EMPTY { return "STATUS_DIRECTORY_NOT_EMPTY"; }
    if s == STATUS_NOT_A_DIRECTORY { return "STATUS_NOT_A_DIRECTORY"; }
    if s == STATUS_CANCELLED { return "STATUS_CANCELLED"; }
    if s == STATUS_CANNOT_DELETE { return "STATUS_CANNOT_DELETE"; }
    if s == STATUS_FILE_CLOSED { return "STATUS_FILE_CLOSED"; }
    if s == STATUS_USER_SESSION_DELETED { return "STATUS_USER_SESSION_DELETED"; }
    if s == STATUS_NOT_FOUND { return "STATUS_NOT_FOUND"; }
    if s == STATUS_NETWORK_SESSION_EXPIRED { return "STATUS_NETWORK_SESSION_EXPIRED"; }
    return "STATUS_UNKNOWN";
}

// --- Negotiation (§2.2.3, §2.2.4) ---------------------------------------------------------------

let SIGNING_ENABLED:  u16 = 0x0001;
let SIGNING_REQUIRED: u16 = 0x0002;

let CAP_DFS:                u32 = 0x00000001;
let CAP_LEASING:            u32 = 0x00000002;
let CAP_LARGE_MTU:          u32 = 0x00000004;
let CAP_MULTI_CHANNEL:      u32 = 0x00000008;
let CAP_PERSISTENT_HANDLES: u32 = 0x00000010;
let CAP_DIRECTORY_LEASING:  u32 = 0x00000020;
let CAP_ENCRYPTION:         u32 = 0x00000040;

let PREAUTH_INTEGRITY_CAPABILITIES: u16 = 1;
let ENCRYPTION_CAPABILITIES:        u16 = 2;
let COMPRESSION_CAPABILITIES:       u16 = 3;
let NETNAME_NEGOTIATE_CONTEXT_ID:   u16 = 5;
let TRANSPORT_CAPABILITIES:         u16 = 6;
let RDMA_TRANSFORM_CAPABILITIES:    u16 = 7;
let SIGNING_CAPABILITIES:           u16 = 8;

let HASH_SHA512: u16 = 1;

// Ciphers: what a cipher id is, and its key size.
let AES128_CCM: u16 = 1;
let AES128_GCM: u16 = 2;
let AES256_CCM: u16 = 3;
let AES256_GCM: u16 = 4;

fn cipher_name(c: u16) -> const u8[:] {
    if c == AES128_CCM { return "AES-128-CCM"; }
    if c == AES128_GCM { return "AES-128-GCM"; }
    if c == AES256_CCM { return "AES-256-CCM"; }
    if c == AES256_GCM { return "AES-256-GCM"; }
    if c == 0 { return "none"; }
    return "unknown";
}

fn parse_cipher(s: const u8[:]) -> u16, bool {
    if s == "aes-128-ccm" || s == "AES-128-CCM" { return AES128_CCM, true; }
    if s == "aes-128-gcm" || s == "AES-128-GCM" { return AES128_GCM, true; }
    if s == "aes-256-ccm" || s == "AES-256-CCM" { return AES256_CCM, true; }
    if s == "aes-256-gcm" || s == "AES-256-GCM" { return AES256_GCM, true; }
    return 0, false;
}

fn cipher_key_len(c: u16) -> i64 { if c == AES256_CCM || c == AES256_GCM { 32 } else { 16 } }
fn cipher_is_gcm(c: u16) -> bool { c == AES128_GCM || c == AES256_GCM }

// Signing algorithms (3.1.1's SIGNING_CAPABILITIES).
let HMAC_SHA256: u16 = 0;
let AES_CMAC:    u16 = 1;
let AES_GMAC:    u16 = 2;

fn signing_name(a: u16) -> const u8[:] {
    if a == HMAC_SHA256 { return "HMAC-SHA256"; }
    if a == AES_CMAC { return "AES-128-CMAC"; }
    if a == AES_GMAC { return "AES-128-GMAC"; }
    return "unknown";
}

fn parse_signing(s: const u8[:]) -> u16, bool {
    if s == "hmac-sha256" || s == "HMAC-SHA256" { return HMAC_SHA256, true; }
    if s == "aes-cmac" || s == "AES-128-CMAC" || s == "aes-128-cmac" { return AES_CMAC, true; }
    if s == "aes-gmac" || s == "AES-128-GMAC" || s == "aes-128-gmac" { return AES_GMAC, true; }
    return 0, false;
}

// --- Sessions and trees (§2.2.6 - §2.2.10) --------------------------------------------------------

let SESSION_FLAG_IS_GUEST:     u16 = 0x0001;
let SESSION_FLAG_IS_NULL:      u16 = 0x0002;
let SESSION_FLAG_ENCRYPT_DATA: u16 = 0x0004;

let SHARE_TYPE_DISK:  u8 = 1;
let SHARE_TYPE_PIPE:  u8 = 2;
let SHARE_TYPE_PRINT: u8 = 3;

let SHAREFLAG_DFS:          u32 = 0x00000001;
let SHAREFLAG_ENCRYPT_DATA: u32 = 0x00008000;

// --- Files (§2.2.13, [MS-FSCC]) ---------------------------------------------------------------------

// Access masks.
let FILE_READ_DATA:         u32 = 0x00000001;
let FILE_LIST_DIRECTORY:    u32 = 0x00000001;
let FILE_WRITE_DATA:        u32 = 0x00000002;
let FILE_ADD_FILE:          u32 = 0x00000002;
let FILE_APPEND_DATA:       u32 = 0x00000004;
let FILE_ADD_SUBDIRECTORY:  u32 = 0x00000004;
let FILE_READ_EA:           u32 = 0x00000008;
let FILE_WRITE_EA:          u32 = 0x00000010;
let FILE_EXECUTE:           u32 = 0x00000020;
let FILE_TRAVERSE:          u32 = 0x00000020;
let FILE_DELETE_CHILD:      u32 = 0x00000040;
let FILE_READ_ATTRIBUTES:   u32 = 0x00000080;
let FILE_WRITE_ATTRIBUTES:  u32 = 0x00000100;
let DELETE:                 u32 = 0x00010000;
let READ_CONTROL:           u32 = 0x00020000;
let WRITE_DAC:              u32 = 0x00040000;
let WRITE_OWNER:            u32 = 0x00080000;
let SYNCHRONIZE:            u32 = 0x00100000;
let MAXIMUM_ALLOWED:        u32 = 0x02000000;
let GENERIC_ALL:            u32 = 0x10000000;
let GENERIC_EXECUTE:        u32 = 0x20000000;
let GENERIC_WRITE:          u32 = 0x40000000;
let GENERIC_READ:           u32 = 0x80000000;

let FILE_SHARE_READ:   u32 = 1;
let FILE_SHARE_WRITE:  u32 = 2;
let FILE_SHARE_DELETE: u32 = 4;
let FILE_SHARE_ALL:    u32 = 7;

// CreateDisposition.
let FILE_SUPERSEDE:    u32 = 0;
let FILE_OPEN:         u32 = 1;
let FILE_CREATE:       u32 = 2;
let FILE_OPEN_IF:      u32 = 3;
let FILE_OVERWRITE:    u32 = 4;
let FILE_OVERWRITE_IF: u32 = 5;

// CreateOptions.
let FILE_DIRECTORY_FILE:     u32 = 0x00000001;
let FILE_WRITE_THROUGH:      u32 = 0x00000002;
let FILE_SEQUENTIAL_ONLY:    u32 = 0x00000004;
let FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
let FILE_DELETE_ON_CLOSE:    u32 = 0x00001000;
let FILE_OPEN_REPARSE_POINT: u32 = 0x00200000;

// CreateAction.
let FILE_SUPERSEDED:  u32 = 0;
let FILE_OPENED:      u32 = 1;
let FILE_CREATED:     u32 = 2;
let FILE_OVERWRITTEN: u32 = 3;

// File attributes.
let ATTR_READONLY:  u32 = 0x00000001;
let ATTR_HIDDEN:    u32 = 0x00000002;
let ATTR_SYSTEM:    u32 = 0x00000004;
let ATTR_DIRECTORY: u32 = 0x00000010;
let ATTR_ARCHIVE:   u32 = 0x00000020;
let ATTR_NORMAL:    u32 = 0x00000080;

// QUERY_INFO and SET_INFO: InfoType, and the classes used here.
let INFO_FILE:       u8 = 1;
let INFO_FILESYSTEM: u8 = 2;
let INFO_SECURITY:   u8 = 3;

let FILE_DIRECTORY_INFORMATION:     u8 = 1;
let FILE_BASIC_INFORMATION:         u8 = 4;
let FILE_STANDARD_INFORMATION:      u8 = 5;
let FILE_RENAME_INFORMATION:        u8 = 10;
let FILE_DISPOSITION_INFORMATION:   u8 = 13;
let FILE_END_OF_FILE_INFORMATION:   u8 = 20;
let FILE_NETWORK_OPEN_INFORMATION:  u8 = 34;
let FILE_FS_SIZE_INFORMATION:       u8 = 3;
let FILE_FS_FULL_SIZE_INFORMATION:  u8 = 7;

// QUERY_DIRECTORY flags.
let RESTART_SCANS:       u8 = 0x01;
let RETURN_SINGLE_ENTRY: u8 = 0x02;
let INDEX_SPECIFIED:     u8 = 0x04;
let REOPEN:              u8 = 0x10;

// IOCTL.
let FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x00140204;
let IOCTL_IS_FSCTL:                u32 = 0x00000001;

// --- Little-endian ------------------------------------------------------------------------------

fn put16(out: u8[>..]&, v: u16) { out.push(v as! u8); out.push((v >> 8) as! u8); }
fn put32(out: u8[>..]&, v: u32) { for i in 4 { out.push((v >> (8 * i)) as! u8); } }
fn put64(out: u8[>..]&, v: u64) { for i in 8 { out.push((v >> (8 * i)) as! u8); } }

fn set16(b: u8[:], at: i64, v: u16) { b[at] = v as! u8; b[at + 1] = (v >> 8) as! u8; }
fn set32(b: u8[:], at: i64, v: u32) { for i in 4 { b[at + i] = (v >> (8 * i)) as! u8; } }

fn get16(b: const u8[:], at: i64) -> u16 {
    let lo: u16 = b[at];
    let hi: u16 = b[at + 1];
    return lo | hi << 8;
}

fn get32(b: const u8[:], at: i64) -> u32 {
    var v: u32 = 0;
    for i in 4 { v |= (b[at + i] as u32) << (8 * i); }
    return v;
}

fn get64(b: const u8[:], at: i64) -> u64 {
    var v: u64 = 0;
    for i in 8 { v |= (b[at + i] as u64) << (8 * i); }
    return v;
}

// Zero bytes up to a multiple of n (counted from the start of out).
fn pad_to(out: u8[>..]&, n: i64) { while out.len % n != 0 { out.push(0); } }

// --- Time ---------------------------------------------------------------------------------------------

// FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
let FILETIME_UNIX: u64 = 116444736000000000;

// Seconds since 1970 of a FILETIME (0: before 1970 or none).
fn unix_time(ft: u64) -> i64 {
    if ft <= FILETIME_UNIX { return 0; }
    return ((ft - FILETIME_UNIX) / 10000000) as! i64;
}

fn filetime_of(unix_secs: i64) -> u64 {
    if unix_secs <= 0 { return FILETIME_UNIX; }
    return FILETIME_UNIX + (unix_secs as u64) * 10000000;
}

// --- Names ---------------------------------------------------------------------------------------------

// UTF-8 to UTF-16LE; false for text that is not UTF-8.
fn utf16(out: u8[>..]&, s: const u8[:]) -> bool { ntlm::utf16le(out, s) }

// UTF-16LE to UTF-8; false for an odd length or unpaired surrogates.
fn utf8(out: u8[>..]&, b: const u8[:]) -> bool { ntlm::utf8_of_utf16le(out, b) }

// A path within a share as SMB wants it: backslashes, no leading one, no
// empty or "." parts ("" is the share's root). False for a path with a
// ".." part or a NUL.
fn share_path(p: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var part: u8[>..] = [];
    var i = 0;
    while i <= p.len {
        let end = i == p.len || p[i] == '/' || p[i] == '\\';
        if !end {
            if p[i] == 0 { return out, false; }
            part.push(p[i]);
        } else if part.len > 0 {
            if part == ".." { return out, false; }
            if part != "." {
                if out.len > 0 { out.push('\\'); }
                out.append(part);
            }
            part.clear();
        }
        i++;
    }
    return out, true;
}

// The server and share of "\\server\share" (or "//server/share"); false
// unless both are there and nothing follows.
fn split_unc(unc: const u8[:]) -> const u8[:], const u8[:], bool {
    if unc.len < 5 || (unc[0] != '\\' && unc[0] != '/') || (unc[1] != '\\' && unc[1] != '/') { return "", "", false; }
    var i = 2;
    while i < unc.len && unc[i] != '\\' && unc[i] != '/' { i++; }
    if i == 2 || i >= unc.len - 1 { return "", "", false; }
    let server = unc[2..i];
    let share = unc[i + 1..];
    for ch in share { if ch == '\\' || ch == '/' { return "", "", false; } }
    return server, share, true;
}

// --- Transport: direct TCP (§2.1) ---------------------------------------------------------------------

// The 4-byte header of a message over TCP: a zero byte and a 24-bit
// big-endian length.
fn put_transport(out: u8[>..]&, len: i64) {
    out.push(0);
    out.push(((len >> 16) & 0xff) as! u8);
    out.push(((len >> 8) & 0xff) as! u8);
    out.push((len & 0xff) as! u8);
}

fn transport_len(b: const u8[:]) -> i64, bool {
    if b.len < 4 || b[0] != 0 { return 0, false; }
    return ((b[1] as i64) << 16) | ((b[2] as i64) << 8) | b[3], true;
}
