// sys: the operating system's own calls, as Go's golang.org/x/sys and
// os/user have them, on Windows, Linux and macOS: the host, this process
// and others, users and groups, and files by path and by descriptor, with
// the errors the system gives. The Windows registry, Windows' users,
// groups, sessions, services, software and shares, and Unix's signals,
// limits, sysctl and terminals are in sys's other modules.
//
//   import gslib.sys;          // from a program; `import sys;` inside gslib
//
//   fn main() {
//       print(sys::hostname(), " ", sys::uname().release, " ", sys::cpu_count(), " CPUs");
//       var st = sys::Stat { .. };
//       let e = sys::stat("/etc/hosts", st);
//       if e != 0 { print(sys::error_text(e)); } else { print(st.size, " bytes"); }
//   }
//
// Calls that can fail return 0 or more on success and a negative error
// otherwise: -errno on POSIX, the negated Win32 error on Windows, and
// sys::ENOTSUP for a call the platform does not have. error_text says
// one in words; is_not_exist, is_exist, is_permission and the others ask
// what kind it is on any platform, as Go's os.IsNotExist does.
//
// The C is sys's src/: posix.c and unix.c, win.c, winreg.c and winmgmt.c,
// and the prototypes and stubs that scripts/gen_ffi.py makes from
// src/api.def along with ffi.goose.

namespace sys;

import std;
import sys.ffi;

let PLATFORM_WINDOWS: i64 = 1;
let PLATFORM_LINUX:   i64 = 2;
let PLATFORM_MACOS:   i64 = 3;
let PLATFORM_OTHER:   i64 = 4;

// A call this platform does not have.
let ENOTSUP: i64 = -1000000;
let ENOMEM:  i64 = -1000001;

// File kinds: Stat.kind and DirEntry.kind.
let KIND_UNKNOWN: i64 = 0;
let KIND_FILE:    i64 = 1;
let KIND_DIR:     i64 = 2;
let KIND_SYMLINK: i64 = 3;
let KIND_OTHER:   i64 = 4;     // a device, FIFO or socket

// open's flags, the same on every platform.
let O_RDONLY: i64 = 0x0;
let O_WRONLY: i64 = 0x1;
let O_RDWR:   i64 = 0x2;
let O_APPEND: i64 = 0x8;
let O_CREATE: i64 = 0x40;
let O_EXCL:   i64 = 0x80;
let O_TRUNC:  i64 = 0x200;
let O_SYNC:   i64 = 0x1000;

// seek's whence.
let SEEK_SET: i32 = 0;
let SEEK_CUR: i32 = 1;
let SEEK_END: i32 = 2;

// lock's how: LOCK_SHARED or LOCK_EXCLUSIVE, with LOCK_NONBLOCK added to
// fail rather than wait; LOCK_UNLOCK.
let LOCK_SHARED:    i32 = 1;
let LOCK_EXCLUSIVE: i32 = 2;
let LOCK_UNLOCK:    i32 = 3;
let LOCK_NONBLOCK:  i32 = 4;

// Signals for kill, as POSIX numbers them; on Windows any but 0 ends the
// process (TerminateProcess), and 0 asks whether it exists.
let SIGHUP:  i32 = 1;
let SIGINT:  i32 = 2;
let SIGKILL: i32 = 9;
let SIGTERM: i32 = 15;

// --- Errors ---------------------------------------------------------------------

fn error_text(e: i64) -> u8[>..] {
    var s: u8[>..] = [];
    error_text(e, s);
    return s;
}

let ERRC_NOT_EXIST:     i32 = 1;
let ERRC_EXIST:         i32 = 2;
let ERRC_PERMISSION:    i32 = 3;
let ERRC_TIMEOUT:       i32 = 4;
let ERRC_NOT_SUPPORTED: i32 = 5;
let ERRC_WOULD_BLOCK:   i32 = 6;
let ERRC_INTERRUPTED:   i32 = 7;
let ERRC_NOT_EMPTY:     i32 = 8;
let ERRC_IS_DIR:        i32 = 9;
let ERRC_NOT_DIR:       i32 = 10;
let ERRC_INVALID:       i32 = 11;

fn is_not_exist(e: i64) -> bool { error_is(e, ERRC_NOT_EXIST) != 0 }
fn is_exist(e: i64) -> bool { error_is(e, ERRC_EXIST) != 0 }
fn is_permission(e: i64) -> bool { error_is(e, ERRC_PERMISSION) != 0 }
fn is_timeout(e: i64) -> bool { error_is(e, ERRC_TIMEOUT) != 0 }
fn is_not_supported(e: i64) -> bool { error_is(e, ERRC_NOT_SUPPORTED) != 0 }
fn is_would_block(e: i64) -> bool { error_is(e, ERRC_WOULD_BLOCK) != 0 }
fn is_not_empty(e: i64) -> bool { error_is(e, ERRC_NOT_EMPTY) != 0 }
fn is_dir_error(e: i64) -> bool { error_is(e, ERRC_IS_DIR) != 0 }
fn is_not_dir(e: i64) -> bool { error_is(e, ERRC_NOT_DIR) != 0 }
fn is_invalid(e: i64) -> bool { error_is(e, ERRC_INVALID) != 0 }

// --- Fields: how the C hands back records and lists ----------------------------------

// The next field of b at pos: its bytes; pos moves past it.
fn field(b: const u8[:], pos: i64&) -> const u8[:] {
    if pos + 4 > b.len { pos = b.len; return b[b.len..]; }
    let n: i64 = b[pos] | (b[pos + 1] as i64 << 8) | (b[pos + 2] as i64 << 16) | (b[pos + 3] as i64 << 24);
    let start = pos + 4;
    let end = min(start + n, b.len);
    pos = end;
    return b[start..end];
}

// The next field as a number.
fn field_int(b: const u8[:], pos: i64&) -> i64 {
    let f = field(b, pos);
    var v: i64 = 0;
    for i in min(f.len, 8) { v |= f[i] as i64 << (8 * i); }
    return v;
}

// A list of strings: environ, getgroups' names, a group's members.
fn strings_of(b: const u8[:], n: i64) -> u8[][>..] {
    var out: u8[][>..] = [];
    var pos: i64       = 0;
    for _ in n { out.push(field(b, pos)); }
    return out;
}

// --- The host -------------------------------------------------------------------------

fn platform() -> i64 { platform_id() }

fn hostname() -> u8[>..] {
    var s: u8[>..] = [];
    hostname(s);
    return s;
}

// uname(2): sysname ("Linux", "Darwin", "Windows"), nodename, release
// ("6.8.0", "24.6.0", "10.0.20348"), version, machine ("x86_64", "arm64").
struct Uname { sysname: u8[], nodename: u8[], release: u8[], version: u8[], machine: u8[] }

fn uname() -> Uname {
    var b: u8[>..] = [];
    uname(b);
    var pos: i64 = 0;
    let s = field(b, pos);
    let n = field(b, pos);
    let r = field(b, pos);
    let v = field(b, pos);
    let m = field(b, pos);
    return Uname { sysname: s, nodename: n, release: r, version: v, machine: m };
}

fn mem_info() -> MemInfo {
    var m = MemInfo { .. };
    mem_info(m);
    return m;
}

fn temp_dir() -> u8[>..] {
    var s: u8[>..] = [];
    temp_dir(s);
    return s;
}

fn home_dir() -> u8[>..] {
    var s: u8[>..] = [];
    home_dir(s);
    return s;
}

// --- This process and others ------------------------------------------------------------

fn exe_path() -> u8[>..] {
    var s: u8[>..] = [];
    exe_path(s);
    return s;
}

fn getcwd() -> u8[>..] {
    var s: u8[>..] = [];
    getcwd(s);
    return s;
}

// The environment, each "NAME=value".
fn environ() -> u8[][>..] {
    var b: u8[>..] = [];
    let n = environ(b);
    return strings_of(b, max(n, 0));
}

struct Process { pid: i64, ppid: i64, name: u8[] }

// The processes running: Toolhelp32 on Windows, /proc on Linux,
// libproc on macOS. A name is the program's (Windows: its .exe's file
// name; Linux: the 15-byte comm; macOS: the program's name).
fn processes() -> Process[>..] {
    var b: u8[>..] = [];
    let n = processes(b);
    var out: Process[>..] = [];
    var pos: i64          = 0;
    for _ in max(n, 0) {
        let pid = field_int(b, pos);
        let ppid = field_int(b, pos);
        let name = field(b, pos);
        out.push(Process { pid: pid, ppid: ppid, name: name });
    }
    return out;
}

// The executable of process pid ("" if it cannot be read).
fn process_exe(pid: i64) -> u8[>..] {
    var s: u8[>..] = [];
    process_exe(pid, s);
    return s;
}

// --- Users and groups -----------------------------------------------------------------------

// Go's os/user.User: on POSIX the uid and gid are numbers in decimal; on
// Windows they are SIDs ("S-1-5-21-..."), the username is DOMAIN\name and
// the home directory is the profile's.
struct User { username: u8[], uid: u8[], gid: u8[], name: u8[], home: u8[] }

// Go's os/user.Group, with its members' names (POSIX: the group file's
// list, which leaves out users whose primary group it is; Windows: a
// local group's members as DOMAIN\name).
struct Group { gid: u8[], name: u8[], members: u8[][] }

fn user_of(b: const u8[:]) -> User {
    var pos: i64 = 0;
    let u = field(b, pos);
    let uid = field(b, pos);
    let gid = field(b, pos);
    let n = field(b, pos);
    let h = field(b, pos);
    return User { username: u, uid: uid, gid: gid, name: n, home: h };
}

fn group_of(b: const u8[:]) -> Group {
    var pos: i64 = 0;
    let gid = field(b, pos);
    let name = field(b, pos);
    var members: u8[][>..] = [];
    while pos < b.len { members.push(field(b, pos)); }
    return Group { gid: gid, name: name, members: members };
}

// The user this process runs as (the effective one on POSIX). e is set to
// the error, 0 on success.
fn current_user(e: i64&) -> User {
    var b: u8[>..] = [];
    e = current_user(b);
    return user_of(b);
}

fn lookup_user(name: const u8[:], e: i64&) -> User {
    var b: u8[>..] = [];
    e = lookup_user(name, b);
    return user_of(b);
}

fn lookup_user_id(uid: const u8[:], e: i64&) -> User {
    var b: u8[>..] = [];
    e = lookup_user_id(uid, b);
    return user_of(b);
}

fn lookup_group(name: const u8[:], e: i64&) -> Group {
    var b: u8[>..] = [];
    e = lookup_group(name, b);
    return group_of(b);
}

fn lookup_group_id(gid: const u8[:], e: i64&) -> Group {
    var b: u8[>..] = [];
    e = lookup_group_id(gid, b);
    return group_of(b);
}

// The ids of the groups user name is in (Go's User.GroupIds).
fn user_group_ids(name: const u8[:], e: i64&) -> u8[][>..] {
    var b: u8[>..] = [];
    let n = user_group_ids(name, b);
    e = min(n, 0);
    return strings_of(b, max(n, 0));
}

// This process's supplementary group ids (POSIX).
fn getgroups() -> i64[>..] {
    var b: u8[>..] = [];
    let n = getgroups(b);
    var out: i64[>..] = [];
    var pos: i64      = 0;
    for _ in max(n, 0) { out.push(field_int(b, pos)); }
    return out;
}

// --- Files ----------------------------------------------------------------------------------------

struct DirEntry { kind: i64, name: u8[] }

// A directory's entries, without "." and "..", in the order the system
// gives them. e is set to the error, 0 on success.
fn read_dir(path: const u8[:], e: i64&) -> DirEntry[>..] {
    var b: u8[>..] = [];
    let n = read_dir(path, b);
    e = min(n, 0);
    var out: DirEntry[>..] = [];
    var pos: i64           = 0;
    for _ in max(n, 0) {
        let name = field(b, pos);
        let kind = field_int(b, pos);
        out.push(DirEntry { kind: kind, name: name });
    }
    return out;
}

fn readlink(path: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    readlink(path, s);
    return s;
}

fn realpath(path: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    realpath(path, s);
    return s;
}

fn is_dir(st: const Stat&) -> bool { st.kind == KIND_DIR }
fn is_regular(st: const Stat&) -> bool { st.kind == KIND_FILE }
fn is_symlink(st: const Stat&) -> bool { st.kind == KIND_SYMLINK }

// Writes all of data to fd, retrying short writes: 0, or the error.
fn write_all(fd: i64, data: const u8[:]) -> i64 {
    var off: i64 = 0;
    while off < data.len {
        let n = write(fd, data[off..]);
        if n < 0 { return n; }
        off += n;
    }
    return 0;
}

// Reads fd to its end, appending to out: the bytes read, or the error.
fn read_all(fd: i64, out: u8[>..]&) -> i64 {
    var chunk: u8[16384] = [0; 16384];
    var total: i64       = 0;
    while true {
        let n = read(fd, chunk[..]);
        if n < 0 { return n; }
        if n == 0 { break; }
        out.append(chunk[..n]);
        total += n;
    }
    return total;
}

// Writes data to path, readable and writable by its owner only (0600),
// all or nothing: a new file beside it, synced and renamed over it, as
// credential caches, keytabs and private keys are kept. 0, or the error.
fn write_private(path: const u8[:], data: const u8[:]) -> i64 {
    var attempt = 0;
    var taken: i64 = 0;
    while attempt < 100 {
        let tmp = str(path, ".", getpid(), ".", attempt, ".tmp");
        let fd = open(tmp, O_WRONLY | O_CREATE | O_EXCL, 384);
        if is_exist(fd) { taken = fd; attempt++; continue; }
        if fd < 0 { return fd; }
        var e = write_all(fd, data);
        if e == 0 { e = fsync(fd); }
        let ce = close(fd);
        if e == 0 { e = ce; }
        if e == 0 { e = rename(tmp, path); }
        if e != 0 { unlink(tmp); }
        return e;
    }
    return taken;
}

// --- Another process's arguments ------------------------------------------------------------

// Process pid's command line, as its words (Linux: /proc; macOS:
// KERN_PROCARGS2; Windows: the command line, split as the C runtime
// splits it). e is set to the error, 0 on success.
fn process_args(pid: i64, e: i64&) -> u8[][>..] {
    var b: u8[>..] = [];
    let n = process_args(pid, b);
    e = min(n, 0);
    return strings_of(b, max(n, 0));
}

// --- Memory maps ------------------------------------------------------------------------------

// A mapped region: a file's bytes (shared: writes reach the file) or, from
// map_anonymous, memory of its own. Reads and writes are copies, checked
// against its length.
struct Map { addr: i64, len: i64 }

// fd's bytes [offset, offset + length), writable or not. offset must be a
// multiple of the page size (64 KB on Windows: the allocation
// granularity). e is set to the error, 0 on success.
fn map_file(fd: i64, offset: i64, length: i64, writable: bool, e: i64&) -> Map {
    let a = mmap(fd, offset, length, if writable { 1 } else { 0 });
    e = min(a, 0);
    return Map { addr: max(a, 0), len: if a > 0 { length } else { 0 } };
}

fn map_anonymous(length: i64, e: i64&) -> Map {
    let a = mmap(-1, 0, length, 1);
    e = min(a, 0);
    return Map { addr: max(a, 0), len: if a > 0 { length } else { 0 } };
}

// Copies buf.len bytes at offset into buf: how many, or ERR_RANGE.
let ERR_RANGE: i64 = -1000002;

fn map_read(m: const Map&, offset: i64, buf: u8[:]) -> i64 {
    if m.addr == 0 || offset < 0 || offset > m.len || buf.len > m.len - offset { return ERR_RANGE; }
    return mem_read(m.addr, offset, buf);
}

fn map_write(m: const Map&, offset: i64, data: const u8[:]) -> i64 {
    if m.addr == 0 || offset < 0 || offset > m.len || data.len > m.len - offset { return ERR_RANGE; }
    return mem_write(m.addr, offset, data);
}

// Writes a file map's changes to the file now.
fn map_sync(m: const Map&) -> i64 { msync(m.addr, m.len) }

fn unmap(m: Map&) -> i64 {
    if m.addr == 0 { return 0; }
    let e = munmap(m.addr, m.len);
    if e == 0 { m.addr = 0; m.len = 0; }
    return e;
}
