// sys: the operating system's own calls, as Go's golang.org/x/sys and
// os/user have them, on Windows, Linux and macOS: the host, this process
// and others, users and groups, and files by path and by descriptor, with
// the errors the system gives. The Windows registry, Windows' users,
// groups, sessions, services, software and shares, and Unix's signals,
// limits, sysctl and terminals, and child processes, are in sys's other
// modules. Here too: what the operating system is (os_info), private and
// temporary files, and waiting on descriptors.
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
// The C is sys's src/: posix.c, unix.c and spawn.c, win.c, winreg.c,
// winmgmt.c and winspawn.c,
// and the prototypes and stubs that scripts/gen_ffi.py makes from
// src/api.def along with ffi.goose.

namespace sys;

import std;
import os;
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
let O_NOFOLLOW: i64 = 0x2000;  // fail on a symbolic link (Windows: any reparse point) rather than follow it
let O_NONBLOCK: i64 = 0x4000;  // POSIX: a FIFO opens at once, without waiting for its other end

// A file or directory made with a mode that gives the group and others
// nothing (0600, 0700) is private on Windows too: its DACL lets in only
// its owner, SYSTEM and Administrators, as Python's os.mkdir does for 0700.

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
    if e == ERR_RANGE { return "out of range"; }
    if e == ERR_NOT_PRIVATE { return "the file can be read or written by others"; }
    if e == ERR_NOT_REGULAR { return "not a regular file"; }
    if e == ERR_TOO_LARGE { return "too large"; }
    var s: u8[>..] = [];
    error_text(e, s);
    return s;
}

// sys's own errors: map_read's and map_write's ERR_RANGE (below), and
// read_private's.
let ERR_NOT_PRIVATE: i64 = -1000003;
let ERR_NOT_REGULAR: i64 = -1000004;
let ERR_TOO_LARGE:   i64 = -1000005;

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
let ERRC_BAD_FD:        i32 = 12;
let ERRC_LOOP:          i32 = 13;
let ERRC_NAME_TOO_LONG: i32 = 14;

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
fn is_bad_fd(e: i64) -> bool { error_is(e, ERRC_BAD_FD) != 0 }
fn is_loop(e: i64) -> bool { error_is(e, ERRC_LOOP) != 0 }             // too many symbolic links, or O_NOFOLLOW met one
fn is_name_too_long(e: i64) -> bool { error_is(e, ERRC_NAME_TOO_LONG) != 0 }

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

// What the operating system is, as os-release(5) has it on Linux, from
// sysctl on macOS and from the registry's CurrentVersion on Windows:
//
//   name          "Ubuntu", "macOS", "Windows Server 2022 Datacenter", "Windows 11 Pro"
//   id            "ubuntu", "macos", "windows"
//   id_like       "debian" (Linux)
//   version       "22.04", "15.1", "10.0.20348"
//   version_name  "jammy", "", "21H2" (Windows' DisplayVersion)
//   build         "", "24B83", "20348.2527"
//   edition       os-release's VARIANT, Windows' EditionID ("ServerDatacenter")
//   pretty        "Ubuntu 22.04.4 LTS", "macOS 15.1 (24B83)", "Windows Server 2022 Datacenter 21H2 (20348.2527)"
//
// The kernel is uname()'s; boot_time() is when the system started, in
// seconds since 1970.
struct OsInfo {
    name: u8[], id: u8[], id_like: u8[], version: u8[], version_name: u8[], build: u8[], edition: u8[], pretty: u8[]
}

fn os_info() -> OsInfo {
    var b: u8[>..] = [];
    os_info(b);
    var pos: i64 = 0;
    let name = field(b, pos);
    let id = field(b, pos);
    let like = field(b, pos);
    let version = field(b, pos);
    let vname = field(b, pos);
    let build = field(b, pos);
    let edition = field(b, pos);
    let pretty = field(b, pos);
    return OsInfo { name: name, id: id, id_like: like, version: version, version_name: vname, build: build,
                    edition: edition, pretty: pretty };
}

fn is_windows() -> bool { platform_id() == 1 }

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

// --- Whole files ---------------------------------------------------------------------------

fn is_sep(c: u8) -> bool { c == '/' || (c == '\\' && is_windows()) }

// path's directory ("." when it has none) and its last element.
fn split_path(path: const u8[:]) -> const u8[:], const u8[:] {
    var i = path.len;
    while i > 0 && !is_sep(path[i - 1]) { i -= 1; }
    if i == 0 { return ".", path; }
    return path[..max(i - 1, 1)], path[i..];
}

// A new file at path holding data, made with mode (0600: private, on
// Windows too). Nothing may be there yet, a symbolic link included, which
// is never followed: a file another user put there first is refused, not
// written. If writing fails the file is removed. 0, or the error
// (is_exist when something was there).
fn create_file(path: const u8[:], data: const u8[:], mode: i64) -> i64 {
    let fd = open(path, O_WRONLY | O_CREATE | O_EXCL | O_NOFOLLOW, mode);
    if fd < 0 { return fd; }
    var e = write_all(fd, data);
    if e == 0 { e = fsync(fd); }
    let c = close(fd);
    if e == 0 { e = c; }
    if e != 0 { unlink(path); }
    return e;
}

// path replaced by data in one step: written to a new file beside it
// (create_temp, with mode) and renamed over it, so that a reader sees the
// old file or all of the new one, never part, and a failure leaves the old
// one. 0, or the error.
fn replace_file(path: const u8[:], data: const u8[:], mode: i64) -> i64 {
    let dir, name = split_path(path);
    var tmp: u8[>..] = [];
    let fd = create_temp(dir, str(".", name, ".*"), tmp, mode);
    if fd < 0 { return fd; }
    var e = write_all(fd, data);
    if e == 0 { e = fsync(fd); }
    let c = close(fd);
    if e == 0 { e = c; }
    if e == 0 { e = rename(tmp, path); }
    if e != 0 { unlink(tmp); }
    return e;
}

// Writes data to path, readable and writable by its owner only (0600),
// all or nothing, as credential caches, keytabs and private keys are kept:
// replace_file with mode 0600. 0, or the error.
fn write_private(path: const u8[:], data: const u8[:]) -> i64 { replace_file(path, data, 384) }

// A secret file read whole, as ssh reads its keys: opened without following
// a symbolic link, then checked on the descriptor itself, so nothing can be
// swapped in between. It must be a regular file that only this user can
// reach (is_private: on POSIX owned by the effective user with no group or
// other bits; on Windows owned by the user, SYSTEM or Administrators, whose
// DACL lets in no one else), of at most max bytes. Appends it to out: its
// length, or the error (ERR_NOT_REGULAR, ERR_NOT_PRIVATE, ERR_TOO_LARGE),
// with nothing appended.
fn read_private(path: const u8[:], out: u8[>..]&, max: i64) -> i64 {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);
    if fd < 0 { return fd; }
    var st = Stat { .. };
    var e = fstat(fd, st);
    if e == 0 && st.kind != KIND_FILE { e = ERR_NOT_REGULAR; }
    if e == 0 {
        let p = is_private(fd);
        if p < 0 { e = p; } else if p == 0 { e = ERR_NOT_PRIVATE; }
    }
    if e == 0 && st.size > max { e = ERR_TOO_LARGE; }
    let start = out.len;
    if e == 0 {
        let n = read_all(fd, out);
        if n < 0 { e = n; } else if n > max { e = ERR_TOO_LARGE; }
    }
    close(fd);
    if e != 0 { out.resize(start); return e; }
    return out.len - start;
}

var temp_rng = rng { 0 };

// The next random part of a temporary name: 10 digits.
fn temp_part() -> u8[>..] {
    if temp_rng.s == 0 { temp_rng = rng { ::random_seed() ^ (getpid() as! u64) }; }
    var s: u8[>..] = [];
    format_uint(s, temp_rng.rand_u64() % 10000000000, 10, 10, '0');
    return s;
}

// The name of a temporary in dir ("": temp_dir()) from pattern, whose last
// '*' is replaced by a random string, or which has one added at its end.
fn temp_name(dir: const u8[:], pattern: const u8[:]) -> u8[>..] {
    var d: u8[>..] = [];
    if dir.len == 0 { d = temp_dir(); } else { d.append(dir); }
    if d.len > 0 && !is_sep(d[d.len - 1]) { d.push(if is_windows() { '\\' } else { '/' }); }
    var star = pattern.len;
    for i in pattern.len { if pattern[i] == '*' { star = i; } }
    if star == pattern.len { return str(d, pattern, temp_part()); }
    return str(d, pattern[..star], temp_part(), pattern[star + 1..]);
}

// A new file to read and write, as Go's os.CreateTemp: in dir (""
// for temp_dir()), named from pattern ("upload-*.tmp"), made with mode
// (0600 unless given: private, on Windows too), never one that was there.
// Its path into path; the descriptor, or the error.
fn create_temp(dir: const u8[:], pattern: const u8[:], path: u8[>..]&, mode: i64 = 384) -> i64 {
    var fd: i64 = 0;
    for _ in 10000 {
        let name = temp_name(dir, pattern);
        fd = open(name, O_RDWR | O_CREATE | O_EXCL | O_NOFOLLOW, mode);
        if fd >= 0 { path.clear(); path.append(name); return fd; }
        if !is_exist(fd) { break; }
    }
    return fd;
}

// A new directory, as Go's os.MkdirTemp: mode 0700 (private, on Windows
// too). Its path into path; 0, or the error.
fn mkdir_temp(dir: const u8[:], pattern: const u8[:], path: u8[>..]&) -> i64 {
    var e: i64 = 0;
    for _ in 10000 {
        let name = temp_name(dir, pattern);
        e = mkdir(name, 448);
        if e == 0 { path.clear(); path.append(name); return 0; }
        if !is_exist(e) { break; }
    }
    return e;
}

// --- Waiting on descriptors -----------------------------------------------------------------

// poll's events: what to wait for, and on return what each is ready for.
// Readable includes the end of input and errors, which a read then tells.
let POLL_READ:  i64 = 1;
let POLL_WRITE: i64 = 2;

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
