// The file system for tools/sftp_server.goose and tools/scp.goose, on
// gslib's sys: files by descriptor, paths, directories read through a table
// of open ones, users' home directories and names, and the helpers both use
// (a file's attributes as SFTP's, errors as SFTP's status codes). Every
// call that can fail returns sys's error, which on POSIX is -errno, as
// OpenSSH's sftp-server reports it.
namespace fs;

import std;
import gslib.sys;
import gslib.crypto.ssh.sftp;

// EEXIST, for a rename that would replace a file.
let ERR_EXIST: i64 = -17;

// --- Files -----------------------------------------------------------------

// SFTP's pflags (READ 1, WRITE 2, APPEND 4, CREAT 8, TRUNC 16, EXCL 32) as
// sys's open flags; mode for a file it creates.
fn fs_open(path: const u8[:], pflags: u32, mode: u32) -> i32 {
    var flags: i64 = sys::O_RDONLY;
    if (pflags & 1) != 0 && (pflags & 2) != 0 { flags = sys::O_RDWR; }
    else if (pflags & 2) != 0 { flags = sys::O_WRONLY; }
    if (pflags & 4) != 0 { flags |= sys::O_APPEND; }
    if (pflags & 8) != 0 { flags |= sys::O_CREATE; }
    if (pflags & 16) != 0 { flags |= sys::O_TRUNC; }
    if (pflags & 32) != 0 { flags |= sys::O_EXCL; }
    return sys::open(path, flags, mode & 0xfff) as! i32;
}

fn fs_close(fd: i32) -> i32 { sys::close(fd) as! i32 }

// Reads at offset until buf is full or the file ends: how many bytes (0 at
// the end), or the error.
fn fs_pread(fd: i32, buf: u8[:], offset: u64) -> i64 {
    var got: i64 = 0;
    while got < buf.len {
        let n = sys::pread(fd, buf[got..], (offset as! i64) + got);
        if n < 0 { return if got > 0 { got } else { n }; }
        if n == 0 { break; }
        got += n;
    }
    return got;
}

// Writes all of data at offset (at the end, for a file opened to append):
// 0, or the error.
fn fs_pwrite(fd: i32, data: const u8[:], offset: u64, append: i32) -> i64 {
    var put: i64 = 0;
    while put < data.len {
        let n = if append != 0 { sys::write(fd, data[put..]) } else { sys::pwrite(fd, data[put..], (offset as! i64) + put) };
        if n < 0 { return n; }
        put += n;
    }
    return 0;
}

// SETSTAT's parts, on a path (follow false: the link itself) or, with
// fd >= 0, on the open file. Times are seconds.
fn fs_truncate(path: const u8[:], fd: i32, size: u64) -> i32 {
    let r = if fd >= 0 { sys::ftruncate(fd, size as! i64) } else { sys::truncate(path, size as! i64) };
    return r as! i32;
}

fn fs_chmod(path: const u8[:], fd: i32, mode: u32, follow: i32) -> i32 {
    let m = (mode & 0xfff) as i64;
    let r = if fd >= 0 { sys::fchmod(fd, m) } else if follow != 0 { sys::chmod(path, m) } else { sys::lchmod(path, m) };
    return r as! i32;
}

fn fs_chown(path: const u8[:], fd: i32, uid: u32, gid: u32, follow: i32) -> i32 {
    let r = if fd >= 0 { sys::fchown(fd, uid, gid) } else if follow != 0 { sys::chown(path, uid, gid) } else { sys::lchown(path, uid, gid) };
    return r as! i32;
}

fn fs_utimes(path: const u8[:], fd: i32, atime: u64, mtime: u64, follow: i32) -> i32 {
    let a = (atime as! i64) * 1000000000;
    let m = (mtime as! i64) * 1000000000;
    let r = if fd >= 0 { sys::futimes(fd, a, m) } else if follow != 0 { sys::utimes(path, a, m) } else { sys::lutimes(path, a, m) };
    return r as! i32;
}

fn fs_fsync(fd: i32) -> i32 { sys::fsync(fd) as! i32 }

// --- Paths -----------------------------------------------------------------

fn fs_unlink(path: const u8[:]) -> i32 { sys::unlink(path) as! i32 }
fn fs_mkdir(path: const u8[:], mode: u32) -> i32 { sys::mkdir(path, mode & 0xfff) as! i32 }
fn fs_rmdir(path: const u8[:]) -> i32 { sys::rmdir(path) as! i32 }

// kind 0: rename, replacing what is at `to`; 1: a hard link; 2:
// symlink(from, to), from being the link's target.
fn fs_two(from: const u8[:], to: const u8[:], kind: i32) -> i32 {
    let r = if kind == 0 { sys::rename(from, to) } else if kind == 1 { sys::link(from, to) } else { sys::symlink(from, to) };
    return r as! i32;
}

// readlink (kind 0) or realpath (kind 1): the result, and 0 or the error.
fn resolve(path: const u8[:], kind: i32) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let n = if kind == 0 { sys::readlink(path, out) } else { sys::realpath(path, out) };
    if n < 0 { out.clear(); return out, n; }
    return out, 0;
}

// statvfs of a path, or of fd if >= 0, as OpenSSH's statvfs@openssh.com
// sends it: bsize, frsize, blocks, bfree, bavail, files, ffree, favail,
// fsid, flag (1: read-only, 2: no setuid), namemax.
fn fs_statvfs(path: const u8[:], fd: i32, out: u64[:]) -> i32 {
    var s = sys::StatFs { .. };
    let r = if fd >= 0 { sys::fstatfs(fd, s) } else { sys::statfs(path, s) };
    if r < 0 { return r as! i32; }
    let v: i64[11] = [s.bsize, s.frsize, s.blocks, s.bfree, s.bavail, s.files, s.ffree, s.favail, s.fsid, s.flags, s.namemax];
    for i in ::min(11, out.len) { out[i] = v[i] as! u64; }
    return 0;
}

// --- Directories -------------------------------------------------------------

// Open directories: each slot's names, "." and ".." first as readdir has
// them, are read whole when it is opened and kept in names, NUL-ended, from
// dir_start to dir_end; dir_pos is the next one to give.
let DIRS: i64 = 64;
var dir_open: bool[64] = [false; 64];
var dir_start: i64[64] = [0; 64];
var dir_end: i64[64] = [0; 64];
var dir_pos: i64[64] = [0; 64];
var names: u8[>..] = [];

// A directory opened: its slot, or the error (EMFILE when the table is
// full).
fn fs_opendir(path: const u8[:]) -> i32 {
    var slot: i64 = -1;
    for i in DIRS { if slot < 0 && !dir_open[i] { slot = i; } }
    if slot < 0 { return -24; }
    var e: i64 = 0;
    let list = sys::read_dir(path, e);
    if e < 0 { return e as! i32; }
    var any = false;
    for i in DIRS { if dir_open[i] { any = true; } }
    if !any { names.clear(); }
    dir_start[slot] = names.len;
    names.append(".");
    names.push(0);
    names.append("..");
    names.push(0);
    for d in list { names.append(d.name); names.push(0); }
    dir_end[slot] = names.len;
    dir_pos[slot] = dir_start[slot];
    dir_open[slot] = true;
    return slot as! i32;
}

// The next name of an open directory: the name and its length; 0 at the
// end, EBADF for a slot that is not open.
fn readdir(slot: i32) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if slot < 0 || slot >= DIRS || !dir_open[slot] { return out, -9; }
    var p = dir_pos[slot];
    if p >= dir_end[slot] { return out, 0; }
    while names[p] != 0 { out.push(names[p]); p++; }
    dir_pos[slot] = p + 1;
    return out, out.len;
}

fn fs_closedir(slot: i32) -> i32 {
    if slot < 0 || slot >= DIRS || !dir_open[slot] { return -9; }
    dir_open[slot] = false;
    return 0;
}

// --- Stat --------------------------------------------------------------------

// What stat says of a file; mode with its type bits (S_IFMT).
struct Stat { size: u64, uid: u32, gid: u32, mode: u32, atime: u64, mtime: u64, nlink: u64 }

fn no_stat() -> Stat { Stat { size: 0, uid: 0, gid: 0, mode: 0, atime: 0, mtime: 0, nlink: 0 } }

// sys's Stat: on POSIX attrs holds st_mode's type bits.
fn to_stat(s: const sys::Stat&) -> Stat {
    Stat { size: s.size as! u64, uid: s.uid as! u32, gid: s.gid as! u32, mode: (s.attrs | s.mode) as! u32,
           atime: (s.atime_ns / 1000000000) as! u64, mtime: (s.mtime_ns / 1000000000) as! u64, nlink: s.nlink as! u64 }
}

// stat (follow) or lstat: the file's, and 0 or the error.
fn stat(path: const u8[:], follow: bool) -> Stat, i64 {
    var s = sys::Stat { .. };
    let r = if follow { sys::stat(path, s) } else { sys::lstat(path, s) };
    if r < 0 { return no_stat(), r; }
    return to_stat(s), 0;
}

fn fstat(fd: i32) -> Stat, i64 {
    var s = sys::Stat { .. };
    let r = sys::fstat(fd, s);
    if r < 0 { return no_stat(), r; }
    return to_stat(s), 0;
}

// A file's attributes as SFTP sends them: size, owner, mode and times.
// Times past 2106 do not fit version 3's 32 bits and are cut.
fn attrs(s: const Stat&) -> ssh::Attrs {
    ssh::Attrs { flags: ssh::ATTR_SIZE | ssh::ATTR_UIDGID | ssh::ATTR_PERMISSIONS | ssh::ATTR_ACMODTIME,
                 size: s.size, uid: s.uid, gid: s.gid, perm: s.mode, atime: s.atime as! u32, mtime: s.mtime as! u32 }
}

fn is_dir(s: const Stat&) -> bool { (s.mode & ssh::S_IFMT) == ssh::S_IFDIR }
fn is_reg(s: const Stat&) -> bool { (s.mode & ssh::S_IFMT) == ssh::S_IFREG }

// --- Users -------------------------------------------------------------------

// A user's home directory ("" for this process's user: $HOME, else the
// password database's); false if unknown.
fn home(user: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var e: i64 = 0;
    if user.len == 0 {
        ::env("HOME", out);
        if out.len > 0 { return out, true; }
        let u = sys::current_user(e);
        out.append(u.home);
        return out, e == 0 && out.len > 0;
    }
    let u = sys::lookup_user(user, e);
    out.append(u.home);
    return out, e == 0 && out.len > 0;
}

// The name of a user (kind 0) or group (1) by id into buf: its length, or
// 0 when there is none (or it does not fit).
fn fs_id_name(id: u32, kind: i32, buf: u8[:]) -> i64 {
    var e: i64 = 0;
    var name: u8[>..] = [];
    var num: u8[>..] = [];
    format_uint(num, id, 10, 0, ' ');
    if kind == 0 { let u = sys::lookup_user_id(num, e); name.append(u.username); }
    else { let g = sys::lookup_group_id(num, e); name.append(g.name); }
    if e != 0 || name.len == 0 || name.len > buf.len { return 0; }
    for i in name.len { buf[i] = name[i]; }
    return name.len;
}

// A user's (kind 0) or group's (1) name, or the number when it has none.
fn id_name(id: u32, kind: i32) -> u8[>..] {
    var buf: u8[256] = [0; 256];
    let n = fs_id_name(id, kind, buf);
    var out: u8[>..] = [];
    if n > 0 { out.append(buf[..n]); } else { format_uint(out, id, 10, 0, ' '); }
    return out;
}

// --- Errors ------------------------------------------------------------------

// ENOSYS, which OpenSSH reports as unsupported, apart from EOPNOTSUPP,
// which it reports as a failure.
fn enosys() -> i64 { if sys::platform() == sys::PLATFORM_LINUX { -38 } else { -78 } }

// Whether e is one of the errno values SFTP's status codes tell apart:
// 0 ENOENT, 1 ENOTDIR, 2 EBADF, 3 ELOOP, 4 EPERM, 5 EACCES, 6 EFAULT,
// 7 ENAMETOOLONG, 8 EINVAL, 9 ENOSYS, 10 EEXIST, 11 EISDIR, 12 ENOTEMPTY,
// 13 EXDEV, 14 EOPNOTSUPP. Those numbered alike on every POSIX system are
// compared as numbers, the rest through sys's classes.
fn err_is(e: i64, which: i32) -> bool {
    if e >= 0 { return false; }
    if which == 0 { return sys::is_not_exist(e); }
    if which == 1 { return sys::is_not_dir(e); }
    if which == 2 { return sys::is_bad_fd(e); }
    if which == 3 { return sys::is_loop(e); }
    if which == 4 { return e == -1; }
    if which == 5 { return e == -13; }
    if which == 6 { return e == -14; }
    if which == 7 { return sys::is_name_too_long(e); }
    if which == 8 { return sys::is_invalid(e); }
    if which == 9 { return e == enosys(); }
    if which == 14 { return sys::is_not_supported(e) && e != enosys(); }
    if which == 10 { return e == ERR_EXIST; }
    if which == 11 { return sys::is_dir_error(e); }
    if which == 12 { return sys::is_not_empty(e) && e != ERR_EXIST; }
    if which == 13 { return e == -18; }
    return false;
}

// errno as SFTP's status, as OpenSSH's sftp-server maps it: no such file
// for ENOENT, ENOTDIR, EBADF and ELOOP; permission denied for EPERM,
// EACCES and EFAULT; a bad message for ENAMETOOLONG and EINVAL;
// unsupported for ENOSYS; a failure otherwise.
fn status(e: i64) -> u32 {
    if e >= 0 { return ssh::FX_OK; }
    if err_is(e, 0) || err_is(e, 1) || err_is(e, 2) || err_is(e, 3) { return ssh::FX_NO_SUCH_FILE; }
    if err_is(e, 4) || err_is(e, 5) || err_is(e, 6) { return ssh::FX_PERMISSION_DENIED; }
    if err_is(e, 7) || err_is(e, 8) { return ssh::FX_BAD_MESSAGE; }
    if err_is(e, 9) { return ssh::FX_OP_UNSUPPORTED; }
    return ssh::FX_FAILURE;
}

// --- Names -------------------------------------------------------------------

// A path's last part, and the path joined with a name.
fn base_name(path: const u8[:]) -> const u8[:] {
    var end = path.len;
    while end > 1 && path[end - 1] == '/' { end--; }
    var i = end;
    while i > 0 && path[i - 1] != '/' { i--; }
    return path[i..end];
}

fn join(dir: const u8[:], name: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(dir);
    if out.len > 0 && out[out.len - 1] != '/' { out.push('/'); }
    out.append(name);
    return out;
}
