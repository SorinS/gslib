// sys's unix, term and memory maps: signals sent to this process and
// waited for, limits, usage, sessions, sysctl, every user and group (POSIX;
// on Windows each is sys::ENOTSUP); a process's arguments, file and
// anonymous maps, and what a descriptor that is not a terminal says
// (everywhere). Only failures are printed.

import std;
import os;
import gslib from "../..";
import gslib.sys;
import gslib.sys.unix;
import gslib.sys.term;

var failed = 0;

fn check(ok: bool, what: const u8[:]) {
    if !ok { print("FAIL ", what); failed += 1; }
}

fn posix() {
    let me = sys::getpid();
    let usr1 = unix::sigusr1();
    check(unix::notify(usr1) == 0 && unix::notify(unix::SIGHUP) == 0, "notify");
    check(unix::wait_signal(0) == 0, "wait_signal: nothing yet");
    check(sys::kill(me, usr1) == 0 && sys::kill(me, unix::SIGHUP) == 0, "kill this process");
    let a = unix::wait_signal(2000);
    let b = unix::wait_signal(2000);
    check((a == usr1 && b == unix::SIGHUP) || (a == unix::SIGHUP && b == usr1), "wait_signal: both, queued");
    check(unix::wait_signal(10) == 0, "wait_signal: the time passes");
    check(unix::ignore(usr1) == 0 && sys::kill(me, usr1) == 0 && unix::wait_signal(50) == 0, "ignore");
    check(unix::reset(usr1) == 0 && unix::reset(unix::SIGHUP) == 0, "reset");
    check(unix::notify(unix::SIGKILL) < 0, "notify: not SIGKILL");

    var lim = sys::Rlimit { .. };
    check(unix::getrlimit(unix::RLIMIT_NOFILE, lim) == 0 && lim.cur > 0, "getrlimit");
    let old = lim.cur;
    var lower = sys::Rlimit { cur: min(old, 200), max: lim.max };
    var now = sys::Rlimit { .. };
    check(unix::setrlimit(unix::RLIMIT_NOFILE, lower) == 0 && unix::getrlimit(unix::RLIMIT_NOFILE, now) == 0 && now.cur == min(old, 200), "setrlimit");
    lower.cur = old;
    check(unix::setrlimit(unix::RLIMIT_NOFILE, lower) == 0, "setrlimit: back");
    check(unix::getrlimit(99, lim) < 0, "getrlimit: no such resource");
    let um = unix::umask(18);
    check(unix::umask(um) == 18, "umask");
    check(unix::getsid(0) > 0 && unix::getpgid(0) > 0, "getsid, getpgid");
    var r = unix::Rusage { .. };
    check(unix::rusage(unix::RUSAGE_SELF, r) == 0 && r.utime_ns + r.stime_ns > 0 && r.maxrss > 0, "rusage");

    let linux = sys::platform() == sys::PLATFORM_LINUX;
    let os = unix::sysctl(if linux { "kernel.ostype" } else { "kern.ostype" });
    check(os == sys::uname().sysname, "sysctl: the OS's name");
    var v: i64 = 0;
    check(unix::sysctl_int(if linux { "kernel.pid_max" } else { "hw.ncpu" }, v) == 0 && v > 0, "sysctl_int");
    check(unix::sysctl("no.such.name").len == 0 && unix::sysctl_int("no.such.name", v) < 0, "sysctl: no such name");

    var e: i64 = 0;
    let cu = sys::current_user(e);
    var seen = false;
    for u in unix::users() { if u.uid == cu.uid { seen = true; } }
    check(seen, "users: the current user is one");
    var root_group = false;
    for g in unix::groups() { if g.gid == "0" { root_group = true; } }
    check(root_group, "groups: group 0 is one");
    files();
}

// A file's mode, owner and times by descriptor, a symbolic link's own, the
// file system's sizes, and the error classes an SFTP server tells apart.
fn files() {
    var dir: u8[>..] = [];
    check(sys::mkdir_temp("", "gssys-unix-*", dir) == 0, "mkdir_temp");
    let file = str(dir, "/f");
    let link = str(dir, "/l");
    let fd = sys::open(file, sys::O_RDWR | sys::O_CREATE | sys::O_EXCL, 384);
    check(fd >= 0 && sys::symlink(file, link) == 0, "a file and a link to it");
    var st = sys::Stat { .. };
    check(sys::fchmod(fd, 416) == 0 && sys::fstat(fd, st) == 0 && st.mode == 416, "fchmod");
    check(st.attrs == 32768, "Stat.attrs: S_IFREG");                      // POSIX: st_mode's type bits
    check(sys::fchown(fd, sys::getuid(), sys::getgid()) == 0, "fchown: to its own owner");
    let t: i64 = 1000000000 * 1000000000;                               // 2001-09-09, in ns
    check(sys::futimes(fd, t, t + 2000000000) == 0 && sys::fstat(fd, st) == 0 && st.mtime_ns == t + 2000000000, "futimes");
    check(sys::lutimes(link, t, t) == 0 && sys::lstat(link, st) == 0 && st.mtime_ns == t, "lutimes: the link's own");
    check(sys::stat(link, st) == 0 && st.mtime_ns == t + 2000000000, "lutimes: the file's unchanged");
    let lm = sys::lchmod(link, 384);                                    // Linux: links have no mode
    check(lm == 0 || sys::is_not_supported(lm), "lchmod");
    check(sys::stat(file, st) == 0 && st.mode == 416, "lchmod: the file's mode unchanged");
    var fs = sys::StatFs { .. };
    check(sys::statfs(dir, fs) == 0 && fs.bsize > 0 && fs.blocks > 0 && fs.namemax > 0, "statfs");
    var fs2 = sys::StatFs { .. };
    check(sys::fstatfs(fd, fs2) == 0 && fs2.blocks == fs.blocks, "fstatfs: the same file system");
    check(sys::close(fd) == 0, "close");

    let nf = sys::open(link, sys::O_RDONLY | sys::O_NOFOLLOW, 0);
    check(nf < 0 && sys::is_loop(nf), "is_loop: O_NOFOLLOW on a link");
    check(sys::is_bad_fd(sys::close(fd)), "is_bad_fd: closed twice");
    var long: u8[>..] = [];
    for _ in 300 { long.push('a'); }
    check(sys::is_name_too_long(sys::stat(str(dir, "/", long), st)), "is_name_too_long");
    check(!sys::is_loop(sys::stat(str(dir, "/none"), st)), "is_loop: not for a missing file");
    check(sys::unlink(link) == 0 && sys::unlink(file) == 0 && sys::rmdir(dir) == 0, "clean up");
}

fn windows() {
    var lim = sys::Rlimit { .. };
    check(unix::notify(1) == sys::ENOTSUP && unix::wait_signal(0) == sys::ENOTSUP, "signals: ENOTSUP");
    check(unix::getrlimit(unix::RLIMIT_NOFILE, lim) == sys::ENOTSUP, "getrlimit: ENOTSUP");
    check(unix::users().len == 0 && unix::sysctl("kern.ostype").len == 0, "users, sysctl: none");
}

fn everywhere() {
    var e: i64 = 0;
    let mine = sys::process_args(sys::getpid(), e);
    check(e == 0 && mine.len >= 1, "process_args: this process");
    let parent = sys::process_args(sys::getppid(), e);
    check(e == 0 && parent.len >= 1, "process_args: the parent");
    sys::process_args(999999999, e);
    check(e < 0, "process_args: no such process");

    // A file map: its bytes read, a write reaching the file.
    let win = sys::platform() == sys::PLATFORM_WINDOWS;
    let path = str(sys::temp_dir(), if win { "\\" } else { "/" }, "gssys-map-", sys::getpid());
    var data: u8[>..] = [];
    for i in 70000 { data.push((i % 251) as! u8); }
    check(write_file(path, data), "a file to map");
    let fd = sys::open(path, sys::O_RDWR, 0);
    var m = sys::map_file(fd, 0, 70000, true, e);
    check(e == 0 && m.addr != 0 && m.len == 70000, "map_file");
    var buf: u8[16] = [0; 16];
    check(sys::map_read(m, 65536, buf[..]) == 16 && buf[0] == 65536 % 251 && buf[15] == 65551 % 251, "map_read");
    check(sys::map_write(m, 3, "MAPPED") == 6 && sys::map_sync(m) == 0, "map_write, map_sync");
    check(sys::map_read(m, 69990, buf[..]) == sys::ERR_RANGE && sys::map_write(m, -1, "x") == sys::ERR_RANGE, "map: out of range");
    check(sys::unmap(m) == 0 && m.addr == 0 && sys::close(fd) == 0, "unmap");
    var back: u8[>..] = [];
    check(read_file(path, back) && back.len == 70000 && back[3..9] == "MAPPED" && back[2] == 2 && back[9] == 9, "the write reached the file");
    check(sys::unlink(path) == 0, "cleaned up");
    var am = sys::map_anonymous(100000, e);
    check(e == 0 && sys::map_write(am, 99990, "0123456789") == 10, "map_anonymous");
    check(sys::map_read(am, 99990, buf[..10]) == 10 && buf[..10] == "0123456789" && sys::unmap(am) == 0, "anonymous: read back");

    // A pipe is not a terminal.
    var p: i64[2] = [0; 2];
    check(sys::pipe(p[..]) == 0, "pipe");
    check(!term::is_terminal(p[0]), "is_terminal: no");
    var w: i64 = 0;
    var h: i64 = 0;
    check(term::get_size(p[1], w, h) < 0, "get_size: not a terminal");
    var st = term::State { .. };
    check(term::make_raw(p[0], st) < 0, "make_raw: not a terminal");
    var pw: u8[>..] = [];
    check(term::read_password(p[0], pw) < 0 && pw.len == 0, "read_password: not a terminal");
    check(sys::close(p[0]) == 0 && sys::close(p[1]) == 0, "close");
}

fn main() {
    if sys::platform() == sys::PLATFORM_WINDOWS { windows(); } else { posix(); }
    everywhere();
    if failed > 0 { print(failed, " failed"); exit(1); }
    print("all passed");
}
