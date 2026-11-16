// unix: what POSIX systems have and Windows does not, as Go's
// golang.org/x/sys/unix has it: signals, waited for as values; resource
// limits and usage; the umask; sessions and process groups; sysctl (on
// Linux, the same names read from /proc/sys); and every user and group.
//
//   import gslib.sys.unix;
//
//   unix::notify(unix::SIGHUP);
//   while true {
//       let sig = unix::wait_signal(1000);   // 0: a second passed
//       if sig == unix::SIGHUP { reload(); }
//   }
//
// Results < 0 are errors (-errno; sys::error_text says it in words). On
// Windows every call returns sys::ENOTSUP.

namespace unix;

import std;
import sys;
import sys.ffi;

// The signals whose numbers every POSIX system shares.
let SIGHUP:  i32 = 1;
let SIGINT:  i32 = 2;
let SIGQUIT: i32 = 3;
let SIGKILL: i32 = 9;
let SIGPIPE: i32 = 13;
let SIGALRM: i32 = 14;
let SIGTERM: i32 = 15;

// The ones Linux and the BSDs number differently.
fn sigusr1() -> i32 { if sys::platform() == sys::PLATFORM_LINUX { 10 } else { 30 } }
fn sigusr2() -> i32 { if sys::platform() == sys::PLATFORM_LINUX { 12 } else { 31 } }
fn sigchld() -> i32 { if sys::platform() == sys::PLATFORM_LINUX { 17 } else { 20 } }
fn sigwinch() -> i32 { 28 }

// --- Signals ------------------------------------------------------------------------

// From now on sig is caught and queued for wait_signal rather than doing
// what it would.
fn notify(sig: i32) -> i64 { sys::signal_notify(sig) }

// sig is ignored, or does what it would by default again.
fn ignore(sig: i32) -> i64 { sys::signal_ignore(sig) }
fn reset(sig: i32) -> i64 { sys::signal_reset(sig) }

// The next caught signal; 0 when timeout_ms passed first (< 0: wait for
// ever). Signals arriving between calls queue. Call it from one thread.
fn wait_signal(timeout_ms: i64) -> i64 { sys::signal_wait(timeout_ms) }

// --- Limits and usage ----------------------------------------------------------------

let RLIMIT_CPU:     i32 = 0;     // seconds
let RLIMIT_FSIZE:   i32 = 1;     // bytes
let RLIMIT_DATA:    i32 = 2;
let RLIMIT_STACK:   i32 = 3;
let RLIMIT_CORE:    i32 = 4;
let RLIMIT_NOFILE:  i32 = 5;     // open descriptors
let RLIMIT_AS:      i32 = 6;     // address space
let RLIMIT_NPROC:   i32 = 7;
let RLIMIT_MEMLOCK: i32 = 8;

// No limit.
let RLIM_INFINITY: i64 = -1;

fn getrlimit(resource: i32, lim: sys::Rlimit&) -> i64 { sys::getrlimit(resource, lim) }
fn setrlimit(resource: i32, lim: sys::Rlimit&) -> i64 { sys::setrlimit(resource, lim) }

struct Rusage {
    utime_ns: i64,     // user CPU time
    stime_ns: i64,     // system CPU time
    maxrss:   i64,     // largest resident set, bytes
    minflt:   i64,
    majflt:   i64,
    nvcsw:    i64,     // voluntary context switches
    nivcsw:   i64,
}

let RUSAGE_SELF:     i32 = 0;
let RUSAGE_CHILDREN: i32 = 1;

fn rusage(who: i32, r: Rusage&) -> i64 {
    var v: i64[7] = [0; 7];
    let e = sys::rusage(who, v[..]);
    if e == 0 { r = Rusage { v[0], v[1], v[2], v[3], v[4], v[5], v[6] }; }
    return e;
}

// The old mask.
fn umask(mask: i64) -> i64 { sys::umask(mask) }

fn setsid() -> i64 { sys::setsid() }
fn getsid(pid: i64) -> i64 { sys::getsid(pid) }
fn getpgid(pid: i64) -> i64 { sys::getpgid(pid) }
fn setpgid(pid: i64, pgid: i64) -> i64 { sys::setpgid(pid, pgid) }

// --- sysctl ---------------------------------------------------------------------------

// A string sysctl ("kern.ostype", "kernel.ostype" on Linux), "" when
// there is none.
fn sysctl(name: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    if sys::sysctl_string(name, s) < 0 { s.clear(); }
    return s;
}

// An integer sysctl ("hw.ncpu", "kernel.pid_max") into v: 0 or an error.
fn sysctl_int(name: const u8[:], v: i64&) -> i64 {
    var o: i64[1] = [0];
    let e = sys::sysctl_int(name, o[..]);
    v = o[0];
    return e;
}

// --- Every user and group ----------------------------------------------------------------

// The password database's users (getpwent), as sys::lookup_user has them.
fn users() -> sys::User[>..] {
    var b: u8[>..] = [];
    let n = sys::all_users(b);
    var out: sys::User[>..] = [];
    var pos: i64            = 0;
    for _ in max(n, 0) {
        let u = sys::field(b, pos);
        let uid = sys::field(b, pos);
        let gid = sys::field(b, pos);
        let name = sys::field(b, pos);
        let home = sys::field(b, pos);
        out.push(sys::User { username: u, uid: uid, gid: gid, name: name, home: home });
    }
    return out;
}

// The group database's groups (getgrent), with their listed members.
fn groups() -> sys::Group[>..] {
    var b: u8[>..] = [];
    let n = sys::all_groups(b);
    var out: sys::Group[>..] = [];
    var pos: i64             = 0;
    for _ in max(n, 0) {
        let gid = sys::field(b, pos);
        let name = sys::field(b, pos);
        let m = sys::field_int(b, pos);
        var members: u8[][>..] = [];
        for _ in m { members.push(sys::field(b, pos)); }
        out.push(sys::Group { gid: gid, name: name, members: copy(members) });
    }
    return out;
}
