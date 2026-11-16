// sys: the host, this process, users and groups, errors, on the platform
// it runs on. What is checked is the same everywhere, so the expected
// output is too; values that differ (names, ids, sizes) are compared with
// each other, not printed.

import std;
import os;
import gslib from "../..";
import gslib.sys;

var failed = 0;

fn check(ok: bool, what: const u8[:]) {
    if ok { print("ok   ", what); } else { print("FAIL ", what); failed += 1; }
}

fn has(list: const u8[][:], s: const u8[:]) -> bool {
    for x in list { if x == s { return true; } }
    return false;
}

fn main() {
    let p = sys::platform();
    let win = p == sys::PLATFORM_WINDOWS;
    check(p >= sys::PLATFORM_WINDOWS && p <= sys::PLATFORM_OTHER, "platform");

    // --- The host
    let host = sys::hostname();
    check(host.len > 0, "hostname");
    let u = sys::uname();
    check(u.sysname == (if win { "Windows" } else if p == sys::PLATFORM_LINUX { "Linux" } else if p == sys::PLATFORM_MACOS { "Darwin" } else { u.sysname }), "uname sysname");
    check(u.release.len > 0 && u.machine.len > 0 && u.nodename.len > 0, "uname release, machine, nodename");
    check(sys::cpu_count() >= 1, "cpu_count");
    let ps = sys::page_size();
    check(ps >= 4096 && (ps & (ps - 1)) == 0, "page_size");
    let m = sys::mem_info();
    check(m.total > 0 && m.available > 0 && m.available <= m.total, "mem_info");
    check(sys::uptime_ms() > 0, "uptime_ms");
    var l: f64[3] = [0.0; 3];
    let la = sys::load_avg(l[..]);
    check(if win { la == sys::ENOTSUP } else { la == 3 && l[0] >= 0.0 }, "load_avg");
    let tmp = sys::temp_dir();
    check(tmp.len > 0 && is_dir(tmp), "temp_dir");
    let home = sys::home_dir();
    check(home.len > 0 && is_dir(home), "home_dir");

    // --- This process
    let pid = sys::getpid();
    let ppid = sys::getppid();
    check(pid > 0 && ppid > 0 && pid != ppid, "getpid, getppid");
    let exe = sys::exe_path();
    check(exe.len > 0 && file_exists(exe), "exe_path");
    check(sys::process_exe(pid) == exe, "process_exe of this process");
    var found = false;
    var parent_ok = false;
    for q in sys::processes() {
        if q.pid == pid { found = true; parent_ok = q.ppid == ppid && q.name.len > 0; }
    }
    check(found && parent_ok, "processes lists this one, with its parent");
    check(sys::kill(pid, 0) == 0, "kill 0: this process exists");
    let gone = sys::kill(999999999, 0);
    check(gone < 0 && sys::is_not_exist(gone), "kill 0: no such process");
    let cwd = sys::getcwd();
    check(cwd.len > 0 && sys::chdir(tmp) == 0, "getcwd, chdir");
    check(sys::realpath(sys::getcwd()) == sys::realpath(tmp) && sys::chdir(cwd) == 0 && sys::getcwd() == cwd, "chdir there and back");
    check(sys::is_elevated() >= 0, "is_elevated");

    // --- The environment
    check(sys::setenv("GSSYS_TEST_VAR", "one two") == 0, "setenv");
    var v: u8[>..] = [];
    check(env("GSSYS_TEST_VAR", v) && v == "one two", "env sees setenv");
    check(has(sys::environ(), "GSSYS_TEST_VAR=one two"), "environ has it");
    check(sys::unsetenv("GSSYS_TEST_VAR") == 0 && !has(sys::environ(), "GSSYS_TEST_VAR=one two"), "unsetenv");
    check(sys::is_invalid(sys::setenv("A=B", "x")), "setenv refuses a name with =");

    // --- Users and groups
    var e: i64 = 0;
    let me = sys::current_user(e);
    check(e == 0 && me.username.len > 0 && me.uid.len > 0, "current_user");
    let byname = sys::lookup_user(me.username, e);
    check(e == 0 && byname.uid == me.uid, "lookup_user finds the current user");
    let byid = sys::lookup_user_id(me.uid, e);
    check(e == 0 && byid.username == me.username, "lookup_user_id finds the current user");
    sys::lookup_user("gssys-no-such-user-x", e);
    check(sys::is_not_exist(e), "lookup_user: no such user");
    let ids = sys::user_group_ids(me.username, e);
    check(e == 0 && ids.len > 0, "user_group_ids");
    var first: u8[>..] = [];
    for id in ids { if first.len == 0 { first.append(id); } }
    let g = sys::lookup_group_id(first, e);
    check(e == 0 && g.name.len > 0 && g.gid == first, "lookup_group_id of one of them");
    let g2 = sys::lookup_group(g.name, e);
    check(e == 0 && g2.gid == g.gid, "lookup_group by its name");
    // POSIX ids: the effective uid is current_user's; Windows has none.
    let ids_ok = if win { sys::getuid() == sys::ENOTSUP && sys::getgroups().len == 0 }
                 else { str(sys::geteuid()) == me.uid && sys::getgid() >= 0 && sys::getegid() >= 0 };
    check(ids_ok, "getuid, geteuid, getgid, getegid, getgroups");

    // --- Errors
    var st = sys::Stat { .. };
    let ne = sys::stat(str(tmp, "/gssys-no-such-dir/x"), st);
    check(ne < 0 && sys::is_not_exist(ne) && !sys::is_exist(ne), "stat: not found");
    check(sys::error_text(ne).len > 0 && sys::error_text(sys::ENOTSUP) == "not supported on this platform", "error_text");

    if failed > 0 { print(failed, " failed"); exit(1); }
    print("all passed");
}
