// sys: what the operating system is, and private and temporary files:
// create_file, replace_file, read_private, create_temp, mkdir_temp and
// O_NOFOLLOW. A mode with nothing for the group and others is private on
// Windows too (an owner-only DACL), so the checks are the same; the file
// that is not private is a system one there (win.ini) and /etc/hosts here.

import std;
import os;
import gslib from "../..";
import gslib.sys;

var failed = 0;

fn check(ok: bool, what: const u8[:]) {
    if ok { print("ok   ", what); } else { print("FAIL ", what); failed += 1; }
}

fn main() {
    let win = sys::is_windows();

    // --- The operating system
    let o = sys::os_info();
    check(o.name.len > 0 && o.id.len > 0 && o.pretty.len > 0, "os_info: name, id, pretty");
    let want_id = if win { "windows" } else if sys::platform() == sys::PLATFORM_MACOS { "macos" } else { "" };
    check(want_id.len == 0 || o.id == want_id, "os_info: the id of this platform");
    check(o.version.len > 0, "os_info: a version");
    let boot = sys::boot_time();
    let now = ::time() as! i64;
    check(boot > 0 && boot <= now && now - boot >= sys::uptime_ms() / 1000 - 5, "boot_time: before now, by the uptime");

    // --- A directory of its own, private
    var dir: u8[>..] = [];
    check(sys::mkdir_temp("", "gssys-private-*", dir) == 0, "mkdir_temp");
    let dfd = sys::open(dir, sys::O_RDONLY, 0);
    check(dfd >= 0 && sys::is_private(dfd) == 1, "mkdir_temp: private");
    sys::close(dfd);
    let sep = if win { "\\" } else { "/" };

    // --- create_file: new only, private with 0600
    let key = str(dir, sep, "key");
    check(sys::create_file(key, "secret\n", 384) == 0, "create_file");
    let again = sys::create_file(key, "other\n", 384);
    check(again < 0 && sys::is_exist(again), "create_file: never over one that is there");
    var got: u8[>..] = [];
    check(sys::read_private(key, got, 1024) == 7 && got == "secret\n", "read_private");
    got.clear();
    let big = sys::read_private(key, got, 3);
    check(big == sys::ERR_TOO_LARGE && got.len == 0, "read_private: longer than max, nothing appended");

    // --- replace_file: whole, still private
    check(sys::replace_file(key, "new secret\n", 384) == 0, "replace_file");
    got.clear();
    check(sys::read_private(key, got, 1024) == 11 && got == "new secret\n", "replace_file: the new data, private");
    var de: i64 = 0;
    let entries = sys::read_dir(dir, de);
    var count = 0;
    for _ in entries { count += 1; }
    check(count == 1, "replace_file: no temporary left beside it");

    // --- Not private: a system file anyone may read
    let public = if win { "C:\\Windows\\win.ini" } else { "/etc/hosts" };
    got.clear();
    let pe = sys::read_private(public, got, 1 << 20);
    check(pe == sys::ERR_NOT_PRIVATE && got.len == 0, "read_private: a file others can read is refused");
    check(sys::error_text(pe) == "the file can be read or written by others", "error_text of sys's own errors");
    got.clear();
    check(sys::read_private(dir, got, 1024) < 0, "read_private: a directory is refused");

    // --- A world-readable file made with 0644 is not private on POSIX
    if !win {
        let open_file = str(dir, sep, "open");
        check(sys::create_file(open_file, "x", 420) == 0 && sys::chmod(open_file, 420) == 0, "create_file 0644");
        got.clear();
        check(sys::read_private(open_file, got, 10) == sys::ERR_NOT_PRIVATE, "read_private: 0644 is refused");
        sys::unlink(open_file);
    } else {
        check(true, "create_file 0644");
        check(true, "read_private: 0644 is refused");
    }

    // --- O_NOFOLLOW: a symbolic link is not followed, nor written through
    let link = str(dir, sep, "link");
    let made = sys::symlink(key, link);
    if made == 0 {
        let lf = sys::open(link, sys::O_RDONLY | sys::O_NOFOLLOW, 0);
        check(lf < 0, "O_NOFOLLOW: a link is refused");
        if lf >= 0 { sys::close(lf); }
        let w = sys::create_file(link, "through", 384);
        check(w < 0 && sys::is_exist(w), "create_file: never through a link");
        got.clear();
        check(sys::read_private(link, got, 1024) < 0 && got.len == 0, "read_private: never through a link");
        sys::unlink(link);
    } else {
        // Windows without the privilege or developer mode.
        check(true, "O_NOFOLLOW: a link is refused");
        check(true, "create_file: never through a link");
        check(true, "read_private: never through a link");
    }

    // --- create_temp: new names, private
    var t1: u8[>..] = [];
    var t2: u8[>..] = [];
    let f1 = sys::create_temp(dir, "up-*.tmp", t1);
    let f2 = sys::create_temp(dir, "up-*.tmp", t2);
    check(f1 >= 0 && f2 >= 0 && t1 != t2, "create_temp: two new files");
    let _, base = sys::split_path(t1);
    check(base.len == 3 + 10 + 4 && base[..3] == "up-" && base[13..] == ".tmp", "create_temp: the pattern's * replaced");
    check(sys::is_private(f1) == 1, "create_temp: private");
    sys::close(f1);
    sys::close(f2);
    sys::unlink(t1);
    sys::unlink(t2);

    sys::unlink(key);
    check(sys::rmdir(dir) == 0, "all removed");
    if failed > 0 { print(failed, " failed"); exit(1); }
    print("all passed");
}
