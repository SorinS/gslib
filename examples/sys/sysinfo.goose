// sysinfo: what the system says about itself, the same on Windows, Linux
// and macOS: the host, the OS and its kernel, CPUs and memory, how long it has been up,
// who this runs as, and the processes: how many, this one and its parent.
//
//   goose run sysinfo.goose

import std;
import gslib from "../..";
import gslib.sys;

fn mib(bytes: i64) -> i64 { bytes / (1024 * 1024) }

fn main() {
    let u = sys::uname();
    print("host     ", sys::hostname());
    let info = sys::os_info();
    let edition: u8[>..] = if info.edition.len > 0 { str(", ", info.edition) } else { "" };
    print("os       ", info.pretty, " [", info.id, edition, "]");
    print("kernel   ", u.sysname, " ", u.release, " (", u.version, ") on ", u.machine);
    print("cpus     ", sys::cpu_count(), ", pages of ", sys::page_size(), " bytes");
    let m = sys::mem_info();
    print("memory   ", mib(m.available), " MiB free of ", mib(m.total), " MiB; swap ",
          mib(m.swap_free), " MiB free of ", mib(m.swap_total), " MiB");
    let up = sys::uptime_ms() / 1000;
    print("up       ", up / 86400, "d ", up % 86400 / 3600, "h ", up % 3600 / 60, "m");
    var l: f64[3] = [0.0; 3];
    if sys::load_avg(l[..]) == 3 { print("load     ", l[0], " ", l[1], " ", l[2]); }

    var e: i64 = 0;
    let me = sys::current_user(e);
    if e == 0 {
        print("user     ", me.username, " (uid ", me.uid, ", gid ", me.gid, ")",
              if sys::is_elevated() == 1 { ", elevated" } else { "" });
        print("home     ", me.home);
        var groups = 0;
        for _ in sys::user_group_ids(me.username, e) { groups += 1; }
        print("groups   ", groups);
    } else {
        print("user     ? (", sys::error_text(e), ")");
    }
    print("temp     ", sys::temp_dir());

    let pid = sys::getpid();
    let ppid = sys::getppid();
    var count = 0;
    for p in sys::processes() {
        count += 1;
        if p.pid == pid { print("this     ", p.pid, " ", p.name, " ", sys::process_exe(p.pid)); }
        if p.pid == ppid {
            var words: u8[>..] = [];
            for a in sys::process_args(p.pid, e) { words.append(a); words.push(' '); }
            print("parent   ", p.pid, " ", p.name, ": ", words);
        }
    }
    print("running  ", count, " processes");
}
