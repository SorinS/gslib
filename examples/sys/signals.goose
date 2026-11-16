// signals: waits for signals as values (POSIX), as a daemon does: SIGHUP
// to reload, SIGUSR1 to report, SIGTERM or SIGINT (Ctrl+C) to stop.
//
//   goose run signals.goose &
//   kill -HUP <pid>; kill -USR1 <pid>; kill <pid>

import std;
import gslib from "../..";
import gslib.sys;
import gslib.sys.unix;

fn main() {
    if sys::platform() == sys::PLATFORM_WINDOWS { print("signals: POSIX only (gslib.service has Ctrl+C on Windows)"); return; }
    for s in [unix::SIGHUP, unix::SIGTERM, unix::SIGINT, unix::sigusr1()] { unix::notify(s); }
    print("pid ", sys::getpid(), ": waiting");
    var ticks = 0;
    while true {
        let s = unix::wait_signal(1000);
        if s == 0 { ticks += 1; continue; }
        if s == unix::SIGHUP { print("reload"); }
        else if s == unix::sigusr1() { print("up ", ticks, " s"); }
        else { print("stopping on signal ", s); break; }
    }
}
