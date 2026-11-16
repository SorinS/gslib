// heartbeat: a service that writes a line a second to a file until it is
// stopped, on Windows, Linux (systemd) and macOS (launchd).
//
//   heartbeat [--user] install FILE     install it, writing to FILE
//   heartbeat [--user] start | stop | restart | status | uninstall
//   heartbeat FILE                      run it here; Ctrl+C stops it
//
// --user makes it a user's systemd unit or launchd agent, which needs no
// root; Windows services are the system's, and take an administrator.
// Once installed and started, it writes "beat N" to FILE every second,
// "reload" on SIGHUP, and "stopped" when it is asked to stop, then exits.

import std;
import os;
import gslib from "../..";
import gslib.service;

let NAME: const u8[:] = "goose-heartbeat";

fn run() -> i32 {
    var c = service::config(NAME, "Goose heartbeat", "Writes a line a second to a file, as a service");
    let all = args();
    var rest: const u8[:][>..] = [];
    for a in all {
        if a == "--user" { c.user_level = true; } else { rest.push(a); }
    }
    let rc = service::command(c, rest);
    if rc >= 0 { return rc as! i32; }

    // Running: as the service, or from a console.
    let mode = service::begin(NAME);
    if mode < 0 {
        write_stderr(str("heartbeat: ", service::error_text(-mode), "\n"));
        return 1;
    }
    if rest.len < 2 {
        service::log(NAME, service::LOG_ERROR, "heartbeat: no file to write to");
        service::end(2);
        return 2;
    }
    let path = rest[1];
    service::log(NAME, service::LOG_INFO, str("heartbeat: writing to ", path,
        if mode == service::MODE_SERVICE { " (as a service)" } else { " (interactive)" }));
    append_file(path, str("started ", if mode == service::MODE_SERVICE { "service" } else { "interactive" }, "\n"));
    var n = 0;
    while true {
        let ev = service::wait(1000);
        if service::is_stop(ev) { break; }
        if ev == service::EV_RELOAD { append_file(path, "reload\n"); continue; }
        if ev == service::EV_NONE {
            n++;
            append_file(path, str("beat ", n, "\n"));
        }
    }
    append_file(path, "stopped\n");
    service::log(NAME, service::LOG_INFO, "heartbeat: stopped");
    service::end(0);
    return 0;
}

fn main() { exit(run()); }
