// service: what it asks of the system without installing anything: this
// executable's path, running a command and taking what it prints (POSIX:
// systemctl and launchctl), and the files a Config's service goes in.

import std;
import os;
import gslib from "../..";
import gslib.service;

fn main() {
    let exe = service::exe_path();
    assert(exe.len > 0);
    assert(file_exists(exe));
    let p = service::platform();
    assert(p >= service::PLATFORM_WINDOWS && p <= service::PLATFORM_OTHER);

    if p != service::PLATFORM_WINDOWS {
        var argv: u8[>..] = [];
        service::add_word(argv, "sh");
        service::add_word(argv, "-c");
        service::add_word(argv, "echo out; echo err >&2; exit 3");
        assert(service::run_argv(argv) == 3);
        assert(service::last_output() == "out\nerr\n");
        argv.clear();
        service::add_word(argv, "sh");
        service::add_word(argv, "-c");
        service::add_word(argv, "kill -TERM $$");
        assert(service::run_argv(argv) == 128 + 15);
        argv.clear();
        service::add_word(argv, "/nonexistent/goose-no-such-program");
        let r = service::run_argv(argv);
        assert(r < 0 || r == 127);
        // More than the buffer holds is cut, not overrun.
        argv.clear();
        service::add_word(argv, "sh");
        service::add_word(argv, "-c");
        service::add_word(argv, "i=0; while [ $i -lt 3000 ]; do echo 0123456789; i=$((i+1)); done");
        assert(service::run_argv(argv) == 0);
        assert(service::last_output().len == 16384);

        var c = service::config("goose-test");
        c.user_level = true;
        let unit = service::systemd_unit_path(c);
        assert(service::position_of(unit, "/systemd/user/goose-test.service") > 0);
        let plist = service::launchd_plist_path(c);
        assert(service::position_of(plist, "/Library/LaunchAgents/goose-test.plist") > 0);
        c.user_level = false;
        assert(service::systemd_unit_path(c) == "/etc/systemd/system/goose-test.service");
        assert(service::launchd_plist_path(c) == "/Library/LaunchDaemons/goose-test.plist");
        assert(service::launchd_domain(c) == "system");
        c.user_level = true;
        assert(starts_with(service::launchd_domain(c), "gui/"));
    } else {
        var argv: u8[>..] = [];
        service::add_word(argv, "cmd");
        assert(service::run_argv(argv) == -50);
    }

    // A name install refuses, before it touches anything.
    let bad = service::config("bad name");
    assert(service::install(bad) == service::ERR_ARG);
    assert(service::status(bad) == service::STATUS_UNKNOWN);
    // One that is not installed.
    let none = service::config("goose-test-not-installed-anywhere");
    assert(service::status(none) == service::STATUS_NOT_INSTALLED);
    assert(service::stop(none) == service::ERR_NOT_INSTALLED);
    print("ok");
}
