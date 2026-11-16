// service: the texts the service managers read, the same on every
// platform: a systemd unit, a launchd property list and a Windows command
// line, for plain and awkward arguments; and the names install accepts.

import std;
import gslib from "../..";
import gslib.service;

fn awkward() -> service::Config {
    var c = service::config("goose-test", "Goose test", "A test\nservice & <more>, 100%");
    c.exe.append("/opt/goose tools/bin/goose-test");
    c.args.push("--config");
    c.args.push("/etc/goose test/a.yaml");
    c.args.push("");
    c.args.push("100%");
    c.args.push("$HOME");
    c.args.push("say \"hi\"");
    c.args.push("C:\\dir with space\\");
    c.dir.append("/var/lib/goose data");
    c.log_file.append("/tmp/goose-test.log");
    c.restart_ms = 2500;
    c.stop_timeout_ms = 10000;
    return c;
}

fn main() {
    let plain = service::config("goose-plain");
    print("== systemd, system, plain");
    print(service::systemd_unit(plain, "/usr/local/bin/goose-plain"));
    var c = awkward();
    print("== systemd, system, awkward");
    print(service::systemd_unit(c, c.exe));
    c.user_level = true;
    c.restart_ms = 0;
    print("== systemd, user, no restart");
    print(service::systemd_unit(c, c.exe));

    c = awkward();
    c.user_level = true;
    print("== launchd agent, awkward");
    print(service::launchd_plist(c, c.exe));
    var m = service::config("dev.goose.manual");
    m.start = service::START_MANUAL;
    m.restart_ms = 0;
    print("== launchd, manual, no restart");
    print(service::launchd_plist(m, "/usr/local/bin/x"));

    c = awkward();
    print("== windows command line");
    print(service::windows_command_line("C:\\Program Files\\Goose\\goose-test.exe", c.args));
    var w = service::config("x");
    print(service::windows_command_line("C:\\x.exe", w.args));
    w.args.push("a\\\\b");
    w.args.push("a\\\"b");
    w.args.push("tab\there");
    print(service::windows_command_line("C:\\x.exe", w.args));

    print("== names");
    for n in ["goose-test", "dev.goose.heartbeat", "a_b", "", "-x", ".x", "a b", "a/b", "ä"] {
        print(str("'", n, "' ", service::valid_name(n)));
    }
    var long: u8[>..] = [];
    for _ in 0..81 { long.push('a'); }
    print(str("81 letters ", service::valid_name(long)));

    print("== words");
    for s in [service::STATUS_NOT_INSTALLED, service::STATUS_STOPPED, service::STATUS_RUNNING,
              service::STATUS_STARTING, service::STATUS_STOPPING, service::STATUS_PAUSED, service::STATUS_UNKNOWN] {
        print(service::status_text(s));
    }
    for e in 0..10 { print(service::error_text(e)); }
}
