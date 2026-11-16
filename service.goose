// service: a program as a system service, after Go's kardianos/service:
// a Windows service (the service control manager), a systemd unit on
// Linux, or a launchd agent or daemon on macOS, with one API for all
// three. Two halves:
//
//   - running as one: begin() first thing in main, then wait() for the
//     system's requests (stop, shutdown, reload, pause, continue) while
//     the program works, and end() when it is done;
//   - managing one: install, uninstall, start, stop, restart and status,
//     from a Config, and command() to give a program those as verbs.
//
//   import gslib.service;      // from a program; `import service;` inside gslib
//
//   fn main() {
//       var c = service::config("goose-echo", "Goose echo", "Echoes, as a service");
//       let rc = service::command(c, args());   // install, start, stop, ... or -1
//       if rc >= 0 { exit(rc); }
//       let mode = service::begin(c.name);
//       while true {
//           let ev = service::wait(1000);
//           if ev == service::EV_STOP || ev == service::EV_SHUTDOWN { break; }
//           // ... work ...
//       }
//       service::end(0);
//   }
//
// The same program runs from a console as it does as a service: begin()
// tells which (MODE_SERVICE or MODE_INTERACTIVE), and Ctrl+C (SIGINT),
// SIGTERM and a console's closing come as EV_STOP either way, SIGHUP as
// EV_RELOAD.
//
// Windows wants begin() within 30 s of the process starting, before the
// program does anything slow, or it gives up on the service (error 1053).
// begin() has the service reported running; end() reports it stopped, and
// the process should exit then. The control handler reports a stop as
// pending with a 30 s hint; a program that needs longer calls
// still_stopping() as it goes.
//
// The C is service/src/service.c, compiled only into programs that call
// it; on Windows it needs advapi32 (in gslib.build). Installing a system
// service takes an administrator on Windows, root for systemd's system
// units and launchd's daemons; a user's systemd unit (user_level) and a
// launchd agent take neither.

namespace service;

import std;
import os;

extern fn gssvc_platform() -> i32;
extern fn gssvc_start(name: const u8[:], flags: i32) -> i32;
extern fn gssvc_wait(timeout_ms: i32) -> i32;
extern fn gssvc_inject(ev: i32) -> i32;
extern fn gssvc_raise(ev: i32) -> i32;
extern fn gssvc_pending(wait_hint_ms: i32) -> i32;
extern fn gssvc_finish(exit_code: i32);
extern fn gssvc_mode() -> i32;
extern fn gssvc_exe_path(out: u8[:]) -> i64;
extern fn gssvc_uid() -> i64;
extern fn gssvc_spawn(argv: const u8[:], out: u8[:]) -> i32;
extern fn gssvc_spawn_output_len() -> i64;
extern fn gssvc_win_install(name: const u8[:], display: const u8[:], description: const u8[:],
                            command: const u8[:], start: i32, restart_ms: i32) -> i32;
extern fn gssvc_win_uninstall(name: const u8[:]) -> i32;
extern fn gssvc_win_status(name: const u8[:]) -> i32;
extern fn gssvc_win_control(name: const u8[:], stop: i32, timeout_ms: i32) -> i32;
extern fn gssvc_win_log(name: const u8[:], level: i32, msg: const u8[:]) -> i32;

// --- Constants ----------------------------------------------------------------

let PLATFORM_WINDOWS: i64 = 1;
let PLATFORM_LINUX:   i64 = 2;
let PLATFORM_MACOS:   i64 = 3;
let PLATFORM_OTHER:   i64 = 4;     // another POSIX system: it runs, but nothing installs

// What begin() found.
let MODE_INTERACTIVE: i64 = 0;     // from a console or a shell
let MODE_SERVICE:     i64 = 1;     // started by the service control manager, systemd or launchd

// What wait() returns.
let EV_NONE:     i64 = 0;          // the time passed
let EV_STOP:     i64 = 1;          // stop: the service manager, Ctrl+C, SIGTERM, SIGINT, the console closing
let EV_SHUTDOWN: i64 = 2;          // the system is shutting down (Windows; elsewhere it is a SIGTERM, EV_STOP)
let EV_RELOAD:   i64 = 3;          // SIGHUP, or Windows' parameters-changed control
let EV_PAUSE:    i64 = 4;          // Windows, when begin() said pausable
let EV_CONTINUE: i64 = 5;

// When an installed service starts.
let START_AUTO:     i64 = 0;       // with the system (systemd: enabled; launchd: RunAtLoad)
let START_MANUAL:   i64 = 1;       // when started
let START_DELAYED:  i64 = 2;       // Windows: automatic, after the others; elsewhere as START_AUTO
let START_DISABLED: i64 = 3;       // Windows: not at all until changed; elsewhere as START_MANUAL

// What status() returns.
let STATUS_NOT_INSTALLED: i64 = 0;
let STATUS_STOPPED:       i64 = 1;
let STATUS_RUNNING:       i64 = 2;
let STATUS_STARTING:      i64 = 3;
let STATUS_STOPPING:      i64 = 4;
let STATUS_PAUSED:        i64 = 5;
let STATUS_UNKNOWN:       i64 = 6;

// Errors: every fallible function returns OK or one of these.
let OK:                i64 = 0;
let ERR_ARG:           i64 = 1;    // a name or path that cannot be used
let ERR_UNSUPPORTED:   i64 = 2;    // no service manager here that this knows (Linux without systemd)
let ERR_EXISTS:        i64 = 3;    // installing one that is installed
let ERR_NOT_INSTALLED: i64 = 4;
let ERR_ACCESS:        i64 = 5;    // needs an administrator, or root
let ERR_TIMEOUT:       i64 = 6;    // it did not reach running or stopped in time
let ERR_STATE:         i64 = 7;    // starting one that runs, stopping one that does not; begin() twice
let ERR_COMMAND:       i64 = 8;    // systemctl or launchctl failed: last_output() says why
let ERR_SYSTEM:        i64 = 9;    // another error from the system: last_system_error()

fn error_text(e: i64) -> const u8[:] {
    return if e == OK { "ok" }
    else if e == ERR_ARG { "service: bad name or argument" }
    else if e == ERR_UNSUPPORTED { "service: no supported service manager" }
    else if e == ERR_EXISTS { "service: already installed" }
    else if e == ERR_NOT_INSTALLED { "service: not installed" }
    else if e == ERR_ACCESS { "service: access denied (administrator or root needed)" }
    else if e == ERR_TIMEOUT { "service: timed out" }
    else if e == ERR_STATE { "service: already in that state" }
    else if e == ERR_COMMAND { "service: the service manager's command failed" }
    else { "service: system error" };
}

fn status_text(s: i64) -> const u8[:] {
    return if s == STATUS_NOT_INSTALLED { "not installed" }
    else if s == STATUS_STOPPED { "stopped" }
    else if s == STATUS_RUNNING { "running" }
    else if s == STATUS_STARTING { "starting" }
    else if s == STATUS_STOPPING { "stopping" }
    else if s == STATUS_PAUSED { "paused" }
    else { "unknown" };
}

fn platform() -> i64 { gssvc_platform() }

// --- Running as a service -----------------------------------------------------

// Connects to the service manager, the first thing a service does: on
// Windows it reports the service running, and from a console it catches
// Ctrl+C and the console closing; on POSIX it catches SIGTERM, SIGINT and
// SIGHUP. MODE_SERVICE or MODE_INTERACTIVE, or < 0: -ERR_STATE when called
// twice, -ERR_ARG for an empty name, else the negated system error. name
// is the installed service's on Windows (one process, one service) and
// only for logging elsewhere. pausable: Windows offers pause and continue.
fn begin(name: const u8[:], pausable: bool = false) -> i64 {
    let r = gssvc_start(name, if pausable { 1 } else { 0 }) as i64;
    return if r == -1 { -ERR_STATE } else if r == -87 { -ERR_ARG } else { r };
}

// The next request, waiting up to timeout_ms for one (< 0: for ever):
// EV_NONE when none came. Requests queue up, so none is lost between
// calls. Call it from one thread.
fn wait(timeout_ms: i64) -> i64 {
    let t = if timeout_ms > 2000000000 { 2000000000 } else if timeout_ms < 0 { -1 } else { timeout_ms };
    return gssvc_wait(t as! i32);
}

// Whether ev asks the program to end.
fn is_stop(ev: i64) -> bool { ev == EV_STOP || ev == EV_SHUTDOWN }

// Tells the Windows service manager the stop is under way and may take
// wait_hint_ms more, for a stop longer than 30 s. Nothing elsewhere:
// systemd's TimeoutStopSec and launchd's ExitTimeOut are in the Config.
fn still_stopping(wait_hint_ms: i64) {
    gssvc_pending(min(wait_hint_ms, 2000000000) as! i32);
}

// The end: a service is reported stopped, with exit_code (non-zero: a
// failure, which the restart policy acts on), and the signal handlers are
// put back. Exit the process afterwards.
fn end(exit_code: i64) {
    gssvc_finish(exit_code as! i32);
}

// Queues ev as if the system had sent it, and on POSIX raise() sends this
// process the signal behind EV_STOP (SIGTERM) or EV_RELOAD (SIGHUP): for
// tests.
fn inject(ev: i64) -> i64 { if gssvc_inject(ev as! i32) == 0 { OK } else { ERR_ARG } }
fn raise(ev: i64) -> i64 {
    let r = gssvc_raise(ev as! i32);
    return if r == 0 { OK } else if r == -50 { ERR_UNSUPPORTED } else { ERR_ARG };
}

let LOG_INFO:    i64 = 0;
let LOG_WARNING: i64 = 1;
let LOG_ERROR:   i64 = 2;

// A line for the service's log: the Application event log when running as
// a Windows service (under name, the source install() registers), else
// stderr, which systemd's journal and launchd's StandardErrorPath take.
// Under systemd each line carries its priority (<3>, <4>, <6>).
fn log(name: const u8[:], level: i64, msg: const u8[:]) {
    if platform() == PLATFORM_WINDOWS && gssvc_mode() == 1 {
        if gssvc_win_log(name, level as! i32, msg) == 0 { return; }
    }
    var line: u8[>..] = [];
    var js:   u8[>..] = [];
    if env("JOURNAL_STREAM", js) && js.len > 0 {
        line.append(if level >= LOG_ERROR { "<3>" } else if level == LOG_WARNING { "<4>" } else { "<6>" });
    } else {
        line.append(if level >= LOG_ERROR { "error: " } else if level == LOG_WARNING { "warning: " } else { "" });
    }
    line.append(msg);
    line.push('\n');
    write_stderr(line);
}

// --- Describing one -------------------------------------------------------------

struct Config {
    name:            u8[..80],  // letters, digits, '.', '-', '_'; launchd's Label (reverse DNS is usual there)
    display:         u8[..256], // Windows' display name
    description:     u8[..1024],
    exe:             u8[..1024],      // the program; empty: this one (exe_path())
    args:            u8[..512][..16], // its arguments when it runs as the service
    dir:             u8[..1024],      // the working directory; empty: the system's choice
    log_file:        u8[..1024],      // launchd: where stdout and stderr go (it keeps neither otherwise)
    user_level:      bool,            // a user's systemd unit or launchd agent, not the system's; Windows ignores it
    start:           i64,             // START_*
    restart_ms:      i64,             // > 0: restarted that long after it fails (a non-zero exit too)
    stop_timeout_ms: i64,             // how long it has to stop before it is killed (systemd, launchd)
}

fn config(name: const u8[:], display: const u8[:] = "", description: const u8[:] = "") -> Config {
    var c = Config {
        name:       [], display: [], description: [], exe: [], args: [], dir: [], log_file: [],
        user_level: false, start: START_AUTO, restart_ms: 5000, stop_timeout_ms: 30000,
    };
    c.name.append(name[..min(name.len, 80)]);
    c.display.append(display[..min(display.len, 256)]);
    c.description.append(description[..min(description.len, 1024)]);
    return c;
}

fn valid_name(n: const u8[:]) -> bool {
    if n.len == 0 || n.len > 80 || n[0] == '.' || n[0] == '-' { return false; }
    for b in n {
        if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '_') {
            return false;
        }
    }
    return true;
}

// This executable's full path, or "" when the system will not say.
fn exe_path() -> u8[>..] {
    var buf: u8[>..] = [];
    buf.resize(4096, 0);
    let n = gssvc_exe_path(buf);
    if n < 0 { buf.clear(); } else { buf.resize(n, 0); }
    return buf;
}

fn program(c: const Config&) -> u8[>..] {
    var p: u8[>..] = [];
    if c.exe.len > 0 { p.append(c.exe); } else { p.append(exe_path()); }
    return p;
}

// --- The service managers' texts ------------------------------------------------

// One argument as CommandLineToArgvW reads it back: quoted when it is
// empty or has a space, tab or quote, a quote escaped, and backslashes
// doubled before a quote (the closing one too).
fn append_windows_arg(out: u8[>..]&, a: const u8[:]) {
    var plain = a.len > 0;
    for b in a { if b == ' ' || b == '\t' || b == '"' || b == '\n' || b == 0x0b { plain = false; } }
    if plain { out.append(a); return; }
    out.push('"');
    var slashes = 0;
    for b in a {
        if b == '\\' { slashes++; continue; }
        if b == '"' {
            for _ in 0..slashes * 2 + 1 { out.push('\\'); }
        } else {
            for _ in 0..slashes { out.push('\\'); }
        }
        slashes = 0;
        out.push(b);
    }
    for _ in 0..slashes * 2 { out.push('\\'); }
    out.push('"');
}

// The command line a Windows service runs: the program always quoted (an
// unquoted path with spaces is a known hole), then its arguments.
fn windows_command_line(exe: const u8[:], args: const u8[..512][..16]&) -> u8[>..] {
    var out: u8[>..] = [];
    out.push('"');
    out.append(exe);
    out.push('"');
    for a in args {
        out.push(' ');
        append_windows_arg(out, a);
    }
    return out;
}

// One word of a systemd command line: quoted when it needs to be, with
// '\' and '"' escaped; '%' (a specifier) and '$' (a variable) doubled.
fn append_systemd_word(out: u8[>..]&, a: const u8[:]) {
    var plain = a.len > 0;
    for b in a {
        if b == ' ' || b == '\t' || b == '"' || b == '\'' || b == '\\' || b == ';' || b < 0x20 { plain = false; }
    }
    if !plain { out.push('"'); }
    for b in a {
        if b == '%' { out.append("%%"); }
        else if b == '$' { out.append("$$"); }
        else if !plain && (b == '\\' || b == '"') { out.push('\\'); out.push(b); }
        else if b == '\n' { out.append("\\n"); }
        else if b == '\t' { out.append("\\t"); }
        else { out.push(b); }
    }
    if !plain { out.push('"'); }
}

// A value on one line of a unit file, as Description= and
// WorkingDirectory= take it (not quoted): '%' doubled, as a specifier
// starts with one, and a newline, which cannot be in one, made a space.
fn append_unit_value(out: u8[>..]&, s: const u8[:]) {
    for b in s {
        if b == '%' { out.append("%%"); }
        else { out.push(if b == '\n' || b == '\r' { ' ' } else { b }); }
    }
}

fn append_ms_as_seconds(out: u8[>..]&, ms: i64) {
    format(out, ms / 1000);
    if ms % 1000 != 0 {
        out.push('.');
        var f = ms % 1000;
        if f < 100 { out.push('0'); }
        if f < 10 { out.push('0'); }
        while f % 10 == 0 { f /= 10; }
        format(out, f);
    }
}

// The systemd unit for c, its program being exe.
fn systemd_unit(c: const Config&, exe: const u8[:]) -> u8[>..] {
    var u: u8[>..] = [];
    u.append("[Unit]\nDescription=");
    append_unit_value(u, if c.description.len > 0 { c.description[..] } else if c.display.len > 0 { c.display[..] } else { c.name[..] });
    u.append("\n");
    if !c.user_level { u.append("After=network-online.target\nWants=network-online.target\n"); }
    u.append("\n[Service]\nType=simple\nExecStart=");
    append_systemd_word(u, exe);
    for a in c.args { u.push(' '); append_systemd_word(u, a); }
    u.append("\n");
    if c.dir.len > 0 { u.append("WorkingDirectory="); append_unit_value(u, c.dir); u.append("\n"); }
    if c.restart_ms > 0 {
        u.append("Restart=on-failure\nRestartSec=");
        append_ms_as_seconds(u, c.restart_ms);
        u.append("\n");
    }
    u.append("TimeoutStopSec=");
    append_ms_as_seconds(u, c.stop_timeout_ms);
    u.append("\n\n[Install]\nWantedBy=");
    u.append(if c.user_level { "default.target" } else { "multi-user.target" });
    u.append("\n");
    return u;
}

fn append_xml(out: u8[>..]&, s: const u8[:]) {
    for b in s {
        if b == '&' { out.append("&amp;"); }
        else if b == '<' { out.append("&lt;"); }
        else if b == '>' { out.append("&gt;"); }
        else if b == '"' { out.append("&quot;"); }
        else { out.push(b); }
    }
}

fn append_plist_string(out: u8[>..]&, indent: const u8[:], s: const u8[:]) {
    out.append(indent);
    out.append("<string>");
    append_xml(out, s);
    out.append("</string>\n");
}

// The launchd property list for c, its program being exe.
fn launchd_plist(c: const Config&, exe: const u8[:]) -> u8[>..] {
    var p: u8[>..] = [];
    p.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    p.append("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    p.append("<plist version=\"1.0\">\n<dict>\n");
    p.append("\t<key>Label</key>\n");
    append_plist_string(p, "\t", c.name);
    p.append("\t<key>ProgramArguments</key>\n\t<array>\n");
    append_plist_string(p, "\t\t", exe);
    for a in c.args { append_plist_string(p, "\t\t", a); }
    p.append("\t</array>\n");
    if c.dir.len > 0 {
        p.append("\t<key>WorkingDirectory</key>\n");
        append_plist_string(p, "\t", c.dir);
    }
    p.append("\t<key>RunAtLoad</key>\n");
    p.append(if c.start == START_AUTO || c.start == START_DELAYED { "\t<true/>\n" } else { "\t<false/>\n" });
    if c.restart_ms > 0 {
        p.append("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n");
        p.append("\t<key>ThrottleInterval</key>\n\t<integer>");
        format(p, max((c.restart_ms + 999) / 1000, 1));
        p.append("</integer>\n");
    }
    p.append("\t<key>ExitTimeOut</key>\n\t<integer>");
    format(p, max((c.stop_timeout_ms + 999) / 1000, 1));
    p.append("</integer>\n");
    if c.log_file.len > 0 {
        p.append("\t<key>StandardOutPath</key>\n");
        append_plist_string(p, "\t", c.log_file);
        p.append("\t<key>StandardErrorPath</key>\n");
        append_plist_string(p, "\t", c.log_file);
    }
    p.append("</dict>\n</plist>\n");
    return p;
}

// --- Where they go ----------------------------------------------------------------

fn home() -> u8[>..] {
    var h: u8[>..] = [];
    if !env("HOME", h) { h.clear(); }
    return h;
}

// The unit's file: ~/.config/systemd/user (or $XDG_CONFIG_HOME/systemd/user)
// for a user's, /etc/systemd/system for the system's.
fn systemd_unit_path(c: const Config&) -> u8[>..] {
    var p: u8[>..] = [];
    if c.user_level {
        if !env("XDG_CONFIG_HOME", p) || p.len == 0 {
            p.clear();
            p.append(home());
            p.append("/.config");
        }
        p.append("/systemd/user/");
    } else {
        p.append("/etc/systemd/system/");
    }
    p.append(c.name);
    p.append(".service");
    return p;
}

// The property list's file: ~/Library/LaunchAgents for an agent,
// /Library/LaunchDaemons for a daemon.
fn launchd_plist_path(c: const Config&) -> u8[>..] {
    var p: u8[>..] = [];
    if c.user_level { p.append(home()); p.append("/Library/LaunchAgents/"); }
    else { p.append("/Library/LaunchDaemons/"); }
    p.append(c.name);
    p.append(".plist");
    return p;
}

// launchctl's domain: gui/<uid> for an agent, system for a daemon.
fn launchd_domain(c: const Config&) -> u8[>..] {
    var d: u8[>..] = [];
    if c.user_level { d.append("gui/"); format(d, gssvc_uid()); } else { d.append("system"); }
    return d;
}

// Every directory of path up to its file, made if missing.
fn make_parents(path: const u8[:]) -> bool {
    var i = 1;
    while i < path.len {
        if path[i] == '/' && !make_dir(path[..i]) { return false; }
        i++;
    }
    return true;
}

// --- Running the service managers' commands ---------------------------------------

var last_out: u8[>..] = [];
var last_sys: i64     = 0;

// What the last systemctl or launchctl printed, for ERR_COMMAND.
fn last_output() -> const u8[:] { last_out[..] }

// The last system error behind ERR_SYSTEM (a Win32 code on Windows).
fn last_system_error() -> i64 { last_sys }

// Runs a command, argv being its words each followed by a NUL: its exit
// status, < 0 if it could not run.
fn run_argv(argv: const u8[:]) -> i64 {
    last_out.clear();
    last_out.resize(16384, 0);
    let rc = gssvc_spawn(argv, last_out);
    last_out.resize(gssvc_spawn_output_len(), 0);
    return rc;
}

fn add_word(argv: u8[>..]&, w: const u8[:]) { argv.append(w); argv.push(0); }

fn systemctl(c: const Config&, verb: const u8[:], name: const u8[:] = "") -> i64 {
    var argv: u8[>..] = [];
    add_word(argv, "systemctl");
    if c.user_level { add_word(argv, "--user"); }
    add_word(argv, verb);
    if name.len > 0 { add_word(argv, name); }
    return run_argv(argv);
}

fn launchctl(verb: const u8[:], a: const u8[:], b: const u8[:] = "") -> i64 {
    var argv: u8[>..] = [];
    add_word(argv, "launchctl");
    add_word(argv, verb);
    add_word(argv, a);
    if b.len > 0 { add_word(argv, b); }
    return run_argv(argv);
}

fn win_error(r: i32) -> i64 {
    if r == 0 { return OK; }
    last_sys = -(r as i64);
    return if r == -5 { ERR_ACCESS }
    else if r == -1073 { ERR_EXISTS }
    else if r == -1060 { ERR_NOT_INSTALLED }
    else if r == -1056 || r == -1062 || r == -1072 { ERR_STATE }
    else if r == -1460 { ERR_TIMEOUT }
    else if r == -87 { ERR_ARG }
    else { ERR_SYSTEM };
}

fn have_systemd() -> bool { is_dir("/run/systemd/system") }

fn unit_name(c: const Config&) -> u8[>..] {
    var n: u8[>..] = [];
    n.append(c.name);
    n.append(".service");
    return n;
}

// --- Managing one -------------------------------------------------------------------

// Installs c: registered with the service control manager (with its event
// log source), or its systemd unit written and enabled when it starts
// automatically, or its launchd property list written. It is not started.
fn install(c: const Config&) -> i64 {
    if !valid_name(c.name) { return ERR_ARG; }
    let exe = program(c);
    if exe.len == 0 { return ERR_ARG; }
    let p = platform();
    if p == PLATFORM_WINDOWS {
        let cmd = windows_command_line(exe, c.args);
        return win_error(gssvc_win_install(c.name, c.display, c.description, cmd,
                                           c.start as! i32, min(c.restart_ms, 2000000000) as! i32));
    }
    if p == PLATFORM_LINUX {
        if !have_systemd() { return ERR_UNSUPPORTED; }
        let path = systemd_unit_path(c);
        if file_exists(path) { return ERR_EXISTS; }
        if !make_parents(path) { return ERR_ACCESS; }
        if !write_file(path, systemd_unit(c, exe)) { return ERR_ACCESS; }
        if systemctl(c, "daemon-reload") != 0 { return ERR_COMMAND; }
        if c.start == START_AUTO || c.start == START_DELAYED {
            if systemctl(c, "enable", unit_name(c)) != 0 { return ERR_COMMAND; }
        }
        return OK;
    }
    if p == PLATFORM_MACOS {
        let path = launchd_plist_path(c);
        if file_exists(path) { return ERR_EXISTS; }
        if !make_parents(path) { return ERR_ACCESS; }
        if !write_file(path, launchd_plist(c, exe)) { return ERR_ACCESS; }
        return OK;
    }
    return ERR_UNSUPPORTED;
}

// Removes c: on Windows marked for deletion (it goes once stopped), its
// systemd unit disabled and removed, its launchd job unloaded and its
// property list removed.
fn uninstall(c: const Config&) -> i64 {
    if !valid_name(c.name) { return ERR_ARG; }
    let p = platform();
    if p == PLATFORM_WINDOWS { return win_error(gssvc_win_uninstall(c.name)); }
    if p == PLATFORM_LINUX {
        let path = systemd_unit_path(c);
        if !file_exists(path) { return ERR_NOT_INSTALLED; }
        systemctl(c, "disable", unit_name(c));
        if !delete_file(path) { return ERR_ACCESS; }
        systemctl(c, "daemon-reload");
        systemctl(c, "reset-failed", unit_name(c));
        return OK;
    }
    if p == PLATFORM_MACOS {
        let path = launchd_plist_path(c);
        if !file_exists(path) { return ERR_NOT_INSTALLED; }
        var target = launchd_domain(c);
        target.push('/');
        target.append(c.name);
        launchctl("bootout", target);
        if !delete_file(path) { return ERR_ACCESS; }
        return OK;
    }
    return ERR_UNSUPPORTED;
}

// Starts c and, on Windows, waits up to timeout_ms for it to be running.
fn start(c: const Config&, timeout_ms: i64 = 30000) -> i64 {
    if !valid_name(c.name) { return ERR_ARG; }
    let p = platform();
    if p == PLATFORM_WINDOWS { return win_error(gssvc_win_control(c.name, 0, min(timeout_ms, 2000000000) as! i32)); }
    if p == PLATFORM_LINUX {
        if !file_exists(systemd_unit_path(c)) { return ERR_NOT_INSTALLED; }
        return if systemctl(c, "start", unit_name(c)) == 0 { OK } else { ERR_COMMAND };
    }
    if p == PLATFORM_MACOS {
        let path = launchd_plist_path(c);
        if !file_exists(path) { return ERR_NOT_INSTALLED; }
        var target = launchd_domain(c);
        target.push('/');
        target.append(c.name);
        if launchctl("print", target) != 0 {
            // Not loaded: bootstrap loads it, and starts it when RunAtLoad.
            if launchctl("bootstrap", launchd_domain(c), path) != 0 { return ERR_COMMAND; }
            if c.start == START_AUTO || c.start == START_DELAYED { return OK; }
        }
        return if launchctl("kickstart", target) == 0 { OK } else { ERR_COMMAND };
    }
    return ERR_UNSUPPORTED;
}

// Stops c, waiting up to timeout_ms on Windows (systemctl waits on its
// own). On macOS the job is unloaded, so launchd does not restart it.
fn stop(c: const Config&, timeout_ms: i64 = 30000) -> i64 {
    if !valid_name(c.name) { return ERR_ARG; }
    let p = platform();
    if p == PLATFORM_WINDOWS { return win_error(gssvc_win_control(c.name, 1, min(timeout_ms, 2000000000) as! i32)); }
    if p == PLATFORM_LINUX {
        if !file_exists(systemd_unit_path(c)) { return ERR_NOT_INSTALLED; }
        return if systemctl(c, "stop", unit_name(c)) == 0 { OK } else { ERR_COMMAND };
    }
    if p == PLATFORM_MACOS {
        if !file_exists(launchd_plist_path(c)) { return ERR_NOT_INSTALLED; }
        var target = launchd_domain(c);
        target.push('/');
        target.append(c.name);
        if launchctl("print", target) != 0 { return ERR_STATE; }
        return if launchctl("bootout", target) == 0 { OK } else { ERR_COMMAND };
    }
    return ERR_UNSUPPORTED;
}

fn restart(c: const Config&, timeout_ms: i64 = 30000) -> i64 {
    let s = status(c);
    if s == STATUS_NOT_INSTALLED { return ERR_NOT_INSTALLED; }
    if s == STATUS_RUNNING || s == STATUS_PAUSED || s == STATUS_STARTING {
        let e = stop(c, timeout_ms);
        if e != OK { return e; }
    }
    return start(c, timeout_ms);
}

// Where c is: STATUS_*.
fn status(c: const Config&) -> i64 {
    if !valid_name(c.name) { return STATUS_UNKNOWN; }
    let p = platform();
    if p == PLATFORM_WINDOWS {
        let s = gssvc_win_status(c.name);
        if s < 0 { win_error(s); return STATUS_UNKNOWN; }
        return if s == 0 { STATUS_NOT_INSTALLED }
        else if s == 1 { STATUS_STOPPED }
        else if s == 2 || s == 5 { STATUS_STARTING }
        else if s == 3 { STATUS_STOPPING }
        else if s == 4 { STATUS_RUNNING }
        else if s == 6 || s == 7 { STATUS_PAUSED }
        else { STATUS_UNKNOWN };
    }
    if p == PLATFORM_LINUX {
        if !file_exists(systemd_unit_path(c)) { return STATUS_NOT_INSTALLED; }
        systemctl(c, "is-active", unit_name(c));
        let st = trim(last_out[..]);
        return if st == "active" || st == "reloading" { STATUS_RUNNING }
        else if st == "activating" { STATUS_STARTING }
        else if st == "deactivating" { STATUS_STOPPING }
        else if st == "inactive" || st == "failed" { STATUS_STOPPED }
        else { STATUS_UNKNOWN };
    }
    if p == PLATFORM_MACOS {
        if !file_exists(launchd_plist_path(c)) { return STATUS_NOT_INSTALLED; }
        var target = launchd_domain(c);
        target.push('/');
        target.append(c.name);
        if launchctl("print", target) != 0 { return STATUS_STOPPED; }
        // "state = running" in launchctl print's first block.
        return if position_of(last_out, "state = running") >= 0 { STATUS_RUNNING } else { STATUS_STOPPED };
    }
    return STATUS_UNKNOWN;
}

fn trim(s: const u8[:]) -> const u8[:] {
    var a = 0;
    var b = s.len;
    while a < b && (s[a] == ' ' || s[a] == '\n' || s[a] == '\r' || s[a] == '\t') { a++; }
    while b > a && (s[b - 1] == ' ' || s[b - 1] == '\n' || s[b - 1] == '\r' || s[b - 1] == '\t') { b--; }
    return s[a..b];
}

fn position_of(s: const u8[:], sub: const u8[:]) -> i64 {
    if sub.len == 0 { return 0; }
    var i = 0;
    while i + sub.len <= s.len {
        if s[i..i + sub.len] == sub { return i; }
        i++;
    }
    return -1;
}

// --- Verbs for a program ---------------------------------------------------------

// When args[1] is install, uninstall, start, stop, restart or status, does
// it to c, prints what happened, and returns the exit status (0, or 1);
// else -1, and the program runs. "install" takes the program's other
// arguments (args[2..]) as the service's, unless c has some already.
fn command(c: Config&, args: const u8[:][:]) -> i64 {
    if args.len < 2 { return -1; }
    let verb = args[1];
    var e = OK;
    if verb == "install" {
        if c.args.len == 0 {
            for a in args[2..] {
                if c.args.len < 16 && a.len <= 512 { c.args.push(a); }
            }
        }
        e = install(c);
    }
    else if verb == "uninstall" { e = uninstall(c); }
    else if verb == "start" { e = start(c); }
    else if verb == "stop" { e = stop(c); }
    else if verb == "restart" { e = restart(c); }
    else if verb == "status" {
        print(str(c.name, ": ", status_text(status(c))));
        return 0;
    }
    else { return -1; }
    if e == OK {
        print(str(c.name, ": ", verb, " done"));
        return 0;
    }
    var msg: u8[>..] = [];
    msg.append(c.name);
    msg.append(": ");
    msg.append(verb);
    msg.append(": ");
    msg.append(error_text(e));
    if e == ERR_SYSTEM { msg.append(" "); format(msg, last_sys); }
    if e == ERR_COMMAND && last_out.len > 0 { msg.append("\n"); msg.append(trim(last_out[..])); }
    msg.push('\n');
    write_stderr(msg);
    return 1;
}
