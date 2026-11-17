// process: child processes, as Go's os/exec has them, on pipes or on a
// pseudo-terminal (a POSIX pty, Windows' ConPTY), on Windows, Linux and
// macOS.
//
//   import gslib.sys.process;
//
//   var c = process::Cmd { .. };
//   process::args(c, ["git", "status", "--short"]);
//   c.stdout = process::PIPE;
//   var e: i64 = 0;
//   var ch = process::start(c, e);
//   var out: u8[>..] = [];
//   sys::read_all(ch.stdout_fd, out);
//   var st = process::Status { .. };
//   process::wait(ch, st);
//   process::release(ch);
//
// A child is a sys::Child: its pid, this end of its pipes (stdin_fd, stdout_fd,
// stderr_fd: descriptors for sys::read and sys::write, -1 when not piped) and,
// on Windows, its process and pseudo-console handles. wait reaps it;
// release closes what this process holds of it. Once wait has seen the
// child end, its pid is negated, so that nothing signals a pid the system
// may have given to another process since.

namespace process;

import std;
import os;
import sys;

// Where a child's stdin, stdout and stderr go: a descriptor of this process
// (given to the child, still this process's afterwards) or one of these.
let INHERIT: i64 = -1;   // this process's own
let PIPE:    i64 = -2;   // a new pipe, this end in the Child
let NULL:    i64 = -3;   // /dev/null, NUL
let STDOUT:  i64 = -4;   // stderr only: where stdout goes (2>&1)

let SPAWN_SETSID:          i64 = 0x1;
let SPAWN_PGROUP:          i64 = 0x2;
let SPAWN_PTY:             i64 = 0x4;
let SPAWN_DEFAULT_SIGNALS: i64 = 0x8;
let SPAWN_NO_WINDOW:       i64 = 0x10;

// What to run and how. A root struct: its words and environment grow in
// place (arg, args, setenv), and it is passed by reference.
root struct Cmd {
    path: u8[>..] = [],       // the program; empty for the first word found by look_path
    argv: u8[>..] = [],       // its words, each ended by a NUL (arg, args): the first its name for itself
    env: u8[>..] = [],        // NAME=value, each ended by a NUL (setenv), over this process's
    clear_env: bool = false,  // env alone, nothing inherited
    dir: u8[>..] = [],        // where it runs; empty for here
    stdin: i64 = INHERIT,
    stdout: i64 = INHERIT,
    stderr: i64 = INHERIT,
    new_session: bool = false,     // POSIX setsid; Windows: a new process group
    new_group: bool = false,       // a process group of its own: kill reaches all of it
    default_signals: bool = false, // POSIX: every signal's disposition the default, so an ignored SIGPIPE or SIGHUP is not passed on
    pty: bool = false,        // on a new pseudo-terminal of cols x rows: stdin_fd and stdout_fd are its two ends, stderr goes there too; stdin, stdout and stderr are then not used
    cols: i64 = 80,
    rows: i64 = 24,
    hide_window: bool = false,     // Windows: a console program gets no console window
    cmdline: u8[>..] = []     // Windows: the command line as it is, instead of the words quoted
}

// One more word.
fn arg(c: Cmd&, word: const u8[:]) { c.argv.append(word); c.argv.push(0); }

// More words: process::args(c, ["git", "status", "--short"]).
fn args(c: Cmd&, words: const u8[:][:]) { for w in words { arg(c, w); } }
fn args(c: Cmd&, words: const u8[][:]) { for w in words { arg(c, w); } }

// NAME=value for the child, over this process's NAME.
fn setenv(c: Cmd&, name: const u8[:], value: const u8[:]) {
    c.env.append(name); c.env.push('='); c.env.append(value); c.env.push(0);
}

// The NUL-ended strings of a list, one by one: the next from pos.
fn next_string(list: const u8[:], pos: i64&) -> const u8[:] {
    let start = pos;
    while pos < list.len && list[pos] != 0 { pos += 1; }
    let s = list[start..pos];
    if pos < list.len { pos += 1; }
    return s;
}

// How a child ended: exited with code, or killed by signal (POSIX; code
// is then -1).
struct Status { exited: bool, code: i64, signal: i64 }

fn has_sep(s: const u8[:]) -> bool {
    for c in s { if c == '/' || (c == '\\' && sys::is_windows()) { return true; } }
    return false;
}

fn ends_with_ci(s: const u8[:], suffix: const u8[:]) -> bool {
    if suffix.len > s.len { return false; }
    let t = s[s.len - suffix.len..];
    for i in suffix.len {
        var a = t[i];
        var b = suffix[i];
        if a >= 'A' && a <= 'Z' { a += 32; }
        if b >= 'A' && b <= 'Z' { b += 32; }
        if a != b { return false; }
    }
    return true;
}

// A program file: a regular file, executable on POSIX.
fn is_program(p: const u8[:]) -> bool {
    var st = sys::Stat { .. };
    if sys::stat(p, st) != 0 || st.kind != sys::KIND_FILE { return false; }
    return sys::is_windows() || (st.mode & 73) != 0;      // 0111
}

// On Windows a name without an extension is tried with each of PATHEXT's.
fn find_program(base: const u8[:], out: u8[>..]&) -> bool {
    if !sys::is_windows() {
        if is_program(base) { out.append(base); return true; }
        return false;
    }
    var exts: u8[>..] = [];
    if !::env("PATHEXT", exts) || exts.len == 0 { exts.clear(); exts.append(".COM;.EXE;.BAT;.CMD"); }
    var i: i64 = 0;
    while i <= exts.len {
        var j = i;
        while j < exts.len && exts[j] != ';' { j += 1; }
        let ext = exts[i..j];
        if ext.len > 0 && ends_with_ci(base, ext) && is_program(base) { out.append(base); return true; }
        i = j + 1;
    }
    i = 0;
    while i <= exts.len {
        var j = i;
        while j < exts.len && exts[j] != ';' { j += 1; }
        if j > i {
            let p = str(base, exts[i..j]);
            if is_program(p) { out.append(p); return true; }
        }
        i = j + 1;
    }
    return false;
}

// The program name runs, as Go's exec.LookPath: a name with a separator as
// it is, else the first of PATH's directories that has it (on Windows with
// PATHEXT's extensions). The current directory is not searched unless PATH
// names it. e is set to sys's error for "not found" when nothing does.
fn look_path(name: const u8[:], e: i64&) -> u8[>..] {
    e = 0;
    var out: u8[>..] = [];
    if has_sep(name) {
        if find_program(name, out) { return out; }
        e = if sys::is_windows() { -2 } else { -2 };     // ENOENT, ERROR_FILE_NOT_FOUND
        return out;
    }
    var path: u8[>..] = [];
    ::env("PATH", path);
    let sep = if sys::is_windows() { ';' } else { ':' };
    var i: i64 = 0;
    while i <= path.len {
        var j = i;
        while j < path.len && path[j] != sep { j += 1; }
        let dir = if j > i { path[i..j] } else { "." };
        let full = if dir[dir.len - 1] == '/' || dir[dir.len - 1] == '\\' { str(dir, name) }
                   else { str(dir, if sys::is_windows() { "\\" } else { "/" }, name) };
        if find_program(full, out) { return out; }
        i = j + 1;
    }
    e = -2;
    return out;
}

// The NAME of a NAME=value.
fn env_name(kv: const u8[:]) -> const u8[:] {
    // A Windows name can start with '=' (=C:=C:\dir).
    var i: i64 = if kv.len > 0 && kv[0] == '=' { 1 } else { 0 };
    while i < kv.len && kv[i] != '=' { i += 1; }
    return kv[..i];
}

fn same_name(a: const u8[:], b: const u8[:]) -> bool {
    if !sys::is_windows() { return a == b; }
    return a.len == b.len && ends_with_ci(a, b);
}

// The child's environment: this process's, each name in c.env replaced.
fn child_env(c: const Cmd&) -> u8[>..] {
    var out: u8[>..] = [];
    if !c.clear_env {
        let mine = sys::environ();
        for kv in mine {
            var replaced = false;
            var pos: i64 = 0;
            while pos < c.env.len { if same_name(env_name(kv), env_name(next_string(c.env, pos))) { replaced = true; } }
            if !replaced { out.append(kv); out.push(0); }
        }
    }
    out.append(c.env);
    // Go's addCriticalEnv: a Windows program without SYSTEMROOT cannot
    // load its DLLs.
    if c.clear_env && sys::is_windows() {
        var has = false;
        var pos: i64 = 0;
        while pos < c.env.len { if same_name(env_name(next_string(c.env, pos)), "SYSTEMROOT") { has = true; } }
        var root: u8[>..] = [];
        if !has && ::env("SYSTEMROOT", root) { out.append("SYSTEMROOT="); out.append(root); out.push(0); }
    }
    return out;
}

// A command line from words, as Windows' C runtime splits it again (Go's
// syscall.EscapeArg): a word with a space, a tab or a quote goes in
// quotes, its quotes and the backslashes before them escaped.
fn quote_windows(argv: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var pos: i64 = 0;
    var first = true;
    while pos < argv.len {
        let a = next_string(argv, pos);
        if !first { out.push(' '); }
        first = false;
        var plain = a.len > 0;
        for ch in a { if ch == ' ' || ch == '\t' || ch == '"' || ch == '\n' || ch == 11 { plain = false; } }
        if plain { out.append(a); continue; }
        out.push('"');
        var slashes: i64 = 0;
        for ch in a {
            if ch == '\\' { slashes += 1; continue; }
            if ch == '"' { for _ in 2 * slashes + 1 { out.push('\\'); } }
            else { for _ in slashes { out.push('\\'); } }
            slashes = 0;
            out.push(ch);
        }
        for _ in 2 * slashes { out.push('\\'); }
        out.push('"');
    }
    return out;
}

// Starts c. e is set to the error, 0 on success: the program not found,
// or, on POSIX too, one exec could not run (the child's errno comes back
// through a pipe), so that a failed start is never a child that exits 127.
fn start(c: const Cmd&, e: i64&) -> sys::Child {
    var ch = sys::Child { pid: 0, handle: 0, stdin_fd: -1, stdout_fd: -1, stderr_fd: -1, pty: 0 };
    e = 0;
    var pos: i64 = 0;
    let name = next_string(c.argv, pos);
    if name.len == 0 && c.path.len == 0 { e = -22; return ch; }
    var path: u8[>..] = [];
    if c.path.len > 0 { path.append(c.path); }
    else {
        path = look_path(name, e);
        if e != 0 { return ch; }
    }
    var args: u8[>..] = [];
    if c.argv.len == 0 { args.append(path); args.push(0); } else { args.append(c.argv); }
    if sys::is_windows() {
        if c.cmdline.len > 0 { args.clear(); args.append(c.cmdline); }
        else { let line = quote_windows(args); args.clear(); args.append(line); }
    }
    var flags: i64 = 0;
    if c.new_session { flags |= SPAWN_SETSID; }
    if c.new_group { flags |= SPAWN_PGROUP; }
    if c.pty { flags |= SPAWN_PTY; }
    if c.default_signals { flags |= SPAWN_DEFAULT_SIGNALS; }
    if c.hide_window { flags |= SPAWN_NO_WINDOW; }
    var stdio: i64[3] = [c.stdin, c.stdout, c.stderr];
    var size: i64[2] = [c.cols, c.rows];
    e = sys::spawn(path, args, child_env(c), c.dir, flags, stdio[..], size[..], ch);
    return ch;
}

// Waits up to timeout_ms (-1, the default: until it ends) for the child:
// 1 when it has ended, with st saying how; 0 when it still runs; or the
// error. A child is waited for once.
fn wait(ch: sys::Child&, st: Status&, timeout_ms: i64 = -1) -> i64 {
    var s: i64[2] = [0; 2];
    let r = sys::child_wait(ch, timeout_ms, s[..]);
    if r == 1 { st = Status { exited: s[0] >= 0, code: s[0], signal: s[1] }; }
    return r;
}

// sig to the child (sys::SIGTERM, ...), or to its whole group when it has
// one of its own (new_session, new_group, pty). On Windows any signal but 0
// ends it (TerminateProcess) and 0 asks whether it still runs.
fn kill(ch: sys::Child&, sig: i32) -> i64 { sys::child_kill(ch, sig) }

// A pseudo-terminal's new size.
fn resize(ch: sys::Child&, cols: i64, rows: i64) -> i64 { sys::pty_resize(ch, cols, rows) }

// Windows: closes the pseudo-console, which ends its output (stdout reads
// 0) once the child has gone; with the child still there, it ends it. On
// POSIX nothing: a pty's output ends when the child's side closes.
fn close_pty(ch: sys::Child&) -> i64 { sys::pty_close(ch) }

// Closes this process's ends of the child's pipes or terminal and, on
// Windows, its handles. After wait, or to let the child go on alone.
fn release(ch: sys::Child&) -> i64 { sys::child_release(ch) }

// Reads the child's output (stdout, or its terminal's) into buf: how many
// bytes, 0 at its end, or the error. A Linux pty's master gives EIO once
// the child's side has closed, which is the end here.
fn read(ch: sys::Child&, buf: u8[:]) -> i64 {
    let n = sys::read(ch.stdout_fd, buf);
    if n == -5 && ch.pty != 0 && !sys::is_windows() { return 0; }
    return n;
}

// Waits for a started child to end, reading its output (stdout, or its
// terminal's) into out as it comes: 0 with st saying how it ended, or the
// error. This is the way to run a pty child to its end on every platform.
// Windows' pseudo-console holds its output until it is closed, and closing
// it waits for room in a full pipe, so the order is: read while the child
// runs, close the console once it has gone, then read to the end. On
// POSIX the output is read as poll finds it (macOS's FIONREAD says nothing
// of a pty's, and a child leaving a pty waits for its output to be read).
fn collect(ch: sys::Child&, out: u8[>..]&, st: Status&) -> i64 {
    var buf: u8[16384] = [0; 16384];
    var ended = ch.stdout_fd < 0;
    while true {
        var nap: i64 = 20;
        if !ended && sys::is_windows() {
            while true {
                let a = sys::available(ch.stdout_fd);
                if a <= 0 { break; }
                let n = read(ch, buf[..min(a, buf.len)]);
                if n <= 0 { break; }
                out.append(buf[..n]);
            }
        } else if !ended {
            var fds: i64[1] = [ch.stdout_fd];
            var ev: i64[1] = [sys::POLL_READ];
            let p = sys::poll(fds[..], ev[..], 20);
            if p < 0 { return p; }
            if p > 0 {
                let n = read(ch, buf[..]);
                if n < 0 { return n; }
                if n > 0 { out.append(buf[..n]); } else { ended = true; }
            }
            nap = 0;
        }
        let r = wait(ch, st, if ended { -1 } else { nap });
        if r < 0 { return r; }
        if r == 1 { break; }
    }
    close_pty(ch);
    if ch.stdout_fd >= 0 {
        while true {
            let n = read(ch, buf[..]);
            if n < 0 { return n; }
            if n == 0 { break; }
            out.append(buf[..n]);
        }
    }
    return 0;
}

// Runs c to its end: its exit code (-1 when a signal ended it), or the
// error into e.
fn run(c: const Cmd&, e: i64&) -> i64 {
    var ch = start(c, e);
    if e != 0 { return -1; }
    var st = Status { .. };
    let r = wait(ch, st);
    release(ch);
    if r < 0 { e = r; return -1; }
    return st.code;
}

// Runs c with its stdout into out (appended): its exit code (-1 when a
// signal ended it), or the error into e. Its stderr is c's, this process's
// unless set.
fn output(c: Cmd&, out: u8[>..]&, e: i64&) -> i64 {
    let was = c.stdout;
    c.stdout = PIPE;
    var ch = start(c, e);
    c.stdout = was;
    if e != 0 { return -1; }
    let n = sys::read_all(ch.stdout_fd, out);
    var st = Status { .. };
    let r = wait(ch, st);
    release(ch);
    if n < 0 { e = n; return -1; }
    if r < 0 { e = r; return -1; }
    return st.code;
}
