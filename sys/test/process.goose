// sys.process: children on pipes and on a pseudo-terminal, their exit
// codes, environment and directory, waiting with a timeout, killing, and
// waiting on descriptors. The programs differ (sh, cmd, sort), the lines
// printed do not.

import std;
import os;
import gslib from "../..";
import gslib.sys;
import gslib.sys.process;

var failed = 0;

fn check(ok: bool, what: const u8[:]) {
    if ok { print("ok   ", what); } else { print("FAIL ", what); failed += 1; }
}

let win = sys::is_windows();

// A command for the shell: sh -c, or cmd /c with the line as it is.
fn shell(c: process::Cmd&, posix: const u8[:], windows: const u8[:]) {
    if win {
        process::arg(c, "cmd");
        c.cmdline.append(str("cmd /d /v:on /c \"", windows, "\""));
    } else {
        process::args(c, ["sh", "-c", posix]);
    }
}

// Text with Windows' \r\n as \n.
fn lf(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for ch in s { if ch != '\r' { out.push(ch); } }
    return out;
}

fn contains(s: const u8[:], sub: const u8[:]) -> bool {
    if sub.len > s.len { return false; }
    for i in s.len - sub.len + 1 { if s[i..i + sub.len] == sub { return true; } }
    return false;
}

fn main() {
    var e: i64 = 0;
    var st = process::Status { .. };

    // --- Output, exit codes, the environment
    var c = process::Cmd { .. };
    shell(c, "echo hi $GSSYS_WORD; exit 3", "echo hi %GSSYS_WORD%& exit 3");
    process::setenv(c, "GSSYS_WORD", "there");
    var out: u8[>..] = [];
    let code = process::output(c, out, e);
    check(e == 0 && code == 3 && lf(out) == "hi there\n", "output: stdout, the exit code, a variable set");

    var m = process::Cmd { .. };
    shell(m, "echo out; echo err >&2", "echo out& echo err>&2");
    m.stderr = process::STDOUT;
    out.clear();
    check(process::output(m, out, e) == 0 && lf(out) == "out\nerr\n", "stderr where stdout goes");

    var q = process::Cmd { .. };
    shell(q, "echo err >&2", "echo err>&2");
    q.stdout = process::NULL;
    q.stderr = process::PIPE;
    var ch = process::start(q, e);
    var err: u8[>..] = [];
    check(e == 0 && sys::read_all(ch.stderr_fd, err) > 0 && lf(err) == "err\n", "stderr on a pipe of its own");
    check(process::wait(ch, st) == 1 && st.exited && st.code == 0 && process::release(ch) == 0, "wait, release");
    check(ch.pid < 0, "a waited child's pid is negated");

    // stdin: sort reads to the end, on every platform.
    var s = process::Cmd { .. };
    process::arg(s, "sort");
    s.stdin = process::PIPE;
    s.stdout = process::PIPE;
    ch = process::start(s, e);
    check(e == 0 && sys::write_all(ch.stdin_fd, if win { "pear\r\napple\r\n" } else { "pear\napple\n" }) == 0, "stdin: written");
    sys::close(ch.stdin_fd);
    ch.stdin_fd = -1;
    out.clear();
    sys::read_all(ch.stdout_fd, out);
    check(lf(out) == "apple\npear\n" && process::wait(ch, st) == 1 && st.code == 0, "stdin: sorted and back");
    process::release(ch);

    // The environment, inherited or not.
    sys::setenv("GSSYS_MARK", "inherited");
    var v = process::Cmd { .. };
    shell(v, "echo [$GSSYS_MARK]", "echo [%GSSYS_MARK%]");
    out.clear();
    check(process::output(v, out, e) == 0 && lf(out) == "[inherited]\n", "env: this process's is inherited");
    var v2 = process::Cmd { .. };
    shell(v2, "echo [$GSSYS_MARK] [$ONLY]", "if defined GSSYS_MARK (echo inherited) else (echo [] [!ONLY!])");
    if !win { v2.path.append("/bin/sh"); }
    v2.clear_env = true;
    process::setenv(v2, "ONLY", "this");
    out.clear();
    check(process::output(v2, out, e) == 0 && lf(out) == "[] [this]\n", "env: clear_env leaves only what is set");

    // The working directory.
    var dir: u8[>..] = [];
    check(sys::mkdir_temp("", "gssys-proc-*", dir) == 0, "mkdir_temp for a working directory");
    var d = process::Cmd { .. };
    shell(d, "pwd", "cd");
    d.dir.append(dir);
    out.clear();
    let _, base = sys::split_path(dir);
    check(process::output(d, out, e) == 0 && contains(out, base), "dir: the child runs there");

    // --- Not started: not found, not a program
    var nf = process::Cmd { .. };
    process::arg(nf, "gssys-no-such-program");
    ch = process::start(nf, e);
    check(e < 0 && sys::is_not_exist(e) && ch.pid == 0, "look_path: not found is start's error");
    var txt: u8[>..] = [];
    let fd = sys::create_temp(dir, "text-*.txt", txt);
    sys::write_all(fd, "not a program\n");
    sys::close(fd);
    var np = process::Cmd { .. };
    np.path.append(txt);
    process::arg(np, "text");
    ch = process::start(np, e);
    check(e < 0 && ch.pid == 0, "exec's failure is start's error, not a child that exits 127");
    sys::unlink(txt);

    // --- Waiting with a timeout; kill
    var k = process::Cmd { .. };
    if win { process::args(k, ["ping", "-n", "30", "127.0.0.1"]); } else { process::args(k, ["sleep", "30"]); }
    k.stdout = process::NULL;
    k.new_group = true;
    ch = process::start(k, e);
    check(e == 0 && process::wait(ch, st, 50) == 0, "wait: still running after 50 ms");
    check(process::kill(ch, 0) == 0, "kill 0: it is there");
    check(process::kill(ch, sys::SIGTERM) == 0, "kill");
    check(process::wait(ch, st, 10000) == 1 && (if win { st.code == 1 } else { !st.exited && st.signal == 15 }),
          "killed: by SIGTERM (Windows: terminated)");
    process::release(ch);

    // --- Waiting on descriptors
    var late = process::Cmd { .. };
    shell(late, "sleep 1; echo late", "ping -n 2 127.0.0.1 >nul& echo late");
    late.stdout = process::PIPE;
    ch = process::start(late, e);
    check(e == 0 && sys::available(ch.stdout_fd) == 0, "available: nothing yet");
    if win {
        var fds: i64[1] = [ch.stdout_fd];
        var ev: i64[1] = [sys::POLL_READ];
        check(sys::poll(fds[..], ev[..], 0) == sys::ENOTSUP, "poll: not readable yet");   // POSIX only: ENOTSUP here
        check(true, "poll: readable once written");
    } else {
        var fds: i64[1] = [ch.stdout_fd];
        var ev: i64[1] = [sys::POLL_READ];
        check(sys::poll(fds[..], ev[..], 10) == 0 && ev[0] == 0, "poll: not readable yet");
        ev[0] = sys::POLL_READ;
        check(sys::poll(fds[..], ev[..], 5000) == 1 && ev[0] == sys::POLL_READ, "poll: readable once written");
    }
    out.clear();
    check(process::collect(ch, out, st) == 0 && lf(out) == "late\n" && st.code == 0, "collect: output read while it runs");
    process::release(ch);

    // --- A pseudo-terminal
    var t = process::Cmd { .. };
    shell(t, "stty size; read x; echo got $x", "set /p x=& echo got !x!");
    t.pty = true;
    t.cols = 100;
    t.rows = 40;
    ch = process::start(t, e);
    check(e == 0 && ch.pty != 0, "pty: started");
    out.clear();
    // POSIX: its size first, before the resize below can change it.
    var buf: u8[256] = [0; 256];
    var tries = 0;
    while !win && !contains(out, "40 100") && tries < 100 {
        var pf: i64[1] = [ch.stdout_fd];
        var pe: i64[1] = [sys::POLL_READ];
        if sys::poll(pf[..], pe[..], 50) > 0 {
            let n = process::read(ch, buf[..]);
            if n <= 0 { break; }
            out.append(buf[..n]);
        } else { tries += 1; }
    }
    check(win || contains(out, "40 100"), "pty: its size");
    check(sys::write_all(ch.stdin_fd, if win { "hello\r" } else { "hello\n" }) == 0, "pty: typed at");
    check(process::resize(ch, 120, 50) == 0, "pty: resized");
    check(process::collect(ch, out, st) == 0 && st.code == 0, "pty: collected to the end");
    check(contains(out, "got hello"), "pty: the child read the line and answered");
    check(win || sys::isatty(ch.stdout_fd) == 1, "pty: a terminal");
    check(process::release(ch) == 0, "pty: released");

    sys::rmdir(dir);
    if failed > 0 { print(failed, " failed"); exit(1); }
    print("all passed");
}
