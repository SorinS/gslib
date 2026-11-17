// run: a command as Go's os/exec runs one, its output read back, then the
// same command on a terminal of its own (a POSIX pty, Windows' ConPTY), where
// it sees a terminal and its size. With no arguments it lists the current
// directory.
//
//   goose run examples/sys/run.goose
//   goose run examples/sys/run.goose -- git status --short

import std;
import os;
import gslib from "../..";
import gslib.sys;
import gslib.sys.process;

// The command: the arguments given, else ls (dir, through cmd, on Windows).
fn words(c: process::Cmd&) {
    let a = args();
    if a.len > 1 {
        for i in a.len - 1 { process::arg(c, a[i + 1]); }
    } else if sys::is_windows() {
        process::args(c, ["cmd", "/c", "dir", "/b"]);
    } else {
        process::args(c, ["ls", "-F"]);
    }
}

fn main() {
    var e: i64 = 0;

    // On pipes: stdout read back, stderr with it.
    var c = process::Cmd { .. };
    words(c);
    c.stderr = process::STDOUT;
    var out: u8[>..] = [];
    let code = process::output(c, out, e);
    if e != 0 { print("cannot run it: ", sys::error_text(e)); exit(1); }
    print("--- on a pipe: exit code ", code, ", ", out.len, " bytes");
    write_stdout(out);

    // On a terminal of 100 x 30: programs that ask (ls's columns, colours)
    // see one. collect reads while it runs, then to the end.
    var t = process::Cmd { .. };
    words(t);
    t.pty = true;
    t.cols = 100;
    t.rows = 30;
    var ch = process::start(t, e);
    if e != 0 { print("no terminal: ", sys::error_text(e)); exit(1); }
    var st = process::Status { .. };
    out.clear();
    process::collect(ch, out, st);
    process::release(ch);
    print("--- on a terminal: exit code ", st.code, ", ", out.len, " bytes (with its escape sequences)");
    write_stdout(out);
    print("");
}
