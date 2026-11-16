// password: reads a password at the terminal without echoing it, then a
// key in raw mode, and prints the terminal's size (as Go's x/term
// examples). It needs a terminal: run it in one.
//
//   goose run password.goose

import std;
import os;
import gslib from "../..";
import gslib.sys;
import gslib.sys.term;

fn main() {
    let fd = sys::std_fd(0);
    if !term::is_terminal(fd) { print("password: stdin is not a terminal"); exit(1); }
    var w: i64 = 0;
    var h: i64 = 0;
    if term::get_size(sys::std_fd(1), w, h) == 0 { print("terminal ", w, "x", h); }
    write_stdout("password: ");
    flush_stdout();
    var pw: u8[>..] = [];
    let e = term::read_password(fd, pw);
    print("");
    if e != 0 { print("password: ", sys::error_text(e)); exit(1); }
    print("read ", pw.len, " bytes");
    write_stdout("press a key: ");
    flush_stdout();
    var old = term::State { .. };
    if term::make_raw(fd, old) == 0 {
        var k: u8[1] = [0];
        sys::read(fd, k[..]);
        term::restore(fd, old);
        print("\nkey ", k[0]);
    }
}
