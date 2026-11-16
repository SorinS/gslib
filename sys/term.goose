// term: terminals and Windows consoles, as Go's golang.org/x/term has
// them: whether a descriptor is one, its size, raw mode and putting it
// back, and reading a password without echoing it.
//
//   import gslib.sys.term;
//
//   let fd = sys::std_fd(0);
//   if term::is_terminal(fd) {
//       var old = term::State { .. };
//       if term::make_raw(fd, old) == 0 {
//           // ... read keys one at a time ...
//           term::restore(fd, old);
//       }
//   }
//
// A descriptor is sys's: on Windows a console HANDLE (sys::std_fd).
// Results < 0 are errors.

namespace term;

import std;
import sys;
import sys.ffi;

// A terminal's settings, to put back with restore (a struct termios, or a
// console's mode).
struct State { data: u8[..256] }

fn is_terminal(fd: i64) -> bool { sys::isatty(fd) == 1 }

// Its size in characters: 0, or an error (not a terminal).
fn get_size(fd: i64, width: i64&, height: i64&) -> i64 {
    var w = sys::WinSize { .. };
    let e = sys::term_size(fd, w);
    width = w.cols;
    height = w.rows;
    return e;
}

fn get_state(fd: i64, st: State&) -> i64 {
    var b: u8[>..] = [];
    let n = sys::term_get_state(fd, b);
    if n < 0 { return n; }
    if b.len > 256 { return sys::ERR_RANGE; }
    st.data.clear();
    st.data.append(b);
    return 0;
}

// Raw mode, its old state in old: no echo, no line editing, keys as they
// come.
fn make_raw(fd: i64, old: State&) -> i64 {
    let e = get_state(fd, old);
    if e < 0 { return e; }
    return sys::term_make_raw(fd);
}

fn restore(fd: i64, st: const State&) -> i64 { sys::term_set_state(fd, st.data) }

// A line typed at the terminal without echoing it, as x/term's
// ReadPassword: the line without its end, in out; 0 or an error.
fn read_password(fd: i64, out: u8[>..]&) -> i64 {
    var old = State { .. };
    var e = get_state(fd, old);
    if e < 0 { return e; }
    e = sys::term_set_echo(fd, 0);
    if e < 0 { return e; }
    var c: u8[1] = [0];
    while true {
        let n = sys::read(fd, c[..]);
        if n < 0 { e = n; break; }
        if n == 0 || c[0] == '\n' { break; }
        if c[0] == '\r' { continue; }
        if c[0] == 8 || c[0] == 127 {          // backspace, as a line discipline would
            if out.len > 0 { out.pop(); }
            continue;
        }
        out.push(c[0]);
    }
    restore(fd, old);
    return e;
}
