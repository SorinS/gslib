// The operating system for the ssh tools: sockets (gslib's net), waiting on
// several descriptors, the terminal (sys.term), child processes on pipes or
// a pseudo-terminal (sys.process), private files (sys), and a few helpers.
// Descriptors are i32, as the tools keep them; each function returns -1
// (or a negative value) on failure. POSIX: sshd forks, and its sessions
// and the client wait on sockets, pipes and terminals together.
namespace sysnet;

import std;
import os;
import gslib.net;
import gslib.net.ip;
import gslib.sys;
import gslib.sys.term;
import gslib.sys.process;
import gslib.sys.unix;

// An environment variable's value, empty when it is not set.
fn getenv(name: const u8[:]) -> u8[>..] {
    var v: u8[>..] = [];
    ::env(name, v);
    return v;
}

// SIGPIPE off: a closed peer is a write error, not a death.
fn net_init() { unix::ignore(unix::SIGPIPE); }

// --- Sockets ---------------------------------------------------------------

// A TCP connection, each of host's addresses in turn: the socket, -2 if
// the name does not resolve, -1 otherwise.
fn net_connect(host: const u8[:], port: i32) -> i32 {
    let fd = net::dial(host, port, 0);
    if fd == net::ERR_RESOLVE { return -2; }
    if fd < 0 { return -1; }
    return fd as! i32;
}

// Listens on addr:port ("" for every address).
fn net_listen(addr: const u8[:], port: i32) -> i32 {
    let fd = net::listen(addr, port);
    return if fd < 0 { -1 } else { fd as! i32 };
}

// A connection, and its peer's address as text into peer, its length
// through peer_len, and its port through peer_port.
fn net_accept(fd: i32, peer: u8[:], peer_len: i64&, peer_port: i32&) -> i32 {
    peer_len = 0;
    peer_port = 0;
    let c = net::accept(fd, 0);
    if c < 0 { return -1; }
    let ap, e = net::peer_addr(c);
    if e == 0 {
        let text = net::addr_string(ap.addr);
        let n = ::min(text.len, peer.len);
        for i in n { peer[i] = text[i]; }
        peer_len = n;
        peer_port = ap.port as! i32;
    }
    return c as! i32;
}

// The port a socket is bound to (a listener's, after port 0).
fn net_local_port(fd: i32) -> i32 {
    let p = net::local_port(fd);
    return if p < 0 { -1 } else { p as! i32 };
}

// Waits up to timeout_ms (-1: no limit) for any of fds (-1 entries
// ignored) to be readable or closed, or, where write[i] is nonzero (write
// may be shorter than fds), to take a write: ready[i] is 1 for those that
// are. How many are, 0 on timeout, -1 on error.
fn net_poll_rw(fds: const i32[:], write: const u8[:], ready: u8[:], timeout_ms: i32) -> i32 {
    var f: i64[>..] = [];
    var want: u8[>..] = [];
    for i in fds.len {
        f.push(fds[i]);
        want.push(if i < write.len && write[i] != 0 { net::WANT_WRITE } else { net::WANT_READ });
    }
    var got: u8[>..] = [];
    got.resize(fds.len, 0);
    // net's timeouts: 0 waits for ever, a negative one not at all.
    let n = net::poll(f, want, got, if timeout_ms < 0 { 0 } else if timeout_ms == 0 { -1 } else { timeout_ms });
    for i in ::min(ready.len, fds.len) { ready[i] = if got[i] != 0 { 1 } else { 0 }; }
    if n == net::ERR_TIMEOUT { return 0; }
    return if n < 0 { -1 } else { n as! i32 };
}

// The same, for reading only.
fn net_poll_set(fds: const i32[:], ready: u8[:], timeout_ms: i32) -> i32 {
    let none: u8[0] = [];
    return net_poll_rw(fds, none, ready, timeout_ms);
}

// Up to buf.len bytes from a socket, pipe or terminal: how many, 0 at end
// of file, -1 on error.
fn net_read(fd: i32, buf: u8[:]) -> i64 {
    let n = sys::read(fd, buf);
    return if n < 0 { -1 } else { n };
}

// All of data, or -1: on a non-blocking descriptor too, waiting while it is
// full.
fn net_write(fd: i32, data: const u8[:]) -> i64 {
    var off: i64 = 0;
    while off < data.len {
        let n = sys::write(fd, data[off..]);
        if n > 0 { off += n; continue; }
        if n < 0 && sys::is_would_block(n) {
            var f: i64[1] = [fd];
            var ev: i64[1] = [sys::POLL_WRITE];
            if sys::poll(f[..], ev[..], -1) < 0 { return -1; }
            continue;
        }
        return -1;
    }
    return off;
}

// One write of what fits: how many bytes went, 0 when the descriptor is
// full (a socket's write never waits; a pipe's does unless it is
// non-blocking, as proc_spawn's and proc_pipe's are), -1 on error (a
// closed reader among them).
fn net_write_some(fd: i32, data: const u8[:]) -> i64 {
    if is_socket(fd) {
        let n = net::write_some(fd, data);
        return if n < 0 { -1 } else { n };
    }
    // A pipe or terminal: an ordinary write. (net's write_some would leave
    // it blocking, which a session's stdin must not be.)
    let w = sys::write(fd, data);
    if w >= 0 { return w; }
    return if sys::is_would_block(w) { 0 } else { -1 };
}

// Whether fd is a socket: S_IFSOCK in its type bits (sys's Stat.attrs).
fn is_socket(fd: i32) -> bool {
    var st = sys::Stat { .. };
    return sys::fstat(fd, st) == 0 && st.attrs == 0xc000;
}

fn net_close(fd: i32) { if fd >= 0 { sys::close(fd); } }

fn net_shutdown_write(fd: i32) { if fd >= 0 { net::shutdown(fd, net::SHUT_WRITE); } }

// --- The terminal ----------------------------------------------------------

var saved = term::State { .. };
var saved_ok = false;

fn tty_is(fd: i32) -> i32 { if term::is_terminal(fd) { 1 } else { 0 } }

fn tty_raw(fd: i32) -> i32 {
    if term::make_raw(fd, saved) < 0 { return -1; }
    saved_ok = true;
    return 0;
}

fn tty_restore(fd: i32) { if saved_ok { term::restore(fd, saved); } }

fn tty_size(fd: i32) -> i64, i64 {
    var w: i64 = 0;
    var h: i64 = 0;
    if term::get_size(fd, w, h) < 0 || w <= 0 || h <= 0 { return 80, 24; }
    return w, h;
}

fn tty_cols(fd: i32) -> i32 { let w, _ = tty_size(fd); return w as! i32; }
fn tty_rows(fd: i32) -> i32 { let _, h = tty_size(fd); return h as! i32; }

// A line from fd (to \n, or \r too with cr), without its end, into out:
// its length, or -2 if it did not fit (the rest of it read and dropped,
// never left for the next read, nor the line taken cut short).
fn read_line(fd: i64, out: u8[:], cr: bool) -> i64 {
    var n: i64 = 0;
    var over = false;
    var c: u8[1] = [0];
    while sys::read(fd, c[..]) == 1 && c[0] != '\n' && !(cr && c[0] == '\r') {
        if n < out.len { out[n] = c[0]; n++; } else { over = true; }
    }
    return if over { -2 } else { n };
}

// $SSH_ASKPASS run with the prompt, its first line of output the answer
// (-2 if too long), -1 if it fails.
fn askpass(prog: const u8[:], prompt: const u8[:], out: u8[:]) -> i64 {
    var c = process::Cmd { .. };
    process::arg(c, prog);
    process::arg(c, prompt);
    c.stdout = process::PIPE;
    var e: i64 = 0;
    var ch = process::start(c, e);
    if e != 0 { return -1; }
    let n = read_line(ch.stdout_fd, out, true);
    process::release(ch);
    var st = process::Status { .. };
    process::wait(ch, st);
    return if st.exited && st.code == 0 { n } else { -1 };
}

// A secret typed at the terminal, not echoed, or from $SSH_ASKPASS as
// OpenSSH's ssh has it: always with $SSH_ASKPASS_REQUIRE "force" or
// "prefer", never with "never", else when there is no terminal. Its
// length, -1 for neither, -2 if too long.
fn tty_secret(prompt: const u8[:], out: u8[:]) -> i64 {
    let prog = getenv("SSH_ASKPASS");
    let req = getenv("SSH_ASKPASS_REQUIRE");
    let use = prog.len > 0 && req != "never";
    if use && (req == "force" || req == "prefer") { return askpass(prog, prompt, out); }
    let fd = sys::open("/dev/tty", sys::O_RDWR, 0);
    if fd < 0 { return if use { askpass(prog, prompt, out) } else { -1 }; }
    if sys::write_all(fd, prompt) != 0 { sys::close(fd); return -1; }
    var line: u8[>..] = [];
    let e = term::read_password(fd, line);
    sys::write_all(fd, "\n");
    sys::close(fd);
    if e < 0 { return -1; }
    if line.len > out.len { return -2; }
    for i in line.len { out[i] = line[i]; }
    return line.len;
}

// A line typed at the terminal, echoed (for yes/no); -2 if too long.
fn tty_line(prompt: const u8[:], out: u8[:]) -> i64 {
    let fd = sys::open("/dev/tty", sys::O_RDWR, 0);
    if fd < 0 { return -1; }
    if sys::write_all(fd, prompt) != 0 { sys::close(fd); return -1; }
    let n = read_line(fd, out, false);
    sys::close(fd);
    return n;
}

// --- Processes -------------------------------------------------------------

// A child known by its pid alone, as the tools keep it; group: whether
// signals go to its whole process group (a session's child leads one).
fn child_of(pid: i32, group: bool) -> sys::Child {
    sys::Child { pid: pid, handle: if group { 1 } else { 0 }, stdin_fd: -1, stdout_fd: -1, stderr_fd: -1, pty: 0 }
}

// A session's command as OpenSSH runs it: the user's shell ($SHELL, else
// /bin/sh) with -c, or as a login shell for ""; in a session of its own,
// with every signal's disposition the default (the server ignores SIGPIPE,
// and nohup SIGHUP: ignored dispositions survive exec); in the user's home
// directory ($HOME, else the root); with env's NAME=VALUE lines added.
fn session_cmd(c: process::Cmd&, cmd: const u8[:], env: const u8[:]) {
    var sh = getenv("SHELL");
    if sh.len == 0 { sh.append("/bin/sh"); }
    c.path.append(sh);
    process::arg(c, sh);
    if cmd.len > 0 { process::arg(c, "-c"); process::arg(c, cmd); } else { process::arg(c, "-l"); }
    c.new_session = true;
    c.default_signals = true;
    let home = getenv("HOME");
    var st = sys::Stat { .. };
    if home.len > 0 && sys::stat(home, st) == 0 && sys::is_dir(st) { c.dir.append(home); } else { c.dir.append("/"); }
    var i: i64 = 0;
    while i < env.len {
        var j = i;
        while j < env.len && env[j] != '\n' { j++; }
        let line = env[i..j];
        var eq: i64 = -1;
        for k in line.len { if eq < 0 && line[k] == '=' { eq = k; } }
        if eq > 0 { process::setenv(c, line[..eq], line[eq + 1..]); }
        i = j + 1;
    }
}

// Runs cmd (session_cmd) on three pipes: its stdin, stdout and stderr ends
// through the references. The child's pid, or -1. in_fd is non-blocking
// (net_write_some): a blocking write there, with the child blocked writing a
// full stdout, would hang both.
fn proc_spawn(cmd: const u8[:], env: const u8[:], in_fd: i32&, out_fd: i32&, err_fd: i32&) -> i32 {
    var c = process::Cmd { .. };
    session_cmd(c, cmd, env);
    c.stdin = process::PIPE;
    c.stdout = process::PIPE;
    c.stderr = process::PIPE;
    var e: i64 = 0;
    let ch = process::start(c, e);
    if e != 0 { return -1; }
    sys::set_nonblock(ch.stdin_fd, 1);
    in_fd = ch.stdin_fd as! i32;
    out_fd = ch.stdout_fd as! i32;
    err_fd = ch.stderr_fd as! i32;
    return ch.pid as! i32;
}

// The same on a new pseudo-terminal of cols x rows, with TERM set: its
// master end through master, which carries stdin, stdout and stderr.
fn proc_spawn_pty(cmd: const u8[:], env: const u8[:], term_name: const u8[:], cols: i32, rows: i32, master: i32&) -> i32 {
    var c = process::Cmd { .. };
    if term_name.len > 0 { process::setenv(c, "TERM", term_name); }
    session_cmd(c, cmd, env);
    c.pty = true;
    c.cols = cols;
    c.rows = rows;
    var e: i64 = 0;
    let ch = process::start(c, e);
    if e != 0 { return -1; }
    sys::close(ch.stdout_fd);          // a second descriptor for the master: one is kept
    master = ch.stdin_fd as! i32;
    return ch.pid as! i32;
}

fn proc_resize(master: i32, cols: i32, rows: i32) {
    var ch = child_of(0, false);
    ch.stdin_fd = master;
    ch.pty = 1;
    sys::pty_resize(ch, cols, rows);
}

// A child's exit status: -1 while it runs (until_done: wait for it); 128
// plus the signal for one that was killed; 255 if it cannot be waited for.
fn proc_wait(pid: i32, until_done: i32) -> i32 {
    var ch = child_of(pid, false);
    var st = process::Status { .. };
    let r = process::wait(ch, st, if until_done != 0 { -1 } else { 0 });
    if r == 0 { return -1; }
    if r < 0 { return 255; }
    if st.exited { return st.code as! i32; }
    if st.signal > 0 { return (128 + st.signal) as! i32; }
    return 255;
}

// sig to a session's child and its process group.
fn proc_kill(pid: i32, sig: i32) {
    if pid <= 0 { return; }
    var ch = child_of(pid, true);
    process::kill(ch, sig);
}

// Ends a session's child: SIGHUP to its process group, up to two seconds
// to go, then SIGKILL. Its exit status, as proc_wait's.
fn proc_end(pid: i32) -> i32 {
    if pid <= 0 { return 255; }
    proc_kill(pid, unix::SIGHUP);
    var ch = child_of(pid, true);
    var st = process::Status { .. };
    if process::wait(ch, st, 2000) == 0 {
        proc_kill(pid, unix::SIGKILL);
        return proc_wait(pid, 1);
    }
    if st.exited { return st.code as! i32; }
    return if st.signal > 0 { (128 + st.signal) as! i32 } else { 255 };
}

// A client's proxy (-J, ProxyCommand): argv, its arguments each ended by a
// NUL, found on $PATH and run with its stdin and stdout on pipes and its
// stderr and terminal ours, in this directory. The pipes' ends through
// to_fd (its stdin) and from_fd (its stdout); to_fd is non-blocking
// (net_write waits on it, net_write_some does not). The pid, or -1.
fn proc_pipe(argv: const u8[:], to_fd: i32&, from_fd: i32&) -> i32 {
    if argv.len == 0 || argv[argv.len - 1] != 0 { return -1; }
    var c = process::Cmd { .. };
    c.argv.append(argv);
    c.default_signals = true;
    c.stdin = process::PIPE;
    c.stdout = process::PIPE;
    var e: i64 = 0;
    let ch = process::start(c, e);
    if e != 0 { return -1; }
    sys::set_nonblock(ch.stdin_fd, 1);
    to_fd = ch.stdin_fd as! i32;
    from_fd = ch.stdout_fd as! i32;
    return ch.pid as! i32;
}

// Ends a proxy whose pipes are closed: a second to go, then SIGTERM, a
// second more, then SIGKILL. Its exit status, as proc_wait's.
fn proc_pipe_end(pid: i32) -> i32 {
    if pid <= 0 { return 255; }
    let sigs: i32[3] = [0, unix::SIGTERM, unix::SIGKILL];
    for sig in sigs {
        var ch = child_of(pid, false);
        if sig != 0 { process::kill(ch, sig); }
        var st = process::Status { .. };
        if process::wait(ch, st, 1000) == 1 {
            if st.exited { return st.code as! i32; }
            return if st.signal > 0 { (128 + st.signal) as! i32 } else { 255 };
        }
    }
    return proc_wait(pid, 1);
}

// fork with a pipe from the child: fd its write end in the child, the read
// end in the parent, which sees it ready once the child closes it or ends
// (both ends close-on-exec). Children of the server are reaped as they end
// (proc_reap), so SIGCHLD keeps its default.
fn proc_fork_watched(fd: i32&) -> i32 {
    var p: i64[2] = [-1, -1];
    if sys::pipe(p[..]) < 0 { return -1; }
    unix::reset(unix::sigchld());
    let pid = sys::fork();
    if pid < 0 { sys::close(p[0]); sys::close(p[1]); return -1; }
    if pid == 0 { sys::close(p[0]); fd = p[1] as! i32; return 0; }
    sys::close(p[1]);
    fd = p[0] as! i32;
    return pid as! i32;
}

fn proc_reap() { sys::reap(); }

fn proc_exit(code: i32) { sys::exit_now(code); }

// --- Files -----------------------------------------------------------------

// Reads a private file (sys::read_private: not through a symbolic link,
// checked on the open descriptor) into out: its length, or -1 when it is not
// there, -2 when it cannot be opened, -3 not a regular file, -4 owned by
// another user, -5 group or others have access, -6 too long or unreadable.
fn os_read_private(path: const u8[:], out: u8[:]) -> i64 {
    var data: u8[>..] = [];
    let n = sys::read_private(path, data, out.len);
    if n >= 0 {
        for i in n { out[i] = data[i]; }
        return n;
    }
    if sys::is_not_exist(n) { return -1; }
    if n == sys::ERR_NOT_REGULAR { return -3; }
    if n == sys::ERR_TOO_LARGE { return -6; }
    if n == sys::ERR_NOT_PRIVATE {
        var st = sys::Stat { .. };
        if sys::lstat(path, st) == 0 && st.uid != sys::geteuid() { return -4; }
        return -5;
    }
    return -2;                          // a symbolic link among them (O_NOFOLLOW)
}

// Writes a secret file, mode 0600 from the moment it exists: never through
// a symbolic link. With replace 0 the file must not exist yet; with
// replace 1 a new file beside it is renamed over it, so the old one stays
// whole if anything fails. 0 or -1.
fn os_write_private(path: const u8[:], data: const u8[:], replace: i32) -> i32 {
    let e = if replace != 0 { sys::replace_file(path, data, 384) } else { sys::create_file(path, data, 384) };
    return if e == 0 { 0 } else { -1 };
}

// Reads what is there (up to 64 KB) into a builder: how many bytes, 0 at
// end of file, -1 on error.
fn read_some(fd: i32, out: u8[>..]&) -> i64 {
    var buf: u8[65536] = [0; 65536];
    let n = net_read(fd, buf);
    if n > 0 { out.append(buf[..n]); }
    return n;
}

// The user and home directory, from $USER (or $LOGNAME) and $HOME.
fn user_name() -> u8[>..] {
    var u = getenv("USER");
    if u.len == 0 { u = getenv("LOGNAME"); }
    return u;
}

fn home_dir() -> u8[>..] { getenv("HOME") }

// A secret (passphrase, password) or a line typed, up to 1 KiB: one
// longer is refused (empty), not cut short.
fn secret(prompt: const u8[:]) -> u8[>..] {
    var buf: u8[1024] = [0; 1024];
    let n = tty_secret(prompt, buf);
    var out: u8[>..] = [];
    if n == -2 { eprint("too long: not taken\n"); }
    if n > 0 { out.append(buf[..n]); }
    return out;
}

fn ask_line(prompt: const u8[:]) -> u8[>..] {
    var buf: u8[1024] = [0; 1024];
    let n = tty_line(prompt, buf);
    var out: u8[>..] = [];
    if n == -2 { eprint("too long: not taken\n"); }
    if n > 0 { out.append(buf[..n]); }
    return out;
}

// Text from the peer (a banner, a disconnect's or a refusal's message, a
// signal's name, an SFTP status) made safe for a terminal, as OpenSSH's
// does: printable ASCII, tabs, newlines and CRLF kept, and UTF-8 but for
// its control characters (C1); any other byte (a lone CR too) as \ooo.
fn safe_text(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let ch = s[i];
        let crlf = ch == '\r' && i + 1 < s.len && s[i + 1] == '\n';
        if (ch >= 0x20 && ch < 0x7f) || ch == '\n' || ch == '\t' || crlf { out.push(ch); i++; continue; }
        // A whole UTF-8 sequence, shortest form, not a surrogate, from U+00A0 on.
        var n = 0;
        var cp: u32 = 0;
        if ch >= 0xc2 && ch <= 0xdf { n = 2; cp = ch & 0x1f; }
        else if ch >= 0xe0 && ch <= 0xef { n = 3; cp = ch & 0x0f; }
        else if ch >= 0xf0 && ch <= 0xf4 { n = 4; cp = ch & 0x07; }
        var good = n > 0 && i + n <= s.len;
        if good {
            var j = 1;
            while j < n {
                if (s[i + j] & 0xc0) != 0x80 { good = false; }
                else { cp = (cp << 6) | (s[i + j] & 0x3f); }
                j++;
            }
        }
        let shortest = (n == 2 && cp >= 0x80) || (n == 3 && cp >= 0x800) || (n == 4 && cp >= 0x10000);
        if good && shortest && cp >= 0xa0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) {
            out.append(s[i..i + n]);
            i += n;
            continue;
        }
        out.push('\\');
        out.push('0' + (ch >> 6));
        out.push('0' + ((ch >> 3) & 7));
        out.push('0' + (ch & 7));
        i++;
    }
    return out;
}

fn eprint(s: const u8[:]) { write_stderr(s); }
