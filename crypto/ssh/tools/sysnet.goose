// The operating system for tools/ssh.goose and tools/sshd.goose: the C of
// tools/net.c (sockets, polling, the terminal, child processes), declared
// for Goose, and a few helpers. Each root file's .build sidecar compiles
// net.c.
namespace sysnet;

import std;
import os;

extern fn net_init();
extern fn net_connect(host: const u8[:], port: i32) -> i32;
extern fn net_listen(addr: const u8[:], port: i32) -> i32;
extern fn net_accept(fd: i32, peer: u8[:], peer_len: i64&, peer_port: i32&) -> i32;
extern fn net_local_port(fd: i32) -> i32;
// ready[i] = 1 for each fds[i] (-1: none) readable or closed; how many, 0 on timeout.
extern fn net_poll_set(fds: const i32[:], ready: u8[:], timeout_ms: i32) -> i32;
// The same, waiting instead for fds[i] to take a write where write[i] != 0.
extern fn net_poll_rw(fds: const i32[:], write: const u8[:], ready: u8[:], timeout_ms: i32) -> i32;
extern fn net_read(fd: i32, buf: u8[:]) -> i64;
// All of data (waiting while a non-blocking fd is full), or -1.
extern fn net_write(fd: i32, data: const u8[:]) -> i64;
// One write of what fits: bytes written, 0 when the fd is full (a socket's
// write never waits, another fd's unless non-blocking), -1 on error.
extern fn net_write_some(fd: i32, data: const u8[:]) -> i64;
extern fn net_close(fd: i32);
extern fn net_shutdown_write(fd: i32);
// Bit i set when the i-th descriptor (-1: none) is readable or closed; 0 on timeout.
extern fn net_poll(a: i32, b: i32, c: i32, d: i32, timeout_ms: i32) -> i32;

extern fn tty_is(fd: i32) -> i32;
extern fn tty_raw(fd: i32) -> i32;
extern fn tty_restore(fd: i32);
extern fn tty_cols(fd: i32) -> i32;
extern fn tty_rows(fd: i32) -> i32;
extern fn tty_secret(prompt: const u8[:], out: u8[:]) -> i64;
extern fn tty_line(prompt: const u8[:], out: u8[:]) -> i64;

// env: NAME=VALUE lines for the child. cmd "" runs the user's login shell.
// in_fd is non-blocking: write to it with net_write_some.
extern fn proc_spawn(cmd: const u8[:], env: const u8[:], in_fd: i32&, out_fd: i32&, err_fd: i32&) -> i32;
extern fn proc_spawn_pty(cmd: const u8[:], env: const u8[:], term: const u8[:], cols: i32, rows: i32, master: i32&) -> i32;
extern fn proc_resize(master: i32, cols: i32, rows: i32);
extern fn proc_wait(pid: i32, wait: i32) -> i32;
extern fn proc_kill(pid: i32, sig: i32);
extern fn proc_end(pid: i32) -> i32;
extern fn proc_fork() -> i32;
// fork with a pipe from the child: *fd its write end in the child, the
// read end in the parent, which sees it ready once the child closes it or
// ends (both ends close-on-exec).
extern fn proc_fork_watched(fd: i32&) -> i32;
extern fn proc_reap();
extern fn proc_exit(code: i32);
// argv: each argument ended by a NUL. to_fd is its stdin (non-blocking),
// from_fd its stdout.
extern fn proc_pipe(argv: const u8[:], to_fd: i32&, from_fd: i32&) -> i32;
extern fn proc_pipe_end(pid: i32) -> i32;

extern fn os_user(out: u8[:]) -> i64;
extern fn os_home(out: u8[:]) -> i64;
extern fn os_read_private(path: const u8[:], out: u8[:]) -> i64;
extern fn os_write_private(path: const u8[:], data: const u8[:], replace: i32) -> i32;

// Reads what is there (up to 64 KB) into a builder: how many bytes, 0 at
// end of file, -1 on error.
fn read_some(fd: i32, out: u8[>..]&) -> i64 {
    var buf: u8[65536] = [0; 65536];
    let n = net_read(fd, buf);
    if n > 0 { out.append(buf[..n]); }
    return n;
}

// The user and home directory, from $USER (or $LOGNAME) and $HOME: one
// too long to take is an error, never cut short.
fn user_name() -> u8[>..] {
    var buf: u8[256] = [0; 256];
    let n = os_user(buf);
    if n < 0 { eprint("$USER is too long\n"); exit(255); }
    var out: u8[>..] = [];
    out.append(buf[..n]);
    return out;
}

fn home_dir() -> u8[>..] {
    var buf: u8[4096] = [0; 4096];
    let n = os_home(buf);
    if n < 0 { eprint("$HOME is too long\n"); exit(255); }
    var out: u8[>..] = [];
    out.append(buf[..n]);
    return out;
}

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
