// The operating system for the goose-ldap* tools: the C of tools/net.c
// (sockets, waiting, the terminal), declared for Goose. Each root file's
// .build sidecar compiles net.c.
namespace sysnet;

import std;
import os;

extern fn net_init();
extern fn net_connect(host: const u8[:], port: i32) -> i32;
extern fn net_connect_unix(path: const u8[:]) -> i32;
// How many bytes, 0 at end of file, -1 on error, -2 on timeout.
extern fn net_read(fd: i32, buf: u8[:], timeout_ms: i32) -> i64;
extern fn net_write(fd: i32, data: const u8[:]) -> i64;
extern fn net_close(fd: i32);
extern fn tty_secret(prompt: const u8[:], out: u8[:]) -> i64;

fn secret(prompt: const u8[:]) -> u8[>..], bool {
    var buf: u8[1024] = [0; 1024];
    let n = tty_secret(prompt, buf);
    var out: u8[>..] = [];
    if n > 0 { out.append(buf[..n]); }
    return out, n >= 0;
}

fn eprint(s: const u8[:]) { write_stderr(s); }
