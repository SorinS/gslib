// registry: keys and values of every type under a key of its own in
// HKEY_CURRENT_USER\Software, deleted at the end; a value Windows always
// has; expand_string. Off Windows every registry call is sys::ENOTSUP.
// Only failures are printed, so the output is the same everywhere.

import std;
import gslib from "../..";
import gslib.sys;
import gslib.sys.registry;

var failed = 0;

fn check(ok: bool, what: const u8[:]) {
    if !ok { print("FAIL ", what); failed += 1; }
}

fn windows() {
    let path = str("Software\\gslib-sys-test-", sys::getpid());
    var existed = true;
    let k = registry::create_key(registry::CURRENT_USER, path, registry::ALL_ACCESS, existed);
    check(k >= 0 && !existed, "create_key");
    let k2 = registry::create_key(registry::CURRENT_USER, path, registry::READ, existed);
    check(k2 >= 0 && existed && registry::close(k2) == 0, "create_key: it exists");

    check(registry::set_string(k, "s", "hello, wörld") == 0, "set_string");
    var s: u8[>..] = [];
    check(registry::get_string(k, "s", s) == registry::SZ && s == "hello, wörld", "get_string");
    check(registry::set_expand_string(k, "x", "%SystemRoot%\\x") == 0, "set_expand_string");
    s.clear();
    check(registry::get_string(k, "x", s) == registry::EXPAND_SZ && s == "%SystemRoot%\\x", "get_string: not expanded");
    let ex = registry::expand_string(s);
    check(ex.len > 3 && ex[ex.len - 2..] == "\\x" && ex[0] != '%', "expand_string");
    check(registry::set_strings(k, "m", ["one", "two words", "three"]) == 0, "set_strings");
    var e: i64 = 0;
    let m = registry::get_strings(k, "m", e);
    var joined: u8[>..] = [];
    for x in m { joined.append(x); joined.push('|'); }
    check(e == 0 && m.len == 3 && joined == "one|two words|three|", "get_strings");
    check(registry::set_strings(k, "bad", ["a", ""]) < 0, "set_strings: no empty string");
    check(registry::set_dword(k, "d", 0xdeadbeef) == 0 && registry::set_qword(k, "q", 0x0123456789abcdef) == 0, "set_dword, set_qword");
    var v: i64 = 0;
    check(registry::get_integer(k, "d", v) == registry::DWORD && v == 0xdeadbeef, "get_integer: DWORD");
    check(registry::get_integer(k, "q", v) == registry::QWORD && v == 0x0123456789abcdef, "get_integer: QWORD");
    check(registry::set_binary(k, "b", "\x00\x01\x02\xff") == 0, "set_binary");
    var bin: u8[>..] = [];
    check(registry::get_binary(k, "b", bin) == registry::BINARY && bin == "\x00\x01\x02\xff", "get_binary");
    var size: i64 = 0;
    check(registry::value_type(k, "q", size) == registry::QWORD && size == 8, "value_type");
    s.clear();
    check(registry::get_string(k, "d", s) == registry::ERR_UNEXPECTED_TYPE, "get_string of a DWORD");
    check(registry::get_integer(k, "none", v) == registry::ERR_NOT_EXIST, "a value that is not there");
    check(registry::string_value(k, "none") == "", "string_value: empty when missing");

    // Subkeys, names, info.
    let sub = registry::create_key(k, "child", registry::ALL_ACCESS, existed);
    check(sub >= 0 && registry::set_string(sub, "", "default") == 0 && registry::close(sub) == 0, "a subkey with a default value");
    let subs = registry::read_subkey_names(k, e);
    var n = 0;
    for x in subs { if x == "child" { n += 1; } }
    check(e == 0 && subs.len == 1 && n == 1, "read_subkey_names");
    let names = registry::read_value_names(k, e);
    check(e == 0 && names.len == 6, "read_value_names");
    var info = registry::KeyInfo { .. };
    check(registry::stat(k, info) == 0 && info.subkeys == 1 && info.values == 6 && info.mod_time_ns > 0, "stat");
    check(registry::delete_value(k, "s") == 0 && registry::get_string(k, "s", s) == registry::ERR_NOT_EXIST, "delete_value");
    check(registry::delete_key(registry::CURRENT_USER, path) < 0, "delete_key: not while it has a subkey");
    check(registry::close(k) == 0, "close");
    check(registry::delete_tree(registry::CURRENT_USER, path) == 0, "delete_tree");
    check(registry::open_key(registry::CURRENT_USER, path, registry::READ) == registry::ERR_NOT_EXIST, "gone");
    check(registry::delete_tree(registry::CURRENT_USER, path) == 0, "delete_tree: already gone");

    // A value every Windows has.
    let cv = registry::open_key(registry::LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry::QUERY_VALUE);
    check(cv >= 0 && registry::string_value(cv, "ProductName").len > 0 && registry::close(cv) == 0, "ProductName");
}

fn elsewhere() {
    var existed = false;
    check(registry::open_key(registry::LOCAL_MACHINE, "SOFTWARE", registry::READ) == sys::ENOTSUP, "open_key: ENOTSUP");
    check(registry::create_key(registry::CURRENT_USER, "x", registry::ALL_ACCESS, existed) == sys::ENOTSUP, "create_key: ENOTSUP");
    var e: i64 = 0;
    check(registry::read_subkey_names(0, e).len == 0 && e == sys::ENOTSUP, "read_subkey_names: ENOTSUP");
    check(sys::setenv("GSSYS_X", "v") == 0 && registry::expand_string("a${GSSYS_X}b$GSSYS_X/$") == "avbv/$", "expand_string: $NAME");
}

fn main() {
    if sys::platform() == sys::PLATFORM_WINDOWS { windows(); } else { elsewhere(); }
    if failed > 0 { print(failed, " failed"); exit(1); }
    print("all passed");
}
