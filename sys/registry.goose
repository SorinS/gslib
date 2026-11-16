// registry: the Windows registry, as Go's golang.org/x/sys/windows/registry
// has it: keys opened or created under a root, values read and written by
// type, subkeys and value names listed, keys deleted.
//
//   import gslib.sys.registry;
//
//   var k = registry::open_key(registry::LOCAL_MACHINE,
//       "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry::QUERY_VALUE);
//   if k >= 0 {
//       var name: u8[>..] = [];
//       registry::get_string(k, "ProductName", name);
//       registry::close(k);
//   }
//
// A key is an i64; a negative one, like every other negative result, is
// an error (the negated Win32 code: sys::error_text says it in words, and
// ERR_NOT_EXIST is the one for a key or value that is not there). Off
// Windows every call returns sys::ENOTSUP.

namespace registry;

import std;
import sys;
import sys.ffi;

// The roots.
let CLASSES_ROOT:     i64 = 0x80000000;
let CURRENT_USER:     i64 = 0x80000001;
let LOCAL_MACHINE:    i64 = 0x80000002;
let USERS:            i64 = 0x80000003;
let PERFORMANCE_DATA: i64 = 0x80000004;
let CURRENT_CONFIG:   i64 = 0x80000005;

// Access, combined with |.
let QUERY_VALUE:        i64 = 0x0001;
let SET_VALUE:          i64 = 0x0002;
let CREATE_SUB_KEY:     i64 = 0x0004;
let ENUMERATE_SUB_KEYS: i64 = 0x0008;
let NOTIFY:             i64 = 0x0010;
let CREATE_LINK:        i64 = 0x0020;
let WOW64_64KEY:        i64 = 0x0100;     // the 64-bit view from a 32-bit program
let WOW64_32KEY:        i64 = 0x0200;     // the 32-bit view from a 64-bit program
let READ:               i64 = 0x20019;
let WRITE:              i64 = 0x20006;
let ALL_ACCESS:         i64 = 0xf003f;

// Value types.
let NONE:                       i64 = 0;
let SZ:                         i64 = 1;
let EXPAND_SZ:                  i64 = 2;
let BINARY:                     i64 = 3;
let DWORD:                      i64 = 4;
let DWORD_BIG_ENDIAN:           i64 = 5;
let LINK:                       i64 = 6;
let MULTI_SZ:                   i64 = 7;
let RESOURCE_LIST:              i64 = 8;
let FULL_RESOURCE_DESCRIPTOR:   i64 = 9;
let RESOURCE_REQUIREMENTS_LIST: i64 = 10;
let QWORD:                      i64 = 11;

// No such key or value (ERROR_FILE_NOT_FOUND), and a value of another
// type than the call reads (ERROR_UNSUPPORTED_TYPE).
let ERR_NOT_EXIST:       i64 = -2;
let ERR_UNEXPECTED_TYPE: i64 = -1630;

// --- Keys ------------------------------------------------------------------------

// Opens root\path: the key, or an error.
fn open_key(root: i64, path: const u8[:], access: i64) -> i64 { sys::reg_open(root, path, access) }

// Opens root\path, creating it (and the keys above it) if it is not
// there: the key, or an error. existed says which.
fn create_key(root: i64, path: const u8[:], access: i64, existed: bool&) -> i64 {
    var ex: i64[1] = [0];
    let k = sys::reg_create(root, path, access, ex[..]);
    existed = ex[0] != 0;
    return k;
}

fn close(k: i64) -> i64 { sys::reg_close(k) }

// Deletes root\path, which must have no subkeys. access may hold
// WOW64_32KEY or WOW64_64KEY to say which view.
fn delete_key(root: i64, path: const u8[:], access: i64 = 0) -> i64 { sys::reg_delete_key(root, path, access) }

// Deletes root\path and everything under it; a key that is not there is
// not an error.
fn delete_tree(root: i64, path: const u8[:]) -> i64 { sys::reg_delete_tree(root, path) }

// The names of k's subkeys. e is set to the error, 0 on success.
fn read_subkey_names(k: i64, e: i64&) -> u8[][>..] {
    var b: u8[>..] = [];
    let n = sys::reg_subkeys(k, b);
    e = min(n, 0);
    return sys::strings_of(b, max(n, 0));
}

// The names of k's values ("" is its default value).
fn read_value_names(k: i64, e: i64&) -> u8[][>..] {
    var b: u8[>..] = [];
    let n = sys::reg_value_names(k, b);
    e = min(n, 0);
    return sys::strings_of(b, max(n, 0));
}

// Go's KeyInfo.
struct KeyInfo {
    subkeys:            i64,
    max_subkey_len:     i64,
    values:             i64,
    max_value_name_len: i64,
    max_value_len:      i64,
    mod_time_ns:        i64, // last written, nanoseconds since 1970
}

fn stat(k: i64, info: KeyInfo&) -> i64 {
    var v: i64[6] = [0; 6];
    let e = sys::reg_info(k, v[..]);
    if e == 0 {
        info = KeyInfo { subkeys: v[0], max_subkey_len: v[1], values: v[2],
                         max_value_name_len: v[3], max_value_len: v[4], mod_time_ns: v[5] };
    }
    return e;
}

// --- Values ---------------------------------------------------------------------------

// A value's type and, in size, its length in bytes; or an error.
fn value_type(k: i64, name: const u8[:], size: i64&) -> i64 {
    var s: i64[1] = [0];
    let t = sys::reg_value_type(k, name, s[..]);
    size = s[0];
    return t;
}

// A SZ or EXPAND_SZ value, appended to out (not expanded: see
// expand_string): its type, or an error (ERR_UNEXPECTED_TYPE for another
// type).
fn get_string(k: i64, name: const u8[:], out: u8[>..]&) -> i64 { sys::reg_get_string(k, name, out) }

// A SZ or EXPAND_SZ value, "" when it cannot be read.
fn string_value(k: i64, name: const u8[:]) -> u8[>..] {
    var s: u8[>..] = [];
    if sys::reg_get_string(k, name, s) < 0 { s.clear(); }
    return s;
}

// A MULTI_SZ value's strings. e is set to the error, 0 on success.
fn get_strings(k: i64, name: const u8[:], e: i64&) -> u8[][>..] {
    var b: u8[>..] = [];
    let n = sys::reg_get_strings(k, name, b);
    e = min(n, 0);
    return sys::strings_of(b, max(n, 0));
}

// A DWORD, DWORD_BIG_ENDIAN or QWORD value into v: its type, or an error.
fn get_integer(k: i64, name: const u8[:], v: i64&) -> i64 {
    var o: i64[1] = [0];
    let t = sys::reg_get_int(k, name, o[..]);
    v = o[0];
    return t;
}

// Any value's bytes as stored, appended to out: its type, or an error.
fn get_binary(k: i64, name: const u8[:], out: u8[>..]&) -> i64 { sys::reg_get_binary(k, name, out) }

fn set_string(k: i64, name: const u8[:], value: const u8[:]) -> i64 { sys::reg_set_string(k, name, value, SZ as! i32) }
fn set_expand_string(k: i64, name: const u8[:], value: const u8[:]) -> i64 { sys::reg_set_string(k, name, value, EXPAND_SZ as! i32) }

// A MULTI_SZ value; none of the strings may be empty or hold a NUL.
fn set_strings(k: i64, name: const u8[:], values: const u8[][:]) -> i64 {
    var b: u8[>..] = [];
    for v in values {
        if v.len == 0 { return -87; }
        b.append(v);
        b.push(0);
    }
    return sys::reg_set_strings(k, name, b);
}

// The same, from a list of slices (["a", "b"]).
fn set_strings(k: i64, name: const u8[:], values: const u8[:][:]) -> i64 {
    var b: u8[>..] = [];
    for v in values {
        if v.len == 0 { return -87; }
        b.append(v);
        b.push(0);
    }
    return sys::reg_set_strings(k, name, b);
}

fn set_dword(k: i64, name: const u8[:], v: u32) -> i64 { sys::reg_set_int(k, name, v, DWORD as! i32) }
fn set_qword(k: i64, name: const u8[:], v: u64) -> i64 { sys::reg_set_int(k, name, v as! i64, QWORD as! i32) }
fn set_binary(k: i64, name: const u8[:], v: const u8[:]) -> i64 { sys::reg_set_binary(k, name, v) }

fn delete_value(k: i64, name: const u8[:]) -> i64 { sys::reg_delete_value(k, name) }

// %NAME% replaced by the environment variable's value (Windows), as an
// EXPAND_SZ value means it; elsewhere $NAME and ${NAME}.
fn expand_string(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    sys::expand_env(s, out);
    return out;
}
