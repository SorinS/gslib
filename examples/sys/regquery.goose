// regquery: a registry key's values and subkeys, as `reg query` prints
// them (Windows; elsewhere it says the registry is not there).
//
//   goose run regquery.goose -- "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

import std;
import os;
import gslib from "../..";
import gslib.sys;
import gslib.sys.registry;

fn type_name(t: i64) -> const u8[:] {
    return if t == registry::SZ { "REG_SZ" } else if t == registry::EXPAND_SZ { "REG_EXPAND_SZ" }
    else if t == registry::MULTI_SZ { "REG_MULTI_SZ" } else if t == registry::DWORD { "REG_DWORD" }
    else if t == registry::QWORD { "REG_QWORD" } else if t == registry::BINARY { "REG_BINARY" }
    else { "REG_OTHER" };
}

fn hex(b: const u8[:]) -> u8[>..] {
    let digits = "0123456789ABCDEF";
    var s: u8[>..] = [];
    for x in b { s.push(digits[x >> 4]); s.push(digits[x & 15]); }
    return s;
}

fn main() {
    if sys::platform() != sys::PLATFORM_WINDOWS { print("regquery: Windows only"); return; }
    let argv = args();
    let full = if argv.len > 1 { argv[1] } else { "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" };
    var slash: i64 = full.len;
    for i in full.len { if full[i] == '\\' && slash == full.len { slash = i; } }
    let rootname = full[..slash];
    let path = if slash < full.len { full[slash + 1..] } else { full[full.len..] };
    let root = if rootname == "HKLM" || rootname == "HKEY_LOCAL_MACHINE" { registry::LOCAL_MACHINE }
               else if rootname == "HKCU" || rootname == "HKEY_CURRENT_USER" { registry::CURRENT_USER }
               else if rootname == "HKCR" || rootname == "HKEY_CLASSES_ROOT" { registry::CLASSES_ROOT }
               else if rootname == "HKU" || rootname == "HKEY_USERS" { registry::USERS }
               else { 0 };
    if root == 0 { print("regquery: unknown root ", rootname); exit(1); }
    let k = registry::open_key(root, path, registry::READ);
    if k < 0 { print("regquery: ", full, ": ", sys::error_text(k)); exit(1); }
    print(full);
    var e: i64 = 0;
    for name in registry::read_value_names(k, e) {
        var size: i64 = 0;
        let t = registry::value_type(k, name, size);
        var shown: u8[>..] = [];
        if t == registry::SZ || t == registry::EXPAND_SZ {
            registry::get_string(k, name, shown);
        } else if t == registry::DWORD || t == registry::QWORD {
            var v: i64 = 0;
            registry::get_integer(k, name, v);
            shown.append(str(v));
        } else if t == registry::MULTI_SZ {
            for s in registry::get_strings(k, name, e) { if shown.len > 0 { shown.append("\\0"); } shown.append(s); }
        } else {
            var b: u8[>..] = [];
            registry::get_binary(k, name, b);
            shown.append(hex(b[..min(b.len, 32)]));
            if b.len > 32 { shown.append("..."); }
        }
        print("    ", if name.len == 0 { "(Default)" } else { name }, "    ", type_name(t), "    ", shown);
    }
    print("");
    for sub in registry::read_subkey_names(k, e) { print(full, "\\", sub); }
    registry::close(k);
}
