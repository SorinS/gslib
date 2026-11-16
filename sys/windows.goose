// windows: managing a Windows machine, as Go's iamacarpet/go-win64api
// does: local user accounts (list, add, delete, passwords, enable,
// disable, unlock), local groups and their members, Remote Desktop
// sessions, services with their configuration, shares, installed
// software (from the registry's Uninstall keys), and a process's owner and
// memory.
//
//   import gslib.sys.windows;
//
//   var e: i64 = 0;
//   for u in windows::users(e) {
//       print(u.name, if windows::is_disabled(u) { " (disabled)" } else { "" });
//   }
//
// Changing accounts, groups and shares takes an administrator. Results < 0
// are errors (sys::error_text says them in words; sys::is_exist and
// sys::is_not_exist sort them). Off Windows every call returns
// sys::ENOTSUP, and the lists are empty.

namespace windows;

import std;
import sys;
import sys.ffi;
import sys.registry;

// Account flags (UF_*).
let UF_ACCOUNTDISABLE:     i64 = 0x0002;
let UF_LOCKOUT:            i64 = 0x0010;
let UF_PASSWD_NOTREQD:     i64 = 0x0020;
let UF_PASSWD_CANT_CHANGE: i64 = 0x0040;
let UF_NORMAL_ACCOUNT:     i64 = 0x0200;
let UF_DONT_EXPIRE_PASSWD: i64 = 0x10000;

// Privilege levels.
let USER_PRIV_GUEST: i64 = 0;
let USER_PRIV_USER:  i64 = 1;
let USER_PRIV_ADMIN: i64 = 2;

// --- Local users ------------------------------------------------------------------------

struct User {
    flags:        i64,    // UF_*
    priv:         i64,    // USER_PRIV_*
    last_logon:   i64,    // seconds since 1970; 0 if never
    bad_pw_count: i64,
    num_logons:   i64,
    password_age: i64,    // seconds
    name:         u8[],
    full_name:    u8[],
    comment:      u8[],
    home_dir:     u8[],
}

fn is_disabled(u: const User&) -> bool { (u.flags & UF_ACCOUNTDISABLE) != 0 }
fn is_locked(u: const User&) -> bool { (u.flags & UF_LOCKOUT) != 0 }
fn is_admin_priv(u: const User&) -> bool { u.priv == USER_PRIV_ADMIN }
fn password_never_expires(u: const User&) -> bool { (u.flags & UF_DONT_EXPIRE_PASSWD) != 0 }

// This machine's local accounts. e is set to the error, 0 on success.
fn users(e: i64&) -> User[>..] {
    var b: u8[>..] = [];
    let n = sys::net_users(b);
    e = min(n, 0);
    var out: User[>..] = [];
    var pos: i64       = 0;
    for _ in max(n, 0) {
        let name = sys::field(b, pos);
        let full = sys::field(b, pos);
        let comment = sys::field(b, pos);
        let flags = sys::field_int(b, pos);
        let priv = sys::field_int(b, pos);
        let last = sys::field_int(b, pos);
        let bad = sys::field_int(b, pos);
        let logons = sys::field_int(b, pos);
        let age = sys::field_int(b, pos);
        let home = sys::field(b, pos);
        out.push(User { flags: flags, priv: priv, last_logon: last, bad_pw_count: bad, num_logons: logons,
                        password_age: age, name: name, full_name: full, comment: comment, home_dir: home });
    }
    return out;
}

// A new local account, an ordinary user, enabled, with the password given
// (the machine's password policy applies).
fn add_user(name: const u8[:], password: const u8[:], full_name: const u8[:] = "", comment: const u8[:] = "") -> i64 {
    sys::net_user_add(name, password, full_name, comment, UF_NORMAL_ACCOUNT)
}

fn delete_user(name: const u8[:]) -> i64 { sys::net_user_delete(name) }
fn set_password(name: const u8[:], password: const u8[:]) -> i64 { sys::net_user_set_password(name, password) }
fn set_full_name(name: const u8[:], full_name: const u8[:]) -> i64 { sys::net_user_set_full_name(name, full_name) }
fn disable_user(name: const u8[:]) -> i64 { sys::net_user_set_flags(name, UF_ACCOUNTDISABLE, 0) }
fn enable_user(name: const u8[:]) -> i64 { sys::net_user_set_flags(name, 0, UF_ACCOUNTDISABLE) }
fn unlock_user(name: const u8[:]) -> i64 { sys::net_user_set_flags(name, 0, UF_LOCKOUT) }

fn set_password_never_expires(name: const u8[:], never: bool) -> i64 {
    if never { sys::net_user_set_flags(name, UF_DONT_EXPIRE_PASSWD, 0) } else { sys::net_user_set_flags(name, 0, UF_DONT_EXPIRE_PASSWD) }
}

// --- Local groups -----------------------------------------------------------------------------

struct LocalGroup { name: u8[], comment: u8[] }

// A member: DOMAIN\name, its SID, and what it is (SID_USER, SID_GROUP, ...).
struct Member { kind: i64, name: u8[], sid: u8[] }

let SID_USER:       i64 = 1;
let SID_GROUP:      i64 = 2;
let SID_ALIAS:      i64 = 4;
let SID_WELL_KNOWN: i64 = 5;

// The Administrators group's SID, whatever the group is called in the
// system's language.
let ADMINISTRATORS_SID: const u8[:] = "S-1-5-32-544";

fn groups(e: i64&) -> LocalGroup[>..] {
    var b: u8[>..] = [];
    let n = sys::net_groups(b);
    e = min(n, 0);
    var out: LocalGroup[>..] = [];
    var pos: i64             = 0;
    for _ in max(n, 0) {
        let name = sys::field(b, pos);
        let comment = sys::field(b, pos);
        out.push(LocalGroup { name: name, comment: comment });
    }
    return out;
}

fn add_group(name: const u8[:], comment: const u8[:] = "") -> i64 { sys::net_group_add(name, comment) }
fn delete_group(name: const u8[:]) -> i64 { sys::net_group_delete(name) }

fn group_members(name: const u8[:], e: i64&) -> Member[>..] {
    var b: u8[>..] = [];
    let n = sys::net_group_members(name, b);
    e = min(n, 0);
    var out: Member[>..] = [];
    var pos: i64         = 0;
    for _ in max(n, 0) {
        let m = sys::field(b, pos);
        let sid = sys::field(b, pos);
        let kind = sys::field_int(b, pos);
        out.push(Member { kind: kind, name: m, sid: sid });
    }
    return out;
}

// member is "name" for a local account or "DOMAIN\name".
fn add_member(group: const u8[:], member: const u8[:]) -> i64 { sys::net_group_add_member(group, member) }
fn remove_member(group: const u8[:], member: const u8[:]) -> i64 { sys::net_group_remove_member(group, member) }

// The local Administrators group's name (localized).
fn administrators() -> u8[>..] {
    var e: i64 = 0;
    let g = sys::lookup_group_id(ADMINISTRATORS_SID, e);
    var name: u8[>..] = [];
    if e == 0 { name.append(g.name); }
    return name;
}

// Whether the local account user is in the Administrators group, directly.
fn is_admin(user: const u8[:]) -> bool {
    var e: i64 = 0;
    let me = sys::lookup_user(user, e);
    if e != 0 { return false; }
    for m in group_members(administrators(), e) {
        if m.sid == me.uid { return true; }
    }
    return false;
}

// --- Sessions -----------------------------------------------------------------------------------

// Session states (WTS_CONNECTSTATE_CLASS).
let SESSION_ACTIVE:       i64 = 0;
let SESSION_CONNECTED:    i64 = 1;
let SESSION_CONNECTQUERY: i64 = 2;
let SESSION_SHADOW:       i64 = 3;
let SESSION_DISCONNECTED: i64 = 4;
let SESSION_IDLE:         i64 = 5;
let SESSION_LISTEN:       i64 = 6;
let SESSION_RESET:        i64 = 7;
let SESSION_DOWN:         i64 = 8;
let SESSION_INIT:         i64 = 9;

struct Session {
    id:         i64,
    state:      i64,     // SESSION_*
    logon_time: i64,     // seconds since 1970; 0 unknown
    station:    u8[],    // "Console", "RDP-Tcp#3", "Services"
    user:       u8[],
    domain:     u8[],
    client:     u8[],    // the remote client's name
}

fn sessions(e: i64&) -> Session[>..] {
    var b: u8[>..] = [];
    let n = sys::sessions(b);
    e = min(n, 0);
    var out: Session[>..] = [];
    var pos: i64          = 0;
    for _ in max(n, 0) {
        let id = sys::field_int(b, pos);
        let state = sys::field_int(b, pos);
        let station = sys::field(b, pos);
        let user = sys::field(b, pos);
        let domain = sys::field(b, pos);
        let client = sys::field(b, pos);
        let logon = sys::field_int(b, pos);
        out.push(Session { id: id, state: state, logon_time: logon, station: station, user: user,
                           domain: domain, client: client });
    }
    return out;
}

// --- Services --------------------------------------------------------------------------------------

// Service states.
let SERVICE_STOPPED:          i64 = 1;
let SERVICE_START_PENDING:    i64 = 2;
let SERVICE_STOP_PENDING:     i64 = 3;
let SERVICE_RUNNING:          i64 = 4;
let SERVICE_CONTINUE_PENDING: i64 = 5;
let SERVICE_PAUSE_PENDING:    i64 = 6;
let SERVICE_PAUSED:           i64 = 7;

// Start types.
let SERVICE_BOOT_START:   i64 = 0;
let SERVICE_SYSTEM_START: i64 = 1;
let SERVICE_AUTO_START:   i64 = 2;
let SERVICE_DEMAND_START: i64 = 3;
let SERVICE_DISABLED:     i64 = 4;

struct Service {
    kind:         i64,   // SERVICE_WIN32_OWN_PROCESS 0x10, SHARE_PROCESS 0x20, ...
    state:        i64,   // SERVICE_STOPPED ...
    pid:          i64,   // 0 when not running
    start_type:   i64,   // SERVICE_AUTO_START ...; -1 if its configuration could not be read
    name:         u8[],
    display_name: u8[],
    binary_path:  u8[],
    account:      u8[],  // "LocalSystem", "NT AUTHORITY\LocalService", ...
}

// The Win32 services, running or not. (gslib.service installs, starts and
// stops them.)
fn services(e: i64&) -> Service[>..] {
    var b: u8[>..] = [];
    let n = sys::services(b);
    e = min(n, 0);
    var out: Service[>..] = [];
    var pos: i64          = 0;
    for _ in max(n, 0) {
        let name = sys::field(b, pos);
        let display = sys::field(b, pos);
        let kind = sys::field_int(b, pos);
        let state = sys::field_int(b, pos);
        let pid = sys::field_int(b, pos);
        let start = sys::field_int(b, pos);
        let path = sys::field(b, pos);
        let account = sys::field(b, pos);
        out.push(Service { kind: kind, state: state, pid: pid, start_type: start, name: name,
                           display_name: display, binary_path: path, account: account });
    }
    return out;
}

// --- Shares -----------------------------------------------------------------------------------------

let STYPE_DISKTREE: i64 = 0;
let STYPE_PRINTQ:   i64 = 1;
let STYPE_DEVICE:   i64 = 2;
let STYPE_IPC:      i64 = 3;
let STYPE_SPECIAL:  i64 = 0x80000000;    // added to an administrative share's type (C$, ADMIN$)

struct Share {
    kind:         i64,   // STYPE_*
    max_uses:     i64,   // -1 unlimited, or unknown without an administrator
    current_uses: i64,
    name:         u8[],
    remark:       u8[],
    path:         u8[],  // "" without an administrator
}

fn shares(e: i64&) -> Share[>..] {
    var b: u8[>..] = [];
    let n = sys::shares(b);
    e = min(n, 0);
    var out: Share[>..] = [];
    var pos: i64        = 0;
    for _ in max(n, 0) {
        let name = sys::field(b, pos);
        let kind = sys::field_int(b, pos);
        let remark = sys::field(b, pos);
        let path = sys::field(b, pos);
        let maxu = sys::field_int(b, pos);
        let cur = sys::field_int(b, pos);
        out.push(Share { kind: kind, max_uses: maxu, current_uses: cur, name: name, remark: remark, path: path });
    }
    return out;
}

// Shares directory path as name (a disk share, unlimited users; who may
// use it is the directory's own permissions).
fn add_share(name: const u8[:], path: const u8[:], remark: const u8[:] = "") -> i64 { sys::share_add(name, path, remark) }
fn delete_share(name: const u8[:]) -> i64 { sys::share_delete(name) }

// --- Installed software ---------------------------------------------------------------------------------

struct Software {
    size_kb:          i64,       // EstimatedSize; 0 unknown
    name:             u8[],      // DisplayName
    version:          u8[],
    publisher:        u8[],
    install_date:     u8[],      // as recorded: usually YYYYMMDD
    install_location: u8[],
    uninstall_string: u8[],
    scope:            u8[],      // "x64", "x86" (the 32-bit view) or "user"
}

let UNINSTALL: const u8[:] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

fn add_software(out: Software[>..]&, root: i64, access: i64, scope: const u8[:]) {
    let k = registry::open_key(root, UNINSTALL, registry::READ | access);
    if k < 0 { return; }
    var e: i64 = 0;
    for sub in registry::read_subkey_names(k, e) {
        let s = registry::open_key(k, sub, registry::QUERY_VALUE);
        if s < 0 { continue; }
        let name = registry::string_value(s, "DisplayName");
        var system: i64 = 0;
        registry::get_integer(s, "SystemComponent", system);
        let has_parent = registry::string_value(s, "ParentKeyName").len > 0;
        // Updates and parts of something else are not programs of their own,
        // as Programs and Features lists them.
        if name.len > 0 && system == 0 && !has_parent {
            var size: i64 = 0;
            registry::get_integer(s, "EstimatedSize", size);
            out.push(Software { size_kb: size, name: copy(name),
                                version:          registry::string_value(s, "DisplayVersion"),
                                publisher:        registry::string_value(s, "Publisher"),
                                install_date:     registry::string_value(s, "InstallDate"),
                                install_location: registry::string_value(s, "InstallLocation"),
                                uninstall_string: registry::string_value(s, "UninstallString"),
                                scope: scope });
        }
        registry::close(s);
    }
    registry::close(k);
}

// The programs Programs and Features lists: the machine's (both views)
// and the current user's. e is set to sys::ENOTSUP off Windows.
fn installed_software(e: i64&) -> Software[>..] {
    var out: Software[>..] = [];
    e = if sys::platform() == sys::PLATFORM_WINDOWS { 0 } else { sys::ENOTSUP };
    if e != 0 { return out; }
    add_software(out, registry::LOCAL_MACHINE, registry::WOW64_64KEY, "x64");
    add_software(out, registry::LOCAL_MACHINE, registry::WOW64_32KEY, "x86");
    add_software(out, registry::CURRENT_USER, 0, "user");
    return out;
}

// --- A process's owner and memory --------------------------------------------------------------------------

// DOMAIN\name of the account process pid runs as ("" when it cannot be
// read: another user's process, without an administrator).
fn process_owner(pid: i64) -> u8[>..] {
    var s: u8[>..] = [];
    if sys::process_owner(pid, s) < 0 { s.clear(); }
    return s;
}

struct ProcessMemory { working_set: i64, peak_working_set: i64, pagefile: i64, peak_pagefile: i64 }

fn process_memory(pid: i64, m: ProcessMemory&) -> i64 {
    var v: i64[4] = [0; 4];
    let e = sys::process_memory(pid, v[..]);
    if e == 0 { m = ProcessMemory { v[0], v[1], v[2], v[3] }; }
    return e;
}
