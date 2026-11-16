// windows: local accounts and groups changed and put back (a user and a
// group of its own, named ostest and the process id, deleted at the end),
// sessions, services, shares (one of its own, removed), installed software,
// this process's owner and memory. It needs an administrator on Windows;
// elsewhere each call is sys::ENOTSUP. Only failures are printed.

import std;
import os;
import gslib from "../..";
import gslib.sys;
import gslib.sys.windows;

var failed = 0;

fn check(ok: bool, what: const u8[:]) {
    if !ok { print("FAIL ", what); failed += 1; }
}

// The account's flags, full name and comment, if it is listed.
fn find_user(name: const u8[:], flags: i64&, full: u8[>..]&, comment: u8[>..]&) -> bool {
    var e: i64 = 0;
    for x in windows::users(e) {
        if x.name == name {
            flags = x.flags;
            full.clear();
            full.append(x.full_name);
            comment.clear();
            comment.append(x.comment);
            return true;
        }
    }
    return false;
}

fn accounts() {
    var e: i64 = 0;
    check(windows::users(e).len > 0 && e == 0, "users");
    let name = str("ostest", sys::getpid());
    // A throwaway password that meets a domain's complexity rules; it is
    // never shown, and the account is deleted below.
    let pw = str("Gx9!", sys::uptime_ms() % 1000003, "aZ#q", sys::getpid());
    let added = windows::add_user(name, pw, "", "gslib sys test");
    check(added == 0, str("add_user: ", sys::error_text(added)));
    check(sys::is_exist(windows::add_user(name, pw)), "add_user: it exists");
    var flags:   i64     = 0;
    var full:    u8[>..] = [];
    var comment: u8[>..] = [];
    let disabled = windows::UF_ACCOUNTDISABLE;
    check(find_user(name, flags, full, comment) && (flags & disabled) == 0 && comment == "gslib sys test", "users: the new account");
    check(windows::disable_user(name) == 0 && find_user(name, flags, full, comment) && (flags & disabled) != 0, "disable_user");
    check(windows::enable_user(name) == 0 && find_user(name, flags, full, comment) && (flags & disabled) == 0, "enable_user");
    check(windows::set_full_name(name, "Os Test") == 0 && find_user(name, flags, full, comment) && full == "Os Test", "set_full_name");
    check(windows::set_password_never_expires(name, true) == 0 && find_user(name, flags, full, comment) &&
          (flags & windows::UF_DONT_EXPIRE_PASSWD) != 0, "set_password_never_expires");
    check(windows::set_password(name, str(pw, "2")) == 0, "set_password");
    let admins = windows::administrators();
    check(admins.len > 0, "administrators: the group's name");
    check(!windows::is_admin(name), "is_admin: not yet");
    check(windows::add_member(admins, name) == 0 && windows::is_admin(name), "add_member: Administrators");
    check(windows::remove_member(admins, name) == 0 && !windows::is_admin(name), "remove_member");

    let group = str("ostestgrp", sys::getpid());
    check(windows::add_group(group, "gslib sys test") == 0, "add_group");
    var listed = false;
    for g in windows::groups(e) { if g.name == group && g.comment == "gslib sys test" { listed = true; } }
    check(listed, "groups: the new one");
    check(windows::add_member(group, name) == 0, "add_member");
    var member = false;
    var acct = sys::lookup_user(name, e);
    for m in windows::group_members(group, e) { if m.sid == acct.uid && m.kind == windows::SID_USER { member = true; } }
    check(member, "group_members");
    check(windows::delete_group(group) == 0, "delete_group");
    check(windows::delete_user(name) == 0, "delete_user");
    check(!find_user(name, flags, full, comment), "deleted");
    check(sys::is_not_exist(windows::delete_user(name)), "delete_user: not there");
}

fn machine() {
    var e: i64 = 0;
    check(windows::sessions(e).len > 0 && e == 0, "sessions");
    var eventlog = false;
    for s in windows::services(e) {
        if s.name == "EventLog" && s.state == windows::SERVICE_RUNNING && s.pid > 0 && s.binary_path.len > 0 { eventlog = true; }
    }
    check(e == 0 && eventlog, "services: EventLog runs");
    var ipc = false;
    for s in windows::shares(e) { if s.name == "IPC$" && (s.kind & 0xff) == windows::STYPE_IPC { ipc = true; } }
    check(e == 0 && ipc, "shares: IPC$");
    let share = str("ostestshare", sys::getpid());
    check(windows::add_share(share, sys::temp_dir(), "gslib sys test") == 0, "add_share");
    var shared = false;
    for s in windows::shares(e) { if s.name == share { shared = true; } }
    check(shared && windows::delete_share(share) == 0, "shares: the new one, deleted");
    windows::installed_software(e);
    check(e == 0, "installed_software");
    let me = sys::current_user(e);
    check(windows::process_owner(sys::getpid()) == me.username, "process_owner");
    var mem = windows::ProcessMemory { .. };
    check(windows::process_memory(sys::getpid(), mem) == 0 && mem.working_set > 0 && mem.peak_working_set >= mem.working_set, "process_memory");
}

fn elsewhere() {
    var e: i64 = 0;
    check(windows::users(e).len == 0 && e == sys::ENOTSUP, "users: ENOTSUP");
    check(windows::add_user("x", "y") == sys::ENOTSUP, "add_user: ENOTSUP");
    check(windows::services(e).len == 0 && e == sys::ENOTSUP, "services: ENOTSUP");
    check(windows::installed_software(e).len == 0 && e == sys::ENOTSUP, "installed_software: ENOTSUP");
    check(windows::process_owner(sys::getpid()) == "", "process_owner: none");
}

fn main() {
    if sys::platform() == sys::PLATFORM_WINDOWS {
        if sys::is_elevated() == 1 { accounts(); }
        else { print("skip accounts: not an administrator"); }
        machine();
    } else {
        elsewhere();
    }
    if failed > 0 { print(failed, " failed"); exit(1); }
    print("all passed");
}
