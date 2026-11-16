// winadmin: a Windows machine at a glance, as go-win64api's examples show
// it: local accounts, local groups with their members, sessions, running
// services, shares and installed software (Windows; elsewhere it says so).
//
//   goose run winadmin.goose -- [users|groups|sessions|services|shares|software]

import std;
import os;
import gslib from "../..";
import gslib.sys;
import gslib.sys.windows;

fn main() {
    if sys::platform() != sys::PLATFORM_WINDOWS { print("winadmin: Windows only"); return; }
    let argv = args();
    let what = if argv.len > 1 { argv[1] } else { "users" };
    var e: i64 = 0;
    if what == "users" {
        for u in windows::users(e) {
            print(u.name, if windows::is_disabled(u) { " [disabled]" } else { "" },
                  if windows::is_locked(u) { " [locked]" } else { "" },
                  if windows::is_admin_priv(u) { " [admin]" } else { "" },
                  "  logons ", u.num_logons, "  \"", u.full_name, "\"");
        }
    } else if what == "groups" {
        for g in windows::groups(e) {
            print(g.name, ": ", g.comment);
            for m in windows::group_members(g.name, e) { print("    ", m.name); }
        }
    } else if what == "sessions" {
        for s in windows::sessions(e) {
            print(s.id, " ", s.station, " state ", s.state, " ", s.domain, if s.domain.len > 0 { "\\" } else { "" }, s.user,
                  if s.client.len > 0 { str(" from ", s.client) } else { str("") });
        }
    } else if what == "services" {
        for s in windows::services(e) {
            if s.state == windows::SERVICE_RUNNING { print(s.name, " (pid ", s.pid, ") ", s.display_name, " as ", s.account); }
        }
    } else if what == "shares" {
        for s in windows::shares(e) { print(s.name, " ", s.path, "  ", s.remark); }
    } else if what == "software" {
        for s in windows::installed_software(e) { print(s.name, " ", s.version, "  ", s.publisher, " [", s.scope, "]"); }
    } else {
        print("winadmin: users, groups, sessions, services, shares or software");
        exit(2);
    }
    if e != 0 { print("winadmin: ", sys::error_text(e)); exit(1); }
}
