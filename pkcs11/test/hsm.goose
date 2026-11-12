// hsm: what pkcs11's tests share: the module and token scripts/run_tests.py
// set up (P11_MODULE, P11_LABEL, P11_PIN, P11_SO_PIN), and a read-write
// session on the token, logged in as its user.

namespace hsm;

import std;
import os;
import gslib.pkcs11;
import tv;

fn getenv(name: const u8[:]) -> u8[>..] {
    var v: u8[>..] = [];
    if !env(name, v) { abort(str(name, " is not set: run scripts/run_tests.py")); }
    return v;
}

fn module_path() -> u8[>..] { getenv("P11_MODULE") }
fn pin() -> u8[>..] { getenv("P11_PIN") }
fn so_pin() -> u8[>..] { getenv("P11_SO_PIN") }
fn label() -> u8[>..] { getenv("P11_LABEL") }

// The module, loaded and initialized.
fn open() -> pkcs11::Ctx {
    var err: u8[>..] = [];
    var c, ok = pkcs11::new(module_path(), err);
    if !ok { abort(str("cannot load the module: ", err)); }
    let rv = pkcs11::initialize(c);
    if rv != pkcs11::CKR_OK { abort(pkcs11::error_text(rv)); }
    return c;
}

// The slot of the token labelled P11_LABEL.
fn slot(c: pkcs11::Ctx) -> u64 {
    let slots, rv = pkcs11::get_slot_list(c, true);
    for s in slots {
        let t, rt = pkcs11::get_token_info(c, s);
        if rt == pkcs11::CKR_OK && t.label[..] == label()[..] { return s; }
    }
    abort("the test token is not there");
}

// A read-write session on the token, logged in as its user.
fn session(c: pkcs11::Ctx) -> u64 {
    let sh, rv = pkcs11::open_session(c, slot(c), pkcs11::CKF_SERIAL_SESSION | pkcs11::CKF_RW_SESSION);
    if rv != pkcs11::CKR_OK { abort(pkcs11::error_text(rv)); }
    let rl = pkcs11::login(c, sh, pkcs11::CKU_USER, pin());
    if rl != pkcs11::CKR_OK { abort(pkcs11::error_text(rl)); }
    return sh;
}

// Checks rv is CKR_OK, printing its name when it is not.
fn ok(what: const u8[:], rv: u64) {
    tv::check(str(what, ": ", pkcs11::error_text(rv)), rv == pkcs11::CKR_OK);
}

fn check_rv(what: const u8[:], rv: u64, want: u64) {
    tv::check(str(what, ": got ", pkcs11::error_text(rv), ", want ", pkcs11::error_text(want)), rv == want);
}
