// pkcs11: PKCS#11 (Cryptoki, OASIS PKCS #11 2.40 and 3.x), as Go's
// miekg/pkcs11 has it: a module (an HSM's or a token's shared library)
// loaded at run time, and every C_* function of its function list.
//
//   var c, ok = pkcs11::new("/usr/lib/softhsm/libsofthsm2.so");
//   pkcs11::initialize(c);
//   let slots, rv = pkcs11::get_slot_list(c, true);
//   let sh, rv2 = pkcs11::open_session(c, slots[0], pkcs11::CKF_SERIAL_SESSION | pkcs11::CKF_RW_SESSION);
//   pkcs11::login(c, sh, pkcs11::CKU_USER, "1234");
//
// Every call returns the module's CK_RV as a u64 (CKR_OK, 0, for success),
// after its results; error_text(rv) names it. Templates and mechanisms are
// byte encodings built here and turned into the C structures by
// pkcs11/src/p11.c, which loads the module and calls it:
//
//   var t: u8[>..] = [];
//   pkcs11::attr(t, pkcs11::CKA_CLASS, pkcs11::CKO_SECRET_KEY);
//   pkcs11::attr(t, pkcs11::CKA_LABEL, "my key");
//   pkcs11::attr(t, pkcs11::CKA_TOKEN, true);
//   let m = pkcs11::mechanism_gcm(pkcs11::CKM_AES_GCM, iv, aad, 128);
//
//   pkcs11.constants   the constants (CKA_, CKM_, CKR_, ...), from the OASIS header
//   pkcs11.p11     Module, Slot, Session, Object (namespace p11), as miekg's p11

namespace pkcs11;

import std;
import pkcs11.constants;

extern fn p11_load(path: const u8[:], err: u8[>..]&) -> u64;
extern fn p11_unload(ctx: u64);
extern fn p11_ulong_size() -> i64;
extern fn p11_initialize(ctx: u64, flags: u64) -> u64;
extern fn p11_finalize(ctx: u64) -> u64;
extern fn p11_get_info(ctx: u64, out: u8[>..]&) -> u64;
extern fn p11_get_slot_list(ctx: u64, present: bool, out: u8[>..]&) -> u64;
extern fn p11_get_slot_info(ctx: u64, slot: u64, out: u8[>..]&) -> u64;
extern fn p11_get_token_info(ctx: u64, slot: u64, out: u8[>..]&) -> u64;
extern fn p11_get_mechanism_list(ctx: u64, slot: u64, out: u8[>..]&) -> u64;
extern fn p11_get_mechanism_info(ctx: u64, slot: u64, mech: u64, out: u8[>..]&) -> u64;
extern fn p11_init_token(ctx: u64, slot: u64, pin: const u8[:], label: const u8[:]) -> u64;
extern fn p11_init_pin(ctx: u64, sh: u64, pin: const u8[:]) -> u64;
extern fn p11_set_pin(ctx: u64, sh: u64, old: const u8[:], pin: const u8[:]) -> u64;
extern fn p11_open_session(ctx: u64, slot: u64, flags: u64, sh: u64&) -> u64;
extern fn p11_close_session(ctx: u64, sh: u64) -> u64;
extern fn p11_close_all_sessions(ctx: u64, slot: u64) -> u64;
extern fn p11_get_session_info(ctx: u64, sh: u64, out: u8[>..]&) -> u64;
extern fn p11_login(ctx: u64, sh: u64, user: u64, pin: const u8[:]) -> u64;
extern fn p11_logout(ctx: u64, sh: u64) -> u64;
extern fn p11_set_operation_state(ctx: u64, sh: u64, state: const u8[:], enc: u64, auth: u64) -> u64;
extern fn p11_create_object(ctx: u64, sh: u64, t: const u8[:], obj: u64&) -> u64;
extern fn p11_copy_object(ctx: u64, sh: u64, o: u64, t: const u8[:], obj: u64&) -> u64;
extern fn p11_destroy_object(ctx: u64, sh: u64, o: u64) -> u64;
extern fn p11_get_object_size(ctx: u64, sh: u64, o: u64, size: u64&) -> u64;
extern fn p11_get_attribute_value(ctx: u64, sh: u64, o: u64, types: const u8[:], out: u8[>..]&) -> u64;
extern fn p11_set_attribute_value(ctx: u64, sh: u64, o: u64, t: const u8[:]) -> u64;
extern fn p11_find_objects_init(ctx: u64, sh: u64, t: const u8[:]) -> u64;
extern fn p11_find_objects(ctx: u64, sh: u64, max: u64, out: u8[>..]&) -> u64;
extern fn p11_find_objects_final(ctx: u64, sh: u64) -> u64;
extern fn p11_op_init(ctx: u64, op: i64, sh: u64, mech: const u8[:], key: u64) -> u64;
extern fn p11_io(ctx: u64, op: i64, sh: u64, data: const u8[:], out: u8[>..]&) -> u64;
extern fn p11_in(ctx: u64, op: i64, sh: u64, data: const u8[:]) -> u64;
extern fn p11_verify(ctx: u64, sh: u64, data: const u8[:], sig: const u8[:]) -> u64;
extern fn p11_digest_key(ctx: u64, sh: u64, key: u64) -> u64;
extern fn p11_generate_key(ctx: u64, sh: u64, mech: const u8[:], t: const u8[:], key: u64&) -> u64;
extern fn p11_generate_key_pair(ctx: u64, sh: u64, mech: const u8[:], pubt: const u8[:], privt: const u8[:],
                                pub: u64&, priv: u64&) -> u64;
extern fn p11_wrap_key(ctx: u64, sh: u64, mech: const u8[:], wrapping: u64, key: u64, out: u8[>..]&) -> u64;
extern fn p11_unwrap_key(ctx: u64, sh: u64, mech: const u8[:], unwrapping: u64, wrapped: const u8[:],
                         t: const u8[:], key: u64&) -> u64;
extern fn p11_derive_key(ctx: u64, sh: u64, mech: const u8[:], base: u64, t: const u8[:], key: u64&) -> u64;
extern fn p11_generate_random(ctx: u64, sh: u64, len: u64, out: u8[>..]&) -> u64;
extern fn p11_wait_for_slot_event(ctx: u64, flags: u64, slot: u64&) -> u64;
extern fn p11_get_function_status(ctx: u64, sh: u64) -> u64;
extern fn p11_cancel_function(ctx: u64, sh: u64) -> u64;

// --- Errors ----------------------------------------------------------------------

// Failures of pkcs11's own, before the module is reached; above every CKR_.
let ERR_LOAD: u64 = 0x100000001;          // the module would not load
let ERR_SYMBOL: u64 = 0x100000002;        // it has no C_GetFunctionList
let ERR_ENCODING: u64 = 0x100000003;      // a malformed template or mechanism
let ERR_MEMORY: u64 = 0x100000004;
let ERR_NO_MODULE: u64 = 0x100000005;     // a Ctx that was destroyed or never loaded

// The name of a value in one of constants' tables, or "".
fn lookup(values: const u64[:], names: const u8[:][:], v: u64) -> const u8[:] {
    for i in values.len {
        if values[i] == v { return names[i]; }
    }
    return "";
}

fn ckr_name(rv: u64) -> const u8[:] {
    if rv == ERR_LOAD { return "the module would not load"; }
    if rv == ERR_SYMBOL { return "the module has no C_GetFunctionList"; }
    if rv == ERR_ENCODING { return "malformed template or mechanism"; }
    if rv == ERR_MEMORY { return "out of memory"; }
    if rv == ERR_NO_MODULE { return "no module loaded"; }
    return lookup(CKR_VALUES, CKR_NAMES, rv);
}
fn ckm_name(m: u64) -> const u8[:] { lookup(CKM_VALUES, CKM_NAMES, m) }
fn cka_name(a: u64) -> const u8[:] { lookup(CKA_VALUES, CKA_NAMES, a) }
fn cko_name(o: u64) -> const u8[:] { lookup(CKO_VALUES, CKO_NAMES, o) }
fn ckk_name(k: u64) -> const u8[:] { lookup(CKK_VALUES, CKK_NAMES, k) }

fn hex(out: u8[>..]&, v: u64) {
    let digits = "0123456789ABCDEF";
    var started = false;
    var i = 60;
    while i >= 0 {
        let d = (v >> i as u64) & 15;
        if d != 0 || started || i == 0 { out.push(digits[d]); started = true; }
        i -= 4;
    }
}

// "pkcs11: 0x150: CKR_BUFFER_TOO_SMALL", as miekg's Error writes it.
fn error_text(rv: u64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("pkcs11: 0x");
    hex(out, rv);
    out.append(": ");
    out.append(ckr_name(rv));
    return out;
}

// --- Decoding what p11.c appends --------------------------------------------------------

fn get64(b: const u8[:], at: i64) -> u64 {
    var v: u64 = 0;
    var i = 7;
    while i >= 0 {
        v = v << 8 | b[at + i];
        i--;
    }
    return v;
}

fn put64(out: u8[>..]&, v: u64) {
    for i in 8 { out.push((v >> (8 * i as u64)) as! u8); }
}

fn u64s(b: const u8[:]) -> u64[>..] {
    var out: u64[>..] = [];
    var at = 0;
    while at + 8 <= b.len {
        out.push(get64(b, at));
        at += 8;
    }
    return out;
}

// A blank-padded fixed field (labels, IDs) without its trailing blanks.
fn trimmed(b: const u8[:]) -> const u8[:] {
    var n = b.len;
    while n > 0 && (b[n - 1] == ' ' || b[n - 1] == 0) { n--; }
    return b[..n];
}

struct Version { major: u8, minor: u8 }

fn format(out: u8[>..]&, v: Version) { format(out, v.major, ".", v.minor); }

fn version_at(b: const u8[:], at: i64) -> Version { Version { major: b[at], minor: b[at + 1] } }

// --- The module -------------------------------------------------------------------------

// A loaded module. Its functions are called through c.handle; destroy
// unloads it.
struct Ctx { handle: u64 }

// Loads the module at path; false, with the loader's message in err, when
// it will not load or is no PKCS#11 module.
fn new(path: const u8[:], err: u8[>..]&) -> Ctx, bool {
    let h = p11_load(path, err);
    return Ctx { handle: h }, h != 0;
}

fn new(path: const u8[:]) -> Ctx, bool {
    var err: u8[>..] = [];
    let c, ok = new(path, err);
    return c, ok;
}

fn destroy(c: Ctx&) {
    p11_unload(c.handle);
    c.handle = 0;
}

// The size of the module's CK_ULONG: 8 on 64-bit Linux and macOS, 4 on
// Windows. CK_ULONG attribute values are this long.
fn ulong_size() -> i64 { p11_ulong_size() }

// C_Initialize, with these CK_C_INITIALIZE_ARGS flags (CKF_OS_LOCKING_OK
// for a module used from several threads).
fn initialize(c: Ctx, flags: u64 = 0) -> u64 { p11_initialize(c.handle, flags) }
fn finalize(c: Ctx) -> u64 { p11_finalize(c.handle) }

struct Info {
    cryptoki_version: Version,
    manufacturer_id: u8[..32],
    flags: u64,
    library_description: u8[..32],
    library_version: Version,
}

fn get_info(c: Ctx) -> Info, u64 {
    var b: u8[>..] = [];
    let rv = p11_get_info(c.handle, b);
    var i = Info { cryptoki_version: Version { 0, 0 }, manufacturer_id: [], flags: 0, library_description: [],
                   library_version: Version { 0, 0 } };
    if rv != CKR_OK { return i, rv; }
    i.flags = get64(b, 0);
    i.cryptoki_version = version_at(b, 8);
    i.library_version = version_at(b, 10);
    i.manufacturer_id.append(trimmed(b[12..44]));
    i.library_description.append(trimmed(b[44..76]));
    return i, rv;
}

// --- Slots and tokens --------------------------------------------------------------------

// The slots, or those with a token present.
fn get_slot_list(c: Ctx, token_present: bool) -> u64[>..], u64 {
    var b: u8[>..] = [];
    let rv = p11_get_slot_list(c.handle, token_present, b);
    return u64s(b), rv;
}

struct SlotInfo {
    slot_description: u8[..64],
    manufacturer_id: u8[..32],
    flags: u64,
    hardware_version: Version,
    firmware_version: Version,
}

fn get_slot_info(c: Ctx, slot: u64) -> SlotInfo, u64 {
    var b: u8[>..] = [];
    let rv = p11_get_slot_info(c.handle, slot, b);
    var i = SlotInfo { slot_description: [], manufacturer_id: [], flags: 0, hardware_version: Version { 0, 0 },
                       firmware_version: Version { 0, 0 } };
    if rv != CKR_OK { return i, rv; }
    i.flags = get64(b, 0);
    i.hardware_version = version_at(b, 8);
    i.firmware_version = version_at(b, 10);
    i.slot_description.append(trimmed(b[12..76]));
    i.manufacturer_id.append(trimmed(b[76..108]));
    return i, rv;
}

// The counts and sizes are CK_UNAVAILABLE_INFORMATION (all ones) when the
// token does not say.
struct TokenInfo {
    label: u8[..32],
    manufacturer_id: u8[..32],
    model: u8[..16],
    serial_number: u8[..16],
    flags: u64,
    max_session_count: u64,
    session_count: u64,
    max_rw_session_count: u64,
    rw_session_count: u64,
    max_pin_len: u64,
    min_pin_len: u64,
    total_public_memory: u64,
    free_public_memory: u64,
    total_private_memory: u64,
    free_private_memory: u64,
    hardware_version: Version,
    firmware_version: Version,
    utc_time: u8[..16],
}

fn get_token_info(c: Ctx, slot: u64) -> TokenInfo, u64 {
    var b: u8[>..] = [];
    let rv = p11_get_token_info(c.handle, slot, b);
    var i = TokenInfo { label: [], manufacturer_id: [], model: [], serial_number: [], flags: 0, max_session_count: 0,
                        session_count: 0, max_rw_session_count: 0, rw_session_count: 0, max_pin_len: 0,
                        min_pin_len: 0, total_public_memory: 0, free_public_memory: 0, total_private_memory: 0,
                        free_private_memory: 0, hardware_version: Version { 0, 0 },
                        firmware_version: Version { 0, 0 }, utc_time: [] };
    if rv != CKR_OK { return i, rv; }
    i.flags = get64(b, 0);
    i.max_session_count = get64(b, 8);
    i.session_count = get64(b, 16);
    i.max_rw_session_count = get64(b, 24);
    i.rw_session_count = get64(b, 32);
    i.max_pin_len = get64(b, 40);
    i.min_pin_len = get64(b, 48);
    i.total_public_memory = get64(b, 56);
    i.free_public_memory = get64(b, 64);
    i.total_private_memory = get64(b, 72);
    i.free_private_memory = get64(b, 80);
    i.hardware_version = version_at(b, 88);
    i.firmware_version = version_at(b, 90);
    i.label.append(trimmed(b[92..124]));
    i.manufacturer_id.append(trimmed(b[124..156]));
    i.model.append(trimmed(b[156..172]));
    i.serial_number.append(trimmed(b[172..188]));
    i.utc_time.append(trimmed(b[188..204]));
    return i, rv;
}

// The mechanism types the token does.
fn get_mechanism_list(c: Ctx, slot: u64) -> u64[>..], u64 {
    var b: u8[>..] = [];
    let rv = p11_get_mechanism_list(c.handle, slot, b);
    return u64s(b), rv;
}

struct MechanismInfo { min_key_size: u64, max_key_size: u64, flags: u64 }

fn get_mechanism_info(c: Ctx, slot: u64, mech: u64) -> MechanismInfo, u64 {
    var b: u8[>..] = [];
    let rv = p11_get_mechanism_info(c.handle, slot, mech, b);
    if rv != CKR_OK { return MechanismInfo { 0, 0, 0 }, rv; }
    return MechanismInfo { min_key_size: get64(b, 0), max_key_size: get64(b, 8), flags: get64(b, 16) }, rv;
}

// The label goes in blank-padded to 32 bytes.
fn init_token(c: Ctx, slot: u64, so_pin: const u8[:], label: const u8[:]) -> u64 {
    return p11_init_token(c.handle, slot, so_pin, label);
}

fn init_pin(c: Ctx, sh: u64, pin: const u8[:]) -> u64 { p11_init_pin(c.handle, sh, pin) }
fn set_pin(c: Ctx, sh: u64, old_pin: const u8[:], new_pin: const u8[:]) -> u64 {
    p11_set_pin(c.handle, sh, old_pin, new_pin)
}

// --- Sessions -------------------------------------------------------------------------------

// A session on slot; flags must hold CKF_SERIAL_SESSION, and CKF_RW_SESSION
// to change anything on the token.
fn open_session(c: Ctx, slot: u64, flags: u64) -> u64, u64 {
    var sh: u64 = 0;
    let rv = p11_open_session(c.handle, slot, flags, sh);
    return sh, rv;
}

fn close_session(c: Ctx, sh: u64) -> u64 { p11_close_session(c.handle, sh) }
fn close_all_sessions(c: Ctx, slot: u64) -> u64 { p11_close_all_sessions(c.handle, slot) }

struct SessionInfo { slot_id: u64, state: u64, flags: u64, device_error: u64 }

fn get_session_info(c: Ctx, sh: u64) -> SessionInfo, u64 {
    var b: u8[>..] = [];
    let rv = p11_get_session_info(c.handle, sh, b);
    if rv != CKR_OK { return SessionInfo { 0, 0, 0, 0 }, rv; }
    return SessionInfo { slot_id: get64(b, 0), state: get64(b, 8), flags: get64(b, 16), device_error: get64(b, 24) }, rv;
}

// The state of the session's operations, for set_operation_state.
fn get_operation_state(c: Ctx, sh: u64) -> u8[>..], u64 {
    var out: u8[>..] = [];
    let rv = p11_io(c.handle, IO_GET_OPERATION_STATE, sh, "", out);
    return out, rv;
}

fn set_operation_state(c: Ctx, sh: u64, state: const u8[:], encrypt_key: u64, auth_key: u64) -> u64 {
    return p11_set_operation_state(c.handle, sh, state, encrypt_key, auth_key);
}

// user_type is CKU_USER, CKU_SO or CKU_CONTEXT_SPECIFIC.
fn login(c: Ctx, sh: u64, user_type: u64, pin: const u8[:]) -> u64 { p11_login(c.handle, sh, user_type, pin) }
fn logout(c: Ctx, sh: u64) -> u64 { p11_logout(c.handle, sh) }

// --- Templates ----------------------------------------------------------------------------
//
// A template is a u8[>..] the attr overloads append attributes to, as
// miekg's NewAttribute makes them: a bool as CK_BBOOL, an integer as a
// CK_ULONG (ulong_size() bytes, little-endian), bytes and strings as they
// are, a date as CK_DATE's "YYYYMMDD".

fn attr(t: u8[>..]&, kind: u64, value: const u8[:]) {
    put64(t, kind);
    put64(t, value.len as u64);
    t.append(value);
}

fn attr(t: u8[>..]&, kind: u64, value: bool) {
    put64(t, kind);
    put64(t, 1);
    t.push(if value { 1 } else { 0 });
}

fn attr(t: u8[>..]&, kind: u64, value: u64) {
    let n = ulong_size();
    put64(t, kind);
    put64(t, n as u64);
    for i in n { t.push((value >> (8 * i as u64)) as! u8); }
}

fn attr(t: u8[>..]&, kind: u64, value: i64) { attr(t, kind, value as! u64); }

// An attribute with no value: for a find template, or C_GetAttributeValue.
fn attr_empty(t: u8[>..]&, kind: u64) {
    put64(t, kind);
    put64(t, 0);
}

fn attr_date(t: u8[>..]&, kind: u64, year: i64, month: i64, day: i64) {
    var d: u8[>..] = [];
    format_int(d, year, 10, 4, '0');
    format_int(d, month, 10, 2, '0');
    format_int(d, day, 10, 2, '0');
    attr(t, kind, d);
}

// --- Attributes read back ----------------------------------------------------------------
//
// get_attribute_value's result holds each attribute asked for, in order, as
// { u64 type, u64 len, bytes }; a len of all ones marks one the module did
// not give (sensitive, or not the object's).

let UNAVAILABLE: u64 = 0xFFFFFFFFFFFFFFFF;

fn encode_types(types: const u64[:]) -> u8[>..] {
    var b: u8[>..] = [];
    for t in types { put64(b, t); }
    return b;
}

// The values of the attributes of the types listed. rv may be
// CKR_ATTRIBUTE_SENSITIVE or CKR_ATTRIBUTE_TYPE_INVALID with the others
// all there.
fn get_attribute_value(c: Ctx, sh: u64, obj: u64, types: const u64[:]) -> u8[>..], u64 {
    var out: u8[>..] = [];
    let rv = p11_get_attribute_value(c.handle, sh, obj, encode_types(types), out);
    return out, rv;
}

fn set_attribute_value(c: Ctx, sh: u64, obj: u64, t: const u8[:]) -> u64 {
    return p11_set_attribute_value(c.handle, sh, obj, t);
}

// F(type, value, available) for each attribute of a result.
fn each_attr<F>(attrs: const u8[:]) {
    var at = 0;
    while at + 16 <= attrs.len {
        let kind = get64(attrs, at);
        let len = get64(attrs, at + 8);
        if len == UNAVAILABLE {
            F(kind, attrs[at + 16..at + 16], false);
            at += 16;
        } else {
            F(kind, attrs[at + 16..at + 16 + len as i64], true);
            at += 16 + len as i64;
        }
    }
}

// The value of the attribute of type kind in a result; false when it is
// not there or was not given.
fn attr_value(attrs: const u8[:], kind: u64) -> const u8[:], bool {
    each_attr(attrs) { k, v, ok =>
        if k == kind { return v, ok; }
    };
    return attrs[..0], false;
}

// A CK_ULONG attribute value (4 or 8 bytes, little-endian).
fn as_ulong(v: const u8[:]) -> u64 {
    var x: u64 = 0;
    var i = v.len;
    while i > 0 {
        i--;
        x = x << 8 | v[i];
    }
    return x;
}

fn as_bool(v: const u8[:]) -> bool { v.len > 0 && v[0] != 0 }

// --- Objects -----------------------------------------------------------------------------------

fn create_object(c: Ctx, sh: u64, t: const u8[:]) -> u64, u64 {
    var obj: u64 = 0;
    let rv = p11_create_object(c.handle, sh, t, obj);
    return obj, rv;
}

fn copy_object(c: Ctx, sh: u64, obj: u64, t: const u8[:]) -> u64, u64 {
    var o: u64 = 0;
    let rv = p11_copy_object(c.handle, sh, obj, t, o);
    return o, rv;
}

fn destroy_object(c: Ctx, sh: u64, obj: u64) -> u64 { p11_destroy_object(c.handle, sh, obj) }

fn get_object_size(c: Ctx, sh: u64, obj: u64) -> u64, u64 {
    var n: u64 = 0;
    let rv = p11_get_object_size(c.handle, sh, obj, n);
    return n, rv;
}

fn find_objects_init(c: Ctx, sh: u64, t: const u8[:]) -> u64 { p11_find_objects_init(c.handle, sh, t) }

// Up to max more handles of the search (fewer at its end).
fn find_objects(c: Ctx, sh: u64, max: i64) -> u64[>..], u64 {
    var b: u8[>..] = [];
    let rv = p11_find_objects(c.handle, sh, max as u64, b);
    return u64s(b), rv;
}

fn find_objects_final(c: Ctx, sh: u64) -> u64 { p11_find_objects_final(c.handle, sh) }

// --- Mechanisms ---------------------------------------------------------------------------------
//
// A mechanism is its type and parameter, encoded for p11.c: build one with
// the mechanism* functions and pass it to the *_init functions and the key
// functions. The PARAM_ kinds are p11.c's P11_PARAM_.

let PARAM_NONE: u64 = 0;
let PARAM_RAW: u64 = 1;
let PARAM_GCM: u64 = 2;
let PARAM_OAEP: u64 = 3;
let PARAM_PSS: u64 = 4;
let PARAM_ECDH1: u64 = 5;
let PARAM_RSA_AES_KW: u64 = 6;
let PARAM_EDDSA: u64 = 7;
let PARAM_ULONG: u64 = 8;
let PARAM_CCM: u64 = 9;

fn put_bytes(out: u8[>..]&, b: const u8[:]) {
    put64(out, b.len as u64);
    out.append(b);
}

// A mechanism with no parameter.
fn mechanism(m: u64) -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_NONE);
    return out;
}

// A mechanism whose parameter is these bytes as they are: an IV for CBC, a
// struct of CK_ULONGs.
fn mechanism(m: u64, param: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_RAW);
    put_bytes(out, param);
    return out;
}

// A CK_ULONG parameter (the MAC length of a *_MAC_GENERAL mechanism, ...).
fn mechanism_ulong(m: u64, v: u64) -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_ULONG);
    put64(out, v);
    return out;
}

// CK_GCM_PARAMS (miekg's NewGCMParams): the IV, the AAD, the tag in bits.
fn mechanism_gcm(m: u64, iv: const u8[:], aad: const u8[:], tag_bits: u64) -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_GCM);
    put_bytes(out, iv);
    put_bytes(out, aad);
    put64(out, tag_bits);
    return out;
}

// CK_CCM_PARAMS: the message length, the nonce, the AAD, the MAC length.
fn mechanism_ccm(m: u64, data_len: u64, nonce: const u8[:], aad: const u8[:], mac_len: u64) -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_CCM);
    put64(out, data_len);
    put_bytes(out, nonce);
    put_bytes(out, aad);
    put64(out, mac_len);
    return out;
}

// CK_RSA_PKCS_OAEP_PARAMS (NewOAEPParams): the hash (CKM_SHA256, ...), the
// MGF (CKG_MGF1_SHA256, ...), the source (CKZ_DATA_SPECIFIED) and its data.
fn mechanism_oaep(m: u64, hash: u64, mgf: u64, source: u64 = CKZ_DATA_SPECIFIED, label: const u8[:] = "") -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_OAEP);
    put64(out, hash);
    put64(out, mgf);
    put64(out, source);
    put_bytes(out, label);
    return out;
}

// CK_RSA_PKCS_PSS_PARAMS (NewPSSParams): the hash, the MGF, the salt length.
fn mechanism_pss(m: u64, hash: u64, mgf: u64, salt_len: u64) -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_PSS);
    put64(out, hash);
    put64(out, mgf);
    put64(out, salt_len);
    return out;
}

// CK_ECDH1_DERIVE_PARAMS (NewECDH1DeriveParams): the KDF (CKD_NULL, ...),
// the shared data (empty for CKD_NULL), the other party's public key (its
// EC point, uncompressed, or DER-wrapped as some modules want).
fn mechanism_ecdh1(m: u64, kdf: u64, shared: const u8[:], public: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_ECDH1);
    put64(out, kdf);
    put_bytes(out, shared);
    put_bytes(out, public);
    return out;
}

// CK_RSA_AES_KEY_WRAP_PARAMS: the AES key size in bits, and OAEP's.
fn mechanism_rsa_aes_kw(m: u64, aes_bits: u64, hash: u64, mgf: u64, source: u64 = CKZ_DATA_SPECIFIED,
                        label: const u8[:] = "") -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_RSA_AES_KW);
    put64(out, aes_bits);
    put64(out, hash);
    put64(out, mgf);
    put64(out, source);
    put_bytes(out, label);
    return out;
}

// CK_EDDSA_PARAMS (PKCS #11 3.0): prehash (Ed25519ph) and a context.
fn mechanism_eddsa(m: u64, prehash: bool, context: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    put64(out, m);
    put64(out, PARAM_EDDSA);
    put64(out, if prehash { 1 } else { 0 });
    put_bytes(out, context);
    return out;
}

// --- Cryptographic operations ---------------------------------------------------------------
//
// Each operation starts with its *_init and the mechanism; then either the
// one-part call (encrypt, sign, ...) or *_update calls and a *_final. The
// one-part and update calls that give data return it with the CK_RV.

let OP_ENCRYPT: i64 = 1;
let OP_DECRYPT: i64 = 2;
let OP_DIGEST: i64 = 3;
let OP_SIGN: i64 = 4;
let OP_SIGN_RECOVER: i64 = 5;
let OP_VERIFY: i64 = 6;
let OP_VERIFY_RECOVER: i64 = 7;

let IO_ENCRYPT: i64 = 1;
let IO_ENCRYPT_UPDATE: i64 = 2;
let IO_DECRYPT: i64 = 3;
let IO_DECRYPT_UPDATE: i64 = 4;
let IO_DIGEST: i64 = 5;
let IO_SIGN: i64 = 6;
let IO_SIGN_RECOVER: i64 = 7;
let IO_VERIFY_RECOVER: i64 = 8;
let IO_DIGEST_ENCRYPT_UPDATE: i64 = 9;
let IO_DECRYPT_DIGEST_UPDATE: i64 = 10;
let IO_SIGN_ENCRYPT_UPDATE: i64 = 11;
let IO_DECRYPT_VERIFY_UPDATE: i64 = 12;
let IO_ENCRYPT_FINAL: i64 = 20;
let IO_DECRYPT_FINAL: i64 = 21;
let IO_DIGEST_FINAL: i64 = 22;
let IO_SIGN_FINAL: i64 = 23;
let IO_GET_OPERATION_STATE: i64 = 24;

let IN_DIGEST_UPDATE: i64 = 1;
let IN_SIGN_UPDATE: i64 = 2;
let IN_VERIFY_UPDATE: i64 = 3;
let IN_VERIFY_FINAL: i64 = 4;
let IN_SEED_RANDOM: i64 = 5;

fn io(c: Ctx, op: i64, sh: u64, data: const u8[:]) -> u8[>..], u64 {
    var out: u8[>..] = [];
    let rv = p11_io(c.handle, op, sh, data, out);
    return out, rv;
}

fn encrypt_init(c: Ctx, sh: u64, mech: const u8[:], key: u64) -> u64 { p11_op_init(c.handle, OP_ENCRYPT, sh, mech, key) }
fn encrypt(c: Ctx, sh: u64, plain: const u8[:]) -> u8[>..], u64 { let o, rv = io(c, IO_ENCRYPT, sh, plain); return o, rv; }
fn encrypt_update(c: Ctx, sh: u64, plain: const u8[:]) -> u8[>..], u64 {
    let o, rv = io(c, IO_ENCRYPT_UPDATE, sh, plain);
    return o, rv;
}
fn encrypt_final(c: Ctx, sh: u64) -> u8[>..], u64 { let o, rv = io(c, IO_ENCRYPT_FINAL, sh, ""); return o, rv; }

fn decrypt_init(c: Ctx, sh: u64, mech: const u8[:], key: u64) -> u64 { p11_op_init(c.handle, OP_DECRYPT, sh, mech, key) }
fn decrypt(c: Ctx, sh: u64, cipher: const u8[:]) -> u8[>..], u64 { let o, rv = io(c, IO_DECRYPT, sh, cipher); return o, rv; }
fn decrypt_update(c: Ctx, sh: u64, cipher: const u8[:]) -> u8[>..], u64 {
    let o, rv = io(c, IO_DECRYPT_UPDATE, sh, cipher);
    return o, rv;
}
fn decrypt_final(c: Ctx, sh: u64) -> u8[>..], u64 { let o, rv = io(c, IO_DECRYPT_FINAL, sh, ""); return o, rv; }

fn digest_init(c: Ctx, sh: u64, mech: const u8[:]) -> u64 { p11_op_init(c.handle, OP_DIGEST, sh, mech, 0) }
fn digest(c: Ctx, sh: u64, data: const u8[:]) -> u8[>..], u64 { let o, rv = io(c, IO_DIGEST, sh, data); return o, rv; }
fn digest_update(c: Ctx, sh: u64, data: const u8[:]) -> u64 { p11_in(c.handle, IN_DIGEST_UPDATE, sh, data) }
fn digest_key(c: Ctx, sh: u64, key: u64) -> u64 { p11_digest_key(c.handle, sh, key) }
fn digest_final(c: Ctx, sh: u64) -> u8[>..], u64 { let o, rv = io(c, IO_DIGEST_FINAL, sh, ""); return o, rv; }

fn sign_init(c: Ctx, sh: u64, mech: const u8[:], key: u64) -> u64 { p11_op_init(c.handle, OP_SIGN, sh, mech, key) }
fn sign(c: Ctx, sh: u64, data: const u8[:]) -> u8[>..], u64 { let o, rv = io(c, IO_SIGN, sh, data); return o, rv; }
fn sign_update(c: Ctx, sh: u64, data: const u8[:]) -> u64 { p11_in(c.handle, IN_SIGN_UPDATE, sh, data) }
fn sign_final(c: Ctx, sh: u64) -> u8[>..], u64 { let o, rv = io(c, IO_SIGN_FINAL, sh, ""); return o, rv; }
fn sign_recover_init(c: Ctx, sh: u64, mech: const u8[:], key: u64) -> u64 {
    p11_op_init(c.handle, OP_SIGN_RECOVER, sh, mech, key)
}
fn sign_recover(c: Ctx, sh: u64, data: const u8[:]) -> u8[>..], u64 {
    let o, rv = io(c, IO_SIGN_RECOVER, sh, data);
    return o, rv;
}

fn verify_init(c: Ctx, sh: u64, mech: const u8[:], key: u64) -> u64 { p11_op_init(c.handle, OP_VERIFY, sh, mech, key) }
// CKR_OK when sig is good, CKR_SIGNATURE_INVALID when it is not.
fn verify(c: Ctx, sh: u64, data: const u8[:], sig: const u8[:]) -> u64 { p11_verify(c.handle, sh, data, sig) }
fn verify_update(c: Ctx, sh: u64, data: const u8[:]) -> u64 { p11_in(c.handle, IN_VERIFY_UPDATE, sh, data) }
fn verify_final(c: Ctx, sh: u64, sig: const u8[:]) -> u64 { p11_in(c.handle, IN_VERIFY_FINAL, sh, sig) }
fn verify_recover_init(c: Ctx, sh: u64, mech: const u8[:], key: u64) -> u64 {
    p11_op_init(c.handle, OP_VERIFY_RECOVER, sh, mech, key)
}
fn verify_recover(c: Ctx, sh: u64, sig: const u8[:]) -> u8[>..], u64 {
    let o, rv = io(c, IO_VERIFY_RECOVER, sh, sig);
    return o, rv;
}

fn digest_encrypt_update(c: Ctx, sh: u64, part: const u8[:]) -> u8[>..], u64 {
    let o, rv = io(c, IO_DIGEST_ENCRYPT_UPDATE, sh, part);
    return o, rv;
}
fn decrypt_digest_update(c: Ctx, sh: u64, cipher: const u8[:]) -> u8[>..], u64 {
    let o, rv = io(c, IO_DECRYPT_DIGEST_UPDATE, sh, cipher);
    return o, rv;
}
fn sign_encrypt_update(c: Ctx, sh: u64, part: const u8[:]) -> u8[>..], u64 {
    let o, rv = io(c, IO_SIGN_ENCRYPT_UPDATE, sh, part);
    return o, rv;
}
fn decrypt_verify_update(c: Ctx, sh: u64, cipher: const u8[:]) -> u8[>..], u64 {
    let o, rv = io(c, IO_DECRYPT_VERIFY_UPDATE, sh, cipher);
    return o, rv;
}

// --- Keys ------------------------------------------------------------------------------------------

fn generate_key(c: Ctx, sh: u64, mech: const u8[:], t: const u8[:]) -> u64, u64 {
    var key: u64 = 0;
    let rv = p11_generate_key(c.handle, sh, mech, t, key);
    return key, rv;
}

// The public key's handle, the private key's, and the CK_RV.
fn generate_key_pair(c: Ctx, sh: u64, mech: const u8[:], public: const u8[:], private: const u8[:]) -> u64, u64, u64 {
    var pub: u64 = 0;
    var priv: u64 = 0;
    let rv = p11_generate_key_pair(c.handle, sh, mech, public, private, pub, priv);
    return pub, priv, rv;
}

fn wrap_key(c: Ctx, sh: u64, mech: const u8[:], wrapping_key: u64, key: u64) -> u8[>..], u64 {
    var out: u8[>..] = [];
    let rv = p11_wrap_key(c.handle, sh, mech, wrapping_key, key, out);
    return out, rv;
}

fn unwrap_key(c: Ctx, sh: u64, mech: const u8[:], unwrapping_key: u64, wrapped: const u8[:], t: const u8[:]) -> u64, u64 {
    var key: u64 = 0;
    let rv = p11_unwrap_key(c.handle, sh, mech, unwrapping_key, wrapped, t, key);
    return key, rv;
}

fn derive_key(c: Ctx, sh: u64, mech: const u8[:], base_key: u64, t: const u8[:]) -> u64, u64 {
    var key: u64 = 0;
    let rv = p11_derive_key(c.handle, sh, mech, base_key, t, key);
    return key, rv;
}

// --- Random numbers and the rest -------------------------------------------------------------------

fn seed_random(c: Ctx, sh: u64, seed: const u8[:]) -> u64 { p11_in(c.handle, IN_SEED_RANDOM, sh, seed) }

fn generate_random(c: Ctx, sh: u64, len: i64) -> u8[>..], u64 {
    var out: u8[>..] = [];
    let rv = p11_generate_random(c.handle, sh, len as u64, out);
    return out, rv;
}

// The slot of the next slot event; with CKF_DONT_BLOCK, CKR_NO_EVENT when
// there is none. (miekg's WaitForSlotEvent runs this in a goroutine; Goose
// has no shared-memory threads, so the caller waits, or polls.)
fn wait_for_slot_event(c: Ctx, flags: u64) -> u64, u64 {
    var slot: u64 = 0;
    let rv = p11_wait_for_slot_event(c.handle, flags, slot);
    return slot, rv;
}

// Legacy functions (PKCS#11 §5.16): modules answer CKR_FUNCTION_NOT_PARALLEL.
fn get_function_status(c: Ctx, sh: u64) -> u64 { p11_get_function_status(c.handle, sh) }
fn cancel_function(c: Ctx, sh: u64) -> u64 { p11_cancel_function(c.handle, sh) }

// --- Elliptic curves ---------------------------------------------------------------------------
//
// CKA_EC_PARAMS is the curve's named-curve OID in DER (ANSI X9.62's
// ECParameters, RFC 5480); CKA_EC_POINT the public point as a DER OCTET
// STRING (uncompressed 04 || x || y for the NIST curves, the 32-byte key for
// Ed25519 and X25519), which some modules give unwrapped.

let EC_PARAMS_P256: u8[] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
let EC_PARAMS_P384: u8[] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
let EC_PARAMS_P521: u8[] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];
let EC_PARAMS_ED25519: u8[] = [0x06, 0x03, 0x2B, 0x65, 0x70];
let EC_PARAMS_X25519: u8[] = [0x06, 0x03, 0x2B, 0x65, 0x6E];

// The point in a CKA_EC_POINT value: the contents of its OCTET STRING, or
// the value itself when it is not one (a module that gives it raw).
fn ec_point(v: const u8[:]) -> const u8[:] {
    if v.len >= 2 && v[0] == 0x04 {
        var len: i64 = v[1];
        var at = 2;
        if len == 0x81 && v.len >= 3 { len = v[2]; at = 3; }
        else if len == 0x82 && v.len >= 4 { len = (v[2] as i64) << 8 | v[3]; at = 4; }
        if at + len == v.len { return v[at..]; }
    }
    return v;
}

// A point as CKA_EC_POINT wants it, a DER OCTET STRING (for ECDH1's public
// data, some modules want it so too).
fn ec_point_der(point: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.push(0x04);
    if point.len < 0x80 { out.push(point.len as! u8); }
    else if point.len < 0x100 { out.push(0x81); out.push(point.len as! u8); }
    else { out.push(0x82); out.push((point.len >> 8) as! u8); out.push(point.len as! u8); }
    out.append(point);
    return out;
}
