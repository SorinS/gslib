// pkcs11 against SoftHSM2: loading (and refusing what is no module), the
// module's, slots' and token's information, mechanisms, sessions and their
// states, logging in (and a wrong PIN), changing the user PIN, a token
// initialized on the free slot with its user PIN set by the SO, random
// bytes, error names, attribute encodings, and the same through p11.
import std;
import os;
import gslib from "../..";
import gslib.pkcs11;
import gslib.pkcs11.p11;
import hsm;
import tv;

fn main() {
    // What will not load.
    var err: u8[>..] = [];
    let bad, okb = pkcs11::new("/nonexistent/libnothing.so", err);
    tv::check("no such module", !okb && err.len > 0);
    // A shared library that is no PKCS#11 module: the C library of whichever
    // system this is.
    for lib in ["/usr/lib/libSystem.B.dylib", "/lib/x86_64-linux-gnu/libc.so.6", "/lib/aarch64-linux-gnu/libc.so.6",
                "/lib64/libc.so.6", "C:\\Windows\\System32\\kernel32.dll"] {
        if file_exists(lib) {
            var err2: u8[>..] = [];
            let notp11, okn = pkcs11::new(lib, err2);
            tv::check(str("a library that is no PKCS#11 module: ", lib), !okn && err2.len > 0);
        }
    }
    var none = pkcs11::Ctx { handle: 0 };
    hsm::check_rv("a context never loaded", pkcs11::initialize(none), pkcs11::ERR_NO_MODULE);

    tv::check_eq("error text", pkcs11::error_text(0xA0), "pkcs11: 0xA0: CKR_PIN_INCORRECT");
    tv::check_eq("error text of OK", pkcs11::error_text(0), "pkcs11: 0x0: CKR_OK");
    tv::check_eq("mechanism name", pkcs11::ckm_name(pkcs11::CKM_EDDSA), "CKM_EDDSA");
    tv::check_eq("attribute name", pkcs11::cka_name(pkcs11::CKA_LABEL), "CKA_LABEL");
    // unsigned long: 4 bytes on Windows, 8 on 64-bit Linux and macOS.
    tv::check("CK_ULONG size", pkcs11::ulong_size() == 8 || pkcs11::ulong_size() == 4);

    var c = hsm::open();
    hsm::check_rv("initialized twice", pkcs11::initialize(c), pkcs11::CKR_CRYPTOKI_ALREADY_INITIALIZED);
    let info, ri = pkcs11::get_info(c);
    hsm::ok("C_GetInfo", ri);
    tv::check_eq("manufacturer", info.manufacturer_id, "SoftHSM");
    tv::check("cryptoki version", info.cryptoki_version.major >= 2);

    let all, ra = pkcs11::get_slot_list(c, false);
    let present, rp = pkcs11::get_slot_list(c, true);
    hsm::ok("C_GetSlotList", ra);
    tv::check("two slots, both with a token (SoftHSM keeps a free one)", all.len == 2 && present.len == 2);
    let slot = hsm::slot(c);
    let si, rs = pkcs11::get_slot_info(c, slot);
    hsm::ok("C_GetSlotInfo", rs);
    tv::check("slot has a token", si.flags & pkcs11::CKF_TOKEN_PRESENT != 0);
    let ti, rt = pkcs11::get_token_info(c, slot);
    hsm::ok("C_GetTokenInfo", rt);
    tv::check_eq("token label", ti.label, hsm::label());
    tv::check("token initialized, user PIN set", ti.flags & pkcs11::CKF_TOKEN_INITIALIZED != 0
              && ti.flags & pkcs11::CKF_USER_PIN_INITIALIZED != 0);
    tv::check("token PIN lengths", ti.min_pin_len >= 4 && ti.max_pin_len >= ti.min_pin_len);

    let mechs, rm = pkcs11::get_mechanism_list(c, slot);
    hsm::ok("C_GetMechanismList", rm);
    for want in [pkcs11::CKM_AES_GCM, pkcs11::CKM_SHA256_RSA_PKCS, pkcs11::CKM_ECDSA, pkcs11::CKM_EDDSA,
                 pkcs11::CKM_AES_KEY_WRAP, pkcs11::CKM_ECDH1_DERIVE] {
        var has = false;
        for m in mechs { if m == want { has = true; } }
        tv::check(str("token does ", pkcs11::ckm_name(want)), has);
    }
    let mi, rmi = pkcs11::get_mechanism_info(c, slot, pkcs11::CKM_RSA_PKCS_KEY_PAIR_GEN);
    hsm::ok("C_GetMechanismInfo", rmi);
    tv::check("RSA key sizes", mi.min_key_size <= 2048 && mi.max_key_size >= 4096
              && mi.flags & pkcs11::CKF_GENERATE_KEY_PAIR != 0);

    // Sessions and logging in.
    let ro, rro = pkcs11::open_session(c, slot, pkcs11::CKF_SERIAL_SESSION);
    hsm::ok("read-only session", rro);
    let s1, rs1 = pkcs11::get_session_info(c, ro);
    tv::check("read-only public state", rs1 == pkcs11::CKR_OK && s1.state == pkcs11::CKS_RO_PUBLIC_SESSION
              && s1.slot_id == slot);
    let sh, rsh = pkcs11::open_session(c, slot, pkcs11::CKF_SERIAL_SESSION | pkcs11::CKF_RW_SESSION);
    hsm::ok("read-write session", rsh);
    let nos, rnos = pkcs11::open_session(c, slot, 0);
    hsm::check_rv("no serial flag", rnos, pkcs11::CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    hsm::check_rv("wrong PIN", pkcs11::login(c, sh, pkcs11::CKU_USER, "0000"), pkcs11::CKR_PIN_INCORRECT);
    hsm::ok("login", pkcs11::login(c, sh, pkcs11::CKU_USER, hsm::pin()));
    let s2, rs2 = pkcs11::get_session_info(c, sh);
    tv::check("read-write user state", rs2 == pkcs11::CKR_OK && s2.state == pkcs11::CKS_RW_USER_FUNCTIONS);
    hsm::check_rv("logged in twice", pkcs11::login(c, sh, pkcs11::CKU_USER, hsm::pin()),
                  pkcs11::CKR_USER_ALREADY_LOGGED_IN);

    let r1, rr1 = pkcs11::generate_random(c, sh, 32);
    let r2, rr2 = pkcs11::generate_random(c, sh, 32);
    tv::check("random bytes", rr1 == pkcs11::CKR_OK && rr2 == pkcs11::CKR_OK && r1.len == 32 && r1 != r2);
    hsm::ok("seed", pkcs11::seed_random(c, sh, "more entropy"));

    // The user PIN changed, and back.
    hsm::ok("set PIN", pkcs11::set_pin(c, sh, hsm::pin(), "56789"));
    hsm::ok("logout", pkcs11::logout(c, sh));
    hsm::check_rv("old PIN refused", pkcs11::login(c, sh, pkcs11::CKU_USER, hsm::pin()), pkcs11::CKR_PIN_INCORRECT);
    hsm::ok("new PIN", pkcs11::login(c, sh, pkcs11::CKU_USER, "56789"));
    hsm::ok("set PIN back", pkcs11::set_pin(c, sh, "56789", hsm::pin()));
    hsm::ok("logout again", pkcs11::logout(c, sh));
    hsm::ok("close all", pkcs11::close_all_sessions(c, slot));
    hsm::check_rv("closed session", pkcs11::close_session(c, sh), pkcs11::CKR_SESSION_HANDLE_INVALID);

    // A token on the free slot: initialized, its user PIN set by the SO.
    var free_slot: u64 = 0;
    for s in all {
        let t, r = pkcs11::get_token_info(c, s);
        if r == pkcs11::CKR_OK && t.flags & pkcs11::CKF_TOKEN_INITIALIZED == 0 { free_slot = s; }
    }
    hsm::ok("C_InitToken", pkcs11::init_token(c, free_slot, "87654321", "second token"));
    let t2, rt2 = pkcs11::get_token_info(c, free_slot);
    // SoftHSM moves the new token to a slot of its own; find it by label.
    let again, rag = pkcs11::get_slot_list(c, true);
    var second: u64 = 0;
    for s in again {
        let t, r = pkcs11::get_token_info(c, s);
        if r == pkcs11::CKR_OK && t.label[..] == "second token" { second = s; }
    }
    tv::check("second token labelled", second != 0 || t2.label[..] == "second token");
    if second == 0 { second = free_slot; }
    let so, rso = pkcs11::open_session(c, second, pkcs11::CKF_SERIAL_SESSION | pkcs11::CKF_RW_SESSION);
    hsm::ok("SO login", pkcs11::login(c, so, pkcs11::CKU_SO, "87654321"));
    hsm::ok("C_InitPIN", pkcs11::init_pin(c, so, "2468"));
    pkcs11::logout(c, so);
    hsm::ok("user of the second token", pkcs11::login(c, so, pkcs11::CKU_USER, "2468"));
    pkcs11::close_session(c, so);

    hsm::ok("finalize", pkcs11::finalize(c));
    pkcs11::destroy(c);
    hsm::check_rv("destroyed", pkcs11::initialize(c), pkcs11::ERR_NO_MODULE);

    // Attribute encodings: an integer literal takes the CK_ULONG overload.
    var t: u8[>..] = [];
    pkcs11::attr(t, pkcs11::CKA_VALUE_LEN, 32);
    pkcs11::attr(t, pkcs11::CKA_TOKEN, true);
    pkcs11::attr(t, pkcs11::CKA_LABEL, "k");
    pkcs11::attr_date(t, pkcs11::CKA_START_DATE, 2026, 1, 2);
    tv::check_int("template length", t.len, 16 + 8 + 16 + 1 + 16 + 1 + 16 + 8);
    tv::check_eq("date", t[t.len - 8..], "20260102");

    // The same through p11.
    var m, rmo = p11::open_module(hsm::module_path());
    hsm::ok("p11 open_module", rmo);
    let slots, rsl = p11::slots(m);
    tv::check("p11 slots", rsl == pkcs11::CKR_OK && slots.len >= 2);
    var mine = slots[0];
    for &s in slots {
        let tinfo, r = p11::token_info(s);
        if tinfo.label[..] == hsm::label()[..] { mine = s; }
    }
    var ses, ros = p11::open_write_session(mine);
    hsm::ok("p11 session", ros);
    hsm::ok("p11 login", p11::login(ses, hsm::pin()));
    let rnd, rrnd = p11::generate_random(ses, 16);
    tv::check("p11 random", rrnd == pkcs11::CKR_OK && rnd.len == 16);
    let ms, rms = p11::mechanisms(mine);
    tv::check("p11 mechanisms", rms == pkcs11::CKR_OK && ms.len > 20);
    hsm::ok("p11 logout", p11::logout(ses));
    hsm::ok("p11 close", p11::close(ses));
    p11::destroy(m);
    tv::done("module");
}
