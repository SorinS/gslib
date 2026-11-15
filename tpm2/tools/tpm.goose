// goose-tpm: a TPM 2.0 from the command line, on gslib's tpm2:
//
//   goose-tpm [--tpm SPEC] getrandom N                   N random bytes, hex
//   goose-tpm [--tpm SPEC] info                          manufacturer, PCR banks
//   goose-tpm [--tpm SPEC] pcrread [--bank B] [--pcrs L]  PCR values (L: 0-7,14; B: sha256)
//   goose-tpm [--tpm SPEC] pcrextend --pcrs N (--data S | --digest HEX) [--bank B]
//   goose-tpm [--tpm SPEC] createprimary [--template ek-rsa|ek-ecc|srk-rsa|srk-ecc] [--persist HANDLE]
//   goose-tpm [--tpm SPEC] ekpub [--ecc]                 the EK's public key, PEM
//   goose-tpm [--tpm SPEC] ekcert [--ecc] [--out FILE]   the EK certificate from NV, PEM
//   goose-tpm [--tpm SPEC] quote --nonce HEX [--pcrs L] [--bank B] [--ecc] --out PREFIX
//                                                        PREFIX.pub (TPMT_PUBLIC of a new AK),
//                                                        .attest, .sig, .pcrs (the values)
//   goose-tpm verify-quote --in PREFIX --nonce HEX [--pcrs L] [--bank B] [--eventlog FILE]
//                                                        with no TPM: signature, nonce, PCRs
//   goose-tpm [--tpm SPEC] seal (--data S | --in FILE) [--pcrs L] [--bank B] [--auth-file F] --out FILE
//   goose-tpm [--tpm SPEC] unseal --in FILE [--auth-file F]
//   goose-tpm [--tpm SPEC] createkey [--ecc] --out FILE  a signing key under the SRK
//   goose-tpm [--tpm SPEC] sign --key FILE --in FILE [--out FILE]
//                                                        the file's SHA-256 signed (RSASSA or
//                                                        ECDSA), checked here, the signature out
//   goose-tpm [--tpm SPEC] nvdefine --index I --size N [--counter|--extend] [--auth-file F]
//   goose-tpm [--tpm SPEC] nvwrite --index I (--data S | --in FILE) [--offset N] [--auth-file F]
//   goose-tpm [--tpm SPEC] nvread --index I [--size N] [--offset N] [--auth-file F] [--out FILE]
//   goose-tpm [--tpm SPEC] nvundefine --index I
//   goose-tpm [--tpm SPEC] nvlist
//   goose-tpm eventlog --in FILE [--bank B]               a TCG event log replayed to PCRs
//
// SPEC is tcp:HOST:PORT (swtpm's data channel), mssim:HOST:PORT (the
// Microsoft simulator, platform channel on PORT+1), or device:/dev/tpmrm0
// (Linux), else $TPM2_TPM, else device:/dev/tpmrm0. Keys and sealed
// objects live under the ECC P-256 SRK, made again from the owner seed
// each time (the TCG's template, so the same key on the same TPM).
// Authorization values come from files, never arguments; the hierarchies'
// are empty. Every response is checked: Names against the public areas,
// session HMACs, a sign's signature against the key. Exit status 0 on
// success, 1 on failure, 2 on a usage error.
import std;
import os;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.transport;
import gslib.tpm2.session;
import gslib.tpm2.commands;
import gslib.tpm2.policy;
import gslib.tpm2.attest;
import gslib.crypto.x509;
import gslib.encoding.asn1;

struct Options {
    tpm:       u8[..256]  = [],
    bank:      u8[..16]   = [],
    pcrs:      u8[..64]   = [],
    data:      u8[..1024] = [],
    has_data:  bool       = false,
    digest:    u8[..256]  = [],
    template:  u8[..16]   = [],
    persist:   u8[..16]   = [],
    ecc:       bool       = false,
    out:       u8[..512]  = [],
    input:     u8[..512]  = [],
    key:       u8[..512]  = [],
    nonce:     u8[..256]  = [],
    eventlog:  u8[..512]  = [],
    auth_file: u8[..512]  = [],
    index:     u8[..16]   = [],
    size:      i64        = -1,
    offset:    i64        = 0,
    counter:   bool       = false,
    extend:    bool       = false,
}

fn usage() -> i32 {
    write_stderr("usage: goose-tpm [--tpm tcp:HOST:PORT|mssim:HOST:PORT|device:PATH] COMMAND [options]\n");
    write_stderr("  commands: getrandom N, info, pcrread, pcrextend, createprimary, ekpub, ekcert, quote,\n");
    write_stderr("            verify-quote, seal, unseal, createkey, sign, nvdefine, nvwrite, nvread,\n");
    write_stderr("            nvundefine, nvlist, eventlog (see the comment at the top of tools/tpm.goose)\n");
    return 2;
}

fn fail(msg: const u8[:]) -> i32 {
    write_stderr(str("goose-tpm: ", msg, "\n"));
    return 1;
}

fn tfail(t: const tpm2::Tpm&, what: const u8[:], e: i64) -> i32 {
    return fail(str(what, ": ", tpm2::describe(t, e)));
}

fn parse_u32(s: const u8[:]) -> u32, bool {
    var v: u64 = 0;
    if starts_with(s, "0x") {
        if s.len < 3 || s.len > 10 { return 0, false; }
        let digits: u8[>..] = if s.len % 2 == 1 { str("0", s[2..]) } else { str(s[2..]) };
        let b, ok = tpm2::unhex(digits);
        if !ok { return 0, false; }
        for c in b { v = (v << 8) | c; }
        return v as u32, true;
    }
    let n, ok = parse_int(s);
    if !ok || n < 0 || n > 0xffffffff { return 0, false; }
    return n as u32, true;
}

fn pad2(i: i64) -> u8[>..] { if i < 10 { str(" ", i) } else { str(i) } }

fn bank_of(o: const Options&) -> u16 {
    if o.bank.len == 0 { return tpm2::ALG_SHA256; }
    return tpm2::hash_by_name(o.bank);
}

fn mask_of(o: const Options&, dflt: u32) -> u32, bool {
    if o.pcrs.len == 0 { return dflt, true; }
    return tpm2::parse_pcr_list(o.pcrs);
}

fn read_auth(o: const Options&) -> u8[>..], bool {
    var a: u8[>..] = [];
    if o.auth_file.len == 0 { return a, true; }
    if !read_file(o.auth_file, a) { return a, false; }
    while a.len > 0 && (a[a.len - 1] == '\n' || a[a.len - 1] == '\r') { a.pop(); }
    if a.len > 64 { a.clear(); return a, false; }
    return a, true;
}

// The bytes a command works on: --data, or --in's file.
fn input(o: const Options&) -> u8[>..], bool {
    var b: u8[>..] = [];
    if o.has_data { b.append(o.data); return b, true; }
    if o.input.len > 0 { return b, read_file(o.input, b); }
    return b, false;
}

fn emit(o: const Options&, data: const u8[:]) -> bool {
    if o.out.len > 0 { return write_file(o.out, data); }
    write_stdout(data);
    return true;
}

fn srk(t: tpm2::Tpm&) -> tpm2::Object, i64 {
    var s = tpm2::pw();
    return tpm2::create_primary(t, tpm2::owner(), s, tpm2::srk_ecc_template());
}

// A key or sealed object file: TPM2B_PUBLIC then TPM2B_PRIVATE, as
// tpm2-tools' -u and -r files are when concatenated.
fn write_blob(path: const u8[:], o: const tpm2::Object&) -> bool {
    var b: u8[>..] = [];
    tpm2::put_2b(b, tpm2::marshal_public(o.public));
    tpm2::put_2b(b, o.private);
    return write_file(path, b);
}

fn read_blob(path: const u8[:]) -> tpm2::Object, bool {
    var o = tpm2::Object { .. };
    var b: u8[>..] = [];
    if !read_file(path, b) { return o, false; }
    var r = tpm2::reader(b);
    let p, pb = tpm2::read_public_2b(r);
    let priv = tpm2::get_2b(r, 2048);
    if !r.ok || tpm2::left(r) != 0 { return o, false; }
    o.public = p;
    o.private.append(priv);
    o.name = tpm2::public_name(p);
    return o, true;
}

fn pem(label: const u8[:], der: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    asn1::pem_encode(out, label, der);
    return out;
}

fn cmd_info(t: tpm2::Tpm&) -> i32 {
    let m, e = tpm2::manufacturer(t);
    if e != tpm2::OK { return tfail(t, "GetCapability", e); }
    let fw, e2 = tpm2::tpm_property(t, tpm2::PT_FIRMWARE_VERSION_1);
    print("manufacturer: ", m);
    print("firmware: 0x", tpm2::hex_u32(fw));
    let more, data, e3 = tpm2::get_capability(t, tpm2::CAP_PCRS, 0, 8);
    if e3 != tpm2::OK { return tfail(t, "GetCapability(PCRS)", e3); }
    var r = tpm2::reader(data);
    let sel = tpm2::read_pcr_selection(r);
    for s in sel {
        print("PCR bank ", tpm2::hash_name(s.hash), ": ", tpm2::pcr_list(s.mask).len, " PCRs");
    }
    return 0;
}

fn cmd_pcrread(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let bank = bank_of(o);
    let mask, ok = mask_of(o, 0xffffff);
    if bank == tpm2::ALG_ERROR || !ok { return usage(); }
    let vals, e = tpm2::pcr_read_bank(t, bank, mask);
    if e != tpm2::OK { return tfail(t, "PCR_Read", e); }
    let idx = tpm2::pcr_list(mask);
    print(tpm2::hash_name(bank), ":");
    for i in idx.len { print("  ", pad2(idx[i]), ": ", tpm2::hex(vals[i])); }
    return 0;
}

fn cmd_pcrextend(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let bank = bank_of(o);
    let pcr, ok = parse_int(o.pcrs);
    if bank == tpm2::ALG_ERROR || !ok || pcr < 0 || pcr > 23 { return usage(); }
    var d: u8[>..] = [];
    if o.digest.len > 0 {
        let b, okb = tpm2::unhex(o.digest);
        if !okb || b.len != tpm2::digest_size(bank) { return fail("--digest is not a digest of the bank's hash"); }
        d.append(b);
    } else if o.has_data {
        d.append(tpm2::hash(bank, o.data));
    } else {
        return usage();
    }
    var s = tpm2::pw();
    let e = tpm2::pcr_extend(t, pcr, s, bank, d);
    if e != tpm2::OK { return tfail(t, "PCR_Extend", e); }
    let v, ev = tpm2::pcr_read_bank(t, bank, (1 as u32) << (pcr as! u32));
    if ev == tpm2::OK { print(tpm2::hash_name(bank), ":", pcr, " ", tpm2::hex(v[0])); }
    return 0;
}

fn template_of(name: const u8[:]) -> tpm2::Public, bool {
    if name == "ek-rsa" { return tpm2::ek_rsa_template(), true; }
    if name == "ek-ecc" { return tpm2::ek_ecc_template(), true; }
    if name == "srk-rsa" { return tpm2::srk_rsa_template(), true; }
    if name == "srk-ecc" || name.len == 0 { return tpm2::srk_ecc_template(), true; }
    return tpm2::Public { .. }, false;
}

fn cmd_createprimary(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let tmpl, ok = template_of(o.template);
    if !ok { return usage(); }
    let hier = if starts_with(o.template, "ek") { tpm2::endorsement() } else { tpm2::owner() };
    var s = tpm2::pw();
    let k, e = tpm2::create_primary(t, hier, s, tmpl);
    if e != tpm2::OK { return tfail(t, "CreatePrimary", e); }
    print("handle: 0x", tpm2::hex_u32(k.handle));
    print("name: ", tpm2::hex(k.name));
    let spki, oks = tpm2::public_to_spki(k.public);
    if oks { write_stdout(pem("PUBLIC KEY", spki)); }
    if o.persist.len > 0 {
        let ph, okp = parse_u32(o.persist);
        if !okp || tpm2::handle_type(ph) != tpm2::HT_PERSISTENT { tpm2::flush(t, k.handle); return usage(); }
        let ee = tpm2::evict_control(t, tpm2::owner(), s, tpm2::object_of(k), ph);
        tpm2::flush(t, k.handle);
        if ee != tpm2::OK { return tfail(t, "EvictControl", ee); }
        print("persistent: 0x", tpm2::hex_u32(ph));
        return 0;
    }
    tpm2::flush(t, k.handle);
    return 0;
}

fn cmd_ekpub(t: tpm2::Tpm&, o: const Options&) -> i32 {
    var s = tpm2::pw();
    let k, e = tpm2::create_primary(t, tpm2::endorsement(), s, if o.ecc { tpm2::ek_ecc_template() } else { tpm2::ek_rsa_template() });
    if e != tpm2::OK { return tfail(t, "CreatePrimary EK", e); }
    tpm2::flush(t, k.handle);
    let spki, oks = tpm2::public_to_spki(k.public);
    if !oks { return fail("the EK cannot be written as a SubjectPublicKeyInfo"); }
    return if emit(o, pem("PUBLIC KEY", spki)) { 0 } else { fail("cannot write --out") };
}

fn cmd_ekcert(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let index = if o.ecc { tpm2::EK_CERT_ECC_INDEX } else { tpm2::EK_CERT_RSA_INDEX };
    let der, e = tpm2::read_ek_cert(t, index);
    if e == tpm2::ERR_TPM && tpm2::rc_name(t.rc) == "TPM_RC_HANDLE" { return fail(str("no EK certificate at 0x", tpm2::hex_u32(index))); }
    if e != tpm2::OK { return tfail(t, "NV_Read", e); }
    let c, ec = x509::parse(der);
    if ec != x509::OK { return fail("the EK certificate does not parse"); }
    write_stderr(str("subject: ", x509::subject_text(c), "\nissuer: ", x509::issuer_text(c), "\n"));
    return if emit(o, pem("CERTIFICATE", der)) { 0 } else { fail("cannot write --out") };
}

fn cmd_quote(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let bank = bank_of(o);
    let mask, okm = mask_of(o, 0xff);
    let nonce, okn = tpm2::unhex(o.nonce);
    if bank == tpm2::ALG_ERROR || !okm || !okn || o.out.len == 0 || nonce.len > 64 { return usage(); }
    let parent, ep = srk(t);
    if ep != tpm2::OK { return tfail(t, "CreatePrimary SRK", ep); }
    var s = tpm2::pw();
    let ak, ea = tpm2::create_loaded(t, tpm2::object_of(parent), s, if o.ecc { tpm2::ak_ecc_template() } else { tpm2::ak_rsa_template() });
    tpm2::flush(t, parent.handle);
    if ea != tpm2::OK { return tfail(t, "CreateLoaded AK", ea); }
    let sel = [tpm2::PcrSel { hash: bank, mask: mask }];
    let q, eq = tpm2::quote(t, tpm2::object_of(ak), s, nonce, tpm2::ALG_NULL, tpm2::ALG_SHA256, sel);
    tpm2::flush(t, ak.handle);
    if eq != tpm2::OK { return tfail(t, "Quote", eq); }
    let vals, ev = tpm2::pcr_read_bank(t, bank, mask);
    if ev != tpm2::OK { return tfail(t, "PCR_Read", ev); }
    // The values read after the quote must be the quote's.
    let a, e = tpm2::verify_quote(ak.public, q.attest, q.sig, nonce, sel, vals);
    if e != tpm2::OK { return fail(str("the quote does not verify: ", tpm2::error_text(e))); }
    var pv: u8[>..] = [];
    for v in vals { pv.append(v); }
    if !write_file(str(o.out, ".pub"), tpm2::marshal_public(ak.public)) || !write_file(str(o.out, ".attest"), q.attest)
       || !write_file(str(o.out, ".sig"), tpm2::marshal_signature(q.sig)) || !write_file(str(o.out, ".pcrs"), pv) {
        return fail("cannot write the quote's files");
    }
    print("quote of ", tpm2::hash_name(bank), " PCRs ", o.pcrs, " by AK ", tpm2::hex(ak.name), ": ", o.out, ".{pub,attest,sig,pcrs}");
    return 0;
}

fn cmd_verify_quote(o: const Options&) -> i32 {
    let bank = bank_of(o);
    let mask, okm = mask_of(o, 0xff);
    let nonce, okn = tpm2::unhex(o.nonce);
    if bank == tpm2::ALG_ERROR || !okm || !okn || o.input.len == 0 { return usage(); }
    var pb:     u8[>..] = [];
    var attest: u8[>..] = [];
    var sb:     u8[>..] = [];
    var pv:     u8[>..] = [];
    if !read_file(str(o.input, ".pub"), pb) || !read_file(str(o.input, ".attest"), attest) || !read_file(str(o.input, ".sig"), sb)
       || !read_file(str(o.input, ".pcrs"), pv) {
        return fail("cannot read the quote's files");
    }
    let ak, okp = tpm2::parse_public(pb);
    let sig, oks = tpm2::parse_signature(sb);
    if !okp || !oks { return fail("the AK or the signature does not parse"); }
    let n = tpm2::digest_size(bank);
    let idx = tpm2::pcr_list(mask);
    if pv.len != n * idx.len { return fail("the PCR values are not those of the selection"); }
    var vals: u8[..64][>..] = [];
    for i in idx.len {
        var v: u8[..64] = [];
        v.append(pv[i * n..(i + 1) * n]);
        vals.push(v);
    }
    let sel = [tpm2::PcrSel { hash: bank, mask: mask }];
    let a, e = tpm2::verify_quote(ak, attest, sig, nonce, sel, vals);
    if e != tpm2::OK { return fail(str("quote refused: ", tpm2::error_text(e))); }
    print("quote verified: AK ", tpm2::hex(tpm2::public_name(ak)), ", nonce, ", tpm2::hash_name(bank), " PCRs ", o.pcrs,
          ", clock ", a.clock, ", resets ", a.reset_count);
    if o.eventlog.len > 0 {
        var log: u8[>..] = [];
        if !read_file(o.eventlog, log) { return fail("cannot read the event log"); }
        let el = tpm2::check_event_log(log, bank, mask, vals);
        if el != tpm2::OK { return fail(str("event log refused: ", tpm2::error_text(el))); }
        print("event log replays to the quoted PCRs");
    }
    return 0;
}

fn cmd_seal(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let data, okd = input(o);
    let auth, oka = read_auth(o);
    if !okd || !oka || o.out.len == 0 || data.len > 128 { return usage(); }
    let bank = bank_of(o);
    let parent, ep = srk(t);
    if ep != tpm2::OK { return tfail(t, "CreatePrimary SRK", ep); }
    var p = tpm2::policy();
    if o.pcrs.len > 0 {
        let mask, okm = tpm2::parse_pcr_list(o.pcrs);
        if !okm || bank == tpm2::ALG_ERROR { tpm2::flush(t, parent.handle); return usage(); }
        let sel = [tpm2::PcrSel { hash: bank, mask: mask }];
        let vals, ev = tpm2::pcr_read_bank(t, bank, mask);
        if ev != tpm2::OK { tpm2::flush(t, parent.handle); return tfail(t, "PCR_Read", ev); }
        tpm2::policy_pcr(p, sel, tpm2::pcr_digest(bank, vals));
    }
    if auth.len > 0 { tpm2::policy_auth_value(p); }
    let policy = if o.pcrs.len > 0 || auth.len > 0 { p.digest[..] } else { p.digest[0..0] };
    // Salted to the SRK, the data encrypted on its way.
    let so = tpm2::SessionOpts { salt: true, salt_key: tpm2::object_of(parent), salt_pub: parent.public, .. };
    var s, es = tpm2::start_session_with(t, tpm2::SESSION_HMAC, so);
    if es != tpm2::OK { tpm2::flush(t, parent.handle); return tfail(t, "StartAuthSession", es); }
    s.attrs = tpm2::ATTR_CONTINUE | tpm2::ATTR_DECRYPT;
    let obj, e = tpm2::create(t, tpm2::object_of(parent), s, tpm2::sealed_template(policy), auth, data);
    tpm2::flush(t, s.handle);
    tpm2::flush(t, parent.handle);
    if e != tpm2::OK { return tfail(t, "Create", e); }
    if !write_blob(o.out, obj) { return fail("cannot write --out"); }
    var what: u8[>..] = [];
    if o.pcrs.len > 0 { format(what, " to ", tpm2::hash_name(bank), " PCRs ", o.pcrs); }
    if auth.len > 0 { what.append(" with an authValue"); }
    print("sealed ", data.len, " bytes", what, ": ", o.out);
    return 0;
}

fn cmd_unseal(t: tpm2::Tpm&, o: const Options&) -> i32 {
    var obj, ok = read_blob(o.input);
    let auth, oka = read_auth(o);
    if !ok || !oka { return fail("cannot read --in or --auth-file"); }
    let parent, ep = srk(t);
    if ep != tpm2::OK { return tfail(t, "CreatePrimary SRK", ep); }
    var pws = tpm2::pw();
    let el = tpm2::load(t, tpm2::object_of(parent), pws, obj);
    tpm2::flush(t, parent.handle);
    if el != tpm2::OK { return tfail(t, "Load", el); }
    var s = tpm2::pw();
    if obj.public.policy.len > 0 {
        // Replay the policy: the PCRs from --pcrs, PolicyAuthValue with an auth.
        let r, e = tpm2::start_session(t, tpm2::SESSION_POLICY);
        if e != tpm2::OK { tpm2::flush(t, obj.handle); return tfail(t, "StartAuthSession", e); }
        s = r;
        if o.pcrs.len > 0 {
            let mask, okm = tpm2::parse_pcr_list(o.pcrs);
            let sel = [tpm2::PcrSel { hash: bank_of(o), mask: mask }];
            let ep2 = tpm2::policy_pcr_tpm(t, s, sel);
            if !okm || ep2 != tpm2::OK { tpm2::flush(t, s.handle); tpm2::flush(t, obj.handle); return tfail(t, "PolicyPCR", ep2); }
        }
        if auth.len > 0 { tpm2::policy_auth_value_tpm(t, s); }
    }
    s.attrs |= if s.kind == tpm2::SESSION_PW { 0 } else { tpm2::ATTR_ENCRYPT };
    if s.kind == tpm2::SESSION_POLICY { s.sym_bits = 128; }
    let data, eu = tpm2::unseal(t, tpm2::object_of(obj, auth), s);
    if s.kind != tpm2::SESSION_PW { tpm2::flush(t, s.handle); }
    tpm2::flush(t, obj.handle);
    if eu != tpm2::OK { return tfail(t, "Unseal", eu); }
    return if emit(o, data) { 0 } else { fail("cannot write --out") };
}

fn cmd_createkey(t: tpm2::Tpm&, o: const Options&) -> i32 {
    if o.out.len == 0 { return usage(); }
    let parent, ep = srk(t);
    if ep != tpm2::OK { return tfail(t, "CreatePrimary SRK", ep); }
    var s = tpm2::pw();
    var tmpl = if o.ecc { tpm2::ecc_sign_template(tpm2::ECC_NIST_P256) } else { tpm2::rsa_sign_template() };
    tmpl.scheme = if o.ecc { tpm2::ALG_ECDSA } else { tpm2::ALG_RSASSA };
    tmpl.scheme_hash = tpm2::ALG_SHA256;
    let k, e = tpm2::create(t, tpm2::object_of(parent), s, tmpl);
    tpm2::flush(t, parent.handle);
    if e != tpm2::OK { return tfail(t, "Create", e); }
    if !write_blob(o.out, k) { return fail("cannot write --out"); }
    let spki, oks = tpm2::public_to_spki(k.public);
    if oks { write_stdout(pem("PUBLIC KEY", spki)); }
    return 0;
}

fn cmd_sign(t: tpm2::Tpm&, o: const Options&) -> i32 {
    var k, ok = read_blob(o.key);
    var msg: u8[>..] = [];
    if !ok || o.input.len == 0 || !read_file(o.input, msg) { return fail("cannot read --key or --in"); }
    let parent, ep = srk(t);
    if ep != tpm2::OK { return tfail(t, "CreatePrimary SRK", ep); }
    var s = tpm2::pw();
    let el = tpm2::load(t, tpm2::object_of(parent), s, k);
    tpm2::flush(t, parent.handle);
    if el != tpm2::OK { return tfail(t, "Load", el); }
    let d = tpm2::hash(tpm2::ALG_SHA256, msg);
    let sig, es = tpm2::sign(t, tpm2::object_of(k), s, d, tpm2::ALG_NULL, tpm2::ALG_SHA256);
    tpm2::flush(t, k.handle);
    if es != tpm2::OK { return tfail(t, "Sign", es); }
    let ev = tpm2::verify_signature(k.public, d, sig);
    if ev != tpm2::OK { return fail("the TPM's signature does not verify"); }
    let der, okd = tpm2::signature_der(sig, k.public);
    return if emit(o, der) { 0 } else { fail("cannot write --out") };
}

fn nv_index(o: const Options&) -> u32, bool {
    let i, ok = parse_u32(o.index);
    return i, ok && tpm2::handle_type(i) == tpm2::HT_NV_INDEX;
}

fn cmd_nvdefine(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let index, ok = nv_index(o);
    let auth, oka = read_auth(o);
    if !ok || !oka { return usage(); }
    var np = tpm2::NvPublic { index: index, attrs: tpm2::NV_AUTHWRITE | tpm2::NV_AUTHREAD | tpm2::NV_OWNERREAD | tpm2::NV_OWNERWRITE, .. };
    if o.counter { np.attrs |= tpm2::NV_TYPE_COUNTER; np.size = 8; }
    else if o.extend { np.attrs |= tpm2::NV_TYPE_EXTEND; np.size = 32; }
    else {
        if o.size <= 0 || o.size > tpm2::MAX_NV { return usage(); }
        np.size = o.size as u16;
    }
    var s = tpm2::pw();
    let e = tpm2::nv_define(t, tpm2::owner(), s, np, auth);
    if e != tpm2::OK { return tfail(t, "NV_DefineSpace", e); }
    print("defined 0x", tpm2::hex_u32(index), ", ", np.size, " bytes");
    return 0;
}

fn cmd_nvwrite(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let index, ok = nv_index(o);
    let auth, oka = read_auth(o);
    let data, okd = input(o);
    if !ok || !oka || !okd { return usage(); }
    let ix, en = tpm2::nv_entity(t, index, auth);
    if en != tpm2::OK { return tfail(t, "NV_ReadPublic", en); }
    var s = tpm2::pw();
    let n, name, e0 = tpm2::nv_read_public(t, index);
    var e = tpm2::OK;
    if (n.attrs & tpm2::NV_TYPE_EXTEND) != 0 { e = tpm2::nv_extend(t, ix, ix, s, data); }
    else if (n.attrs & tpm2::NV_TYPE_COUNTER) != 0 { e = tpm2::nv_increment(t, ix, ix, s); }
    else { e = tpm2::nv_write(t, ix, ix, s, data, o.offset); }
    if e != tpm2::OK { return tfail(t, "NV_Write", e); }
    return 0;
}

fn cmd_nvread(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let index, ok = nv_index(o);
    let auth, oka = read_auth(o);
    if !ok || !oka { return usage(); }
    let n, name, e0 = tpm2::nv_read_public(t, index);
    if e0 != tpm2::OK { return tfail(t, "NV_ReadPublic", e0); }
    let ix = tpm2::object_entity(index, name, auth);
    let size = if o.size >= 0 { o.size } else { n.size - o.offset };
    var s = tpm2::pw();
    let data, e = tpm2::nv_read(t, ix, ix, s, size, o.offset);
    if e != tpm2::OK { return tfail(t, "NV_Read", e); }
    if o.out.len > 0 { return if write_file(o.out, data) { 0 } else { fail("cannot write --out") }; }
    print(tpm2::hex(data));
    return 0;
}

fn cmd_nvundefine(t: tpm2::Tpm&, o: const Options&) -> i32 {
    let index, ok = nv_index(o);
    if !ok { return usage(); }
    var s = tpm2::pw();
    let e = tpm2::nv_undefine(t, tpm2::owner(), s, index);
    if e != tpm2::OK { return tfail(t, "NV_UndefineSpace", e); }
    return 0;
}

fn cmd_nvlist(t: tpm2::Tpm&) -> i32 {
    let hs, e = tpm2::get_handles(t, 0x01000000);
    if e != tpm2::OK { return tfail(t, "GetCapability(handles)", e); }
    for h in hs {
        let n, name, er = tpm2::nv_read_public(t, h);
        if er == tpm2::OK { print("0x", tpm2::hex_u32(h), "  size ", n.size, "  attributes 0x", tpm2::hex_u32(n.attrs)); }
        else { print("0x", tpm2::hex_u32(h), "  ", tpm2::describe(t, er)); }
    }
    return 0;
}

fn cmd_eventlog(o: const Options&) -> i32 {
    let bank = bank_of(o);
    var log: u8[>..] = [];
    if bank == tpm2::ALG_ERROR || o.input.len == 0 || !read_file(o.input, log) { return usage(); }
    let r, e = tpm2::replay_event_log(log, bank);
    if e != tpm2::OK { return fail(str("event log: ", tpm2::error_text(e))); }
    print(r.events, " events extended; ", tpm2::hash_name(bank), ":");
    for i in 24 { print("  ", pad2(i), ": ", tpm2::hex(r.pcrs[i])); }
    return 0;
}

fn run() -> i32 {
    let a = args();
    var o = Options { .. };
    var command: u8[..32] = [];
    var count:   i64      = -1;
    var i = 1;
    while i < a.len {
        let s = a[i];
        if s == "--ecc" { o.ecc = true; }
        else if s == "--counter" { o.counter = true; }
        else if s == "--extend" { o.extend = true; }
        else if s.len > 0 && s[0] != '-' {
            if command.len == 0 && s.len <= 32 { command.append(s); }
            else if command == "getrandom" && count < 0 {
                let n, ok = parse_int(s);
                if !ok || n < 0 || n > 4096 { return usage(); }
                count = n;
            } else { return usage(); }
        } else {
            if i + 1 >= a.len { return usage(); }
            i++;
            let v = a[i];
            var fits = true;
            if s == "--tpm" { fits = tpm2::set_bytes(o.tpm, v); }
            else if s == "--bank" { fits = tpm2::set_bytes(o.bank, v); }
            else if s == "--pcrs" { fits = tpm2::set_bytes(o.pcrs, v); }
            else if s == "--data" { fits = tpm2::set_bytes(o.data, v); o.has_data = true; }
            else if s == "--digest" { fits = tpm2::set_bytes(o.digest, v); }
            else if s == "--template" { fits = tpm2::set_bytes(o.template, v); }
            else if s == "--persist" { fits = tpm2::set_bytes(o.persist, v); }
            else if s == "--out" { fits = tpm2::set_bytes(o.out, v); }
            else if s == "--in" { fits = tpm2::set_bytes(o.input, v); }
            else if s == "--key" { fits = tpm2::set_bytes(o.key, v); }
            else if s == "--nonce" { fits = tpm2::set_bytes(o.nonce, v); }
            else if s == "--eventlog" { fits = tpm2::set_bytes(o.eventlog, v); }
            else if s == "--auth-file" { fits = tpm2::set_bytes(o.auth_file, v); }
            else if s == "--index" { fits = tpm2::set_bytes(o.index, v); }
            else if s == "--size" { let n, ok = parse_int(v); if !ok || n < 0 { return usage(); } o.size = n; }
            else if s == "--offset" { let n, ok = parse_int(v); if !ok || n < 0 || n > 0xffff { return usage(); } o.offset = n; }
            else { return usage(); }
            if !fits {
                write_stderr(str("goose-tpm: ", s, " is too long\n"));
                return 2;
            }
        }
        i++;
    }
    if command.len == 0 { return usage(); }
    // What needs no TPM.
    if command == "verify-quote" { return cmd_verify_quote(o); }
    if command == "eventlog" { return cmd_eventlog(o); }
    var spec: u8[>..] = [];
    if o.tpm.len > 0 { spec.append(o.tpm); }
    else if !env("TPM2_TPM", spec) || spec.len == 0 { spec.clear(); spec.append("device:/dev/tpmrm0"); }
    var t, e = tpm2::open(spec);
    if e != tpm2::OK { return tfail(t, str("cannot open ", spec), e); }
    let es = tpm2::startup(t);
    if es != tpm2::OK { tpm2::close(t); return tfail(t, "Startup", es); }
    var rc: i32 = 0;
    if command == "getrandom" {
        if count < 0 { rc = usage(); }
        else {
            let r, eg = tpm2::get_random(t, count);
            rc = if eg == tpm2::OK { print(tpm2::hex(r)); 0 } else { tfail(t, "GetRandom", eg) };
        }
    }
    else if command == "info" { rc = cmd_info(t); }
    else if command == "pcrread" { rc = cmd_pcrread(t, o); }
    else if command == "pcrextend" { rc = cmd_pcrextend(t, o); }
    else if command == "createprimary" { rc = cmd_createprimary(t, o); }
    else if command == "ekpub" { rc = cmd_ekpub(t, o); }
    else if command == "ekcert" { rc = cmd_ekcert(t, o); }
    else if command == "quote" { rc = cmd_quote(t, o); }
    else if command == "seal" { rc = cmd_seal(t, o); }
    else if command == "unseal" { rc = cmd_unseal(t, o); }
    else if command == "createkey" { rc = cmd_createkey(t, o); }
    else if command == "sign" { rc = cmd_sign(t, o); }
    else if command == "nvdefine" { rc = cmd_nvdefine(t, o); }
    else if command == "nvwrite" { rc = cmd_nvwrite(t, o); }
    else if command == "nvread" { rc = cmd_nvread(t, o); }
    else if command == "nvundefine" { rc = cmd_nvundefine(t, o); }
    else if command == "nvlist" { rc = cmd_nvlist(t); }
    else { rc = usage(); }
    tpm2::close(t);
    return rc;
}

fn main() {
    let rc = run();
    if rc != 0 { exit(rc); }
}
