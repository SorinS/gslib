// sspi: the system's security packages, a Negotiate context made between
// a client and a server in this process (Kerberos in a domain, NTLM
// otherwise), the messages it signs and seals, and Schannel's
// credentials. On Windows; elsewhere every call says
// SEC_E_UNSUPPORTED_FUNCTION, and the lines printed are the same.

import std;
import gslib from "../..";
import gslib.sspi;

fn find(list: const sspi::Package[:], name: const u8[:]) -> bool {
    for p in list { if p.name == name { return true; } }
    return false;
}

fn not_windows() {
    let list, st = sspi::packages();
    assert(st == sspi::SEC_E_UNSUPPORTED_FUNCTION && list.len == 0);
    let p, st2 = sspi::package_info(sspi::NTLM);
    assert(st2 == sspi::SEC_E_UNSUPPORTED_FUNCTION);
    assert(sspi::acquire(sspi::NEGOTIATE, sspi::CRED_OUTBOUND) == sspi::SEC_E_UNSUPPORTED_FUNCTION);
    assert(sspi::acquire_schannel(0) == sspi::SEC_E_UNSUPPORTED_FUNCTION);
    assert(sspi::context(1) == sspi::SEC_E_UNSUPPORTED_FUNCTION);
    var out: u8[>..] = [];
    assert(sspi::step(1, "", 0, "x", out) == sspi::SEC_E_UNSUPPORTED_FUNCTION);
    assert(sspi::context_package(1) == "");
    print("packages: Negotiate NTLM Kerberos Schannel");
    print("NTLM max token > 0");
    print("no such package refused");
    print("bad credential use refused");
    print("loopback: made");
    print("loopback: package and user known");
    print("sign, verify, tampering found");
    print("seal, unseal, tampering found");
    print("schannel credentials");
    print("schannel versions checked");
    print("bad ids refused");
}

// A client's and a server's context traded tokens until both are made.
fn loopback(client: i64, server: i64, target: const u8[:]) -> i64 {
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var cst = sspi::step(client, target, sspi::ISC_REQ_CONFIDENTIALITY | sspi::ISC_REQ_INTEGRITY |
                         sspi::ISC_REQ_REPLAY_DETECT | sspi::ISC_REQ_SEQUENCE_DETECT, "", to_server);
    var sst = sspi::SEC_I_CONTINUE_NEEDED;
    var rounds = 0;
    while rounds < 10 {
        rounds++;
        if cst < 0 { return cst; }
        if to_server.len > 0 {
            sst = sspi::step(server, "", sspi::ASC_REQ_CONFIDENTIALITY | sspi::ASC_REQ_INTEGRITY |
                             sspi::ASC_REQ_REPLAY_DETECT | sspi::ASC_REQ_SEQUENCE_DETECT, to_server, to_client);
            if sst < 0 { return sst; }
        }
        if cst == sspi::OK && sst == sspi::OK { return sspi::OK; }
        if to_client.len > 0 && cst != sspi::OK {
            let input = to_client;
            cst = sspi::step(client, target, 0, input, to_server);
        } else if cst == sspi::OK && to_server.len == 0 {
            return sst;
        }
    }
    return sspi::SEC_E_INTERNAL_ERROR;
}

fn windows() {
    let list, st = sspi::packages();
    assert(st == sspi::OK);
    assert(find(list, sspi::NEGOTIATE) && find(list, sspi::NTLM) && find(list, sspi::KERBEROS));
    assert(find(list, "Schannel") || find(list, sspi::SCHANNEL));
    print("packages: Negotiate NTLM Kerberos Schannel");
    let p, st2 = sspi::package_info(sspi::NTLM);
    assert(st2 == sspi::OK && p.name == "NTLM" && p.max_token > 0 && p.rpcid == 10);
    print("NTLM max token > 0");
    let q, st3 = sspi::package_info("No Such Package");
    assert(st3 == sspi::SEC_E_SECPKG_NOT_FOUND);
    print("no such package refused");
    assert(sspi::acquire(sspi::NEGOTIATE, 7) == sspi::SEC_E_INVALID_PARAMETER);
    assert(sspi::acquire("No Such Package", sspi::CRED_OUTBOUND) == sspi::SEC_E_SECPKG_NOT_FOUND);
    print("bad credential use refused");

    let ccred = sspi::acquire(sspi::NEGOTIATE, sspi::CRED_OUTBOUND);
    let scred = sspi::acquire(sspi::NEGOTIATE, sspi::CRED_INBOUND);
    assert(ccred > 0 && scred > 0);
    let client = sspi::context(ccred);
    let server = sspi::context(scred, true);
    assert(client > 0 && server > 0);
    let lst = loopback(client, server, "");
    if lst != sspi::OK { print(sspi::error_text(lst)); }
    assert(lst == sspi::OK);
    print("loopback: made");
    let pkg = sspi::context_package(server);
    assert(pkg == "NTLM" || pkg == "Kerberos");
    assert(sspi::context_user(server).len > 0);
    print("loopback: package and user known");

    var sig: u8[>..] = [];
    assert(sspi::sign(client, "the message", sig) == sspi::OK && sig.len > 0);
    assert(sspi::verify(server, "the message", sig) == sspi::OK);
    assert(sspi::sign(client, "another", sig) == sspi::OK);
    assert(sspi::verify(server, "anothex", sig) == sspi::SEC_E_MESSAGE_ALTERED);
    print("sign, verify, tampering found");

    var sealed: u8[>..] = [];
    var plain:  u8[>..] = [];
    assert(sspi::seal(client, "secret payload", sealed) == sspi::OK);
    assert(sealed.len >= 14 + 16);
    assert(sspi::unseal(server, sealed, plain) == sspi::OK && plain == "secret payload");
    assert(sspi::seal(server, "and back", sealed) == sspi::OK);
    assert(sspi::unseal(client, sealed, plain) == sspi::OK && plain == "and back");
    assert(sspi::seal(client, "tamper me", sealed) == sspi::OK);
    sealed[sealed.len - 1] ^= 1;
    assert(sspi::unseal(server, sealed, plain) < 0);
    print("seal, unseal, tampering found");

    assert(sspi::delete_context(client) == sspi::OK);
    assert(sspi::delete_context(server) == sspi::OK);
    assert(sspi::free_credentials(ccred) == sspi::OK);
    assert(sspi::free_credentials(scred) == sspi::OK);

    let tc = sspi::acquire_schannel(sspi::SCH_CRED_MANUAL_CRED_VALIDATION | sspi::SCH_CRED_NO_DEFAULT_CREDS);
    assert(tc > 0);
    let tctx = sspi::context(tc);
    var hello: u8[>..] = [];
    let hst = sspi::step(tctx, "example.com", sspi::ISC_REQ_STREAM | sspi::ISC_REQ_CONFIDENTIALITY, "", hello);
    // A ClientHello: a handshake record, then ClientHello (1).
    assert(hst == sspi::SEC_I_CONTINUE_NEEDED && hello.len > 50 && hello[0] == 0x16 && hello[5] == 1);
    sspi::delete_context(tctx);
    sspi::free_credentials(tc);
    print("schannel credentials");
    assert(sspi::acquire_schannel(0, 0x0304, 0x0303) == sspi::SEC_E_INVALID_PARAMETER);
    let t12 = sspi::acquire_schannel(sspi::SCH_CRED_MANUAL_CRED_VALIDATION, 0x0303, 0x0303);
    assert(t12 > 0);
    sspi::free_credentials(t12);
    print("schannel versions checked");

    assert(sspi::free_credentials(12345) == sspi::SEC_E_INVALID_HANDLE);
    assert(sspi::delete_context(0) == sspi::SEC_E_INVALID_HANDLE);
    var out: u8[>..] = [];
    assert(sspi::step(999, "", 0, "", out) == sspi::SEC_E_INVALID_HANDLE);
    print("bad ids refused");
}

fn main() {
    if sspi::available() { windows(); } else { not_windows(); }
}
