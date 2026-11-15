// Fuzz target: krb5_pac. The first byte picks:
//   0  a whole PAC: decode_pac (every buffer through its NDR decoder),
//      the claims buffers (MS-XCA decompression), the SID lists, the
//      signatures checked with fixed keys, and pac_verify as a service
//      runs it on a ticket's authorization data. The input is also read
//      as AuthorizationData holding the PAC (AD-IF-RELEVANT or not);
//   1  each buffer decoder on the raw input (the PAC header is a tall
//      gate): logon info, device info, delegation info, client info,
//      UPN_DNS_INFO, a signature, claims, a claims set, a SID, NDR strings.

import std;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.crypto;
import gslib.krb5.messages;
import gslib.krb5.ndr;
import gslib.krb5.service;
import gslib.krb5.pac;
import gslib.krb5.claims;

fn walk_pac(raw: const u8[:]) {
    let p, err = krb5::decode_pac(raw);
    let ls = krb5::logon_sids(p.logon_info);
    let ds = krb5::device_sids(p.device_info);
    let c13, e13 = krb5::pac_claims(raw, p, krb5::PAC_CLIENT_CLAIMS_INFO);
    let c15, e15 = krb5::pac_claims(raw, p, krb5::PAC_DEVICE_CLAIMS_INFO);
    if err != krb5::OK { return; }
    let ets: i32[2] = [18, 23];
    for et in ets {
        let k = krb5::make_key(et, if et == 18 { "0123456789abcdef0123456789abcdef" } else { "0123456789abcdef" });
        let vs = krb5::pac_verify_server(raw, p, k);
        let vk = krb5::pac_verify_kdc(p, k);
    }
    // As a service checks it: the PAC in the ticket's authorization data.
    let ctx = krb5::ApContext {
        client:      "alice", client_realm: "EXAMPLE.COM", client_type: 1, server: "", server_realm: "", session_key: krb5::no_key(),
        has_subkey:  false, subkey: krb5::no_key(), has_seq_number: false, seq_number: 0, ap_options: 0, ticket_flags: 0,
        authtime:    krb5::filetime_to_unix(p.client_info.client_id), endtime: 0, ctime: 0, cusec: 0, has_cksum: false,
        cksum:       krb5::no_checksum(), authz: [krb5::AuthData { ad_type: krb5::AD_WIN2K_PAC, data: raw }], kvno: 0,
        service_key: krb5::no_key(),
    };
    let p2, found, verr = krb5::pac_verify(ctx, krb5::make_key(18, "0123456789abcdef0123456789abcdef"));
}

fn whole(b: const u8[:]) {
    walk_pac(b);
    let ad, err = krb5::decode_authdata(b);
    if err == krb5::OK {
        let raw, found = krb5::pac_from_authz(ad);
        if found { walk_pac(raw); }
    }
}

fn buffers(b: const u8[:]) {
    { let v, e = krb5::decode_logon_info(b); let s = krb5::logon_sids(v); }
    { let v, e = krb5::decode_device_info(b); let s = krb5::device_sids(v); }
    { let v, e = krb5::decode_delegation_info(b); }
    { let v, e = krb5::decode_client_info(b); }
    { let v, e = krb5::decode_upn_dns_info(b); }
    { let v, e = krb5::decode_signature(b); }
    { let v, e = krb5::decode_claims(b); }
    { let v, e = krb5::decode_claims_set(b); }
    { let s, ok = krb5::sid_from_bytes(b); }
    {
        var n = krb5::ndr_open(b);
        let w = krb5::ndr_wstring(b, n);
        let s = krb5::ndr_sid(b, n);
    }
    { let u = krb5::utf16_to_utf8(b); }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let rest = data[1..];
    if data[0] % 2 == 0 { whole(rest); } else { buffers(rest); }
    return 0;
}

fn main() {}
