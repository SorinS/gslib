// Fuzz target: tpm2_eventlog. A crypto-agile TCG event log replayed
// (replay_event_log) for the SHA-256, SHA-1 and SHA-384 banks, and checked
// (check_event_log) against the PCRs its own SHA-256 replay gave and
// against PCRs of zeros.

import std;
import gslib from "../..";
import gslib.tpm2;
import gslib.tpm2.commands;
import gslib.tpm2.attest;

export fn fuzz_one(data: const u8[:]) -> i32 {
    let r, e = tpm2::replay_event_log(data, tpm2::ALG_SHA256);
    let r1, e1 = tpm2::replay_event_log(data, tpm2::ALG_SHA1);
    let r2, e2 = tpm2::replay_event_log(data, tpm2::ALG_SHA384);
    if e == tpm2::OK {
        var vals: u8[..64][>..] = [];
        for i in [0, 1, 4, 7] { vals.push(r.pcrs[i]); }
        let _ = tpm2::check_event_log(data, tpm2::ALG_SHA256, 0x93, vals);
        var zeros: u8[..64][>..] = [];
        for i in 24 { var z: u8[..64] = []; z.resize(32, 0); zeros.push(z); }
        let _ = tpm2::check_event_log(data, tpm2::ALG_SHA256, 0xffffff, zeros);
    }
    return 0;
}

fn main() {}
