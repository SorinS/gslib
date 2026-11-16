// packages: the security packages Windows has (EnumerateSecurityPackages),
// one a line: its name, RPC id, largest token and description.
//
//   packages

import std;
import os;
import gslib from "../..";
import gslib.sspi;

fn main() {
    if !sspi::available() {
        print("SSPI is Windows'; nothing to list here");
        return;
    }
    let list, st = sspi::packages();
    if st != sspi::OK {
        write_stderr(str("packages: ", sspi::error_text(st), "\n"));
        exit(1);
    }
    for p in list {
        print(str(p.name, "  rpcid ", p.rpcid, "  max token ", p.max_token, "  ", p.comment));
    }
}
