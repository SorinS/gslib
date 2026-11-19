// The client against the in-memory server (kmip.local), in every
// version: test/scenario.goose's checks, as kmip.server answers them.

import std;
import gslib from "../..";
import gslib.kmip;
import gslib.kmip.client;
import gslib.kmip.local;
import scenario;

fn main() {
    let versions: const u8[:][8] = ["1.0", "1.1", "1.2", "1.3", "1.4", "2.0", "2.1", "auto"];
    for v in versions {
        var c = kmip::local("alice");
        let before = scenario::failures;
        let n = scenario::checks;
        scenario::run(c, v, "local");
        print(v, ": ", scenario::checks - n, " checks, ", scenario::failures - before, " failures");
    }
    print(scenario::checks, " checks, ", scenario::failures, " failures");
    if scenario::failures > 0 { exit(1); }
}
