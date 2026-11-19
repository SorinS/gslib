// kmip.local: a client whose server is in the same program, the
// in-memory one of kmip.server, with no TLS between: every operation of
// kmip.client works on it as on a Client. For tests, and for a program
// that wants KMIP's model without a key manager.
//
//   var c = kmip::local("alice");
//   let uid, e = kmip::create(c, kmip::OBJ_SYMMETRIC_KEY, a);

namespace kmip;

import std;
import kmip;
import kmip.messages;
import kmip.server;

struct Local {
    version: Version,
    cred: Credential,
    last_status: u32,
    last_reason: u32,
    last_message: u8[..1024],
    owner: u8[..128],
    srv: Server,
}

fn local(owner: const u8[:]) -> Local {
    var c = Local { version: V1_2, cred: no_credential(), last_status: 0, last_reason: 0, last_message: [],
                    owner: [], srv: server() };
    c.owner.append(owner[..::min(owner.len, 128)]);
    return c;
}

fn exchange(c: Local&, msg: const u8[:], resp: u8[>..]&) -> i64 {
    handle(c.srv, c.owner, msg, resp);
    return OK;
}
