// sspi: what is the same on every platform: status codes and their
// text, the package lines the C half writes, and the WWW-Authenticate
// values the Negotiate helper reads.

import std;
import gslib from "../..";
import gslib.sspi;
import gslib.sspi.negotiate;

fn main() {
    print("== codes");
    for st in [sspi::OK, sspi::SEC_I_CONTINUE_NEEDED, sspi::SEC_E_INCOMPLETE_MESSAGE, sspi::SEC_E_LOGON_DENIED,
               sspi::SEC_E_UNTRUSTED_ROOT, sspi::CERT_E_CN_NO_MATCH, sspi::SEC_E_UNSUPPORTED_FUNCTION,
               sspi::END, sspi::RENEGOTIATE, -2146893000, 7] {
        print(sspi::error_text(st));
    }
    assert(sspi::hex32(sspi::SEC_E_INVALID_TOKEN) == "0x80090308");
    assert(sspi::failed(sspi::SEC_E_INVALID_TOKEN) && !sspi::failed(sspi::SEC_I_CONTINUE_NEEDED));

    print("== package lines");
    let p = sspi::parse_package("Negotiate\t9136819\t1\t9\t48256\tMicrosoft Package Negotiator");
    print(str(p.name, " caps=", p.capabilities, " version=", p.version, " rpcid=", p.rpcid,
              " max_token=", p.max_token, " comment=", p.comment));
    let q = sspi::parse_package("NTLM\t42");
    print(str(q.name, " caps=", q.capabilities, " max_token=", q.max_token, " comment='", q.comment, "'"));

    print("== challenges");
    for v in ["Negotiate YWJj", "NTLM, Negotiate YWJj", "Negotiate, NTLM", "negotiate   YWJj  , Basic realm=x",
              "Basic realm=\"x\"", "Negotiate !!!", "", "NTLM TlRMTVNTUAAB"] {
        let t, ok = sspi::http_challenge_token(v, "Negotiate");
        print(str("'", v, "' -> ", ok, " '", t, "'"));
    }
    let t, ok = sspi::http_challenge_token("Negotiate abc, NTLM TlRMTVNTUAAB", "NTLM");
    print(str("NTLM -> ", ok, " ", t.len));
}
