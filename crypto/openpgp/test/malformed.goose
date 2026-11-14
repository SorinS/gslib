// Malformed input must give an error, never a crash: every vector (keys,
// messages, signatures, armored or not), truncated at many points, with
// single bytes changed and with random bytes, through every reader
// (add_keys, read_message, verify_detached, verify_cleartext,
// list_packets, dearmor). A changed message must not read as OK with a
// good signature unless the change missed what is signed. The order of
// the changes is fixed (a seeded generator), so a failure repeats.
import std;
import gslib from "../../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.armor;
import gslib.crypto.openpgp.packet;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.sig;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;
import gslib.crypto.openpgp.dump;
import tv;

let V = "vectors/";
let FILES = ["ed.pub", "ed.sec", "prot.sec", "rsa.pub", "enc_ed.gpg", "enc_rsa.asc", "enc_signed.gpg", "enc_bzip2.gpg",
             "sym.gpg", "sym_aes128_zlib.asc", "sig_inline.gpg", "sig_inline_rsa.asc", "det.sig", "det_rsa.asc",
             "clear.asc", "rfc9580_a3_cert.asc", "rfc9580_a4_secret.asc", "rfc9580_a7_inline.asc", "rfc9580_a6_cleartext.asc",
             "pqc.sec", "pqc_prot.sec", "enc_pqc.gpg", "enc_pqc_signed.gpg", "rfc9980_a1_cert.asc", "rfc9980_a1_msg.asc",
             "rfc9980_a2_msg_seipd1.asc", "rfc9980_a3_sig.asc"];

var calls = 0;

// Every reader over one input; the results are not checked, only that
// they come back.
fn all_readers(kr: const openpgp::Keyring&, data: const u8[:], msg: const u8[:], pass: const u8[:]) {
    var k2 = openpgp::Keyring { .. };
    let e1 = openpgp::add_keys(k2, data);
    var m = openpgp::Message { .. };
    var o = openpgp::ReadOptions { .. };
    o.passphrase.append(pass);
    o.max_size = 1 << 20;
    let e2 = openpgp::read_message(kr, data, m, o);
    var md = openpgp::Message { .. };
    let e3 = openpgp::verify_detached(kr, msg, data, md);
    var mc = openpgp::Message { .. };
    let e4 = openpgp::verify_cleartext(kr, data, mc);
    var t: u8[>..] = [];
    let e5 = openpgp::list_packets(data, t);
    var b: u8[>..] = [];
    let l, e6 = openpgp::dearmor(data, b);
    calls += 6;
}

fn main() {
    var kr = openpgp::Keyring { .. };
    let ek = openpgp::add_keys(kr, tv::read(str(V, "ed.sec")));
    // Post-quantum: gpg's Kyber key, RFC 9980's A.1 and A.2 keys and A.3's ML-DSA certificate.
    for f in ["pqc.sec", "rfc9980_a1_secret.asc", "rfc9980_a2_secret.asc", "rfc9980_a3_cert.asc"] {
        let ep = openpgp::add_keys(kr, tv::read(str(V, f)));
    }
    var pass = tv::read(str(V, "passphrase.txt"));
    pass.resize(pass.len - 1);
    let msg = tv::read(str(V, "msg.txt"));
    var r = rng { 20261114 };
    for f in FILES {
        let orig = tv::read(str(V, f));
        // Binary too, for the armored ones: the changes then hit packets.
        var bin: u8[>..] = [];
        let eb = openpgp::decode_input(orig, bin);
        for form in 2 {
            let data = if form == 0 { orig[..] } else { bin[..] };
            if form == 1 && !openpgp::is_armored(orig) || data.len == 0 { continue; }
            // Truncations.
            for i in 24 {
                let cut = data.len * i / 24;
                all_readers(kr, data[..cut], msg, pass);
            }
            // Single changed bytes.
            var bad: u8[>..] = [];
            bad.append(data);
            for i in 40 {
                let at = r.rand_range(data.len);
                let was = bad[at];
                bad[at] = (bad[at] ^ (1 << (r.rand_range(8) as u8)));
                all_readers(kr, bad, msg, pass);
                // A changed signed message must not verify with its data intact.
                var m = openpgp::Message { .. };
                var o = openpgp::ReadOptions { .. };
                o.passphrase.append(pass);
                let e = openpgp::read_message(kr, bad, m, o);
                if e == openpgp::OK && openpgp::signature_status(m) == openpgp::OK && form == 1 {
                    tv::check(str(f, " changed at ", at, " still verifies"), m.data[..] == msg[..] || m.data[..] == "Testing\n" || f == "rfc9580_a7_inline.asc");
                }
                bad[at] = was;
            }
        }
    }
    // Random bytes, after a packet header and alone.
    for i in 200 {
        var junk: u8[>..] = [];
        let n = r.rand_range(300);
        if i % 2 == 0 { junk.push((0xC0 | r.rand_range(22)) as! u8); }
        for j in n { junk.push(r.rand_range(256) as! u8); }
        all_readers(kr, junk, msg, pass);
    }
    tv::check(str(calls, " calls returned"), calls > 0);
    tv::done("malformed");
}
