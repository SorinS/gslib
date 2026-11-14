// openpgp.dump: a packet listing in the manner of gpg --list-packets: each
// packet's offset, header and length, and what this package reads of it.
// Encrypted and compressed data are not opened.
//
//   var text: u8[>..] = [];
//   let err = openpgp::list_packets(data, text);   // armored or binary

namespace openpgp;

import std;
import crypto.openpgp;
import crypto.openpgp.armor;
import crypto.openpgp.packet;
import crypto.openpgp.key;
import crypto.openpgp.sig;

fn dump_key(out: u8[>..]&, tag: i64, body: const u8[:]) {
    let k, err = parse_key(tag, body);
    if err != OK { out.append(str("\t", error_text(err), "\n")); return; }
    out.append(str("\tversion ", k.version, ", algo ", k.algo, " (", algo_name(k.algo), "), created ", k.created, "\n"));
    out.append(str("\ttype: ", key_type_name(k), "\n"));
    if k.algo == PK_ECDH { out.append(str("\tkdf: hash ", k.kdf_hash, ", cipher ", k.kdf_cipher, "\n")); }
    if k.has_secret {
        if k.stub { out.append("\tsecret: gnu-dummy (none here)\n"); }
        else if k.locked {
            let s2k, iv_at, e = protection_of(k);
            out.append(str("\tsecret: protected, usage ", k.sec_raw[0], ", S2K ", s2k.kind, ", hash ", s2k.hash,
                           ", count ", s2k.count, "\n"));
        } else { out.append("\tsecret: unprotected\n"); }
    }
    out.append("\tfingerprint: ");
    hex_append(out, k.fpr);
    out.append("\n\tkeyid: ");
    hex_append(out, k.keyid);
    out.push('\n');
}

fn dump_sig(out: u8[>..]&, body: const u8[:]) {
    let s, err = parse_signature(body);
    if err != OK { out.append(str("\t", error_text(err), "\n")); return; }
    out.append(str("\tversion ", s.version, ", class 0x", hex([s.sigtype as! u8], false), " (", sig_type_name(s.sigtype),
                   "), algo ", s.pk_algo, ", digest ", s.hash, " (", hash_name(s.hash), ")\n"));
    out.append(str("\tcreated ", s.created));
    if s.expires > 0 { out.append(str(", expires after ", s.expires)); }
    if s.key_expires > 0 { out.append(str(", key expires after ", s.key_expires)); }
    out.push('\n');
    if s.has_issuer { out.append("\tissuer key ID "); hex_append(out, s.issuer); out.push('\n'); }
    if s.issuer_fpr.len > 0 { out.append("\tissuer fpr "); hex_append(out, s.issuer_fpr); out.push('\n'); }
    if s.has_flags { out.append(str("\tkey flags 0x", hex([(s.flags & 255) as! u8], false), "\n")); }
    if s.embedded.len > 0 { out.append("\tembedded signature\n"); }
    if s.unknown_critical { out.append("\tunknown critical subpacket\n"); }
}

// Lists the packets of data (its first armored block, or binary) into out.
fn list_packets(data: const u8[:], out: u8[>..]&) -> i64 {
    var bin:    u8[>..] = [];
    var hashes: u8[>..] = [];
    if is_armored(data) {
        let at, l = find_begin(data, 0);
        if at < 0 { return ERR_MALFORMED; }
        if l[..] == ARMOR_SIGNED_MESSAGE {
            let b, l2 = find_begin(data, at + 1, ARMOR_SIGNATURE);
            if b < 0 { return ERR_MALFORMED; }
            out.append("# cleartext signed message\n");
            let label, next, err = dearmor_at(data, b, bin, hashes);
            if err != OK { return err; }
        } else {
            let label, next, err = dearmor_at(data, at, bin, hashes);
            if err != OK { return err; }
        }
    } else {
        bin.append(data);
    }
    var at = 0;
    while at < bin.len {
        let p, err = next_packet(bin, at);
        if err != OK { out.append(str("# off=", at, " malformed packet\n")); return ERR_MALFORMED; }
        var body: u8[>..] = [];
        packet_body(bin, p, body);
        out.append(str("# off=", p.at, " ctb=", hex([bin[p.at]], false), " tag=", p.tag, " hlen=", p.body - p.at,
                       " plen=", body.len, if p.partial { " partial" } else { "" },
                       if p.indeterminate { " indeterminate" } else { "" }, if p.old { "" } else { " new-ctb" }, "\n"));
        out.append(str(":", tag_name(p.tag), " packet:\n"));
        let t = p.tag;
        if t == TAG_PUBLIC_KEY || t == TAG_SECRET_KEY || t == TAG_PUBLIC_SUBKEY || t == TAG_SECRET_SUBKEY {
            dump_key(out, t, body);
        } else if t == TAG_SIGNATURE {
            dump_sig(out, body);
        } else if t == TAG_USER_ID {
            out.append(str("\t\"", body, "\"\n"));
        } else if t == TAG_PKESK && body.len >= 10 {
            out.append(str("\tversion ", body[0], ", algo ", body[9], ", keyid "));
            hex_append(out, body[1..9]);
            out.push('\n');
        } else if t == TAG_SKESK && body.len >= 2 {
            out.append(str("\tversion ", body[0], ", cipher ", body[1], " (", cipher_name(body[1]), ")\n"));
        } else if t == TAG_SEIPD && body.len >= 1 {
            out.append(str("\tversion ", body[0], "\n"));
        } else if t == TAG_AEAD && body.len >= 4 {
            out.append(str("\tversion ", body[0], ", cipher ", body[1], ", aead ", body[2], ", chunk byte ", body[3], "\n"));
        } else if t == TAG_COMPRESSED && body.len >= 1 {
            out.append(str("\talgo ", body[0], "\n"));
        } else if t == TAG_ONE_PASS && body.len >= 4 {
            out.append(str("\tversion ", body[0], ", class 0x", hex([body[1]], false), ", digest ", body[2], ", algo ", body[3], "\n"));
        } else if t == TAG_LITERAL && body.len >= 6 {
            let nl: i64 = body[1];
            if 6 + nl <= body.len {
                out.append(str("\tmode ", body[..1], ", name \"", body[2..2 + nl], "\", created ", be32(body, 2 + nl),
                               ", ", body.len - 6 - nl, " bytes\n"));
            }
        }
        at = p.end;
    }
    return OK;
}
