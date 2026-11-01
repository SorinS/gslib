// krb5.claims: the PAC's claims (MS-PAC §2.11, §2.13; MS-ADTS §2.2.18):
// PAC_CLIENT_CLAIMS_INFO and PAC_DEVICE_CLAIMS_INFO hold a
// CLAIMS_SET_METADATA whose ClaimsSet is itself NDR, compressed with
// MS-XCA's LZ77+Huffman when large (decompressed here). Each claim has an
// id ("ad://ext/department:..."), a type and its values: INT64, UINT64,
// STRING or BOOLEAN (as ULONG64, MS-ADTS §2.2.18.6).
//
// LZNT1 and plain LZ77 (formats 2 and 3), which AD does not use for
// claims, are refused.

namespace krb5;

import std;
import krb5.ndr;
import krb5.pac;

let CLAIM_TYPE_INT64: u32 = 1;
let CLAIM_TYPE_UINT64: u32 = 2;
let CLAIM_TYPE_STRING: u32 = 3;
let CLAIM_TYPE_BOOLEAN: u32 = 6;

let COMPRESSION_NONE: u32 = 0;
let COMPRESSION_LZNT1: u32 = 2;
let COMPRESSION_XPRESS: u32 = 3;
let COMPRESSION_XPRESS_HUFF: u32 = 4;

// One claim: integer values (INT64 as i64 bits, UINT64 and BOOLEAN as
// they are) or strings, by type.
struct Claim { id: u8[], claim_type: u32, ints: u64[], strings: u8[][] }
struct ClaimsArray { source_type: u32, claims: Claim[] }

// --- MS-XCA LZ77+Huffman (MS-XCA §2.2.4) -----------------------------------------

// Decompresses `src` into exactly `size` bytes (the uncompressed size
// the metadata gives); ok false on malformed input.
fn xpress_huff_decompress(src: const u8[:], size: i64, out: u8[>..]&) -> bool {
    if size < 0 || size > 64 << 20 { return false; }
    var table: u16[32768] = [0; 32768];
    var lens: u8[512] = [0; 512];
    var pos = 0;
    while out.len < size {
        // The block's code lengths: 512 symbols, a nibble each.
        if pos + 256 + 4 > src.len { return false; }
        for i in 256 {
            lens[2 * i] = src[pos + i] & 15;
            lens[2 * i + 1] = src[pos + i] >> 4;
        }
        // The canonical code: by length, then by symbol, 15 bits at most.
        var next: i64 = 0;
        for l in 1..16 {
            for sym in 512 {
                if lens[sym] != l { continue; }
                let span = 1 << (15 - l);
                if next + span > 32768 { return false; }
                for k in span { table[next + k] = sym as! u16; }
                next += span;
            }
        }
        if next == 0 { return false; }
        pos += 256;
        let w0 = le16(src, pos) as u64;
        let w1 = le16(src, pos + 2) as u64;
        var bits: u64 = (w0 << 16 | w1) << 32;     // the next bits, at the top of 64
        var extra: i64 = 16;
        pos += 4;
        let block_end = out.len + 65536;
        while out.len < block_end && out.len < size {
            let peek = (bits >> 49) as! i64;
            let sym = table[peek] as i64;
            let sl = lens[sym] as i64;
            if sl == 0 { return false; }
            bits = bits << (sl as! u64);
            extra -= sl;
            if extra < 0 {
                if pos + 2 > src.len { return false; }
                bits = bits | (le16(src, pos) as u64) << ((32 - extra) as! u64);
                extra += 16;
                pos += 2;
            }
            if sym < 256 {
                out.push(sym as! u8);
                continue;
            }
            var s = sym - 256;
            var length = s & 15;
            let off_bits = s >> 4;
            if length == 15 {
                if pos + 1 > src.len { return false; }
                length = src[pos];
                pos++;
                if length == 255 {
                    if pos + 2 > src.len { return false; }
                    length = le16(src, pos);
                    pos += 2;
                    if length == 0 {
                        if pos + 4 > src.len { return false; }
                        length = le32v(src, pos);
                        pos += 4;
                    }
                    if length < 15 { return false; }
                    length -= 15;
                }
                length += 15;
            }
            length += 3;
            var offset: i64 = 1 << off_bits;
            if off_bits > 0 {
                offset += (bits >> ((64 - off_bits) as! u64)) as! i64;
                bits = bits << (off_bits as! u64);
                extra -= off_bits;
                if extra < 0 {
                    if pos + 2 > src.len { return false; }
                    bits = bits | (le16(src, pos) as u64) << ((32 - extra) as! u64);
                    extra += 16;
                    pos += 2;
                }
            }
            if offset > out.len || out.len + length > size { return false; }
            let from = out.len - offset;
            for k in length { out.push(out[from + k]); }
        }
    }
    return true;
}

// --- The claims' NDR ---------------------------------------------------------------

fn ndr_claim_values(b: const u8[:], n: Ndr&, t: u32, count: u32, ints: u64[>..]&, strings: u8[][>..]&) {
    let max = ndr_u32(b, n);
    if max != count || max > 65536 { n.bad = true; return; }
    if t == CLAIM_TYPE_STRING {
        var ptrs: u32[>..] = [];
        for i in max { ptrs.push(ndr_u32(b, n)); }
        for p in ptrs {
            var s: u8[>..] = [];
            if p != 0 { s = ndr_wstring(b, n); }
            strings.push(copy(s));
        }
        return;
    }
    for i in max { ints.push(ndr_u64(b, n)); }
}

// A ClaimsSet (decompressed): its arrays of claims.
fn decode_claims_set(b: const u8[:]) -> ClaimsArray[>..], i64 {
    var out: ClaimsArray[>..] = [];
    var n = ndr_open(b);
    if n.bad { return out, ERR_NDR; }
    let top = ndr_u32(b, n);
    let array_count = ndr_u32(b, n);
    let arrays_ptr = ndr_u32(b, n);
    let rtype = ndr_u16(b, n);
    let rsize = ndr_u32(b, n);
    let rptr = ndr_u32(b, n);
    if top == 0 { return out, ERR_NDR; }
    if arrays_ptr != 0 {
        let max = ndr_u32(b, n);
        if max != array_count || max > 1024 { return out, ERR_NDR; }
        var sources: u32[>..] = [];
        var counts: u32[>..] = [];
        var eptrs: u32[>..] = [];
        for i in max {
            sources.push(ndr_u16(b, n));
            counts.push(ndr_u32(b, n));
            eptrs.push(ndr_u32(b, n));
        }
        for i in sources.len {
            var claims: Claim[>..] = [];
            if eptrs[i] != 0 {
                let emax = ndr_u32(b, n);
                if emax != counts[i] || emax > 65536 { return out, ERR_NDR; }
                var idptrs: u32[>..] = [];
                var types: u32[>..] = [];
                var vcounts: u32[>..] = [];
                var vptrs: u32[>..] = [];
                for k in emax {
                    idptrs.push(ndr_u32(b, n));
                    let t = ndr_u16(b, n);
                    // The union's discriminant, marshaled again (NDR's
                    // non-encapsulated union), then its arm.
                    let disc = ndr_u16(b, n);
                    if disc != t { n.bad = true; }
                    types.push(t);
                    vcounts.push(ndr_u32(b, n));
                    vptrs.push(ndr_u32(b, n));
                }
                for k in idptrs.len {
                    var id: u8[>..] = [];
                    if idptrs[k] != 0 { id = ndr_wstring(b, n); }
                    var ints: u64[>..] = [];
                    var strs: u8[][>..] = [];
                    if vptrs[k] != 0 { ndr_claim_values(b, n, types[k], vcounts[k], ints, strs); }
                    claims.push(Claim { id: copy(id), claim_type: types[k], ints: copy(ints), strings: copy(strs) });
                }
            }
            out.push(ClaimsArray { source_type: sources[i], claims: copy(claims) });
        }
    }
    if rptr != 0 { let x = ndr_bytes(b, n, ndr_u32(b, n)); }
    return out, if n.bad { ERR_NDR } else { OK };
}

// A PAC claims buffer (types 13 and 15): the claims, decompressed and
// decoded. An empty buffer (no claims) gives none.
fn decode_claims(b: const u8[:]) -> ClaimsArray[>..], i64 {
    var none: ClaimsArray[>..] = [];
    if b.len == 0 { return none, OK; }
    var n = ndr_open(b);
    if n.bad { return none, ERR_NDR; }
    let top = ndr_u32(b, n);
    let set_size = ndr_u32(b, n);
    let set_ptr = ndr_u32(b, n);
    let format = ndr_u16(b, n);
    let uncompressed = ndr_u32(b, n);
    let rtype = ndr_u16(b, n);
    let rsize = ndr_u32(b, n);
    let rptr = ndr_u32(b, n);
    if top == 0 || set_ptr == 0 { return none, ERR_NDR; }
    let max = ndr_u32(b, n);
    if max != set_size { return none, ERR_NDR; }
    let set = ndr_bytes(b, n, max);
    if n.bad { return none, ERR_NDR; }
    if format == COMPRESSION_NONE {
        let arrays, err = decode_claims_set(set);
        return arrays, err;
    }
    if format != COMPRESSION_XPRESS_HUFF { return none, ERR_PAC; }
    var plain: u8[>..] = [];
    if !xpress_huff_decompress(set, uncompressed, plain) { return none, ERR_PAC; }
    let arrays, err = decode_claims_set(plain);
    return arrays, err;
}

// The claims of a PAC (client claims, PAC_CLIENT_CLAIMS_INFO, or the
// device's, PAC_DEVICE_CLAIMS_INFO): none when it has no such buffer.
fn pac_claims(raw: const u8[:], p: const Pac&, buffer_type: u32) -> ClaimsArray[>..], i64 {
    let b, found = pac_buffer(raw, p.buffers, buffer_type);
    var none: ClaimsArray[>..] = [];
    if !found { return none, OK; }
    let arrays, err = decode_claims(b);
    return arrays, err;
}
