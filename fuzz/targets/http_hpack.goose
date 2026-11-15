// Fuzz target: http_hpack. The HPACK decoder (RFC 7541) over several
// header blocks of one input, sharing one dynamic table. Input: byte 0 sets
// the decoder's table limit and the header list limit; then blocks, each
// a 2-byte header (bits 0-13 the length, bit 14: change the encoder's
// peer limit to 16 x the next byte first). Each decoded list is encoded
// again (an encoder table of its own) and decoded by a second decoder,
// which must give the same records; each value is Huffman coded and
// decoded back.

import std;
import gslib from "../..";
import gslib.net.http;
import gslib.net.http.hpack;

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let b0 = data[0] as i64;
    let limit:    i64 = if (b0 & 0x80) != 0 { 4096 } else { (b0 & 0x7f) * 33 };
    let max_list: i64 = if (b0 & 0x40) != 0 { 65536 } else { 512 + (b0 & 0x3f) * 64 };
    var dec = http::hpack_table(limit);
    var enc = http::hpack_table(4096);
    var dec2 = http::hpack_table(4096);
    var p = 1;
    var blocks = 0;
    while p < data.len && blocks < 64 {
        blocks++;
        var n: i64 = data.len - p;
        if p + 2 <= data.len {
            let h0 = data[p] as i64;
            let h1 = data[p + 1] as i64;
            p += 2;
            if (h0 & 0x40) != 0 {
                http::hpack_peer_limit(enc, h1 * 16);
            }
            n = ((h0 & 0x3f) << 8) | h1;
            if n > data.len - p { n = data.len - p; }
        } else {
            p = data.len;
            n = 0;
        }
        let blk = data[p..p + n];
        p += n;
        var recs: u8[>..] = [];
        let rc = http::hpack_decode(dec, blk, max_list, recs);
        if rc == http::HPACK_ERROR { break; }   // COMPRESSION_ERROR: the connection is gone
        if rc != http::HPACK_OK { continue; }
        // Encode the list again and decode it: the same records.
        var again: u8[>..] = [];
        http::hpack_begin(enc, again);
        var count = 0;
        http::each_hpack_field(recs) { name, value, sensitive =>
            count++;
            http::hpack_field(enc, again, name, value, sensitive);
            var hv: u8[>..] = [];
            http::huffman_encode(hv, value);
            if hv.len != http::huffman_length(value) { abort("http_hpack: huffman_length differs from huffman_encode"); }
            var back: u8[>..] = [];
            if !http::huffman_decode(hv, back) || back[..] != value { abort("http_hpack: Huffman round trip"); }
        };
        var recs2: u8[>..] = [];
        let rc2 = http::hpack_decode(dec2, again, 1 << 40, recs2);
        if rc2 != http::HPACK_OK || recs2[..] != recs[..] { abort("http_hpack: encode/decode round trip differs"); }
        // Lookups through both tables.
        for i in 1..dec.count + 62 { let _ = http::hpack_lookup(dec, i); }
        let _ = count;
    }
    // Huffman decoding of the raw input (strings are Huffman coded too).
    var h: u8[>..] = [];
    let _ = http::huffman_decode(data, h);
    return 0;
}

fn main() {}
