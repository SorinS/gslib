// Fuzz target: compress_zip. zip_open on the input in memory (and
// zip_open_tail on its second half, with the path check on), every entry's
// name, extra, comment, mode and data offset, each file extracted (1 MiB
// an entry, 4 MiB in all), and each entry copied raw into a new archive
// (zip_copy) which is closed and opened again.

import std;
import gslib from "../..";
import gslib.compress;
import gslib.compress.flate;
import gslib.compress.deflate;
import gslib.compress.zip;

let LIMIT:       i64 = 1 << 20;
let BUDGET:      i64 = 4 << 20;
let MAX_ENTRIES: i64 = 512;

fn entries(r: const compress::ZipReader&, a: const u8[:]) {
    // A failed reader's comment too: "", not a fault.
    let _ = compress::zip_comment(r, a);
    var out: u8[>..] = [];
    var spent = 0;
    var k = 0;
    for e in r.entries {
        if k >= MAX_ENTRIES { break; }
        k++;
        let name = compress::zip_name(r, a, e);
        let _ = compress::zip_extra(r, a, e);
        let _ = compress::zip_entry_comment(r, a, e);
        let _ = compress::zip_mode(r, a, e);
        let _ = compress::zip_insecure_path(name);
        let _, _ = compress::zip_detect_utf8(name);
        let _, _ = compress::zip_data_offset(r, a, e);
        if spent < BUDGET {
            out.clear();
            let _ = compress::zip_extract(r, a, e, out, LIMIT);
            spent += out.len + 1;
        }
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    let r = compress::zip_open(data);
    entries(r, data);
    if r.err == 0 || r.err == compress::ERR_INSECURE_PATH {
        var w = compress::zip_writer();
        var b: u8[>..] = [];
        var k = 0;
        for e in r.entries {
            if k >= MAX_ENTRIES { break; }
            k++;
            // Known finding (zip.goose:1267-1271): zip_copy slices the
            // archive at the local header's data position unchecked, and
            // panics when the local header's name/extra lengths put it past
            // the archive's end. Such entries are not copied.
            let dp, de = compress::zip_data_offset(r, data, e);
            if de == 0 && (dp < 0 || dp > data.len) { continue; }
            if compress::zip_copy(w, r, data, e, b) != 0 { break; }
        }
        if compress::zip_close(w, b) == 0 {
            let r2 = compress::zip_open(b[..]);
            entries(r2, b[..]);
        }
    }
    let half = data[data.len / 2..];
    let rt = compress::zip_open_tail(half, data.len, true);
    entries(rt, half);
    return 0;
}

fn main() {}
