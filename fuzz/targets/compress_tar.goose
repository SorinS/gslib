// Fuzz target: compress_tar. tar_each over the input (1 MiB an entry,
// with the path check), each header's fields and PAX records read and the
// entry written again by the TarWriter, the new archive read back; then
// the streaming reader fed 512 bytes at a time, skipping every other
// entry, into a small buffer.

import std;
import gslib from "../..";
import gslib.compress;
import gslib.compress.tar;

// A per-entry limit well under tar_each's default 1 GiB: the known
// resize-before-data finding (tar.goose:1208) would otherwise allocate
// the declared size from a 512-byte header.
let LIMIT:       i64 = 1 << 20;
let MAX_ENTRIES: i64 = 1024;

fn stream(data: const u8[:]) {
    var r = compress::tar_reader(true);
    var buf: u8[700] = [0; 700];
    var at = 0;
    var entries = 0;
    var idle = 0;
    var total = 0;
    while idle < 4 && entries < MAX_ENTRIES && total <= 4 * LIMIT {
        let end = min(data.len, at + 512);
        let used, made, st = compress::tar_read(r, data[at..end], buf[..]);
        at += used;
        total += made;
        if st < 0 || st == compress::STREAM_END { break; }
        if st == compress::TAR_HEADER {
            entries++;
            let h = compress::tar_header(r);
            let _ = compress::tar_insecure_path(r);
            let _ = compress::tar_why(r);
            let _ = compress::tar_remaining(r);
            // Every other entry skipped, and any larger than LIMIT: a
            // sparse file's holes are written out as zeros, gigabytes of
            // them for a small archive (as Go's reader does).
            if entries % 2 == 0 || compress::tar_remaining(r) > LIMIT { compress::tar_skip(r); }
            let _ = h.size;
        }
        if used == 0 && made == 0 && st != compress::TAR_HEADER { idle++; } else { idle = 0; }
    }
    let _ = compress::tar_finish(r);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    var w = compress::tar_writer();
    var out: u8[>..] = [];
    var n = 0;
    let _ = compress::tar_each(data, LIMIT, true) { h, content =>
        n++;
        let _, _ = compress::tar_pax_get(h.pax, "path");
        compress::tar_pax_each(h.pax) { k, v => let _ = k.len + v.len; };
        let _ = compress::tar_is_local(h.name);
        let _ = compress::tar_time_is_zero(h.mtime);
        if n <= MAX_ENTRIES && compress::tar_write_header(w, h, out) == 0 {
            let _, _ = compress::tar_write(w, content[..min(content.len, max(h.size, 0))], out);
        }
    };
    if compress::tar_close(w, out) == 0 {
        let _ = compress::tar_each(out[..], LIMIT) { h, content => let _ = content.len; };
    }
    stream(data);
    return 0;
}

fn main() {}
