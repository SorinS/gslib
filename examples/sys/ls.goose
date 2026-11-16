// ls: a directory's entries as ls -l shows them, by sys's read_dir and
// lstat: kind and mode, links, size, when last written, the name, and
// where a link points.
//
//   goose run ls.goose -- [DIR]

import std;
import os;
import gslib from "../..";
import gslib.sys;

fn mode_text(st: const sys::Stat&) -> u8[>..] {
    var s: u8[>..] = [];
    s.push(if st.kind == sys::KIND_DIR { 'd' } else if st.kind == sys::KIND_SYMLINK { 'l' }
           else if st.kind == sys::KIND_OTHER { '?' } else { '-' });
    let rwx = "rwx";
    for i in 9 {
        let bit = 1 << (8 - i);
        s.push(if (st.mode & bit) != 0 { rwx[i % 3] } else { '-' });
    }
    return s;
}

fn main() {
    let argv = args();
    let dir = if argv.len > 1 { argv[1] } else { "." };
    let win = sys::platform() == sys::PLATFORM_WINDOWS;
    var e: i64 = 0;
    let entries = sys::read_dir(dir, e);
    if e != 0 {
        print("ls: ", dir, ": ", sys::error_text(e));
        exit(1);
    }
    for d in entries {
        let path = str(dir, if win { "\\" } else { "/" }, d.name);
        var st = sys::Stat { .. };
        let se = sys::lstat(path, st);
        if se != 0 { print("?????????? ", d.name, " (", sys::error_text(se), ")"); continue; }
        let days = st.mtime_ns / 1000000000 / 86400;
        var line: u8[>..] = [];
        line.append(mode_text(st));
        line.append(str(" ", st.nlink, " ", st.size, " day ", days, " ", d.name));
        if st.kind == sys::KIND_SYMLINK { line.append(str(" -> ", sys::readlink(path))); }
        print(line);
    }
}
