// sys: files by path and by descriptor, in a directory of their own under
// the temporary directory, removed at the end. Checked the same on every
// platform; where Windows differs (no owners, modes as read-only or not),
// what it gives is checked instead. Modes are in decimal (Goose has no
// octal literals): 493 is 0755, 420 is 0644, 292 is 0444.

import std;
import os;
import gslib from "../..";
import gslib.sys;

var failed = 0;

fn check(ok: bool, what: const u8[:]) {
    if ok { print("ok   ", what); } else { print("FAIL ", what); failed += 1; }
}

fn join(dir: const u8[:], name: const u8[:]) -> u8[>..] {
    let sep = if sys::platform() == sys::PLATFORM_WINDOWS { "\\" } else { "/" };
    return str(dir, sep, name);
}

fn main() {
    let win = sys::platform() == sys::PLATFORM_WINDOWS;
    let dir = join(sys::temp_dir(), str("gssys-files-", sys::getpid()));
    check(sys::mkdir(dir, 493) == 0, "mkdir");
    let again = sys::mkdir(dir, 493);
    check(again < 0 && sys::is_exist(again), "mkdir: it exists");
    let a = join(dir, "a.txt");
    let b = join(dir, "b.txt");

    // --- Descriptors
    let fd = sys::open(a, sys::O_RDWR | sys::O_CREATE | sys::O_EXCL, 420);
    check(fd >= 0, "open: create");
    let fd2 = sys::open(a, sys::O_RDWR | sys::O_CREATE | sys::O_EXCL, 420);
    check(fd2 < 0 && sys::is_exist(fd2), "open: O_EXCL on an existing file");
    check(sys::write_all(fd, "hello, world\n") == 0, "write");
    check(sys::seek(fd, 0, sys::SEEK_CUR) == 13, "seek: where it is");
    check(sys::seek(fd, 0, sys::SEEK_SET) == 0, "seek: to the start");
    var buf: u8[5] = [0; 5];
    check(sys::read(fd, buf[..]) == 5 && buf[..] == "hello", "read");
    check(sys::pwrite(fd, "W", 7) == 1, "pwrite");
    check(sys::pread(fd, buf[..], 7) == 5 && buf[..] == "World", "pread");
    check(sys::seek(fd, 0, sys::SEEK_END) == 13, "seek: to the end; pread and pwrite left it be");
    var st = sys::Stat { .. };
    check(sys::fstat(fd, st) == 0 && st.size == 13 && st.kind == sys::KIND_FILE, "fstat");
    check(sys::ftruncate(fd, 5) == 0 && sys::fstat(fd, st) == 0 && st.size == 5, "ftruncate");
    check(sys::fsync(fd) == 0, "fsync");

    // Locks: an exclusive lock on one descriptor keeps another from it.
    let other = sys::open(a, sys::O_RDONLY, 0);
    check(other >= 0, "open: a second descriptor");
    check(sys::lock(fd, sys::LOCK_EXCLUSIVE) == 0, "lock: exclusive");
    let busy = sys::lock(other, sys::LOCK_SHARED | sys::LOCK_NONBLOCK);
    check(busy < 0 && sys::is_would_block(busy), "lock: the other cannot have it");
    check(sys::lock(fd, sys::LOCK_UNLOCK) == 0, "unlock");
    check(sys::lock(other, sys::LOCK_SHARED | sys::LOCK_NONBLOCK) == 0, "lock: shared once it is free");
    check(sys::lock(other, sys::LOCK_UNLOCK) == 0 && sys::close(other) == 0, "unlock, close");
    check(sys::close(fd) == 0, "close");

    let ap = sys::open(a, sys::O_WRONLY | sys::O_APPEND, 0);
    check(ap >= 0 && sys::write_all(ap, " more") == 0 && sys::close(ap) == 0, "open: append");
    var all: u8[>..] = [];
    check(read_file(a, all) && all == "hello more", "appended at the end");
    let rd = sys::open(a, sys::O_RDONLY, 0);
    var got: u8[>..] = [];
    check(rd >= 0 && sys::read_all(rd, got) == 10 && got == "hello more" && sys::close(rd) == 0, "read_all");
    let tr = sys::open(a, sys::O_WRONLY | sys::O_TRUNC, 0);
    check(tr >= 0 && sys::close(tr) == 0 && sys::stat(a, st) == 0 && st.size == 0, "open: O_TRUNC");
    let missing = sys::open(join(dir, "none"), sys::O_RDONLY, 0);
    check(missing < 0 && sys::is_not_exist(missing), "open: not found");

    // A pipe: what goes in comes out, then the end.
    var p: i64[2] = [0; 2];
    check(sys::pipe(p[..]) == 0, "pipe");
    check(sys::write_all(p[1], "through") == 0 && sys::close(p[1]) == 0, "pipe: write, close");
    var piped: u8[>..] = [];
    check(sys::read_all(p[0], piped) == 7 && piped == "through" && sys::close(p[0]) == 0, "pipe: read to the end");
    check(sys::std_fd(1) != 0 && sys::std_fd(7) < 0, "std_fd");
    check(sys::isatty(p[0]) == 0 || sys::isatty(p[0]) < 0, "isatty: a closed pipe is not a terminal");

    // --- Paths
    check(write_file(a, "0123456789"), "a file to work on");
    check(sys::stat(a, st) == 0 && st.size == 10 && sys::is_regular(st) && st.nlink == 1, "stat");
    check(sys::truncate(a, 4) == 0 && sys::stat(a, st) == 0 && st.size == 4, "truncate");
    let t = 1600000000 * 1000000000;
    check(sys::utimes(a, t, t + 1000000000) == 0 && sys::stat(a, st) == 0 && st.mtime_ns == t + 1000000000, "utimes");
    check(sys::chmod(a, 292) == 0 && sys::stat(a, st) == 0 && (st.mode & 146) == 0, "chmod: read-only");
    check(sys::chmod(a, 420) == 0 && sys::stat(a, st) == 0 && (st.mode & 128) != 0, "chmod: writable");
    // POSIX: the bits as given and an owner; Windows: no owner, a creation time.
    check(if win { st.uid == -1 && st.btime_ns > 0 } else { (st.mode & 511) == 420 && st.uid >= 0 }, "stat: mode bits and owner");

    check(sys::link(a, b) == 0 && sys::stat(a, st) == 0 && st.nlink == 2, "link");
    var sb = sys::Stat { .. };
    check(sys::stat(b, sb) == 0 && sb.ino == st.ino && sb.dev == st.dev, "link: the same file");
    check(sys::unlink(b) == 0 && sys::stat(a, st) == 0 && st.nlink == 1, "unlink");
    check(sys::rename(a, b) == 0 && !file_exists(a) && file_exists(b), "rename");
    check(write_file(a, "x") && sys::rename(b, a) == 0 && sys::stat(a, st) == 0 && st.size == 4, "rename over a file");

    // Symbolic links (Windows: an administrator, or developer mode).
    let s = join(dir, "s");
    let sl = sys::symlink("a.txt", s);
    if sl == 0 {
        check(sys::readlink(s) == "a.txt", "symlink, readlink");
        check(sys::lstat(s, st) == 0 && sys::is_symlink(st) && sys::stat(s, sb) == 0 && sys::is_regular(sb), "lstat, stat of a link");
        check(sys::realpath(s) == sys::realpath(a), "realpath through a link");
        check(sys::unlink(s) == 0, "unlink a link");
    } else {
        print("skip symlink: ", sys::error_text(sl));
    }
    let nl = sys::readlink(a);
    check(nl.len == 0, "readlink of a file: nothing");

    // Directories.
    let sub = join(dir, "sub");
    check(sys::mkdir(sub, 493) == 0 && write_file(join(sub, "f"), "f"), "a directory with a file");
    var e: i64 = 0;
    var files = 0;
    var dirs = 0;
    for d in sys::read_dir(dir, e) {
        if d.name == "a.txt" && d.kind == sys::KIND_FILE { files += 1; }
        if d.name == "sub" && d.kind == sys::KIND_DIR { dirs += 1; }
        if d.name == "." || d.name == ".." { files += 100; }
    }
    check(e == 0 && files == 1 && dirs == 1, "read_dir: names and kinds, no . or ..");
    let ne = sys::rmdir(sub);
    check(ne < 0 && sys::is_not_empty(ne), "rmdir: not empty");
    sys::read_dir(join(dir, "none"), e);
    check(sys::is_not_exist(e), "read_dir: not found");
    check(sys::unlink(join(sub, "f")) == 0 && sys::rmdir(sub) == 0, "rmdir");
    check(sys::unlink(a) == 0 && sys::rmdir(dir) == 0 && !is_dir(dir), "cleaned up");

    if failed > 0 { print(failed, " failed"); exit(1); }
    print("all passed");
}
