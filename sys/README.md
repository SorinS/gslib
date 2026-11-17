# sys

The operating system's own calls for Goose, as Go has them in
[golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) and
[os/user](https://pkg.go.dev/os/user), with Windows management as
[iamacarpet/go-win64api](https://github.com/iamacarpet/go-win64api) and
terminals as [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) and
child processes as [os/exec](https://pkg.go.dev/os/exec), on Windows, Linux
and macOS. Six modules:

| Module | Namespace | What | Go |
|---|---|---|---|
| `gslib.sys` | `sys` | the host, processes, users and groups, files by path and by descriptor, memory maps, errors | x/sys/unix and x/sys/windows' common ground, os/user |
| `gslib.sys.registry` | `registry` | the Windows registry | x/sys/windows/registry |
| `gslib.sys.windows` | `windows` | local accounts and groups, sessions, services, shares, installed software, a process's owner and memory | go-win64api |
| `gslib.sys.unix` | `unix` | signals, limits, usage, sessions, sysctl, every user and group | x/sys/unix |
| `gslib.sys.term` | `term` | terminals and consoles: size, raw mode, passwords | x/term |
| `gslib.sys.process` | `process` | child processes on pipes or a pseudo-terminal (a POSIX pty, Windows' ConPTY) | os/exec |

```goose
import gslib from "SorinS/gslib@v0.7.0";
import gslib.sys;

fn main() {
    print(sys::hostname(), ": ", sys::uname().sysname, " ", sys::uname().release);
    var st = sys::Stat { .. };
    let e = sys::stat("/etc/hosts", st);
    if e != 0 { print(sys::error_text(e)); } else { print(st.size, " bytes"); }
    var err: i64 = 0;
    let me = sys::current_user(err);
    print(me.username, " ", me.uid, " ", me.home);
}
```

## Errors

A call that can fail returns 0 or more on success and a negative error
otherwise: `-errno` on POSIX, the negated Win32 error on Windows (a failed
HRESULT as itself), and `sys::ENOTSUP` for a call the platform does not
have, so a program can call anything anywhere and find out. Calls that
return a value take an `e: i64&` for the error instead.

| | |
|---|---|
| `error_text(e) -> u8[>..]` | The system's words for it (`strerror`, `FormatMessage`) |
| `is_not_exist(e)`, `is_exist`, `is_permission`, `is_timeout`, `is_not_supported`, `is_would_block`, `is_not_empty`, `is_dir_error`, `is_not_dir`, `is_invalid` | What kind it is, on any platform, as Go's `os.IsNotExist` (ENOENT, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, NERR_UserNotFound... are all `is_not_exist`) |

## sys: the host, processes, users, files

| | |
|---|---|
| `platform()` | `PLATFORM_WINDOWS`, `PLATFORM_LINUX`, `PLATFORM_MACOS`, `PLATFORM_OTHER` |
| `hostname()`, `uname() -> Uname` | sysname (`Linux`, `Darwin`, `Windows`), nodename, release (`10.0.20348` on Windows, from RtlGetVersion), version, machine (`x86_64`, `arm64`) |
| `cpu_count()`, `page_size()`, `mem_info() -> MemInfo`, `uptime_ms()`, `load_avg(out[3])` | memory total and available, swap (on Windows the page files: the commit limit less physical memory); `load_avg` is POSIX's |
| `os_info() -> OsInfo` | What the system is: name (`Ubuntu`, `macOS`, `Windows Server 2022 Datacenter`, `Windows 11 Pro`), id (`ubuntu`, `macos`, `windows`), id_like, version (`22.04`, `15.1`, `10.0.20348`), version_name (`jammy`; Windows' `21H2`), build (`24B83`, `20348.2527`), edition, pretty. Linux's os-release, macOS's sysctl, Windows' CurrentVersion key (Windows 11 told by its build: its ProductName says 10) |
| `boot_time()` | When the system started, in seconds since 1970 |
| `temp_dir()`, `home_dir()` | |
| `getpid()`, `getppid()`, `exe_path()`, `getcwd()`, `chdir(path)` | |
| `environ()`, `setenv(name, value)`, `unsetenv(name)` | On Windows both the process's and the C runtime's copies, so os's `env` sees it |
| `processes() -> Process[>..]` | pid, ppid, name: Toolhelp32, /proc, libproc |
| `process_exe(pid)`, `process_args(pid, e)` | Another process's program and its words (Windows: `NtQueryInformationProcess`, split by the C runtime's rules; macOS: `KERN_PROCARGS2`) |
| `kill(pid, sig)` | POSIX's; on Windows 0 asks whether it is there and any other ends it (`TerminateProcess`) |
| `is_elevated()` | root, or an elevated token |
| `getuid`, `geteuid`, `getgid`, `getegid`, `getgroups` | POSIX |
| `current_user(e)`, `lookup_user(name, e)`, `lookup_user_id(uid, e) -> User` | Go's `user.User`: username, uid, gid, name, home. On Windows the ids are SIDs, the username `DOMAIN\name`, the home the profile's directory |
| `lookup_group(name, e)`, `lookup_group_id(gid, e) -> Group`, `user_group_ids(name, e)` | Go's `user.Group`, with its members |

Files by path: `stat`, `lstat` (into a `Stat`: kind, mode, size, links,
uid and gid, device and inode, access, change, modification and birth
times in nanoseconds, Windows attributes), `chmod`, `chown`, `lchown`,
`symlink`, `readlink`, `link`, `truncate`, `utimes`, `realpath`, `mkdir`,
`rmdir`, `unlink`, `rename` (replacing), `read_dir -> DirEntry[>..]` (name
and kind, no `.` or `..`). On Windows, as in Go: the mode is 0444 or
0666 (plus 0111 for a directory) from the read-only attribute, which
`chmod` sets from the owner's write bit; `uid` and `gid` are -1; a symbolic
link to a directory is made as one, without the privilege when developer
mode allows it; `readlink` gives a link's or a junction's target.

Files by descriptor (a HANDLE on Windows): `open(path, O_* flags, mode)`,
`close`, `read`, `write`, `pread`, `pwrite`, `seek`, `fsync`,
`ftruncate`, `fstat`, `lock` (`LOCK_SHARED` or `LOCK_EXCLUSIVE` on the
whole file, with `LOCK_NONBLOCK`; `flock` and `LockFileEx`), `pipe`,
`std_fd(0..2)`, `isatty`; `write_all` and `read_all` loop over short
writes and reads. The `O_*` flags are sys's own, the same everywhere,
`O_NOFOLLOW` (a symbolic link, or on Windows any reparse point, is refused)
and `O_NONBLOCK` (POSIX: a FIFO opens at once) among them. `available(fd)`
is what a read would give now (`FIONREAD`, `PeekNamedPipe`; macOS says 0
for a pty, so wait on one with `poll`); `poll(fds, events, ms)` waits on
several (POSIX: `POLL_READ`, `POLL_WRITE`), and `set_nonblock` (POSIX).

Private files. A file (`open` with `O_CREATE`) or directory (`mkdir`) made
with a mode that gives the group and others nothing (0600, 0700) is private
on Windows too: its DACL, protected from inheritance, lets in SYSTEM,
Administrators and the owner only, as Python's `os.mkdir(path, 0o700)`
makes one. `is_private(fd)` asks whether only this user can reach a file
(POSIX: owned by the effective user, no group or other bits; Windows: owned
by the user, SYSTEM or Administrators, no one else in the DACL).

| | |
|---|---|
| `create_file(path, data, mode)` | A new file holding data: `O_EXCL` and `O_NOFOLLOW`, so never one that is there nor through a link; removed again if the write fails |
| `replace_file(path, data, mode)` | data in place of path in one step: a new file beside it, synced and renamed over it |
| `read_private(path, out, max)` | A secret file read whole, as ssh reads its keys: opened without following a link, then checked on the descriptor (a regular file, `is_private`, at most max bytes): `ERR_NOT_REGULAR`, `ERR_NOT_PRIVATE`, `ERR_TOO_LARGE` |
| `create_temp(dir, pattern, path, mode = 0600)`, `mkdir_temp(dir, pattern, path)` | Go's `os.CreateTemp` and `os.MkdirTemp`: the pattern's last `*` replaced by a random string, `""` for the temporary directory, private |

Memory maps: `map_file(fd, offset, length, writable, e) -> Map` (shared:
writes reach the file; `map_sync` writes them now), `map_anonymous`,
`map_read`, `map_write` (copies, checked against the map's length:
`ERR_RANGE`), `unmap`. On Windows the offset is a multiple of 64 KB.

## registry

```goose
import gslib.sys.registry;

let k = registry::open_key(registry::LOCAL_MACHINE,
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry::QUERY_VALUE);
if k >= 0 {
    print(registry::string_value(k, "ProductName"));
    registry::close(k);
}
```

`open_key`, `create_key` (says whether it existed), `close`, `delete_key`
(with `WOW64_32KEY` or `WOW64_64KEY` for a view), `delete_tree`;
`read_subkey_names`, `read_value_names`, `stat -> KeyInfo`; `value_type`;
`get_string` (SZ and EXPAND_SZ, not expanded), `string_value`,
`get_strings` (MULTI_SZ), `get_integer` (DWORD, big-endian DWORD, QWORD),
`get_binary` (any value as stored); `set_string`, `set_expand_string`,
`set_strings`, `set_dword`, `set_qword`, `set_binary`; `delete_value`;
`expand_string` (`%NAME%`; elsewhere `$NAME`). Values are UTF-8 in Goose
and UTF-16 in the registry. A key or value that is not there is
`ERR_NOT_EXIST`, a value of another type `ERR_UNEXPECTED_TYPE`.

## windows: managing the machine

| | |
|---|---|
| `users(e) -> User[>..]` | Local accounts (`NetUserEnum`): name, full name, comment, flags, privilege, last logon, bad passwords, logons, password age, home; `is_disabled`, `is_locked`, `is_admin_priv`, `password_never_expires` |
| `add_user(name, password, full_name, comment)`, `delete_user`, `set_password`, `set_full_name`, `disable_user`, `enable_user`, `unlock_user`, `set_password_never_expires` | |
| `groups(e)`, `add_group`, `delete_group`, `group_members(name, e)`, `add_member`, `remove_member` | Local groups; a member is `name` or `DOMAIN\name` |
| `administrators()`, `is_admin(user)` | The Administrators group (`S-1-5-32-544`) by its localized name, and membership in it |
| `sessions(e) -> Session[>..]` | Remote Desktop Services: id, state, station, user, domain, client, logon time |
| `services(e) -> Service[>..]` | Every Win32 service with its state, process, start type, binary and account (gslib's `service` installs and controls them) |
| `shares(e)`, `add_share(name, path, remark)`, `delete_share` | Disk shares; paths and use counts need an administrator |
| `installed_software(e) -> Software[>..]` | What Programs and Features lists, from the Uninstall keys of both registry views and the user's |
| `process_owner(pid)`, `process_memory(pid, m)` | `DOMAIN\name`, and the working set and commit |

Changing accounts, groups and shares needs an administrator. Not yet here
from go-win64api: firewall rules and Windows Update history, which are COM
interfaces (`INetFwPolicy2`, `IUpdateSession`), and its WMI hardware
inventory.

## unix and term

`unix::notify(sig)` makes a signal a value that `unix::wait_signal(ms)`
returns (a handler writes it to a pipe), so a daemon can wait for SIGHUP or
SIGTERM in its loop; `ignore` and `reset` put a signal's disposition back.
`getrlimit` and `setrlimit` take sys's own `RLIMIT_*` numbers (the same
everywhere; `RLIM_INFINITY` is -1), `rusage` gives CPU times, the largest
resident set in bytes and faults, and there are `umask`, `setsid`,
`getsid`, `getpgid`, `setpgid`. `sysctl(name)` and `sysctl_int(name, v)`
read `sysctlbyname` on macOS and the BSDs and `/proc/sys` on Linux (dots for
slashes: `kernel.ostype`). `users()` and `groups()` list the password and
group databases. The signals whose numbers differ are `sigusr1()`,
`sigusr2()`, `sigchld()`, `sigwinch()`.

`term::is_terminal`, `get_size`, `get_state`, `make_raw` (as `cfmakeraw`;
on Windows the console's mode, with virtual terminal input), `restore`, and
`read_password` (a line without echo) work on POSIX terminals and Windows
consoles alike.

## process: child processes

```goose
import gslib.sys.process;

var c = process::Cmd { .. };                 // a root struct: words and env grow in place
process::args(c, ["git", "log", "-1", "--oneline"]);
var out: u8[>..] = [];
var e: i64 = 0;
let code = process::output(c, out, e);       // stdout piped and read; the exit code
```

A `Cmd` holds the program (`path`, or the first word found by
`look_path`), its words (`arg`, `args`), variables over this process's
(`setenv`; `clear_env` for those alone; SYSTEMROOT kept on Windows, as Go
does), its directory (`dir`), where stdin, stdout and stderr go (`INHERIT`,
`PIPE`, `NULL`, a descriptor, or for stderr `STDOUT`), `new_session` (POSIX
setsid) and `new_group` (a process group of its own, so `kill` reaches all
of it), `default_signals` (POSIX: no ignored SIGPIPE or SIGHUP passed on),
`pty` with `cols` and `rows`, and on Windows `hide_window` and `cmdline`
(the command line as it is; otherwise the words are quoted as the C runtime
splits them, Go's `EscapeArg`).

| | |
|---|---|
| `start(c, e) -> sys::Child` | pid, this end of the pipes (`stdin_fd`, `stdout_fd`, `stderr_fd`; -1 when not piped) and on Windows the process and pseudo-console handles. A program that cannot be run is `e`, never a child exiting 127: on POSIX exec's errno comes back through a pipe the exec closes |
| `wait(ch, st, timeout_ms = -1)` | 1 with a `Status` (exited and its code, or the signal), 0 while it runs; its pid is negated then, so it is never signalled again |
| `kill(ch, sig)` | To the child, or its group when it has one; on Windows any signal but 0 ends it |
| `read(ch, buf)`, `collect(ch, out, st)` | Its output; `collect` reads while waiting, then to the end: the way to run a pty child, since Windows' pseudo-console holds its output until it is closed and closing it waits for room in the pipe |
| `resize(ch, cols, rows)`, `close_pty(ch)` | The terminal's size; closing Windows' pseudo-console |
| `release(ch)` | Closes this process's ends and handles |
| `run(c, e)`, `output(c, out, e)` | To the end: the exit code (and stdout) |
| `look_path(name, e)`, `quote_windows(argv)` | Go's `exec.LookPath` (PATHEXT on Windows; the current directory only when PATH names it) and `EscapeArg` |

On POSIX the child is forked and calls only async-signal-safe functions
before `execve` (the words, the environment and the program's path are made
first), closes every descriptor above 2, and with `pty` becomes a session
leader with the terminal as its controlling one. On Windows only the
child's three handles are inherited (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`),
and a pty is a ConPTY (Windows 10 1809 and later), its functions looked up
in kernel32. `sys::fork`, `exit_now` and `reap` are there for a POSIX server
that forks per connection.

## How it works

The C is in `sys/src`: `posix.c`, `unix.c` and `spawn.c` for POSIX,
`win.c`, `winreg.c`, `winmgmt.c` and `winspawn.c` for Windows. Every function the Goose side
declares must exist on every platform, since the JIT's library for a
package resolves all of its externs, so `sys/src/api.def` lists each one once with
the platforms it is for, and `sys/scripts/gen_ffi.py` makes from it the
Goose declarations (`sys/ffi.goose`), the C prototypes
(`sys/src/gssys_api.h`, which every C file includes, so a definition that
drifts from its declaration does not compile) and a stub returning
`ENOTSUP` for each platform a function is not for
(`sys/src/gssys_stubs.c`), as Go's mksyscall does. Strings and lists come
back through a builder: a list as fields, each a 4-byte length and its
bytes, which `sys::field` and `sys::field_int` read. Text is UTF-8 in Goose
and UTF-16 inside the Windows C. On Windows it links advapi32, netapi32 and
wtsapi32.

## Examples and tests

```bash
goose run examples/sys/sysinfo.goose                 # the host, memory, the user, processes
goose run examples/sys/ls.goose -- /etc              # ls -l by read_dir and lstat
goose run examples/sys/regquery.goose -- "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
goose run examples/sys/winadmin.goose -- services    # users, groups, sessions, services, shares, software
goose run examples/sys/password.goose                # a password without echo, a key in raw mode
goose run examples/sys/signals.goose                 # SIGHUP, SIGUSR1, SIGTERM as values
goose run examples/sys/run.goose                     # a command on a pipe, then on a terminal
python3 sys/scripts/run_tests.py [--native] [--cc NAME]
python3 sys/scripts/gen_ffi.py [--check]             # after changing src/api.def
```

The tests check the same things on every platform and print the same, so
one expected output serves all three: the host and process calls, users
and groups looked up three ways, files and descriptors (locks, pipes,
links, maps) in a directory of their own, the registry under a key of its
own in HKEY_CURRENT_USER, signals sent to the test itself, and, as an
administrator on Windows, an account, a group and a share made, changed and
deleted; child processes on pipes and on a pseudo-terminal (the
environment, the directory, a timeout, kill, exec's failure), and private
and temporary files with what the system is. They pass on macOS, Linux (Ubuntu 20.04) and Windows Server 2022
(MSVC), under the JIT and built natively.
