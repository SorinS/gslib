# service

A Goose program as a system service, after Go's
[kardianos/service](https://github.com/kardianos/service), with one API on
three platforms:

| Platform | What it becomes | Installing it takes |
|---|---|---|
| Windows | a service of the service control manager | an administrator |
| Linux (systemd) | a unit: a user's (`systemctl --user`, `user_level`) or the system's | nothing, or root |
| macOS | a launchd agent (`user_level`) or daemon | nothing, or root |

```goose
import gslib from "SorinS/gslib@v0.9.4";
import gslib.service;

fn main() {
    var c = service::config("goose-echo", "Goose echo", "Echoes, as a service");
    let rc = service::command(c, args());      // install, start, stop, ... or -1
    if rc >= 0 { exit(rc as! i32); }
    let mode = service::begin(c.name);         // first: Windows gives a service 30 s
    while true {
        let ev = service::wait(1000);
        if service::is_stop(ev) { break; }
        // ... work ...
    }
    service::end(0);
}
```

## Running as one

| | |
|---|---|
| `begin(name, pausable = false) -> i64` | Connects to the service manager: `MODE_SERVICE` or `MODE_INTERACTIVE`, or < 0 (`-ERR_STATE` the second time). Call it first: Windows gives up on a service that has not called it within 30 s (error 1053). On Windows `name` is the installed service's. `pausable` offers pause and continue there. |
| `wait(timeout_ms) -> i64` | The next request: `EV_STOP`, `EV_SHUTDOWN`, `EV_RELOAD`, `EV_PAUSE`, `EV_CONTINUE`; `EV_NONE` when `timeout_ms` passed (< 0: wait for ever). Requests queue, so none is lost between calls. Call it from one thread. |
| `is_stop(ev) -> bool` | `EV_STOP` or `EV_SHUTDOWN`. |
| `still_stopping(wait_hint_ms)` | Windows: the stop takes longer than the 30 s the control handler asked for. |
| `end(exit_code)` | Reports the service stopped (non-zero: failed, which the restart policy acts on) and puts the signal handlers back. Exit after it. |
| `log(name, level, msg)` | `LOG_INFO`, `LOG_WARNING`, `LOG_ERROR`: the Application event log as a Windows service, else stderr (`<6>`, `<4>`, `<3>` before each line under systemd's journal). |

What arrives as what:

| | Windows service | Windows console | systemd, launchd, a shell |
|---|---|---|---|
| `EV_STOP` | stop control | Ctrl+C, Ctrl+Break, the console closing | SIGTERM, SIGINT |
| `EV_SHUTDOWN` | shutdown control | log-off is ignored; shutdown | (a SIGTERM: `EV_STOP`) |
| `EV_RELOAD` | parameters changed | | SIGHUP |
| `EV_PAUSE`, `EV_CONTINUE` | pause and continue, when pausable | | |

## Managing one

`config(name, display = "", description = "") -> Config`, then the fields:

| Field | |
|---|---|
| `name` | Letters, digits, `.`, `-` and `_`, up to 80; launchd's Label (reverse DNS is usual there) |
| `display`, `description` | Windows' display name; the description everywhere |
| `exe` | The program; empty: this one (`exe_path()`) |
| `args` | Its arguments as the service, up to 16 |
| `dir` | Its working directory |
| `log_file` | launchd: where stdout and stderr go (launchd keeps neither otherwise) |
| `user_level` | A user's systemd unit or launchd agent; Windows ignores it |
| `start` | `START_AUTO` (default), `START_MANUAL`, `START_DELAYED` (Windows; elsewhere automatic), `START_DISABLED` (Windows; elsewhere manual) |
| `restart_ms` | Restarted that long after it fails, a non-zero exit too (default 5000; 0: never) |
| `stop_timeout_ms` | How long it has to stop before systemd or launchd kill it (default 30000) |

| | |
|---|---|
| `install(c) -> i64` | Windows: registered with its description, start type, restart on failure and an event log source. systemd: the unit written, `daemon-reload`, enabled when automatic. launchd: the property list written. Not started. |
| `uninstall(c) -> i64` | Windows: marked for deletion (gone once stopped) and its event log source removed. systemd: disabled, removed, reloaded. launchd: unloaded, removed. |
| `start(c, timeout_ms = 30000)`, `stop(c, ...)`, `restart(c, ...)` | Waiting on Windows until it is running or stopped. launchd's stop unloads the job, so it is not restarted. |
| `status(c) -> i64` | `STATUS_NOT_INSTALLED`, `STATUS_STOPPED`, `STATUS_RUNNING`, `STATUS_STARTING`, `STATUS_STOPPING`, `STATUS_PAUSED`, `STATUS_UNKNOWN`; `status_text` says it in words. |
| `command(c, args) -> i64` | When `args[1]` is install, uninstall, start, stop, restart or status, does it and prints what happened: 0 or 1; else -1, and the program runs. `install` takes `args[2..]` as the service's arguments unless `c.args` has some. |
| `systemd_unit(c, exe)`, `launchd_plist(c, exe)`, `windows_command_line(exe, args)` | The texts the service managers read, for a look before installing. |

Errors are `OK` or `ERR_ARG`, `ERR_UNSUPPORTED` (Linux without systemd),
`ERR_EXISTS`, `ERR_NOT_INSTALLED`, `ERR_ACCESS`, `ERR_TIMEOUT`,
`ERR_STATE`, `ERR_COMMAND` (systemctl or launchctl failed: `last_output()`)
and `ERR_SYSTEM` (`last_system_error()`, a Win32 code); `error_text` says
each.

## How it works

The service control manager calls a service's ServiceMain and control
handler on threads of its own, and Goose has neither function pointers
nor a way to be entered from such threads. So the C half,
`src/service.c`, does all of that itself: `begin` starts the dispatcher
(`StartServiceCtrlDispatcherW`) on a thread and waits until it knows
which it is: the dispatcher's ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
means a console, ServiceMain being called means a service, which it
reports running. The control handler reports a stop pending and queues
an event; ServiceMain waits until `end`, then reports the service
stopped. On POSIX, SIGTERM, SIGINT and SIGHUP write their event to a
self-pipe, which `wait` polls. Running systemctl and launchctl is
there too (posix_spawn), as os cannot start a process.

The program needs `goose build` (or `goose run`) with a C compiler. On
Windows it links advapi32. A program that `goose build --cc gcc` (MinGW)
made imports libwinpthread-1.dll, which the service control manager's
LocalSystem account does not find on its PATH, so the service does not
start (error 1053): copy the DLL beside the program, or use a goose that
links MinGW's runtime statically (a fix proposed for goose).

## Example and tests

`examples/service/heartbeat.goose` writes a line a second to a file
until it is stopped:

```bash
goose build -o heartbeat examples/service/heartbeat.goose
./heartbeat --user install /tmp/beats.txt     # --user: a user's unit or agent
./heartbeat --user start
./heartbeat --user status
./heartbeat --user stop
./heartbeat --user uninstall
./heartbeat /tmp/beats.txt                    # from the console; Ctrl+C stops it
```

```bash
python3 service/scripts/run_tests.py [--native]     # the texts, the event queue, the signals
python3 service/scripts/service_check.py            # live (make live-service)
```

The live check builds heartbeat and goes through install, start, a kill
(the service manager restarts it), stop, restart and uninstall with its
verbs, checking the file and the status after each. It passed on
Windows Server 2022 (built by MSVC, clang-cl, clang, and gcc with
libwinpthread beside it or linked statically), Linux with systemd 245 (a user's unit) and
macOS (an agent). On Windows run it as an administrator, with `--dir` a
directory LocalSystem can read; `--system` installs the system's unit or
daemon (root).
