# fuzz: coverage-guided fuzzing of gslib's parsers

One target per parser of untrusted input, each a small Goose program in
`targets/<name>.goose` whose `export fn fuzz_one(data: const u8[:]) -> i32`
takes one input, parses it, and walks what came back (children, accessors,
re-serialization), ignoring errors. A parser that is wrong shows as a Goose
runtime error (a failed bounds, overflow or `as` range check, an
`abort`/`assert`, an out-of-memory), as a sanitizer report from the C, or as
a time-out.

    python3 fuzz/run.py list                    # the targets, their seeds and regressions
    python3 fuzz/run.py replay [TARGET...]      # corpora and regression inputs, no libFuzzer
    python3 fuzz/run.py fuzz TARGET --seconds 600 [--jobs 4]
    python3 fuzz/run.py triage TARGET [FILE...]
    python3 fuzz/run.py merge TARGET [--dict]   # fold a run's coverage into corpus/TARGET

or `make fuzz-build`, `make fuzz-replay` and `make fuzz TARGET=dns_msg SECONDS=600`.

## How a target is built

`goose -o target.c --no-bce --standalone --header fuzz_target.h` writes the
target's C with every bounds check kept, and the header that declares
`fuzz_one` and `goose_init`. The C is compiled with `GS_DEBUG=1`, so Goose's
overflow, `as` range and tag checks are on (a release build would wrap
where the fuzzer stops), and with `driver/shim.h` forced in. The runtime
ends a failed program with `_Exit`/`_exit`; the shim sends those to
`gs_fuzz_end`, which calls `abort()` for a nonzero status, so the
`goose runtime error: ... (file.goose:line)` line is followed by a crash
that libFuzzer, the sanitizers and a debugger all see. gslib's native C
(sockets, files; nothing a target calls) is linked in so that every target
links. One of two drivers goes with it:

- `driver/replay.c`, built with the system C compiler (Apple clang will
  do) and ASan and UBSan when it has them (`FUZZ_SAN=0` for neither). It
  runs each file named, and each file under each directory named, in a
  child process with a time limit (`-t`, 10 s), and reports `CRASH` or
  `TIMEOUT` for each failing one. `--no-fork` runs them in-process, for a
  debugger. This is what `make fuzz-replay` runs.
- `driver/libfuzzer.c`, `LLVMFuzzerTestOneInput` over `fuzz_one`, built
  with a clang that has libFuzzer: `FUZZ_CC`, else Homebrew's LLVM
  (`/opt/homebrew/opt/llvm`), else a `clang` on `PATH` that links
  `-fsanitize=fuzzer`. Apple's clang has no libFuzzer. On Linux, clang 10
  and later work.

Builds go to `fuzz/build/` (not committed), and are redone only when the
generated C, the drivers or the flags change.

ASan sees the runtime and the native C, not inside Goose's own data
stacks: Goose's bounds checks guard those, which is why `--no-bce` matters.

## Running and triage

`run.py fuzz` keeps its working corpus and raw crashes under `--work`
(default `$FUZZ_WORK/<target>`, else `fuzz/build/work/<target>`), seeded
from `corpus/<target>` with `dict/<target>.dict`. Afterwards each crash is
replayed and keyed by its abort site: the Goose runtime error's
`file:line` and message (numbers dropped), else the sanitizer's kind and
first frames. One crash per key is minimized (`-minimize_crash`) and
written to `crashes/<target>/<key>.bin` with its report in `.txt`.
`crashes/` is not committed. A crash worth keeping, once it is understood
and fast to replay, is copied to `regressions/<target>/`; hangs and
out-of-memory inputs are not, since replay would be slow or flaky.

`--jobs N` runs libFuzzer's `-fork=N`, and `--keep-going` does the same
with one job: either carries on past crashes, time-outs and out-of-memory,
so a long run collects many distinct ones, and triage afterwards sorts
them. Without them the run stops at the first crash.

## Layout

- `targets/` one Goose program per target.
- `corpus/<target>/` seeds: small inputs from the libraries' test vectors
  and RFC examples, and inputs `run.py merge` kept for their coverage
  (each at most 8 KiB, a few hundred at most per target).
- `dict/<target>.dict` libFuzzer dictionaries: DER tags, HTTP, XML, LDAP
  filter tokens and the like.
- `regressions/<target>/` minimized inputs that once crashed a parser,
  replayed by `make fuzz-replay`.
- `driver/` the shim and the two drivers.

## Writing a target

    import std;
    import gslib from "../..";
    import gslib.encoding.asn1;

    export fn fuzz_one(data: const u8[:]) -> i32 {
        let t, ok = asn1::parse(data);
        if ok { /* walk it */ }
        return 0;
    }

    fn main() {}

`main` runs once, inside `goose_init`, before any input: fixed keys and
configurations are made there or as top-level `let`s. `fuzz_one` must be
deterministic: no clock, randomness, files or network. Several cheap
parsers may share a target, chosen by the first byte; a slow one gets its
own target so as not to slow the others. Walk trees with a work list
rather than recursion (a `recursive fn` may not keep a non-fixed-size
local across its recursive call), and bound the walk. Then add seeds under
`corpus/<target>/`.
