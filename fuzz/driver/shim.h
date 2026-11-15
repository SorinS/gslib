/* Force-included (cc -include) into each fuzz target's generated C. The
   runtime ends the process with _Exit or _exit after printing a runtime
   error (a failed bounds, overflow or `as` check, abort(msg), out of
   memory, a data stack overflow); here those calls go to gs_fuzz_end,
   which turns a nonzero status into abort(), so libFuzzer and the replay
   driver see a crash, with the "goose runtime error: ..." line before it.
   The C library's headers come first, so their declarations stay as they
   are and only the runtime's calls are renamed. */
#ifndef GSLIB_FUZZ_SHIM_H
#define GSLIB_FUZZ_SHIM_H
#include <stdlib.h>
#include <unistd.h>
__attribute__((noreturn)) void gs_fuzz_end(int code);
#define _Exit(c) gs_fuzz_end(c)
#define _exit(c) gs_fuzz_end(c)
#endif
