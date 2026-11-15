/* What both drivers share: the end of a runtime error, and the start of
   the Goose program. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "fuzz_target.h"

/* shim.h sends the runtime's _Exit and _exit here. */
__attribute__((noreturn)) void gs_fuzz_end(int code) {
    fflush(NULL);
    if (code == 0) _Exit(0);
    abort();
}

static int gs_fuzz_started;

static void gs_fuzz_start(void) {
    if (gs_fuzz_started) return;
    static char *argv[] = {"fuzz", NULL};
    goose_init(1, argv);
    gs_fuzz_started = 1;
}

static int gs_fuzz_run(const unsigned char *data, size_t len) {
    sl_u8 s = {(uint8_t *)data, (int64_t)len};
    return (int)fuzz_one(s);
}
