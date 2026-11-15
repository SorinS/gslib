/* libFuzzer's entry points over a target's export fn fuzz_one. */
#include "common.c"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    gs_fuzz_start();
    return 0;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t len) {
    gs_fuzz_run(data, len);
    return 0;
}
