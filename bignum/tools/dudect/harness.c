/* dudect's harness (github.com/oreparaz/dudect, src/dudect.h, used as it
   is) around one of tools/dudect/targets.goose's functions, chosen at
   compile time: -DTARGET=dut_x25519_base -DCHUNK=32. Class 0 is one fixed
   input, class 1 random ones; both are made the same way (random bytes,
   then class 0's overwritten with the fixed ones), as dudect's examples
   do. dut_memcmp is a control that must be caught: a comparison with a
   secret that stops at the first difference, class 0 the secret itself
   (every byte compared), class 1 random (one).

   Runs dudect_main for argv[1] seconds (60 by default), whatever it says
   on the way: a noisy machine crosses dudect's moderate threshold (t 10)
   with constant-time code, given millions of measurements, so the verdict
   is left to scripts/dudect.py, from dudect's last line (max t, max tau).
   x86 only: dudect times with rdtsc. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

#ifndef TARGET
#error "define TARGET"
#endif
#ifndef CHUNK
#error "define CHUNK"
#endif

#define STR2(x) #x
#define STR(x) STR2(x)

typedef struct { uint8_t *data; int64_t len; } sl_u8;
void goose_init(int argc, char **argv);
uint8_t TARGET(sl_u8 data);

static uint8_t fixed_input[CHUNK];

static uint8_t secret[CHUNK];

/* A byte loop that stops at the first difference, kept out of line and
   unvectorized: memcmp itself, expanded by the compiler or vectorized by
   libc, compares a block at a time and does not show the difference. */
__attribute__((noinline)) uint8_t dut_memcmp(sl_u8 d) {
    const volatile uint8_t *a = d.data;
    for (int64_t i = 0; i < d.len; i++) {
        if (a[i] != secret[i]) return 1;
    }
    return 0;
}

uint8_t do_one_computation(uint8_t *data) {
    sl_u8 s = { data, CHUNK };
    return TARGET(s);
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    randombytes(input_data, c->number_measurements * c->chunk_size);
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) memcpy(input_data + i * c->chunk_size, fixed_input, c->chunk_size);
    }
}

int main(int argc, char **argv) {
    double budget = argc > 1 ? atof(argv[1]) : 60.0;
    goose_init(0, NULL);
    randombytes(fixed_input, CHUNK);
    memcpy(secret, fixed_input, CHUNK);
    dudect_config_t config = { .chunk_size = CHUNK, .number_measurements = 500 };
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    time_t start = time(NULL);
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (difftime(time(NULL), start) < budget) {
        state = dudect_main(&ctx);
    }
    dudect_free(&ctx);
    printf("RESULT %s after %.0f s\n", STR(TARGET), difftime(time(NULL), start));
    return 0;
}
