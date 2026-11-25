// PCRE2 (with its JIT and without) and POSIX regex.h in the regex benchmark
// (bench.py): the same protocol as bench.goose.
//
//   bench <pcre2-jit|pcre2|posix> patterns.tsv corpus.txt name [pattern]
//
// PCRE2 runs without UTF, so its \w, \d, \s and \b are ASCII, and with
// PCRE2_DOLLAR_ENDONLY, so that `$` without (?m) is the end of the text as
// in the others. POSIX uses the ERE spelling of the patterns file (a
// pattern ERE cannot say is skipped) with REG_EXTENDED, and REG_ICASE or
// REG_NEWLINE where the file says; it iterates with REG_STARTEND, and
// REG_NOTBOL past the start. POSIX matching is leftmost-longest.
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc(n + 1);
    if (fread(b, 1, n, f) != (size_t)n) { perror(path); exit(1); }
    b[n] = 0;
    fclose(f);
    *len = n;
    return b;
}

enum { PJIT, PCRE, POSIX };
static int engine;
static const char *text;
static size_t text_len;

// One compiled pattern, whichever the engine.
typedef struct {
    pcre2_code *code;
    pcre2_match_data *md;
    regex_t posix;
} pat;

static int compile(pat *p, const char *pattern, const char *flags) {
    if (engine == POSIX) {
        int cf = REG_EXTENDED;
        if (strstr(flags, "icase")) cf |= REG_ICASE;
        if (strstr(flags, "newline")) cf |= REG_NEWLINE;
        return regcomp(&p->posix, pattern, cf) == 0;
    }
    int err;
    PCRE2_SIZE off;
    p->code = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, PCRE2_DOLLAR_ENDONLY, &err, &off, NULL);
    if (!p->code) return 0;
    if (engine == PJIT && pcre2_jit_compile(p->code, PCRE2_JIT_COMPLETE) != 0) return 0;
    p->md = pcre2_match_data_create_from_pattern(p->code, NULL);
    return 1;
}

static void release(pat *p) {
    if (engine == POSIX) { regfree(&p->posix); return; }
    pcre2_match_data_free(p->md);
    pcre2_code_free(p->code);
}

// The next match at or after `at`: its span in s[0..1] and group 1's in
// s[2..3] (-1 if it took no part); 0 if there is none, -1 on an error.
static int next(pat *p, size_t at, long *s) {
    if (engine == POSIX) {
        regmatch_t m[2];
        m[0].rm_so = at;
        m[0].rm_eo = text_len;
        int r = regexec(&p->posix, text, 2, m, REG_STARTEND | (at > 0 ? REG_NOTBOL : 0));
        if (r == REG_NOMATCH) return 0;
        if (r != 0) return -1;
        s[0] = m[0].rm_so; s[1] = m[0].rm_eo; s[2] = m[1].rm_so; s[3] = m[1].rm_eo;
        return 1;
    }
    int r = engine == PJIT
        ? pcre2_jit_match(p->code, (PCRE2_SPTR)text, text_len, at, 0, p->md, NULL)
        : pcre2_match(p->code, (PCRE2_SPTR)text, text_len, at, 0, p->md, NULL);
    if (r == PCRE2_ERROR_NOMATCH) return 0;
    if (r < 0) return -1;
    PCRE2_SIZE *ov = pcre2_get_ovector_pointer(p->md);
    s[0] = ov[0]; s[1] = ov[1];
    s[2] = r > 1 && ov[2] != PCRE2_UNSET ? (long)ov[2] : -1;
    s[3] = r > 1 && ov[3] != PCRE2_UNSET ? (long)ov[3] : -1;
    return 1;
}

// The non-overlapping matches from the start (an empty one moves on a
// byte), and the sum of group 1's lengths; -1 on an error.
static long run(pat *p, long *sum) {
    long n = 0, s[4];
    size_t at = 0;
    *sum = 0;
    while (at <= text_len) {
        int r = next(p, at, s);
        if (r < 0) return -1;
        if (r == 0) break;
        n++;
        if (s[2] >= 0) *sum += s[3] - s[2];
        at = s[1] > s[0] ? (size_t)s[1] : (size_t)s[1] + 1;
    }
    return n;
}

// The best of the runs, by bench.goose's rule.
static double best(pat *p, long *n, long *sum) {
    double b = 1e9, total = 0;
    int runs = 0;
    while (runs < 20 && !(runs >= 3 && total >= 0.5) && !(runs >= 1 && total >= 3.0)) {
        // a run repeats the search until it has taken 5 ms
        double t0 = now(), t = 0;
        int reps = 0;
        while (reps == 0 || t < 0.005) {
            *n = run(p, sum);
            reps++;
            t = now() - t0;
            if (*n < 0) return t;
        }
        total += t;
        if (t / reps < b) b = t / reps;
        runs++;
    }
    return b;
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: bench pcre2-jit|pcre2|posix patterns corpus name [pattern]\n"); return 2; }
    engine = !strcmp(argv[1], "posix") ? POSIX : !strcmp(argv[1], "pcre2") ? PCRE : PJIT;
    size_t tl;
    char *table = slurp(argv[2], &tl);
    text = slurp(argv[3], &text_len);
    const char *corpus = argv[4], *only = argc > 5 ? argv[5] : NULL;
    double mb = text_len / 1e6;
    for (char *line = strtok(table, "\n"); line; line = strtok(NULL, "\n")) {
        if (line[0] == '#') continue;
        char *f[5] = {0};
        int k = 0;
        for (char *q = line; k < 5; k++) {
            f[k] = q;
            char *t = strchr(q, '\t');
            if (!t) { k++; break; }
            *t = 0;
            q = t + 1;
        }
        const char *name = f[0], *kind = f[1];
        const char *pattern = engine == POSIX ? f[3] : f[2];
        const char *flags = f[4] ? f[4] : "-";
        if (only && strcmp(only, name)) continue;
        if (!pattern || !strcmp(pattern, "-")) { printf("%s %s skip 1\n", name, corpus); continue; }
        pat p;
        int compiles = 0;
        double c0 = now();
        while (compiles < 1 || (now() - c0 < 0.2 && compiles < 1000)) {
            if (!compile(&p, pattern, flags)) { printf("%s %s error compile\n", name, corpus); goto next_pattern; }
            release(&p);
            compiles++;
        }
        printf("%s %s compile_us %g\n", name, corpus, (now() - c0) / compiles * 1e6);
        compile(&p, pattern, flags);
        long n, sum;
        double t = best(&p, &n, &sum);
        if (n < 0) { printf("%s %s error match\n", name, corpus); release(&p); continue; }
        printf("%s %s count %ld\n", name, corpus, n);
        printf("%s %s count_mbps %g\n", name, corpus, mb / t);
        if (!strcmp(kind, "caps")) {
            // the same loop: group 1 is read either way
            printf("%s %s caps_sum %ld\n", name, corpus, sum);
            printf("%s %s caps_mbps %g\n", name, corpus, mb / t);
        }
        release(&p);
        fflush(stdout);
    next_pattern:;
    }
    return 0;
}
