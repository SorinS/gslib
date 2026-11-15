/* The plain driver: runs a target's fuzz_one on each file named, and on
   every file under each directory named, with no libFuzzer. Each input
   runs in a child process with a time limit, so one crash or hang is
   reported and the rest still run. Exit status 1 if any input crashed or
   timed out.

     replay [-t seconds] [-q] [--no-fork] path...

   --no-fork runs the inputs in this process (for a debugger: the first
   crash ends the run). Also libFuzzer's style of reproducing works with
   the libFuzzer build itself: ./target crash-file. */
#include "common.c"

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

static int timeout_s = 10;
static int quiet = 0;
static int no_fork = 0;
static long n_ok, n_bad;

static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    unsigned char *buf = malloc(cap);
    for (;;) {
        if (n == cap) {
            cap *= 2;
            buf = realloc(buf, cap);
        }
        size_t got = fread(buf + n, 1, cap - n, f);
        n += got;
        if (got == 0) break;
    }
    fclose(f);
    *len = n;
    return buf;
}

static void run_file(const char *path) {
    size_t len;
    unsigned char *buf = slurp(path, &len);
    if (!buf) {
        fprintf(stderr, "replay: %s: %s\n", path, strerror(errno));
        n_bad++;
        return;
    }
    if (no_fork) {
        if (!quiet) fprintf(stderr, "replay: %s\n", path);
        gs_fuzz_run(buf, len);
        free(buf);
        n_ok++;
        return;
    }
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        alarm((unsigned)timeout_s);
        gs_fuzz_run(buf, len);
        fflush(NULL);
        _Exit(0);
    }
    free(buf);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        n_ok++;
        if (!quiet) fprintf(stderr, "ok      %s\n", path);
        return;
    }
    n_bad++;
    if (WIFSIGNALED(st) && WTERMSIG(st) == SIGALRM)
        fprintf(stderr, "TIMEOUT %s (over %d s)\n", path, timeout_s);
    else if (WIFSIGNALED(st))
        fprintf(stderr, "CRASH   %s (signal %d)\n", path, WTERMSIG(st));
    else
        fprintf(stderr, "CRASH   %s (exit %d)\n", path, WEXITSTATUS(st));
}

static int by_name(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static void run_path(const char *path) {
    struct stat sb;
    if (stat(path, &sb) != 0) {
        fprintf(stderr, "replay: %s: %s\n", path, strerror(errno));
        n_bad++;
        return;
    }
    if (!S_ISDIR(sb.st_mode)) {
        run_file(path);
        return;
    }
    DIR *d = opendir(path);
    if (!d) return;
    char **names = NULL;
    size_t n = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 64;
            names = realloc(names, cap * sizeof *names);
        }
        size_t l = strlen(path) + strlen(e->d_name) + 2;
        names[n] = malloc(l);
        snprintf(names[n], l, "%s/%s", path, e->d_name);
        n++;
    }
    closedir(d);
    if (n) qsort(names, n, sizeof *names, by_name);
    for (size_t i = 0; i < n; i++) {
        run_path(names[i]);
        free(names[i]);
    }
    free(names);
}

int main(int argc, char **argv) {
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "-t") && i + 1 < argc) timeout_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-q")) quiet = 1;
        else if (!strcmp(argv[i], "--no-fork")) no_fork = 1;
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else {
            fprintf(stderr, "usage: %s [-t seconds] [-q] [--no-fork] path...\n", argv[0]);
            return 2;
        }
    }
    gs_fuzz_start();
    for (; i < argc; i++) run_path(argv[i]);
    fprintf(stderr, "replay: %ld ran, %ld crashed or timed out\n", n_ok + n_bad, n_bad);
    return n_bad ? 1 : 0;
}
