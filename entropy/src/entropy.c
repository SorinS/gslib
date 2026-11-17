/* entropy's C: cryptographically secure random bytes from the operating
   system. getentropy(3) on macOS, Linux and the BSDs, 256 bytes a call,
   else /dev/urandom (Linux before 3.17 has no getentropy system call);
   BCryptGenRandom with the system's preferred generator on Windows,
   linked from bcrypt.lib, so nothing is looked up at run time. A C source
   of gslib.build, not a header: gslib's JIT library resolves every extern
   of the package's modules. */

#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#else
#  define _DEFAULT_SOURCE
#  define _DARWIN_C_SOURCE
#  include <stdio.h>
#  include <unistd.h>
#  if defined(__APPLE__) || defined(__linux__)
#    include <sys/random.h>
#  endif
#endif
#include <stdint.h>

typedef struct { uint8_t *data; int64_t len; } gsent_buf;

/* Fills out: 0, or -1 if the OS gave fewer bytes than asked for (and then
   none of out is to be used). */
int64_t gsent_fill(gsent_buf out) {
    uint8_t *p = out.data;
    int64_t n = out.len;
    if (n <= 0) return 0;
#if defined(_WIN32)
    while (n > 0) {
        ULONG part = n > 0x40000000 ? 0x40000000 : (ULONG)n;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, p, part, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) return -1;
        p += part;
        n -= part;
    }
    return 0;
#else
    int64_t done = 0;
    while (done < n) {
        size_t part = n - done > 256 ? 256 : (size_t)(n - done);
        if (getentropy(p + done, part) != 0) break;
        done += (int64_t)part;
    }
    if (done == n) return 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    while (done < n) {
        size_t got = fread(p + done, 1, (size_t)(n - done), f);
        if (got == 0) break;
        done += (int64_t)got;
    }
    fclose(f);
    return done == n ? 0 : -1;
#endif
}
