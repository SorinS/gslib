/* sys: what the C files share. Strings arrive as Goose slices, { data,
   len }, not NUL-terminated, and leave by being appended to a builder
   (gs_rref): a single string as its bytes, a record or a list as fields,
   each a 4-byte little-endian length and its bytes, a number being an
   8-byte little-endian field. */

#ifndef GSSYS_COMMON_H
#define GSSYS_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "gssys_api.h"

/* Error classes (sys::ERR_*), for gssys_error_is. */
#define CLS_NOT_EXIST     1
#define CLS_EXIST         2
#define CLS_PERMISSION    3
#define CLS_TIMEOUT       4
#define CLS_NOT_SUPPORTED 5
#define CLS_WOULD_BLOCK   6
#define CLS_INTERRUPTED   7
#define CLS_NOT_EMPTY     8
#define CLS_IS_DIR        9
#define CLS_NOT_DIR       10
#define CLS_INVALID       11
#define CLS_BAD_FD        12
#define CLS_LOOP          13
#define CLS_NAME_TOO_LONG 14

/* File kinds (Stat.kind, read_dir). */
#define KIND_UNKNOWN 0
#define KIND_FILE    1
#define KIND_DIR     2
#define KIND_SYMLINK 3
#define KIND_OTHER   4

/* open's flags (sys::O_*), the same on every platform. */
#define GO_RDONLY 0x0
#define GO_WRONLY 0x1
#define GO_RDWR   0x2
#define GO_ACCESS 0x3
#define GO_APPEND 0x8
#define GO_CREATE 0x40
#define GO_EXCL   0x80
#define GO_TRUNC  0x200
#define GO_SYNC   0x1000
#define GO_NOFOLLOW 0x2000
#define GO_NONBLOCK 0x4000

/* spawn's flags (process::SPAWN_*) and its stdio entries: a descriptor,
   or one of the STDIO_* below. */
#define SP_SETSID          0x1
#define SP_PGROUP          0x2
#define SP_PTY             0x4
#define SP_DEFAULT_SIGNALS 0x8
#define SP_NO_WINDOW       0x10
#define STDIO_INHERIT (-1)
#define STDIO_PIPE    (-2)
#define STDIO_NULL    (-3)
#define STDIO_STDOUT  (-4)

/* lock's how (sys::LOCK_*). */
#define LK_SHARED    1
#define LK_EXCLUSIVE 2
#define LK_UNLOCK    3
#define LK_NONBLOCK  4

#define GSSYS_ENOMEM_CODE (-1000001)

static inline void put_raw(gs_rref out, const void *p, int64_t n) { gs_bld_append(out, p, n); }

static inline void put_field(gs_rref out, const void *p, int64_t n) {
    uint8_t len[4];
    uint32_t u = (uint32_t)n;
    len[0] = (uint8_t)u; len[1] = (uint8_t)(u >> 8); len[2] = (uint8_t)(u >> 16); len[3] = (uint8_t)(u >> 24);
    gs_bld_append(out, len, 4);
    gs_bld_append(out, p, n);
}

static inline void put_str(gs_rref out, const char *s) { put_field(out, s ? s : "", s ? (int64_t)strlen(s) : 0); }

static inline void put_i64(gs_rref out, int64_t v) {
    uint8_t b[8];
    uint64_t u = (uint64_t)v;
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(u >> (8 * i));
    put_field(out, b, 8);
}

/* A NUL-terminated copy of a slice (malloc'd), or NULL when it holds a NUL
   or memory ran out. */
static inline char *cstr(gssys_slice s) {
    if (s.len < 0 || (s.len > 0 && memchr(s.data, 0, (size_t)s.len))) return NULL;
    char *p = (char *)malloc((size_t)s.len + 1);
    if (!p) return NULL;
    if (s.len) memcpy(p, s.data, (size_t)s.len);
    p[s.len] = 0;
    return p;
}

#endif
