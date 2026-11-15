/* mime's platform constant for multipart's file names (filepath.Base)
   and mime.types: 1 when the program is built for Windows, else 0; and
   multipart forms' temporary files, made new and readable by their owner
   only. A C source of gslib.build, not a header: gslib's JIT library
   resolves every extern of the package's modules. */

#if defined(_WIN32)
#  include <fcntl.h>
#  include <io.h>
#  include <sys/stat.h>
#else
#  define _XOPEN_SOURCE 700
#  define _DEFAULT_SOURCE
#  define _DARWIN_C_SOURCE
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif
#include <errno.h>
#include <stdint.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } mime_slice;

int64_t mime_path_windows(void) {
#if defined(_WIN32)
    return 1;
#else
    return 0;
#endif
}

/* Creates path, which must not exist (O_EXCL; a symbolic link there is not
   followed), mode 0600, and writes data to it. 0; 1 when something is
   there already; -1 for any other error (the file removed). */
int32_t mime_create_private(mime_slice path, mime_slice data) {
    char p[4096];
    if (path.len <= 0 || (size_t)path.len >= sizeof p || data.len < 0) return -1;
    memcpy(p, path.data, (size_t)path.len);
    p[path.len] = 0;
    if (memchr(p, 0, (size_t)path.len) != NULL) return -1;
#if defined(_WIN32)
    int fd = _open(p, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (fd < 0) return errno == EEXIST ? 1 : -1;
#else
    int fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return errno == EEXIST ? 1 : -1;
#endif
    int64_t off = 0;
    while (off < data.len) {
#if defined(_WIN32)
        int n = _write(fd, data.data + off, (unsigned)(data.len - off > (1 << 30) ? (1 << 30) : data.len - off));
#else
        ssize_t n;
        do { n = write(fd, data.data + off, (size_t)(data.len - off)); } while (n < 0 && errno == EINTR);
#endif
        if (n <= 0) break;
        off += n;
    }
#if defined(_WIN32)
    int closed = _close(fd) == 0;
    if (off != data.len || !closed) { _unlink(p); return -1; }
#else
    int closed = close(fd) == 0;
    if (off != data.len || !closed) { unlink(p); return -1; }
#endif
    return 0;
}

/* The permission bits of path (not followed when a symbolic link), -1 if
   there is nothing there: for the tests of the files above. */
int64_t mime_file_mode(mime_slice path) {
    char p[4096];
    if (path.len <= 0 || (size_t)path.len >= sizeof p) return -1;
    memcpy(p, path.data, (size_t)path.len);
    p[path.len] = 0;
    if (memchr(p, 0, (size_t)path.len) != NULL) return -1;
    struct stat st;
#if defined(_WIN32)
    if (stat(p, &st) != 0) return -1;
#else
    if (lstat(p, &st) != 0) return -1;
#endif
    return (int64_t)(st.st_mode & 0777);
}
