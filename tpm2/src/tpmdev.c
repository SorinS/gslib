/* tpm2: a TPM character device (Linux's /dev/tpmrm0 or /dev/tpm0), behind
   tpm2/transport.goose's device: transport. The kernel takes one command
   per write and gives its response to the next read. Elsewhere every call
   fails with -ENOSYS; Windows' TBS is not done.

   Results: >= 0 on success, else a negative errno. Strings arrive as
   Goose slices, { data, len }, not NUL-terminated. */

#include <stdint.h>
#include <string.h>

typedef struct { const uint8_t *data; int64_t len; } gs_cslice;
typedef struct { uint8_t *data; int64_t len; } gs_slice;

#if defined(__linux__)
#  include <errno.h>
#  include <fcntl.h>
#  include <unistd.h>

int64_t tpm2dev_open(gs_cslice path) {
    char p[256];
    if (path.len <= 0 || path.len >= (int64_t)sizeof p || memchr(path.data, 0, (size_t)path.len))
        return -EINVAL;
    memcpy(p, path.data, (size_t)path.len);
    p[path.len] = 0;
    int fd;
    do { fd = open(p, O_RDWR | O_CLOEXEC); } while (fd < 0 && errno == EINTR);
    return fd < 0 ? -(int64_t)errno : fd;
}

int64_t tpm2dev_transmit(int64_t fd, gs_cslice cmd, gs_slice out) {
    ssize_t w;
    do { w = write((int)fd, cmd.data, (size_t)cmd.len); } while (w < 0 && errno == EINTR);
    if (w < 0) return -(int64_t)errno;
    if (w != cmd.len) return -EIO;
    ssize_t r;
    do { r = read((int)fd, out.data, (size_t)out.len); } while (r < 0 && errno == EINTR);
    return r < 0 ? -(int64_t)errno : (int64_t)r;
}

void tpm2dev_close(int64_t fd) {
    if (fd >= 0) close((int)fd);
}

#else

int64_t tpm2dev_open(gs_cslice path) { (void)path; return -38; /* ENOSYS */ }
int64_t tpm2dev_transmit(int64_t fd, gs_cslice cmd, gs_slice out) { (void)fd; (void)cmd; (void)out; return -38; }
void tpm2dev_close(int64_t fd) { (void)fd; }

#endif
