/* mime's platform constant for multipart's file names (filepath.Base)
   and mime.types: 1 when the program is built for Windows, else 0. A
   C source of gslib.build, not a header: gslib's JIT library resolves
   every extern of the package's modules. */

#include <stdint.h>

int64_t mime_path_windows(void) {
#if defined(_WIN32)
    return 1;
#else
    return 0;
#endif
}
