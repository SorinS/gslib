/* mime's platform constant for multipart's file names (filepath.Base):
   Windows rules. Included into the program's C by mime.build's c_headers. */
#ifndef MIME_PATH_H
#define MIME_PATH_H
static inline int64_t mime_path_windows(void) { return 1; }
#endif
