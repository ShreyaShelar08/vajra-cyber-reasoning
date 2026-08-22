/*
 * Extracted and simplified from miniz_zip.c, function mz_zip_file_stat_internal()
 * (lines ~1305-1319 in the original), specifically the filename/comment copy logic.
 *
 * Original bug pattern: the comment's source offset is computed using
 * FILENAME_LEN and EXTRA_LEN, both read directly from the untrusted ZIP
 * central directory header, with no bounds check against the actual
 * buffer size before being used in a memcpy.
 */
#include <string.h>
#include <stdint.h>

#define CENTRAL_DIR_HEADER_SIZE 46
#define MAX_COMMENT_SIZE 256

typedef unsigned short mz_uint16;
typedef unsigned int   mz_uint32;

static mz_uint16 read_le16(const unsigned char *p) {
    return (mz_uint16)(p[0] | (p[1] << 8));
}

/*
 * p               = pointer to a central directory header buffer
 * p_buf_len       = actual allocated length of p (for bounds-checking demo)
 * out_comment     = destination buffer (size MAX_COMMENT_SIZE)
 */
void copy_zip_comment(const unsigned char *p, size_t p_buf_len, char *out_comment) {
    mz_uint16 filename_len = read_le16(p + 28); /* offset of filename length field */
    mz_uint16 extra_len    = read_le16(p + 30); /* offset of extra field length */
    mz_uint16 comment_len  = read_le16(p + 32); /* offset of comment length field */

    mz_uint32 n = comment_len;
    if (n > MAX_COMMENT_SIZE - 1) n = MAX_COMMENT_SIZE - 1;

    /* VULNERABLE: source offset uses attacker-controlled filename_len and
       extra_len with no check that CENTRAL_DIR_HEADER_SIZE + filename_len +
       extra_len + n stays within p_buf_len. */
    memcpy(out_comment, p + CENTRAL_DIR_HEADER_SIZE + filename_len + extra_len, n);
    out_comment[n] = '\0';
}
