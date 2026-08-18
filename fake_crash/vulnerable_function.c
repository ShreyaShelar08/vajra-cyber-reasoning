/*
 * vulnerable_function.c
 *
 * SYNTHETIC / DEMO BUG — this is a simplified stand-in for the kind of
 * literal-copy loop found in miniz's low-level decompressor (miniz_tinfl.c).
 * It is used to prove the auto-patch pipeline end-to-end before a real
 * fuzzer-found crash is available (per the "fake/sample crash" test step).
 *
 * The bug: num_bytes (attacker/input-controlled, comes from the compressed
 * stream's length field) is copied into pOut_buf with NO check against
 * out_buf_size. A crafted input with a large literal-run length causes a
 * heap-buffer-overflow write.
 */

#include <stddef.h>
#include <stdint.h>

typedef unsigned char mz_uint8;
typedef unsigned int  mz_uint32;
typedef int mz_bool;
#define MZ_TRUE 1
#define MZ_FALSE 0

/*
 * tinfl_copy_literals - copies `num_bytes` literal bytes from the input
 * stream into the output buffer during decompression.
 *
 * pOut_buf      - destination buffer
 * out_buf_size  - allocated size of pOut_buf
 * pIn_buf       - source buffer (compressed stream data)
 * in_buf_size   - allocated size of pIn_buf
 * num_bytes     - number of literal bytes to copy, READ FROM THE INPUT STREAM
 */
mz_bool tinfl_copy_literals(mz_uint8 *pOut_buf, size_t out_buf_size,
                             const mz_uint8 *pIn_buf, size_t in_buf_size,
                             mz_uint32 num_bytes)
{
    mz_uint32 i;

    /* BUG: no check that num_bytes <= out_buf_size (or <= in_buf_size)
     * before writing. A malicious/corrupt stream can set num_bytes larger
     * than the destination buffer, causing a heap-buffer-overflow write. */
    for (i = 0; i < num_bytes; i++)
    {
        pOut_buf[i] = pIn_buf[i];
    }

    return MZ_TRUE;
}
