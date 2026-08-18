/*
 * harness.c - drives tinfl_copy_literals() with attacker-controlled sizes
 * read from a crash input file, to reproduce a heap-buffer-overflow.
 *
 * Input file format (crash_input.bin):
 *   byte 0     : out_buf_size   (destination buffer size we allocate)
 *   byte 1     : num_bytes      (literal length claimed by the "stream")
 *   bytes 2..N : the literal bytes themselves (source data)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char mz_uint8;
typedef unsigned int  mz_uint32;
typedef int mz_bool;

extern mz_bool tinfl_copy_literals(mz_uint8 *pOut_buf, size_t out_buf_size,
                                    const mz_uint8 *pIn_buf, size_t in_buf_size,
                                    mz_uint32 num_bytes);

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <crash_input.bin>\n", argv[0]);
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }

    unsigned char header[2];
    if (fread(header, 1, 2, f) != 2) {
        fprintf(stderr, "input too short\n");
        fclose(f);
        return 2;
    }

    size_t out_buf_size = header[0];
    mz_uint32 num_bytes = header[1];

    unsigned char *in_buf = malloc(num_bytes > 0 ? num_bytes : 1);
    size_t got = fread(in_buf, 1, num_bytes, f);
    fclose(f);
    if (got < num_bytes) {
        /* pad remaining with zeros so we still exercise the requested size */
        memset(in_buf + got, 0, num_bytes - got);
    }

    /* Exactly out_buf_size bytes allocated for the destination, as a real
     * decompressor would allocate based on the *declared* output size. */
    unsigned char *out_buf = malloc(out_buf_size > 0 ? out_buf_size : 1);

    printf("[harness] out_buf_size=%zu num_bytes=%u\n", out_buf_size, num_bytes);
    fflush(stdout);

    tinfl_copy_literals(out_buf, out_buf_size, in_buf, num_bytes, num_bytes);

    printf("[harness] completed without crash\n");

    free(in_buf);
    free(out_buf);
    return 0;
}
