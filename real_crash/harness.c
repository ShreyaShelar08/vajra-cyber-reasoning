#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_zip_comment(const unsigned char *p, size_t p_buf_len, char *out_comment);

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 0;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;

    unsigned char *buf = malloc(64);   /* heap allocation, ASan tracks this precisely */
    memset(buf, 0, 64);
    size_t read_len = fread(buf, 1, 64, f);
    fclose(f);

    char comment[256];
    copy_zip_comment(buf, read_len, comment);

    printf("Comment (first bytes): %.20s\n", comment);
    free(buf);
    return 0;
}
