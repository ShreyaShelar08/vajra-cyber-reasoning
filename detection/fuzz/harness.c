#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "miniz.h"
#include "miniz_tinfl.h"
#include "miniz_zip.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <zip_file>\n", argv[0]);
        return 0;
    }

    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));

    // Try to open the file as a ZIP archive
    if (!mz_zip_reader_init_file(&zip, argv[1], 0)) {
        // Not a valid/openable zip — nothing to do, this is normal for AFL's random mutations
        return 0;
    }

    int num_files = (int)mz_zip_reader_get_num_files(&zip);

    for (int i = 0; i < num_files; i++) {
        // Target 1: filename reading (miniz_zip.h line 273)
        char filename[512];
        mz_zip_reader_get_filename(&zip, i, filename, sizeof(filename));

        // Target 2: file stat / header parsing (line 282)
        mz_zip_archive_file_stat stat;
        if (!mz_zip_reader_file_stat(&zip, i, &stat)) {
            continue;
        }

        // Target 3: extraction to memory (line 298) — the main attack surface
        size_t out_size = 0;
        void *p = mz_zip_reader_extract_to_heap(&zip, i, &out_size, 0);
        if (p) {
            free(p);
        }
    }

    mz_zip_reader_end(&zip);
    return 0;
}