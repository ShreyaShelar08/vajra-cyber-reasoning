Static Triage Notes — VAJRA 

Target: miniz_zip.c / miniz_zip.h (ZIP archive reading)

Risky functions identified (untrusted-input handling):
- mz_zip_reader_extract_to_mem (miniz_zip.h line 298) — extracts file data into memory, size controlled by ZIP entry
- mz_zip_reader_get_filename (miniz_zip.h line 273) — reads file name string directly from ZIP entry
- mz_zip_reader_file_stat (miniz_zip.h line 282) — reads file metadata from ZIP header

Risky memcpy calls found in miniz_zip.c (copy data/filenames/comments from untrusted ZIP header into fixed buffers):
- Line 1313 — copies filename from central directory header (length n taken from file itself)
- Line 1319 — copies comment field from central directory header
- Line 4865 — copies filename from central directory header (second occurrence)

Why these matter:
These functions read length/size values directly from the ZIP file's own header and use
them to copy data into buffers. If a malicious ZIP is crafted with a manipulated length
field, this is the classic pattern for buffer overflow bugs — exactly the kind of malicious
archive attack associated wi
th APT36/SideCopy-style campaigns.

Next step: fuzz mz_zip_reader_extract_to_mem and the filename-reading path with
malformed ZIP headers (bad length fields, oversized filename fields).
