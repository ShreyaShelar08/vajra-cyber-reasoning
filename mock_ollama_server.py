#!/usr/bin/env python3
"""
mock_ollama_server.py

FOR DEMO/TESTING ONLY.

Mimics Ollama's /api/generate endpoint so generate_patch.py, verify_patch.py
and report_generator.py can be proven end-to-end in an environment without
a real Ollama install/GPU. It returns a genuine, correct unified diff for
our synthetic fake_crash bug (a bounds check on num_bytes).

When Person A hands off a real crash, you do NOT use this file — you run
`ollama serve` for real and point generate_patch.py --url at it instead.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

FAKE_MODEL_RESPONSE = """```diff
--- vulnerable_function.c
+++ vulnerable_function.c
@@ -38,9 +38,15 @@
     mz_uint32 i;
 
-    /* BUG: no check that num_bytes <= out_buf_size (or <= in_buf_size)
-     * before writing. A malicious/corrupt stream can set num_bytes larger
-     * than the destination buffer, causing a heap-buffer-overflow write. */
-    for (i = 0; i < num_bytes; i++)
+    /* FIX: clamp the copy length to the smaller of the destination buffer
+     * and source buffer sizes. A malicious/corrupt stream can no longer
+     * force a write or read past the end of either buffer. */
+    mz_uint32 safe_bytes = num_bytes;
+    if (safe_bytes > out_buf_size)
+        safe_bytes = (mz_uint32)out_buf_size;
+    if (safe_bytes > in_buf_size)
+        safe_bytes = (mz_uint32)in_buf_size;
+
+    for (i = 0; i < safe_bytes; i++)
     {
         pOut_buf[i] = pIn_buf[i];
     }
```

EXPLANATION: The crash is a heap-buffer-overflow write in tinfl_copy_literals(). The loop copies `num_bytes` bytes into `pOut_buf`, but `num_bytes` is attacker/stream-controlled and was never checked against `out_buf_size` (the actual allocated size of the destination). When a corrupt or malicious stream declares a literal run longer than the output buffer, the loop writes past the end of the heap allocation. The fix clamps the effective copy length to the minimum of `out_buf_size` and `in_buf_size` before the loop runs, so the function can never write past the destination or read past the source, while leaving behavior for valid inputs unchanged.
"""


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)  # request body (prompt) ignored by the mock
        body = json.dumps({"response": FAKE_MODEL_RESPONSE, "done": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[mock-ollama] {self.address_string()} - {fmt % args}")


if __name__ == "__main__":
    port = 11434
    print(f"[mock-ollama] Serving fake /api/generate on http://localhost:{port} (DEMO ONLY)")
    HTTPServer(("localhost", port), Handler).serve_forever()
