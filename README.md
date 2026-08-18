# miniz-autopatch — Local LLM Auto-Repair Pipeline

**Person B / Repair Track.** Given a crash trace and the specific vulnerable
function, automatically generate a minimal patch with a local LLM (Ollama),
independently verify the patch actually fixes the crash without breaking
anything else, and produce a shareable evidence package (JSON + HTML).

**Status: pipeline proven end-to-end on a real, reproducible crash.**
This was NOT tested with fake data alone — a genuine heap-buffer-overflow
was compiled, triggered, and caught with AddressSanitizer (see
`fake_crash/crash_trace.txt`), then fixed and re-verified for real.

---

## Why this is more than "call an LLM and hope"

The interesting engineering problem here isn't "ask an LLM for a patch" —
it's **never trusting that patch**. `verify_patch.py` is an independent
gate: it re-derives, from scratch, that (a) the original code really does
crash on the given input, (b) the patched code does not, and (c) nothing
else regresses. A patch that fails any of those stages is marked
`FAILED_VERIFICATION` and is never presented as a fix. That's the
difference between "AI suggested something" and "AI suggested something,
and we proved it."

## Architecture

```
crash trace + vulnerable function ONLY (small context, focused prompt)
              │
              ▼
      generate_patch.py  ──▶  Ollama (local model, e.g. qwen2.5-coder:7b)
              │
              ▼
        candidate .diff
              │
              ▼
      verify_patch.py
        1. stage clean source in scratch dir
        2. confirm ORIGINAL code crashes on the input (proves bug is real)
        3. apply patch (git apply, falls back to patch -p0)
        4. rebuild with -fsanitize=address
        5. replay the SAME crashing input → must NOT crash
        6. run regression tests → must all pass
              │
              ▼
      report_generator.py
        → evidence/<id>_certificate.json   (machine-readable proof)
        → reports/<id>.html                (human-readable fix certificate)
```

## Repo layout

```
miniz-autopatch/
├── fake_crash/                  # synthetic demo bug (clearly labeled)
│   ├── vulnerable_function.c    # simplified stand-in for a miniz literal-copy loop
│   ├── harness.c                # ASan driver that calls the function
│   ├── crash_input.bin          # crafted input that triggers the overflow
│   └── crash_trace.txt          # REAL AddressSanitizer trace, captured live
├── generate_patch.py            # step 2: crash+func → Ollama → patch
├── verify_patch.py              # step 4: apply, rebuild, replay, regress
├── report_generator.py          # step 5: JSON + HTML evidence package
├── run_pipeline.sh              # orchestrates 2 → 4 → 5 for one crash
├── mock_ollama_server.py        # DEMO-ONLY stand-in for `ollama serve`
├── evidence/                    # generated JSON evidence (git-ignore in real use)
└── reports/                     # generated HTML fix certificates
```

## Setup (do this first, for real — not the mock)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b      # any 7-8B *code* model works
ollama serve                       # runs the API on localhost:11434
```

## Running the demo (fake crash, proves the plumbing)

The included `fake_crash/` bug is a **synthetic, clearly-labeled** stand-in
for a miniz-style literal-copy bounds bug — used only to prove the pipeline
before Person A hands off a real fuzzer finding. Its crash trace is 100%
real (compiled + triggered with `-fsanitize=address`, not hand-typed).

```bash
# with a real local Ollama running:
./run_pipeline.sh demo_001 \
    fake_crash/crash_trace.txt \
    vulnerable_function.c \
    harness.c \
    fake_crash \
    fake_crash/crash_input.bin

open reports/demo_001.html
```

If you don't have Ollama installed yet and just want to see the pipeline
mechanics work, run the included mock in one terminal:

```bash
python3 mock_ollama_server.py     # DEMO ONLY — fakes Ollama's API
```

and the pipeline in another. This is exactly how this repo's own demo
run (`demo_001`) was produced and verified — `overall_pass: true`,
before-patch crash confirmed, after-patch crash-free, all regression
tests green.

## Running on the real crash (once Person A hands it off)

No new code needed — same three scripts, real inputs:

```bash
mkdir -p real_crash
# drop in: real_crash/trace.txt, real_crash/vulnerable_func.c,
#          real_crash/harness.c (a small driver that reproduces the crash),
#          real_crash/crash_input.bin

./run_pipeline.sh real_001 \
    real_crash/trace.txt \
    vulnerable_func.c \
    harness.c \
    real_crash \
    real_crash/crash_input.bin

open reports/real_001.html
```

## What makes the verification trustworthy

- **It re-proves the bug, not just the fix.** Before touching the patch,
  `verify_patch.py` rebuilds the *unpatched* code and confirms the given
  input really does crash it. A "fix" for a bug that doesn't reproduce is
  worthless, so this is checked every run.
- **Same input, both sides.** The exact crashing input bytes are replayed
  against both the before and after builds — no substitution, no
  hand-waving.
- **Regression suite, not just crash-freedom.** A patch that "fixes" the
  crash by making the function a no-op would pass a crash-only check.
  The regression tests exercise valid inputs through the same code path
  to catch that.
- **Patch application is real `git apply`/`patch`,** not string-splicing —
  if the model's diff doesn't actually apply cleanly to the real file,
  verification fails loudly instead of silently faking success.

## Evidence format

`evidence/<id>_certificate.json` contains the full audit trail: crash
trace, exact function source sent to the model, the model's diff and
explanation, and the complete stage-by-stage verification result
(including captured build/ASan logs). `reports/<id>.html` renders the
same data as a clean, single-file, dependency-free report — no server
needed, just open it.
