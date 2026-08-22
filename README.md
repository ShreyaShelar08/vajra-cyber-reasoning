# VAJRA
### Threat-Intel-Directed Cyber Reasoning System for Defence-Facing Parsers

> **Find the bug. Prove it. Fix it. Prove the fix.**  
> Autonomously — without cloud dependency, without trusting the LLM blindly.

---

## What VAJRA does in one line

VAJRA is a lightweight, offline-capable cyber reasoning system that finds memory-safety vulnerabilities in archive/file-parsing code used in Indian defence workflows, generates a minimal patch using a local LLM, and **proves the fix holds** before any human engineer is asked to sign off.

---

## Why this matters for Indian defence

Adversary groups (APT36/SideCopy) have sustained phishing-led intrusion campaigns against Indian defence and DRDO-linked networks — delivering malware via **malicious ZIP archives, LNK shortcuts, and spoofed Army app installers**. The common thread is not a mystery bug. It is a known, exploitable class of weakness in file-parsing code that ships inside everyday defence workflows.

Most affected systems are air-gapped or constrained hardware. Cloud-LLM scanning tools don't work there. And a patch is worthless unless it comes with **proof** it fixes the bug without breaking the software people depend on.

VAJRA was built to close exactly that gap.

---

## Live proof-of-concept: real_001

| Stage | Result |
|-------|--------|
| Static triage | `mz_zip_file_stat_internal` in `miniz_zip.c` flagged — attacker-controlled `filename_len` / `extra_len` fields used in `memcpy` source offset with no bounds check |
| Fuzzing | AFL++ with threat-intel-seeded malformed ZIPs; confirmed attack surface |
| Proof-of-vulnerability | `AddressSanitizer: heap-buffer-overflow` — READ of 100 bytes past a 64-byte heap allocation (exit code 1, reproducible every run) |
| Patch generation | Local LLM proposed bounds check before `memcpy` |
| Verification | Original crash **eliminated**; all regression tests **green** |
| Fix certificate | `evidence/real_001_certificate.json` + `reports/real_001.html` |
| **Overall verdict** | ✅ **VERIFIED_FIX** |

Open `reports/real_001.html` in any browser — no server needed. It is a single-file, self-contained fix certificate with the full evidence trail.

---

## Pipeline

```
Untrusted archive/parser code
            │
            ▼
   [1] Static Triage
       Semgrep + Clang Static Analyzer
       Flags risky, reachable functions before any expensive stage runs
            │
            ▼
   [2] Threat-Intel-Directed Fuzzing
       AFL++ with ASan/UBSan
       Seeds derived from APT36/SideCopy-style malformed file structures
       (path-traversal sequences, malformed archive entries, corrupted headers)
            │
            ▼
   [3] Proof-of-Vulnerability
       Crash converted to reproducible test case
       (input hash, sanitizer type, stack trace, reproduction command)
            │
            ▼
   [4] Offline LLM Patch Generation
       Small quantized model (7-8B) via Ollama — no cloud dependency
       Receives ONLY: crash trace + vulnerable function (not the whole repo)
       Output: minimal unified diff, not a rewrite
            │
            ▼
   [5] Verification Gate (the trust boundary)
       ├── Rebuild with original code → confirm crash still triggers (proves bug is real)
       ├── Apply patch → rebuild
       ├── Replay same crashing input → must NOT crash
       ├── Run full regression suite → must all pass
       └── Reject patch on ANY failure
            │
            ▼
   [6] Fix Certificate
       evidence/<id>_certificate.json  (machine-readable audit trail)
       reports/<id>.html               (human-readable, shareable proof)
            │
            ▼
   Human engineer sign-off (nothing auto-deploys to a live system)
```

---

## Key differentiators

**Threat-intel-directed, not blind**  
Fuzzing seeds and static analysis rules are derived from real APT36/SideCopy TTPs — so compute is spent where adversaries are actually probing, not spread thin over the entire codebase.

**Air-gapped by design**  
The reasoning model runs fully offline via Ollama. No cloud API call is ever required. Compatible with isolated defence infrastructure.

**Reachability-first triage**  
The LLM receives only a narrow, pre-filtered slice of code — never the whole repository. This keeps latency and cost low enough for constrained hardware.

**Proof over promise**  
A patch is only certified after independently surviving:
- Before-patch crash confirmation (proves the bug is real, not a false positive)
- After-patch crash freedom (proves the fix works)
- Regression suite pass (proves nothing else broke)

**Interoperability-safe**  
Regression testing explicitly protects legitimate document/file workflows — a "security fix" that breaks availability is worse than the original bug.

**Sovereignty path**  
Model-agnostic architecture: the local LLM can be swapped for an indigenous or DRDO-hosted model with zero pipeline changes.

---

## Repo structure

```
vajra-cyber-reasoning/
├── detection/                    # Person A — find the bug
│   ├── static_triage/
│   │   ├── notes.md              # reachability-first triage findings
│   │   └── results.txt           # Semgrep output
│   └── fuzz/
│       ├── harness.c             # AFL++ entry point (full miniz parser)
│       ├── fuzz_target           # compiled instrumented binary
│       ├── seeds/                # threat-intel-seeded inputs
│       └── output/               # AFL++ corpus (gitignored)
├── real_crash/                   # extracted vulnerable function + proof
│   ├── vulnerable_func.c         # mz_zip_file_stat_internal (simplified standalone)
│   ├── harness.c                 # ASan driver
│   ├── crash_input.bin           # malicious input (crafted bad length fields)
│   └── trace.txt                 # captured ASan stack trace
├── target/
│   └── miniz/                    # target library (C/C++ ZIP parser)
├── evidence/                     # Person B — fix and prove it
│   ├── real_001.diff             # minimal unified diff (the patch)
│   ├── real_001.meta.json        # patch metadata
│   ├── real_001_certificate.json # full audit trail (machine-readable)
│   ├── real_crash_trace.txt      # ASan output, captured live
│   └── verify_real_001.json      # stage-by-stage verification result
├── reports/
│   └── real_001.html             # fix certificate (open in any browser)
├── generate_patch.py             # Stage 4: crash + func → Ollama → diff
├── verify_patch.py               # Stage 5: apply, rebuild, replay, regress
├── report_generator.py           # Stage 6: JSON + HTML fix certificate
├── run_pipeline.py               # orchestrates stages 4 → 5 → 6
└── mock_ollama_server.py         # demo-only stand-in if Ollama not installed
```

---

## Setup

**Requirements:** Python 3.10+, `gcc`, `clang`, `AFL++`, `Semgrep`

```bash
# Ubuntu/WSL
sudo apt install -y clang build-essential afl++
pip3 install semgrep

# For real LLM patch generation (optional — mock server works without this)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b
ollama serve
```

---

## Reproducing the real_001 finding

```bash
# Confirm the bug (should crash with ASan heap-buffer-overflow)
cd real_crash
gcc -fsanitize=address -g -O0 harness.c vulnerable_func.c -o test_harness
./test_harness crash_input.bin
# Expected: AddressSanitizer: heap-buffer-overflow, exit code 1

# Run verification + report generation with the correct patch
cd ..
python3 verify_patch.py \
    --source-dir real_crash \
    --func-file vulnerable_func.c \
    --harness harness.c \
    --patch evidence/real_001.diff \
    --crash-input real_crash/crash_input.bin \
    --out evidence/verify_real_001.json
# Expected: [verify_patch] Verification PASS

python3 report_generator.py \
    --id real_001 \
    --trace real_crash/trace.txt \
    --func real_crash/vulnerable_func.c \
    --patch-meta evidence/real_001.meta.json \
    --patch-diff evidence/real_001.diff \
    --verify-json evidence/verify_real_001.json \
    --evidence-dir evidence \
    --report-dir reports
# Expected: Verdict: VERIFIED_FIX
# Open: reports/real_001.html
```

---

## Technology stack

| Component | Technology |
|---|---|
| Static analysis | Semgrep, Clang Static Analyzer |
| Fuzzing | AFL++ with AddressSanitizer / UBSan |
| Target | miniz (C/C++ ZIP archive parser) |
| LLM interface | Local quantized model (7–8B) via Ollama, no cloud dependency |
| Orchestration | Python |
| Evidence storage | JSON artefacts |
| Fix certificate | Single-file HTML + JSON (no server required) |
| Regression | gcc + ASan recompile + replay |

---

## What's built vs. roadmap

| | Built & demonstrated | Roadmap |
|---|---|---|
| Language | C/C++ | Java (Jazzer) |
| Fuzzing | AFL++ on archive/ZIP parser | Protocol-aware generators (binary telemetry, auth, C2-in-sandbox) |
| Model routing | Single local model (7–8B) | Adaptive routing — small model for triage, large model for hard reasoning |
| Threat intel | Hand-crafted APT36-style seeds | Live CERT-In / OSINT feed integration |

---

## Human oversight

VAJRA is a decision-support and acceleration layer, not an autonomous deployment system. Every certified fix is presented to a human engineer with full proof evidence before any patch reaches a live system. The loop closes on evidence; the decision closes on a person.


