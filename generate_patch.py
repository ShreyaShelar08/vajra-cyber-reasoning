#!/usr/bin/env python3
"""
generate_patch.py

Takes:
  --trace     path to the crash trace (ASan/UBSan/gdb output, etc.)
  --func      path to ONLY the specific vulnerable function's source
              (not the whole repo — keeps the model focused and the
              context window small)

Sends both to a local Ollama model and asks for a minimal unified diff
patch. Saves the raw model response and the extracted patch separately
so verify_patch.py can consume it.

Usage:
    python3 generate_patch.py \
        --trace fake_crash/crash_trace.txt \
        --func  fake_crash/vulnerable_function.c \
        --out   evidence/patch_001

Requires Ollama running locally (default http://localhost:11434):
    ollama pull qwen2.5-coder:7b
    ollama serve
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

DEFAULT_MODEL = "qwen2.5-coder:7b"
DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"

PROMPT_TEMPLATE = """You are a senior C security engineer. A fuzzer found a crash.

=== CRASH TRACE ===
{trace}

=== VULNERABLE FUNCTION SOURCE ===
{func}

=== TASK ===
1. Identify the root cause of the crash from the trace and the function above.
2. Produce the SMALLEST POSSIBLE fix. Do not refactor, rename, or reformat
   anything you don't have to touch. Do not change the function's signature
   or behavior for valid, non-crashing inputs.
3. Output your answer as a unified diff (git diff format) ONLY, wrapped in a
   ```diff code block. The diff must apply cleanly with `patch -p0` or
   `git apply` against the exact file contents given above.
4. After the diff block, add a short "EXPLANATION:" section (3-5 sentences)
   describing the root cause and why this fix resolves it.

Do not include anything else before the diff block.
"""


def build_prompt(trace_text: str, func_text: str, func_filename: str) -> str:
    # Give the model the filename context so its diff header is usable.
    func_with_header = f"--- filename: {func_filename} ---\n{func_text}"
    return PROMPT_TEMPLATE.format(trace=trace_text.strip(), func=func_with_header.strip())


def call_ollama(prompt: str, model: str, url: str, timeout: int = 300) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise SystemExit(
            f"[generate_patch] Could not reach Ollama at {url}: {e}\n"
            f"Is `ollama serve` running, and did you `ollama pull {model}`?"
        )
    return body.get("response", "")


def extract_diff(model_output: str) -> str:
    """Pull the fenced ```diff ... ``` block out of the model's response."""
    m = re.search(r"```diff\s*\n(.*?)```", model_output, re.DOTALL)
    if m:
        return m.group(1).strip() + "\n"
    # Fallback: some models omit the "diff" tag or fences entirely.
    m = re.search(r"```\s*\n(---.*?)```", model_output, re.DOTALL)
    if m:
        return m.group(1).strip() + "\n"
    if model_output.strip().startswith("---"):
        return model_output.strip() + "\n"
    return ""


def extract_explanation(model_output: str) -> str:
    m = re.search(r"EXPLANATION:\s*(.*)", model_output, re.DOTALL)
    return m.group(1).strip() if m else ""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", required=True, help="Path to crash trace file")
    ap.add_argument("--func", required=True, help="Path to the vulnerable function's source file only")
    ap.add_argument("--out", required=True, help="Output prefix, e.g. evidence/patch_001")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model tag (default: {DEFAULT_MODEL})")
    ap.add_argument("--url", default=DEFAULT_OLLAMA_URL, help="Ollama /api/generate URL")
    args = ap.parse_args()

    trace_path = Path(args.trace)
    func_path = Path(args.func)
    out_prefix = Path(args.out)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    trace_text = trace_path.read_text()
    func_text = func_path.read_text()

    prompt = build_prompt(trace_text, func_text, func_path.name)
    print(f"[generate_patch] Sending {len(prompt)} chars to {args.model} @ {args.url} ...")

    raw_response = call_ollama(prompt, args.model, args.url)

    raw_path = out_prefix.with_suffix(".raw.txt")
    raw_path.write_text(raw_response)

    diff_text = extract_diff(raw_response)
    explanation = extract_explanation(raw_response)

    if not diff_text:
        print("[generate_patch] WARNING: could not extract a diff block from the model's response.")
        print(f"[generate_patch] Raw response saved to {raw_path} for manual inspection.")
        sys.exit(1)

    patch_path = out_prefix.with_suffix(".diff")
    patch_path.write_text(diff_text)

    meta = {
        "model": args.model,
        "trace_file": str(trace_path),
        "function_file": str(func_path),
        "prompt_chars": len(prompt),
        "patch_file": str(patch_path),
        "raw_response_file": str(raw_path),
        "explanation": explanation,
    }
    meta_path = out_prefix.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2))

    print(f"[generate_patch] Patch written to {patch_path}")
    print(f"[generate_patch] Metadata written to {meta_path}")
    if explanation:
        print(f"[generate_patch] Model explanation:\n{explanation}")


if __name__ == "__main__":
    main()
