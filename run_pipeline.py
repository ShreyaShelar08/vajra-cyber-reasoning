#!/usr/bin/env python3
"""
run_pipeline.py - Cross-platform pipeline orchestrator for miniz-autopatch.

Runs generate_patch.py -> verify_patch.py -> report_generator.py
If Ollama is not running on http://localhost:11434, automatically launches
mock_ollama_server.py in the background for demo/testing mode.

Usage:
    python run_pipeline.py [run_id] [trace_file] [func_file] [harness_file] [source_dir] [crash_input]

Default (runs demo_001):
    python run_pipeline.py
"""

import os
import sys
import time
import subprocess
import urllib.request
import urllib.error
from pathlib import Path


def is_ollama_running(url="http://localhost:11434"):
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status in (200, 404, 405)
    except Exception:
        return False


def main():
    args = sys.argv[1:]

    run_id = args[0] if len(args) > 0 else "demo_001"
    trace = args[1] if len(args) > 1 else "fake_crash/crash_trace.txt"
    func_file = args[2] if len(args) > 2 else "vulnerable_function.c"
    harness_file = args[3] if len(args) > 3 else "harness.c"
    source_dir = args[4] if len(args) > 4 else "fake_crash"
    crash_input = args[5] if len(args) > 5 else "fake_crash/crash_input.bin"

    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
    model = os.environ.get("MODEL", "qwen2.5-coder:7b")

    mock_proc = None
    if not is_ollama_running("http://localhost:11434"):
        print("[run_pipeline] Local Ollama not detected. Starting mock_ollama_server.py ...")
        mock_proc = subprocess.Popen([sys.executable, "mock_ollama_server.py"])
        time.sleep(1.5)

    try:
        print(f"\n=== [1/3] Generating patch with {model} ===")
        gen_cmd = [
            sys.executable, "generate_patch.py",
            "--trace", trace,
            "--func", f"{source_dir}/{func_file}",
            "--out", f"evidence/{run_id}",
            "--model", model,
            "--url", ollama_url
        ]
        res1 = subprocess.run(gen_cmd)
        if res1.returncode != 0:
            print("[run_pipeline] FAILED at patch generation step.")
            sys.exit(res1.returncode)

        print("\n=== [2/3] Verifying patch (apply, rebuild, replay crash, regression tests) ===")
        ver_cmd = [
            sys.executable, "verify_patch.py",
            "--source-dir", source_dir,
            "--func-file", func_file,
            "--harness", harness_file,
            "--patch", f"evidence/{run_id}.diff",
            "--crash-input", crash_input,
            "--out", f"evidence/verify_{run_id}.json"
        ]
        res2 = subprocess.run(ver_cmd)
        if res2.returncode != 0:
            print(f"[run_pipeline] Verification step returned non-zero code {res2.returncode}")

        print("\n=== [3/3] Generating fix certificate (JSON + HTML) ===")
        rep_cmd = [
            sys.executable, "report_generator.py",
            "--id", run_id,
            "--trace", trace,
            "--func", f"{source_dir}/{func_file}",
            "--patch-meta", f"evidence/{run_id}.meta.json",
            "--patch-diff", f"evidence/{run_id}.diff",
            "--verify-json", f"evidence/verify_{run_id}.json",
            "--evidence-dir", "evidence",
            "--report-dir", "reports"
        ]
        res3 = subprocess.run(rep_cmd)
        if res3.returncode != 0:
            print("[run_pipeline] FAILED at report generation step.")
            sys.exit(res3.returncode)

        print(f"\nPipeline finished successfully! HTML report available at: reports/{run_id}.html")

    finally:
        if mock_proc is not None:
            mock_proc.terminate()
            mock_proc.wait()


if __name__ == "__main__":
    main()
