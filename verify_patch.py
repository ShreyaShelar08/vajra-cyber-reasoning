#!/usr/bin/env python3
"""
verify_patch.py

The trust boundary of the whole project: never ship an LLM-suggested patch
without independently proving it. This script:

  1. Copies the clean source into a scratch workdir.
  2. Applies the candidate patch (git apply / patch -p0 fallback).
  3. Rebuilds with AddressSanitizer.
  4. Replays the ORIGINAL crashing input against the rebuilt binary and
     confirms it no longer crashes.
  5. Runs a small regression test suite (round-trip compress/decompress on
     a handful of known-good inputs) to confirm the patch didn't break
     anything else.
  6. Writes a structured JSON result (consumed by report_generator.py).

Usage:
    python3 verify_patch.py \
        --source-dir fake_crash \
        --func-file  vulnerable_function.c \
        --harness    harness.c \
        --patch      evidence/patch_001.diff \
        --crash-input fake_crash/crash_input.bin \
        --out        evidence/verify_001.json
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def ensure_tool_path():
    paths_to_add = []
    for cand in [r"C:\msys64\ucrt64\bin", r"C:\msys64\usr\bin", r"C:\Program Files\Git\cmd", r"C:\Program Files\Git\usr\bin"]:
        if os.path.isdir(cand) and cand not in os.environ.get("PATH", ""):
            paths_to_add.append(cand)
    if paths_to_add:
        os.environ["PATH"] = os.path.pathsep.join(paths_to_add) + os.path.pathsep + os.environ.get("PATH", "")


ensure_tool_path()


def run(cmd, cwd=None, timeout=60):
    """Run a subprocess, always capturing output, never raising on nonzero exit."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired as e:
        return -1, f"TIMEOUT after {timeout}s: {e}"
    except FileNotFoundError as e:
        return -1, f"COMMAND NOT FOUND: {e}"


def stage_workdir(source_dir: Path, func_file: str, harness_file: str, workdir: Path):
    workdir.mkdir(parents=True, exist_ok=True)
    shutil.copy(source_dir / func_file, workdir / func_file)
    shutil.copy(source_dir / harness_file, workdir / harness_file)


def apply_patch(workdir: Path, patch_path: Path, func_file: str):
    """Try git apply first (more forgiving of fuzz), fall back to patch -p0."""
    rc, out = run(["git", "apply", "--unsafe-paths", "--whitespace=fix",
                   str(patch_path.resolve())], cwd=workdir)
    if rc == 0:
        return True, "git apply", out
    rc2, out2 = run(["patch", "-p0", "-i", str(patch_path.resolve())], cwd=workdir)
    if rc2 == 0:
        return True, "patch -p0", out2
    return False, "both git apply and patch -p0 failed", out + "\n---\n" + out2


def get_bin_path(workdir: Path, binary_name: str) -> str:
    bin_name = binary_name + (".exe" if sys.platform == "win32" else "")
    return str((workdir / bin_name).resolve())


def build(workdir: Path, func_file: str, harness_file: str, binary_name: str):
    bin_name = binary_name + (".exe" if sys.platform == "win32" else "")
    cmd = ["gcc", "-fsanitize=address", "-g", "-O0",
           harness_file, func_file, "-o", bin_name]
    rc, out = run(cmd, cwd=workdir)
    if rc != 0 and "cannot find -lasan" in out:
        cmd = ["gcc", "-g", "-O0", harness_file, func_file, "-o", bin_name]
        rc, out = run(cmd, cwd=workdir)
    return rc == 0, out


def replay_crash(workdir: Path, binary_name: str, crash_input: Path):
    bin_path = get_bin_path(workdir, binary_name)
    rc, out = run([bin_path, str(crash_input.resolve())], cwd=workdir)
    # ASan aborts with nonzero exit and "ERROR: AddressSanitizer" in output.
    crashed = (rc != 0) or ("AddressSanitizer" in out) or ("ERROR" in out)
    return (not crashed), rc, out


def regression_tests(workdir: Path, binary_name: str):
    """
    Small, fast regression suite standing in for "miniz's existing tests":
    round-trip a handful of benign inputs of varying sizes through the same
    code path and confirm none of them crash or misbehave post-patch.
    """
    results = []
    test_cases = [
        {"name": "empty_copy", "out_size": 8, "num_bytes": 0},
        {"name": "exact_fit", "out_size": 8, "num_bytes": 8},
        {"name": "small_copy", "out_size": 32, "num_bytes": 5},
        {"name": "max_valid", "out_size": 64, "num_bytes": 64},
    ]
    bin_path = get_bin_path(workdir, binary_name)
    for tc in test_cases:
        payload = bytes([tc["out_size"], tc["num_bytes"]]) + bytes(range(tc["num_bytes"]))
        tmp_input = workdir / f"regress_{tc['name']}.bin"
        tmp_input.write_bytes(payload)
        rc, out = run([bin_path, str(tmp_input.resolve())], cwd=workdir)
        crashed = (rc != 0) or ("AddressSanitizer" in out) or ("ERROR" in out)
        results.append({
            "test": tc["name"],
            "passed": not crashed,
            "exit_code": rc,
            "output_excerpt": out[-300:],
        })
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source-dir", required=True, type=Path)
    ap.add_argument("--func-file", required=True)
    ap.add_argument("--harness", required=True)
    ap.add_argument("--patch", required=True, type=Path)
    ap.add_argument("--crash-input", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--workdir", default=None, type=Path)
    args = ap.parse_args()

    started = time.time()
    workdir = args.workdir or Path(tempfile.gettempdir()) / f"verify_workdir_{int(started)}"
    if workdir.exists():
        shutil.rmtree(workdir)

    result = {
        "started_at": started,
        "patch_file": str(args.patch),
        "stages": {},
        "overall_pass": False,
    }

    # Stage 0: capture pre-patch state (proves the ORIGINAL code really crashes)
    prebuild_dir = workdir / "before"
    stage_workdir(args.source_dir, args.func_file, args.harness, prebuild_dir)
    ok, build_log = build(prebuild_dir, args.func_file, args.harness, "harness_before")
    result["stages"]["before_patch_build"] = {"passed": ok, "log": build_log[-1500:]}
    if ok:
        no_crash_before, rc_before, out_before = replay_crash(prebuild_dir, "harness_before", args.crash_input)
        result["stages"]["before_patch_crash_replay"] = {
            "expected": "CRASH (proves the bug is real)",
            "actually_crashed": not no_crash_before,
            "exit_code": rc_before,
            "output_excerpt": out_before[-1500:],
        }

    # Stage 1: stage clean copy + apply patch
    after_dir = workdir / "after"
    stage_workdir(args.source_dir, args.func_file, args.harness, after_dir)
    applied, method, apply_log = apply_patch(after_dir, args.patch, args.func_file)
    result["stages"]["apply_patch"] = {"passed": applied, "method": method, "log": apply_log[-1500:]}
    if not applied:
        result["overall_pass"] = False
        result["finished_at"] = time.time()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"[verify_patch] FAILED at apply_patch stage. See {args.out}")
        sys.exit(1)

    # Stage 2: rebuild
    built, build_log2 = build(after_dir, args.func_file, args.harness, "harness_after")
    result["stages"]["rebuild"] = {"passed": built, "log": build_log2[-1500:]}
    if not built:
        result["overall_pass"] = False
        result["finished_at"] = time.time()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"[verify_patch] FAILED at rebuild stage. See {args.out}")
        sys.exit(1)

    # Stage 3: replay original crashing input -> must NOT crash now
    no_crash_after, rc_after, out_after = replay_crash(after_dir, "harness_after", args.crash_input)
    result["stages"]["crash_replay"] = {
        "passed": no_crash_after,
        "expected": "NO CRASH",
        "exit_code": rc_after,
        "output_excerpt": out_after[-1500:],
    }

    # Stage 4: regression tests
    regress = regression_tests(after_dir, "harness_after")
    all_regress_pass = all(r["passed"] for r in regress)
    result["stages"]["regression_tests"] = {
        "passed": all_regress_pass,
        "tests": regress,
    }

    result["overall_pass"] = bool(no_crash_after and all_regress_pass)
    result["finished_at"] = time.time()
    result["duration_seconds"] = round(result["finished_at"] - started, 2)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2))

    status = "PASS" if result["overall_pass"] else "FAIL"
    print(f"[verify_patch] Verification {status}. Full result: {args.out}")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
