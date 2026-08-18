#!/usr/bin/env bash
# run_pipeline.sh - runs generate_patch.py -> verify_patch.py -> report_generator.py
# for one crash. Works for both the fake/demo crash and a real handoff from
# Person A, as long as you pass the right files.
#
# Usage:
#   ./run_pipeline.sh <run_id> <trace_file> <func_file> <harness_file> <source_dir> <crash_input>
#
# Example (fake demo crash):
#   ./run_pipeline.sh demo_001 \
#       fake_crash/crash_trace.txt \
#       vulnerable_function.c \
#       harness.c \
#       fake_crash \
#       fake_crash/crash_input.bin
#
# Example (real crash from Person A, once handed off):
#   ./run_pipeline.sh real_001 \
#       real_crash/trace.txt \
#       real_crash/vulnerable_func.c \
#       real_crash/harness.c \
#       real_crash \
#       real_crash/crash_input.bin

set -euo pipefail

RUN_ID="${1:?run_id required}"
TRACE="${2:?trace file required}"
FUNC_FILE="${3:?func filename required (relative to source_dir)}"
HARNESS_FILE="${4:?harness filename required (relative to source_dir)}"
SOURCE_DIR="${5:?source_dir required}"
CRASH_INPUT="${6:?crash_input required}"

OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434/api/generate}"
MODEL="${MODEL:-qwen2.5-coder:7b}"

if command -v python3 >/dev/null 2>&1 && python3 --version >/dev/null 2>&1; then
    PYTHON="python3"
else
    PYTHON="python"
fi

echo "=== [1/3] Generating patch with $MODEL ==="
$PYTHON generate_patch.py \
  --trace "$TRACE" \
  --func "$SOURCE_DIR/$FUNC_FILE" \
  --out "evidence/${RUN_ID}" \
  --model "$MODEL" \
  --url "$OLLAMA_URL"

echo "=== [2/3] Verifying patch (apply, rebuild, replay crash, regression tests) ==="
$PYTHON verify_patch.py \
  --source-dir "$SOURCE_DIR" \
  --func-file "$FUNC_FILE" \
  --harness "$HARNESS_FILE" \
  --patch "evidence/${RUN_ID}.diff" \
  --crash-input "$CRASH_INPUT" \
  --out "evidence/verify_${RUN_ID}.json"

echo "=== [3/3] Generating fix certificate (JSON + HTML) ==="
$PYTHON report_generator.py \
  --id "$RUN_ID" \
  --trace "$TRACE" \
  --func "$SOURCE_DIR/$FUNC_FILE" \
  --patch-meta "evidence/${RUN_ID}.meta.json" \
  --patch-diff "evidence/${RUN_ID}.diff" \
  --verify-json "evidence/verify_${RUN_ID}.json" \
  --evidence-dir evidence \
  --report-dir reports

echo ""
echo "Done. Open reports/${RUN_ID}.html"
