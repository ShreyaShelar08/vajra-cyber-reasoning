#!/usr/bin/env python3
"""
report_generator.py

Packages a full run (crash trace, vulnerable function, generated patch,
verification result) into:
  1. evidence/<id>_certificate.json  - single structured evidence file
  2. reports/<id>.html               - standalone, styleable fix-certificate

Usage:
    python3 report_generator.py \
        --id run_001 \
        --trace fake_crash/crash_trace.txt \
        --func fake_crash/vulnerable_function.c \
        --patch-meta evidence/patch_001.meta.json \
        --patch-diff evidence/patch_001.diff \
        --verify-json evidence/verify_001.json \
        --evidence-dir evidence \
        --report-dir reports
"""

import argparse
import html
import json
import time
from pathlib import Path


def load(path: Path):
    return path.read_text()


def load_json(path: Path):
    return json.loads(path.read_text())


def build_certificate(run_id, trace_text, func_text, patch_meta, patch_diff, verify_result):
    return {
        "run_id": run_id,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "crash_trace": trace_text,
        "vulnerable_function_source": func_text,
        "patch": {
            "model": patch_meta.get("model"),
            "diff": patch_diff,
            "explanation": patch_meta.get("explanation"),
        },
        "verification": verify_result,
        "verdict": "VERIFIED_FIX" if verify_result.get("overall_pass") else "FAILED_VERIFICATION",
    }


def esc(s):
    return html.escape(s or "")


def badge(passed):
    if passed is True:
        return '<span class="badge pass">PASS</span>'
    if passed is False:
        return '<span class="badge fail">FAIL</span>'
    return '<span class="badge unknown">N/A</span>'


def render_html(cert: dict) -> str:
    v = cert["verification"]
    stages = v.get("stages", {})
    verdict = cert["verdict"]
    verdict_class = "verdict-pass" if verdict == "VERIFIED_FIX" else "verdict-fail"

    def stage_block(title, key):
        s = stages.get(key)
        if not s:
            return ""
        log = s.get("log") or s.get("output_excerpt") or ""
        return f"""
        <div class="stage">
          <div class="stage-head">
            <span class="stage-title">{esc(title)}</span>
            {badge(s.get("passed"))}
          </div>
          {'<pre class="log">' + esc(log) + '</pre>' if log else ''}
        </div>"""

    regress = stages.get("regression_tests", {}).get("tests", [])
    regress_rows = "".join(
        f"""<tr>
              <td>{esc(t['test'])}</td>
              <td>{badge(t['passed'])}</td>
              <td>exit={t['exit_code']}</td>
            </tr>""" for t in regress
    )

    before_replay = stages.get("before_patch_crash_replay", {})
    after_replay = stages.get("crash_replay", {})

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Fix Certificate — {esc(cert['run_id'])}</title>
<style>
  :root {{
    --bg: #0b0d12;
    --panel: #12151c;
    --panel-2: #171b24;
    --border: #262b36;
    --text: #e6e9ef;
    --muted: #8b93a3;
    --accent: #5b8cff;
    --green: #35c98f;
    --red: #ff5d6c;
    --amber: #f5b942;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    line-height: 1.55; padding: 40px 20px 80px;
  }}
  .wrap {{ max-width: 900px; margin: 0 auto; }}
  header {{ margin-bottom: 28px; }}
  .eyebrow {{ color: var(--muted); font-size: 13px; letter-spacing: .08em; text-transform: uppercase; }}
  h1 {{ font-size: 28px; margin: 6px 0 4px; }}
  .meta {{ color: var(--muted); font-size: 14px; }}

  .verdict {{
    display: inline-flex; align-items: center; gap: 8px;
    padding: 10px 18px; border-radius: 10px; font-weight: 700;
    font-size: 15px; margin: 18px 0 28px; border: 1px solid var(--border);
  }}
  .verdict-pass {{ background: rgba(53,201,143,.12); color: var(--green); border-color: rgba(53,201,143,.35); }}
  .verdict-fail {{ background: rgba(255,93,108,.12); color: var(--red); border-color: rgba(255,93,108,.35); }}

  .card {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 14px; padding: 22px 24px; margin-bottom: 20px;
  }}
  .card h2 {{ margin-top: 0; font-size: 16px; letter-spacing: .02em; color: var(--text); }}
  .card h2 .sub {{ color: var(--muted); font-weight: 400; font-size: 13px; }}

  pre.log, pre.code {{
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 10px;
    padding: 14px 16px; overflow-x: auto; font-size: 12.5px; color: #c9d1e0;
    max-height: 320px; overflow-y: auto; white-space: pre-wrap; word-break: break-word;
  }}
  pre.diff {{
    background: var(--panel-2); border: 1px solid var(--border); border-radius: 10px;
    padding: 14px 16px; overflow-x: auto; font-size: 13px; max-height: 420px; overflow-y: auto;
  }}
  .diff-add {{ color: var(--green); }}
  .diff-del {{ color: var(--red); }}

  .stage {{ border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; margin-bottom: 12px; background: var(--panel-2); }}
  .stage-head {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
  .stage-title {{ font-weight: 600; font-size: 14px; }}

  .badge {{ font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px; letter-spacing: .04em; }}
  .badge.pass {{ background: rgba(53,201,143,.15); color: var(--green); }}
  .badge.fail {{ background: rgba(255,93,108,.15); color: var(--red); }}
  .badge.unknown {{ background: rgba(139,147,163,.15); color: var(--muted); }}

  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }}

  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  @media (max-width: 720px) {{ .grid2 {{ grid-template-columns: 1fr; }} }}

  .explanation {{ color: #cdd3e0; font-size: 14.5px; }}
  footer {{ color: var(--muted); font-size: 12px; text-align: center; margin-top: 40px; }}
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div class="eyebrow">Automated Repair Pipeline — Fix Certificate</div>
    <h1>Run: {esc(cert['run_id'])}</h1>
    <div class="meta">Generated {esc(cert['generated_at'])} &middot; Model: {esc(cert['patch']['model'] or 'unknown')}</div>
  </header>

  <div class="verdict {verdict_class}">
    {'&#10003;' if verdict == 'VERIFIED_FIX' else '&#10007;'} {esc(verdict.replace('_', ' '))}
  </div>

  <div class="card">
    <h2>1. Crash Trace <span class="sub">— as reproduced with AddressSanitizer</span></h2>
    <pre class="log">{esc(cert['crash_trace'])}</pre>
  </div>

  <div class="card">
    <h2>2. Vulnerable Function <span class="sub">— exact source sent to the model (not the whole repo)</span></h2>
    <pre class="code">{esc(cert['vulnerable_function_source'])}</pre>
  </div>

  <div class="card">
    <h2>3. Model-Suggested Patch</h2>
    <pre class="diff">{esc(cert['patch']['diff'])}</pre>
    {'<p class="explanation"><strong>Model explanation:</strong> ' + esc(cert['patch']['explanation']) + '</p>' if cert['patch']['explanation'] else ''}
  </div>

  <div class="card">
    <h2>4. Verification <span class="sub">— independent proof the patch works</span></h2>

    <div class="grid2">
      <div class="stage">
        <div class="stage-head"><span class="stage-title">Before patch: input crashes original code?</span>
          {badge(before_replay.get('actually_crashed'))}
        </div>
      </div>
      <div class="stage">
        <div class="stage-head"><span class="stage-title">After patch: same input no longer crashes?</span>
          {badge(after_replay.get('passed'))}
        </div>
      </div>
    </div>

    {stage_block("Apply patch", "apply_patch")}
    {stage_block("Rebuild (ASan)", "rebuild")}
    {stage_block("Replay original crashing input", "crash_replay")}

    <div class="stage">
      <div class="stage-head"><span class="stage-title">Regression tests (existing behavior unaffected)</span>
        {badge(stages.get('regression_tests', {}).get('passed'))}
      </div>
      <table>
        <tr><th>Test</th><th>Result</th><th>Detail</th></tr>
        {regress_rows}
      </table>
    </div>

    <p class="meta">Total verification time: {v.get('duration_seconds', '—')}s</p>
  </div>

  <footer>
    Generated automatically by the local repair pipeline (Ollama + verify_patch.py).<br/>
    Fake/demo runs are clearly labeled as synthetic in the accompanying README.
  </footer>

</div>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--id", required=True)
    ap.add_argument("--trace", required=True, type=Path)
    ap.add_argument("--func", required=True, type=Path)
    ap.add_argument("--patch-meta", required=True, type=Path)
    ap.add_argument("--patch-diff", required=True, type=Path)
    ap.add_argument("--verify-json", required=True, type=Path)
    ap.add_argument("--evidence-dir", required=True, type=Path)
    ap.add_argument("--report-dir", required=True, type=Path)
    args = ap.parse_args()

    trace_text = load(args.trace)
    func_text = load(args.func)
    patch_meta = load_json(args.patch_meta)
    patch_diff = load(args.patch_diff)
    verify_result = load_json(args.verify_json)

    cert = build_certificate(args.id, trace_text, func_text, patch_meta, patch_diff, verify_result)

    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    args.report_dir.mkdir(parents=True, exist_ok=True)

    cert_path = args.evidence_dir / f"{args.id}_certificate.json"
    cert_path.write_text(json.dumps(cert, indent=2))

    html_path = args.report_dir / f"{args.id}.html"
    html_path.write_text(render_html(cert))

    print(f"[report_generator] JSON evidence: {cert_path}")
    print(f"[report_generator] HTML report:   {html_path}")
    print(f"[report_generator] Verdict: {cert['verdict']}")


if __name__ == "__main__":
    main()
