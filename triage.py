#!/usr/bin/env python3
"""
triage.py — LLM-powered security triage for scan results.
Uses MiniMax-M2.7-highspeed via OpenClaw subagent.
"""
import json, sys, os, subprocess
from pathlib import Path
from datetime import datetime, timezone

BUGHUNT = Path.home() / 'bughunt'
MODEL   = "minimax-portal/MiniMax-M2.7-highspeed"

TRIAGE_PROMPT = """# Security Triage Task

You are a senior application security engineer performing triage on automated
scan results. Raw tool output is provided below.

## Your tasks (in order):
1. **De-duplicate** findings across tools that describe the same vulnerability.
2. **Filter false positives** — common FP indicators:
   - Test/mock/fixture files (paths containing: test, spec, mock, fixture, example, sample, demo)
   - Commented-out code
   - Placeholder values: "your-api-key", "xxx", "changeme", "todo", "example.com"
   - Environment variable references (os.environ, process.env) — these are CORRECT patterns
   - Generic template strings in README or docs
   - Low-confidence findings where the code is clearly not vulnerable
3. **For each TRUE POSITIVE**, produce a structured finding object (schema below).
4. **Generate a unified diff patch** for each fixable finding.
5. **Write PR explanation** (3–5 sentences, non-technical, suitable for maintainer).

## Finding severity guide:
- CRITICAL (9-10): Hardcoded live credentials, RCE, direct path to data breach
- HIGH (7-8):      Hardcoded dev/staging creds, SQL injection, auth bypass, SSRF
- MEDIUM (4-6):    Weak crypto, insecure patterns, high-severity CVE deps
- LOW (1-3):       Info disclosure, best-practice violations, outdated but low-risk deps

## Finding type labels:
SECRET_HARDCODED | SECRET_IN_HISTORY | INJECTION_SQL | INJECTION_CMD | INJECTION_PATH |
AUTH_MISSING | INSECURE_RANDOM | DEPRECATED_CRYPTO | SSRF | OPEN_REDIRECT | CVE_DEPENDENCY

## Output: JSON array of finding objects
[
  {{
    "id": "F001",
    "severity": "CRITICAL",
    "cvss_score": 9.1,
    "type": "SECRET_HARDCODED",
    "tool": "trufflehog",
    "file": "config/settings.py",
    "line_start": 34,
    "line_end": 34,
    "title": "Hardcoded Stripe secret key",
    "description": "Full human-readable explanation of the vulnerability.",
    "snippet_masked": "STRIPE_SECRET_KEY = \"sk_live_4x***\"",
    "false_positive": false,
    "fp_reason": null,
    "fix_available": true,
    "patch_unified_diff": "--- a/config/settings.py\\n+++ b/config/settings.py\\n@@ -31,7 +31,7 @@\\n import os\\n \\n-STRIPE_SECRET_KEY = \\"sk_live_4xG...\\"\\n+STRIPE_SECRET_KEY = os.environ.get(\\"STRIPE_SECRET_KEY\\", \\"\\")",
    "pr_explanation": "Text suitable for PR description...",
    "remediation": "Step-by-step fix instructions.",
    "cwe": "CWE-798",
    "references": ["https://..."]
  }}
]

## Raw scan data:
{{raw_data}}
"""


def load_raw_findings(scan_dir: Path) -> dict:
    """Load all raw tool outputs from a scan directory."""
    raw_dir = scan_dir / 'raw'
    data = {}
    for f in raw_dir.glob('*.json'):
        try:
            data[f.stem] = json.loads(f.read_text())
        except Exception:
            data[f.stem] = {}
    return data


def run_triage(scan_dir: Path, repo_meta: dict) -> list:
    """Send findings to LLM for triage via OpenClaw session."""
    raw = load_raw_findings(scan_dir)
    raw_json = json.dumps(raw, indent=2, default=str)[:15000]  # truncate if huge

    prompt = TRIAGE_PROMPT.format(
        raw_data=raw_json,
    )

    # Build a concise task description
    task = f"""Triage security findings for {repo_meta['full_name']}.

Repo description: {repo_meta.get('description', 'N/A')}
Language: {repo_meta.get('language', 'unknown')}
Stars: {repo_meta.get('stars', 0)}

{prompt}

Return a JSON array of findings. If no true positives, return []."""

    # Spawn subagent with highspeed model
    try:
        from openclaw import OpenClaw
        oc = OpenClaw()
        result = oc.sessions_spawn(
            task=task,
            runtime="subagent",
            model=MODEL,
            mode="run",
            run_timeout=120,
        )
        # Parse JSON from result
        if result and isinstance(result, str):
            # Try to extract JSON array from response
            start = result.find('[')
            end = result.rfind(']') + 1
            if start != -1 and end != 0:
                return json.loads(result[start:end])
    except Exception as e:
        print(f"[triage] Subagent error: {e}", flush=True)

    return []


def main():
    if len(sys.argv) < 2:
        # Find most recent unscanned
        summaries = sorted(
            BUGHUNT.glob('scans/*/*/*/*/summary.json'),
            key=lambda p: p.stat().st_mtime, reverse=True
        )
        for s in summaries:
            scan_dir = s.parent
            # Check if already triaged
            if not (scan_dir / 'findings' / 'triage_done.json').exists():
                meta = json.loads((scan_dir / 'meta.json').read_text())
                print(f"Triaging: {scan_dir.name}")
                findings = run_triage(scan_dir, meta['repo'])
                if findings:
                    (scan_dir / 'findings' / 'triage_done.json').write_text(
                        json.dumps(findings, indent=2)
                    )
                    print(f"  {len(findings)} true positives")
                else:
                    (scan_dir / 'findings' / 'triage_done.json').write_text('[]')
                    print(f"  No true positives (or triage failed)")
                break
    else:
        scan_dir = Path(sys.argv[1])
        meta = json.loads((scan_dir / 'meta.json').read_text())
        findings = run_triage(scan_dir, meta['repo'])
        print(json.dumps(findings, indent=2))


if __name__ == '__main__':
    main()
