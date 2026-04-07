#!/usr/bin/env python3
"""
triage_runner.py — Spawns a highspeed subagent to triage raw scan findings.
Run after agent.py scan completes:
  python3 triage_runner.py [scan_dir]
"""
import json, subprocess, sys
from pathlib import Path

BUGHUNT = Path.home() / 'bughunt'
MODEL   = "minimax-portal/MiniMax-M2.7-highspeed"


def get_latest_scans():
    """Find scans that haven't been triaged yet."""
    summaries = sorted(
        BUGHUNT.glob('scans/*/*/*/*/summary.json'),
        key=lambda p: p.stat().st_mtime, reverse=True
    )
    pending = []
    for s in summaries:
        scan_dir = s.parent
        triage_marker = scan_dir / 'findings' / 'triage_done.json'
        if not triage_marker.exists():
            pending.append(scan_dir)
    return pending


def build_triage_task(scan_dir: Path) -> tuple[str, dict]:
    """Build the triage task prompt for a scan directory."""
    meta = json.loads((scan_dir / 'meta.json').read_text())
    repo = meta['repo']

    raw_dir = scan_dir / 'raw'
    raw_data = {}
    for f in raw_dir.glob('*.json'):
        try:
            raw_data[f.stem] = json.loads(f.read_text())
        except Exception:
            raw_data[f.stem] = {}

    raw_json = json.dumps(raw_data, indent=2, default=str)[:12000]

    task = f"""Triage security scan results for {repo['full_name']}.

Repo: {repo['full_name']}
Language: {repo.get('language', 'unknown')}
Description: {repo.get('description', 'N/A')}
Stars: {repo.get('stars', 0)}

Raw findings (truncated to 12k chars):
{raw_json}

Output instructions:
- De-duplicate findings across tools
- Mark false positives: test files, commented code, placeholders (xxx, changeme, example.com), os.environ references
- For true positives: produce JSON array with id, severity, cvss_score, type, tool, file, line_start, title, description, snippet_masked (mask secrets), false_positive, fp_reason, fix_available, patch_unified_diff, pr_explanation, remediation, cwe, references
- fix_available=true only if you can generate a working unified diff patch
- severity: CRITICAL (9-10), HIGH (7-8), MEDIUM (4-6), LOW (1-3)
- types: SECRET_HARDCODED, SECRET_IN_HISTORY, INJECTION_SQL, INJECTION_CMD, INJECTION_PATH, AUTH_MISSING, INSECURE_RANDOM, DEPRECATED_CRYPTO, SSRF, OPEN_REDIRECT, CVE_DEPENDENCY

Return ONLY valid JSON array. No markdown, no text. Empty array if no true positives with working patches."""

    return task, meta


def spawn_triage_session(task: str, scan_dir: Path, repo_meta: dict):
    """Spawn a subagent to do the triage."""
    importuuid = subprocess.check_output(['python3', '-c',
        'import uuid; print(uuid.uuid4().hex[:8])'],
        text=True).strip()

    # Write task to a temp file
    task_file = BUGHUNT / f'triage_task_{importuuid}.txt'
    task_file.write_text(task)

    print(f"[triage] Spawning subagent for {scan_dir.name}...")
    print(f"[triage] Task file: {task_file}")

    # Use openclaw sessions spawn via CLI
    # The subagent will read the task file and process
    return task_file


def main():
    if len(sys.argv) > 1:
        scan_dirs = [Path(sys.argv[1])]
    else:
        scan_dirs = get_latest_scans()
        print(f"[triage] Found {len(scan_dirs)} pending scans")

    for scan_dir in scan_dirs:
        task, meta = build_triage_task(scan_dir)
        task_file = spawn_triage_session(task, scan_dir, meta)
        print(f"[triage] Queued: {scan_dir.name}")


if __name__ == '__main__':
    main()
