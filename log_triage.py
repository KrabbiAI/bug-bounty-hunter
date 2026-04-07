#!/usr/bin/env python3
"""
log_triage.py — Persist triage results + PR status to scan directory.
Run after manual triage:
  python3 log_triage.py <scan_dir> [--findings findings.json] [--pr https://github.com/...]
"""
import json, sys
from pathlib import Path
from datetime import datetime, timezone

BUGHUNT = Path.home() / 'bughunt'

def log_triage(scan_dir: Path, findings: list, pr_url: str = None):
    """Update summary.json with triage findings and write pr.json if PR was submitted."""
    summary_file = scan_dir / 'summary.json'
    if not summary_file.exists():
        print(f"[log] No summary.json in {scan_dir}")
        return

    summary = json.loads(summary_file.read_text())

    # Classify findings
    tp = [f for f in findings if not f.get('false_positive')]
    fp = [f for f in findings if f.get('false_positive')]

    by_sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    by_type = {}
    for f in tp:
        sev = f.get('severity', 'low').lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        t = f.get('type', 'OTHER')
        by_type[t] = by_type.get(t, 0) + 1

    # Update summary
    summary['findings'] = {
        'total': len(tp) + len(fp),
        'true_positives': len(tp),
        'false_positives_filtered': len(fp),
        'by_severity': by_sev,
        'by_type': by_type,
        'pr_submitted': pr_url is not None,
        'pr_url': pr_url,
    }
    summary['top_findings'] = sorted(tp, key=lambda x: x.get('cvss_score', 0), reverse=True)[:5]

    summary_file.write_text(json.dumps(summary, indent=2))

    # Write individual finding files
    for i, f in enumerate(tp):
        fid = f.get('id', f'F{i+1:03d}')
        (scan_dir / 'findings' / f'{fid}.json').write_text(
            json.dumps({'schema_version': '1.0', 'repo_full_name': summary['repo_full_name'], **f}, indent=2)
        )

    # Write pr.json if PR was submitted
    if pr_url:
        pr_info = {
            'schema_version': '1.0',
            'repo_full_name': summary['repo_full_name'],
            'submitted_at': datetime.now(timezone.utc).isoformat(),
            'pr_url': pr_url,
            'pr_number': int(pr_url.split('/')[-1]) if pr_url else None,
            'pr_state': 'open',
            'findings_addressed': [f.get('id') for f in tp if f.get('fix_available')],
            'outcome': 'pending',
        }
        (scan_dir / 'pr.json').write_text(json.dumps(pr_info, indent=2))

    print(f"[log] Triage logged: {len(tp)} TP, {len(fp)} FP")
    if pr_url:
        print(f"[log] PR: {pr_url}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: log_triage.py <scan_dir> [--pr URL]")
        sys.exit(1)

    scan_dir = Path(sys.argv[1])
    pr_url = None

    if '--pr' in sys.argv:
        idx = sys.argv.index('--pr')
        pr_url = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None

    # Load findings if a JSON file is provided
    findings = []
    if '--findings' in sys.argv:
        idx = sys.argv.index('--findings')
        findings_file = Path(sys.argv[idx + 1])
        if findings_file.exists() and findings_file.stat().st_size > 0:
            findings = json.loads(findings_file.read_text())

    log_triage(scan_dir, findings, pr_url)
