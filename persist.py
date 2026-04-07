#!/usr/bin/env python3
"""persist.py — Write all scan artifacts and rebuild master index."""
import json, shutil
from pathlib import Path
from datetime import datetime, timezone

BUGHUNT = Path.home() / 'bughunt'

def _count_raw_findings(scan_dir: Path) -> int:
    """Count findings across all raw tool outputs before triage."""
    raw_dir = scan_dir / 'raw'
    total = 0
    for f in raw_dir.glob('*.json'):
        try:
            data = json.loads(f.read_text())
            if f.stem == 'semgrep':
                total += len(data.get('results', []))
            elif f.stem == 'bandit':
                total += len(data.get('results', []))
            elif f.stem == 'trufflehog':
                total += len(data) if isinstance(data, list) else 0
            elif f.stem == 'gitleaks':
                total += len(data) if isinstance(data, list) else 0
            elif f.stem == 'detect_secrets':
                total += sum(len(v) for v in data.get('results', {}).values())
            elif f.stem == 'pip_audit':
                total += len(data.get('vulnerabilities', []))
            elif f.stem == 'npm_audit':
                total += len(data.get('vulnerabilities', {}))
        except Exception:
            pass
    return total


def persist_scan(scan_result: dict, repo_meta: dict, findings: list, pr_info: dict | None):
    scan_dir = BUGHUNT / scan_result['scan_dir']

    # Count raw findings before triage
    raw_findings_count = _count_raw_findings(scan_dir)
    has_findings = raw_findings_count > 0

    (scan_dir / 'meta.json').write_text(json.dumps({
        'schema_version': '1.0',
        'scanned_at': scan_result['scanned_at'],
        'run_id': scan_result['run_id'],
        'repo': repo_meta,
        'size_check': {
            'passed': True,
            'size_kb': repo_meta['size_kb'],
            'limit_kb': 102400,
        },
        'clone': {
            'success': True,
            'duration_s': scan_result.get('clone_duration_s'),
            'depth': 1,
        },
        'findings_summary': {
            'raw_findings_count': raw_findings_count,
            'has_raw_findings': has_findings,
            'findings_after_triage': len([f for f in findings if not f.get('false_positive')]) if findings else 0,
            'language': repo_meta.get('language', 'unknown'),
        }
    }, indent=2))

    for f in findings:
        if not f.get('false_positive'):
            fid = f['id']
            (scan_dir / 'findings' / f'{fid}.json').write_text(
                json.dumps({
                    'schema_version': '1.0',
                    'repo_full_name': repo_meta['full_name'],
                    **f
                }, indent=2)
            )

    tp = [f for f in findings if not f.get('false_positive')]
    fp = [f for f in findings if f.get('false_positive')]
    by_sev  = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    by_type = {}
    for f in tp:
        sev = f.get('severity', 'low').lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        t = f.get('type', 'OTHER')
        by_type[t] = by_type.get(t, 0) + 1

    (scan_dir / 'summary.json').write_text(json.dumps({
        'schema_version': '1.0',
        'repo_full_name': repo_meta['full_name'],
        'scanned_at': scan_result['scanned_at'],
        'run_id': scan_result['run_id'],
        'analysis_duration_s': sum(
            v.get('duration_s', 0) for v in scan_result.get('tools_run', {}).values()
        ),
        'cleanup_confirmed': scan_result.get('cleanup_confirmed', False),
        'findings': {
            'total': len(tp) + len(fp),
            'true_positives': len(tp),
            'false_positives_filtered': len(fp),
            'by_severity': by_sev,
            'by_type': by_type,
            'pr_submitted': pr_info is not None,
            'pr_url': pr_info.get('pr_url') if pr_info else None,
            'pr_number': pr_info.get('pr_number') if pr_info else None,
        },
        'tools_run': scan_result.get('tools_run', {}),
        'has_raw_findings': has_findings,
        'top_findings': sorted(tp, key=lambda x: x.get('cvss_score', 0), reverse=True)[:5],
    }, indent=2))

    if pr_info:
        (scan_dir / 'pr.json').write_text(json.dumps({
            'schema_version': '1.0', **pr_info
        }, indent=2))

    print(f"[persist] Saved: {scan_dir}")


def rebuild_index():
    """Rebuild index.json from all meta.json and summary.json files."""
    index = {
        'schema_version': '1.0',
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'total_runs': 0,
        'total_repos_analyzed': 0,
        'total_findings': 0,
        'total_true_positives': 0,
        'total_prs_submitted': 0,
        'total_raw_findings': 0,
        'cumulative_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'cumulative_by_type': {},
        'languages': {},
        'recent_repos': [],
    }

    # Find all scan directories (those with meta.json)
    scan_dirs = sorted(
        BUGHUNT.glob('scans/*/*/*/*/'),
        key=lambda p: p.stat().st_mtime, reverse=True
    )

    for scan_dir in scan_dirs:
        meta_file = scan_dir / 'meta.json'
        summary_file = scan_dir / 'summary.json'

        if not meta_file.exists():
            continue

        try:
            meta = json.loads(meta_file.read_text())
        except Exception:
            continue

        repo = meta.get('repo', {})
        findings_sum = meta.get('findings_summary', {})
        full_name = repo.get('full_name', scan_dir.name.replace('__', '/'))
        scan_entry = {
            'repo': full_name,
            'scanned_at': meta.get('scanned_at', ''),
            'scan_dir': str(scan_dir.relative_to(BUGHUNT)),
            'language': findings_sum.get('language', repo.get('language', 'unknown')),
            'stars': repo.get('stars', 0),
            'forks': repo.get('forks', 0),
            'raw_findings': findings_sum.get('raw_findings_count', 0),
            'has_raw_findings': findings_sum.get('has_raw_findings', False),
            'true_positives': 0,
            'critical': 0,
            'high': 0,
            'pr_url': None,
        }

        # Enhance with summary.json if available
        if summary_file.exists():
            try:
                summary = json.loads(summary_file.read_text())
                findings = summary.get('findings', {})
                scan_entry['true_positives'] = findings.get('true_positives', 0)
                scan_entry['critical'] = findings.get('by_severity', {}).get('critical', 0)
                scan_entry['high'] = findings.get('by_severity', {}).get('high', 0)
                scan_entry['pr_url'] = findings.get('pr_url')
                index['total_true_positives'] += findings.get('true_positives', 0)
                if findings.get('pr_submitted'):
                    index['total_prs_submitted'] += 1
                for sev, cnt in findings.get('by_severity', {}).items():
                    index['cumulative_by_severity'][sev] = \
                        index['cumulative_by_severity'].get(sev, 0) + cnt
                for t, cnt in findings.get('by_type', {}).items():
                    index['cumulative_by_type'][t] = \
                        index['cumulative_by_type'].get(t, 0) + cnt
            except Exception:
                pass

        index['total_repos_analyzed'] += 1
        index['total_raw_findings'] += findings_sum.get('raw_findings_count', 0)

        # Track languages
        lang = findings_sum.get('language', repo.get('language', 'unknown'))
        index['languages'][lang] = index['languages'].get(lang, 0) + 1

        if len(index['recent_repos']) < 100:
            index['recent_repos'].append(scan_entry)

    (BUGHUNT / 'index.json').write_text(json.dumps(index, indent=2))
    print(f"[index] Rebuilt: {index['total_repos_analyzed']} repos, {index['total_raw_findings']} raw findings")


def prune_old_scans(keep=100):
    """Delete old scan directories, keeping only the most recent `keep` repos."""
    # Find all scan directories (those with meta.json)
    scan_dirs = sorted(
        BUGHUNT.glob('scans/*/*/*/*/'),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    if len(scan_dirs) <= keep:
        print(f"[prune] {len(scan_dirs)} repos — nothing to prune")
        return

    to_delete = scan_dirs[keep:]
    deleted = 0
    for scan_dir in to_delete:
        try:
            shutil.rmtree(scan_dir)
            deleted += 1
        except Exception as e:
            print(f"[prune] Failed to delete {scan_dir}: {e}")

    print(f"[prune] Deleted {deleted} old repos, kept {keep} most recent")
