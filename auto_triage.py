#!/usr/bin/env python3
"""
auto_triage.py — Triage latest scan findings via MiniMax LLM and create PR for worst finding.
"""
import json, os, sys, subprocess, shutil
import urllib.request, urllib.parse, urllib.error
from pathlib import Path
from datetime import datetime, timezone

BUGHUNT = Path.home() / 'bughunt'
CREDS    = Path.home() / '.openclaw' / 'workspace' / 'credentials.json'
MODEL    = "MiniMax-M2.7-highspeed"


def get_minimax_key():
    try:
        d = json.loads(CREDS.read_text())
        return d.get('minimax', {}).get('api_key', '')
    except:
        return os.environ.get('MINIMAX_API_KEY', '')


def llm_chat(messages: list) -> str:
    """Call MiniMax API with messages, return assistant text."""
    key = get_minimax_key()
    if not key:
        return '{"error": "No API key"}'

    url = 'https://api.minimax.io/v1/chat/completions'
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {key}'
    }
    
    payload = {
        'model': MODEL,
        'messages': messages,
        'max_tokens': 4096,
        'temperature': 1.0,
        'reasoning_split': False,
    }

    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            return result['choices'][0]['message']['content']
    except Exception as e:
        print(f"[llm] Error: {e}")
        return '{"error": "' + str(e) + '"}'


def find_best_scan():
    """Find scan with most raw findings that hasn't been triaged yet."""
    candidates = []
    for sd in BUGHUNT.glob('scans/*/*/*/*/'):
        meta_file = sd / 'meta.json'
        triage_file = sd / 'triage_result.json'
        
        # Skip if already triaged with no true positives
        if triage_file.exists():
            try:
                triage_data = json.loads(triage_file.read_text())
                if triage_data.get('result') in ('no_true_positives', 'pr_created'):
                    continue
            except:
                pass
        
        if not meta_file.exists():
            continue
        try:
            meta = json.loads(meta_file.read_text())
            raw = meta.get('findings_summary', {}).get('raw_findings_count', 0)
            if raw > 0:
                candidates.append((sd, meta, raw))
        except:
            pass
    candidates.sort(key=lambda x: x[2], reverse=True)
    return candidates[0] if candidates else None, candidates


def load_raw(scan_dir):
    raw = {}
    for f in scan_dir.glob('raw/*.json'):
        try:
            raw[f.stem] = json.loads(f.read_text())
        except:
            raw[f.stem] = {}
    return raw


def triage_scan(scan_dir, meta):
    """Ask LLM to triage raw findings and return sorted true positives."""
    repo = meta['repo']
    raw = load_raw(scan_dir)
    raw_json = json.dumps(raw, indent=2, default=str)[:14000]

    system = """You are a senior application security engineer.
Return ONLY valid JSON array. No explanation before or after.
For each true positive: severity, cvss_score, type, tool, file, line_start, title, description, snippet_masked (secrets masked as ***), patch_unified_diff (apply cleanly), pr_explanation (3 sentences for maintainer), remediation (step by step), cwe.

Types: SECRET_HARDCODED, SECRET_IN_HISTORY, INJECTION_SQL, INJECTION_CMD, INJECTION_PATH, AUTH_MISSING, INSECURE_RANDOM, DEPRECATED_CRYPTO, SSRF, CVE_DEPENDENCY, OTHER

False positives: test/spec/mock paths, commented code, placeholders (xxx/changeme), os.environ references, node_modules.

Sort by severity: CRITICAL > HIGH > MEDIUM > LOW. Return JSON array, empty if no true positives."""

    user = f"""Triage these security scan results for {repo['full_name']}.

Language: {repo.get('language','?')} | Stars: {repo.get('stars',0)} | Forks: {repo.get('forks',0)}
Description: {repo.get('description','N/A')}

Raw scan data (first 14k chars):
{raw_json}

Return JSON array of TRUE POSITIVES only with working patches.
Empty array if none."""

    response = llm_chat([
        {"role": "system", "content": system},
        {"role": "user", "content": user}
    ])

    try:
        start = response.find('[')
        end = response.rfind(']') + 1
        if start != -1 and end != 0:
            findings = json.loads(response[start:end])
            # Sort by severity
            sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            findings.sort(key=lambda f: sev_order.get(f.get('severity', 'LOW'), 9))
            return findings
    except Exception as e:
        print(f"[triage] Parse error: {e}")
    return []


def make_pr(repo, finding):
    """Create PR with the fix."""
    owner = repo['owner']
    name = repo['name']
    full = f"{owner}/{name}"
    branch = f"security/auto-fix-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"

    # Fork
    subprocess.run(['gh', 'repo', 'fork', full, '--clone=false'],
                  capture_output=True, timeout=30)

    # Get my username
    my_user = subprocess.run(
        ['gh', 'api', 'user', '-q', '.login'],
        capture_output=True, text=True
    ).stdout.strip()

    tmp = Path('/tmp') / f'bbt_{datetime.now().strftime("%Y%m%d%H%M")}'
    tmp.mkdir()

    try:
        # Clone fork
        subprocess.run(
            ['git', 'clone', f'https://github.com/{my_user}/{name}'],
            cwd='/tmp', capture_output=True, timeout=30
        )
        clone = tmp / name
        if not clone.exists():
            return None, "Clone failed"

        # Add upstream
        subprocess.run(['git', 'remote', 'add', 'upstream', f'https://github.com/{full}'],
                      cwd=str(clone), capture_output=True)
        subprocess.run(['git', 'fetch', 'upstream', '--quiet'],
                      cwd=str(clone), capture_output=True, timeout=30)

        # Get default branch
        upstream_info = subprocess.run(
            ['git', 'remote', 'show', 'upstream'],
            cwd=str(clone), capture_output=True, text=True
        )
        default_branch = 'main'
        for line in upstream_info.stdout.split('\n'):
            if 'HEAD branch' in line:
                default_branch = line.split(':')[1].strip()
                break

        subprocess.run(['git', 'checkout', '-b', branch, f'upstream/{default_branch}'],
                      cwd=str(clone), capture_output=True, timeout=10)

        # Apply patch
        patch = finding.get('patch_unified_diff', '')
        if patch:
            patch_file = tmp / 'fix.patch'
            patch_file.write_text(patch)
            result = subprocess.run(
                ['git', 'apply', '--index', str(patch_file)],
                cwd=str(clone), capture_output=True, text=True
            )
            if result.returncode == 0:
                subprocess.run(
                    ['git', 'add', '.'],
                    cwd=str(clone), capture_output=True
                )
                subprocess.run(
                    ['git', 'commit', '-m', f"security: {finding.get('title', 'auto-fix')}"],
                    cwd=str(clone), capture_output=True
                )
                subprocess.run(
                    ['git', 'push', 'origin', branch, '--quiet'],
                    cwd=str(clone), capture_output=True, timeout=30
                )
            else:
                return None, f"Patch failed: {result.stderr[:200]}"

        # Create PR
        pr_title = f"[Security] {finding.get('title', 'Automated fix')} — {datetime.now().strftime('%Y-%m-%d')}"
        pr_body = f"""## Automated Security Finding

**Severity:** {finding.get('severity', '?')} | **CVSS:** {finding.get('cvss_score', '?')} | **CWE:** {finding.get('cwe', 'N/A')}

**File:** `{finding.get('file', '?')}` line {finding.get('line_start', '?')}

{finding.get('description', '')}

**Remediation:** {finding.get('remediation', '')}

---
*Automated PR by Krabbi Bug Bounty Hunter*"""

        result = subprocess.run(
            ['gh', 'pr', 'create',
             '--repo', full,
             '--title', pr_title,
             '--body', pr_body,
             '--label', 'security',
             '--head', f'{my_user}:{branch}'],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip(), None
        return None, f"PR failed: {result.stderr[:200]}"

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("[triage] Starting auto triage...")

    best, all_scans = find_best_scan()
    if not best:
        print("[triage] No scans with findings found")
        return

    scan_dir, meta, raw_count = best
    repo = meta['repo']

    print(f"[triage] Best candidate: {repo['full_name']} — {raw_count} raw findings")
    print(f"[triage] Running LLM triage...")

    findings = triage_scan(scan_dir, meta)

    if not findings:
        print("[triage] No true positives found")
        # Write empty result
        (scan_dir / 'triage_result.json').write_text(json.dumps({
            'scanned_at': datetime.now(timezone.utc).isoformat(),
            'repo': repo['full_name'],
            'raw_count': raw_count,
            'true_positives': 0,
            'result': 'no_true_positives'
        }, indent=2))
        return

    print(f"[triage] Found {len(findings)} true positives")
    best_finding = findings[0]
    print(f"[triage] Worst: [{best_finding.get('severity')}] {best_finding.get('title')}")

    print(f"[triage] Creating PR...")
    pr_url, err = make_pr(repo, best_finding)

    if pr_url:
        print(f"[triage] PR created: {pr_url}")
        (scan_dir / 'triage_result.json').write_text(json.dumps({
            'scanned_at': datetime.now(timezone.utc).isoformat(),
            'repo': repo['full_name'],
            'raw_count': raw_count,
            'true_positives': len(findings),
            'best_finding': best_finding,
            'pr_url': pr_url,
            'result': 'pr_created'
        }, indent=2))

        # Update summary.json with pr info
        summary_file = scan_dir / 'summary.json'
        if summary_file.exists():
            s = json.loads(summary_file.read_text())
            s['findings']['pr_submitted'] = True
            s['findings']['pr_url'] = pr_url
            summary_file.write_text(json.dumps(s, indent=2))

        # Rebuild index
        import importlib, persist
        importlib.reload(persist)
        persist.rebuild_index()

    else:
        print(f"[triage] PR failed: {err}")
        (scan_dir / 'triage_result.json').write_text(json.dumps({
            'scanned_at': datetime.now(timezone.utc).isoformat(),
            'repo': repo['full_name'],
            'raw_count': raw_count,
            'true_positives': len(findings),
            'best_finding': best_finding,
            'result': 'pr_failed',
            'error': err
        }, indent=2))

    print("[triage] Done!")


if __name__ == '__main__':
    main()
