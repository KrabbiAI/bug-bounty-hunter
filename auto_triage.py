#!/usr/bin/env python3
"""
auto_triage.py — Triage latest scan findings via MiniMax LLM and create PR for worst finding.
"""
import json, os, sys, subprocess, shutil, time
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


def find_best_scan(run_id: str = None, limit: int = None):
    """Find scan with most raw findings that hasn't been triaged yet.
    
    Args:
        run_id: Only scans from this run_id (YYYYMMDD_HHMM)
        limit: Only look at the N most recent scans (from current run)
    """
    candidates = []
    for sd in BUGHUNT.glob('scans/*/*/*/*/'):
        meta_file = sd / 'meta.json'
        triage_file = sd / 'triage_result.json'
        
        # Skip if already triaged
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
            scan_run_id = meta.get('run_id', '')
            
            # Filter to current run if specified
            if run_id and scan_run_id != run_id:
                continue
            
            if raw > 0:
                candidates.append((sd, meta, raw))
        except:
            pass
    
    # Sort by newest first (by mtime)
    candidates.sort(key=lambda x: x[0].stat().st_mtime, reverse=True)
    
    # Limit to N most recent
    if limit:
        candidates = candidates[:limit]
    
    # Sort remaining by raw findings count (worst first)
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


def get_file_content(clone_path: Path, finding_file: str, line_start: int, line_end: int = None):
    """Read actual file content from cloned repo for patch generation."""
    file_path = clone_path / finding_file
    if not file_path.exists():
        return None
    try:
        lines = file_path.read_text().split('\n')
        if line_end is None:
            line_end = line_start + 10
        # Get context: 3 lines before, the finding lines, 3 lines after
        start = max(0, line_start - 4)
        end = min(len(lines), line_end + 4)
        content = '\n'.join(f'{i+1}: {lines[i]}' for i in range(start, end))
        return content
    except:
        return None


def triage_scan(scan_dir, meta):
    """Ask LLM to triage raw findings and return sorted true positives."""
    repo = meta['repo']
    raw = load_raw(scan_dir)
    raw_json = json.dumps(raw, indent=2, default=str)[:14000]

    # Clone the repo to get actual file content for accurate patches
    clone_path = None
    try:
        # Fork if needed
        subprocess.run(['gh', 'repo', 'fork', repo['full_name'], '--clone=false'],
                      capture_output=True, timeout=30)
        time.sleep(2)
        
        # Get my username
        my_user = subprocess.run(
            ['gh', 'api', 'user', '-q', '.login'],
            capture_output=True, text=True
        ).stdout.strip()
        
        # Clone
        clone_path = Path(f"/tmp/bbt_clone_{repo['name']}")
        if clone_path.exists():
            shutil.rmtree(clone_path, ignore_errors=True)
        clone_result = subprocess.run(
            ['git', 'clone', '--quiet', f'https://github.com/{my_user}/{repo["name"]}'],
            cwd='/tmp', capture_output=True, text=True, timeout=60
        )
        if clone_result.returncode != 0:
            clone_path = None
    except Exception as e:
        print(f"[triage] Clone for content: {e}")
        clone_path = None

    # Get actual file content for better patches
    file_contexts = ""
    if clone_path and clone_path.exists():
        file_contexts = "\n\n--- ACTUAL FILE CONTENT FOR PATCH GENERATION ---\n"
        for tool_name, tool_data in raw.items():
            if isinstance(tool_data, dict) and 'results' in tool_data:
                for finding in tool_data['results'][:3]:  # First 3 findings per tool
                    file_path = finding.get('file', '')
                    line_start = finding.get('line_start', 0)
                    if file_path:
                        content = get_file_content(clone_path, file_path, line_start)
                        if content:
                            file_contexts += f"\nFile: {file_path} (around line {line_start}):\n{content}\n"

    system = """You are a senior application security engineer.
Return ONLY valid JSON array. No explanation before or after.

For each true positive provide: severity, cvss_score, type, tool, file, line_start, title, description, snippet_masked (secrets masked as ***), patch_unified_diff, pr_explanation (3 sentences), remediation (step by step), cwe.

Types: SECRET_HARDCODED, SECRET_IN_HISTORY, INJECTION_SQL, INJECTION_CMD, INJECTION_PATH, AUTH_MISSING, INSECURE_RANDOM, DEPRECATED_CRYPTO, SSRF, CVE_DEPENDENCY, OTHER

False positives: test/spec/mock paths, commented code, placeholders (xxx/changeme), os.environ references, node_modules.

PATCH FORMAT - CRITICAL:
patch_unified_diff must be a VALID UNIFIED DIFF.

The patch MUST:
1. Start with "--- a/<file>" and "+++ b/<file>"  
2. Include proper hunk headers like "@@ -1,3 +1,4 @@"
3. Use REAL newline characters in the JSON string (not literal \\n)
4. Apply cleanly with: git apply patch.diff
5. NO trailing whitespace on any line
6. Match the EXACT line numbers from the actual file content provided

IMPORTANT: Use the ACTUAL FILE CONTENT shown above to generate accurate patches.
If the file content shows line 5 starts with "FROM node:18", your patch header must reference line 5.

Keep patches minimal - only change what's needed.

Sort by severity: CRITICAL > HIGH > MEDIUM > LOW. Return JSON array, empty if no true positives."""

    user = f"""Triage these security scan results for {repo['full_name']}.

Language: {repo.get('language','?')} | Stars: {repo.get('stars',0)} | Forks: {repo.get('forks',0)}
{file_contexts}

Raw scan data (first 14k chars):
{raw_json}

Return JSON array of TRUE POSITIVES only with working patches.
Empty array if none."""

    response = llm_chat([
        {"role": "system", "content": system},
        {"role": "user", "content": user}
    ])

    # Cleanup clone
    if clone_path and clone_path.exists():
        try:
            shutil.rmtree(clone_path, ignore_errors=True)
        except:
            pass

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


def make_pr(repo, finding, retries=2):
    """Create PR with the fix. Retries on clone failure."""
    owner = repo['owner']
    name = repo['name']
    full = f"{owner}/{name}"
    branch = f"security/auto-fix-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"

    # Fork (idempotent - fine if already exists)
    subprocess.run(['gh', 'repo', 'fork', full, '--clone=false'],
                  capture_output=True, timeout=30)
    time.sleep(3)  # Give GitHub time to create the fork

    # Get my username
    my_user = subprocess.run(
        ['gh', 'api', 'user', '-q', '.login'],
        capture_output=True, text=True
    ).stdout.strip()

    clone = None
    for attempt in range(retries + 1):
        tmp = Path('/tmp') / f'bbt_{datetime.now().strftime("%Y%m%d%H%M")}_{attempt}'
        tmp.mkdir(parents=True, exist_ok=True)

        try:
            # Clone fork
            clone_result = subprocess.run(
                ['git', 'clone', f'https://github.com/{my_user}/{name}'],
                cwd=str(tmp), capture_output=True, text=True, timeout=60
            )
            clone = tmp / name
            print(f"[triage] Clone attempt {attempt}: {clone} exists={clone.exists()}, returncode={clone_result.returncode}")
            if clone_result.returncode != 0 or not clone.exists():
                clone_err = clone_result.stderr.strip()[:200] if clone_result.stderr else 'unknown'
                print(f"[triage] Clone attempt {attempt} failed: {clone_err}")
                if attempt < retries:
                    time.sleep(5)
                    shutil.rmtree(tmp, ignore_errors=True)
                    continue
                return None, f"Clone failed after {retries+1} attempts"

            # Add upstream
            subprocess.run(['git', 'remote', 'add', 'upstream', f'https://github.com/{full}'],
                          cwd=str(clone), capture_output=True)
            subprocess.run(['git', 'fetch', 'upstream', '--quiet'],
                          cwd=str(clone), capture_output=True, timeout=60)

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
                          cwd=str(clone), capture_output=True, timeout=30)

            # Apply patch (handle both escaped and real newlines)
            patch = finding.get('patch_unified_diff', '')
            if patch:
                # Unescape \n to real newlines if needed
                patch_unescaped = patch.replace('\\n', '\n')
                patch_file = tmp / 'fix.patch'
                patch_file.write_text(patch_unescaped)
                print(f"[triage] Patch content preview: {patch_unescaped[:200]}...")
                result = subprocess.run(
                    ['git', 'apply', '--index', str(patch_file)],
                    cwd=str(clone), capture_output=True, text=True
                )
                if result.returncode == 0:
                    subprocess.run(['git', 'add', '.'],
                                  cwd=str(clone), capture_output=True)
                    subprocess.run(
                        ['git', 'commit', '-m', f"security: {finding.get('title', 'auto-fix')}"],
                        cwd=str(clone), capture_output=True
                    )
                    subprocess.run(
                        ['git', 'push', 'origin', branch, '--quiet'],
                        cwd=str(clone), capture_output=True, timeout=60
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
                 '--head', f'{my_user}:{branch}'],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip(), None
            return None, f"PR failed: {result.stderr[:200]}"

        except subprocess.TimeoutExpired:
            if attempt < retries:
                time.sleep(5)
                continue
            return None, "Timeout after retries"
        except Exception as e:
            if attempt < retries:
                time.sleep(5)
                continue
            return None, str(e)
        finally:
            if clone:
                shutil.rmtree(tmp, ignore_errors=True)
            else:
                shutil.rmtree(tmp, ignore_errors=True)
    
    return None, "Max retries exceeded"


def main(limit=None, run_id=None):
    import sys
    
    # Allow CLI args as fallback
    if limit is None and len(sys.argv) >= 2:
        limit = int(sys.argv[1])
    if run_id is None and len(sys.argv) >= 3:
        run_id = sys.argv[2]
    
    print(f"[triage] Starting auto triage (limit={limit}, run_id={run_id})...")

    best, all_scans = find_best_scan(run_id=run_id, limit=limit)
    if not all_scans:
        print("[triage] No scans with findings found")
        return

    prs_created = 0
    for scan_dir, meta, raw_count in all_scans:
        repo = meta['repo']
        print(f"\n[triage] Triaging: {repo['full_name']} — {raw_count} raw findings")

        findings = triage_scan(scan_dir, meta)

        if not findings:
            print(f"[triage] No true positives found")
            (scan_dir / 'triage_result.json').write_text(json.dumps({
                'scanned_at': datetime.now(timezone.utc).isoformat(),
                'repo': repo['full_name'],
                'raw_count': raw_count,
                'true_positives': 0,
                'result': 'no_true_positives'
            }, indent=2))
            continue

        print(f"[triage] Found {len(findings)} true positives")
        best_finding = findings[0]
        print(f"[triage] Worst: [{best_finding.get('severity')}] {best_finding.get('title')}")

        print(f"[triage] Creating PR (with retry)...")
        pr_url, err = make_pr(repo, best_finding)

        if pr_url:
            print(f"[triage] PR created: {pr_url}")
            prs_created += 1
            
            # Build severity counts from all true positives
            by_sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            by_type = {}
            for f in findings:
                sev = f.get('severity', 'LOW').lower()
                if sev in by_sev:
                    by_sev[sev] += 1
                t = f.get('type', 'OTHER')
                by_type[t] = by_type.get(t, 0) + 1

            (scan_dir / 'triage_result.json').write_text(json.dumps({
                'scanned_at': datetime.now(timezone.utc).isoformat(),
                'repo': repo['full_name'],
                'raw_count': raw_count,
                'true_positives': len(findings),
                'best_finding': best_finding,
                'pr_url': pr_url,
                'result': 'pr_created',
                'by_severity': by_sev,
                'by_type': by_type
            }, indent=2))

            # Update summary.json with pr info and severity counts
            summary_file = scan_dir / 'summary.json'
            if summary_file.exists():
                s = json.loads(summary_file.read_text())
                s['findings']['pr_submitted'] = True
                s['findings']['pr_url'] = pr_url
                s['findings']['true_positives'] = len(findings)
                s['findings']['by_severity'] = by_sev
                s['findings']['by_type'] = by_type
                summary_file.write_text(json.dumps(s, indent=2))
            
            # Also update meta.json findings_summary
            meta_file = scan_dir / 'meta.json'
            if meta_file.exists():
                m = json.loads(meta_file.read_text())
                m['findings_summary']['by_severity'] = by_sev
                m['findings_summary']['by_type'] = by_type
                m['findings_summary']['findings_after_triage'] = len(findings)
                meta_file.write_text(json.dumps(m, indent=2))

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

    # Rebuild index once at the end
    import importlib, persist
    importlib.reload(persist)
    persist.rebuild_index()

    print(f"\n[triage] Done! PRs created: {prs_created}/{len(all_scans)}")


if __name__ == '__main__':
    main()
