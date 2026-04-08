#!/usr/bin/env python3
"""agent.py — Bug Bounty Hunter scan orchestrator for cron."""
import json, os, sys, time, subprocess
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))
from check_size import check_repo
from analyze import analyze_repo
from persist import persist_scan, rebuild_index, prune_old_scans

BUGHUNT   = Path.home() / 'bughunt'
TOKEN     = os.environ.get('GITHUB_TOKEN', '')
RUN_ID    = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')
MAX_REPOS = 10
SLEEP_SEC = 2
THREAD_INTEL_PATH = Path.home() / 'projects' / 'krabbi-thread-intelligence'
DO_AUTO_TRIAGE = True  # Set False to skip auto-triage


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def mirror_to_thread_intelligence():
    """Mirror scan results to Thread Intelligence project and deploy to Netlify."""
    import shutil, subprocess

    scans_src = BUGHUNT / 'scans'
    scans_dst = THREAD_INTEL_PATH / 'data' / 'scans'
    index_src = BUGHUNT / 'index.json'
    index_dst = THREAD_INTEL_PATH / 'data' / 'index.json'

    if not scans_src.exists():
        log("[mirror] No scans directory found")
        return

    # Create destination dirs
    scans_dst.mkdir(parents=True, exist_ok=True)
    (THREAD_INTEL_PATH / 'data').mkdir(parents=True, exist_ok=True)

    # Mirror all scan directories preserving path: scans/YYYY/MM/DD/{owner}__{repo}/
    count = 0
    for scan_dir in scans_src.glob('*/*/*/*/'):
        if not scan_dir.is_dir():
            continue
        rel_path = scan_dir.relative_to(scans_src)
        dst = scans_dst / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(scan_dir, dst)
        count += 1

    # Mirror index
    if index_src.exists():
        shutil.copy2(index_src, index_dst)

    log(f"[mirror] Mirrored {count} scan dirs")

    # Deploy to Netlify
    try:
        result = subprocess.run(
            ['netlify', 'deploy', '--dir=.', '--prod'],
            cwd=str(THREAD_INTEL_PATH),
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Production URL' in line or 'deploy is live' in line.lower():
                    log(f"[mirror] {line.strip()}")
                    break
            log("[mirror] Netlify deploy complete")
        else:
            log(f"[mirror] Netlify failed: {result.stderr[:200]}")
    except FileNotFoundError:
        log("[mirror] netlify CLI not found — skipping deploy")
    except Exception as e:
        log(f"[mirror] Netlify error: {e}")


def main():
    log(f"=== Bug Bounty Hunter — Run {RUN_ID} ===")

    # Phase 1 — Discovery
    subprocess.run(['bash', str(BUGHUNT / 'discovery.sh')], check=False)
    queue = [u.strip() for u in (BUGHUNT / 'queue.txt').read_text().splitlines() if u.strip()]
    log(f"Queue: {len(queue)} repos discovered")

    processed = 0
    run_repos  = []

    for url in queue:
        if processed >= MAX_REPOS:
            break

        log(f"[{processed+1}/{MAX_REPOS}] {url}")

        # Phase 2 — Size gate (15 MB limit)
        check = check_repo(url, TOKEN)
        if not check['ok']:
            log(f"  SKIP ({check['reason']})")
            with open(BUGHUNT / 'processed.txt', 'a') as f:
                f.write(url + '\n')
            continue

        meta = check['meta']
        log(f"  OK — {meta['language']} · {meta['size_kb']/1024:.1f} MB · {meta['stars']}★")

        # Phase 3 — Clone + analyze + cleanup
        result = analyze_repo(url, meta, RUN_ID)
        total_time = sum(v.get('duration_s', 0) for v in result.get('tools_run', {}).values())
        log(f"  Analyzed in {total_time:.0f}s — cleanup: {result.get('cleanup_confirmed')}")

        # Phase 4 — Persist (triage done separately via Krabbi)
        persist_scan(result, meta, [], None)

        with open(BUGHUNT / 'processed.txt', 'a') as f:
            f.write(url + '\n')

        run_repos.append({
            'repo': meta['full_name'],
            'scan_dir': result['scan_dir'],
            'language': meta['language'],
            'size_mb': round(meta['size_kb']/1024, 1),
        })

        processed += 1
        # Count raw findings for notification
        raw_dir = BUGHUNT / result['scan_dir'] / 'raw'
        raw_count = 0
        for f in raw_dir.glob('*.json'):
            try:
                data = json.loads(f.read_text())
                if f.stem == 'semgrep':
                    raw_count += len(data.get('results', []))
                elif f.stem == 'bandit':
                    raw_count += len(data.get('results', []))
                elif f.stem in ('trufflehog', 'gitleaks'):
                    raw_count += len(data) if isinstance(data, list) else 0
                elif f.stem == 'detect_secrets':
                    raw_count += sum(len(v) for v in data.get('results', {}).values())
                elif f.stem in ('pip_audit', 'npm_audit'):
                    raw_count += len(data.get('vulnerabilities', {}))
            except:
                pass
        result['raw_findings_count'] = raw_count
        send_repo_scanned(processed, MAX_REPOS, meta, result)
        time.sleep(SLEEP_SEC)

    # Phase 5 — Rebuild index
    rebuild_index()

    # Phase 6 — Prune old scans (keep last 100)
    prune_old_scans(keep=100)

    # Phase 7 — Write run record
    run_record = {
        'run_id': RUN_ID,
        'started_at': f"{RUN_ID[:8]}T03:00:00Z",
        'finished_at': datetime.now(timezone.utc).isoformat(),
        'repos_queued': len(queue),
        'repos_analyzed': processed,
        'repos': run_repos,
    }
    (BUGHUNT / 'runs' / f'run_{RUN_ID}.json').write_text(json.dumps(run_record, indent=2))
    log(f"=== Run complete. Processed: {processed} repos ===")

    # Phase 8 — Auto Triage + PR (if enabled)
    triage_result = None
    if DO_AUTO_TRIAGE:
        log(f"[agent] Running auto triage on last {processed} repos...")
        try:
            import importlib, auto_triage
            importlib.reload(auto_triage)
            auto_triage.main(limit=processed, run_id=RUN_ID)
            # Read triage result if PR was created
            triage_files = sorted(BUGHUNT.glob('scans/*/*/*/*/triage_result.json'),
                                  key=lambda p: p.stat().st_mtime, reverse=True)
            if triage_files:
                triage_data = json.loads(triage_files[0].read_text())
                if triage_data.get('result') == 'pr_created':
                    triage_result = {
                        'repo': triage_data.get('repo', ''),
                        'pr_url': triage_data.get('pr_url', ''),
                        'severity': triage_data.get('best_finding', {}).get('severity', ''),
                        'title': triage_data.get('best_finding', {}).get('title', ''),
                    }
        except Exception as e:
            log(f"[agent] Triage failed: {e}")

    # Phase 9 — Mirror to Thread Intelligence + Deploy
    mirror_to_thread_intelligence()

    # Phase 10 — Send Telegram summary
    send_telegram_summary(processed, run_repos, triage_result=triage_result)


def send_telegram_summary(processed: int, run_repos: list, triage_result: dict = None):
    """Send a summary message to Telegram after scan completion.
    
    Args:
        processed: Number of repos scanned in this session
        run_repos: List of repo metadata dicts
        triage_result: Optional dict with keys: repo, pr_url, severity, title
    """
    import urllib.request, urllib.parse

    index_file = BUGHUNT / 'index.json'
    if index_file.exists():
        index = json.loads(index_file.read_text())
        total_repos = index.get('total_repos_analyzed', 0)
        total_raw = index.get('total_raw_findings', 0)
        total_prs = index.get('total_prs_submitted', 0)
        languages = index.get('languages', {})
        sev = index.get('cumulative_by_severity', {})
    else:
        total_repos = processed
        total_raw = 0
        total_prs = 0
        languages = {}
        sev = {}

    # Build top languages string
    top_langs = sorted(languages.items(), key=lambda x: x[1], reverse=True)[:5]
    langs_str = ', '.join([f"{k}:{v}" for k, v in top_langs]) or 'none'

    # Build recent findings (read raw_findings from meta.json)
    recent_with_findings = []
    for r in run_repos:
        scan_dir = BUGHUNT / r['scan_dir']
        meta_file = scan_dir / 'meta.json'
        if meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text())
                raw = meta.get('findings_summary', {}).get('raw_findings_count', 0)
                recent_with_findings.append({'repo': r['repo'], 'raw': raw})
            except:
                pass
    findings_str = '\n'.join([f"  • {r['repo']}: {r['raw']} raw" for r in recent_with_findings if r['raw'] > 0]) or '  None'

    # Build PR section if triage found something
    pr_section = ""
    if triage_result and triage_result.get('pr_url'):
        sev_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(
            triage_result.get('severity', ''), '⚪')
        pr_section = f"""

✨ *PR Created!*
{sev_emoji} [{triage_result.get('severity', '?')}] {triage_result.get('title', 'Security fix')}
🔗 {triage_result.get('pr_url', '')}"""

    msg = f"""🦀 *Bug Bounty Hunter — Scan Complete*

📊 *Session:* {processed} repos scanned
📈 *Total:* {total_repos} repos | {total_raw} raw findings | {total_prs} PRs

🔍 *This run:*
{findings_str}
📂 *Languages:* {langs_str}
🔴 Critical: {sev.get('critical', 0)} | 🟠 High: {sev.get('high', 0)} | 🟡 Medium: {sev.get('medium', 0)}{pr_section}

Dashboard: https://serene-daifuku-1d5503.netlify.app"""

    token = "8798400513:AAHVGh4T2dtsEXZML6zmtXLNLVPM4lpAcZE"
    chat_id = "631196199"
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    data = urllib.parse.urlencode({
        'chat_id': chat_id,
        'text': msg,
        'parse_mode': 'Markdown',
    }).encode()

    try:
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
        log("[telegram] Summary sent")
    except Exception as e:
        log(f"[telegram] Failed: {e}")


def send_repo_scanned(num: int, total: int, meta: dict, result: dict):
    """Send Telegram notification after each repo is scanned."""
    import urllib.request, urllib.parse

    raw_count = result.get('raw_findings_count', 0)
    lang = meta.get('language', '?')
    size_mb = meta.get('size_kb', 0) / 1024
    stars = meta.get('stars', 0)
    repo_name = meta.get('full_name', '?')

    next_msg = ""
    if num < total:
        next_num = num + 1
        next_msg = f"\n🔄 Starting next scan ({next_num}/{total})..."

    msg = f"""📦 *Repo {num} von {total} wurde gescannt*

🔗 {repo_name}
📂 {lang} | {size_mb:.1f} MB | ⭐ {stars}
🔍 {raw_count} raw findings{next_msg}"""

    token = "8798400513:AAHVGh4T2dtsEXZML6zmtXLNLVPM4lpAcZE"
    chat_id = "631196199"
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    data = urllib.parse.urlencode({
        'chat_id': chat_id,
        'text': msg,
        'parse_mode': 'Markdown',
    }).encode()

    try:
        req = urllib.request.Request(url, data=data)
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log(f"[telegram] Per-repo notification failed: {e}")


if __name__ == '__main__':
    main()
