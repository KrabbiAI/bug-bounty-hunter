#!/usr/bin/env python3
"""agent.py — Bug Bounty Hunter scan-only orchestrator (for cron)."""
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


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


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
        time.sleep(SLEEP_SEC)

    # Phase 5 — Rebuild index
    rebuild_index()

    # Phase 6 — Prune old scans (keep last 100)
    prune_old_scans(keep=100)

    # Phase 6 — Write run record
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


if __name__ == '__main__':
    main()
