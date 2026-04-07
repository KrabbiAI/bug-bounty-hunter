#!/usr/bin/env python3
"""analyze.py — Clone + run all SAST tools + immediate cleanup."""
import subprocess, json, shutil, time
from pathlib import Path
from datetime import datetime, timezone

WORK_DIR  = Path.home() / 'bughunt' / 'workspace'
SCAN_ROOT = Path.home() / 'bughunt' / 'scans'

def run_tool(cmd, cwd=None, timeout=300):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, cwd=cwd)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, '', 'TIMEOUT'
    except FileNotFoundError as e:
        return -1, '', f'TOOL_NOT_FOUND: {e}'

def analyze_repo(url: str, repo_meta: dict, run_id: str) -> dict:
    owner  = repo_meta['owner']
    name   = repo_meta['name']
    lang   = (repo_meta.get('language') or 'unknown').lower()
    branch = repo_meta.get('default_branch', 'main')

    now     = datetime.now(timezone.utc)
    scan_dir = SCAN_ROOT / now.strftime('%Y/%m/%d') / f'{owner}__{name}'
    scan_dir.mkdir(parents=True, exist_ok=True)
    raw_dir     = scan_dir / 'raw'
    raw_dir.mkdir(exist_ok=True)
    findings_dir = scan_dir / 'findings'
    findings_dir.mkdir(exist_ok=True)

    clone_dir = WORK_DIR / f'{owner}__{name}'
    clone_dir.mkdir(parents=True, exist_ok=True)

    result = {
        'repo_full_name': f'{owner}/{name}',
        'scan_dir': str(scan_dir.relative_to(Path.home() / 'bughunt')),
        'scanned_at': now.isoformat(),
        'run_id': run_id,
        'tools_run': {},
        'errors': [],
    }

    try:
        # Clone
        t0 = time.time()
        rc, out, err = run_tool([
            'git', 'clone', '--depth', '1', '--single-branch',
            '--branch', branch, url, str(clone_dir)
        ], timeout=120)
        result['clone_duration_s'] = round(time.time() - t0, 1)
        if rc != 0:
            result['errors'].append(f'clone_failed: {err[:200]}')
            return result

        # trufflehog
        t0 = time.time()
        rc, out, err = run_tool([
            'trufflehog', 'filesystem', str(clone_dir),
            '--json', '--no-verification'
        ], timeout=180)
        th_results = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('{'):
                try:
                    th_results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        (raw_dir / 'trufflehog.json').write_text(json.dumps(th_results, indent=2))
        result['tools_run']['trufflehog'] = {
            'status': 'ok' if rc == 0 else 'error',
            'findings_raw': len(th_results),
            'duration_s': round(time.time() - t0, 1),
        }

        # gitleaks
        gl_file = raw_dir / 'gitleaks.json'
        t0 = time.time()
        rc, out, err = run_tool([
            str(Path.home() / 'bin' / 'gitleaks'), 'detect',
            '--source', str(clone_dir),
            '--report-format', 'json',
            '--report-path', str(gl_file),
            '--no-git', '--exit-code', '0'
        ], timeout=120)
        if not gl_file.exists():
            gl_file.write_text('[]')
        try:
            gl_results = json.loads(gl_file.read_text()) or []
        except Exception:
            gl_results = []
        result['tools_run']['gitleaks'] = {
            'status': 'ok',
            'findings_raw': len(gl_results),
            'duration_s': round(time.time() - t0, 1),
        }

        # semgrep
        t0 = time.time()
        rc, out, err = run_tool([
            'semgrep', 'scan',
            '--config', 'p/security-audit',
            '--config', 'p/secrets',
            '--config', 'p/owasp-top-ten',
            '--json', '--quiet',
            str(clone_dir)
        ], timeout=300)
        sg_file = raw_dir / 'semgrep.json'
        try:
            sg_data = json.loads(out) if out.strip() else {'results': []}
        except Exception:
            sg_data = {'results': []}
        sg_file.write_text(json.dumps(sg_data, indent=2))
        result['tools_run']['semgrep'] = {
            'status': 'ok' if rc in (0, 1) else 'error',
            'findings_raw': len(sg_data.get('results', [])),
            'duration_s': round(time.time() - t0, 1),
        }

        # bandit (Python only)
        if 'python' in lang:
            t0 = time.time()
            rc, out, err = run_tool([
                'bandit', '-r', str(clone_dir),
                '-f', 'json', '--quiet', '-ll'
            ], timeout=180)
            bd_file = raw_dir / 'bandit.json'
            try:
                bd_data = json.loads(out) if out.strip() else {'results': []}
            except Exception:
                bd_data = {'results': []}
            bd_file.write_text(json.dumps(bd_data, indent=2))
            result['tools_run']['bandit'] = {
                'status': 'ok',
                'findings_raw': len(bd_data.get('results', [])),
                'duration_s': round(time.time() - t0, 1),
            }

        # pip-audit (Python only)
        if 'python' in lang and any(
            (clone_dir / f).exists()
            for f in ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile']
        ):
            t0 = time.time()
            rc, out, err = run_tool([
                'pip-audit', '--path', str(clone_dir),
                '--format', 'json', '--progress-spinner', 'off'
            ], timeout=180)
            pa_file = raw_dir / 'pip_audit.json'
            try:
                pa_data = json.loads(out) if out.strip() else {'vulnerabilities': []}
            except Exception:
                pa_data = {'vulnerabilities': []}
            pa_file.write_text(json.dumps(pa_data, indent=2))
            result['tools_run']['pip_audit'] = {
                'status': 'ok',
                'findings_raw': len(pa_data.get('vulnerabilities', [])),
                'duration_s': round(time.time() - t0, 1),
            }

        # npm audit (JS/TS only)
        if lang in ('javascript', 'typescript') and (clone_dir / 'package.json').exists():
            t0 = time.time()
            rc, out, err = run_tool(
                ['npm', 'audit', '--json'],
                cwd=str(clone_dir), timeout=180
            )
            nm_file = raw_dir / 'npm_audit.json'
            try:
                nm_data = json.loads(out) if out.strip() else {}
            except Exception:
                nm_data = {}
            nm_file.write_text(json.dumps(nm_data, indent=2))
            result['tools_run']['npm_audit'] = {
                'status': 'ok',
                'findings_raw': len(nm_data.get('vulnerabilities', {})),
                'duration_s': round(time.time() - t0, 1),
            }

        # detect-secrets
        t0 = time.time()
        rc, out, err = run_tool([
            'detect-secrets', 'scan', str(clone_dir), '--all-files'
        ], timeout=120)
        ds_file = raw_dir / 'detect_secrets.json'
        try:
            ds_data = json.loads(out) if out.strip() else {}
        except Exception:
            ds_data = {}
        ds_file.write_text(json.dumps(ds_data, indent=2))
        result['tools_run']['detect_secrets'] = {
            'status': 'ok' if rc == 0 else 'error',
            'findings_raw': sum(len(v) for v in ds_data.get('results', {}).values()),
            'duration_s': round(time.time() - t0, 1),
        }

    finally:
        # IMMEDIATE CLEANUP
        if clone_dir.exists():
            shutil.rmtree(clone_dir, ignore_errors=True)
        result['cleanup_confirmed'] = not clone_dir.exists()

    return result
