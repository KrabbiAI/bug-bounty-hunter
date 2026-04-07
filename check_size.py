#!/usr/bin/env python3
"""check_size.py — GitHub repo size gate. Pure API, never clones."""
import subprocess, json, sys, os

def check_repo(url: str, token: str) -> dict:
    parts = url.rstrip('/').split('/')
    owner, repo = parts[-2], parts[-1]

    result = subprocess.run(
        ['curl', '-sf',
         '-H', f'Authorization: token {token}',
         '-H', 'Accept: application/vnd.github+json',
         f'https://api.github.com/repos/{owner}/{repo}'],
        capture_output=True, text=True
    )

    if result.returncode != 0 or not result.stdout.strip():
        return {'ok': False, 'reason': 'api_error', 'meta': {}}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {'ok': False, 'reason': 'json_error', 'meta': {}}

    if 'message' in data:
        return {'ok': False, 'reason': f"api_msg:{data['message']}", 'meta': {}}

    if data.get('archived'):
        return {'ok': False, 'reason': 'archived', 'meta': data}
    if data.get('fork'):
        return {'ok': False, 'reason': 'fork', 'meta': data}
    if data.get('private'):
        return {'ok': False, 'reason': 'private', 'meta': data}
    if data.get('disabled'):
        return {'ok': False, 'reason': 'disabled', 'meta': data}

    size_kb = data.get('size', 0)
    if size_kb > 15360:  # 15 MB
        return {'ok': False, 'reason': f'size_exceeded:{size_kb}KB', 'meta': data}

    return {
        'ok': True,
        'reason': 'passed',
        'meta': {
            'owner': owner,
            'name': repo,
            'full_name': data['full_name'],
            'url': url,
            'language': data.get('language', 'unknown'),
            'stars': data.get('stargazers_count', 0),
            'forks': data.get('forks_count', 0),
            'size_kb': size_kb,
            'default_branch': data.get('default_branch', 'main'),
            'description': data.get('description', ''),
            'topics': data.get('topics', []),
            'license': data.get('license', {}).get('spdx_id') if data.get('license') else None,
            'open_issues': data.get('open_issues_count', 0),
            'last_pushed_at': data.get('pushed_at'),
            'created_at': data.get('created_at'),
        }
    }

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read().strip()
    token = os.environ.get('GITHUB_TOKEN', '')
    result = check_repo(url, token)
    print(json.dumps(result, indent=2))
