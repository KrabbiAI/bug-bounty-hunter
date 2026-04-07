# 🦀 Bug Bounty Hunter

Autonomous security scanner that discovers public GitHub repositories, finds vulnerabilities, and submits automated PRs with fixes.

## How It Works

```
03:00 Uhr (cron) → Discovery → Size Gate → Clone + Analyze → Triage → PR
```

**Discovery:** GitHub Search API + random repo IDs + topic search
**Analysis:** 7 open-source SAST tools (no commercial tools)
**Cleanup:** Cloned repos are DELETED immediately after analysis

## Tools

| Tool | Purpose | License |
|------|---------|---------|
| `semgrep` | Multi-language SAST | GPL/AGPL |
| `trufflehog` | Secret detection | Apache 2.0 |
| `gitleaks` | Git history secrets | MIT |
| `bandit` | Python SAST | Apache 2.0 |
| `pip-audit` | Python CVE deps | Apache 2.0 |
| `npm audit` | JS CVE deps | MIT (bundled) |
| `detect-secrets` | Entropy secrets | MIT |

## Setup

```bash
# 1. Clone this repo
git clone https://github.com/KrabbiAI/bug-bounty-hunter ~/bughunt
cd ~/bughunt

# 2. Install tools (no root required)
pipx install semgrep trufflehog bandit pip-audit detect-secrets

# 3. Download binaries
curl -sL "https://github.com/cli/cli/releases/latest/... | tar xz -C ~/bin gh
curl -sL "https://github.com/gitleaks/gitleaks/releases/latest/... | tar xz -C ~/bin gitleaks
curl -sL "https://github.com/jqlang/jq/releases/latest/... -o ~/bin/jq

# 4. GitHub token
mkdir -p ~/.secrets
echo "$YOUR_GITHUB_TOKEN" > ~/.secrets/github_token
chmod 600 ~/.secrets/github_token

# 5. Auth gh CLI
export PATH="$HOME/bin:$HOME/.local/bin:$PATH"
export GITHUB_TOKEN="$(cat ~/.secrets/github_token)"
echo "$GITHUB_TOKEN" | gh auth login --with-token
```

## Usage

```bash
export PATH="$HOME/bin:$HOME/.local/bin:$PATH"
export GITHUB_TOKEN="$(cat ~/.secrets/github_token)"
cd ~/bughunt

# Manual run (scans 10 repos)
python3 agent.py

# Cron (daily at 03:00)
0 3 * * * /bin/bash -c 'export PATH="$HOME/bin:$HOME/.local/bin:$PATH"; export GITHUB_TOKEN="$(cat ~/.secrets/github_token)"; cd ~/bughunt && python3 agent.py 2>&1 | tee logs/run_$(date +\%Y\%m\%d_\%H\%M).log'
```

## Constraints

- **Max 10 repos per run**
- **Max 15 MB repo size** (GitHub API check before clone)
- **Only public, non-archived, non-fork repos**
- **No commercial tools** (Snyk, Socket banned)
- **Clones deleted immediately** after analysis

## Storage Structure

```
~/bughunt/
├── scans/                    # Permanent scan archive
│   └── YYYY/MM/DD/{owner}__{repo}/
│       ├── meta.json        # Repo metadata
│       ├── summary.json     # Aggregated findings
│       ├── raw/            # Raw tool output
│       ├── findings/        # Individual findings (after triage)
│       └── pr.json         # PR details (if submitted)
├── runs/                    # Run records
├── logs/                    # Cron logs
├── queue.txt               # Current discovery queue
├── processed.txt           # All-time processed repos
├── blocklist.txt           # Repos that opted out
└── index.json              # Master index
```

## Security Rules

- Static analysis only — never exploit
- Secrets reported masked, never exfiltrated
- PRs clearly labeled as automated
- No root/sudo required

## License

MIT — use freely, contribute improvements.
