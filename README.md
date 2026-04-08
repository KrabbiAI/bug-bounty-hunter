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
# Requires: Python 3.8+, GitHub account

# 1. Clone this repo
git clone https://github.com/KrabbiAI/bug-bounty-hunter ~/bughunt
cd ~/bughunt

# 2. Install tools (no root required)
pipx install semgrep trufflehog bandit pip-audit detect-secrets
pipx ensurepath  # Adds ~/.local/bin to PATH

# 3. Download binaries
# gh CLI
curl -sL "https://github.com/cli/cli/releases/download/v2.63.0/gh_2.63.0_linux_amd64.tar.gz" | tar xz -C /tmp && mv /tmp/gh_2.63.0_linux_amd64/bin/gh ~/bin/gh && chmod +x ~/bin/gh

# gitleaks
curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks-v8.30.1-linux-amd64.tar.gz" | tar xz -C ~/bin

# jq
curl -sL "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux64" -o ~/bin/jq && chmod +x ~/bin/jq

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

## Verify Installation

```bash
# After setup, verify all tools:
semgrep --version
trufflehog version
gitleaks version
bandit --version
detect-secrets --version
gh auth status

# Test discovery
export PATH="$HOME/bin:$HOME/.local/bin:$PATH"
export GITHUB_TOKEN="$(cat ~/.secrets/github_token)"
cd ~/bughunt && python3 agent.py --dry_run
```

## License

MIT — use freely, contribute improvements.
