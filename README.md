# 🦀 Bug Bounty Hunter

Autonomous security scanner that discovers public GitHub repositories, finds vulnerabilities, and submits automated PRs with fixes.

**GitHub:** https://github.com/KrabbiAI/bug-bounty-hunter

## Was Es Macht

```
Cron (03:00/09:00) → Discovery → Size Gate → Clone + Analyze → Triage → PR
```

**Discovery:** GitHub Search API + random repo IDs + topic search
**Analysis:** 7 open-source SAST tools (Semgrep, TruffleHog, Gitleaks, Bandit, pip-audit, npm audit, detect-secrets)
**Cleanup:** Cloned repos werden SOFORT nach analysis gelöscht

## Tech Stack

| Tool | Purpose | License |
|------|---------|---------|
| semgrep | Multi-language SAST | GPL/AGPL |
| trufflehog | Secret detection | Apache 2.0 |
| gitleaks | Git history secrets | MIT |
| bandit | Python SAST | Apache 2.0 |
| pip-audit | Python CVE deps | Apache 2.0 |
| npm audit | JS CVE deps | MIT (bundled) |
| detect-secrets | Entropy secrets | MIT |
| gh CLI | GitHub API | MIT |

**Runtime:** Python 3.8+

## Restore from Scratch

### 1. System Requirements

```bash
python3 --version  # must be >= 3.8
git --version
```

### 2. Tools Installieren

```bash
# pipx (package manager für CLI tools)
pip install pipx
pipx ensurepath

# Security tools
pipx install semgrep trufflehog bandit pip-audit detect-secrets

# GitHub CLI
curl -sL "https://github.com/cli/cli/releases/download/v2.63.0/gh_2.63.0_linux_amd64.tar.gz" | tar xz -C /tmp
mv /tmp/gh_2.63.0_linux_amd64/bin/gh ~/bin/gh
chmod +x ~/bin/gh

# Gitleaks
curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks-v8.30.1-linux-amd64.tar.gz" | tar xz -C ~/bin

# jq
curl -sL "https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux64" -o ~/bin/jq
chmod +x ~/bin/jq
```

### 3. GitHub Token

```bash
mkdir -p ~/.secrets
echo "$YOUR_GITHUB_TOKEN" > ~/.secrets/github_token
chmod 600 ~/.secrets/github_token

# gh CLI auth
export GITHUB_TOKEN="$(cat ~/.secrets/github_token)"
echo "$GITHUB_TOKEN" | gh auth login --with-token
```

### 4. Environment Variables

```bash
export PATH="$HOME/bin:$HOME/.local/bin:$PATH"
export GITHUB_TOKEN="$(cat ~/.secrets/github_token)"
```

### 5. Credentials Storage

**GitHub Token:** `~/.secrets/github_token`
- **WICHTIG:** Token NIE in Code oder README
- Permissions: `repo`, `workflow` für PR creation

## Usage

```bash
# Manual run (scans 20 repos)
export PATH="$HOME/bin:$HOME/.local/bin:$PATH"
export GITHUB_TOKEN="$(cat ~/.secrets/github_token)"
cd ~/bughunt
python3 agent.py

# Specific repo count
python3 agent.py --max_repos 10

# Dry run (keine PRs, nur analysis)
python3 agent.py --dry_run

# Oder nutze das wrapper script:
./reposcan.sh <num_repos>
./reposcan.sh 20
```

## Telegram Commands

Gib in Telegram ein: `/reposcan X` (z.B. `/reposcan 20`)

Der Agent startet dann einen manuellen Scan mit X Repos. Keine extra Konfiguration nötig — einfach den Befehl senden.

## API Endpoints

### GitHub API

**Base URL:** `https://api.github.com`

**Search Repositories:**
```
GET /search/repositories?q=<query>&sort=stars&order=desc
Headers: Authorization: token <GITHUB_TOKEN>
```

**Get Repository:**
```
GET /repos/<owner>/<repo>
Headers: Authorization: token <GITHUB_TOKEN>
```

**Create PR:**
```
POST /repos/<owner>/<repo>/pulls
Headers: Authorization: token <GITHUB_TOKEN>
Body: {title, head, base, body}
```

## Constraints

- **Max 20 repos per scan (4x daily: 03:00, 09:00, 15:00, 21:00)
- **Max 15 MB repo size** (GitHub API check vor clone)
- **Only public, non-archived, non-fork repos**
- **No commercial tools** (Snyk, Socket banned)
- **Clones deleted immediately** nach analysis
- **Last 1000 scans kept** — scans mit PRs werden NIE gelöscht

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

## Finding Types

| Type | Tool | Severity |
|------|------|----------|
| AUTH_MISSING | semgrep | HIGH |
| SECRET_HARDCODED | trufflehog/gitleaks | CRITICAL |
| CVE_DEPENDENCY | pip-audit/npm audit | varies |
| SQL_INJECTION | semgrep | CRITICAL |
| XSS | semgrep | HIGH |
| INSECURE_CRYPTO | semgrep | MEDIUM |

## Security Rules

- Static analysis only — never exploit
- Secrets reported masked, never exfiltrated
- PRs clearly labeled as automated
- No root/sudo required

## Cron Setup

```bash
# Daily runs um 03:00 und 09:00
0 3,9 * * * /bin/bash -c 'export PATH="$HOME/bin:$HOME/.local/bin:$PATH"; export GITHUB_TOKEN="$(cat ~/.secrets/github_token)"; cd ~/bughunt && python3 agent.py 2>&1 | tee logs/run_$(date +\%Y\%m\%d_\%H\%M).log'
```

## Troubleshooting

**GitHub API rate limit:**
- Token hat 5000 req/hour
- Mehrere tokens in rotation (noch nicht implementiert)
- `gh api rate_limit` zum checken

**Clone schlägt fehl:**
- Repo existiert noch? (kann zwischen discovery und clone gelöscht werden)
- Netzwerk probleme → retry logic

**Semgrep findet nichts:**
- Rulesets installiert? `semgrep --install-rules`
- Repo nutzt unterstützte Sprachen?

**PR creation failed:**
- Branch existiert bereits?
- Token hat `repo` permission?
- Repo erlaubt PRs von fork? (für fork repos: nur issue, kein PR)

## Verify Installation

```bash
# Alle tools:
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
