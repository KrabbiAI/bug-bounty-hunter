#!/bin/bash
# Manual Bug Bounty Hunter scan
# Usage: ./reposcan.sh <num_repos> [scenario]
# Example: ./reposcan.sh 20

set -e

NUM_REPOS="${1:-10}"
SCENARIO="${2:-standard}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PATH="$HOME/bin:$HOME/.local/bin:$PATH"
export GITHUB_TOKEN="$(cat ~/.secrets/github_token)"

cd "$SCRIPT_DIR"

echo "[$(date)] Starting manual scan: $NUM_REPOS repos ($SCENARIO scenario)"
python3 agent.py --max_repos "$NUM_REPOS" 2>&1 | tee "logs/manual_$(date +%Y%m%d_%H%M).log"
echo "[$(date)] Scan complete"
