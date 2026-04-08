#!/usr/bin/env bash
# discovery.sh — Build repo queue for the night run

GITHUB_TOKEN="${GITHUB_TOKEN:?Need GITHUB_TOKEN}"
QUEUE_FILE=~/bughunt/queue.txt
PROCESSED_FILE=~/bughunt/processed.txt
BLOCKLIST=~/bughunt/blocklist.txt

# Languages compatible with our SAST tools
# semgrep: Python, JS, TS, Go, PHP, Ruby, Java, C, C++, Shell, etc.
# bandit + pip-audit: Python
# npm audit: JavaScript, TypeScript
LANGUAGES=("python" "javascript" "typescript" "go" "php" "ruby" "java" "c" "c++" "shell" "csharp" "swift" "kotlin")
TOPICS=("fastapi" "rest-api" "authentication" "jwt" "oauth" "express"
        "django" "flask" "laravel" "api-gateway" "graphql" "webhook" "security" "api")

touch "$PROCESSED_FILE" "$BLOCKLIST"
> /tmp/discovered_raw.txt

### Strategy A — GitHub Search API (one compatible language)
LANG=${LANGUAGES[$RANDOM % ${#LANGUAGES[@]}]}
CUTOFF=$(date -d '90 days ago' +%Y-%m-%d 2>/dev/null || date -v-90d +%Y-%m-%d)
PAGE=$((RANDOM % 5 + 1))

echo "[discovery] Strategy A: language=$LANG page=$PAGE"
curl -sf -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/search/repositories?q=stars:10..2000+pushed:>${CUTOFF}+language:${LANG}+fork:false&sort=updated&order=desc&per_page=100&page=${PAGE}" \
| jq -r '.items[]? | select(.archived==false and .private==false and .language!=null) | .html_url' \
>> /tmp/discovered_raw.txt
sleep 2

### Strategy B — Random page from search API (uniformly random, language-specific)
echo "[discovery] Strategy B: random page search"
for i in {1..3}; do
  LANG=${LANGUAGES[$RANDOM % ${#LANGUAGES[@]}]}
  PAGE=$((RANDOM % 50 + 1))  # Random page 1-50 for fresh results
  curl -sf -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/repositories?q=language:${LANG}+fork:false&sort=updated&per_page=100&page=${PAGE}" \
  | jq -r '.items[]? | select(.archived==false and .private==false) | .html_url' \
  >> /tmp/discovered_raw.txt
  sleep 2
done

### Strategy C — Topic hunt (only with language)
TOPIC=${TOPICS[$RANDOM % ${#TOPICS[@]}]}
echo "[discovery] Strategy C: topic=$TOPIC"
curl -sf -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/repositories?q=topic:${TOPIC}+stars:5..1000+fork:false&sort=updated&per_page=60" \
| jq -r '.items[]? | select(.archived==false and .private==false and .language!=null) | .html_url' \
>> /tmp/discovered_raw.txt
sleep 2

### Deduplicate + filter
# Extract URLs from blocklist (ignore the tab-separated reason)
grep -v '^#' "$BLOCKLIST" 2>/dev/null | cut -f1 > /tmp/blocklist_urls.txt || true

sort -u /tmp/discovered_raw.txt \
| grep -v -F -f "$PROCESSED_FILE" \
| grep -v -F -f /tmp/blocklist_urls.txt \
> "$QUEUE_FILE"

QUEUE_SIZE=$(wc -l < "$QUEUE_FILE")
echo "[discovery] Queue ready: $QUEUE_SIZE unique repos"
