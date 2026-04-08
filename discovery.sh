#!/usr/bin/env bash
# discovery.sh — Build repo queue for the night run

GITHUB_TOKEN="${GITHUB_TOKEN:?Need GITHUB_TOKEN}"
QUEUE_FILE=~/bughunt/queue.txt
PROCESSED_FILE=~/bughunt/processed.txt
BLOCKLIST=~/bughunt/blocklist.txt
LANGUAGES=("python" "javascript" "typescript" "go" "php" "ruby" "java")
TOPICS=("fastapi" "rest-api" "authentication" "jwt" "oauth" "express"
        "django" "flask" "laravel" "api-gateway" "graphql" "webhook")

touch "$PROCESSED_FILE" "$BLOCKLIST"
> /tmp/discovered_raw.txt

### Strategy A — GitHub Search API
LANG=${LANGUAGES[$RANDOM % ${#LANGUAGES[@]}]}
CUTOFF=$(date -d '90 days ago' +%Y-%m-%d 2>/dev/null || date -v-90d +%Y-%m-%d)
PAGE=$((RANDOM % 5 + 1))

echo "[discovery] Strategy A: language=$LANG page=$PAGE"
curl -sf -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/search/repositories?q=stars:10..2000+pushed:>${CUTOFF}+language:${LANG}+fork:false&sort=updated&order=desc&per_page=100&page=${PAGE}" \
| jq -r '.items[]? | select(.archived==false and .private==false) | .html_url' \
>> /tmp/discovered_raw.txt
sleep 2

### Strategy B — Random since-ID (true random)
echo "[discovery] Strategy B: random since-ID"
for i in {1..4}; do
  RAND_ID=$(python3 -c "import random; print(random.randint(10000000, 900000000))")
  curl -sf -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/repositories?since=${RAND_ID}&per_page=30" \
  | jq -r '.[]? | select(.fork==false and .private==false) | .html_url' \
  >> /tmp/discovered_raw.txt
  sleep 1
done

### Strategy C — Topic hunt
TOPIC=${TOPICS[$RANDOM % ${#TOPICS[@]}]}
echo "[discovery] Strategy C: topic=$TOPIC"
curl -sf -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/repositories?q=topic:${TOPIC}+stars:5..1000+fork:false&sort=updated&per_page=60" \
| jq -r '.items[]? | select(.archived==false and .private==false) | .html_url' \
>> /tmp/discovered_raw.txt
sleep 2

### Deduplicate + filter
# Extract URLs from blocklist (ignore the tab-separated reason)
grep -v '^#' "$BLOCKLIST" | cut -f1 > /tmp/blocklist_urls.txt 2>/dev/null || true

sort -u /tmp/discovered_raw.txt \
| grep -v -F -f "$PROCESSED_FILE" \
| grep -v -F -f /tmp/blocklist_urls.txt \
> "$QUEUE_FILE"

QUEUE_SIZE=$(wc -l < "$QUEUE_FILE")
echo "[discovery] Queue ready: $QUEUE_SIZE unique repos"
