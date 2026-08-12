#!/bin/bash
# =============================================================================
# Subdomain Takeover Scanner — wrap subjack with curl fallback check
# =============================================================================
set -uo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAG='\033[0;35m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
hit()  { echo -e "${MAG}[TAKEOVER]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1" >&2; }

_have() { command -v "$1" >/dev/null 2>&1; }

INPUT=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    *) INPUT="$1" ;;
  esac
  shift
done

[ -z "$INPUT" ] || [ ! -s "$INPUT" ] && { err "subdomains file required and non-empty"; exit 2; }

OUT_DIR="${TAKEOVER_OUT_DIR:-$(pwd)/findings/takeover}"
mkdir -p "$OUT_DIR"

OUT_FILE="$OUT_DIR/results.json"
: > "$OUT_FILE"

# Prepare JSON array container
echo "[" > "$OUT_FILE"
first=1

# subjack strategy
if _have subjack; then
  log "Running subjack on $(wc -l < "$INPUT" | tr -d ' ') subdomains..."
  SUBJACK_OUT=$(mktemp)
  subjack -w "$INPUT" -t 20 -ssl -o "$SUBJACK_OUT" 2>/dev/null || true
  if [ -s "$SUBJACK_OUT" ]; then
    while IFS= read -r line; do
      if [ -n "$line" ]; then
        subdomain=$(echo "$line" | awk '{print $1}')
        service=$(echo "$line" | awk '{print $2}')
        if [ "$first" -eq 0 ]; then
          echo "," >> "$OUT_FILE"
        fi
        first=0
        echo "  {\"subdomain\": \"$subdomain\", \"service\": \"$service\", \"vulnerable\": true, \"source\": \"subjack\"}" >> "$OUT_FILE"
        hit "subjack: $subdomain is vulnerable to $service takeover!"
      fi
    done < "$SUBJACK_OUT"
  fi
  rm -f "$SUBJACK_OUT"
fi

# Fallback/hybrid curl signature check (direct fingerprint match)
log "Running direct signature checks on $(wc -l < "$INPUT" | tr -d ' ') subdomains..."
while IFS= read -r host; do
  host=$(echo "$host" | tr -d '\r' | xargs)
  [ -z "$host" ] && continue
  
  # CNAME lookup
  cname=$(dig +short CNAME "$host" | tail -n1 | sed 's/\.$//' | xargs)
  
  # Fast curl check
  body=$(curl -sk --max-time 6 "http://$host" 2>/dev/null || true)
  service=""
  sig=""
  case "$body" in
    *"There isn't a GitHub Pages site here"*)        service="github"; sig="There isn't a GitHub Pages site here." ;;
    *"NoSuchBucket"*)                                 service="aws_s3"; sig="NoSuchBucket" ;;
    *"Heroku | No such app"*)                         service="heroku"; sig="Heroku | No such app" ;;
    *"The specified bucket does not exist"*)          service="aws_s3"; sig="The specified bucket does not exist" ;;
    *"Sorry, this shop is currently unavailable"*)    service="shopify"; sig="Sorry, this shop is currently unavailable" ;;
    *"project not found"*)                            service="surge"; sig="project not found" ;;
    *"You're Almost There"*)                          service="pantheon"; sig="You're Almost There" ;;
    *"Do you want to register"*".wordpress.com"*)     service="wordpress"; sig="Do you want to register" ;;
  esac

  if [ -n "$service" ]; then
    if [ "$first" -eq 0 ]; then
      echo "," >> "$OUT_FILE"
    fi
    first=0
    echo "  {\"subdomain\": \"$host\", \"service\": \"$service\", \"cname\": \"$cname\", \"vulnerable\": true, \"evidence\": \"$sig\", \"source\": \"signature_grep\"}" >> "$OUT_FILE"
    hit "signature_grep: $host is vulnerable to $service takeover! (CNAME: $cname)"
  fi
done < "$INPUT"

echo "" >> "$OUT_FILE"
echo "]" >> "$OUT_FILE"

# Output summary
n=$(python3 -c "import json; d=json.load(open('$OUT_FILE')); print(len(d))" 2>/dev/null || echo 0)
if [ "$n" -gt 0 ]; then
  ok "Scan completed. Found $n takeover candidate(s)."
else
  ok "Scan completed. No candidates found."
fi
echo "Results saved to $OUT_FILE"
