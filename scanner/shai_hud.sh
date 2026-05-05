#!/bin/bash
# shai_hud.sh — Recursive IOC scanner (Linux + macOS + Git Bash on Windows)

# -------------------------------------------------------
# Colors & Helpers
# -------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
NC='\033[0m'

OS="$(uname -s)"
case "$OS" in
  Linux*)  PLATFORM="linux"  ;;
  Darwin*) PLATFORM="macos"  ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows_bash" ;;
  *)       PLATFORM="unknown" ;;
esac

get_file_size() {
  case "$PLATFORM" in
    macos) stat -f%z "$1" 2>/dev/null ;;
    *)     stat -c%s "$1" 2>/dev/null ;;
  esac
}

get_tmp_dir() {
  if [ -n "$TMPDIR" ]; then echo "$TMPDIR"
  elif [ -d "/tmp" ]; then echo "/tmp"
  elif [ -n "$TEMP" ]; then echo "$TEMP"
  else echo "/tmp"; fi
}

get_scan_roots() {
  case "$PLATFORM" in
    macos)         echo "/Users /Applications /Library /opt /usr/local" ;;
    linux)         echo "/home /opt /var /usr /etc /root" ;;
    windows_bash)  echo "/c/Users /d/Users /c/ProgramData" ;;
    *)             echo "/" ;;
  esac
}

trunc() {
  local s="$1" m="$2"
  [ ${#s} -gt "$m" ] && echo "${s:0:$((m-3))}..." || echo "$s"
}

section() {
  echo ""
  echo -e "${CYAN}  $1${NC}"
  echo -e "${DIM}  ────────────────────────────────────────────────────${NC}"
}

ok()       { echo -e "  ${GREEN}[OK]${NC}       $1"; }
critical() { echo -e "  ${RED}[CRITICAL]${NC} $1"; echo "F" >> "$FLOG"; }
warning()  { echo -e "  ${YELLOW}[WARNING]${NC}  $1"; echo "F" >> "$FLOG"; }
review()   { echo -e "  ${CYAN}[REVIEW]${NC}   $1"; echo "F" >> "$FLOG"; }

# -------------------------------------------------------
# Banner & Input
# -------------------------------------------------------
echo ""
echo -e "${WHITE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${WHITE}║            ${CYAN}SHAI-HULUD IOC SCANNER${WHITE}                      ║${NC}"
echo -e "${WHITE}║            Supply-Chain Attack Detector                ║${NC}"
echo -e "${WHITE}╚════════════════════════════════════════════════════════╝${NC}"
echo -e "  Platform: ${WHITE}$PLATFORM${NC} ($(uname -s))"
echo ""

read -rp "  Enter project folder to scan (or Enter for current dir): " INPUT_DIR
INPUT_DIR="${INPUT_DIR/#\~/$HOME}"
SCAN_DIR="${INPUT_DIR:-.}"

if [ ! -d "$SCAN_DIR" ]; then
  echo -e "\n  ${RED}ERROR: '$SCAN_DIR' is not a valid directory.${NC}"
  exit 1
fi

SCAN_DIR=$(cd "$SCAN_DIR" && pwd)
FLOG=$(mktemp)

echo ""
echo -e "  Target:   ${WHITE}$SCAN_DIR${NC}"
echo -e "${DIM}  ════════════════════════════════════════════════════════${NC}"

# -------------------------------------------------------
# 1. Malicious settings.json
# -------------------------------------------------------
section "[1/6] Claude Code Hook Injection"

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

# Scan filesystem roots
for ROOT in $(get_scan_roots); do
  [ -d "$ROOT" ] && find "$ROOT" -name 'settings.json' \
    -not -path '*/node_modules/*' \
    -not -path '*/.Trash/*' \
    2>/dev/null -exec grep -l "SessionStart" {} \; 2>/dev/null | \
    while read -r f; do
      grep -q "setup.mjs" "$f" && critical "Malicious hook: $(trunc "$f" 60)"
    done
done

# Scan project dir
find "$SCAN_DIR" -name 'settings.json' \
  -not -path '*/node_modules/*' \
  2>/dev/null -exec grep -l "SessionStart" {} \; 2>/dev/null | \
  while read -r f; do
    grep -q "setup.mjs" "$f" && critical "Malicious hook: $(trunc "$f" 60)"
  done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No malicious hooks found"

# -------------------------------------------------------
# 2. Bun dropper files
# -------------------------------------------------------
section "[2/6] Bun Dropper Detection"

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

find "$SCAN_DIR" -name "setup.mjs" 2>/dev/null | while read -r f; do
  grep -qi "bun\|oven-sh\|BUN_VERSION" "$f" && critical "Bun dropper: $(trunc "$f" 60)"
done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No dropper files found"

# -------------------------------------------------------
# 3. Large execution.js payloads
# -------------------------------------------------------
section "[3/6] Obfuscated Payload Detection"

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

find "$SCAN_DIR" -name "execution.js" 2>/dev/null | while read -r f; do
  SIZE=$(get_file_size "$f")
  if [ -n "$SIZE" ] && [ "$SIZE" -gt 1000000 ]; then
    SIZE_MB=$(awk "BEGIN {printf \"%.1f\", $SIZE/1048576}")
    critical "execution.js (${SIZE_MB}MB): $(trunc "$f" 55)"
  fi
done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No suspicious payloads found"

# -------------------------------------------------------
# 4. Lock file
# -------------------------------------------------------
section "[4/6] Malware Lock File"

TMP_DIR=$(get_tmp_dir)
LOCKFILE=$(find "$TMP_DIR" -maxdepth 1 -name "tmp.987654321.lock" 2>/dev/null)
if [ -n "$LOCKFILE" ]; then
  critical "Lock file: $LOCKFILE"
else
  ok "No lock file found"
fi

# -------------------------------------------------------
# 5. Suspicious npm preinstall scripts
# -------------------------------------------------------
section "[5/6] NPM Preinstall Scripts"

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

find "$SCAN_DIR" -name "package.json" -not -path '*/node_modules/*' 2>/dev/null | while read -r f; do
  if command -v jq >/dev/null 2>&1; then
    PREINSTALL=$(jq -r ".scripts.preinstall // empty" "$f" 2>/dev/null)
  else
    PREINSTALL=$(grep "\"preinstall\"" "$f" 2>/dev/null | sed "s/.*\"preinstall\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/")
  fi
  if echo "$PREINSTALL" | grep -qEi "setup\.mjs|config\.mjs|execution\.js"; then
    warning "$(trunc "$f" 50)"
    echo -e "             Script: ${DIM}$PREINSTALL${NC}"
  fi
done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No suspicious preinstall scripts"

# -------------------------------------------------------
# 6. AI-authored workflow changes
# -------------------------------------------------------
section "[6/6] AI-Authored Workflow Changes"

REPO_LIST=$(find "$SCAN_DIR" -name ".git" -type d 2>/dev/null)

if [ -z "$REPO_LIST" ]; then
  echo -e "  ${DIM}No git repositories found.${NC}"
else
  # Repo table
  echo ""
  printf "  ${WHITE}%-40s  %-12s  %-35s${NC}\n" "REPOSITORY" "BRANCH" "LAST COMMIT"
  echo -e "  ${DIM}────────────────────────────────────────  ────────────  ───────────────────────────────────${NC}"

  echo "$REPO_LIST" | while read -r gitdir; do
    REPO_DIR=$(dirname "$gitdir")
    REPO_NAME=$(basename "$REPO_DIR")
    BRANCH=$(git -C "$REPO_DIR" branch --show-current 2>/dev/null || echo "unknown")
    HASH=$(git -C "$REPO_DIR" log -1 --format='%h' 2>/dev/null || echo "-------")
    MSG=$(git -C "$REPO_DIR" log -1 --format='%s' 2>/dev/null || echo "no commits")

    printf "  %-40s  %-12s  ${DIM}%s${NC} %s\n" \
      "$(trunc "$REPO_NAME" 40)" \
      "$(trunc "$BRANCH" 12)" \
      "$HASH" \
      "$(trunc "$MSG" 25)"
  done

  REPO_COUNT=$(echo "$REPO_LIST" | wc -l | tr -d ' ')
  echo -e "  ${DIM}────────────────────────────────────────  ────────────  ───────────────────────────────────${NC}"
  echo -e "  ${WHITE}$REPO_COUNT repo(s) scanned${NC}"
  echo ""

  # Scan for AI changes
  BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

  echo "$REPO_LIST" | while read -r gitdir; do
    REPO_DIR=$(dirname "$gitdir")
    REPO_NAME=$(basename "$REPO_DIR")
    git -C "$REPO_DIR" log --all --format='%h|%ae|%s' -- '.github/workflows/' 2>/dev/null | \
      grep -iE 'claude|copilot|ai-bot|github-actions\[bot\]|dependabot|renovate\[bot\]' | \
      grep -iv '[0-9]\++[a-zA-Z].*@users\.noreply\.github\.com' | while IFS='|' read -r hash email subject; do
        review "${WHITE}$REPO_NAME${NC} ${DIM}$hash${NC} $(trunc "$subject" 40)"
        echo -e "             Author: ${DIM}$email${NC}"
      done
  done

  AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
  [ "$BEFORE" = "$AFTER" ] && ok "No AI-authored workflow changes"
fi

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
echo ""
echo -e "${DIM}  ════════════════════════════════════════════════════════${NC}"

TOTAL=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
TOTAL=${TOTAL:-0}
rm -f "$FLOG"

if [ "$TOTAL" -eq 0 ]; then
  echo ""
  echo -e "  ${GREEN}╔════════════════════════════════════════════════╗${NC}"
  echo -e "  ${GREEN}║   CLEAN — No indicators of compromise found    ║${NC}"
  echo -e "  ${GREEN}╚════════════════════════════════════════════════╝${NC}"
  echo ""
  exit 0
else
  echo ""
  echo -e "  ${RED}╔════════════════════════════════════════════════╗${NC}"
  printf "   ${RED}║  ALERT — %-3s finding(s) detected              ║${NC}\n" "$TOTAL"
  echo -e "  ${RED}║   Review the output above for details          ║${NC}"
  echo -e "  ${RED}╚════════════════════════════════════════════════╝${NC}"
  echo ""
  exit 1
fi