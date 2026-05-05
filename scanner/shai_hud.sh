#!/bin/bash
# shai_hud.sh — Recursive IOC scanner (Linux + macOS + Git Bash on Windows)

# -------------------------------------------------------
# Detect OS
# -------------------------------------------------------
OS="$(uname -s)"
case "$OS" in
  Linux*)  PLATFORM="linux"  ;;
  Darwin*) PLATFORM="macos"  ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows_bash" ;;
  *)       PLATFORM="unknown" ;;
esac

# Cross-platform file size
get_file_size() {
  case "$PLATFORM" in
    macos) stat -f%z "$1" 2>/dev/null ;;
    *)     stat -c%s "$1" 2>/dev/null ;;
  esac
}

# Cross-platform temp directory
get_tmp_dir() {
  if [ -n "$TMPDIR" ]; then
    echo "$TMPDIR"
  elif [ -d "/tmp" ]; then
    echo "/tmp"
  elif [ -n "$TEMP" ]; then
    echo "$TEMP"
  else
    echo "/tmp"
  fi
}

# Cross-platform filesystem roots for full settings.json scan
get_scan_roots() {
  case "$PLATFORM" in
    macos)         echo "/Users /Applications /Library /opt /usr/local" ;;
    linux)         echo "/home /opt /var /usr /etc /root" ;;
    windows_bash)  echo "/c/Users /d/Users /c/ProgramData" ;;
    *)             echo "/" ;;
  esac
}

# -------------------------------------------------------
# Banner
# -------------------------------------------------------
echo "=== Shai-Hulud IOC Scanner ==="
echo "Platform: $PLATFORM ($(uname -s))"
echo ""

# -------------------------------------------------------
# Ask user for project folder
# -------------------------------------------------------
read -rp "Enter project folder to scan (or press Enter for current directory): " INPUT_DIR
INPUT_DIR="${INPUT_DIR/#\~/$HOME}"
SCAN_DIR="${INPUT_DIR:-.}"

if [ ! -d "$SCAN_DIR" ]; then
  echo "ERROR: '$SCAN_DIR' is not a valid directory."
  exit 1
fi

SCAN_DIR=$(cd "$SCAN_DIR" && pwd)
FINDINGS_LOG=$(mktemp)
echo ""
echo "Scanning: $SCAN_DIR (recursive)"
echo "-----------------------------------"

# -------------------------------------------------------
# 1. Malicious settings.json (searches common paths + project)
# -------------------------------------------------------
echo "[1/6] Scanning for malicious settings.json..."

for ROOT in $(get_scan_roots); do
  [ -d "$ROOT" ] && find "$ROOT" -name 'settings.json' \
    -not -path '*/node_modules/*' \
    -not -path '*/.Trash/*' \
    2>/dev/null -exec sh -c '
    if grep -q "SessionStart" "$1" && grep -q "setup.mjs" "$1"; then
      echo "  CRITICAL: Malicious Claude hook found: $1"
      echo "FINDING" >> '"$FINDINGS_LOG"'
    fi
  ' _ {} \;
done

# Also scan project dir in case it falls outside the roots above
find "$SCAN_DIR" -name 'settings.json' \
  -not -path '*/node_modules/*' \
  2>/dev/null -exec sh -c '
  if grep -q "SessionStart" "$1" && grep -q "setup.mjs" "$1"; then
    echo "  CRITICAL: Malicious Claude hook found: $1"
    echo "FINDING" >> '"$FINDINGS_LOG"'
  fi
' _ {} \;

# -------------------------------------------------------
# 2. Bun dropper files
# -------------------------------------------------------
echo "[2/6] Scanning for Bun dropper files..."
find "$SCAN_DIR" -name "setup.mjs" 2>/dev/null -exec sh -c '
  if grep -qi "bun\|oven-sh\|BUN_VERSION" "$1"; then
    echo "  CRITICAL: Bun dropper found: $1"
    echo "FINDING" >> '"$FINDINGS_LOG"'
  fi
' _ {} \;

# -------------------------------------------------------
# 3. Large execution.js payloads
# -------------------------------------------------------
echo "[3/6] Scanning for large execution.js payloads..."
find "$SCAN_DIR" -name "execution.js" 2>/dev/null | while read -r file; do
  SIZE=$(get_file_size "$file")
  if [ -n "$SIZE" ] && [ "$SIZE" -gt 1000000 ]; then
    echo "  CRITICAL: Large execution.js payload ($SIZE bytes): $file"
    echo "FINDING" >> "$FINDINGS_LOG"
  fi
done

# -------------------------------------------------------
# 4. Lock file (anti-double-execution marker)
# -------------------------------------------------------
TMP_DIR=$(get_tmp_dir)
echo "[4/6] Checking for malware lock file in $TMP_DIR..."
LOCKFILE=$(find "$TMP_DIR" -maxdepth 1 -name "tmp.987654321.lock" 2>/dev/null)
if [ -n "$LOCKFILE" ]; then
  echo "  CRITICAL: Malware lock file found: $LOCKFILE"
  echo "FINDING" >> "$FINDINGS_LOG"
fi

# -------------------------------------------------------
# 5. Suspicious npm preinstall scripts
# -------------------------------------------------------
echo "[5/6] Scanning package.json files for suspicious preinstall scripts..."
find "$SCAN_DIR" -name "package.json" -not -path '*/node_modules/*' 2>/dev/null -exec sh -c '
  if command -v jq >/dev/null 2>&1; then
    PREINSTALL=$(jq -r ".scripts.preinstall // empty" "$1" 2>/dev/null)
  else
    PREINSTALL=$(grep "\"preinstall\"" "$1" 2>/dev/null | sed "s/.*\"preinstall\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/")
  fi
  if echo "$PREINSTALL" | grep -qEi "setup\.mjs|config\.mjs|execution\.js"; then
    echo "  WARNING: Suspicious preinstall in $1: $PREINSTALL"
    echo "FINDING" >> '"$FINDINGS_LOG"'
  fi
' _ {} \;

# -------------------------------------------------------
# 6. AI-authored workflow changes in all git repos
# -------------------------------------------------------
echo "[6/6] Scanning git repos for AI-authored workflow changes..."
find "$SCAN_DIR" -name ".git" -type d 2>/dev/null | while read -r gitdir; do
  REPO_DIR=$(dirname "$gitdir")
  git -C "$REPO_DIR" log --all --format='%H %ae %s' -- '.github/workflows/' 2>/dev/null | \
    grep -i 'claude\|noreply' | while read -r line; do
      echo "  REVIEW: [$REPO_DIR] AI-authored workflow change: $line"
      echo "FINDING" >> "$FINDINGS_LOG"
    done
done

echo "-----------------------------------"

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
TOTAL=$(wc -l < "$FINDINGS_LOG" 2>/dev/null | tr -d ' ')
TOTAL=${TOTAL:-0}
rm -f "$FINDINGS_LOG"

if [ "$TOTAL" -eq 0 ]; then
  echo ""
  echo "CLEAN: No indicators of compromise found."
  echo "=== Scan complete ==="
  exit 0
else
  echo ""
  echo "ALERT: $TOTAL finding(s) detected. Review the output above."
  echo "=== Scan complete ==="
  exit 1
fi