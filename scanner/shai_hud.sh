#!/bin/bash
# scan-for-shai-hulud.sh — Recursive IOC scanner

echo "=== Shai-Hulud IOC Scanner ==="
echo ""

# Ask user for project folder
read -rp "Enter project folder to scan (or press Enter for current directory): " INPUT_DIR
INPUT_DIR="${INPUT_DIR/#\~/$HOME}"
SCAN_DIR="${INPUT_DIR:-.}"

# Validate directory
if [ ! -d "$SCAN_DIR" ]; then
  echo "ERROR: '$SCAN_DIR' is not a valid directory."
  exit 1
fi

SCAN_DIR=$(cd "$SCAN_DIR" && pwd)
echo ""
echo "Scanning: $SCAN_DIR (recursive)"
echo "-----------------------------------"

# 1. Check for malicious Claude Code settings (entire filesystem)
echo "[1/6] Scanning entire filesystem for malicious settings.json..."
find / -name 'settings.json' 2>/dev/null -exec sh -c '
  if grep -q "SessionStart" "$1" && grep -q "setup.mjs" "$1"; then
    echo "  CRITICAL: Malicious Claude hook found: $1"
  fi
' _ {} \;

# 2. Check for dropper files recursively
echo "[2/6] Scanning for Bun dropper files..."
find "$SCAN_DIR" -name "setup.mjs" 2>/dev/null -exec sh -c '
  if grep -qi "bun\|oven-sh\|BUN_VERSION" "$1"; then
    echo "  CRITICAL: Bun dropper found: $1"
  fi
' _ {} \;

# 3. Check for payload files recursively
echo "[3/6] Scanning for large execution.js payloads..."
find "$SCAN_DIR" -name "execution.js" 2>/dev/null -exec sh -c '
  SIZE=$(stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null)
  if [ "$SIZE" -gt 1000000 ]; then
    echo "  CRITICAL: Large execution.js payload ($SIZE bytes): $1"
  fi
' _ {} \;

# 4. Check for lock file (anti-double-execution marker)
echo "[4/6] Checking for malware lock file in /tmp..."
LOCKFILE=$(find /tmp -name "tmp.987654321.lock" 2>/dev/null)
if [ -n "$LOCKFILE" ]; then
  echo "  CRITICAL: Malware lock file found: $LOCKFILE"
fi

# 5. Check for suspicious npm preinstall scripts recursively
echo "[5/6] Scanning package.json files for suspicious preinstall scripts..."
find "$SCAN_DIR" -name "package.json" -not -path '*/node_modules/*' 2>/dev/null -exec sh -c '
  PREINSTALL=$(jq -r ".scripts.preinstall // empty" "$1" 2>/dev/null)
  if echo "$PREINSTALL" | grep -qEi "setup\.mjs|config\.mjs|execution\.js"; then
    echo "  WARNING: Suspicious preinstall in $1: $PREINSTALL"
  fi
' _ {} \;

# 6. Check git history for AI commits to workflows in all repos recursively
echo "[6/6] Scanning git repos for AI-authored workflow changes..."
find "$SCAN_DIR" -name ".git" -type d 2>/dev/null | while read gitdir; do
  REPO_DIR=$(dirname "$gitdir")
  git -C "$REPO_DIR" log --all --format='%H %ae %s' -- '.github/workflows/' 2>/dev/null | \
    grep -i 'claude\|noreply' | while read line; do
      echo "  REVIEW: [$REPO_DIR] AI-authored workflow change: $line"
    done
done

echo "-----------------------------------"
echo "=== Scan complete ==="