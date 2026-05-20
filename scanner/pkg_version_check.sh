#!/bin/bash
# pkg_version_check.sh — Mini Shai-Hulud package-version scanner
#
# Detects (package, version) pairs from the Mini Shai-Hulud campaign in:
#   (a) a local project directory — manifests, lockfiles, and installed node_modules
#   (b) the user's GitHub repositories — via gh code-search + dependency-graph SBOM
#
# Standalone companion to scanner/ais.sh — do NOT source from ais.sh.

# -------------------------------------------------------
# Colors & Helpers  (match ais.sh palette exactly)
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
  Linux*)              PLATFORM="linux"        ;;
  Darwin*)             PLATFORM="macos"        ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows_bash" ;;
  *)                   PLATFORM="unknown"      ;;
esac

get_file_size() {
  case "$PLATFORM" in
    macos) stat -f%z "$1" 2>/dev/null ;;
    *)     stat -c%s  "$1" 2>/dev/null ;;
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

describe() {
  echo -e "${DIM}  What:${NC} $1"
  echo -e "${DIM}  Fix:${NC}  $2"
  echo ""
}

ok()       { echo -e "  ${GREEN}[OK]${NC}       $1"; }
critical() { echo -e "  ${RED}[CRITICAL]${NC} $1"; echo "C" >> "$FLOG"; }
warning()  { echo -e "  ${YELLOW}[WARNING]${NC}  $1"; echo "W" >> "$FLOG"; }
review()   { echo -e "  ${CYAN}[REVIEW]${NC}   $1"; echo "R" >> "$FLOG"; }

find_line() {
  grep -nE "$1" "$2" 2>/dev/null | head -1 | cut -d: -f1
}

loc() {
  local f="$1" l="$2"
  if [ -n "$l" ]; then echo "$f:$l"; else echo "$f"; fi
}

# -------------------------------------------------------
# Parse flags
# -------------------------------------------------------
SKIP_NODE_MODULES=0
for arg in "$@"; do
  case "$arg" in
    --skip-node-modules) SKIP_NODE_MODULES=1 ;;
    --help|-h)
      echo "Usage: $(basename "$0") [--skip-node-modules]"
      echo "  --skip-node-modules   Exclude node_modules from local scan (misses installed-but-unlocked packages)"
      echo ""
      echo "Env overrides:"
      echo "  IOC_CSV=<path>        CSV of (package,version) pairs  [default: ~/Downloads/Mini Shai-Hulud - Sheet1.csv]"
      echo "  PROJECT_DIR=<path>    Local project to scan            [default: interactive prompt]"
      echo "  REPORT_FILE=<path>    Output report path               [default: ./shai-hulud-pkg-scan-TIMESTAMP.log]"
      exit 0
      ;;
  esac
done

# -------------------------------------------------------
# Banner
# -------------------------------------------------------
echo ""
echo -e "${WHITE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${WHITE}║       ${CYAN}MINI SHAI-HULUD PACKAGE VERSION SCANNER${WHITE}          ║${NC}"
echo -e "${WHITE}║       Affected (package, version) pair detector        ║${NC}"
echo -e "${WHITE}╚════════════════════════════════════════════════════════╝${NC}"
echo -e "  Platform: ${WHITE}$PLATFORM${NC} ($(uname -s))"
echo ""

# -------------------------------------------------------
# Load CSV
# -------------------------------------------------------
DEFAULT_CSV="$HOME/Downloads/ Mini Shai-Hulud - Sheet1.csv"
IOC_CSV="${IOC_CSV:-$DEFAULT_CSV}"

if [ ! -f "$IOC_CSV" ]; then
  echo -e "  ${RED}ERROR: CSV not found at: $IOC_CSV${NC}"
  echo -e "  Set IOC_CSV=/path/to/file.csv and retry."
  exit 1
fi

# Detect and skip header row: if col1 looks like a literal header word
# (not a package name — i.e. no / or @ and matches common header vocabulary)
# then skip row 1. Heuristic: if first field contains "package" or "name"
# (case-insensitive) and second field contains "version", it's a header.
CSV_HEADER_SKIP=0
FIRST_COL=$(awk -F',' 'NR==1{print $1}' "$IOC_CSV" | tr -d '"' | tr '[:upper:]' '[:lower:]' | tr -d ' ')
SECOND_COL=$(awk -F',' 'NR==1{print $2}' "$IOC_CSV" | tr -d '"' | tr '[:upper:]' '[:lower:]' | tr -d ' ')
if echo "$FIRST_COL" | grep -qiE '^(package|name|pkg)$' && echo "$SECOND_COL" | grep -qiE '^(version|ver)$'; then
  CSV_HEADER_SKIP=1
fi

# Load (pkg, version) pairs into parallel arrays via temp file to avoid subshell isolation.
# Format in tmp: "PKG\tVERSION" — one per line.
PAIRS_FILE=$(mktemp)
awk -F',' -v skip="$CSV_HEADER_SKIP" '
  NR==1 && skip==1 { next }
  NF>=2 {
    pkg=$1; ver=$2
    # Strip surrounding quotes
    gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", pkg)
    gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", ver)
    # Skip blank rows
    if (pkg=="" || ver=="") next
    print pkg "\t" ver
  }
' "$IOC_CSV" >> "$PAIRS_FILE"

PAIR_COUNT=$(wc -l < "$PAIRS_FILE" | tr -d ' ')

# Determine ecosystem mix: if any package name starts with @ or contains /
# it is npm-scoped; unscoped names could theoretically be PyPI too.
# Detect PyPI candidates: names that look like python packages (contain _ or
# are known PyPI-style with no . or / in the name). We keep it simple: if
# any row has no @ and no /, flag as "possible PyPI candidate" in the banner
# but still scan PyPI manifests.
SCOPED_COUNT=$(awk -F'\t' '$1 ~ /^@/' "$PAIRS_FILE" | wc -l | tr -d ' ')
UNSCOPED_COUNT=$((PAIR_COUNT - SCOPED_COUNT))
PYPI_COUNT=$(awk -F'\t' '$1 !~ /^@/ && $1 !~ /\// {print}' "$PAIRS_FILE" | wc -l | tr -d ' ')
ECOSYSTEM_NOTE="npm"
[ "$PYPI_COUNT" -gt 0 ] && ECOSYSTEM_NOTE="npm + possible PyPI overlap ($PYPI_COUNT unscoped)"

echo -e "  CSV:      ${WHITE}${IOC_CSV}${NC}"
echo -e "  Pairs:    ${WHITE}${PAIR_COUNT}${NC} (scoped: ${SCOPED_COUNT}, unscoped: ${UNSCOPED_COUNT})"
echo -e "  Ecosys:   ${WHITE}${ECOSYSTEM_NOTE}${NC}"
[ "$CSV_HEADER_SKIP" = "1" ] && echo -e "  ${DIM}(header row detected and skipped)${NC}"

# -------------------------------------------------------
# Input: local project dir
# -------------------------------------------------------
if [ -n "$PROJECT_DIR" ]; then
  INPUT_DIR="$PROJECT_DIR"
else
  echo ""
  read -rp "  Enter project folder to scan (or Enter for current dir): " INPUT_DIR
fi
INPUT_DIR="${INPUT_DIR/#\~/$HOME}"
SCAN_DIR="${INPUT_DIR:-.}"

if [ ! -d "$SCAN_DIR" ]; then
  echo -e "\n  ${RED}ERROR: '$SCAN_DIR' is not a valid directory.${NC}"
  rm -f "$PAIRS_FILE"
  exit 1
fi
SCAN_DIR=$(cd "$SCAN_DIR" && pwd)

# -------------------------------------------------------
# Report file setup (ANSI-stripped copy to disk)
# -------------------------------------------------------
REPORT_FILE="${REPORT_FILE:-$(pwd)/shai-hulud-pkg-scan-$(date +%Y%m%d-%H%M%S).log}"
: > "$REPORT_FILE" 2>/dev/null || {
  echo "WARN: cannot write to $REPORT_FILE — disabling report"
  REPORT_FILE=""
}
if [ -n "$REPORT_FILE" ]; then
  exec > >(tee >(sed -u $'s/\x1b\\[[0-9;]*[mGKH]//g' >> "$REPORT_FILE"))
  exec 2>&1
fi

FLOG=$(mktemp)

echo ""
echo -e "  Target:   ${WHITE}$SCAN_DIR${NC}"
[ "$SKIP_NODE_MODULES" = "1" ] && echo -e "  ${DIM}(node_modules excluded — pass --skip-node-modules)${NC}"
[ -n "$REPORT_FILE" ]         && echo -e "  Report:   ${WHITE}${REPORT_FILE}${NC}"
echo -e "${DIM}  ════════════════════════════════════════════════════════${NC}"

# -------------------------------------------------------
# Helper: version range check
# Given a pinned affected version and a range string from a manifest,
# returns "critical" if exact match, "review" if range could include it,
# "ok" if definitely excluded.
# This is heuristic-only — semver full resolution is not done in bash.
# -------------------------------------------------------
version_match_type() {
  local affected="$1"
  local manifest_ver="$2"

  # Exact match (including if quoted or with 'v' prefix stripped already)
  if [ "$manifest_ver" = "$affected" ]; then
    echo "critical"; return
  fi

  # Range characters present — flag for review
  case "$manifest_ver" in
    \^*|\~*|\>=*|\<=*|\>*|\<*|"*"|x|X|"||"*|" - "*)
      echo "review"; return ;;
  esac

  # "latest", "next", "*" — always review
  case "$manifest_ver" in
    latest|next|\*) echo "review"; return ;;
  esac

  echo "ok"
}

# -------------------------------------------------------
# §1  Local scan — npm manifests
# -------------------------------------------------------
section "[1/3] Local NPM Manifest & Lockfile Scan"
describe \
  "Walks the project for package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, and installed node_modules/<pkg>/package.json. Exact version matches in lockfiles and installed packages are CRITICAL; range specifiers that could include an affected version are REVIEW." \
  "For CRITICAL: remove the package from package.json, delete node_modules + lockfile, run 'npm install' to regenerate. For REVIEW: pin to a known-clean version and re-lock. In both cases check whether the package's install script ran (see ais.sh §5 for preinstall detection)."

BEFORE_LOCAL=$(wc -l < "$FLOG" | tr -d ' ')

# Build find prune arguments for node_modules
NM_PRUNE_ARGS=""
[ "$SKIP_NODE_MODULES" = "1" ] && NM_PRUNE_ARGS="-not -path '*/node_modules/*'"

# ---- package.json (non-node_modules, unless skip flag is off) ----
echo -e "\n  ${DIM}Scanning package.json files...${NC}"

find "$SCAN_DIR" -name "package.json" \
    \( -path '*/node_modules/*/package.json' -o -not -path '*/node_modules/*' \) \
    -print0 2>/dev/null | \
  while IFS= read -r -d '' manifest; do

    # For node_modules/<pkg>/package.json: read 'name' and 'version' directly
    # (these are installed packages, not user-authored manifests)
    case "$manifest" in
      */node_modules/*/package.json)
        # Respect --skip-node-modules
        [ "$SKIP_NODE_MODULES" = "1" ] && continue

        if command -v jq >/dev/null 2>&1; then
          INST_NAME=$(jq -r '.name // empty'    "$manifest" 2>/dev/null)
          INST_VER=$(jq  -r '.version // empty' "$manifest" 2>/dev/null)
        else
          INST_NAME=$(grep -m1 '"name"'    "$manifest" 2>/dev/null | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
          INST_VER=$(grep -m1  '"version"' "$manifest" 2>/dev/null | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        fi

        [ -z "$INST_NAME" ] || [ -z "$INST_VER" ] && continue

        # Look up against pairs
        while IFS=$'\t' read -r pkg ver; do
          if [ "$INST_NAME" = "$pkg" ] && [ "$INST_VER" = "$ver" ]; then
            critical "Installed node_module exact match: ${WHITE}${pkg}@${ver}${NC}"
            echo -e "             Location: $(loc "$manifest")"
          fi
        done < "$PAIRS_FILE"
        continue
        ;;
    esac

    # User-authored package.json — scan dependency fields
    for DEP_FIELD in dependencies devDependencies optionalDependencies peerDependencies; do
      if command -v jq >/dev/null 2>&1; then
        # Output "name\trange" pairs
        jq -r --arg f "$DEP_FIELD" '.[$f] // {} | to_entries[] | "\(.key)\t\(.value)"' \
          "$manifest" 2>/dev/null
      else
        # Fallback: awk the JSON block (handles single-level objects only)
        awk -v field="$DEP_FIELD" '
          /^[[:space:]]*"/ && found && /^[[:space:]]*}/ { found=0 }
          found && match($0, /"([^"]+)"[[:space:]]*:[[:space:]]*"([^"]+)"/, a) {
            print a[1] "\t" a[2]
          }
          $0 ~ "\"" field "\"" { found=1 }
        ' "$manifest" 2>/dev/null
      fi
    done | while IFS=$'\t' read -r dep_name dep_range; do
      [ -z "$dep_name" ] && continue

      # Strip leading ^ ~ >= <= > < from version for comparison
      clean_range=$(echo "$dep_range" | sed 's/^[^0-9]*//')

      while IFS=$'\t' read -r pkg ver; do
        [ "$dep_name" = "$pkg" ] || continue
        mtype=$(version_match_type "$ver" "$clean_range")
        line=$(find_line "\"${pkg//\//\\/}\"" "$manifest")
        case "$mtype" in
          critical)
            critical "${WHITE}${pkg}@${ver}${NC} in ${DEP_FIELD} (exact pin)"
            echo -e "             File: $(loc "$manifest" "$line")"
            ;;
          review)
            review "${WHITE}${pkg}${NC} range '${dep_range}' may include affected ${ver}"
            echo -e "             File: $(loc "$manifest" "$line")"
            ;;
        esac
      done < "$PAIRS_FILE"
    done

  done

# ---- package-lock.json ----
echo -e "  ${DIM}Scanning package-lock.json files...${NC}"

find "$SCAN_DIR" -name "package-lock.json" \
  -not -path '*/node_modules/*' \
  -print0 2>/dev/null | \
  while IFS= read -r -d '' lockfile; do
    while IFS=$'\t' read -r pkg ver; do
      [ -z "$pkg" ] && continue
      # Escape for grep
      PKG_ESC=$(printf '%s' "$pkg" | sed 's/[].[\/*^$]/\\&/g')
      # In npm lockfiles the resolved entry looks like "node_modules/@scope/pkg": { "version": "x.y.z" }
      # or "name": "@scope/pkg" ... "version": "x.y.z"
      # Strategy: grep for the package name, then check if the version appears on the next few lines
      if grep -q "\"$PKG_ESC\"" "$lockfile" 2>/dev/null; then
        # Extract version value from context block around pkg name
        # Works for both lockfile v1 and v2/v3 formats
        FOUND_VER=$(grep -A 5 "\"$PKG_ESC\"" "$lockfile" 2>/dev/null | \
          grep '"version"' | head -1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [ "$FOUND_VER" = "$ver" ]; then
          LINE=$(grep -n "\"$PKG_ESC\"" "$lockfile" 2>/dev/null | head -1 | cut -d: -f1)
          critical "Lockfile exact match: ${WHITE}${pkg}@${ver}${NC}"
          echo -e "             File: $(loc "$lockfile" "$LINE")"
        fi
      fi
    done < "$PAIRS_FILE"
  done

# ---- yarn.lock ----
echo -e "  ${DIM}Scanning yarn.lock files...${NC}"

find "$SCAN_DIR" -name "yarn.lock" \
  -not -path '*/node_modules/*' \
  -print0 2>/dev/null | \
  while IFS= read -r -d '' lockfile; do
    while IFS=$'\t' read -r pkg ver; do
      [ -z "$pkg" ] && continue
      PKG_ESC=$(printf '%s' "$pkg" | sed 's/[].[\/*^$]/\\&/g')
      # yarn.lock format: "@scope/name@^1.2.3, @scope/name@1.2.3:" followed by "  version \"x.y.z\""
      if grep -q "\"$PKG_ESC@" "$lockfile" 2>/dev/null || \
         grep -q "^${PKG_ESC}@" "$lockfile" 2>/dev/null; then
        FOUND_VER=$(grep -A 10 "\"*${PKG_ESC}@\|^${PKG_ESC}@" "$lockfile" 2>/dev/null | \
          grep -m1 'version ' | sed 's/.*version[[:space:]]*"\([^"]*\)".*/\1/; s/.*version[[:space:]]\([^[:space:]]*\).*/\1/')
        if [ "$FOUND_VER" = "$ver" ]; then
          LINE=$(grep -n "\"*${PKG_ESC}@\|^${PKG_ESC}@" "$lockfile" 2>/dev/null | head -1 | cut -d: -f1)
          critical "yarn.lock exact match: ${WHITE}${pkg}@${ver}${NC}"
          echo -e "             File: $(loc "$lockfile" "$LINE")"
        fi
      fi
    done < "$PAIRS_FILE"
  done

# ---- pnpm-lock.yaml ----
echo -e "  ${DIM}Scanning pnpm-lock.yaml files...${NC}"

find "$SCAN_DIR" -name "pnpm-lock.yaml" \
  -not -path '*/node_modules/*' \
  -print0 2>/dev/null | \
  while IFS= read -r -d '' lockfile; do
    while IFS=$'\t' read -r pkg ver; do
      [ -z "$pkg" ] && continue
      PKG_ESC=$(printf '%s' "$pkg" | sed 's/[].[\/*^$]/\\&/g')
      if grep -q "${PKG_ESC}" "$lockfile" 2>/dev/null; then
        # pnpm-lock.yaml v6+: "  /@scope/name@1.2.3:" or "/name@1.2.3:"
        if grep -qE "[[:space:]]/?\"?${PKG_ESC}@${ver}[\":]" "$lockfile" 2>/dev/null; then
          LINE=$(grep -nE "[[:space:]]/?\"?${PKG_ESC}@${ver}[\":]" "$lockfile" 2>/dev/null | head -1 | cut -d: -f1)
          critical "pnpm-lock.yaml exact match: ${WHITE}${pkg}@${ver}${NC}"
          echo -e "             File: $(loc "$lockfile" "$LINE")"
        fi
      fi
    done < "$PAIRS_FILE"
  done

# -------------------------------------------------------
# §2  Local scan — PyPI manifests
# (Only run if unscoped packages exist in the CSV — they may overlap
#  with PyPI names. This is a best-effort scan, not authoritative.)
# -------------------------------------------------------
if [ "$PYPI_COUNT" -gt 0 ]; then
  section "[2/3] Local PyPI Manifest Scan"
  describe \
    "Scans requirements.txt, poetry.lock, and Pipfile.lock for unscoped package names from the CSV that could be PyPI packages. Most Mini Shai-Hulud packages are npm; this is a supplementary check for any PyPI overlap." \
    "For CRITICAL: remove the package from your requirements, recreate your virtual environment. For REVIEW: verify the package name is genuinely PyPI — the overlap with npm names may be coincidental."

  PYPI_PAIRS=$(awk -F'\t' '$1 !~ /^@/ && $1 !~ /\// {print}' "$PAIRS_FILE")

  # ---- requirements.txt ----
  echo -e "  ${DIM}Scanning requirements.txt files...${NC}"
  find "$SCAN_DIR" -name "requirements*.txt" \
    -not -path '*/node_modules/*' \
    -print0 2>/dev/null | \
    while IFS= read -r -d '' reqfile; do
      echo "$PYPI_PAIRS" | while IFS=$'\t' read -r pkg ver; do
        [ -z "$pkg" ] && continue
        PKG_ESC=$(printf '%s' "$pkg" | sed 's/[].[\/*^$]/\\&/g')
        # requirements.txt: pkg==ver  or pkg>=ver,<ver2
        EXACT_LINE=$(grep -niE "^${PKG_ESC}[[:space:]]*==[[:space:]]*${ver//./\\.}([[:space:],;#]|$)" "$reqfile" 2>/dev/null | head -1)
        if [ -n "$EXACT_LINE" ]; then
          LINE=$(echo "$EXACT_LINE" | cut -d: -f1)
          critical "requirements.txt exact: ${WHITE}${pkg}==${ver}${NC}"
          echo -e "             File: $(loc "$reqfile" "$LINE")"
        else
          RANGE_LINE=$(grep -niE "^${PKG_ESC}[[:space:]]*[><=!~]" "$reqfile" 2>/dev/null | head -1)
          if [ -n "$RANGE_LINE" ]; then
            LINE=$(echo "$RANGE_LINE" | cut -d: -f1)
            review "${WHITE}${pkg}${NC} version constraint may include affected ${ver}"
            echo -e "             File: $(loc "$reqfile" "$LINE")"
          fi
        fi
      done
    done

  # ---- poetry.lock ----
  echo -e "  ${DIM}Scanning poetry.lock files...${NC}"
  find "$SCAN_DIR" -name "poetry.lock" \
    -not -path '*/node_modules/*' \
    -print0 2>/dev/null | \
    while IFS= read -r -d '' lockfile; do
      echo "$PYPI_PAIRS" | while IFS=$'\t' read -r pkg ver; do
        [ -z "$pkg" ] && continue
        PKG_ESC=$(printf '%s' "$pkg" | sed 's/[].[\/*^$]/\\&/g')
        # poetry.lock: [[package]]\nname = "pkg"\nversion = "ver"
        if grep -qi "^name = \"${PKG_ESC}\"" "$lockfile" 2>/dev/null; then
          FOUND_VER=$(grep -A 5 -i "^name = \"${PKG_ESC}\"" "$lockfile" 2>/dev/null | \
            grep -i "^version" | head -1 | sed 's/.*= *"\([^"]*\)".*/\1/')
          if [ "$FOUND_VER" = "$ver" ]; then
            LINE=$(grep -ni "^name = \"${PKG_ESC}\"" "$lockfile" 2>/dev/null | head -1 | cut -d: -f1)
            critical "poetry.lock exact: ${WHITE}${pkg}@${ver}${NC}"
            echo -e "             File: $(loc "$lockfile" "$LINE")"
          fi
        fi
      done
    done

  # ---- Pipfile.lock ----
  echo -e "  ${DIM}Scanning Pipfile.lock files...${NC}"
  find "$SCAN_DIR" -name "Pipfile.lock" \
    -not -path '*/node_modules/*' \
    -print0 2>/dev/null | \
    while IFS= read -r -d '' lockfile; do
      echo "$PYPI_PAIRS" | while IFS=$'\t' read -r pkg ver; do
        [ -z "$pkg" ] && continue
        PKG_ESC=$(printf '%s' "$pkg" | sed 's/[].[\/*^$]/\\&/g')
        if grep -qi "\"${PKG_ESC}\"" "$lockfile" 2>/dev/null; then
          FOUND_VER=$(grep -A 5 -i "\"${PKG_ESC}\"" "$lockfile" 2>/dev/null | \
            grep '"version"' | head -1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"==\?\([^"]*\)".*/\1/')
          if [ "$FOUND_VER" = "$ver" ]; then
            LINE=$(grep -ni "\"${PKG_ESC}\"" "$lockfile" 2>/dev/null | head -1 | cut -d: -f1)
            critical "Pipfile.lock exact: ${WHITE}${pkg}@${ver}${NC}"
            echo -e "             File: $(loc "$lockfile" "$LINE")"
          fi
        fi
      done
    done
fi

AFTER_LOCAL=$(wc -l < "$FLOG" | tr -d ' ')
[ "$BEFORE_LOCAL" = "$AFTER_LOCAL" ] && ok "No affected packages found in local project"

# -------------------------------------------------------
# §3  GitHub repository scan
# -------------------------------------------------------
section "[3/3] GitHub Repository Scan"
describe \
  "Uses the gh CLI to search your GitHub repos for lockfiles referencing affected packages, then validates exact version via the dependency-graph SBOM API. Rate-limited — batched with sleep between requests." \
  "For CRITICAL: update the dependency in that repository, re-lock, and push. For REVIEW: inspect the lockfile in the repo manually to confirm the version. Run this scanner again after remediation to verify."

BEFORE_GH=$(wc -l < "$FLOG" | tr -d ' ')

GH_OK=0
if ! command -v gh >/dev/null 2>&1; then
  echo -e "  ${DIM}gh CLI not found — install from https://cli.github.com and run 'gh auth login'${NC}"
  echo -e "  ${DIM}GitHub scan skipped.${NC}"
elif ! gh auth status >/dev/null 2>&1; then
  echo -e "  ${DIM}gh CLI is not authenticated — run 'gh auth login' and retry.${NC}"
  echo -e "  ${DIM}GitHub scan skipped.${NC}"
else
  GH_OK=1
fi

if [ "$GH_OK" = "1" ]; then
  # Discover GitHub user
  GH_USER=$(gh api /user --jq '.login' 2>/dev/null)
  if [ -z "$GH_USER" ]; then
    echo -e "  ${DIM}Could not determine GitHub username — GitHub scan skipped.${NC}"
    GH_OK=0
  else
    echo -e "  GitHub user: ${WHITE}${GH_USER}${NC}"
    echo ""
  fi
fi

if [ "$GH_OK" = "1" ]; then
  # We scan in batches to stay within GitHub code-search rate limits
  # (10 authenticated requests/minute). Sleep 7s between requests; for
  # large CSV sets this will be slow — that is intentional.
  GH_BATCH_SIZE=5
  GH_SLEEP=7        # seconds between code-search API calls
  GH_COUNT=0

  # Track repos already confirmed critical to avoid SBOM re-fetch
  CONFIRMED_REPOS=$(mktemp)

  while IFS=$'\t' read -r pkg ver; do
    [ -z "$pkg" ] && continue

    GH_COUNT=$((GH_COUNT + 1))

    # Throttle every batch
    if [ $((GH_COUNT % GH_BATCH_SIZE)) -eq 0 ]; then
      echo -e "  ${DIM}[rate-limit pause ${GH_SLEEP}s — processed ${GH_COUNT}/${PAIR_COUNT} packages]${NC}"
      sleep "$GH_SLEEP"
    fi

    # Encode the query string for the API URL
    # Search across the three main lockfile types
    for lockfilename in "package-lock.json" "yarn.lock" "pnpm-lock.yaml"; do
      QUERY=$(printf '%s in:file filename:%s user:%s' "$pkg" "$lockfilename" "$GH_USER" | \
        sed 's/ /%20/g; s/"/%22/g; s/@/%40/g; s/\//%2F/g')

      SEARCH_RESULT=$(gh api \
        "/search/code?q=${QUERY}&per_page=5" \
        --jq '.items[].repository.full_name' 2>/dev/null) || continue

      [ -z "$SEARCH_RESULT" ] && continue

      echo "$SEARCH_RESULT" | while read -r repo; do
        [ -z "$repo" ] && continue
        # Guard: repo must look like "owner/name" — skip error JSON blobs
        case "$repo" in
          */*) ;;
          *) continue ;;
        esac

        # Check if we already confirmed CRITICAL for this repo
        if grep -qxF "$repo" "$CONFIRMED_REPOS" 2>/dev/null; then
          continue
        fi

        # Fetch the dependency-graph SBOM and check for exact version
        SBOM_RESULT=$(gh api "/repos/${repo}/dependency-graph/sbom" 2>/dev/null) || true
        # Validate SBOM response looks like actual JSON (starts with '{')
        case "${SBOM_RESULT# }" in
          \{*) ;;
          *) SBOM_RESULT="" ;;
        esac
        if [ -n "$SBOM_RESULT" ]; then
          # Look for the package name in SBOM packages array
          if command -v jq >/dev/null 2>&1; then
            SBOM_VER=$(echo "$SBOM_RESULT" | jq -r \
              --arg pkg "$pkg" \
              '.sbom.packages[]? | select(.name == $pkg or .name == ("pkg:" + $pkg) or (.name | endswith("/" + $pkg))) | .versionInfo' \
              2>/dev/null | head -1)
          else
            # Fallback: grep for package name then grab versionInfo nearby
            SBOM_VER=$(echo "$SBOM_RESULT" | \
              grep -A 3 "\"${pkg}\"" 2>/dev/null | \
              grep "versionInfo" | head -1 | \
              sed 's/.*"versionInfo"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
          fi

          if [ "$SBOM_VER" = "$ver" ]; then
            critical "GitHub SBOM exact match: ${WHITE}${pkg}@${ver}${NC} in ${WHITE}${repo}${NC}"
            echo "$repo" >> "$CONFIRMED_REPOS"
          elif [ -n "$SBOM_VER" ]; then
            review "${WHITE}${pkg}${NC} found in ${WHITE}${repo}${NC} (SBOM ver: ${SBOM_VER}, affected: ${ver})"
          else
            # Package name appeared in code search but not resolved in SBOM
            review "${WHITE}${pkg}${NC} reference in ${WHITE}${repo}${NC}/${lockfilename} — version unconfirmed"
          fi
        else
          # SBOM unavailable (private repo, dependency-graph disabled, or no graph)
          review "${WHITE}${pkg}${NC} in ${WHITE}${repo}${NC}/${lockfilename} — SBOM unavailable, inspect manually"
        fi
      done
    done

  done < "$PAIRS_FILE"

  rm -f "$CONFIRMED_REPOS"
fi

AFTER_GH=$(wc -l < "$FLOG" | tr -d ' ')
[ "$BEFORE_GH" = "$AFTER_GH" ] && ok "No affected packages found in GitHub repositories"

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
echo ""
echo -e "${DIM}  ════════════════════════════════════════════════════════${NC}"

TOTAL_C=$(grep -c '^C$' "$FLOG" 2>/dev/null); TOTAL_C="${TOTAL_C:-0}"
TOTAL_W=$(grep -c '^W$' "$FLOG" 2>/dev/null); TOTAL_W="${TOTAL_W:-0}"
TOTAL_R=$(grep -c '^R$' "$FLOG" 2>/dev/null); TOTAL_R="${TOTAL_R:-0}"
TOTAL=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
TOTAL=${TOTAL:-0}
rm -f "$FLOG" "$PAIRS_FILE"

echo ""
echo -e "  Findings:  ${RED}[CRITICAL] ${TOTAL_C}${NC}  ${YELLOW}[WARNING] ${TOTAL_W}${NC}  ${CYAN}[REVIEW] ${TOTAL_R}${NC}"
echo ""

if [ "$TOTAL" -eq 0 ]; then
  echo -e "  ${GREEN}╔════════════════════════════════════════════════╗${NC}"
  echo -e "  ${GREEN}║   CLEAN — No affected packages detected        ║${NC}"
  echo -e "  ${GREEN}╚════════════════════════════════════════════════╝${NC}"
  [ -n "$REPORT_FILE" ] && echo -e "  Report saved: ${WHITE}${REPORT_FILE}${NC}"
  echo ""
  EXIT_CODE=0
else
  echo -e "  ${RED}╔════════════════════════════════════════════════╗${NC}"
  printf  "  ${RED}║  ALERT — %-3s finding(s) detected               ║${NC}\n" "$TOTAL"
  echo -e "  ${RED}║   Review the output above for details          ║${NC}"
  echo -e "  ${RED}╚════════════════════════════════════════════════╝${NC}"
  [ -n "$REPORT_FILE" ] && echo -e "  Report saved: ${WHITE}${REPORT_FILE}${NC}"
  echo ""
  EXIT_CODE=1
fi

# Allow tee subprocess to drain before exit
exec >&- 2>&-
sleep 0.2 2>/dev/null
exit "$EXIT_CODE"
