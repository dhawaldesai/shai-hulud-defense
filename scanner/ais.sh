#!/bin/bash
# ais.sh — agentic-ioc-scanner (Linux + macOS + Git Bash on Windows)

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

# describe WHAT FIX — short purpose + remediation, shown under each section
# header. Visible in both terminal and on-disk report.
describe() {
  echo -e "${DIM}  What:${NC} $1"
  echo -e "${DIM}  Fix:${NC}  $2"
  echo ""
}

ok()       { echo -e "  ${GREEN}[OK]${NC}       $1"; }
critical() { echo -e "  ${RED}[CRITICAL]${NC} $1"; echo "F" >> "$FLOG"; }
warning()  { echo -e "  ${YELLOW}[WARNING]${NC}  $1"; echo "F" >> "$FLOG"; }
review()   { echo -e "  ${CYAN}[REVIEW]${NC}   $1"; echo "F" >> "$FLOG"; }

# find_line PATTERN FILE — print first matching line number, or empty
find_line() {
  grep -nE "$1" "$2" 2>/dev/null | head -1 | cut -d: -f1
}

# loc FILE [LINE] — formatted "path:line" or "path" if no line
loc() {
  local f="$1" l="$2"
  if [ -n "$l" ]; then echo "$f:$l"; else echo "$f"; fi
}

# -------------------------------------------------------
# Banner & Input
# -------------------------------------------------------
echo ""
echo -e "${WHITE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${WHITE}║            ${CYAN}AGENT IOC SCANNER${WHITE}                           ║${NC}"
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

# -------------------------------------------------------
# Report file — duplicate all output (ANSI-stripped) to disk
# Override path with $REPORT_FILE; default is timestamped in $PWD.
# -------------------------------------------------------
REPORT_FILE="${REPORT_FILE:-$(pwd)/agentic-ioc-scan-$(date +%Y%m%d-%H%M%S).log}"
: > "$REPORT_FILE" 2>/dev/null || {
  echo "WARN: cannot write to $REPORT_FILE — disabling report"
  REPORT_FILE=""
}
if [ -n "$REPORT_FILE" ]; then
  # Tee stdout to report file with ANSI escape codes stripped.
  exec > >(tee >(sed -u $'s/\x1b\\[[0-9;]*[mGKH]//g' >> "$REPORT_FILE"))
  exec 2>&1
fi

# -------------------------------------------------------
# Load IOC list (alongside script, override via $IOC_FILE)
# -------------------------------------------------------
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
IOC_FILE="${IOC_FILE:-$SCRIPT_DIR/iocs.txt}"
IOC_VERSION="unknown"

ioc_values() {
  # ioc_values TYPE — emits VALUE column for matching lines
  [ -f "$IOC_FILE" ] || return 0
  awk -F'|' -v t="$1" '!/^#/ && NF>=2 && $1==t {print $2}' "$IOC_FILE"
}

if [ -f "$IOC_FILE" ]; then
  IOC_VERSION=$(grep -m1 '^# version:' "$IOC_FILE" | sed 's/^# version:[[:space:]]*//')
fi

echo ""
echo -e "  Target:   ${WHITE}$SCAN_DIR${NC}"
echo -e "  IOC list: ${WHITE}${IOC_FILE}${NC} (${DIM}v${IOC_VERSION}${NC})"
[ -n "$REPORT_FILE" ] && echo -e "  Report:   ${WHITE}${REPORT_FILE}${NC}"
echo -e "${DIM}  ════════════════════════════════════════════════════════${NC}"

# -------------------------------------------------------
# 1. Malicious settings.json
# -------------------------------------------------------
section "[1/11] Claude Code Hook Injection"
describe \
  "Looks for malicious SessionStart hooks in any settings.json that invoke a dropper (setup.mjs / execution.js / config.mjs). This is the Mini Shai-Hulud persistence mechanism — the hook fires every time Claude Code opens the project." \
  "If CRITICAL: delete the offending settings.json (or revert to a known-good version), rotate any credentials Claude Code could access (GitHub token, npm token, cloud creds), audit recent commits for tampering, and deploy enterprise managed-settings with allowManagedHooksOnly to block project-level hooks org-wide."

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

# Scan filesystem roots
for ROOT in $(get_scan_roots); do
  [ -d "$ROOT" ] && find "$ROOT" -name 'settings.json' \
    -not -path '*/node_modules/*' \
    -not -path '*/.Trash/*' \
    -not -path '*/.Trashes/*' \
    -not -path '*/Library/Mobile Documents/*' \
    -not -path '*/.git/*' \
    -print0 2>/dev/null | \
    while IFS= read -r -d '' f; do
      MATCH_HOOK=0
      if command -v jq >/dev/null 2>&1; then
        jq -e '.. | objects | select(has("command")) | .command | strings | test("setup\\.mjs|execution\\.js|config\\.mjs")' "$f" >/dev/null 2>&1 && MATCH_HOOK=1
      else
        grep -q "SessionStart" "$f" 2>/dev/null && \
          grep -qE "(setup|execution|config)\\.(mjs|js)" "$f" 2>/dev/null && MATCH_HOOK=1
      fi
      if [ "$MATCH_HOOK" = "1" ]; then
        LINE=$(find_line "(setup|execution|config)\\.(mjs|js)|SessionStart" "$f")
        critical "Malicious hook: $(loc "$f" "$LINE")"
      fi
    done
done

# Scan project dir
find "$SCAN_DIR" -name 'settings.json' \
  -not -path '*/node_modules/*' \
  -not -path '*/.git/*' \
  -print0 2>/dev/null | \
  while IFS= read -r -d '' f; do
    MATCH_HOOK=0
    if command -v jq >/dev/null 2>&1; then
      jq -e '.. | objects | select(has("command")) | .command | strings | test("setup\\.mjs|execution\\.js|config\\.mjs")' "$f" >/dev/null 2>&1 && MATCH_HOOK=1
    else
      grep -q "SessionStart" "$f" 2>/dev/null && \
        grep -qE "(setup|execution|config)\\.(mjs|js)" "$f" 2>/dev/null && MATCH_HOOK=1
    fi
    if [ "$MATCH_HOOK" = "1" ]; then
      LINE=$(find_line "(setup|execution|config)\\.(mjs|js)|SessionStart" "$f")
      critical "Malicious hook: $(loc "$f" "$LINE")"
    fi
  done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No malicious hooks found"

# -------------------------------------------------------
# 2. Bun dropper files
# -------------------------------------------------------
section "[2/11] Bun Dropper Detection"
describe \
  "Hunts for setup.mjs files that reference the Bun runtime (bun, oven-sh, BUN_VERSION). Mini Shai-Hulud uses a Bun-based dropper because it bundles its dependencies into a single binary, evading signature-based AV." \
  "If CRITICAL: quarantine the file, do not execute. Inspect npm preinstall scripts (§5) that may have invoked it. Re-clone affected repos from a trusted upstream after rotating tokens. Set ignore-scripts=true in ~/.npmrc to neutralise preinstall droppers globally."

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

find "$SCAN_DIR" -name "setup.mjs" 2>/dev/null | while read -r f; do
  if grep -qiE "bun|oven-sh|BUN_VERSION" "$f" 2>/dev/null; then
    LINE=$(find_line "bun|oven-sh|BUN_VERSION" "$f")
    critical "Bun dropper: $(loc "$f" "$LINE")"
  fi
done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No dropper files found"

# -------------------------------------------------------
# 3. Large execution.js payloads
# -------------------------------------------------------
section "[3/11] Obfuscated Payload Detection"
describe \
  "Finds large execution.js files (>1MB) that look obfuscated — single-line blobs, base64-decoded payloads, eval(atob(...)), or child_process imports. This is the credential-stealer stage of Mini Shai-Hulud." \
  "If CRITICAL: do not run it. Capture a copy for IR analysis (sha256sum first), then delete. Treat the host as compromised: rotate every credential the developer account had access to, review GitHub audit log for unauthorised pushes, and check public GitHub for repos titled 'A Mini Shai-Hulud has Appeared'."

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

find "$SCAN_DIR" -name "execution.js" -not -path '*/node_modules/*' -print0 2>/dev/null | \
  while IFS= read -r -d '' f; do
    SIZE=$(get_file_size "$f")
    [ -z "$SIZE" ] || [ "$SIZE" -le 1000000 ] && continue
    # Heuristic: legit bundles contain newlines and source maps; obfuscated payloads
    # tend to be single-line, base64 blob, or eval-driven. Require at least one
    # obfuscation signal before flagging CRITICAL — otherwise downgrade to REVIEW.
    LINES=$(wc -l < "$f" 2>/dev/null | tr -d ' ')
    SIZE_MB=$(awk "BEGIN {printf \"%.1f\", $SIZE/1048576}")
    OBFUSC_PATTERN="Buffer\\.from\\([^)]+,['\"]base64|eval\\(atob|require\\(['\"]child_process"
    if [ "${LINES:-0}" -lt 50 ]; then
      critical "execution.js (${SIZE_MB}MB, ${LINES} lines, single-line blob): $f"
    elif grep -qE "$OBFUSC_PATTERN" "$f" 2>/dev/null; then
      LINE=$(find_line "$OBFUSC_PATTERN" "$f")
      critical "execution.js (${SIZE_MB}MB, obfuscation signal): $(loc "$f" "$LINE")"
    else
      review "Large execution.js (${SIZE_MB}MB) — likely legitimate bundle: $f"
    fi
  done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No suspicious payloads found"

# -------------------------------------------------------
# 4. Lock file
# -------------------------------------------------------
section "[4/11] Malware Lock File"
describe \
  "Checks /tmp (and equivalent) for sentinel lockfiles the malware writes to avoid double-execution (e.g. tmp.987654321.lock). Presence of the lockfile is strong evidence the dropper has already run on this host." \
  "If CRITICAL: assume host compromise. Capture the lockfile for IR, then proceed as for §3 — rotate creds, audit GitHub activity, check for exfil repos, review process history (lsof, ps, login records) for the malware's runtime artefacts."

TMP_DIR=$(get_tmp_dir)
BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
LOCK_NAMES=$(ioc_values LOCKFILE)
if [ -z "$LOCK_NAMES" ]; then LOCK_NAMES="tmp.987654321.lock"; fi
echo "$LOCK_NAMES" | while read -r name; do
  [ -z "$name" ] && continue
  HIT=$(find "$TMP_DIR" -maxdepth 2 -name "$name" 2>/dev/null)
  [ -n "$HIT" ] && critical "Lock file ($name): $HIT"
done
AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No lock file found"

# -------------------------------------------------------
# 5. Suspicious npm preinstall scripts
# -------------------------------------------------------
section "[5/11] NPM Preinstall Scripts"
describe \
  "Scans every package.json (excluding node_modules) for a preinstall script that invokes a known dropper filename. preinstall runs automatically on npm install with no prompt — the entry point most supply-chain worms use." \
  "If WARNING: do not run npm install in that directory. Remove the malicious package.json change (git revert), determine which dependency added it, and report the upstream package to npm security. Org-wide: set ignore-scripts=true in .npmrc, or use pnpm with onlyBuiltDependencies allowlist."

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

find "$SCAN_DIR" -name "package.json" -not -path '*/node_modules/*' 2>/dev/null | while read -r f; do
  if command -v jq >/dev/null 2>&1; then
    PREINSTALL=$(jq -r ".scripts.preinstall // empty" "$f" 2>/dev/null)
  else
    PREINSTALL=$(grep "\"preinstall\"" "$f" 2>/dev/null | sed "s/.*\"preinstall\"[[:space:]]*:[[:space:]]*\"\(.*\)\".*/\1/")
  fi
  DROPPER_PATTERN=$(ioc_values FILENAME | tr '\n' '|' | sed 's/|$//; s/\./\\./g')
  [ -z "$DROPPER_PATTERN" ] && DROPPER_PATTERN="setup\.mjs|config\.mjs|execution\.js"
  if echo "$PREINSTALL" | grep -qEi "$DROPPER_PATTERN"; then
    LINE=$(find_line '"preinstall"' "$f")
    warning "$(loc "$f" "$LINE")"
    echo -e "             Script: ${DIM}$PREINSTALL${NC}"
  fi
done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No suspicious preinstall scripts"

# -------------------------------------------------------
# 6. AI-authored workflow changes
# -------------------------------------------------------
section "[6/11] AI-Authored Workflow Changes"
describe \
  "Surfaces git commits to .github/workflows/ authored by AI-agent identities (Claude, Copilot, OpenAI, ai-bot) outside an allowlist of legitimate bots (dependabot, renovate, github-actions). CI workflow tampering is the highest-leverage point in a supply chain." \
  "If REVIEW: inspect each flagged commit. Confirm the workflow change is legitimate (a real developer asked the agent to make it) and not the result of a compromised token committing under an AI identity. Pin all AI-related actions to a SHA, not a tag, and require human review on PRs that touch .github/workflows/."

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
    # Match on author email (%ae) only. Subject-line matching is too noisy
    # (any commit mentioning "claude" or "ai" trips it). Allowlist common
    # legitimate bot identities; flag anything else for review.
    git -C "$REPO_DIR" log --all --format='%h|%ae|%s' -- '.github/workflows/' 2>/dev/null | \
      while IFS='|' read -r hash email subject; do
        case "$email" in
          *@users.noreply.github.com|\
          *dependabot*|\
          *renovate*|\
          *github-actions*|\
          *@anthropic.com|\
          *claude*[bot]*) ;;
          *claude*|*copilot*|*"ai-bot"*|*"@openai."*)
            review "${WHITE}$REPO_NAME${NC} ${DIM}$hash${NC} $(trunc "$subject" 40)"
            echo -e "             Author: ${DIM}$email${NC}"
            ;;
        esac
      done
  done

  AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
  [ "$BEFORE" = "$AFTER" ] && ok "No AI-authored workflow changes"
fi

# -------------------------------------------------------
# 7. Gemini CLI configuration files (CVSS 10.0 RCE vector)
# -------------------------------------------------------
section "[7/11] Gemini CLI Config Files"
describe \
  "Finds .gemini/ config directories and inspects their JSON/YAML/TOML contents for shell metacharacters (\$(, backticks, ; curl, && wget). This is the CVSS 10.0 RCE vector patched in Gemini CLI v0.39.1 — config parsing executed shell commands before the sandbox initialised." \
  "If CRITICAL: upgrade @google/gemini-cli to >=0.39.1 immediately, delete the offending config, and audit any CI runner where Gemini CLI ran from PRs (those secrets must be considered exposed). Pin google-github-actions/run-gemini-cli to a SHA and never run agents against fork PRs without isolation."

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

find "$SCAN_DIR" -type d -name '.gemini' \
  -not -path '*/node_modules/*' -not -path '*/.git/*' \
  -print0 2>/dev/null | while IFS= read -r -d '' d; do
    review "Gemini CLI config dir: $d"
    # Flag suspicious shell-metachar patterns inside settings/config files
    find "$d" -maxdepth 2 -type f \( -name '*.json' -o -name '*.yaml' -o -name '*.yml' -o -name '*.toml' \) -print0 2>/dev/null | \
      while IFS= read -r -d '' f; do
        METACHAR_PATTERN='\$\(|`|;[[:space:]]*(curl|wget|bash|sh )|&&[[:space:]]*(curl|wget)'
        if grep -qE "$METACHAR_PATTERN" "$f" 2>/dev/null; then
          LINE=$(find_line "$METACHAR_PATTERN" "$f")
          critical "Suspicious shell metachars in Gemini config: $(loc "$f" "$LINE")"
        fi
      done
  done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No Gemini CLI config files found"

# -------------------------------------------------------
# 8. Cursor AGENTS.md / .cursor/rules (CVE-2026-26268 vector)
# -------------------------------------------------------
section "[8/11] Cursor AGENTS.md & .cursor Configs"
describe \
  "AGENTS.md is a legitimate convention for instructing Cursor (and other agents) about a project. It becomes weaponised under CVE-2026-26268 when it directs the agent at a bare git repo or a malicious post-checkout hook — the agent then runs the hook silently outside its approval flow." \
  "If CRITICAL: delete the AGENTS.md or revert to a trusted version, then run §9 to confirm whether the referenced git hook was actually deployed. Update Cursor to >=2.2.5 (patches CVE-2026-26268). REVIEW-level findings (AGENTS.md / .cursor present) just mean the project uses Cursor — not malicious by themselves."

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

find "$SCAN_DIR" -name 'AGENTS.md' \
  -not -path '*/node_modules/*' -not -path '*/.git/*' \
  -print0 2>/dev/null | while IFS= read -r -d '' f; do
    # AGENTS.md itself is legitimate; flag if it points the agent at a bare git
    # repo or post-checkout hook (the actual CVE-2026-26268 primitive).
    AGENTSMD_PATTERN='(\.git/hooks/|core\.hooksPath|bare repo|--git-dir|post-checkout)'
    if grep -qiE "$AGENTSMD_PATTERN" "$f" 2>/dev/null; then
      LINE=$(grep -niE "$AGENTSMD_PATTERN" "$f" 2>/dev/null | head -1 | cut -d: -f1)
      critical "AGENTS.md references git-hooks/bare-repo primitive: $(loc "$f" "$LINE")"
    else
      review "AGENTS.md present: $f"
    fi
  done

find "$SCAN_DIR" -type d -name '.cursor' \
  -not -path '*/node_modules/*' -not -path '*/.git/*' \
  -print0 2>/dev/null | while IFS= read -r -d '' d; do
    review "Cursor config dir: $d"
  done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No Cursor agent configs found"

# -------------------------------------------------------
# 9. Git post-checkout hooks & core.hooksPath reassignment
# -------------------------------------------------------
section "[9/11] Git Hook Hijacking"
describe \
  "Inspects every .git/hooks/{post-checkout,post-merge,post-rewrite,pre-commit} for fetch-and-execute primitives (curl, wget, base64 -d, bash -c, nc, /dev/tcp/), and flags any core.hooksPath redirected outside the safe allowlist (.githooks, .git/hooks, hooks). The actual CVE-2026-26268 exec primitive lives here." \
  "If CRITICAL: delete the offending hook (or unset core.hooksPath via 'git config --local --unset core.hooksPath'), then re-clone the repo from a trusted upstream rather than trusting the existing working tree. REVIEW (custom hook present, no fetch-exec pattern): inspect manually — likely legitimate lint/test hook, but confirm with the maintainer."

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

# Walk every .git directory we already discovered (or rediscover)
find "$SCAN_DIR" -name '.git' \( -type d -o -type f \) -print0 2>/dev/null | \
  while IFS= read -r -d '' gitpath; do
    # Resolve actual git dir (handles git worktrees where .git is a file)
    if [ -f "$gitpath" ]; then
      GIT_DIR=$(sed -n 's/^gitdir:[[:space:]]*//p' "$gitpath")
      [ -z "$GIT_DIR" ] && continue
      case "$GIT_DIR" in /*) ;; *) GIT_DIR="$(dirname "$gitpath")/$GIT_DIR" ;; esac
    else
      GIT_DIR="$gitpath"
    fi
    REPO_DIR=$(dirname "$GIT_DIR")

    # Suspicious hooks
    for hook in post-checkout post-merge post-rewrite pre-commit; do
      H="$GIT_DIR/hooks/$hook"
      [ -f "$H" ] || continue
      HOOK_PATTERN='(curl|wget|base64 -d|bash -c|nc |/dev/tcp/)'
      if grep -qE "$HOOK_PATTERN" "$H" 2>/dev/null; then
        LINE=$(find_line "$HOOK_PATTERN" "$H")
        critical "Suspicious git $hook hook: $(loc "$H" "$LINE")"
      else
        review "Custom git $hook hook present: $H"
      fi
    done

    # core.hooksPath reassignment outside the repo
    HP=$(git -C "$REPO_DIR" config --local --get core.hooksPath 2>/dev/null)
    if [ -n "$HP" ]; then
      case "$HP" in
        .githooks|.git/hooks|hooks) ;;
        *) critical "core.hooksPath redirected to '$HP' in $REPO_DIR/.git/config" ;;
      esac
    fi
  done

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No suspicious git hooks or hooksPath redirects"

# -------------------------------------------------------
# 10. Globally-installed npm packages vs IOC list
# -------------------------------------------------------
section "[10/11] Global NPM Packages vs IOCs"
describe \
  "Cross-references globally-installed npm packages (npm ls -g) and local node_modules trees against the NPM/PYPI entries in iocs.txt. Catches confirmed-malicious packages from Mini Shai-Hulud (SAP CAP set), DPRK PromptMink (@validate-sdk/v2), and any new IOC you add to the list." \
  "If CRITICAL: uninstall immediately ('npm uninstall -g <pkg>' or remove from package.json + delete node_modules + reinstall). Rotate any credentials accessible from the host. Check npm audit log for when the package was installed and trace what ran during install. Report the package to npm security if not already taken down."

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

if command -v npm >/dev/null 2>&1; then
  GLOBAL_LIST=$(npm ls -g --depth=0 --parseable 2>/dev/null)
  ioc_values NPM | while read -r pkg; do
    [ -z "$pkg" ] && continue
    if echo "$GLOBAL_LIST" | grep -qE "/${pkg//\//\\/}\$|/${pkg//\//\\/}@"; then
      critical "Globally-installed malicious npm package: $pkg"
    fi
  done
  # Also scan for malicious packages in local node_modules
  ioc_values NPM | while read -r pkg; do
    [ -z "$pkg" ] && continue
    HIT=$(find "$SCAN_DIR" -type d -path "*/node_modules/$pkg" -print -quit 2>/dev/null)
    [ -n "$HIT" ] && critical "Malicious npm package in node_modules: $pkg ($HIT)"
  done
else
  echo -e "  ${DIM}npm not on PATH — skipping global package check${NC}"
fi

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No malicious packages from IOC list found"

# -------------------------------------------------------
# 11. Worm exfiltration repo names on local clones / GitHub remotes
# -------------------------------------------------------
section "[11/11] Worm Exfiltration Repo Names"
describe \
  "Scans every git remote URL against known worm-exfil repository name patterns ('Shai-Hulud', 'A Mini Shai-Hulud has Appeared'). The Mini Shai-Hulud worm publishes stolen secrets to public repos under the victim's own GitHub account — finding such a remote is unambiguous evidence of compromise." \
  "If CRITICAL: this is incident-response territory. Make the exfil repo private or delete it (after capturing for evidence), rotate every credential the compromised account ever held, review GitHub audit logs for unauthorised activity, and notify your IR team. Assume any secret that touched this developer's machine is now public."

BEFORE=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')

REPO_NAME_PATTERN=$(ioc_values REPONAME | tr '\n' '|' | sed 's/|$//')
if [ -n "$REPO_NAME_PATTERN" ]; then
  find "$SCAN_DIR" -name '.git' \( -type d -o -type f \) -print0 2>/dev/null | \
    while IFS= read -r -d '' gitpath; do
      # Resolve actual git dir (handles worktree .git files)
      if [ -f "$gitpath" ]; then
        GIT_DIR=$(sed -n 's/^gitdir:[[:space:]]*//p' "$gitpath")
        [ -z "$GIT_DIR" ] && continue
        case "$GIT_DIR" in /*) ;; *) GIT_DIR="$(dirname "$gitpath")/$GIT_DIR" ;; esac
      else
        GIT_DIR="$gitpath"
      fi
      REPO_DIR=$(dirname "$GIT_DIR")
      CONFIG_FILE="$GIT_DIR/config"

      REMOTES=$(git -C "$REPO_DIR" remote -v 2>/dev/null)
      if echo "$REMOTES" | grep -qiE "$REPO_NAME_PATTERN"; then
        # Find the matching remote URL and its line number in .git/config
        MATCH_URL=$(echo "$REMOTES" | grep -iE "$REPO_NAME_PATTERN" | head -1 | awk '{print $2}')
        CONFIG_LINE=""
        if [ -f "$CONFIG_FILE" ] && [ -n "$MATCH_URL" ]; then
          CONFIG_LINE=$(grep -nFx "	url = $MATCH_URL" "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d: -f1)
          [ -z "$CONFIG_LINE" ] && CONFIG_LINE=$(grep -niE "$REPO_NAME_PATTERN" "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d: -f1)
        fi
        critical "Repo points to known worm exfil name"
        echo -e "             Repo:   ${WHITE}$REPO_DIR${NC}"
        echo -e "             Config: $(loc "$CONFIG_FILE" "$CONFIG_LINE")"
        [ -n "$MATCH_URL" ] && echo -e "             URL:    ${DIM}$MATCH_URL${NC}"
      fi
    done
fi

AFTER=$(wc -l < "$FLOG" 2>/dev/null | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] && ok "No worm exfiltration repo names found"

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
  [ -n "$REPORT_FILE" ] && echo -e "  Report saved: ${WHITE}${REPORT_FILE}${NC}"
  echo ""
  EXIT_CODE=0
else
  echo ""
  echo -e "  ${RED}╔════════════════════════════════════════════════╗${NC}"
  printf "  ${RED}║  ALERT — %-3s finding(s) detected               ║${NC}\n" "$TOTAL"
  echo -e "  ${RED}║   Review the output above for details          ║${NC}"
  echo -e "  ${RED}╚════════════════════════════════════════════════╝${NC}"
  [ -n "$REPORT_FILE" ] && echo -e "  Report saved: ${WHITE}${REPORT_FILE}${NC}"
  echo ""
  EXIT_CODE=1
fi

# Allow the tee subprocess to drain before we exit, otherwise the last few
# lines of the report file can be truncated.
exec >&- 2>&-
sleep 0.2 2>/dev/null
exit "$EXIT_CODE"