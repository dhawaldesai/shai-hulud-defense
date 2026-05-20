# agentic-ioc-scanner

> IOC scanner for agentic AI coding tools — detects Mini Shai-Hulud, Gemini CLI RCE, Cursor CVE-2026-26268, and DPRK PromptMink.

A detection kit for compromise of agentic AI coding assistants (Claude Code, Gemini CLI, Cursor) and the dependencies they pull into your repos. Eleven checks across hook injection, RCE configs, malicious dependencies, git-hook backdoors, and CI workflow tampering. IOC list is externalised — adding new indicators requires no code changes.

Companion blog post: [When the Tool Fights Back](https://cisomandate.com/when-the-tool-fights-back-three-ways-ai-coding-assistants-have-become-an-attack-surface/).

## What's Included

### 1. IOC Scanner (`scanner/ais.sh`)

Eleven checks, each with an inline `What:` (purpose) and `Fix:` (remediation) printed under the section header so the report is self-explanatory. IOC list lives in `scanner/iocs.txt` (versioned; override with `IOC_FILE=/path/to/iocs.txt`).

| §  | Check | Threat covered |
|---:|-------|----------------|
|  1 | Claude Code `SessionStart` hook injection in any `settings.json` (jq-based, low-FP) | Mini Shai-Hulud persistence |
|  2 | Bun-runtime dropper signatures in `setup.mjs` | Mini Shai-Hulud install stage |
|  3 | Obfuscated `execution.js` payloads — size **plus** obfuscation signal (single-line, base64, `eval(atob(`, `child_process`) | Mini Shai-Hulud credential stealer |
|  4 | Malware lock files in `$TMPDIR` (names sourced from IOC list) | Mini Shai-Hulud sentinel |
|  5 | `package.json` `preinstall` scripts referencing dropper filenames | Generic supply-chain worm entry point |
|  6 | AI-authored commits touching `.github/workflows/` (email-allowlist filter) | CI tampering by compromised AI-agent identity |
|  7 | `.gemini/` config files with shell-metachar patterns | Gemini CLI CVSS 10.0 RCE (pre-`v0.39.1`) |
|  8 | Cursor `AGENTS.md` and `.cursor/` configs referencing git hooks / bare repos | Cursor CVE-2026-26268 |
|  9 | Git `post-checkout` / `post-merge` / `post-rewrite` / `pre-commit` hooks containing fetch-and-execute primitives, plus `core.hooksPath` redirected outside the safe allowlist | CVE-2026-26268 exec primitive + generic hook hijacking |
| 10 | Globally-installed and local `node_modules` packages cross-referenced against the IOC list | Mini Shai-Hulud SAP CAP set, DPRK PromptMink, future bad packages |
| 11 | Git remotes matching known worm exfiltration repo names (`Shai-Hulud`, `A Mini Shai-Hulud has Appeared`) | Confirmed-compromise signal |

**Usage:**
```bash
bash scanner/ais.sh
# Enter your project folder when prompted

# Custom IOC list:
IOC_FILE=./my-iocs.txt bash scanner/ais.sh

# Custom report path (default: ./agentic-ioc-scan-YYYYMMDD-HHMMSS.log):
REPORT_FILE=/var/log/agentic-scan.log bash scanner/ais.sh
```

**Output**

- Findings stream to the terminal (colourised) **and** to a plain-text report file (`agentic-ioc-scan-YYYYMMDD-HHMMSS.log` by default, ANSI-stripped via `tee` → `sed`).
- Severity tags: `[CRITICAL]` (act now), `[WARNING]` (likely malicious — verify), `[REVIEW]` (legitimate use possible — confirm), `[OK]` (clean).
- File-content findings include the **line number** where the indicator was found (`path:line` form). Sections that surface line numbers: §1 hook, §2 Bun signature, §3 obfuscation signal, §5 preinstall key, §7 Gemini metachar, §8 AGENTS.md git-hook reference, §9 suspicious hook contents.
- The §11 worm-remote finding additionally reports the offending **`.git/config` line** plus the matching remote URL, so you can jump straight to the entry that needs removing.
- `core.hooksPath` redirection (§9) reports the absolute path to the repo's `.git/config` so the reassignment is auditable.
- Worktree-aware: when a `.git` is a file (containing `gitdir: …`), the actual git directory is resolved before inspection.

**Sample finding**
```
[CRITICAL] Repo points to known worm exfil name
           Repo:   /home/dev/projects/myrepo
           Config: /home/dev/projects/myrepo/.git/config:9
           URL:    https://github.com/dhawaldesai/A-Mini-Shai-Hulud-has-Appeared

[CRITICAL] Malicious hook: /home/dev/projects/myrepo/.claude/settings.json:3
[CRITICAL] Suspicious git post-checkout hook: /home/dev/projects/myrepo/.git/hooks/post-checkout:2
```

**Updating IOCs**

Edit `scanner/iocs.txt` and bump the `# version:` header. Format is `TYPE|VALUE|NOTES`. Supported types:

| Type | Used by | Example |
|------|---------|---------|
| `FILENAME` | §5 preinstall pattern | `setup.mjs` |
| `LOCKFILE` | §4 lock-file scan | `tmp.987654321.lock` |
| `NPM` | §10 global + local package scan | `@validate-sdk/v2` |
| `PYPI` | §10 (cross-checked when a PyPI scanner is added) | `lightning` |
| `HOOKSTRING` | §1 hook content match (currently inline-coded) | `SessionStart` |
| `REPONAME` | §11 git-remote match | `A Mini Shai-Hulud has Appeared` |
| `EMAILSUBSTRING` | reserved for future commit-author IOC matching | — |
| `CONFIGPATH` | reference list of agentic-tool config paths | `.claude/settings.json` |

No code change is required when new IOCs surface — the scanner reads them at startup and prints the loaded version in the banner.

**Dependencies**

Required: `bash`, `find`, `grep`, `awk`, `sed`, `git`. Optional: `jq` (preferred for §1 — falls back to grep heuristic if absent), `npm` (required for §10 global package check; section is skipped silently if unavailable).


### 2. Affected-Package Version Scanner (`scanner/pkg_version_check.sh`)

Companion to the IOC scanner. Reads a CSV of affected `package,version` pairs (e.g. the Mini Shai-Hulud IOC feed at `~/Downloads/Mini Shai-Hulud - Sheet1.csv` — 633 npm package/version pairs) and checks whether they appear in:

1. A user-supplied local project directory — scans `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and installed `node_modules/<pkg>/package.json`. PyPI manifests (`requirements.txt`, `poetry.lock`, `Pipfile.lock`) are also checked when the CSV contains unscoped names.
2. The user's GitHub repos — via `gh` CLI: code search across lockfile types, then exact-version validation via the dependency-graph SBOM API (`/repos/{owner}/{repo}/dependency-graph/sbom`).

**Severity model:** exact `pkg@version` match in a lockfile, `node_modules/`, or SBOM → `[CRITICAL]`. Range specifier (`^1.2.3`, `~1.2.3`, `>=…`) that could include the affected version → `[REVIEW]`. Package name match without version confirmation → `[REVIEW]`. Output streams to terminal and to `./shai-hulud-pkg-scan-YYYYMMDD-HHMMSS.log` (ANSI-stripped), with a severity-breakdown summary at the end.

**Usage:**
```bash
# Interactive — prompts for project directory
bash scanner/pkg_version_check.sh

# Fully scripted (env-var overrides)
PROJECT_DIR=/path/to/project \
  IOC_CSV="$HOME/Downloads/Mini Shai-Hulud - Sheet1.csv" \
  REPORT_FILE=/var/log/pkg-scan.log \
  bash scanner/pkg_version_check.sh --skip-node-modules
```

**CSV format:** col1 = package name (scoped names like `@scope/pkg` supported), col2 = exact affected version. A header row is auto-detected and skipped. Override the path with `IOC_CSV=…`.

**Dependencies:** `bash`, `find`, `grep`, `awk`, `sed`. Optional: `jq` (improves `node_modules/<pkg>/package.json` parsing accuracy), `gh` (required for the GitHub phase — phase is skipped with a clear message if absent or unauthenticated).

**Known limitations:**
- GitHub code search misses lockfiles >384KB and only indexes default branches — the SBOM path is the authoritative check.
- GitHub phase is rate-limit-bound (10 req/min authenticated); throttled at ~5 packages per 7s, so a full 633-row CSV takes ~22 minutes against GitHub. Run local scans first, GitHub phase separately.
- Lockfile parsing is `grep`-based, not fully parsed — deeply nested or unusual formatting may produce false negatives. Highest-value follow-up is jq-based lockfile parsing.
- SBOM API requires the repo's dependency graph to be enabled and indexed; repos without it fall back to `[REVIEW]`.

### 3. Claude Code Security Policy (`claude-code-policy/`)

Prevention layer for Claude Code, complementing the detection layer above.

- Blocks project-level hooks from running (`allowManagedHooksOnly`)
- Blocks writes to `.claude/settings.json`
- Blocks execution of known dropper patterns
- Blocks `curl`, `wget`, and `bun` commands from agent tool-use

**Installation:**
```bash
# Copy managed settings (cannot be overridden by projects)
cp claude-code-policy/managed-settings.json ~/.claude/managed-settings.json

# Copy the PreToolUse hook
mkdir -p ~/.claude/hooks
cp claude-code-policy/hooks/block_shai_hulud.py ~/.claude/hooks/
chmod +x ~/.claude/hooks/block_shai_hulud.py
```

## Roadmap / known gaps

- PyPI global scan equivalent to §10 (currently only `npm ls -g` is wired).
- Server-side `pre-receive` hook to reject pushes adding `.claude/settings.json`, `.vscode/tasks.json`, or `.gemini/` files from non-allowlisted authors.
- Optional integration with GitHub push-protection / Advanced Security.

## References

- [When the Tool Fights Back](https://cisomandate.com/when-the-tool-fights-back-three-ways-ai-coding-assistants-have-become-an-attack-surface/) — companion analysis
- [Sophos: Mini Shai-Hulud supply chain attack on SAP npm packages](https://www.sophos.com/en-us/blog/-mini-shai-hulud-supply-chain-attack-targets-sap-npm-packages)
- [Mend.io: Shai-Hulud strikes SAP — supply chain worm weaponizes Claude Code](https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/)
- [Wiz: Mini Shai-Hulud supply chain on SAP npm](https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm)
- [Novee Security: Google Gemini CLI RCE — CVSS 10.0 advisory](https://novee.security/blog/google-gemini-cli-rce-vulnerability-cvss-10-critical-security-advisory/)
- [The Hacker News: Google fixes CVSS 10 Gemini CLI CI/CD RCE (also covers Cursor CVE-2026-26268)](https://thehackernews.com/2026/04/google-fixes-cvss-10-gemini-cli-ci-rce.html)
- [ReversingLabs: PromptMink — DPRK malware inserted into codebase via Claude](https://www.reversinglabs.com/blog/claude-promptmink-malware-crypto)

## Contributing

Issues and PRs welcome — particularly for new IOC submissions (add to `scanner/iocs.txt` and bump the version header), additional platform-specific scan roots, and detection patterns for adjacent agentic tools (Continue, Cody, Codex CLI, Aider).

## License

MIT
