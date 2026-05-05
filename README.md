# shai-hulud-defense
IOC scanner and Claude Code security policy for the Shai-Hulud supply-chain attack
# Shai-Hulud Defense Kit

Detection and prevention tools for the Mini Shai-Hulud supply-chain attack
targeting Claude Code via malicious npm packages.

## What's Included

### 1. IOC Scanner (`scanner/shai_hud.sh`)

A bash script that scans your system for indicators of compromise:

- Malicious `SessionStart` hooks in any `settings.json`
- Bun-based dropper files (`setup.mjs`)
- Large obfuscated payloads (`execution.js` > 1MB)
- Malware lock files in `/tmp`
- Suspicious `preinstall` scripts in `package.json`
- AI-authored changes to GitHub Actions workflows

**Usage:**
```bash
bash scanner/shai_hud.sh
# Enter your project folder when prompted
```

### 2. Claude Code Security Policy (`claude-code-policy/`)

A managed settings file and PreToolUse hook that prevent the attack:

- Blocks project-level hooks from running (`allowManagedHooksOnly`)
- Blocks writes to `.claude/settings.json`
- Blocks execution of known dropper patterns
- Blocks `curl`, `wget`, and `bun` commands

**Installation:**
```bash
# Copy managed settings (cannot be overridden by projects)
cp claude-code-policy/managed-settings.json ~/.claude/managed-settings.json

# Copy the hook script
mkdir -p ~/.claude/hooks
cp claude-code-policy/hooks/block_shai_hulud.py ~/.claude/hooks/
chmod +x ~/.claude/hooks/block_shai_hulud.py
```

## References

- [When the tool fights back] (https://cisomandate.com/when-the-tool-fights-back-three-ways-ai-coding-assistants-have-become-an-attack-surface/)
- [Sophos Blog: Mini Shai-Hulud](https://www.sophos.com/en-us/blog/-mini-shai-hulud-supply-chain-attack-targets-sap-npm-packages)
- [Mend.io: Shai-Hulud SAP CAP Attack](https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/)

## License

MIT