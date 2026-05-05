#!/usr/bin/env python3
"""
block_shai_hulud.py — PreToolUse hook for Claude Code
Blocks indicators of the Mini Shai-Hulud supply-chain attack.

Install:
  cp block_shai_hulud.py ~/.claude/hooks/
  chmod +x ~/.claude/hooks/block_shai_hulud.py

Exit codes:
  0 = allow the operation
  2 = block the operation (stderr message shown to user)
"""

import sys
import json

input_data = json.load(sys.stdin)
tool_name = input_data.get("tool_name", "")
tool_input = input_data.get("tool_input", {})

# --- Block writes to Claude Code settings ---
if tool_name in ("Edit", "Write"):
    target = tool_input.get("file_path", "")
    blocked_paths = [
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".claude/hooks/",
    ]
    for blocked in blocked_paths:
        if blocked in target:
            print(f"BLOCKED: Attempt to modify protected path '{blocked}'", file=sys.stderr)
            sys.exit(2)

# --- Block suspicious bash commands ---
if tool_name == "Bash":
    cmd = tool_input.get("command", "")
    suspicious_patterns = [
        "setup.mjs",
        "execution.js",
        "config.mjs",
        "oven-sh",
        "BUN_VERSION",
        "tmp.987654321.lock",
    ]
    for pattern in suspicious_patterns:
        if pattern in cmd:
            print(f"BLOCKED: Command contains suspicious pattern '{pattern}'", file=sys.stderr)
            sys.exit(2)

# --- Allow everything else ---
sys.exit(0)