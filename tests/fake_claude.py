#!/usr/bin/env python3
"""Stand-in for the Claude Code CLI used by the tests.

Behaviour is chosen with FAKE_CLAUDE_MODE:
  success    stream an init event and a successful result
  auth       emit a fatal api_retry event, then hang (must be killed)
  hang       sleep forever (timeout test)
  noresult   exit 1 without a result line
  maxturns   result with subtype error_max_turns
  barefail   like noresult when --bare is given, else success
Every call appends its argv, the prompt and selected env vars to
FAKE_CLAUDE_RECORD (one JSON object per line).
"""

import json
import os
import sys
import time

mode = os.environ.get("FAKE_CLAUDE_MODE", "success")
argv = sys.argv[1:]

if argv == ["--version"]:
    print("9.9.9 (Claude Code)")
    sys.exit(0)

prompt = sys.stdin.read()
record = os.environ.get("FAKE_CLAUDE_RECORD")
if record:
    keys = ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL", "DISABLE_AUTOUPDATER",
            "HTTPS_PROXY", "HUNTER_PROXY")
    with open(record, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"argv": argv, "prompt": prompt, "cwd": os.getcwd(),
                                 "env": {k: os.environ.get(k) for k in keys}}) + "\n")


def emit(obj):
    print(json.dumps(obj), flush=True)


emit({"type": "system", "subtype": "init", "model": os.environ.get("ANTHROPIC_MODEL"), "session_id": "s-1"})

if mode == "barefail":
    mode = "noresult" if "--bare" in argv else "success"

if mode == "draft":
    # Policy reader stand-in: copy the next prepared draft into ./scope_draft.json.
    drafts = os.environ["FAKE_CLAUDE_DRAFTS"].split(os.pathsep)
    counter = os.environ["FAKE_CLAUDE_RECORD"] + ".n"
    n = int(open(counter).read()) if os.path.exists(counter) else 0
    open(counter, "w").write(str(n + 1))
    source = drafts[min(n, len(drafts) - 1)]
    if source != "NOFILE":
        with open(source, encoding="utf-8") as src, open("scope_draft.json", "w", encoding="utf-8") as dst:
            dst.write(src.read())
    mode = "success"

if mode == "script":
    # Simulate an agent's Bash tool: run the provided shell script in cwd with
    # the inherited phase environment (proxy, HUNTER_*, PATH). Proves hk and the
    # command checker work in the real environment.
    import subprocess
    script = os.environ.get("FAKE_CLAUDE_SCRIPT", "")
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    open("agent-stdout.txt", "w").write(proc.stdout + "\n--stderr--\n" + proc.stderr)
    if not os.path.exists("handoff.md"):
        open("handoff.md", "w").write("Automated recon done. See hk stats.\n")
    mode = "success"

if mode == "files":
    # FAKE_CLAUDE_FILES="review.json=/path/a.json;lead.json=/path/b.json":
    # write each output the prompt asks for (named in the prompt) into cwd.
    for pair in filter(None, os.environ.get("FAKE_CLAUDE_FILES", "").split(";")):
        name, source = pair.split("=", 1)
        if name in prompt:
            with open(source, encoding="utf-8") as src, open(name, "w", encoding="utf-8") as dst:
                dst.write(src.read())
    mode = "success"

if mode == "success":
    emit({"type": "assistant", "message": {"content": [{"type": "text", "text": "READY"}]}})
    emit({"type": "result", "subtype": "success", "is_error": False, "result": "READY",
          "num_turns": 1, "total_cost_usd": 0.0123, "session_id": "s-1"})
    sys.exit(0)
if mode == "maxturns":
    emit({"type": "result", "subtype": "error_max_turns", "is_error": True, "result": "",
          "num_turns": 2, "session_id": "s-1"})
    sys.exit(1)
if mode == "auth":
    emit({"type": "system", "subtype": "api_retry", "attempt": 1, "max_retries": 10,
          "retry_delay_ms": 1000, "error_status": 401, "error": "authentication_failed"})
    time.sleep(600)
if mode == "hang":
    time.sleep(600)
if mode == "noresult":
    print("boom: something broke", file=sys.stderr)
    sys.exit(1)
sys.exit(3)
