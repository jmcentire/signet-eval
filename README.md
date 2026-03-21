# signet-eval

Policy enforcement hook for Claude Code. Evaluates every tool call against user-defined rules before execution. Deterministic — no LLM in the decision path.

## Install

```bash
pip install signet-eval
# or
pip install -e .
```

## Usage

signet-eval runs as a [Claude Code PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code). It reads tool call JSON from stdin and returns allow/deny/ask on stdout.

### Quick start

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -m signet_eval_tool",
            "timeout": 5000
          }
        ]
      }
    ]
  }
}
```

That's it. Every tool call now passes through policy evaluation.

### Default policy

With no config file, signet-eval uses built-in safe defaults:

| Action | Decision | Reason |
|--------|----------|--------|
| `rm`, `rmdir` | **deny** | File deletion blocked |
| `git push --force` | **ask** | Escalates to user |
| `mkfs`, `format`, `dd if=` | **deny** | Destructive disk ops blocked |
| `curl \| sh`, `wget \| sh` | **deny** | Piped remote execution blocked |
| Everything else | **allow** | — |

### Custom policy

Install the default policy file as a starting point:

```bash
python3 -m signet_eval_tool --init
```

Then edit `~/.signet/policy.yaml`:

```yaml
version: 1
default_action: ALLOW
rules:
  - name: block_rm
    tool_pattern: ".*"
    conditions:
      - "'rm ' in str(parameters)"
    action: DENY
    reason: "File deletion blocked"

  - name: block_force_push
    tool_pattern: ".*"
    conditions:
      - "'push --force' in str(parameters) or 'push -f' in str(parameters)"
    action: ASK
    reason: "Force push requires confirmation"

  - name: block_env_writes
    tool_pattern: "Write|Edit"
    conditions:
      - "'.env' in str(parameters) or '.pem' in str(parameters)"
    action: DENY
    reason: "Cannot write to credential files"
```

Rules are evaluated in order — first match wins. Override the policy path with `SIGNET_POLICY_PATH` env var.

### How it works

1. Claude Code fires a PreToolUse hook before every tool call
2. Hook invokes `signet-eval` with tool call JSON on stdin
3. Policy rules are evaluated (first-match-wins)
4. Decision returned as JSON on stdout: `{"permissionDecision": "allow"}` or `{"permissionDecision": "deny", "permissionDecisionReason": "..."}`

Policy evaluation is deterministic: regex + simple conditions. No LLM, no network, no prompt injection surface.

### Performance

~60ms cold start (Python + yaml import). Policy evaluation itself is <1ms. Invisible for tool calls that take 50ms+.

## Architecture

signet-eval is the Tier 1 integration of the [Signet](https://github.com/jmcentire/signet) personal sovereign agent stack. It provides mandatory policy enforcement — the agent cannot bypass the hook because it fires automatically on every tool call.

The design principle: **the authorization layer must not be an LLM.** It processes structured data only. No natural language, no context window, no persuasion surface. A rule either matches or it doesn't.

## Development

```bash
pip install -e .
python3 -m pytest tests/ -v    # 40 contract tests
```

## License

MIT
