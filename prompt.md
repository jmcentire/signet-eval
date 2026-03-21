# Signet Eval — Claude Code Policy Enforcement Hook

## What This Is

A fast, deterministic policy enforcement tool that sits between Claude Code (or any agent) and the actions it takes. It receives structured tool call proposals via stdin, evaluates them against user-configured policy rules, and returns allow/deny/ask decisions on stdout.

This is the Tier 1 integration of the Signet personal sovereign agent architecture. The core principle: the authorization layer must not be an LLM. It processes structured data only — no natural language, no context window, no prompt injection surface. Policy evaluation is deterministic: a signed rule either matches or it doesn't.

## Why It Exists

Claude Code's permission model is binary: approve each tool call individually, or `dangerously-skip-permissions` to skip all checks. There is no middle ground — no way to say "allow reads, deny deletes, require confirmation for force-pushes." This tool fills that gap.

An agent that doesn't want to hear "no" won't ask the question. So this tool must sit in the mandatory execution path — Claude Code's PreToolUse hook fires before every tool call, and the agent cannot bypass it. The tool is invisible when it permits (adds ~10ms overhead) and firm when it denies.

## How It Works

1. Claude Code fires a PreToolUse hook before every tool call
2. The hook invokes `signet-eval` with the tool call JSON on stdin
3. `signet-eval` loads policy from `~/.signet/policy.yaml` (cached after first load)
4. Evaluates the tool name + arguments against ordered policy rules
5. Returns a JSON decision on stdout: allow, deny (with reason), or ask (escalate to user)

## Design Principles

- **Zero NLP in the decision path.** Regex and literal matching only. No LLM judgment calls.
- **Fast.** Policy evaluation in microseconds. Process startup is the bottleneck (~10ms), acceptable for tool calls that take 50ms+.
- **Reasonable defaults.** Ships with a default policy that blocks destructive operations (rm, format, force-push) and permits everything else. Users tune from there.
- **Transparent denials.** When a tool call is denied, the reason is clear and specific. The agent sees why and can adjust.
- **No dependencies.** Python stdlib only. No pip install, no venv, no startup penalty from importing heavy packages.
- **First-match wins.** Rules are evaluated in order. First matching rule determines the decision. If no rule matches, the default applies.

## Key Scenarios

| Action | Default Policy |
|--------|---------------|
| Read any file | allow |
| Write to project files | allow |
| Write to .env, .pem, credentials | deny |
| `rm` or `rm -rf` anything | deny |
| `git push --force` | ask (escalate to user) |
| `git push` (normal) | allow |
| `mkfs`, `format`, `dd if=` | deny |
| `curl ... \| sh` (piped remote exec) | deny |
| `chmod 777` | ask |
| Any MCP tool call | allow (no default restrictions) |
| Everything else | allow |

## Integration Point

Claude Code settings.json:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [{ "type": "command", "command": "signet-eval" }]
      }
    ]
  }
}
```

The empty matcher means it fires for ALL tool calls. `signet-eval` handles tool-specific routing internally via policy rules.
