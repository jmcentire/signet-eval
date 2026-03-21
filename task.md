# Task: Build signet-eval

Build a Claude Code PreToolUse hook that enforces user-defined policy on every tool call. The tool reads hook JSON from stdin, evaluates it against policy rules, and returns an allow/deny/ask decision on stdout.

## Requirements

1. **Read hook input from stdin.** Claude Code sends JSON: `{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "session_id": "...", ...}`. Parse it, extract `tool_name` and `tool_input`.

2. **Load policy from `~/.signet/policy.yaml`.** YAML file with a `default` decision and an ordered list of `rules`. Each rule has: `tool` (tool name match), `match` (regex against serialized tool_input), `path` (regex against file paths for file-related tools), `decision` (allow/deny/ask), `reason` (explanation string). Cache after first load.

3. **Evaluate first-match-wins.** Walk rules in order. For each rule: if `tool` is set and doesn't match `tool_name`, skip. If `match` is set and doesn't match the serialized tool input, skip. If `path` is set and the tool input has a file_path/file-related field and the path doesn't match, skip. If all conditions match, return that rule's decision. If no rule matches, return the default.

4. **Return hook response JSON on stdout.** `{"permissionDecision": "allow"}` or `{"permissionDecision": "deny", "permissionDecisionReason": "..."}` or `{"permissionDecision": "ask"}`.

5. **Ship safe defaults.** If no policy file exists, use built-in defaults that block: `rm`, `rmdir`, `git push --force`, `git push -f`, `mkfs`, `format`, `dd if=`, `curl|sh`, `wget|sh`, and writes to `.env`, `.pem`, `.key`, `.secret` files. Everything else allowed.

6. **`signet-eval --init` installs the default policy** to `~/.signet/policy.yaml` if it doesn't exist.

7. **Fail secure.** Malformed stdin, missing fields, policy parse errors, any exception → deny with descriptive reason.

8. **Python stdlib only.** No external dependencies. Zero import overhead beyond stdlib yaml (use json for policy if yaml is too slow; or bundle a minimal yaml parser).

9. **Exit code 0 always** (Claude Code treats non-zero as hook failure, not as deny).

## Non-Requirements

- No daemon mode (v2)
- No SPL policy language (v2 — regex matching is sufficient for v1)
- No network access ever
- No audit logging to disk (v2)
- No interaction with Signet vault (standalone for now)

## Acceptance Criteria

- `echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | signet-eval` → deny with reason
- `echo '{"tool_name":"Read","tool_input":{"file_path":"/tmp/foo.txt"}}' | signet-eval` → allow
- `echo '{"tool_name":"Write","tool_input":{"file_path":"/app/.env"}}' | signet-eval` → deny
- `echo '{}' | signet-eval` → deny (malformed)
- `echo 'not json' | signet-eval` → deny (malformed)
- Total execution time under 15ms (cached policy)
