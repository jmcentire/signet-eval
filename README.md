# signet-eval

Deterministic policy enforcement for AI agent tool calls. Every action an agent proposes passes through user-defined rules before execution. No LLM in the authorization path. No prompt injection surface. 25ms end-to-end.

## Install

```bash
cargo install signet-eval
```

## Quick Start

**1. Hook into Claude Code** — add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{"type": "command", "command": "signet-eval", "timeout": 2000}]
    }]
  }
}
```

**2. Done.** Every tool call now passes through policy evaluation. The default policy blocks destructive operations, protects its own configuration, and allows everything else.

**3. (Optional) Customize** — talk to Claude with the MCP server:

```bash
claude mcp add --scope user --transport stdio signet -- signet-eval serve
```

Then say: *"Add a $50 limit for amazon orders"* or *"Block all rm commands"*.

## Default Policy

Self-protection rules are **locked** — they cannot be removed, edited, or reordered by the AI agent, even through the MCP management server. This prevents the agent from disabling its own guardrails.

| Action | Decision | Locked |
|--------|----------|--------|
| Write/Edit/Bash touching `.signet/` | **deny** | yes |
| Write/Edit/Bash touching `signet-eval` binary | **deny** | yes |
| Write/Edit `settings.json` / `settings.local.json` | **ask** | yes |
| Bash `kill`/`pkill`/`killall` + `signet` | **deny** | yes |
| `rm`, `rmdir` | **deny** | |
| `git push --force` | **ask** | |
| `mkfs`, `format`, `dd if=` | **deny** | |
| `curl \| sh`, `wget \| sh` | **deny** | |
| Everything else | **allow** | |

## Custom Policy

```bash
signet-eval init       # write default policy to ~/.signet/policy.yaml
signet-eval validate   # check policy for errors
signet-eval rules      # show current rules
```

Edit `~/.signet/policy.yaml`:

```yaml
version: 1
default_action: ALLOW
rules:
  - name: block_rm
    tool_pattern: ".*"
    conditions: ["contains(parameters, 'rm ')"]
    action: DENY
    reason: "File deletion blocked"

  - name: books_limit
    tool_pattern: ".*purchase.*"
    conditions:
      - "param_eq(category, 'books')"
      - "spend_plus_amount_gt('books', amount, 200)"
    action: DENY
    reason: "Books spending limit ($200) exceeded"

  - name: protect_my_config
    tool_pattern: ".*"
    conditions: ["contains(parameters, '/etc/')"]
    action: ASK
    locked: true
    reason: "System config changes require confirmation"
```

Rules are evaluated in order — first match wins. Multiple conditions on a rule are AND'd. Rules with `locked: true` cannot be modified through the MCP management server.

## Condition Functions

| Function | Description | Example |
|----------|-------------|---------|
| `contains(parameters, 'X')` | Tool input contains string | `contains(parameters, 'rm ')` |
| `any_of(parameters, 'X', 'Y')` | Any string present | `any_of(parameters, 'mkfs', 'format')` |
| `param_eq(field, 'value')` | Field equals value | `param_eq(category, 'books')` |
| `param_ne(field, 'value')` | Field not equal | `param_ne(role, 'admin')` |
| `param_gt(field, N)` | Field > number | `param_gt(amount, 100)` |
| `param_lt(field, N)` | Field < number | `param_lt(amount, 5)` |
| `param_contains(field, 'X')` | Field contains substring | `param_contains(command, 'sudo')` |
| `matches(field, 'regex')` | Field matches regex | `matches(file_path, '\\.env$')` |
| `has_credential('name')` | Credential exists in vault | `has_credential('cc_visa')` |
| `spend_gt('cat', N)` | Session spend > limit | `spend_gt('books', 200)` |
| `spend_plus_amount_gt('cat', field, N)` | Spend + this amount > limit | `spend_plus_amount_gt('books', amount, 200)` |
| `not(condition)` | Negate condition | `not(param_eq(format, 'json'))` |
| `or(A \|\| B)` | Either condition | `or(contains(parameters, '-f') \|\| contains(parameters, '--force'))` |
| `true` / `false` | Literal | `true` |

## Encrypted Vault

Three-tier encrypted storage with passphrase-derived key hierarchy (Argon2id + AES-256-GCM):

| Tier | Encryption | Contents |
|------|-----------|----------|
| 1 | None | Action log, spending ledger |
| 2 | Session key | Session state |
| 3 | Compartment key | CC numbers, API tokens, secrets |

```bash
signet-eval setup                      # create vault with passphrase
signet-eval store cc_visa 4111...      # store Tier 3 credential
signet-eval status                     # vault status and spending
signet-eval log                        # recent action log
signet-eval unlock                     # refresh session after timeout
```

Credentials support scoped access via `request_capability`: domain restrictions, purpose constraints, per-use amount caps, and one-time tokens that auto-invalidate after a single use.

Spending limits use the vault ledger — each tool call that spends money is logged, and `spend_plus_amount_gt()` checks cumulative totals before allowing the next purchase.

## Self-Protection

signet-eval ships with four locked rules that prevent an AI agent from disabling its own policy enforcement:

1. **protect_signet_dir** — Denies any Write, Edit, or Bash command touching `.signet/` (policy files, vault, HMAC)
2. **protect_signet_binary** — Denies tampering with the `signet-eval` binary itself
3. **protect_hook_config** — Requires user confirmation before modifying `settings.json` (where the hook is configured)
4. **protect_signet_process** — Denies kill/pkill/killall commands targeting signet processes

These rules are:
- **Locked** — MCP tools refuse to remove, edit, or reorder them
- **Position-protected** — Unlocked rules cannot be reordered above locked rules (first-match-wins)
- **Hardcoded in defaults** — If the policy file is corrupted or missing, the binary falls back to hardcoded defaults that include self-protection
- **HMAC-backed** — Direct file edits break the policy signature, triggering fallback to safe defaults

## MCP Management Server

Manage policies conversationally through Claude:

```bash
claude mcp add --scope user --transport stdio signet -- signet-eval serve
```

| Tool | Purpose |
|------|---------|
| `signet_list_rules` | Show all rules with locked status |
| `signet_add_rule` | Add a new rule (appended after locked rules) |
| `signet_remove_rule` | Remove a rule (refuses on locked rules) |
| `signet_edit_rule` | Modify rule properties (refuses on locked rules) |
| `signet_reorder_rule` | Move a rule (refuses on locked, prevents placing above locked) |
| `signet_set_limit` | Set a spending limit for a category |
| `signet_test` | Test a tool call against the current policy |
| `signet_validate` | Check policy for errors |
| `signet_condition_help` | Show available condition functions |
| `signet_status` | Vault status, spending totals, credential count |
| `signet_recent_actions` | Show recent action log |
| `signet_store_credential` | Store a Tier 3 credential |
| `signet_use_credential` | Request a credential through capability constraints |
| `signet_list_credentials` | List credential names |
| `signet_delete_credential` | Delete a credential |
| `signet_sign_policy` | HMAC-sign the policy file |
| `signet_reset_session` | Clear spending counters |

All mutating operations auto-sign the policy when the vault is available.

## MCP Proxy

Wrap upstream MCP servers with policy enforcement. The agent connects to the proxy, never directly to servers. Policy is hot-reloaded on every call.

```bash
# Configure upstream servers
cat > ~/.signet/proxy.yaml << 'YAML'
servers:
  linear:
    command: npx
    args: ["-y", "mcp-linear"]
    env:
      LINEAR_API_KEY: "your-key"
YAML

# Register proxy with Claude Code
claude mcp add --scope user --transport stdio signet-proxy -- signet-eval proxy
```

## All Commands

| Command | Purpose |
|---------|---------|
| `signet-eval` | Hook evaluation (default, 25ms) |
| `signet-eval init` | Write default policy with locked self-protection rules |
| `signet-eval rules` | Show current policy rules (locked rules tagged) |
| `signet-eval validate` | Check policy for errors |
| `signet-eval test '<json>'` | Test a tool call against policy |
| `signet-eval setup` | Create encrypted vault |
| `signet-eval unlock` | Refresh vault session |
| `signet-eval status` | Vault status and spending |
| `signet-eval store <name> <value>` | Store Tier 3 credential |
| `signet-eval delete <name>` | Delete a credential |
| `signet-eval log` | Recent action log |
| `signet-eval reset-session` | Clear spending counters |
| `signet-eval sign` | HMAC-sign policy file |
| `signet-eval serve` | MCP management server (17 tools) |
| `signet-eval proxy` | MCP proxy for upstream servers |

## Performance

| Metric | Value |
|--------|-------|
| Hook eval (end-to-end) | **25ms** — process spawn, stdin, JSON parse, policy load, eval, response |
| In-process policy eval | **14–63μs** — 14μs deny, 21μs ask, 63μs spending check |
| CLI validate / rules | **8ms** |
| Binary size | **6.2MB** (stripped, LTO) |

## Architecture

signet-eval is the enforcement layer of the [Signet](https://signet.tools) personal sovereign agent stack. The core principle: **the authorization layer must not be an LLM.** It processes structured data only — regex, comparisons, and vault queries. No natural language, no context window, no persuasion surface. A rule either matches or it doesn't.

```
Agent proposes action  ->  signet-eval evaluates policy  ->  allow / deny / ask
                           (deterministic, 25ms, no NLP)
```

## License

MIT
