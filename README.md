# signet-eval

Deterministic policy enforcement for AI agent tool calls. Every action an agent proposes passes through user-defined rules before execution. No LLM in the authorization path. No prompt injection surface. 5ms.

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

**2. Done.** Every tool call now passes through policy evaluation. The default policy blocks destructive operations and allows everything else.

**3. (Optional) Customize** — talk to Claude with the MCP server:

```bash
claude mcp add --scope user --transport stdio signet -- signet-eval serve
```

Then say: *"Add a $50 limit for amazon orders"* or *"Block all rm commands"*.

## Default Policy

| Action | Decision |
|--------|----------|
| `rm`, `rmdir` | **deny** |
| `git push --force` | **ask** (escalate to user) |
| `mkfs`, `format`, `dd if=` | **deny** |
| `curl \| sh`, `wget \| sh` | **deny** |
| Write to `.env`, `.pem`, `.key` | **deny** |
| `chmod 777` | **ask** |
| Everything else | **allow** |

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
```

Rules are evaluated in order — first match wins. Multiple conditions on a rule are AND'd.

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

Three-tier encrypted storage with passphrase-derived key hierarchy (Argon2 + AES-256-GCM):

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

Spending limits use the vault ledger — each tool call that spends money is logged, and `spend_plus_amount_gt()` checks cumulative totals before allowing the next purchase.

## MCP Management Server

Manage policies conversationally through Claude:

```bash
claude mcp add --scope user --transport stdio signet -- signet-eval serve
```

| Tool | Purpose |
|------|---------|
| `signet_set_limit` | "Add a $50 limit for amazon orders" |
| `signet_add_rule` | "Block all rm commands" |
| `signet_remove_rule` | "Remove the books limit" |
| `signet_list_rules` | "What's currently blocked?" |
| `signet_status` | "How much have I spent?" |
| `signet_test` | "Would this tool call be allowed?" |
| `signet_validate` | "Is my policy file valid?" |
| `signet_condition_help` | "What condition functions are available?" |
| `signet_store_credential` | "Store my Visa card" |
| `signet_list_credentials` | "What credentials do I have?" |
| `signet_delete_credential` | "Delete my old API key" |
| `signet_recent_actions` | "Show recent actions" |

## MCP Proxy

Wrap upstream MCP servers with policy enforcement. The agent connects to the proxy, never directly to servers:

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
| `signet-eval` | Hook evaluation (default, 5ms) |
| `signet-eval init` | Write default policy file |
| `signet-eval rules` | Show current policy rules |
| `signet-eval validate` | Check policy for errors |
| `signet-eval test '<json>'` | Test a tool call against policy |
| `signet-eval setup` | Create encrypted vault |
| `signet-eval unlock` | Refresh vault session |
| `signet-eval status` | Vault status and spending |
| `signet-eval store <name> <value>` | Store Tier 3 credential |
| `signet-eval log` | Recent action log |
| `signet-eval serve` | MCP management server |
| `signet-eval proxy` | MCP proxy |

## Performance

| Metric | Value |
|--------|-------|
| Cold start | **5ms** |
| Policy evaluation | **<1us** |
| Binary size | **6MB** |
| 1000-rule evaluation | **<10ms** |
| Tests | **44** (including adversarial) |

## Architecture

signet-eval is the enforcement layer of the [Signet](https://signet.tools) personal sovereign agent stack. The core principle: **the authorization layer must not be an LLM.** It processes structured data only — regex, comparisons, and vault queries. No natural language, no context window, no persuasion surface. A rule either matches or it doesn't.

```
Agent proposes action  ->  signet-eval evaluates policy  ->  allow / deny / ask
                           (deterministic, 5ms, no NLP)
```

## License

MIT
