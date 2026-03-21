# signet-eval

Policy enforcement for Claude Code. Evaluates every tool call against user-defined rules before execution. 5ms cold start. Deterministic — no LLM in the decision path.

## Install

```bash
cargo install signet-eval
```

## Usage

Add to `~/.claude/settings.json`:

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

### Default policy

Without a config file, blocks destructive operations and allows everything else:

| Action | Decision |
|--------|----------|
| `rm`, `rmdir` | **deny** |
| `git push --force` | **ask** (escalate to user) |
| `mkfs`, `format`, `dd if=` | **deny** |
| `curl \| sh`, `wget \| sh` | **deny** |
| Everything else | **allow** |

### Custom policy

```bash
signet-eval init   # writes default policy to ~/.signet/policy.yaml
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

### Condition functions

| Function | Description |
|----------|-------------|
| `contains(parameters, 'X')` | Serialized params contain string |
| `any_of(parameters, 'X', 'Y')` | Any of the strings present |
| `param_eq(field, 'value')` | Parameter field equals value |
| `param_gt(field, number)` | Parameter field exceeds number |
| `spend_gt('category', limit)` | Session spend exceeds limit |
| `spend_plus_amount_gt('cat', field, limit)` | Cumulative spend + this amount exceeds limit |

### Encrypted vault

```bash
signet-eval setup              # create vault with passphrase
signet-eval store cc_visa 4111...  # store Tier 3 credential
signet-eval status             # vault status and recent actions
```

Three-tier encryption: Tier 1 unencrypted (ledger), Tier 2 session-encrypted, Tier 3 compartment-encrypted (requires passphrase).

## Performance

- **5ms** cold start (vs 82ms Python)
- **<1μs** policy evaluation
- **3.7MB** stripped binary

## Architecture

Tier 1 of the [Signet](https://github.com/jmcentire/signet) personal sovereign agent stack. The authorization layer is deterministic — no natural language, no context window, no prompt injection surface. A rule either matches or it doesn't.

## License

MIT
