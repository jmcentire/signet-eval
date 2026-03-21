# signet-eval

Deterministic policy enforcement for AI agent tool calls. Rust. Single binary.

## Quick Reference

```bash
cargo build --release          # build
cargo test                     # 51+ unit + integration tests
cargo install --path .         # install to ~/.cargo/bin

# Hook mode (default — reads stdin, writes stdout)
echo '{"tool_name":"Bash","tool_input":{"command":"rm foo"}}' | signet-eval

# CLI
signet-eval init               # write default policy
signet-eval rules              # show rules
signet-eval validate           # check policy
signet-eval test '<json>'      # test a tool call
signet-eval setup              # create vault
signet-eval unlock             # refresh session
signet-eval status             # vault info
signet-eval store <n> <v>      # store credential
signet-eval delete <n>         # delete credential
signet-eval log                # action log
signet-eval reset-session      # clear spending
signet-eval sign               # HMAC-sign policy
signet-eval serve              # MCP management server
signet-eval proxy              # MCP proxy
```

## Structure

```
src/
  main.rs          — CLI entry point (clap), 15 subcommands
  policy.rs        — Policy engine, 14 condition functions, first-match-wins
  vault.rs         — Encrypted vault (Argon2 + AES-256-GCM), 3-tier, spending ledger
  hook.rs          — PreToolUse hook I/O (stdin JSON → stdout JSON)
  mcp_server.rs    — MCP management server (16 tools, rmcp)
  mcp_proxy.rs     — MCP proxy for upstream servers (rmcp)
tests/
  integration_hook.rs  — End-to-end hook subprocess tests
  integration_cli.rs   — CLI subcommand integration tests
examples/
  basic_policy.yaml       — Simple deny/ask rules
  spending_limits.yaml    — Cumulative spending with vault
  enterprise_policy.yaml  — Strict controls for regulated environments
```

## Security Model

- Session key file encrypted with device-specific key (not plaintext)
- Brute-force protection: 5 attempts then 5-minute lockout
- Policy file HMAC integrity verification (sign with `signet-eval sign`)
- Tier 3 credentials use compartment key (separate from session key)
- No NLP, no network, no eval() in the policy engine

## Condition Functions

`contains`, `any_of`, `param_eq`, `param_ne`, `param_gt`, `param_lt`,
`param_contains`, `matches`, `has_credential`, `spend_gt`,
`spend_plus_amount_gt`, `not`, `or`, `true`/`false`

## MCP Server Tools (16)

`signet_list_rules`, `signet_add_rule`, `signet_remove_rule`, `signet_edit_rule`,
`signet_reorder_rule`, `signet_set_limit`, `signet_status`, `signet_recent_actions`,
`signet_store_credential`, `signet_delete_credential`, `signet_list_credentials`,
`signet_validate`, `signet_test`, `signet_condition_help`, `signet_sign_policy`,
`signet_reset_session`

## Testing

Unit tests are in each module's `#[cfg(test)]` block. Integration tests in `tests/`.
Goodhart/adversarial tests in `policy::goodhart_tests`: unicode homoglyphs, null bytes,
1MB inputs, SQL injection, 1000-rule performance.

## Conventions

- Rust 2021 edition, stable toolchain
- No unsafe code
- All errors handled — no unwrap() on user input paths
- Exit code always 0 in hook mode (non-zero = hook failure in Claude Code)
- Policy evaluation deterministic and side-effect-free
