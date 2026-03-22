# Preflight Extension — Standards of Procedure

## Tech Stack
- Language: Rust 2021 edition, stable toolchain
- No unsafe code
- No network calls in the policy engine
- SQLite via rusqlite (already a dependency)
- HMAC-SHA256 via hmac + sha2 crates (already a dependency)
- Serde for serialization (already a dependency)

## Code Standards
- All errors handled — no unwrap() on user input paths
- Exit code always 0 in hook mode
- Policy evaluation deterministic and side-effect-free
- New structs derive Debug, Clone, Serialize, Deserialize
- Locked rules use `locked: true` (false is not serialized)
- All new vault methods must be idempotent

## Testing Standards
- Unit tests in `policy::preflight_tests` module
- Integration tests in `tests/integration_hook.rs`
- Adversarial tests: agent attempts to modify/delete preflight mid-lockout
- Self-protection test: verify locked rule blocks preflight storage tampering
- Performance test: preflight evaluation adds <1ms (hard budget)
- Test preflight HMAC verification failure gracefully degrades

## Security Invariants
- Soft constraints can only DENY or ASK, never ALLOW
- Hard rules always evaluated before soft constraints (two-pass)
- Lockout checked via system clock in vault, not in policy evaluation
- No MCP tool exists for delete/modify of active preflight
- HMAC verified on every preflight read, not just on submit
- Violation count and escalation stored in vault, not in memory

## Verification Gate
- All 88+ existing tests must pass after changes
- New preflight tests must cover: submit, lockout, violation, escalation, HMAC, tamper-detection
- `cargo clippy` clean, no warnings
- `cargo test` passes in both debug and release
