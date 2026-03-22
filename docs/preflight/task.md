# Preflight: Self-Planning Subsystem for signet-eval

## What to Build

A pre-execution planning gate that requires the AI agent to file a "preflight" —
a structured declaration of task intent, identified risks, self-imposed constraints,
and plan B alternatives — before beginning work. The preflight is validated against
hard policy rules, HMAC-signed, stored in the vault, and enforced immutably during
execution. The agent can query its active preflight but cannot modify it mid-session
without restarting the planning phase.

The subsystem integrates with kindex (persistent knowledge graph) at planning time
to surface past failures relevant to the current task, improving constraint quality
over time.

## Key Actions (verb-led)

- Accept preflight submissions via MCP tool (`signet_preflight_submit`)
- Validate soft constraints do not conflict with or weaken hard policy rules
- HMAC-sign and vault-store the accepted preflight, starting the lockout timer
- Evaluate tool calls against both hard rules (pass 1) and active soft constraints (pass 2)
- Block modification of active preflight during lockout period
- Log all preflight violations with the declared plan B alternative in the deny reason
- Surface active preflight and violation history via read-only MCP tools
- Protect preflight storage with locked self-protection rules

## Scope & Boundaries

**In scope:**
- Preflight struct, storage, signing, lockout enforcement
- Two-pass evaluation (hard rules first, soft constraints second)
- 5 new MCP tools (submit, active, history, violations, test)
- 1 new CLI subcommand (preflight-status)
- 1 new locked self-protection rule
- Modified hook.rs to check active preflight
- Integration point for kindex queries (MCP call from agent, not from signet-eval)

**Out of scope:**
- signet-eval does NOT call kindex directly (no network dependency)
- No changes to existing hard rule evaluation logic
- No NLP or fuzzy matching — soft constraints use the same condition DSL
- No automatic preflight generation — the agent produces the preflight, signet-eval only validates and enforces

## Constraints & Failure Modes

- Soft constraints MUST NOT override, weaken, or shadow hard policy rules
- Lockout period is set at submission time and cannot be shortened
- If the vault is unavailable, preflight features degrade gracefully (hard rules still enforced)
- HMAC verification failure on a stored preflight falls back to hard-rules-only mode
- Maximum 20 soft constraints per preflight (prevent token-wasting abuse)
- Preflight submission must complete in <50ms (no network calls)
- A preflight violation returns the plan B text in the deny reason, not just the constraint name

## Non-Functional Requirements

- Performance: preflight evaluation adds <1ms to each tool call
- Storage: preflights stored in vault SQLite, <1KB each typical
- Security: HMAC-signed, vault-encrypted, tamper-evident
- Determinism: all evaluation is regex + string comparison, no randomness
