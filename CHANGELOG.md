# Changelog

## [3.8.0] - 2026-04-02

### Added
- `validate --fix` CLI flag — auto-fixes clampable issues (gate.within, ensure.timeout clamping) and removes broken unlocked rules; writes updated policy and re-signs if vault exists
- `validate --fix --dry-run` — previews what --fix would change without writing to disk
- `status` now shows complete enforcement state: global disable, disabled sessions, global pause with expiry, per-rule/per-session pauses with timestamps
- `status` shows enforcement overrides even without a vault (file-based state is independent)

### Fixed
- `enable` (no flags) now clears both global disable AND all session disables in one invocation; previously required running twice if both existed
- `status` no longer returns exit code 1 when vault is not set up — enforcement info is still useful without a vault

## [3.6.0] - 2026-04-01

### Changed
- `github_identity_guard` moved from self-protection (locked) to default policy (unlocked) — no longer blocks git operations on fresh installs without the check script
- `validate_policy()` returns structured `ValidationDiagnostic` with severity (Error/Warning), actionable `fix_hint`, and `auto_fixable` flag
- MCP `signet_validate` tool shows actionable fix hints per diagnostic; accepts `fix=true` to auto-repair broken rules
- CLI `signet-eval validate` displays ERROR/WARN with fix instructions

### Added
- `fix_policy()` function — auto-removes broken unlocked rules, clamps out-of-range gate.within and ensure.timeout; never touches locked rules
- Ensure script existence and executable checks (Warning-level diagnostics)
- `has_recent_action` added to KNOWN_CONDITION_FNS (was implemented but missing from validation whitelist)
- Graceful ensure resolution for unlocked rules: missing script = allow (locked rules still fail-closed)

## [3.5.0] - 2026-03-28

### Added
- `has_recent_action('search', within)` condition function -- searches both tool name and detail columns in the action ledger; supports pipe-delimited OR for multiple search terms
- `require_plan_before_code` default rule -- ASKs before Edit/Write/NotebookEdit if no recent EnterPlanMode or TaskCreate action in the ledger
- `protect_core_files` default rule -- ASKs before Edit/Write on paths matching core/dsl/schema/engine patterns

### Changed
- GATE action `has_recent_allowed_action()` now searches both `tool` and `detail` columns (was detail-only, so tool-name-based gates silently failed)
- GATE `requires_prior` supports pipe-delimited OR: `"EnterPlanMode|TaskCreate"` matches either term

### Note
The `require_plan_before_code` rule fires before other Edit/Write rules (first-match-wins). Without a logged plan, agents see "Present a plan" before any other edit-related rule.

## [3.4.0] - 2026-03-27

### Fixed
- Default policy tool patterns were overbroad (matched substrings instead of exact tool names)
- `query` subcommand output now goes to stdout instead of stderr

## [3.3.0] - 2026-03-22

### Added
- Gate and Ensure action types for prerequisite enforcement
- Claude Code plugin structure
