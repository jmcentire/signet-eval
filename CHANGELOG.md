# Changelog

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
