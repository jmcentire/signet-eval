# Design: signet-eval

*Version 1 — Auto-maintained by pact*

## Decomposition

- [C] **Signet Evaluation Tool** (`signet_eval_tool`)
  A standalone Python CLI tool that reads Claude Code PreToolUse hook JSON from stdin, evaluates it against user-defined policy rules from ~/.signet/policy.yaml (with built-in safe defaults), and returns allow/deny/ask decisions on stdout. Implements first-match-wins rule evaluation, secure input validation, policy file caching, fail-secure behavior for all error conditions, and provides --init command to install default policy. Single-file implementation using only Python stdlib with type hints and optimized for <15ms execution time.

## Engineering Decisions

### 
**Decision:** Single module implementation
**Rationale:** This is a straightforward CLI tool with clear data flow: stdin JSON → policy evaluation → stdout JSON. All functionality revolves around the same data structures (hook input, policy rules, evaluation state) and shares common error handling patterns. The complexity comes from business logic rather than architectural boundaries.

### 
**Decision:** Built-in default policy as embedded data
**Rationale:** The safe defaults requirement suggests embedding the default policy as a Python data structure rather than requiring a separate file, ensuring the tool works out-of-box and can't fail due to missing default policy files.

### 
**Decision:** Policy caching at module level
**Rationale:** The 15ms performance requirement with cached policy suggests simple module-level caching rather than a separate caching subsystem, since the tool is invoked per-hook-call rather than running as a daemon.

### 
**Decision:** JSON over YAML for performance
**Rationale:** Given the 15ms performance constraint and 'no external dependencies' requirement, using JSON for policy format eliminates YAML parsing overhead while maintaining human readability. The interview mentions 'use json for policy if yaml is too slow'.
