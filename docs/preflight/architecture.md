# Preflight Architecture

## 1. Data Structures

### PolicyRule extension

Add an optional `alternative` field to PolicyRule. When present, this is the
"plan B" — surfaced in the deny reason when the rule fires.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub tool_pattern: String,
    #[serde(default)]
    pub conditions: Vec<String>,
    pub action: Decision,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alternative: Option<String>,   // NEW: plan B hint
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub locked: bool,
}
```

When a rule with `alternative` fires, the deny reason becomes:
`"{reason} Instead: {alternative}"`

### Preflight struct

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preflight {
    /// Unique ID (UUID v4)
    pub id: String,
    /// Human-readable task description
    pub task: String,
    /// Identified risks
    pub risks: Vec<String>,
    /// Self-imposed soft constraints
    pub constraints: Vec<SoftConstraint>,
    /// When this preflight was submitted (Unix timestamp)
    pub submitted_at: u64,
    /// Lockout expiry (Unix timestamp). Cannot be moved earlier.
    pub lockout_until: u64,
    /// Number of violations recorded against this preflight
    pub violation_count: u32,
    /// Whether escalation mode is active (violation_count > threshold)
    pub escalated: bool,
    /// HMAC of the serialized preflight (set by vault, not by agent)
    #[serde(skip)]
    pub hmac: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftConstraint {
    /// Constraint name (e.g., "no_bulk_delete")
    pub name: String,
    /// Tool pattern regex (same DSL as PolicyRule)
    pub tool_pattern: String,
    /// Conditions (same DSL as PolicyRule)
    pub conditions: Vec<String>,
    /// Action: Deny or Ask (never Allow — soft constraints only restrict)
    pub action: Decision,
    /// Why this constraint exists
    pub reason: String,
    /// REQUIRED: what to do instead
    pub alternative: String,
}
```

### Violation record

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightViolation {
    pub preflight_id: String,
    pub constraint_name: String,
    pub tool_name: String,
    pub parameters_summary: String,  // truncated to 500 chars
    pub alternative: String,
    pub timestamp: u64,
}
```

## 2. Evaluation Changes

Current flow (policy.rs:298-340):
```
for rule in policy.rules:
    if tool matches and conditions match:
        return rule.decision   # first match wins
return default_action
```

New two-pass flow:
```
# Pass 1: Hard rules (unchanged)
for rule in policy.rules:
    if tool matches and conditions match:
        return rule.decision

# Pass 2: Active preflight soft constraints (if any)
if let Some(preflight) = active_preflight:
    if preflight.escalated:
        return Ask("Preflight escalated: {violation_count} violations. Review required.")
    for constraint in preflight.constraints:
        if tool matches and conditions match:
            log_violation(preflight, constraint, call)
            return constraint.action with reason: "{reason} Instead: {alternative}"

return default_action
```

Key: hard rules always win. If a hard rule allows something, we still check soft
constraints. If a hard rule denies something, we never reach pass 2.

Actually, correction: the two-pass design means soft constraints can ONLY add
restrictions, never remove them. If hard rules return Allow (no match, default),
soft constraints can still deny. If hard rules return Deny, we short-circuit.
This is the correct behavior — PF-C001 is enforced structurally, not just by validation.

## 3. Vault Storage

New SQLite table in vault init:

```sql
CREATE TABLE IF NOT EXISTS preflights (
    id TEXT PRIMARY KEY,
    task TEXT NOT NULL,
    payload TEXT NOT NULL,       -- JSON-serialized Preflight
    hmac BLOB NOT NULL,          -- HMAC-SHA256 of payload
    submitted_at INTEGER NOT NULL,
    lockout_until INTEGER NOT NULL,
    violation_count INTEGER DEFAULT 0,
    escalated INTEGER DEFAULT 0,
    active INTEGER DEFAULT 1     -- 0 = expired/superseded
);

CREATE TABLE IF NOT EXISTS preflight_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    preflight_id TEXT NOT NULL,
    constraint_name TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    params_summary TEXT,
    alternative TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (preflight_id) REFERENCES preflights(id)
);
```

### Vault methods

```rust
impl Vault {
    /// Store a new preflight. HMAC-signs it. Deactivates any previous active preflight.
    pub fn store_preflight(&self, preflight: &Preflight) -> Result<(), String>;

    /// Get the currently active preflight (if any, and if not expired).
    pub fn active_preflight(&self) -> Option<Preflight>;

    /// Record a violation. Increments violation_count. Sets escalated if threshold exceeded.
    pub fn log_preflight_violation(&self, violation: &PreflightViolation) -> Result<(), String>;

    /// Get violation history for a preflight.
    pub fn preflight_violations(&self, preflight_id: &str) -> Vec<PreflightViolation>;

    /// Get all preflights (for history view).
    pub fn preflight_history(&self, limit: u32) -> Vec<Preflight>;

    /// Verify HMAC of a stored preflight.
    pub fn verify_preflight_hmac(&self, preflight_id: &str) -> bool;

    /// Check if lockout is active (current time < lockout_until).
    pub fn is_preflight_locked(&self) -> bool;
}
```

## 4. MCP Tools

### signet_preflight_submit

Submit a new preflight. Validates constraints, HMAC-signs, stores, starts lockout.

```json
{
  "name": "signet_preflight_submit",
  "description": "File a preflight: declare task intent, risks, and self-imposed constraints before starting work.",
  "inputSchema": {
    "type": "object",
    "required": ["task", "risks", "constraints", "lockout_minutes"],
    "properties": {
      "task": {
        "type": "string",
        "description": "What you intend to do"
      },
      "risks": {
        "type": "array",
        "items": { "type": "string" },
        "description": "What could go wrong"
      },
      "constraints": {
        "type": "array",
        "maxItems": 20,
        "items": {
          "type": "object",
          "required": ["name", "tool_pattern", "conditions", "action", "reason", "alternative"],
          "properties": {
            "name": { "type": "string" },
            "tool_pattern": { "type": "string" },
            "conditions": { "type": "array", "items": { "type": "string" } },
            "action": { "enum": ["DENY", "ASK"] },
            "reason": { "type": "string" },
            "alternative": { "type": "string", "minLength": 1 }
          }
        }
      },
      "lockout_minutes": {
        "type": "integer",
        "minimum": 5,
        "maximum": 480,
        "description": "How long this preflight is locked (5 min to 8 hours)"
      }
    }
  }
}
```

**Validation on submit:**
1. All constraint conditions must parse (same validator as policy rules)
2. All tool_patterns must compile as regex
3. All `alternative` fields must be non-empty
4. `action` must be DENY or ASK (never ALLOW — soft constraints only restrict)
5. At most 20 constraints
6. lockout_minutes >= 5 (minimum commitment)
7. No soft constraint can have `locked: true`

**Returns:** `{ "id": "...", "lockout_until": "2026-03-22T15:30:00Z", "constraints_accepted": 5 }`

### signet_preflight_active

Read-only. Show the current active preflight.

```json
{
  "name": "signet_preflight_active",
  "description": "View your active preflight: task, constraints, lockout status, violation count.",
  "inputSchema": { "type": "object", "properties": {} }
}
```

### signet_preflight_history

Read-only. Show past preflights.

```json
{
  "name": "signet_preflight_history",
  "description": "View past preflights and their outcomes.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "limit": { "type": "integer", "default": 10 }
    }
  }
}
```

### signet_preflight_violations

Read-only. Show violations for the active or a specified preflight.

```json
{
  "name": "signet_preflight_violations",
  "description": "View constraint violations: what was blocked and what the alternative was.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "preflight_id": { "type": "string", "description": "Optional. Defaults to active preflight." }
    }
  }
}
```

### signet_preflight_test

Dry-run a preflight submission — validates without storing.

```json
{
  "name": "signet_preflight_test",
  "description": "Dry-run: validate a preflight without submitting it.",
  "inputSchema": {
    "type": "object",
    "required": ["constraints"],
    "properties": {
      "constraints": {
        "type": "array",
        "items": { "$ref": "#/definitions/SoftConstraint" }
      }
    }
  }
}
```

## 5. Compliance Mechanisms

### Timed Lockout

- `lockout_minutes` is set at submission time (minimum 5, maximum 480)
- `lockout_until = submitted_at + lockout_minutes * 60`
- During lockout: `signet_preflight_submit` rejects with "Active preflight locked until {time}. Cannot modify."
- After lockout expires: new preflight can be submitted, old one archived
- **Critical**: lockout is checked in vault.rs using system clock, not in policy evaluation.
  The agent cannot manipulate the system clock via tool calls (Bash `date -s` would be
  caught by hard rules or OS permissions).
- User override: `signet-eval preflight-override` CLI command (requires vault passphrase)
  allows early termination. This is a human-only escape hatch.

### HMAC Signing

- On submit, the vault serializes the Preflight to JSON, computes HMAC-SHA256
  using the session key, stores both payload and HMAC
- On every read (active_preflight), the vault verifies HMAC before returning
- If HMAC verification fails: log a tampering alert, deactivate the preflight,
  fall back to hard-rules-only mode
- Same mechanism as policy.yaml HMAC signing — uses existing vault crypto

### Anti-Circumvention

New locked self-protection rule:

```yaml
- name: protect_preflight_storage
  tool_pattern: ".*"
  conditions:
    - "any_of(parameters, 'preflights', 'preflight_violations', 'vault.db')"
    - "or(contains_word(parameters, 'DELETE') || contains_word(parameters, 'UPDATE') || contains_word(parameters, 'DROP') || contains_word(parameters, 'sqlite3'))"
  action: DENY
  reason: "Self-protection: preflight storage is tamper-protected."
  locked: true
```

Additional protections:
- The `signet_preflight_submit` MCP tool checks `is_preflight_locked()` before accepting
- No MCP tool exists for `signet_preflight_delete` or `signet_preflight_modify`
- The vault's SQLite file is already protected by the `protect_signet_dir` locked rule

### Escalation

When `violation_count` exceeds the threshold (default: 5):
1. Set `escalated = true` on the preflight record
2. All subsequent tool calls get an additional check: if escalated, return ASK for everything
3. The ASK reason: "Preflight escalated: {n} constraint violations. Task may need replanning."
4. Escalation persists until lockout expires or user overrides
5. This is the equivalent of ATC telling a pilot "you need to declare your intentions"

## 6. Self-Protection Rules

Add to `self_protection_rules()` in policy.rs:

```rust
PolicyRule {
    name: "protect_preflight_storage".into(),
    tool_pattern: ".*".into(),
    conditions: vec![
        "any_of(parameters, 'preflights', 'preflight_violations')".into(),
        "or(contains_word(parameters, 'DELETE') || contains_word(parameters, 'UPDATE') || contains_word(parameters, 'DROP') || contains_word(parameters, 'sqlite3'))".into(),
    ],
    action: Decision::Deny,
    locked: true,
    reason: Some("Self-protection: preflight records are tamper-protected.".into()),
    alternative: Some("Use signet_preflight_active or signet_preflight_violations to read your preflight data.".into()),
},
```

## 7. Hook Integration

In hook.rs, after hard rule evaluation:

```rust
pub fn run_hook(policy: &CompiledPolicy, vault: Option<&Vault>) -> i32 {
    // ... existing input parsing ...

    // Pass 1: Hard rules
    let result = policy::evaluate(&call, policy, vault);

    // If hard rules deny, short-circuit (no soft constraint can override)
    if result.decision == Decision::Deny {
        emit_and_log(result, vault, &call);
        return 0;
    }

    // Pass 2: Active preflight soft constraints
    if let Some(v) = vault {
        if let Some(preflight) = v.active_preflight() {
            // Check escalation first
            if preflight.escalated {
                emit_decision("ask", Some(format!(
                    "Preflight escalated: {} violations. Review required.", preflight.violation_count
                )));
                return 0;
            }
            // Evaluate soft constraints
            if let Some(violation) = evaluate_preflight(&call, &preflight) {
                v.log_preflight_violation(&violation);
                let reason = format!("{} Instead: {}", violation.reason, violation.alternative);
                emit_decision(violation.action.as_lowercase(), Some(reason));
                return 0;
            }
        }
    }

    // No violation — emit the hard rule result (Allow or Ask)
    emit_and_log(result, vault, &call);
    0
}
```

## 8. CLI Addition

```rust
/// Show active preflight status
PreflightStatus,

/// Override (end) an active preflight early (requires vault passphrase)
PreflightOverride,
```

`preflight-status` is read-only, usable by agents.
`preflight-override` requires vault passphrase — human-only escape hatch.
