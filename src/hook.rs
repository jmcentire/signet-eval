//! Hook I/O — reads Claude Code PreToolUse JSON from stdin, returns decision on stdout.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::policy::{self, CompiledPolicy, Decision, ToolCall};
use crate::vault::{Preflight, PreflightViolation, SoftConstraint, Vault};

#[derive(Deserialize)]
struct HookInput {
    tool_name: String,
    #[serde(alias = "tool_input")]
    parameters: Option<Value>,
}

/// Claude Code expects hook responses wrapped in hookSpecificOutput.
#[derive(Serialize)]
struct HookResponse {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookOutput,
}

#[derive(Serialize)]
struct HookOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    permission_decision: String,
    #[serde(rename = "permissionDecisionReason", skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Evaluate a tool call against preflight soft constraints.
/// Returns the first matching constraint (if any).
fn evaluate_preflight_constraint(
    call: &ToolCall,
    preflight: &Preflight,
    vault: &Vault,
) -> Option<(SoftConstraint, String)> {
    for constraint in &preflight.constraints {
        // Check tool pattern
        let re = match regex::Regex::new(&constraint.tool_pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !re.is_match(&call.tool_name) {
            continue;
        }
        // Check all conditions (AND)
        let mut all_match = true;
        for cond in &constraint.conditions {
            match policy::evaluate_condition(cond, call, Some(vault)) {
                Ok(true) => {},
                _ => { all_match = false; break; },
            }
        }
        if all_match {
            let reason = format!("{} Instead: {}", constraint.reason, constraint.alternative);
            return Some((constraint.clone(), reason));
        }
    }
    None
}

pub fn run_hook(policy: &CompiledPolicy, vault: Option<&Vault>) -> i32 {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        emit_deny("Failed to read stdin");
        return 0;
    }

    let hook_input: HookInput = match serde_json::from_str(&input) {
        Ok(h) => h,
        Err(_) => {
            emit_deny("Malformed hook input");
            return 0;
        }
    };

    let call = ToolCall {
        tool_name: hook_input.tool_name.clone(),
        parameters: hook_input.parameters.unwrap_or(Value::Object(Default::default())),
    };

    // Check if paused — if so, only enforce locked (self-protection) rules
    if let Some(v) = vault {
        if v.is_paused() {
            let result = policy::evaluate(&call, policy, vault);
            if result.decision == Decision::Deny && result.matched_locked {
                // Self-protection still enforced during pause
                emit_decision("deny", result.reason);
                return 0;
            }
            // Not a locked rule — allow during pause
            emit_decision("allow", None);
            return 0;
        }
    }

    // Pass 1: Evaluate against compiled hard rules
    let result = policy::evaluate(&call, policy, vault);

    // Hard deny always wins — short-circuit
    let (final_decision, final_reason) = if result.decision == Decision::Deny {
        (result.decision, result.reason)
    } else {
        // Pass 2: Check active preflight soft constraints
        match vault.and_then(|v| {
            let preflight = v.active_preflight()?;
            Some((v, preflight))
        }) {
            Some((v, preflight)) => {
                if preflight.escalated {
                    // Escalated preflight — require human review for everything
                    let reason = format!(
                        "Preflight escalated: {} violations. Review required.",
                        preflight.violation_count
                    );
                    (Decision::Ask, Some(reason))
                } else {
                    // Evaluate soft constraints
                    match evaluate_preflight_constraint(&call, &preflight, v) {
                        Some((constraint, reason)) => {
                            // Log the violation
                            let detail = serde_json::to_string(&call.parameters).unwrap_or_default();
                            let violation = PreflightViolation {
                                preflight_id: preflight.id.clone(),
                                constraint_name: constraint.name.clone(),
                                tool_name: call.tool_name.clone(),
                                parameters_summary: detail[..detail.len().min(200)].to_string(),
                                alternative: constraint.alternative.clone(),
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            };
                            let _ = v.log_preflight_violation(&violation);

                            // Parse constraint action
                            let decision = match constraint.action.to_uppercase().as_str() {
                                "DENY" => Decision::Deny,
                                "ASK" => Decision::Ask,
                                _ => Decision::Ask,
                            };
                            (decision, Some(reason))
                        }
                        None => {
                            // No soft constraint matched — use Pass 1 result
                            (result.decision, result.reason)
                        }
                    }
                }
            }
            None => {
                // No active preflight — use Pass 1 result
                (result.decision, result.reason)
            }
        }
    };

    // Log to vault if available
    if let Some(v) = vault {
        let params = &call.parameters;
        let amount: f64 = params.get("amount")
            .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(0.0);
        let category = params.get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let detail = serde_json::to_string(params).unwrap_or_default();
        let amt = if final_decision == Decision::Allow { amount } else { 0.0 };
        v.log_action(&call.tool_name, final_decision.as_lowercase(), category, amt, &detail[..detail.len().min(500)]);
    }

    emit_decision(
        final_decision.as_lowercase(),
        if final_decision != Decision::Allow { final_reason } else { None },
    );
    0
}

fn emit_decision(decision: &str, reason: Option<String>) {
    let response = HookResponse {
        hook_specific_output: HookOutput {
            hook_event_name: "PreToolUse".into(),
            permission_decision: decision.into(),
            reason,
        },
    };
    println!("{}", serde_json::to_string(&response).unwrap());
}

fn emit_deny(reason: &str) {
    emit_decision("deny", Some(reason.into()));
}
