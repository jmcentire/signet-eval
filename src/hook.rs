//! Hook I/O — reads Claude Code PreToolUse JSON from stdin, returns decision on stdout.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wait_timeout::ChildExt;

use crate::policy::{self, CompiledPolicy, Decision, EnsureConfig, EvaluationResult, ToolCall};
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
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    additional_context: Option<String>,
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
    // Full disable — bypass everything silently
    if crate::vault::is_disabled_file() {
        emit_allow();
        return 0;
    }

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
    // File-based global pause OR session-scoped global pause from pauses.json
    if crate::vault::is_paused_file() || crate::vault::is_globally_paused_json() {
        let result = policy::evaluate(&call, policy, vault);
        if result.decision == Decision::Deny && result.matched_locked {
            // Self-protection: locked deny always enforced during pause
            emit_decision("deny", result.reason, None);
            return 0;
        }
        if result.decision == Decision::Ensure && result.matched_locked {
            // Self-protection: locked ensure (e.g., identity guard) enforced during pause
            let resolved = resolve_ensure_result(result);
            if resolved.decision == Decision::Deny {
                emit_decision("deny", resolved.reason, None);
                return 0;
            }
        }
        // Not a locked rule — allow during pause
        emit_decision("allow", None, None);
        return 0;
    }

    // Pass 1: Evaluate against compiled hard rules
    let result = policy::evaluate(&call, policy, vault);

    // Resolve Ensure: run check script, convert to Allow/Deny
    let result = if result.decision == Decision::Ensure {
        resolve_ensure_result(result)
    } else {
        result
    };

    // Per-rule pause: if the matched (non-locked) rule is paused, allow silently
    let result = if result.decision != Decision::Allow && !result.matched_locked {
        if let Some(ref rule_name) = result.matched_rule {
            if crate::vault::is_rule_paused(rule_name) {
                EvaluationResult { decision: Decision::Allow, ..result }
            } else { result }
        } else { result }
    } else { result };

    // Hard deny always wins — short-circuit
    let (final_decision, final_reason, final_context) = if result.decision == Decision::Deny {
        (result.decision, result.reason, None)
    } else {
        // Pass 2: Check active preflight soft constraints
        match vault.and_then(|v| {
            let preflight = v.active_preflight()?;
            Some((v, preflight))
        }) {
            Some((v, preflight)) => {
                if preflight.escalated {
                    // Escalated preflight — build rich context for Claude and user
                    let violations = v.preflight_violations(&preflight.id);

                    // Group violations by constraint
                    let mut by_constraint: std::collections::HashMap<String, Vec<String>> =
                        std::collections::HashMap::new();
                    for viol in violations.iter().take(20) {
                        by_constraint
                            .entry(viol.constraint_name.clone())
                            .or_default()
                            .push(format!("{}({})", viol.tool_name,
                                &viol.parameters_summary[..viol.parameters_summary.len().min(60)]));
                    }

                    // Build constraint detail block
                    let mut constraint_detail = String::new();
                    for constraint in &preflight.constraints {
                        constraint_detail.push_str(&format!(
                            "\n  - [{}] {} ({}): {}\n    INSTEAD: {}",
                            constraint.action, constraint.name,
                            constraint.tool_pattern, constraint.reason, constraint.alternative
                        ));
                        if let Some(hits) = by_constraint.get(&constraint.name) {
                            constraint_detail.push_str(&format!(
                                "\n    YOU DID THIS {} TIME(S): {}",
                                hits.len(), hits.join("; ")
                            ));
                        }
                    }

                    let task_short = if preflight.task.len() > 80 {
                        format!("{}...", &preflight.task[..77])
                    } else {
                        preflight.task.clone()
                    };

                    let context = format!(
                        "CRITICAL — PREFLIGHT ESCALATED\n\
                         \n\
                         Your task: {task}\n\
                         Violations: {count}\n\
                         \n\
                         You repeatedly violated constraints that were set BEFORE you started working. \
                         ALL tool calls now require human approval until this is resolved.\n\
                         \n\
                         Constraints and what you did wrong:{detail}\n\
                         \n\
                         YOU MUST:\n\
                         1. STOP your current approach immediately\n\
                         2. Tell the user: your preflight constraints escalated, explain which ones and why\n\
                         3. For each violated constraint, explain the alternative approach you should have used\n\
                         4. Ask the user how to proceed — they can clear the escalation once you change approach\n\
                         \n\
                         Do NOT continue with the approach that caused these violations. \
                         Do NOT try to work around the constraints. Change your approach.",
                        task = preflight.task,
                        count = preflight.violation_count,
                        detail = constraint_detail,
                    );

                    let reason = format!(
                        "PREFLIGHT ESCALATED: '{}' — {} violations. Claude should explain what went wrong.",
                        task_short, preflight.violation_count
                    );

                    (Decision::Ask, Some(reason), Some(context))
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

                            // Build context so Claude knows what it violated
                            let context = format!(
                                "PREFLIGHT CONSTRAINT VIOLATED: '{}'\n\
                                 Task: {}\n\
                                 Rule: {}\n\
                                 Alternative: {}\n\
                                 \n\
                                 You MUST use the alternative approach described above. \
                                 Do NOT retry the same action. If you keep violating constraints, \
                                 your preflight will escalate and ALL tool calls will require manual approval.",
                                constraint.name, preflight.task,
                                constraint.reason, constraint.alternative,
                            );

                            // Parse constraint action
                            let decision = match constraint.action.to_uppercase().as_str() {
                                "DENY" => Decision::Deny,
                                "ASK" => Decision::Ask,
                                _ => Decision::Ask,
                            };
                            (decision, Some(reason), Some(context))
                        }
                        None => {
                            // No soft constraint matched — use Pass 1 result
                            (result.decision, result.reason, None)
                        }
                    }
                }
            }
            None => {
                // No active preflight — use Pass 1 result
                (result.decision, result.reason, None)
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
        final_context,
    );
    0
}

fn emit_decision(decision: &str, reason: Option<String>, additional_context: Option<String>) {
    let response = HookResponse {
        hook_specific_output: HookOutput {
            hook_event_name: "PreToolUse".into(),
            permission_decision: decision.into(),
            reason,
            additional_context,
        },
    };
    println!("{}", serde_json::to_string(&response).unwrap());
}

fn emit_allow() {
    emit_decision("allow", None, None);
}

fn emit_deny(reason: &str) {
    emit_decision("deny", Some(reason.into()), None);
}

/// Run an ensure check script and return (passed, stderr_output).
/// For unlocked rules, missing scripts resolve gracefully (allow).
/// For locked rules, missing scripts fail closed (deny).
fn resolve_ensure(config: &EnsureConfig, locked: bool) -> (bool, String) {
    let script_path = match policy::resolve_ensure_script_path(&config.check) {
        Ok(p) => p,
        Err(e) => {
            if locked {
                return (false, e);
            } else {
                // Unlocked ensure: script not installed yet, allow gracefully
                return (true, String::new());
            }
        }
    };

    if !script_path.exists() {
        if locked {
            return (false, format!("Check script not found: {}", script_path.display()));
        } else {
            // Unlocked ensure: script not installed yet, allow gracefully
            return (true, String::new());
        }
    }

    let timeout_secs = config.timeout.max(1).min(30) as u64;

    let mut child = match Command::new(&script_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (false, format!("Failed to spawn check script: {e}")),
    };

    match child.wait_timeout(Duration::from_secs(timeout_secs)) {
        Ok(Some(status)) => {
            let stderr = child.stderr.take()
                .and_then(|mut s| {
                    let mut buf = Vec::new();
                    io::Read::read_to_end(&mut s, &mut buf).ok()?;
                    Some(String::from_utf8_lossy(&buf[..buf.len().min(500)]).to_string())
                })
                .unwrap_or_default();
            if status.success() {
                (true, String::new())
            } else {
                (false, stderr)
            }
        }
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            (false, format!("Check script timed out after {timeout_secs}s"))
        }
        Err(e) => {
            (false, format!("Error waiting for check script: {e}"))
        }
    }
}

/// Resolve an Ensure evaluation result by running the check script.
fn resolve_ensure_result(result: EvaluationResult) -> EvaluationResult {
    if let Some(ref ensure_config) = result.ensure_config {
        let (passed, stderr) = resolve_ensure(ensure_config, result.matched_locked);
        if passed {
            EvaluationResult {
                decision: Decision::Allow,
                ensure_config: None,
                ..result
            }
        } else {
            let msg = if ensure_config.message.is_empty() {
                format!("Ensure check '{}' failed", ensure_config.check)
            } else {
                ensure_config.message.clone()
            };
            let reason = if stderr.is_empty() {
                msg
            } else {
                format!("{msg} -- {stderr}")
            };
            EvaluationResult {
                decision: Decision::Deny,
                reason: Some(reason),
                ensure_config: None,
                ..result
            }
        }
    } else {
        // Ensure without config — misconfigured, deny
        EvaluationResult {
            decision: Decision::Deny,
            reason: Some("Ensure rule missing ensure config".into()),
            ensure_config: None,
            ..result
        }
    }
}
