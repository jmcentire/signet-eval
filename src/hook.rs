//! Hook I/O — reads Claude Code PreToolUse JSON from stdin, returns decision on stdout.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read};

use crate::policy::{self, CompiledPolicy, Decision, ToolCall};
use crate::vault::Vault;

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

    let result = policy::evaluate(&call, policy, vault);

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
        let amt = if result.decision == Decision::Allow { amount } else { 0.0 };
        v.log_action(&call.tool_name, result.decision.as_lowercase(), category, amt, &detail[..detail.len().min(500)]);
    }

    emit_decision(
        result.decision.as_lowercase(),
        if result.decision != Decision::Allow { result.reason } else { None },
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
