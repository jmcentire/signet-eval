//! Signet MCP Management Server — manage policies conversationally through Claude.

use rmcp::model::*;
use rmcp::{RoleServer, ServerHandler, Error as McpError, Service};
use rmcp::service::RequestContext;
use serde_json::Value;
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;

use crate::policy::{PolicyConfig, PolicyRule, Decision};
use crate::vault;

fn policy_path() -> PathBuf {
    vault::signet_dir().join("policy.yaml")
}

fn load_policy_raw() -> PolicyConfig {
    let path = policy_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_yaml::from_str(&content).unwrap_or_default(),
        Err(_) => PolicyConfig::default(),
    }
}

fn save_policy(config: &PolicyConfig) {
    let path = policy_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Ok(yaml) = serde_yaml::to_string(config) {
        std::fs::write(&path, &yaml).ok();
    }
}

/// Auto-sign the policy after MCP modifications (if vault is available).
fn auto_sign_policy() {
    if let Some(v) = vault::try_load_vault() {
        let path = policy_path();
        let _ = vault::sign_policy(v.session_key(), &path);
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig { version: 1, rules: vec![], default_action: Decision::Allow }
    }
}

fn make_tool(name: &'static str, desc: &'static str, schema: serde_json::Value) -> Tool {
    let obj: serde_json::Map<String, Value> = match schema {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    let mut tool = Tool::default();
    tool.name = Cow::Borrowed(name);
    tool.description = Some(Cow::Borrowed(desc));
    tool.input_schema = Arc::new(obj);
    tool
}

pub struct SignetMcpServer;

impl ServerHandler for SignetMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.instructions = Some("Signet policy enforcement for Claude Code. Use these tools to manage what actions are allowed, denied, or require confirmation.".into());
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .build();
        info
    }

    fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        async {
            let tools = vec![
                make_tool("signet_list_rules", "List all current policy rules. Shows what's blocked, allowed, or requires confirmation.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_add_rule", "Add a policy rule. Action must be ALLOW, DENY, or ASK.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Rule name (e.g. 'block_rm', 'limit_amazon')"},
                        "action": {"type": "string", "description": "ALLOW, DENY, or ASK"},
                        "reason": {"type": "string", "description": "Why this rule exists"},
                        "tool_pattern": {"type": "string", "description": "Regex matching tool names (default '.*')", "default": ".*"},
                        "conditions": {"type": "array", "items": {"type": "string"}, "description": "Condition expressions"}
                    },
                    "required": ["name", "action", "reason"]
                })),
                make_tool("signet_remove_rule", "Remove a policy rule by name.", serde_json::json!({
                    "type": "object",
                    "properties": {"name": {"type": "string", "description": "Rule name to remove"}},
                    "required": ["name"]
                })),
                make_tool("signet_set_limit", "Set a spending limit for a category.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Spending category (e.g. 'books', 'amazon')"},
                        "max_amount": {"type": "number", "description": "Maximum spend in dollars"},
                        "per": {"type": "string", "description": "'session' or 'total'", "default": "session"},
                        "tool_pattern": {"type": "string", "description": "Regex for purchase tool names", "default": ".*purchase.*|.*buy.*|.*shop.*|.*order.*"}
                    },
                    "required": ["category", "max_amount"]
                })),
                make_tool("signet_status", "Show vault status, spending totals, credential count.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_recent_actions", "Show recent action log.", serde_json::json!({
                    "type": "object",
                    "properties": {"limit": {"type": "integer", "description": "Number of actions to show", "default": 20}},
                })),
                make_tool("signet_store_credential", "Store a Tier 3 credential (compartment-encrypted).", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Credential name (e.g. 'cc_visa')"},
                        "value": {"type": "string", "description": "Secret value to store"}
                    },
                    "required": ["name", "value"]
                })),
                make_tool("signet_list_credentials", "List credential names (not values).", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_delete_credential", "Delete a credential from the vault.", serde_json::json!({
                    "type": "object",
                    "properties": {"name": {"type": "string", "description": "Credential name to delete"}},
                    "required": ["name"]
                })),
                make_tool("signet_validate", "Validate the current policy file for errors (bad regex, unknown functions).", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_test", "Test a tool call against the current policy without executing it.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string", "description": "Tool name (e.g. 'Bash', 'Write')"},
                        "tool_input": {"type": "object", "description": "Tool arguments as JSON object"}
                    },
                    "required": ["tool_name"]
                })),
                make_tool("signet_condition_help", "Show all available condition functions with descriptions and examples.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_reorder_rule", "Move a rule to a new position (1-based). Critical since first-match-wins.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Rule name to move"},
                        "position": {"type": "integer", "description": "New position (1-based, 1 = first/highest priority)"}
                    },
                    "required": ["name", "position"]
                })),
                make_tool("signet_edit_rule", "Edit an existing rule's properties.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Rule name to edit"},
                        "action": {"type": "string", "description": "New action (ALLOW/DENY/ASK)"},
                        "reason": {"type": "string", "description": "New reason"},
                        "tool_pattern": {"type": "string", "description": "New tool pattern regex"},
                        "conditions": {"type": "array", "items": {"type": "string"}, "description": "New conditions (replaces existing)"}
                    },
                    "required": ["name"]
                })),
                make_tool("signet_sign_policy", "Sign the policy file with HMAC for tamper detection.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_reset_session", "Reset session spending counters.", serde_json::json!({"type": "object", "properties": {}})),
                make_tool("signet_use_credential", "Request a credential through the policy-gated capability system. Enforces domain, purpose, amount, and one-time constraints.", serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Credential name (e.g. 'cc_visa')"},
                        "domain": {"type": "string", "description": "Domain for this use (e.g. 'amazon.com')", "default": ""},
                        "amount": {"type": "number", "description": "Transaction amount (checked against max_amount constraint)", "default": 0},
                        "purpose": {"type": "string", "description": "Purpose of use (e.g. 'purchase')", "default": ""}
                    },
                    "required": ["name"]
                })),
            ];
            Ok(ListToolsResult { tools, next_cursor: None, meta: None })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
            let empty = serde_json::Map::new();
            let args_map = request.arguments.as_ref().unwrap_or(&empty);
            let args = &args_map;
            let result = match &*request.name {
                "signet_list_rules" => handle_list_rules(),
                "signet_add_rule" => handle_add_rule(args),
                "signet_remove_rule" => handle_remove_rule(args),
                "signet_set_limit" => handle_set_limit(args),
                "signet_status" => handle_status(),
                "signet_recent_actions" => handle_recent_actions(args),
                "signet_store_credential" => handle_store_credential(args),
                "signet_list_credentials" => handle_list_credentials(),
                "signet_delete_credential" => handle_delete_credential(args),
                "signet_validate" => handle_validate(),
                "signet_test" => handle_test(args),
                "signet_condition_help" => handle_condition_help(),
                "signet_reorder_rule" => handle_reorder_rule(args),
                "signet_edit_rule" => handle_edit_rule(args),
                "signet_sign_policy" => handle_sign_policy(),
                "signet_reset_session" => handle_reset_session(),
                "signet_use_credential" => handle_use_credential(args),
                _ => format!("Unknown tool: {}", request.name),
            };
            Ok(CallToolResult::success(vec![Content::text(result)]))
        }
    }
}

// === Tool Handlers ===

fn handle_list_rules() -> String {
    let config = load_policy_raw();
    if config.rules.is_empty() {
        return format!("No rules. Default action: {:?}. Everything is allowed.", config.default_action);
    }
    let mut lines = vec![
        format!("Default: {:?}", config.default_action),
        format!("Rules ({}):\n", config.rules.len()),
    ];
    for (i, r) in config.rules.iter().enumerate() {
        let lock_tag = if r.locked { " [LOCKED]" } else { "" };
        lines.push(format!("  {}. [{:?}] {}{}", i + 1, r.action, r.name, lock_tag));
        if let Some(ref reason) = r.reason {
            lines.push(format!("     Reason: {reason}"));
        }
        if r.tool_pattern != ".*" {
            lines.push(format!("     Tools: {}", r.tool_pattern));
        }
        for c in &r.conditions {
            lines.push(format!("     Condition: {c}"));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

fn handle_add_rule(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let action_str = args.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let reason = args.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    let tool_pattern = args.get("tool_pattern").and_then(|v| v.as_str()).unwrap_or(".*");
    let conditions: Vec<String> = args.get("conditions")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let action = match action_str.to_uppercase().as_str() {
        "ALLOW" => Decision::Allow,
        "DENY" => Decision::Deny,
        "ASK" => Decision::Ask,
        _ => return format!("Invalid action '{action_str}'. Must be ALLOW, DENY, or ASK."),
    };

    let mut config = load_policy_raw();
    if config.rules.iter().any(|r| r.name == name) {
        return format!("Rule '{name}' already exists. Remove it first.");
    }

    config.rules.push(PolicyRule {
        name: name.into(), tool_pattern: tool_pattern.into(),
        conditions, action, reason: Some(reason.into()),
        locked: false,
    });
    save_policy(&config);
    auto_sign_policy();
    format!("Added rule '{name}' ({action:?}): {reason}")
}

fn handle_remove_rule(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let mut config = load_policy_raw();
    if let Some(rule) = config.rules.iter().find(|r| r.name == name) {
        if rule.locked {
            return format!("Cannot remove rule '{name}': rule is locked (self-protection).");
        }
    }
    let before = config.rules.len();
    config.rules.retain(|r| r.name != name);
    if config.rules.len() == before {
        return format!("Rule '{name}' not found.");
    }
    save_policy(&config);
    auto_sign_policy();
    format!("Removed rule '{name}'.")
}

fn handle_set_limit(args: &serde_json::Map<String, Value>) -> String {
    let category = args.get("category").and_then(|v| v.as_str()).unwrap_or("");
    let max_amount = args.get("max_amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let per = args.get("per").and_then(|v| v.as_str()).unwrap_or("session");
    let tool_pattern = args.get("tool_pattern").and_then(|v| v.as_str())
        .unwrap_or(".*purchase.*|.*buy.*|.*shop.*|.*order.*");

    let name = format!("limit_{}_{}", category, max_amount as u64);

    let mut config = load_policy_raw();
    config.rules.retain(|r| r.name != name);
    config.rules.push(PolicyRule {
        name: name.clone(),
        tool_pattern: tool_pattern.into(),
        conditions: vec![
            format!("param_eq(category, '{category}')"),
            format!("spend_plus_amount_gt('{category}', amount, {max_amount})"),
        ],
        action: Decision::Deny,
        reason: Some(format!("Spending limit: ${max_amount:.0}/{per} on {category}")),
        locked: false,
    });
    save_policy(&config);
    auto_sign_policy();
    format!("Set ${max_amount:.0}/{per} limit on {category}.")
}

fn handle_status() -> String {
    let config = load_policy_raw();
    let mut lines = vec![
        format!("Policy: {} rules (default: {:?})", config.rules.len(), config.default_action),
    ];
    if !vault::vault_exists() {
        lines.push("Vault: not set up (run: signet-eval setup)".into());
        return lines.join("\n");
    }
    match vault::try_load_vault() {
        Some(v) => {
            lines.push("Vault: unlocked".into());
            lines.push(format!("Credentials: {}", v.list_credentials().len()));
            let spend = v.session_spend("");
            if spend > 0.0 { lines.push(format!("Session spend: ${spend:.2}")); }
            let actions = v.recent_actions(5);
            if !actions.is_empty() {
                lines.push(format!("\nLast {} actions:", actions.len()));
                for a in &actions {
                    let tool = a["tool"].as_str().unwrap_or("?");
                    let dec = a["decision"].as_str().unwrap_or("?");
                    let amt = a["amount"].as_f64().unwrap_or(0.0);
                    let cat = a["category"].as_str().unwrap_or("");
                    if amt > 0.0 { lines.push(format!("  {tool} [{cat}] ${amt:.2} -> {dec}")); }
                    else { lines.push(format!("  {tool} -> {dec}")); }
                }
            }
        }
        None => lines.push("Vault: locked".into()),
    }
    lines.join("\n")
}

fn handle_recent_actions(args: &serde_json::Map<String, Value>) -> String {
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as u32;
    match vault::try_load_vault() {
        Some(v) => {
            let actions = v.recent_actions(limit);
            if actions.is_empty() { return "No actions recorded.".into(); }
            let mut lines = vec![format!("Recent actions ({}):", actions.len())];
            for a in &actions {
                let tool = a["tool"].as_str().unwrap_or("?");
                let dec = a["decision"].as_str().unwrap_or("?");
                let amt = a["amount"].as_f64().unwrap_or(0.0);
                let cat = a["category"].as_str().unwrap_or("");
                if amt > 0.0 { lines.push(format!("  {tool} [{cat}] ${amt:.2} -> {dec}")); }
                else { lines.push(format!("  {tool} -> {dec}")); }
            }
            lines.join("\n")
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_store_credential(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let value = args.get("value").and_then(|v| v.as_str()).unwrap_or("");
    match vault::try_load_vault() {
        Some(v) => {
            v.store_credential(name, value, 3);
            format!("Stored '{name}' (Tier 3 compartment-encrypted).")
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_list_credentials() -> String {
    match vault::try_load_vault() {
        Some(v) => {
            let creds = v.list_credentials();
            if creds.is_empty() { return "No credentials stored.".into(); }
            let mut lines = vec![format!("Credentials ({}):", creds.len())];
            for c in &creds {
                let name = c["name"].as_str().unwrap_or("?");
                let tier = c["tier"].as_i64().unwrap_or(0);
                lines.push(format!("  {name} (Tier {tier})"));
            }
            lines.join("\n")
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_delete_credential(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    match vault::try_load_vault() {
        Some(v) => {
            if v.delete_credential(name) {
                format!("Deleted credential '{name}'.")
            } else {
                format!("Credential '{name}' not found.")
            }
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_validate() -> String {
    let path = policy_path();
    match crate::policy::load_policy_config(&path) {
        Ok(config) => {
            let errors = crate::policy::validate_policy(&config);
            if errors.is_empty() {
                format!("Policy valid: {} rules, no errors.", config.rules.len())
            } else {
                let mut lines = vec![format!("Policy has {} error(s):", errors.len())];
                for e in &errors {
                    lines.push(format!("  - {e}"));
                }
                lines.join("\n")
            }
        }
        Err(e) => format!("Cannot load policy: {e}"),
    }
}

fn handle_test(args: &serde_json::Map<String, Value>) -> String {
    let tool_name = args.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
    let tool_input = args.get("tool_input").cloned().unwrap_or(serde_json::Value::Object(Default::default()));

    let path = policy_path();
    let policy = crate::policy::load_policy(&path);
    let v = vault::try_load_vault();
    let call = crate::policy::ToolCall {
        tool_name: tool_name.to_string(),
        parameters: tool_input,
    };
    let result = crate::policy::evaluate(&call, &policy, v.as_ref());
    let mut lines = vec![
        format!("Decision: {:?}", result.decision),
    ];
    if let Some(rule) = &result.matched_rule {
        lines.push(format!("Matched rule: {rule}"));
    } else {
        lines.push("Matched rule: (none — default action)".into());
    }
    if let Some(reason) = &result.reason {
        lines.push(format!("Reason: {reason}"));
    }
    lines.push(format!("Eval time: {}us", result.evaluation_time_us));
    lines.join("\n")
}

fn handle_reorder_rule(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let position = args.get("position").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    if position == 0 { return "Position must be >= 1".into(); }

    let mut config = load_policy_raw();
    let idx = config.rules.iter().position(|r| r.name == name);
    match idx {
        None => format!("Rule '{name}' not found."),
        Some(old_idx) => {
            if config.rules[old_idx].locked {
                return format!("Cannot reorder rule '{name}': rule is locked (self-protection).");
            }
            let rule = config.rules.remove(old_idx);
            let new_idx = (position - 1).min(config.rules.len());
            // Prevent placing unlocked rules before any locked rules
            let first_unlocked = config.rules.iter().position(|r| !r.locked).unwrap_or(config.rules.len());
            let safe_idx = new_idx.max(first_unlocked);
            config.rules.insert(safe_idx, rule);
            save_policy(&config);
            auto_sign_policy();
            let actual_pos = safe_idx + 1;
            format!("Moved rule '{name}' to position {actual_pos}.")
        }
    }
}

fn handle_edit_rule(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let mut config = load_policy_raw();
    let rule = config.rules.iter_mut().find(|r| r.name == name);
    match rule {
        None => format!("Rule '{name}' not found."),
        Some(rule) => {
            if rule.locked {
                return format!("Cannot edit rule '{name}': rule is locked (self-protection).");
            }
            let mut changes = Vec::new();
            if let Some(action_str) = args.get("action").and_then(|v| v.as_str()) {
                match action_str.to_uppercase().as_str() {
                    "ALLOW" => { rule.action = Decision::Allow; changes.push("action"); }
                    "DENY" => { rule.action = Decision::Deny; changes.push("action"); }
                    "ASK" => { rule.action = Decision::Ask; changes.push("action"); }
                    _ => return format!("Invalid action '{action_str}'."),
                }
            }
            if let Some(reason) = args.get("reason").and_then(|v| v.as_str()) {
                rule.reason = Some(reason.into());
                changes.push("reason");
            }
            if let Some(pattern) = args.get("tool_pattern").and_then(|v| v.as_str()) {
                rule.tool_pattern = pattern.into();
                changes.push("tool_pattern");
            }
            if let Some(conds) = args.get("conditions").and_then(|v| v.as_array()) {
                rule.conditions = conds.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                changes.push("conditions");
            }
            save_policy(&config);
            auto_sign_policy();
            format!("Updated rule '{name}': changed {}", changes.join(", "))
        }
    }
}

fn handle_sign_policy() -> String {
    match vault::try_load_vault() {
        Some(v) => {
            let path = policy_path();
            match vault::sign_policy(v.session_key(), &path) {
                Ok(_) => "Policy signed. HMAC written.".into(),
                Err(e) => format!("Error signing: {e}"),
            }
        }
        None => "Vault not set up or locked (needed for signing key).".into(),
    }
}

fn handle_reset_session() -> String {
    match vault::try_load_vault() {
        Some(mut v) => {
            v.reset_session();
            "Session reset. Spending counters cleared.".into()
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_use_credential(args: &serde_json::Map<String, Value>) -> String {
    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let domain = args.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let amount = args.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let purpose = args.get("purpose").and_then(|v| v.as_str()).unwrap_or("");

    match vault::try_load_vault() {
        Some(v) => {
            match v.request_capability(name, domain, amount, purpose) {
                Ok(value) => {
                    // Mask the credential in the response — show last 4 chars only
                    let masked = if value.len() > 4 {
                        format!("{}...{}", "*".repeat(value.len() - 4), &value[value.len()-4..])
                    } else {
                        "*".repeat(value.len())
                    };
                    format!("Credential '{name}' released (masked: {masked}). Domain: {domain}, Amount: ${amount:.2}, Purpose: {purpose}")
                }
                Err(e) => format!("Credential request denied: {e}"),
            }
        }
        None => "Vault not set up or locked.".into(),
    }
}

fn handle_condition_help() -> String {
    r#"Available condition functions:

  contains(parameters, 'text')        — serialized tool input contains string
  any_of(parameters, 'a', 'b', ...)   — any of the strings present in tool input
  param_eq(field, 'value')             — parameter field equals value
  param_ne(field, 'value')             — parameter field not equal to value
  param_gt(field, number)              — parameter field > number
  param_lt(field, number)              — parameter field < number
  param_contains(field, 'substr')      — parameter field contains substring
  matches(field, 'regex')              — parameter field matches regex pattern
  has_credential('name')               — credential exists in vault
  spend_gt('category', limit)          — session spend > limit
  spend_plus_amount_gt('cat', field, limit) — session spend + param > limit
  not(condition)                       — negate any condition
  or(cond1 || cond2)                   — either condition is true
  true / false                         — literal boolean

Multiple conditions on a rule are AND'd together. Use or() for OR logic.

Examples:
  Block rm:              contains(parameters, 'rm ')
  Books limit $200:      spend_plus_amount_gt('books', amount, 200)
  Only allow JSON:       not(param_eq(format, 'json'))
  Block large purchases: param_gt(amount, 500)
  Block IP access:       matches(host, '^\d+\.\d+\.\d+\.\d+$')"#.into()
}

/// Run the MCP management server on stdio.
pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let server = SignetMcpServer;
    let service = rmcp::serve_server(server, rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
