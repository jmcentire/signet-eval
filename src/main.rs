mod hook;
mod policy;
mod vault;

#[cfg(feature = "mcp")]
mod mcp_server;
#[cfg(feature = "mcp")]
mod mcp_proxy;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "signet-eval", version, about = "Claude Code policy enforcement")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to policy file
    #[arg(long, default_value = "~/.signet/policy.yaml")]
    policy_path: String,
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate a tool call from stdin (default, hook mode)
    Eval,
    /// Initialize default policy file
    Init,
    /// Create encrypted vault with passphrase
    Setup,
    /// Show vault status and recent actions
    Status,
    /// Store a Tier 3 credential
    Store {
        /// Credential name
        name: String,
        /// Credential value
        value: String,
    },
    /// Show current policy rules
    Rules,
    /// Show recent actions from the vault ledger
    Log {
        /// Number of entries to show
        #[arg(long, default_value = "20")]
        limit: u32,
    },
    /// Test a policy against sample JSON input
    Test {
        /// JSON tool call, e.g. '{"tool_name":"Bash","tool_input":{"command":"rm foo"}}'
        json: String,
    },
    /// Delete a credential from the vault
    Delete {
        /// Credential name to delete
        name: String,
    },
    /// Reset session — clears spending counters for the current session
    ResetSession,
    /// Sign the policy file (HMAC integrity protection)
    Sign,
    /// Unlock vault and refresh session key
    Unlock,
    /// Validate the policy file
    Validate,
    /// Run MCP management server (conversational policy editing)
    #[cfg(feature = "mcp")]
    Serve,
    /// Run MCP proxy (wraps upstream servers with policy enforcement)
    #[cfg(feature = "mcp")]
    Proxy,
    /// Show active preflight status
    PreflightStatus,
    /// Override (end) an active preflight early (requires vault passphrase)
    PreflightOverride,
    /// Pause policy enforcement for N minutes (self-protection still active)
    Pause {
        /// Duration in minutes (1-60)
        #[arg(default_value = "10")]
        minutes: u32,
    },
    /// Resume policy enforcement (end pause early)
    Resume,
    /// Fully disable policy enforcement (bypasses everything including self-protection)
    Disable,
    /// Re-enable policy enforcement after disable
    Enable,
}

fn expand_home(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

fn run() -> i32 {
    let cli = Cli::parse();
    let policy_path = expand_home(&cli.policy_path);

    match cli.command {
        None | Some(Command::Eval) => {
            let v = vault::try_load_vault();
            // If vault exists, verify policy HMAC — tampered files fall back to safe defaults.
            // Without vault, policy.yaml is loaded as-is (no cryptographic verification).
            // String matching is defense-in-depth, not a security boundary.
            // HMAC (requires vault setup) is the real integrity guarantee.
            if let Some(ref vault) = v {
                if !vault::verify_policy_integrity(vault.session_key(), &policy_path) {
                    eprintln!("WARNING: Policy integrity check failed. Using safe defaults.");
                    let compiled = policy::default_policy();
                    return hook::run_hook(&compiled, Some(vault));
                }
            }
            let compiled = policy::load_policy(&policy_path);
            hook::run_hook(&compiled, v.as_ref())
        }
        Some(Command::Init) => {
            let mut rules = policy::self_protection_rules();
            rules.extend(vec![
                policy::PolicyRule { name: "block_rm".into(), tool_pattern: "^Bash$".into(), conditions: vec!["contains(parameters, 'rm ')".into()], action: policy::Decision::Deny, locked: false, reason: Some("File deletion blocked.".into()), alternative: Some("Use 'trash <file>' (recoverable) or 'mv <file> /tmp/'.".into()), gate: None, ensure: None },
                policy::PolicyRule { name: "block_force_push".into(), tool_pattern: "^Bash$".into(), conditions: vec!["any_of(parameters, 'push --force', 'push -f')".into()], action: policy::Decision::Ask, locked: false, reason: Some("Force push can overwrite others' work.".into()), alternative: Some("Use 'git push --force-with-lease' or push to a new branch.".into()), gate: None, ensure: None },
                policy::PolicyRule { name: "block_destructive".into(), tool_pattern: "^Bash$".into(), conditions: vec!["or(contains_word(parameters, 'mkfs') || contains(parameters, 'dd if=') || contains(parameters, 'diskutil erase') || contains(parameters, 'wipefs'))".into()], action: policy::Decision::Deny, locked: false, reason: Some("Destructive disk ops blocked.".into()), alternative: Some("Write to a temp file first. Ask the user to execute disk operations directly.".into()), gate: None, ensure: None },
                policy::PolicyRule { name: "block_piped_exec".into(), tool_pattern: "^Bash$".into(), conditions: vec!["any_of(parameters, 'curl', 'wget')".into(), "contains(parameters, '| sh')".into()], action: policy::Decision::Deny, locked: false, reason: Some("Piped remote execution blocked.".into()), alternative: Some("Download first: 'curl -o /tmp/script.sh <url>', then inspect with 'cat'. Let the user review.".into()), gate: None, ensure: None },
                policy::PolicyRule { name: "block_credential_writes".into(), tool_pattern: "^(Write|Edit)$".into(), conditions: vec!["matches(file_path, '\\.(env|pem|key|secret|credentials)$')".into()], action: policy::Decision::Deny, locked: false, reason: Some("Writing to credential/secret files blocked.".into()), alternative: Some("Write to a '.example' file with placeholder values, then instruct the user to copy and fill in real credentials.".into()), gate: None, ensure: None },
                policy::PolicyRule { name: "block_chmod_777".into(), tool_pattern: "^Bash$".into(), conditions: vec!["contains(parameters, 'chmod 777')".into()], action: policy::Decision::Ask, locked: false, reason: Some("chmod 777 grants world-readable/writable/executable access.".into()), alternative: Some("Use minimum permissions: 'chmod 755' for executables, 'chmod 644' for files, 'chmod 600' for secrets.".into()), gate: None, ensure: None },
                policy::PolicyRule { name: "github_identity_guard".into(), tool_pattern: "^Bash$".into(), conditions: vec!["any_of(parameters, 'git push', 'git pull', 'git fetch', 'git clone')".into()], action: policy::Decision::Ensure, locked: false, reason: Some("Git remote operations must use the correct GitHub identity.".into()), alternative: Some("Run 'gh auth switch --user <correct_user>' to match the remote's org.".into()), gate: None, ensure: Some(policy::EnsureConfig { check: "gh-identity-matches-remote".into(), timeout: 15, message: "GitHub identity mismatch. Run: gh auth switch --user <correct_user>".into() }) },
            ]);
            let config = policy::PolicyConfig {
                version: 1,
                default_action: policy::Decision::Allow,
                rules,
            };
            let yaml = serde_yaml::to_string(&config).unwrap();
            if let Some(parent) = policy_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            match std::fs::write(&policy_path, &yaml) {
                Ok(_) => {
                    println!("Policy written to {}", policy_path.display());
                    // Auto-sign if vault exists
                    if let Some(v) = vault::try_load_vault() {
                        match vault::sign_policy(v.session_key(), &policy_path) {
                            Ok(_) => println!("Policy signed (HMAC verified on every eval)."),
                            Err(e) => eprintln!("Warning: could not sign policy: {e}"),
                        }
                    } else {
                        eprintln!("Warning: no vault. Run 'signet-eval setup' to enable HMAC verification.");
                        eprintln!("Without vault, only hardcoded default rules are enforced.");
                    }
                    0
                }
                Err(e) => { eprintln!("Error: {e}"); 1 }
            }
        }
        Some(Command::Setup) => {
            if vault::vault_exists() {
                eprintln!("Vault already exists. Delete ~/.signet/vault.meta to reset.");
                1
            } else {
                let pass = rpassword::prompt_password("Create vault passphrase: ").unwrap_or_default();
                let confirm = rpassword::prompt_password("Confirm passphrase: ").unwrap_or_default();
                if pass != confirm {
                    eprintln!("Passphrases don't match.");
                    1
                } else if pass.len() < 8 {
                    eprintln!("Passphrase must be at least 8 characters.");
                    1
                } else {
                    match vault::setup_vault(&pass) {
                        Ok(_) => { println!("Vault created. Session key cached."); 0 }
                        Err(e) => { eprintln!("Error: {e}"); 1 }
                    }
                }
            }
        }
        Some(Command::Status) => {
            match vault::try_load_vault() {
                Some(v) => {
                    let spend = v.session_spend("");
                    let creds = v.list_credentials();
                    let actions = v.recent_actions(10);
                    println!("Vault: unlocked");
                    println!("Credentials: {}", creds.len());
                    if spend > 0.0 { println!("Session spend: ${spend:.2}"); }
                    if !actions.is_empty() {
                        println!("\nRecent actions:");
                        for a in &actions {
                            let tool = a["tool"].as_str().unwrap_or("?");
                            let dec = a["decision"].as_str().unwrap_or("?");
                            let amt = a["amount"].as_f64().unwrap_or(0.0);
                            let cat = a["category"].as_str().unwrap_or("");
                            if amt > 0.0 {
                                println!("  {tool} [{cat}] ${amt:.2} -> {dec}");
                            } else {
                                println!("  {tool} -> {dec}");
                            }
                        }
                    }
                    0
                }
                None => { eprintln!("Vault not set up or locked. Run: signet-eval setup"); 1 }
            }
        }
        Some(Command::Store { name, value }) => {
            match vault::try_load_vault() {
                Some(v) => {
                    v.store_credential(&name, &value, 3);
                    println!("Stored '{name}' (Tier 3 compartment-encrypted)");
                    0
                }
                None => { eprintln!("Vault not set up or locked."); 1 }
            }
        }
        Some(Command::Rules) => {
            match policy::load_policy_config(&policy_path) {
                Ok(config) => {
                    println!("Policy: {} (v{})", policy_path.display(), config.version);
                    println!("Default action: {:?}", config.default_action);
                    println!("Rules: {}\n", config.rules.len());
                    for rule in &config.rules {
                        let action = format!("{:?}", rule.action).to_uppercase();
                        let lock_tag = if rule.locked { " [LOCKED]" } else { "" };
                        println!("  {} [{}]{}", rule.name, action, lock_tag);
                        println!("    tool: {}", rule.tool_pattern);
                        for cond in &rule.conditions {
                            println!("    when: {cond}");
                        }
                        if let Some(reason) = &rule.reason {
                            println!("    reason: {reason}");
                        }
                        println!();
                    }
                    0
                }
                Err(e) => { eprintln!("Error: {e}"); 1 }
            }
        }
        Some(Command::Log { limit }) => {
            match vault::try_load_vault() {
                Some(v) => {
                    let actions = v.recent_actions(limit);
                    if actions.is_empty() {
                        println!("No actions recorded.");
                    } else {
                        println!("{:<24} {:<12} {:<10} {:>8} {}", "TIMESTAMP", "TOOL", "CATEGORY", "AMOUNT", "DECISION");
                        println!("{}", "-".repeat(70));
                        for a in &actions {
                            let ts = a["timestamp"].as_f64().unwrap_or(0.0);
                            let dt = chrono::DateTime::from_timestamp(ts as i64, 0)
                                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                                .unwrap_or_else(|| format!("{ts:.0}"));
                            let tool = a["tool"].as_str().unwrap_or("?");
                            let cat = a["category"].as_str().unwrap_or("");
                            let amt = a["amount"].as_f64().unwrap_or(0.0);
                            let dec = a["decision"].as_str().unwrap_or("?");
                            let amt_str = if amt > 0.0 { format!("${amt:.2}") } else { "-".into() };
                            println!("{dt:<24} {tool:<12} {cat:<10} {amt_str:>8} {dec}");
                        }
                    }
                    0
                }
                None => { eprintln!("Vault not set up or locked. Run: signet-eval setup"); 1 }
            }
        }
        Some(Command::Test { json }) => {
            #[derive(serde::Deserialize)]
            struct TestInput {
                tool_name: String,
                #[serde(alias = "tool_input")]
                parameters: Option<serde_json::Value>,
            }
            let input: TestInput = match serde_json::from_str(&json) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Invalid JSON: {e}");
                    std::process::exit(1);
                }
            };
            let compiled = policy::load_policy(&policy_path);
            let v = vault::try_load_vault();
            let call = policy::ToolCall {
                tool_name: input.tool_name,
                parameters: input.parameters.unwrap_or(serde_json::Value::Object(Default::default())),
            };
            let result = policy::evaluate(&call, &compiled, v.as_ref());
            println!("Decision:     {:?}", result.decision);
            if let Some(rule) = &result.matched_rule {
                println!("Matched rule: {rule}");
            } else {
                println!("Matched rule: (none — default action)");
            }
            if let Some(reason) = &result.reason {
                println!("Reason:       {reason}");
            }
            println!("Eval time:    {}us", result.evaluation_time_us);
            0
        }
        Some(Command::Delete { name }) => {
            match vault::try_load_vault() {
                Some(v) => {
                    if v.delete_credential(&name) {
                        println!("Deleted credential '{name}'.");
                        0
                    } else {
                        eprintln!("Credential '{name}' not found.");
                        1
                    }
                }
                None => { eprintln!("Vault not set up or locked."); 1 }
            }
        }
        Some(Command::ResetSession) => {
            match vault::try_load_vault() {
                Some(mut v) => {
                    v.reset_session();
                    println!("Session reset. Spending counters cleared.");
                    0
                }
                None => { eprintln!("Vault not set up or locked."); 1 }
            }
        }
        Some(Command::Sign) => {
            match vault::try_load_vault() {
                Some(v) => {
                    match vault::sign_policy(v.session_key(), &policy_path) {
                        Ok(_) => { println!("Policy signed: {}", policy_path.with_extension("hmac").display()); 0 }
                        Err(e) => { eprintln!("Error: {e}"); 1 }
                    }
                }
                None => { eprintln!("Vault not set up or locked (needed for signing key)."); 1 }
            }
        }
        Some(Command::Unlock) => {
            if !vault::vault_exists() {
                eprintln!("No vault found. Run: signet-eval setup");
                1
            } else {
                let pass = rpassword::prompt_password("Vault passphrase: ").unwrap_or_default();
                match vault::unlock_vault(&pass) {
                    Ok(_) => { println!("Vault unlocked. Session key refreshed."); 0 }
                    Err(e) => { eprintln!("Error: {e}"); 1 }
                }
            }
        }
        Some(Command::Validate) => {
            match policy::load_policy_config(&policy_path) {
                Ok(config) => {
                    let diagnostics = policy::validate_policy(&config);
                    let errors: Vec<_> = diagnostics.iter()
                        .filter(|d| d.severity == policy::DiagnosticSeverity::Error)
                        .collect();
                    let warnings: Vec<_> = diagnostics.iter()
                        .filter(|d| d.severity == policy::DiagnosticSeverity::Warning)
                        .collect();

                    if errors.is_empty() && warnings.is_empty() {
                        println!("Policy valid: {} rules", config.rules.len());
                        0
                    } else {
                        for e in &errors {
                            eprintln!("ERROR [{}]: {}", e.rule_name, e.error);
                            eprintln!("  Fix: {}", e.fix_hint);
                        }
                        for w in &warnings {
                            eprintln!("WARN  [{}]: {}", w.rule_name, w.error);
                            eprintln!("  Fix: {}", w.fix_hint);
                        }
                        if errors.is_empty() { 0 } else { 1 }
                    }
                }
                Err(e) => { eprintln!("ERROR: {e}"); 1 }
            }
        }
        #[cfg(feature = "mcp")]
        Some(Command::Serve) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            match rt.block_on(mcp_server::run_server()) {
                Ok(_) => 0,
                Err(e) => { eprintln!("MCP server error: {e}"); 1 }
            }
        }
        #[cfg(feature = "mcp")]
        Some(Command::Proxy) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            match rt.block_on(mcp_proxy::run_proxy()) {
                Ok(_) => 0,
                Err(e) => { eprintln!("MCP proxy error: {e}"); 1 }
            }
        }
        Some(Command::PreflightStatus) => {
            match vault::try_load_vault() {
                Some(v) => {
                    match v.active_preflight() {
                        Some(pf) => {
                            println!("Active preflight: {}", pf.id);
                            println!("Task: {}", pf.task);
                            println!("Constraints: {}", pf.constraints.len());
                            println!("Violations: {}", pf.violation_count);
                            println!("Escalated: {}", pf.escalated);
                            println!("Lockout until: {}", pf.lockout_until);
                            let locked = v.is_preflight_locked();
                            println!("Locked: {locked}");
                            for (i, c) in pf.constraints.iter().enumerate() {
                                println!("  {}. [{}] {} — {}", i + 1, c.action, c.name, c.reason);
                                println!("     Plan B: {}", c.alternative);
                            }
                            0
                        }
                        None => { println!("No active preflight."); 0 }
                    }
                }
                None => { eprintln!("Vault not set up or locked."); 1 }
            }
        }
        Some(Command::Pause { minutes }) => {
            if minutes < 1 || minutes > 60 {
                eprintln!("Pause duration must be 1-60 minutes.");
                return 1;
            }
            if vault::is_paused_file() {
                eprintln!("Already paused until timestamp {}.", vault::pause_until_file());
                return 1;
            }
            let until = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                + (minutes as u64 * 60);
            vault::set_pause_file(until);
            println!("Policy enforcement paused for {minutes} minutes.");
            println!("Self-protection rules remain active.");
            println!("Run 'signet-eval resume' to end early.");
            0
        }
        Some(Command::Resume) => {
            if !vault::is_paused_file() {
                eprintln!("Not currently paused.");
                return 0;
            }
            vault::clear_pause_file();
            println!("Policy enforcement resumed.");
            0
        }
        Some(Command::Disable) => {
            if vault::is_disabled_file() {
                eprintln!("Already disabled.");
                return 0;
            }
            vault::set_disabled_file();
            println!("Policy enforcement FULLY disabled.");
            println!("ALL rules bypassed including self-protection.");
            println!("Run 'signet-eval enable' to re-enable.");
            0
        }
        Some(Command::Enable) => {
            if !vault::is_disabled_file() {
                eprintln!("Not currently disabled.");
                return 0;
            }
            vault::clear_disabled_file();
            println!("Policy enforcement re-enabled.");
            0
        }
        Some(Command::PreflightOverride) => {
            match vault::try_load_vault() {
                Some(v) => {
                    match v.active_preflight() {
                        Some(pf) => {
                            println!("Active preflight: {} (task: {})", pf.id, pf.task);
                            println!("Violations: {}, Escalated: {}", pf.violation_count, pf.escalated);
                            // Require passphrase confirmation for override
                            let pass = rpassword::prompt_password("Vault passphrase to confirm override: ").unwrap_or_default();
                            match vault::unlock_vault(&pass) {
                                Ok(_) => {
                                    match v.override_preflight() {
                                        Ok(_) => { println!("Preflight overridden. Soft constraints deactivated."); 0 }
                                        Err(e) => { eprintln!("Error: {e}"); 1 }
                                    }
                                }
                                Err(e) => { eprintln!("Authentication failed: {e}"); 1 }
                            }
                        }
                        None => { eprintln!("No active preflight to override."); 0 }
                    }
                }
                None => { eprintln!("Vault not set up or locked."); 1 }
            }
        }
    }
}

fn main() {
    std::process::exit(run());
}
