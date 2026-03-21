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
    /// Run MCP management server (conversational policy editing)
    #[cfg(feature = "mcp")]
    Serve,
    /// Run MCP proxy (wraps upstream servers with policy enforcement)
    #[cfg(feature = "mcp")]
    Proxy,
}

fn expand_home(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

fn main() {
    let cli = Cli::parse();
    let policy_path = expand_home(&cli.policy_path);

    let code = match cli.command {
        None | Some(Command::Eval) => {
            let compiled = policy::load_policy(&policy_path);
            let v = vault::try_load_vault();
            hook::run_hook(&compiled, v.as_ref())
        }
        Some(Command::Init) => {
            let config = policy::PolicyConfig {
                version: 1,
                default_action: policy::Decision::Allow,
                rules: vec![
                    policy::PolicyRule { name: "block_rm".into(), tool_pattern: ".*".into(), conditions: vec!["contains(parameters, 'rm ')".into()], action: policy::Decision::Deny, reason: Some("File deletion blocked".into()) },
                    policy::PolicyRule { name: "block_force_push".into(), tool_pattern: ".*".into(), conditions: vec!["any_of(parameters, 'push --force', 'push -f')".into()], action: policy::Decision::Ask, reason: Some("Force push requires confirmation".into()) },
                    policy::PolicyRule { name: "block_destructive".into(), tool_pattern: ".*".into(), conditions: vec!["any_of(parameters, 'mkfs', 'format ', 'dd if=')".into()], action: policy::Decision::Deny, reason: Some("Destructive disk ops blocked".into()) },
                    policy::PolicyRule { name: "block_piped_exec".into(), tool_pattern: ".*".into(), conditions: vec!["any_of(parameters, 'curl', 'wget')".into(), "contains(parameters, '| sh')".into()], action: policy::Decision::Deny, reason: Some("Piped remote execution blocked".into()) },
                ],
            };
            let yaml = serde_yaml::to_string(&config).unwrap();
            if let Some(parent) = policy_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            match std::fs::write(&policy_path, yaml) {
                Ok(_) => { eprintln!("Policy written to {}", policy_path.display()); 0 }
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
                        Ok(_) => { eprintln!("Vault created. Session key cached."); 0 }
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
                    eprintln!("Vault: unlocked");
                    eprintln!("Credentials: {}", creds.len());
                    if spend > 0.0 { eprintln!("Session spend: ${spend:.2}"); }
                    if !actions.is_empty() {
                        eprintln!("\nRecent actions:");
                        for a in &actions {
                            let tool = a["tool"].as_str().unwrap_or("?");
                            let dec = a["decision"].as_str().unwrap_or("?");
                            let amt = a["amount"].as_f64().unwrap_or(0.0);
                            let cat = a["category"].as_str().unwrap_or("");
                            if amt > 0.0 {
                                eprintln!("  {tool} [{cat}] ${amt:.2} -> {dec}");
                            } else {
                                eprintln!("  {tool} -> {dec}");
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
                    eprintln!("Stored '{name}' (Tier 3 compartment-encrypted)");
                    0
                }
                None => { eprintln!("Vault not set up or locked."); 1 }
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
    };

    std::process::exit(code);
}
