//! Signet Vault — Encrypted local state with tiered access.
//!
//! Security model:
//! - Master key derived from passphrase via Argon2id (memory-hard)
//! - Session key file encrypted with a device key (not plaintext)
//! - Brute-force protection: lockout after N failed attempts
//! - Policy file integrity via HMAC
//!
//! Tier 1: Unencrypted (ledger, action log)
//! Tier 2: Session-key encrypted (session state)
//! Tier 3: Compartment-key encrypted (credentials — requires passphrase)

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const SALT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SESSION_TTL_SECS: f64 = 1800.0; // 30 minutes
const MAX_FAILED_ATTEMPTS: u32 = 5;
const LOCKOUT_SECS: f64 = 300.0; // 5 minute lockout after max failures
const MAX_PREFLIGHT_CONSTRAINTS: usize = 20;
const DEFAULT_VIOLATION_THRESHOLD: u32 = 5;

type HmacSha256 = Hmac<Sha256>;

fn now_epoch() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

pub(crate) fn random_hex_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// === Key Derivation ===

fn derive_master_key(passphrase: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("Argon2 derivation failed");
    key
}

fn derive_subkey(master: &[u8; KEY_LEN], purpose: &str) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; KEY_LEN];
    hk.expand(format!("signet-{purpose}").as_bytes(), &mut out)
        .expect("HKDF expand failed");
    out
}

fn make_key_check(master: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master).unwrap();
    mac.update(b"signet-vault-check");
    mac.finalize().into_bytes().to_vec()
}

// === Encryption ===

fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");
    let mut out = nonce_bytes.to_vec();
    out.extend(ciphertext);
    out
}

fn decrypt(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < NONCE_LEN {
        return Err("data too short".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    cipher.decrypt(nonce, &data[NONCE_LEN..])
        .map_err(|_| "decryption failed".into())
}

// === Vault Metadata ===

#[derive(Serialize, Deserialize)]
struct VaultMeta {
    salt: String,
    key_check: String,
    created_at: f64,
    #[serde(default)]
    failed_attempts: u32,
    #[serde(default)]
    locked_until: f64,
}

// === Policy Integrity ===

/// Compute HMAC of a policy file's contents using the session key.
pub fn policy_hmac(session_key: &[u8; KEY_LEN], policy_content: &str) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(session_key).unwrap();
    mac.update(policy_content.as_bytes());
    B64.encode(mac.finalize().into_bytes())
}

/// Verify policy HMAC. Returns true if valid, false if tampered.
/// - No policy file: true (uses defaults)
/// - No HMAC file but vault exists: false (fail closed — policy was modified without signing)
/// - HMAC mismatch: false
pub fn verify_policy_integrity(session_key: &[u8; KEY_LEN], policy_path: &std::path::Path) -> bool {
    let hmac_path = policy_path.with_extension("hmac");
    let policy_content = match std::fs::read_to_string(policy_path) {
        Ok(c) => c,
        Err(_) => return true, // No policy file = ok (uses defaults)
    };
    let expected = match std::fs::read_to_string(&hmac_path) {
        Ok(h) => h.trim().to_string(),
        Err(_) => return false, // Vault exists but no HMAC = fail closed
    };
    let actual = policy_hmac(session_key, &policy_content);
    actual == expected
}

/// Sign a policy file — write its HMAC alongside it.
pub fn sign_policy(session_key: &[u8; KEY_LEN], policy_path: &std::path::Path) -> Result<(), String> {
    let hmac_path = policy_path.with_extension("hmac");
    let content = std::fs::read_to_string(policy_path)
        .map_err(|e| format!("read policy: {e}"))?;
    let sig = policy_hmac(session_key, &content);
    std::fs::write(&hmac_path, &sig).map_err(|e| format!("write hmac: {e}"))?;
    Ok(())
}

// === Credential Metadata ===

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialMeta {
    #[serde(default)]
    pub domain: Option<String>,      // e.g. "amazon.com"
    #[serde(default)]
    pub purpose: Option<String>,     // e.g. "purchase", "api_access"
    #[serde(default)]
    pub max_amount: Option<f64>,     // per-use amount cap
    #[serde(default)]
    pub one_time: bool,              // invalidate after first use
    #[serde(default)]
    pub label: Option<String>,       // human-readable label
}

// === Preflight Structs ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preflight {
    pub id: String,
    pub task: String,
    pub risks: Vec<String>,
    pub constraints: Vec<SoftConstraint>,
    pub submitted_at: u64,
    pub lockout_until: u64,
    pub violation_count: u32,
    pub escalated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftConstraint {
    pub name: String,
    pub tool_pattern: String,
    pub conditions: Vec<String>,
    pub action: String,  // "DENY" or "ASK"
    pub reason: String,
    pub alternative: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightViolation {
    pub preflight_id: String,
    pub constraint_name: String,
    pub tool_name: String,
    pub parameters_summary: String,
    pub alternative: String,
    pub timestamp: u64,
}

// === Vault ===

pub struct Vault {
    #[allow(dead_code)] // retained for future subkey derivation
    master_key: [u8; KEY_LEN],
    session_key: [u8; KEY_LEN],
    compartment_key: [u8; KEY_LEN],
    db_path: PathBuf,
    session_start: f64,
}

impl Vault {
    fn new(master_key: [u8; KEY_LEN], db_path: PathBuf) -> Self {
        let session_key = derive_subkey(&master_key, "session");
        let compartment_key = derive_subkey(&master_key, "compartment");

        let vault = Vault {
            master_key,
            session_key,
            compartment_key,
            db_path,
            session_start: 0.0,
        };
        vault.init_db();
        let start = vault.load_or_create_session_start();
        Vault { session_start: start, ..vault }
    }

    pub fn session_key(&self) -> &[u8; KEY_LEN] {
        &self.session_key
    }

    fn init_db(&self) {
        let conn = Connection::open(&self.db_path).expect("open db");
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                tool TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT '',
                amount REAL NOT NULL DEFAULT 0.0,
                decision TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                tier INTEGER NOT NULL,
                encrypted_value BLOB NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL,
                metadata TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS session_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ledger_category ON ledger(category);
            CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger(timestamp);
            CREATE TABLE IF NOT EXISTS preflights (
                id TEXT PRIMARY KEY,
                task TEXT NOT NULL,
                payload TEXT NOT NULL,
                hmac TEXT NOT NULL,
                submitted_at INTEGER NOT NULL,
                lockout_until INTEGER NOT NULL,
                violation_count INTEGER DEFAULT 0,
                escalated INTEGER DEFAULT 0,
                active INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS preflight_violations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                preflight_id TEXT NOT NULL,
                constraint_name TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                params_summary TEXT NOT NULL DEFAULT '',
                alternative TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_preflight_active ON preflights(active);
            CREATE INDEX IF NOT EXISTS idx_pv_preflight ON preflight_violations(preflight_id);
        ").expect("init db");
    }

    fn load_or_create_session_start(&self) -> f64 {
        let conn = Connection::open(&self.db_path).unwrap();
        let existing: Option<f64> = conn.query_row(
            "SELECT value FROM session_state WHERE key = '_session_start'",
            [], |row| row.get::<_, String>(0).map(|s| s.parse::<f64>().unwrap_or(0.0))
        ).ok();

        if let Some(start) = existing {
            if now_epoch() - start < SESSION_TTL_SECS {
                return start;
            }
        }

        let now = now_epoch();
        conn.execute(
            "INSERT OR REPLACE INTO session_state (key, value, updated_at) VALUES ('_session_start', ?1, ?2)",
            params![now.to_string(), now],
        ).unwrap();
        now
    }

    pub fn reset_session(&mut self) {
        let now = now_epoch();
        self.session_start = now;
        if let Ok(conn) = Connection::open(&self.db_path) {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO session_state (key, value, updated_at) VALUES ('_session_start', ?1, ?2)",
                params![now.to_string(), now],
            );
        }
    }

    // --- Ledger ---

    pub fn log_action(&self, tool: &str, decision: &str, category: &str, amount: f64, detail: &str) {
        if let Ok(conn) = Connection::open(&self.db_path) {
            let _ = conn.execute(
                "INSERT INTO ledger (timestamp, tool, category, amount, decision, detail) VALUES (?1,?2,?3,?4,?5,?6)",
                params![now_epoch(), tool, category, amount, decision, detail],
            );
        }
    }

    pub fn session_spend(&self, category: &str) -> f64 {
        self.total_spend(category, self.session_start)
    }

    pub fn total_spend(&self, category: &str, since: f64) -> f64 {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return 0.0,
        };
        if category.is_empty() {
            conn.query_row(
                "SELECT COALESCE(SUM(amount), 0) FROM ledger WHERE timestamp >= ?1 AND decision = 'ALLOW'",
                params![since], |row| row.get(0),
            ).unwrap_or(0.0)
        } else {
            conn.query_row(
                "SELECT COALESCE(SUM(amount), 0) FROM ledger WHERE category = ?1 AND timestamp >= ?2 AND decision = 'ALLOW'",
                params![category, since], |row| row.get(0),
            ).unwrap_or(0.0)
        }
    }

    pub fn recent_actions(&self, limit: u32) -> Vec<serde_json::Value> {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let mut stmt = conn.prepare(
            "SELECT timestamp, tool, category, amount, decision, detail FROM ledger ORDER BY id DESC LIMIT ?1"
        ).unwrap();
        stmt.query_map(params![limit], |row| {
            Ok(serde_json::json!({
                "timestamp": row.get::<_, f64>(0)?,
                "tool": row.get::<_, String>(1)?,
                "category": row.get::<_, String>(2)?,
                "amount": row.get::<_, f64>(3)?,
                "decision": row.get::<_, String>(4)?,
                "detail": row.get::<_, String>(5)?,
            }))
        }).unwrap().filter_map(|r| r.ok()).collect()
    }

    // --- Credentials ---

    pub fn store_credential(&self, name: &str, value: &str, tier: u8) {
        self.store_credential_full(name, value, tier, None, None);
    }

    #[allow(dead_code)] // public API — used by callers with expiry constraints
    pub fn store_credential_with_expiry(&self, name: &str, value: &str, tier: u8, expires_at: Option<f64>) {
        self.store_credential_full(name, value, tier, expires_at, None);
    }

    pub fn store_credential_full(
        &self, name: &str, value: &str, tier: u8,
        expires_at: Option<f64>, metadata: Option<&CredentialMeta>,
    ) {
        let key = if tier == 3 { &self.compartment_key } else { &self.session_key };
        let encrypted = encrypt(key, value.as_bytes());
        let meta_json = metadata
            .map(|m| serde_json::to_string(m).unwrap_or_else(|_| "{}".into()))
            .unwrap_or_else(|| "{}".into());
        let conn = Connection::open(&self.db_path).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO credentials (name, tier, encrypted_value, created_at, expires_at, metadata) VALUES (?1,?2,?3,?4,?5,?6)",
            params![name, tier as i32, encrypted, now_epoch(), expires_at, meta_json],
        ).unwrap();
    }

    pub fn get_credential(&self, name: &str) -> Option<String> {
        let conn = Connection::open(&self.db_path).ok()?;
        let (tier, encrypted, expires_at): (i32, Vec<u8>, Option<f64>) = conn.query_row(
            "SELECT tier, encrypted_value, expires_at FROM credentials WHERE name = ?1",
            params![name], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        ).ok()?;

        if let Some(exp) = expires_at {
            if now_epoch() > exp {
                return None;
            }
        }

        let key = if tier == 3 { &self.compartment_key } else { &self.session_key };
        let plaintext = decrypt(key, &encrypted).ok()?;
        String::from_utf8(plaintext).ok()
    }

    pub fn get_credential_meta(&self, name: &str) -> Option<CredentialMeta> {
        let conn = Connection::open(&self.db_path).ok()?;
        let meta_json: String = conn.query_row(
            "SELECT metadata FROM credentials WHERE name = ?1",
            params![name], |row| row.get(0),
        ).ok()?;
        serde_json::from_str(&meta_json).ok()
    }

    /// Request a scoped capability token for a credential.
    /// Returns the credential value if the request matches the credential's constraints.
    /// Logs the access. Invalidates one-time credentials after use.
    pub fn request_capability(&self, name: &str, domain: &str, amount: f64, purpose: &str) -> Result<String, String> {
        let meta = self.get_credential_meta(name)
            .unwrap_or_default();

        // Check domain constraint
        if let Some(ref allowed_domain) = meta.domain {
            if !domain.is_empty() && allowed_domain != domain {
                return Err(format!("Credential '{name}' is scoped to domain '{allowed_domain}', not '{domain}'"));
            }
        }

        // Check purpose constraint
        if let Some(ref allowed_purpose) = meta.purpose {
            if !purpose.is_empty() && allowed_purpose != purpose {
                return Err(format!("Credential '{name}' is scoped to purpose '{allowed_purpose}', not '{purpose}'"));
            }
        }

        // Check amount constraint
        if let Some(max) = meta.max_amount {
            if amount > max {
                return Err(format!("Credential '{name}' caps at ${max:.2}, requested ${amount:.2}"));
            }
        }

        // Get the actual credential
        let value = self.get_credential(name)
            .ok_or_else(|| format!("Credential '{name}' not found or expired"))?;

        // Log the capability request
        self.log_action(
            &format!("capability:{name}"),
            "ALLOW",
            purpose,
            amount,
            &format!("domain={domain}"),
        );

        // Invalidate if one-time
        if meta.one_time {
            self.delete_credential(name);
        }

        Ok(value)
    }

    pub fn delete_credential(&self, name: &str) -> bool {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let rows = conn.execute(
            "DELETE FROM credentials WHERE name = ?1",
            params![name],
        ).unwrap_or(0);
        rows > 0
    }

    pub fn credential_exists(&self, name: &str) -> bool {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return false,
        };
        conn.query_row(
            "SELECT 1 FROM credentials WHERE name = ?1",
            params![name], |_row| Ok(()),
        ).is_ok()
    }

    pub fn list_credentials(&self) -> Vec<serde_json::Value> {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let mut stmt = conn.prepare(
            "SELECT name, tier, created_at, expires_at, metadata FROM credentials"
        ).unwrap();
        stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "name": row.get::<_, String>(0)?,
                "tier": row.get::<_, i32>(1)?,
                "created_at": row.get::<_, f64>(2)?,
                "expires_at": row.get::<_, Option<f64>>(3)?,
                "metadata": row.get::<_, String>(4)?,
            }))
        }).unwrap().filter_map(|r| r.ok()).collect()
    }

    // --- Preflight ---

    /// Store a new preflight. HMAC-signs it. Deactivates any previous active preflight.
    pub fn store_preflight(&self, preflight: &Preflight) -> Result<(), String> {
        if preflight.constraints.len() > MAX_PREFLIGHT_CONSTRAINTS {
            return Err(format!("Too many constraints: {} (max {})", preflight.constraints.len(), MAX_PREFLIGHT_CONSTRAINTS));
        }
        // Validate all constraints have non-empty alternatives
        for c in &preflight.constraints {
            if c.alternative.trim().is_empty() {
                return Err(format!("Constraint '{}' has empty alternative (plan B required)", c.name));
            }
            if c.action != "DENY" && c.action != "ASK" {
                return Err(format!("Constraint '{}' action must be DENY or ASK, got '{}'", c.name, c.action));
            }
        }

        let payload = serde_json::to_string(preflight)
            .map_err(|e| format!("serialize: {e}"))?;
        let hmac = self.preflight_hmac(&payload);

        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("open db: {e}"))?;
        // Deactivate previous active preflight
        conn.execute("UPDATE preflights SET active = 0 WHERE active = 1", [])
            .map_err(|e| format!("deactivate: {e}"))?;
        conn.execute(
            "INSERT INTO preflights (id, task, payload, hmac, submitted_at, lockout_until, violation_count, escalated, active) VALUES (?1,?2,?3,?4,?5,?6,0,0,1)",
            params![preflight.id, preflight.task, payload, hmac, preflight.submitted_at as i64, preflight.lockout_until as i64],
        ).map_err(|e| format!("insert: {e}"))?;
        Ok(())
    }

    /// Get the currently active preflight (if any, not expired, HMAC valid).
    pub fn active_preflight(&self) -> Option<Preflight> {
        let conn = Connection::open(&self.db_path).ok()?;
        let (payload, stored_hmac, violation_count, escalated): (String, String, u32, bool) = conn.query_row(
            "SELECT payload, hmac, violation_count, escalated FROM preflights WHERE active = 1",
            [], |row| Ok((
                row.get(0)?,
                row.get(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, i32>(3)? != 0,
            ))
        ).ok()?;

        // Verify HMAC
        let expected = self.preflight_hmac(&payload);
        if stored_hmac != expected {
            eprintln!("WARNING: Preflight HMAC mismatch — possible tampering. Ignoring preflight.");
            return None;
        }

        let mut preflight: Preflight = serde_json::from_str(&payload).ok()?;
        // Update with live violation count from DB
        preflight.violation_count = violation_count;
        preflight.escalated = escalated;

        // Check if lockout has expired
        let now = now_epoch() as u64;
        if now > preflight.lockout_until {
            // Lockout expired — deactivate
            let _ = conn.execute("UPDATE preflights SET active = 0 WHERE id = ?1", params![preflight.id]);
            return None;
        }

        Some(preflight)
    }

    /// Check if a preflight is currently locked (cannot be replaced).
    pub fn is_preflight_locked(&self) -> bool {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let lockout_until: Option<i64> = conn.query_row(
            "SELECT lockout_until FROM preflights WHERE active = 1",
            [], |row| row.get(0),
        ).ok();
        match lockout_until {
            Some(until) => (now_epoch() as i64) < until,
            None => false,
        }
    }

    /// Record a preflight violation. Increments violation_count. Sets escalated if threshold exceeded.
    pub fn log_preflight_violation(&self, violation: &PreflightViolation) -> Result<(), String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("open db: {e}"))?;
        conn.execute(
            "INSERT INTO preflight_violations (preflight_id, constraint_name, tool_name, params_summary, alternative, timestamp) VALUES (?1,?2,?3,?4,?5,?6)",
            params![violation.preflight_id, violation.constraint_name, violation.tool_name, violation.parameters_summary, violation.alternative, violation.timestamp as i64],
        ).map_err(|e| format!("insert violation: {e}"))?;

        // Increment violation count
        conn.execute(
            "UPDATE preflights SET violation_count = violation_count + 1 WHERE id = ?1",
            params![violation.preflight_id],
        ).map_err(|e| format!("update count: {e}"))?;

        // Check escalation threshold
        let count: u32 = conn.query_row(
            "SELECT violation_count FROM preflights WHERE id = ?1",
            params![violation.preflight_id], |row| row.get(0),
        ).unwrap_or(0);

        if count >= DEFAULT_VIOLATION_THRESHOLD {
            conn.execute(
                "UPDATE preflights SET escalated = 1 WHERE id = ?1",
                params![violation.preflight_id],
            ).map_err(|e| format!("escalate: {e}"))?;
        }

        Ok(())
    }

    /// Get violations for a preflight.
    pub fn preflight_violations(&self, preflight_id: &str) -> Vec<PreflightViolation> {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let mut stmt = conn.prepare(
            "SELECT preflight_id, constraint_name, tool_name, params_summary, alternative, timestamp FROM preflight_violations WHERE preflight_id = ?1 ORDER BY timestamp DESC"
        ).unwrap();
        stmt.query_map(params![preflight_id], |row| {
            Ok(PreflightViolation {
                preflight_id: row.get(0)?,
                constraint_name: row.get(1)?,
                tool_name: row.get(2)?,
                parameters_summary: row.get(3)?,
                alternative: row.get(4)?,
                timestamp: row.get::<_, i64>(5)? as u64,
            })
        }).unwrap().filter_map(|r| r.ok()).collect()
    }

    /// Get preflight history.
    pub fn preflight_history(&self, limit: u32) -> Vec<serde_json::Value> {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };
        let mut stmt = conn.prepare(
            "SELECT id, task, submitted_at, lockout_until, violation_count, escalated, active FROM preflights ORDER BY submitted_at DESC LIMIT ?1"
        ).unwrap();
        stmt.query_map(params![limit], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "task": row.get::<_, String>(1)?,
                "submitted_at": row.get::<_, i64>(2)?,
                "lockout_until": row.get::<_, i64>(3)?,
                "violation_count": row.get::<_, u32>(4)?,
                "escalated": row.get::<_, i32>(5)? != 0,
                "active": row.get::<_, i32>(6)? != 0,
            }))
        }).unwrap().filter_map(|r| r.ok()).collect()
    }

    /// Deactivate the active preflight (human override).
    pub fn override_preflight(&self) -> Result<(), String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("open db: {e}"))?;
        let rows = conn.execute("UPDATE preflights SET active = 0 WHERE active = 1", [])
            .map_err(|e| format!("deactivate: {e}"))?;
        if rows == 0 {
            return Err("No active preflight to override.".into());
        }
        Ok(())
    }

    // --- Pause ---

    /// Set a timed pause. Non-self-protection rules are bypassed until pause_until.
    pub fn set_pause(&self, pause_until: u64) {
        if let Ok(conn) = Connection::open(&self.db_path) {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO session_state (key, value, updated_at) VALUES ('_pause_until', ?1, ?2)",
                params![pause_until.to_string(), now_epoch()],
            );
        }
    }

    /// Check if evaluation is currently paused.
    pub fn is_paused(&self) -> bool {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let until: Option<String> = conn.query_row(
            "SELECT value FROM session_state WHERE key = '_pause_until'",
            [], |row| row.get(0),
        ).ok();
        match until {
            Some(s) => {
                let ts: u64 = s.parse().unwrap_or(0);
                if (now_epoch() as u64) < ts { true } else {
                    let _ = conn.execute("DELETE FROM session_state WHERE key = '_pause_until'", []);
                    false
                }
            }
            None => false,
        }
    }

    /// Clear the pause (resume immediately).
    pub fn clear_pause(&self) {
        if let Ok(conn) = Connection::open(&self.db_path) {
            let _ = conn.execute("DELETE FROM session_state WHERE key = '_pause_until'", []);
        }
    }

    /// Get pause expiry timestamp (0 if not paused).
    pub fn pause_until(&self) -> u64 {
        let conn = match Connection::open(&self.db_path) {
            Ok(c) => c,
            Err(_) => return 0,
        };
        conn.query_row(
            "SELECT value FROM session_state WHERE key = '_pause_until'",
            [], |row| row.get::<_, String>(0),
        ).ok().and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    /// HMAC for preflight payload.
    fn preflight_hmac(&self, payload: &str) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.session_key).unwrap();
        mac.update(b"signet-preflight:");
        mac.update(payload.as_bytes());
        B64.encode(mac.finalize().into_bytes())
    }
}

// === Setup & Unlock ===

pub fn signet_dir() -> PathBuf {
    dirs().join(".signet")
}

fn dirs() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
}

fn meta_path() -> PathBuf { signet_dir().join("vault.meta") }
fn db_path() -> PathBuf { signet_dir().join("state.db") }
fn session_key_path() -> PathBuf { signet_dir().join(".session_key") }

pub fn vault_exists() -> bool { meta_path().exists() }

/// Derive a device-specific key for encrypting the session key file.
/// Uses machine ID + username as entropy — not a passphrase, just prevents
/// trivial copying of the session key to another machine.
fn device_key() -> [u8; KEY_LEN] {
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .unwrap_or_else(|_| {
            // macOS: use hardware UUID
            std::process::Command::new("ioreg")
                .args(["-rd1", "-c", "IOPlatformExpertDevice"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.contains("IOPlatformUUID"))
                        .map(|l| l.to_string())
                })
                .unwrap_or_else(|| "signet-fallback-device-id".into())
        });
    let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let input = format!("signet-device:{machine_id}:{username}");
    let mut key = [0u8; KEY_LEN];
    let hk = Hkdf::<Sha256>::new(Some(b"signet-device-key"), input.as_bytes());
    hk.expand(b"session-file-encryption", &mut key).expect("HKDF");
    key
}

/// Encrypt master key with device key before writing to disk.
fn encrypt_session_key(master_key: &[u8; KEY_LEN]) -> Vec<u8> {
    let dk = device_key();
    encrypt(&dk, master_key)
}

/// Decrypt session key file with device key.
fn decrypt_session_key(encrypted: &[u8]) -> Option<[u8; KEY_LEN]> {
    let dk = device_key();
    let plain = decrypt(&dk, encrypted).ok()?;
    if plain.len() != KEY_LEN { return None; }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plain);
    Some(key)
}

pub fn setup_vault(passphrase: &str) -> Result<Vault, String> {
    let dir = signet_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let master_key = derive_master_key(passphrase, &salt);
    let check = make_key_check(&master_key);

    let meta = VaultMeta {
        salt: B64.encode(&salt),
        key_check: B64.encode(&check),
        created_at: now_epoch(),
        failed_attempts: 0,
        locked_until: 0.0,
    };
    let meta_json = serde_json::to_string(&meta).map_err(|e| e.to_string())?;
    std::fs::write(meta_path(), meta_json).map_err(|e| format!("write meta: {e}"))?;

    // Cache encrypted master key for hook mode
    let encrypted_key = encrypt_session_key(&master_key);
    let key_file = session_key_path();
    std::fs::write(&key_file, B64.encode(&encrypted_key)).map_err(|e| format!("write key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).ok();
    }

    Ok(Vault::new(master_key, db_path()))
}

pub fn unlock_vault(passphrase: &str) -> Result<Vault, String> {
    let meta_json = std::fs::read_to_string(meta_path())
        .map_err(|_| "No vault found. Run 'signet-eval setup' first.".to_string())?;
    let mut meta: VaultMeta = serde_json::from_str(&meta_json).map_err(|e| e.to_string())?;

    // Check lockout
    if meta.failed_attempts >= MAX_FAILED_ATTEMPTS {
        let remaining = meta.locked_until - now_epoch();
        if remaining > 0.0 {
            return Err(format!("Vault locked for {:.0} more seconds ({} failed attempts)", remaining, meta.failed_attempts));
        }
        // Lockout expired — reset
        meta.failed_attempts = 0;
    }

    let salt = B64.decode(&meta.salt).map_err(|e| e.to_string())?;
    let master_key = derive_master_key(passphrase, &salt);
    let check = make_key_check(&master_key);
    let expected = B64.decode(&meta.key_check).map_err(|e| e.to_string())?;

    if check != expected {
        // Record failed attempt
        meta.failed_attempts += 1;
        if meta.failed_attempts >= MAX_FAILED_ATTEMPTS {
            meta.locked_until = now_epoch() + LOCKOUT_SECS;
        }
        let _ = std::fs::write(meta_path(), serde_json::to_string(&meta).unwrap_or_default());
        return Err(format!("Wrong passphrase ({}/{} attempts)", meta.failed_attempts, MAX_FAILED_ATTEMPTS));
    }

    // Reset failed attempts on success
    if meta.failed_attempts > 0 {
        meta.failed_attempts = 0;
        meta.locked_until = 0.0;
        let _ = std::fs::write(meta_path(), serde_json::to_string(&meta).unwrap_or_default());
    }

    // Update encrypted session key cache
    let encrypted_key = encrypt_session_key(&master_key);
    let key_file = session_key_path();
    std::fs::write(&key_file, B64.encode(&encrypted_key)).ok();

    Ok(Vault::new(master_key, db_path()))
}

/// Try loading vault from cached session key (for hook mode — no passphrase prompt).
pub fn try_load_vault() -> Option<Vault> {
    let key_data = std::fs::read_to_string(session_key_path()).ok()?;
    let encrypted_bytes = B64.decode(key_data.trim()).ok()?;
    let master_key = decrypt_session_key(&encrypted_bytes)?;

    // Verify against vault metadata
    let meta_json = std::fs::read_to_string(meta_path()).ok()?;
    let meta: VaultMeta = serde_json::from_str(&meta_json).ok()?;
    let expected = B64.decode(&meta.key_check).ok()?;
    let check = make_key_check(&master_key);

    if check != expected {
        return None;
    }

    Some(Vault::new(master_key, db_path()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_vault(dir: &std::path::Path, passphrase: &str) -> Vault {
        let db = dir.join("state.db");
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let master_key = derive_master_key(passphrase, &salt);
        Vault::new(master_key, db)
    }

    #[test]
    fn test_setup_and_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        vault.log_action("test", "ALLOW", "books", 25.0, "");
        assert_eq!(vault.session_spend("books"), 25.0);
    }

    #[test]
    fn test_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        vault.store_credential("cc_visa", "4111111111111111", 3);
        assert_eq!(vault.get_credential("cc_visa").as_deref(), Some("4111111111111111"));
        assert_eq!(vault.get_credential("nonexistent"), None);
    }

    #[test]
    fn test_spending_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        vault.log_action("buy", "ALLOW", "books", 100.0, "");
        vault.log_action("buy", "ALLOW", "books", 80.0, "");
        vault.log_action("buy", "DENY", "books", 300.0, "");
        vault.log_action("buy", "ALLOW", "food", 50.0, "");
        assert_eq!(vault.session_spend("books"), 180.0);
        assert_eq!(vault.session_spend("food"), 50.0);
        assert_eq!(vault.session_spend(""), 230.0);
    }

    #[test]
    fn test_wrong_passphrase() {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let k1 = derive_master_key("correct", &salt);
        let k2 = derive_master_key("wrong", &salt);
        assert_ne!(make_key_check(&k1), make_key_check(&k2));
    }

    #[test]
    fn test_recent_actions() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        vault.log_action("read", "ALLOW", "", 0.0, "");
        vault.log_action("write", "DENY", "", 0.0, "blocked");
        assert_eq!(vault.recent_actions(10).len(), 2);
    }

    #[test]
    fn test_credential_exists() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        assert!(!vault.credential_exists("api_key"));
        vault.store_credential("api_key", "secret123", 2);
        assert!(vault.credential_exists("api_key"));
    }

    #[test]
    fn test_delete_credential() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        vault.store_credential("to_delete", "val", 2);
        assert!(vault.delete_credential("to_delete"));
        assert!(!vault.credential_exists("to_delete"));
        assert!(!vault.delete_credential("to_delete"));
    }

    #[test]
    fn test_get_credential_expired() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        vault.store_credential_with_expiry("expired_key", "secret", 2, Some(now_epoch() - 3600.0));
        assert_eq!(vault.get_credential("expired_key"), None);
        vault.store_credential("valid_key", "secret2", 2);
        assert_eq!(vault.get_credential("valid_key").as_deref(), Some("secret2"));
    }

    #[test]
    fn test_credential_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        let meta = CredentialMeta {
            domain: Some("amazon.com".into()),
            purpose: Some("purchase".into()),
            max_amount: Some(500.0),
            one_time: false,
            label: Some("My Visa".into()),
        };
        vault.store_credential_full("cc_visa", "4111111111111111", 3, None, Some(&meta));
        let loaded = vault.get_credential_meta("cc_visa").unwrap();
        assert_eq!(loaded.domain.as_deref(), Some("amazon.com"));
        assert_eq!(loaded.max_amount, Some(500.0));
    }

    #[test]
    fn test_request_capability_domain_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        let meta = CredentialMeta {
            domain: Some("amazon.com".into()),
            max_amount: Some(200.0),
            ..Default::default()
        };
        vault.store_credential_full("cc", "4111", 3, None, Some(&meta));

        // Matching domain works
        assert!(vault.request_capability("cc", "amazon.com", 50.0, "").is_ok());
        // Wrong domain fails
        assert!(vault.request_capability("cc", "evil.com", 50.0, "").is_err());
        // Over max fails
        assert!(vault.request_capability("cc", "amazon.com", 300.0, "").is_err());
    }

    #[test]
    fn test_request_capability_one_time() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        let meta = CredentialMeta { one_time: true, ..Default::default() };
        vault.store_credential_full("token", "abc123", 2, None, Some(&meta));

        assert!(vault.request_capability("token", "", 0.0, "").is_ok());
        // Second use fails — credential was invalidated
        assert!(vault.request_capability("token", "", 0.0, "").is_err());
    }

    #[test]
    fn test_device_key_deterministic() {
        let k1 = device_key();
        let k2 = device_key();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_session_key_encryption_roundtrip() {
        let mut master = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut master);
        let encrypted = encrypt_session_key(&master);
        let decrypted = decrypt_session_key(&encrypted).unwrap();
        assert_eq!(master, decrypted);
    }

    #[test]
    fn test_policy_hmac() {
        let key = [42u8; KEY_LEN];
        let content = "version: 1\ndefault_action: ALLOW\nrules: []";
        let sig1 = policy_hmac(&key, content);
        let sig2 = policy_hmac(&key, content);
        assert_eq!(sig1, sig2);
        // Different content → different HMAC
        let sig3 = policy_hmac(&key, "version: 1\ndefault_action: DENY");
        assert_ne!(sig1, sig3);
        // Different key → different HMAC
        let sig4 = policy_hmac(&[99u8; KEY_LEN], content);
        assert_ne!(sig1, sig4);
    }

    #[test]
    fn test_reset_session() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = make_test_vault(dir.path(), "testpass123");
        vault.log_action("buy", "ALLOW", "books", 100.0, "");
        assert_eq!(vault.session_spend("books"), 100.0);
        vault.reset_session();
        // After reset, previous spend is before the new session start
        assert_eq!(vault.session_spend("books"), 0.0);
    }
}
