//! Signet Vault — Encrypted local state with tiered access.
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

type HmacSha256 = Hmac<Sha256>;

fn now_epoch() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
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
    // nonce || ciphertext
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
    salt: String,       // base64
    key_check: String,  // base64
    created_at: f64,
}

// === Vault ===

pub struct Vault {
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
            session_key,
            compartment_key,
            db_path,
            session_start: 0.0,
        };
        vault.init_db();
        let start = vault.load_or_create_session_start();
        Vault { session_start: start, ..vault }
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
        self.store_credential_with_expiry(name, value, tier, None);
    }

    pub fn store_credential_with_expiry(&self, name: &str, value: &str, tier: u8, expires_at: Option<f64>) {
        let key = if tier == 3 { &self.compartment_key } else { &self.session_key };
        let encrypted = encrypt(key, value.as_bytes());
        let conn = Connection::open(&self.db_path).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO credentials (name, tier, encrypted_value, created_at, expires_at, metadata) VALUES (?1,?2,?3,?4,?5,'{}')",
            params![name, tier as i32, encrypted, now_epoch(), expires_at],
        ).unwrap();
    }

    pub fn get_credential(&self, name: &str) -> Option<String> {
        let conn = Connection::open(&self.db_path).ok()?;
        let (tier, encrypted, expires_at): (i32, Vec<u8>, Option<f64>) = conn.query_row(
            "SELECT tier, encrypted_value, expires_at FROM credentials WHERE name = ?1",
            params![name], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        ).ok()?;

        // Enforce expiration
        if let Some(exp) = expires_at {
            if now_epoch() > exp {
                return None;
            }
        }

        let key = if tier == 3 { &self.compartment_key } else { &self.session_key };
        let plaintext = decrypt(key, &encrypted).ok()?;
        String::from_utf8(plaintext).ok()
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
            }))
        }).unwrap().filter_map(|r| r.ok()).collect()
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
    };
    let meta_json = serde_json::to_string(&meta).map_err(|e| e.to_string())?;
    std::fs::write(meta_path(), meta_json).map_err(|e| format!("write meta: {e}"))?;

    // Cache master key for hook mode
    let key_file = session_key_path();
    std::fs::write(&key_file, B64.encode(&master_key)).map_err(|e| format!("write key: {e}"))?;
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
    let meta: VaultMeta = serde_json::from_str(&meta_json).map_err(|e| e.to_string())?;

    let salt = B64.decode(&meta.salt).map_err(|e| e.to_string())?;
    let master_key = derive_master_key(passphrase, &salt);
    let check = make_key_check(&master_key);
    let expected = B64.decode(&meta.key_check).map_err(|e| e.to_string())?;

    if check != expected {
        return Err("Wrong passphrase".into());
    }

    // Update session key cache
    let key_file = session_key_path();
    std::fs::write(&key_file, B64.encode(&master_key)).ok();

    Ok(Vault::new(master_key, db_path()))
}

/// Try loading vault from cached session key (for hook mode — no passphrase prompt).
pub fn try_load_vault() -> Option<Vault> {
    let key_data = std::fs::read_to_string(session_key_path()).ok()?;
    let master_bytes = B64.decode(key_data.trim()).ok()?;
    if master_bytes.len() != KEY_LEN {
        return None;
    }

    let meta_json = std::fs::read_to_string(meta_path()).ok()?;
    let meta: VaultMeta = serde_json::from_str(&meta_json).ok()?;
    let expected = B64.decode(&meta.key_check).ok()?;

    let mut master_key = [0u8; KEY_LEN];
    master_key.copy_from_slice(&master_bytes);
    let check = make_key_check(&master_key);

    if check != expected {
        return None;
    }

    Some(Vault::new(master_key, db_path()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a vault directly in a temp dir without touching HOME.
    fn make_test_vault(dir: &std::path::Path, passphrase: &str) -> Vault {
        let salt_path = dir.join("vault.meta");
        let db = dir.join("state.db");

        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let master_key = derive_master_key(passphrase, &salt);
        let check = make_key_check(&master_key);

        let meta = VaultMeta {
            salt: B64.encode(&salt),
            key_check: B64.encode(&check),
            created_at: now_epoch(),
        };
        std::fs::write(&salt_path, serde_json::to_string(&meta).unwrap()).unwrap();

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
        let dir = tempfile::tempdir().unwrap();
        let salt_path = dir.path().join("vault.meta");

        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let master_key = derive_master_key("correct", &salt);
        let check = make_key_check(&master_key);

        let meta = VaultMeta {
            salt: B64.encode(&salt),
            key_check: B64.encode(&check),
            created_at: now_epoch(),
        };
        std::fs::write(&salt_path, serde_json::to_string(&meta).unwrap()).unwrap();

        // Try to derive with wrong passphrase
        let wrong_key = derive_master_key("wrong", &salt);
        let wrong_check = make_key_check(&wrong_key);
        let expected = B64.decode(&meta.key_check).unwrap();
        assert_ne!(wrong_check, expected.as_slice());
    }

    #[test]
    fn test_recent_actions() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        vault.log_action("read", "ALLOW", "", 0.0, "");
        vault.log_action("write", "DENY", "", 0.0, "blocked");
        let actions = vault.recent_actions(10);
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_credential_exists() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        assert!(!vault.credential_exists("api_key"));
        vault.store_credential("api_key", "secret123", 2);
        assert!(vault.credential_exists("api_key"));
        assert!(!vault.credential_exists("nonexistent"));
    }

    #[test]
    fn test_delete_credential() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        vault.store_credential("to_delete", "val", 2);
        assert!(vault.credential_exists("to_delete"));
        assert!(vault.delete_credential("to_delete"));
        assert!(!vault.credential_exists("to_delete"));
        assert!(!vault.delete_credential("to_delete")); // already gone
    }

    #[test]
    fn test_get_credential_expired() {
        let dir = tempfile::tempdir().unwrap();
        let vault = make_test_vault(dir.path(), "testpass123");
        // Store with expiry in the past
        let past = now_epoch() - 3600.0;
        vault.store_credential_with_expiry("expired_key", "secret", 2, Some(past));
        assert_eq!(vault.get_credential("expired_key"), None);
        // Store without expiry — should work
        vault.store_credential("valid_key", "secret2", 2);
        assert_eq!(vault.get_credential("valid_key").as_deref(), Some("secret2"));
    }
}
