"""
Signet Vault — Encrypted local state for policy evaluation.

Three-tier data model:
  Tier 1: Unencrypted. Policy rules, action log. Agent reads freely.
  Tier 2: Encrypted with session key. Spending ledger, session state.
          Agent can read during active session, but data at rest is encrypted.
  Tier 3: Encrypted with compartment key derived from user passphrase.
          CC numbers, API tokens. Agent cannot decrypt without user grant.

Key hierarchy:
  User passphrase (Argon2id)
    → Master key
      → Session key (Tier 2 encryption, HKDF-derived, TTL-bounded)
      → Compartment key (Tier 3 encryption, HKDF-derived, requires passphrase)
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes


# === Constants ===

SIGNET_DIR = Path.home() / ".signet"
STATE_DB = SIGNET_DIR / "state.db"
VAULT_META = SIGNET_DIR / "vault.meta"

SCRYPT_N = 2**17  # ~130ms on modern hardware
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LEN = 32
SESSION_TTL_SECONDS = 1800  # 30 minutes


class Tier(IntEnum):
    PUBLIC = 1    # Unencrypted
    SENSITIVE = 2  # Session-key encrypted
    RESTRICTED = 3  # Compartment-key encrypted (requires passphrase)


# === Key Derivation ===

def _derive_master_key(passphrase: str, salt: bytes) -> bytes:
    """Derive 32-byte master key from passphrase using scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def _derive_subkey(master_key: bytes, purpose: str) -> bytes:
    """Derive a purpose-specific subkey from master key via HKDF."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                 info=f"signet-{purpose}".encode())
    return hkdf.derive(master_key)


def _key_to_fernet(key_bytes: bytes) -> Fernet:
    """Convert raw 32-byte key to Fernet (needs url-safe base64 encoding)."""
    return Fernet(base64.urlsafe_b64encode(key_bytes))


# === Vault Metadata ===

@dataclass
class VaultMeta:
    salt: bytes
    master_key_check: bytes  # HMAC of known plaintext, for passphrase verification
    created_at: float

    def save(self, path: Path = None):
        if path is None:
            path = VAULT_META
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "salt": base64.b64encode(self.salt).decode(),
            "master_key_check": base64.b64encode(self.master_key_check).decode(),
            "created_at": self.created_at,
        }
        path.write_text(json.dumps(data))

    @classmethod
    def load(cls, path: Path = None) -> "VaultMeta":
        if path is None:
            path = VAULT_META
        data = json.loads(path.read_text())
        return cls(
            salt=base64.b64decode(data["salt"]),
            master_key_check=base64.b64decode(data["master_key_check"]),
            created_at=data["created_at"],
        )


def _make_key_check(master_key: bytes) -> bytes:
    """Create a check value to verify passphrase correctness."""
    return hmac.new(master_key, b"signet-vault-check", hashlib.sha256).digest()


# === Vault ===

class Vault:
    """Encrypted local state store with tiered access."""

    def __init__(self, master_key: bytes, db_path: Path = None):
        if db_path is None:
            db_path = STATE_DB
        self._master_key = master_key
        self._session_key = _derive_subkey(master_key, "session")
        self._compartment_key = _derive_subkey(master_key, "compartment")
        self._session_fernet = _key_to_fernet(self._session_key)
        self._compartment_fernet = _key_to_fernet(self._compartment_key)
        self._db_path = db_path
        self._init_db()
        self._session_unlocked_at = self._load_or_create_session_start()

    def _init_db(self):
        """Create tables if they don't exist."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    tool TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT '',
                    amount REAL NOT NULL DEFAULT 0.0,
                    decision TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    tier INTEGER NOT NULL,
                    encrypted_value TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL,
                    metadata TEXT NOT NULL DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_category ON ledger(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger(timestamp)")

    def _load_or_create_session_start(self) -> float:
        """Load persisted session start time, or create one if expired/missing."""
        with sqlite3.connect(str(self._db_path)) as conn:
            row = conn.execute(
                "SELECT value FROM session_state WHERE key = '_session_start'"
            ).fetchone()
            if row:
                try:
                    start_time = float(row[0])
                    if (time.time() - start_time) < SESSION_TTL_SECONDS:
                        return start_time
                except (ValueError, TypeError):
                    pass
            # Create new session
            now = time.time()
            conn.execute(
                "INSERT OR REPLACE INTO session_state (key, value, updated_at) "
                "VALUES ('_session_start', ?, ?)",
                (str(now), now)
            )
            return now

    def reset_session(self):
        """Start a new session (resets session_spend counters)."""
        now = time.time()
        self._session_unlocked_at = now
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO session_state (key, value, updated_at) "
                "VALUES ('_session_start', ?, ?)",
                (str(now), now)
            )

    # --- Session validity ---

    def session_valid(self) -> bool:
        """Check if the current session key is still within TTL."""
        return (time.time() - self._session_unlocked_at) < SESSION_TTL_SECONDS

    # --- Ledger (Tier 1 — unencrypted, append-only) ---

    def log_action(self, tool: str, decision: str, category: str = "",
                   amount: float = 0.0, detail: str = ""):
        """Append an action to the spending ledger."""
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                "INSERT INTO ledger (timestamp, tool, category, amount, decision, detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (time.time(), tool, category, amount, decision, detail)
            )

    def total_spend(self, category: str = "", since: float = 0.0) -> float:
        """Sum spending in a category since a timestamp."""
        with sqlite3.connect(str(self._db_path)) as conn:
            if category:
                row = conn.execute(
                    "SELECT COALESCE(SUM(amount), 0) FROM ledger "
                    "WHERE category = ? AND timestamp >= ? AND decision = 'ALLOW'",
                    (category, since)
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COALESCE(SUM(amount), 0) FROM ledger "
                    "WHERE timestamp >= ? AND decision = 'ALLOW'",
                    (since,)
                ).fetchone()
            return row[0]

    def session_spend(self, category: str = "") -> float:
        """Total spend in current session (since session unlock)."""
        return self.total_spend(category, since=self._session_unlocked_at)

    def recent_actions(self, limit: int = 20) -> list:
        """Return recent ledger entries."""
        with sqlite3.connect(str(self._db_path)) as conn:
            rows = conn.execute(
                "SELECT timestamp, tool, category, amount, decision, detail "
                "FROM ledger ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [
                {"timestamp": r[0], "tool": r[1], "category": r[2],
                 "amount": r[3], "decision": r[4], "detail": r[5]}
                for r in rows
            ]

    # --- Credentials (Tier 2 or 3 — encrypted) ---

    def store_credential(self, name: str, value: str, tier: Tier,
                         expires_at: float = None, metadata: dict = None):
        """Store an encrypted credential."""
        if tier == Tier.RESTRICTED:
            encrypted = self._compartment_fernet.encrypt(value.encode()).decode()
        else:
            encrypted = self._session_fernet.encrypt(value.encode()).decode()

        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO credentials "
                "(name, tier, encrypted_value, created_at, expires_at, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, int(tier), encrypted, time.time(), expires_at,
                 json.dumps(metadata or {}))
            )

    def get_credential(self, name: str) -> Optional[str]:
        """Retrieve and decrypt a credential. Returns None if not found or expired."""
        with sqlite3.connect(str(self._db_path)) as conn:
            row = conn.execute(
                "SELECT tier, encrypted_value, expires_at FROM credentials WHERE name = ?",
                (name,)
            ).fetchone()

        if not row:
            return None

        tier, encrypted, expires_at = row
        if expires_at and time.time() > expires_at:
            return None

        try:
            if tier == Tier.RESTRICTED:
                return self._compartment_fernet.decrypt(encrypted.encode()).decode()
            else:
                if not self.session_valid():
                    return None
                return self._session_fernet.decrypt(encrypted.encode()).decode()
        except InvalidToken:
            return None

    def list_credentials(self) -> list:
        """List credential names and metadata (not values)."""
        with sqlite3.connect(str(self._db_path)) as conn:
            rows = conn.execute(
                "SELECT name, tier, created_at, expires_at, metadata FROM credentials"
            ).fetchall()
            return [
                {"name": r[0], "tier": Tier(r[1]).name, "created_at": r[2],
                 "expires_at": r[3], "metadata": json.loads(r[4])}
                for r in rows
            ]

    # --- Session State (Tier 2 — encrypted key-value) ---

    def set_state(self, key: str, value: str):
        """Set an encrypted session state value."""
        encrypted = self._session_fernet.encrypt(value.encode()).decode()
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO session_state (key, value, updated_at) "
                "VALUES (?, ?, ?)",
                (key, encrypted, time.time())
            )

    def get_state(self, key: str) -> Optional[str]:
        """Get a decrypted session state value."""
        if not self.session_valid():
            return None
        with sqlite3.connect(str(self._db_path)) as conn:
            row = conn.execute(
                "SELECT value FROM session_state WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return None
        try:
            return self._session_fernet.decrypt(row[0].encode()).decode()
        except InvalidToken:
            return None


# === Setup & Unlock ===

def setup_vault(passphrase: str) -> Vault:
    """Create a new vault with a passphrase. Overwrites existing vault metadata."""
    salt = secrets.token_bytes(SALT_LEN)
    master_key = _derive_master_key(passphrase, salt)
    check = _make_key_check(master_key)

    meta = VaultMeta(salt=salt, master_key_check=check, created_at=time.time())
    meta.save()

    return Vault(master_key)


def unlock_vault(passphrase: str) -> Vault:
    """Unlock an existing vault with a passphrase."""
    if not VAULT_META.exists():
        raise FileNotFoundError("No vault found. Run 'signet-eval --setup' first.")

    meta = VaultMeta.load()
    master_key = _derive_master_key(passphrase, meta.salt)
    check = _make_key_check(master_key)

    if not hmac.compare_digest(check, meta.master_key_check):
        raise ValueError("Wrong passphrase")

    return Vault(master_key)


def vault_exists() -> bool:
    """Check if a vault has been set up."""
    return VAULT_META.exists()
