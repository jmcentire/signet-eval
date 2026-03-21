"""Tests for the Signet vault — encrypted state store."""

import os
import tempfile
import time
import pytest
from pathlib import Path

from signet_eval_tool.vault import (
    Vault, VaultMeta, Tier,
    setup_vault, unlock_vault, vault_exists,
    _derive_master_key, _derive_subkey, _make_key_check,
    VAULT_META, STATE_DB,
)


@pytest.fixture
def tmp_signet(tmp_path, monkeypatch):
    """Redirect vault paths to a temp directory."""
    import signet_eval_tool.vault as v
    monkeypatch.setattr(v, "SIGNET_DIR", tmp_path)
    monkeypatch.setattr(v, "STATE_DB", tmp_path / "state.db")
    monkeypatch.setattr(v, "VAULT_META", tmp_path / "vault.meta")
    return tmp_path


class TestKeyDerivation:
    def test_derive_master_key_deterministic(self):
        salt = b"0" * 32
        k1 = _derive_master_key("testpass", salt)
        k2 = _derive_master_key("testpass", salt)
        assert k1 == k2
        assert len(k1) == 32

    def test_different_salt_different_key(self):
        k1 = _derive_master_key("testpass", b"a" * 32)
        k2 = _derive_master_key("testpass", b"b" * 32)
        assert k1 != k2

    def test_different_passphrase_different_key(self):
        salt = b"0" * 32
        k1 = _derive_master_key("pass1", salt)
        k2 = _derive_master_key("pass2", salt)
        assert k1 != k2

    def test_subkey_derivation(self):
        master = b"0" * 32
        session = _derive_subkey(master, "session")
        compartment = _derive_subkey(master, "compartment")
        assert session != compartment
        assert len(session) == 32


class TestVaultSetupUnlock:
    def test_setup_creates_vault(self, tmp_signet):
        vault = setup_vault("testpassphrase")
        assert (tmp_signet / "vault.meta").exists()
        assert (tmp_signet / "state.db").exists()

    def test_unlock_with_correct_passphrase(self, tmp_signet):
        setup_vault("testpassphrase")
        vault = unlock_vault("testpassphrase")
        assert vault is not None

    def test_unlock_with_wrong_passphrase(self, tmp_signet):
        setup_vault("testpassphrase")
        with pytest.raises(ValueError, match="Wrong passphrase"):
            unlock_vault("wrongpassphrase")

    def test_unlock_without_setup(self, tmp_signet):
        with pytest.raises(FileNotFoundError):
            unlock_vault("anything")

    def test_vault_exists(self, tmp_signet):
        assert not vault_exists()
        setup_vault("testpassphrase")
        assert vault_exists()


class TestLedger:
    def test_log_and_query(self, tmp_signet):
        vault = setup_vault("testpass12")
        vault.log_action("purchase", "ALLOW", category="books", amount=25.0)
        vault.log_action("purchase", "ALLOW", category="books", amount=15.0)
        vault.log_action("purchase", "ALLOW", category="food", amount=50.0)

        assert vault.total_spend("books") == 40.0
        assert vault.total_spend("food") == 50.0
        assert vault.total_spend() == 90.0

    def test_session_spend(self, tmp_signet):
        vault = setup_vault("testpass12")
        vault.log_action("purchase", "ALLOW", category="books", amount=30.0)
        assert vault.session_spend("books") == 30.0
        assert vault.session_spend("food") == 0.0

    def test_denied_actions_not_counted(self, tmp_signet):
        vault = setup_vault("testpass12")
        vault.log_action("purchase", "ALLOW", category="books", amount=25.0)
        vault.log_action("purchase", "DENY", category="books", amount=300.0)
        assert vault.total_spend("books") == 25.0

    def test_recent_actions(self, tmp_signet):
        vault = setup_vault("testpass12")
        vault.log_action("read", "ALLOW")
        vault.log_action("write", "DENY", detail="blocked")
        actions = vault.recent_actions(10)
        assert len(actions) == 2
        assert actions[0]["tool"] == "write"  # Most recent first


class TestCredentials:
    def test_store_and_retrieve_tier2(self, tmp_signet):
        vault = setup_vault("testpass12")
        vault.store_credential("api_key", "sk-1234567890", Tier.SENSITIVE)
        assert vault.get_credential("api_key") == "sk-1234567890"

    def test_store_and_retrieve_tier3(self, tmp_signet):
        vault = setup_vault("testpass12")
        vault.store_credential("cc_visa", "4111111111111111", Tier.RESTRICTED)
        assert vault.get_credential("cc_visa") == "4111111111111111"

    def test_credential_not_found(self, tmp_signet):
        vault = setup_vault("testpass12")
        assert vault.get_credential("nonexistent") is None

    def test_expired_credential(self, tmp_signet):
        vault = setup_vault("testpass12")
        vault.store_credential("temp_token", "abc123", Tier.SENSITIVE, expires_at=time.time() - 1)
        assert vault.get_credential("temp_token") is None

    def test_list_credentials_no_values(self, tmp_signet):
        vault = setup_vault("testpass12")
        vault.store_credential("cc_visa", "4111111111111111", Tier.RESTRICTED)
        vault.store_credential("api_key", "sk-123", Tier.SENSITIVE)
        creds = vault.list_credentials()
        assert len(creds) == 2
        names = {c["name"] for c in creds}
        assert names == {"cc_visa", "api_key"}
        # Values should NOT be in the listing
        for c in creds:
            assert "4111" not in str(c)
            assert "sk-123" not in str(c)

    def test_different_vaults_cant_read_each_others_creds(self, tmp_signet):
        vault1 = setup_vault("passphrase1")
        vault1.store_credential("secret", "vault1_data", Tier.RESTRICTED)

        # Setup new vault with different passphrase (overwrites meta)
        vault2 = setup_vault("passphrase2")
        # vault2 can't decrypt vault1's credentials
        assert vault2.get_credential("secret") is None


class TestSessionState:
    def test_set_and_get(self, tmp_signet):
        vault = setup_vault("testpass12")
        vault.set_state("current_budget", "500.00")
        assert vault.get_state("current_budget") == "500.00"

    def test_get_missing_key(self, tmp_signet):
        vault = setup_vault("testpass12")
        assert vault.get_state("nonexistent") is None


class TestStatefulPolicyConditions:
    """Test that vault functions work in policy condition evaluation."""

    def test_spending_limit_condition(self, tmp_signet):
        from signet_eval_tool.signet_eval_tool import (
            ToolUseRequest, PolicyRule, PolicyConfig, Decision,
            evaluate_request,
        )

        vault = setup_vault("testpass12")
        vault.log_action("purchase", "ALLOW", category="books", amount=180.0)

        request = ToolUseRequest(
            tool_name="mcp__shop__buy",
            parameters={"amount": "25", "category": "books"},
            context={},
        )

        # Rule: deny if session spend on books + this amount > 200
        rule = PolicyRule(
            name="books_spending_limit",
            tool_pattern=".*",
            conditions=["session_spend('books') + float(parameters.get('amount', 0)) > 200"],
            action=Decision.DENY,
            reason="Books spending limit ($200) exceeded",
        )
        policy = PolicyConfig(version=1, rules=[rule], default_action=Decision.ALLOW)

        result = evaluate_request(request, policy, vault=vault)
        assert result.decision == Decision.DENY
        assert "spending limit" in result.reason

    def test_under_spending_limit_allows(self, tmp_signet):
        from signet_eval_tool.signet_eval_tool import (
            ToolUseRequest, PolicyRule, PolicyConfig, Decision,
            evaluate_request,
        )

        vault = setup_vault("testpass12")
        vault.log_action("purchase", "ALLOW", category="books", amount=100.0)

        request = ToolUseRequest(
            tool_name="mcp__shop__buy",
            parameters={"amount": "25", "category": "books"},
            context={},
        )

        rule = PolicyRule(
            name="books_spending_limit",
            tool_pattern=".*",
            conditions=["session_spend('books') + float(parameters.get('amount', 0)) > 200"],
            action=Decision.DENY,
            reason="Books spending limit ($200) exceeded",
        )
        policy = PolicyConfig(version=1, rules=[rule], default_action=Decision.ALLOW)

        result = evaluate_request(request, policy, vault=vault)
        assert result.decision == Decision.ALLOW
