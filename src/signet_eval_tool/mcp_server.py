"""
Signet Eval MCP Server — Manage policies and vault through Claude.

Tools exposed:
  - signet_add_rule: Add a policy rule
  - signet_remove_rule: Remove a rule by name
  - signet_list_rules: Show current policy
  - signet_set_limit: Convenience: add a spending limit
  - signet_status: Vault status, recent actions, spending
  - signet_store_credential: Store a Tier 3 credential
  - signet_list_credentials: List credential names (not values)
  - signet_recent_actions: Show recent action log
"""

import json
import os
import sys
import yaml
from pathlib import Path

from mcp.server.fastmcp import FastMCP

POLICY_PATH = Path.home() / ".signet" / "policy.yaml"

mcp = FastMCP("signet", instructions="""Signet policy enforcement for Claude Code.
Use these tools to manage what actions are allowed, denied, or require confirmation.
When the user says things like "add a limit of $50 for amazon orders", use signet_set_limit.
When they say "block rm commands", use signet_add_rule with appropriate conditions.
When they say "show me what's blocked", use signet_list_rules.""")


def _load_policy() -> dict:
    """Load policy YAML as dict."""
    if not POLICY_PATH.exists():
        return {"version": 1, "default_action": "ALLOW", "rules": []}
    return yaml.safe_load(POLICY_PATH.read_text()) or {"version": 1, "default_action": "ALLOW", "rules": []}


def _save_policy(policy: dict):
    """Save policy dict as YAML."""
    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    POLICY_PATH.write_text(yaml.safe_dump(policy, default_flow_style=False, sort_keys=False))


@mcp.tool()
def signet_list_rules() -> str:
    """List all current policy rules. Shows what's blocked, allowed, or requires confirmation."""
    policy = _load_policy()
    if not policy.get("rules"):
        return f"No rules. Default action: {policy.get('default_action', 'ALLOW')}. Everything is allowed."

    lines = [f"Default: {policy.get('default_action', 'ALLOW')}", f"Rules ({len(policy['rules'])}):", ""]
    for i, r in enumerate(policy["rules"], 1):
        action = r.get("action", "DENY")
        name = r.get("name", f"rule_{i}")
        reason = r.get("reason", "")
        conditions = r.get("conditions", [])
        tool_pat = r.get("tool_pattern", ".*")

        lines.append(f"  {i}. [{action}] {name}")
        if reason:
            lines.append(f"     Reason: {reason}")
        if tool_pat != ".*":
            lines.append(f"     Tools: {tool_pat}")
        if conditions:
            for c in conditions:
                lines.append(f"     Condition: {c}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool()
def signet_add_rule(
    name: str,
    action: str,
    reason: str,
    tool_pattern: str = ".*",
    conditions: list[str] | None = None,
) -> str:
    """Add a policy rule. Action must be ALLOW, DENY, or ASK.

    Args:
        name: Human-readable rule name (e.g. "block_rm", "limit_amazon_spend")
        action: ALLOW, DENY, or ASK
        reason: Why this rule exists (shown when triggered)
        tool_pattern: Regex matching tool names (default ".*" matches all)
        conditions: List of Python expressions evaluated against the tool call.
                   Available variables: parameters (dict), tool_name (str),
                   session_spend(category), total_spend(category), amount, has_credential(name)
    """
    if action.upper() not in ("ALLOW", "DENY", "ASK"):
        return f"Invalid action '{action}'. Must be ALLOW, DENY, or ASK."

    policy = _load_policy()
    # Check for duplicate name
    for r in policy["rules"]:
        if r["name"] == name:
            return f"Rule '{name}' already exists. Remove it first with signet_remove_rule."

    rule = {
        "name": name,
        "tool_pattern": tool_pattern,
        "action": action.upper(),
        "conditions": conditions or [],
        "reason": reason,
    }
    policy["rules"].append(rule)
    _save_policy(policy)
    return f"Added rule '{name}' ({action.upper()}): {reason}"


@mcp.tool()
def signet_remove_rule(name: str) -> str:
    """Remove a policy rule by name.

    Args:
        name: The rule name to remove
    """
    policy = _load_policy()
    original_count = len(policy["rules"])
    policy["rules"] = [r for r in policy["rules"] if r["name"] != name]

    if len(policy["rules"]) == original_count:
        return f"Rule '{name}' not found."

    _save_policy(policy)
    return f"Removed rule '{name}'."


@mcp.tool()
def signet_set_limit(
    category: str,
    max_amount: float,
    per: str = "session",
    tool_pattern: str = ".*purchase.*|.*buy.*|.*shop.*|.*order.*",
) -> str:
    """Set a spending limit for a category. Convenience wrapper around signet_add_rule.

    Args:
        category: Spending category (e.g. "books", "amazon", "food")
        max_amount: Maximum allowed spend in dollars
        per: Time window — "session" (default) or "total"
        tool_pattern: Regex for tool names that count as purchases
    """
    spend_fn = "session_spend" if per == "session" else "total_spend"
    name = f"limit_{category}_{int(max_amount)}"

    conditions = [
        f"parameters.get('category', '') == '{category}'",
        f"{spend_fn}('{category}') + float(parameters.get('amount', 0)) > {max_amount}",
    ]

    policy = _load_policy()
    # Remove existing rule with same name
    policy["rules"] = [r for r in policy["rules"] if r["name"] != name]

    rule = {
        "name": name,
        "tool_pattern": tool_pattern,
        "action": "DENY",
        "conditions": conditions,
        "reason": f"Spending limit: ${max_amount:.0f}/{per} on {category}",
    }
    policy["rules"].append(rule)
    _save_policy(policy)
    return f"Set ${max_amount:.0f}/{per} limit on {category}."


@mcp.tool()
def signet_status() -> str:
    """Show vault status: session info, spending totals, credential count."""
    from signet_eval_tool.signet_eval_tool import _try_load_vault
    from signet_eval_tool.vault import vault_exists
    import time

    lines = []

    # Policy
    policy = _load_policy()
    lines.append(f"Policy: {len(policy.get('rules', []))} rules (default: {policy.get('default_action', 'ALLOW')})")

    # Vault
    if not vault_exists():
        lines.append("Vault: not set up (run: signet-eval --setup)")
        return "\n".join(lines)

    vault = _try_load_vault()
    if not vault:
        lines.append("Vault: locked")
        return "\n".join(lines)

    lines.append(f"Vault: unlocked ({'valid' if vault.session_valid() else 'expired'} session)")
    lines.append(f"Credentials: {len(vault.list_credentials())}")

    # Spending
    session = vault.session_spend()
    if session > 0:
        lines.append(f"Session spend: ${session:.2f}")

    # Recent actions
    actions = vault.recent_actions(5)
    if actions:
        lines.append(f"\nLast {len(actions)} actions:")
        for a in actions:
            t = time.strftime("%H:%M:%S", time.localtime(a["timestamp"]))
            amt = f" ${a['amount']:.2f}" if a["amount"] else ""
            cat = f" [{a['category']}]" if a["category"] else ""
            lines.append(f"  {t} {a['tool']}{cat}{amt} -> {a['decision']}")

    return "\n".join(lines)


@mcp.tool()
def signet_recent_actions(limit: int = 20) -> str:
    """Show recent action log from the vault.

    Args:
        limit: Number of recent actions to show (default 20)
    """
    from signet_eval_tool.signet_eval_tool import _try_load_vault
    from signet_eval_tool.vault import vault_exists
    import time

    if not vault_exists():
        return "No vault. Run: signet-eval --setup"

    vault = _try_load_vault()
    if not vault:
        return "Vault locked."

    actions = vault.recent_actions(limit)
    if not actions:
        return "No actions recorded yet."

    lines = [f"Recent actions ({len(actions)}):"]
    for a in actions:
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["timestamp"]))
        amt = f" ${a['amount']:.2f}" if a["amount"] else ""
        cat = f" [{a['category']}]" if a["category"] else ""
        det = f" — {a['detail'][:80]}" if a["detail"] else ""
        lines.append(f"  {t} {a['tool']}{cat}{amt} -> {a['decision']}{det}")

    return "\n".join(lines)


@mcp.tool()
def signet_store_credential(name: str, value: str) -> str:
    """Store a credential in the vault (Tier 3 — compartment encrypted, requires passphrase).

    Args:
        name: Credential name (e.g. "cc_visa", "aws_key")
        value: The secret value to store
    """
    from signet_eval_tool.signet_eval_tool import _try_load_vault
    from signet_eval_tool.vault import vault_exists, Tier

    if not vault_exists():
        return "No vault. Run: signet-eval --setup"

    vault = _try_load_vault()
    if not vault:
        return "Vault locked."

    vault.store_credential(name, value, Tier.RESTRICTED)
    return f"Stored '{name}' (Tier 3 compartment-encrypted). The agent cannot read this value without a user-issued decryption grant."


@mcp.tool()
def signet_list_credentials() -> str:
    """List credential names and metadata (never shows actual values)."""
    from signet_eval_tool.signet_eval_tool import _try_load_vault
    from signet_eval_tool.vault import vault_exists
    import time

    if not vault_exists():
        return "No vault. Run: signet-eval --setup"

    vault = _try_load_vault()
    if not vault:
        return "Vault locked."

    creds = vault.list_credentials()
    if not creds:
        return "No credentials stored."

    lines = [f"Credentials ({len(creds)}):"]
    for c in creds:
        created = time.strftime("%Y-%m-%d", time.localtime(c["created_at"]))
        expires = ""
        if c["expires_at"]:
            expires = f", expires {time.strftime('%Y-%m-%d', time.localtime(c['expires_at']))}"
        lines.append(f"  {c['name']} ({c['tier']}, created {created}{expires})")

    return "\n".join(lines)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
