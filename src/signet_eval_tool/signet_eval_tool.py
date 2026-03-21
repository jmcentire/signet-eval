#!/usr/bin/env python3
"""
Signet Evaluation Tool — Claude Code PreToolUse hook policy enforcer.
Deterministic policy evaluation. No NLP. No network.
"""

import getpass
import json
import re
import time
import os
import sys
import argparse
import yaml
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Any


# === Exception Classes ===

class ArgumentError(Exception):
    """Error in command-line arguments"""

class PolicyInitError(Exception):
    """Error initializing policy file"""

class PolicyParseError(Exception):
    """Error parsing policy configuration"""

class RegexCompileError(Exception):
    """Error compiling regex pattern"""

class ValidationError(Exception):
    """Error in data validation"""

class InputSizeError(Exception):
    """Error when input exceeds size limit"""

class EvaluationTimeoutError(Exception):
    """Error when evaluation exceeds time limit"""

class RegexMatchError(Exception):
    """Error during regex pattern matching"""

class ConditionEvalError(Exception):
    """Error evaluating rule condition"""

class SerializationError(Exception):
    """Error serializing result to JSON"""

class FileSystemError(Exception):
    """Error with file system operations"""

class ArgumentParsingError(Exception):
    """Error parsing command-line arguments"""


# === Core Types ===

class Decision(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ASK = "ASK"


@dataclass
class ToolUseRequest:
    tool_name: str
    parameters: dict
    context: dict = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.tool_name, str):
            raise ValidationError("tool_name must be a string")
        if not self.tool_name or len(self.tool_name) > 100:
            raise ValidationError("tool_name must be between 1 and 100 characters")
        if not isinstance(self.parameters, dict):
            raise ValidationError("parameters must be a dict")
        if not isinstance(self.context, dict):
            raise ValidationError("context must be a dict")


@dataclass
class PolicyRule:
    name: str
    tool_pattern: str
    conditions: List[str] = field(default_factory=list)
    action: Decision = Decision.DENY
    reason: Optional[str] = None
    _compiled_pattern: Optional[re.Pattern] = field(init=False, repr=False, default=None)

    def __post_init__(self):
        if not self.name or len(self.name) > 200:
            raise ValidationError("name must be between 1 and 200 characters")
        try:
            self._compiled_pattern = re.compile(self.tool_pattern)
        except re.error as e:
            raise ValidationError(f"Invalid regex pattern: {e}")


@dataclass
class PolicyConfig:
    version: int
    rules: List[PolicyRule]
    default_action: Decision = Decision.DENY

    def __post_init__(self):
        if self.version < 1:
            raise ValidationError("version must be >= 1")


@dataclass
class EvaluationResult:
    decision: Decision
    evaluation_time_ms: float
    matched_rule: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class CliArgs:
    init: bool = False
    policy_path: Optional[str] = None
    verbose: bool = False
    setup: bool = False
    status: bool = False
    store: Optional[list] = None


# === Dotdict helper for condition evaluation ===

class _DotDict(dict):
    """Dict subclass allowing attribute access for condition evaluation."""
    def __getattr__(self, key):
        try:
            val = self[key]
            if isinstance(val, dict):
                return _DotDict(val)
            return val
        except KeyError:
            raise AttributeError(key)


# === Default Policy ===

def get_default_policy() -> PolicyConfig:
    """Return embedded default policy configuration as fallback."""
    rules = [
        PolicyRule(
            name="block_rm",
            tool_pattern=".*",
            conditions=["'rm ' in str(parameters) or str(parameters).endswith(\"'rm'\")"],
            action=Decision.DENY,
            reason="File deletion blocked by policy"
        ),
        PolicyRule(
            name="block_force_push",
            tool_pattern=".*",
            conditions=["'push --force' in str(parameters) or 'push -f' in str(parameters)"],
            action=Decision.ASK,
            reason="Force push requires confirmation"
        ),
        PolicyRule(
            name="block_destructive_disk",
            tool_pattern=".*",
            conditions=["any(w in str(parameters) for w in ['mkfs', 'format ', 'dd if='])"],
            action=Decision.DENY,
            reason="Destructive disk operations blocked"
        ),
        PolicyRule(
            name="block_piped_exec",
            tool_pattern=".*",
            conditions=["('curl' in str(parameters) or 'wget' in str(parameters)) and '| sh' in str(parameters)"],
            action=Decision.DENY,
            reason="Piped remote execution blocked"
        ),
    ]
    return PolicyConfig(version=1, rules=rules, default_action=Decision.ALLOW)


# === Core Functions ===

def parse_args(args: List[str]) -> CliArgs:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(prog="signet-eval", description="Signet Policy Evaluation Tool")
    parser.add_argument("--init", action="store_true", help="Initialize default policy file")
    parser.add_argument("--setup", action="store_true", help="Create encrypted vault with passphrase")
    parser.add_argument("--status", action="store_true", help="Show vault status and recent actions")
    parser.add_argument("--store", nargs=2, metavar=("NAME", "VALUE"),
                        help="Store a Tier 3 credential (e.g. --store cc_visa 4111...)")
    parser.add_argument("--policy-path", type=str,
                        default=os.path.expanduser("~/.signet/policy.yaml"),
                        help="Path to policy configuration file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    try:
        parsed = parser.parse_args(args)
        return CliArgs(
            init=parsed.init, policy_path=parsed.policy_path, verbose=parsed.verbose,
            setup=getattr(parsed, 'setup', False),
            status=getattr(parsed, 'status', False),
            store=getattr(parsed, 'store', None),
        )
    except SystemExit:
        raise ArgumentError("Invalid arguments")


def init_policy_file(policy_path: Optional[str] = None) -> None:
    """Create default policy file at specified or standard location."""
    if policy_path is None:
        policy_path = os.path.expanduser("~/.signet/policy.yaml")

    try:
        Path(policy_path).parent.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise PermissionError(f"Insufficient permissions: {e}")
    except OSError as e:
        raise FileSystemError(f"Cannot create directories: {e}")

    default_policy = get_default_policy()
    policy_dict = {
        "version": default_policy.version,
        "default_action": default_policy.default_action.value,
        "rules": [
            {
                "name": r.name,
                "tool_pattern": r.tool_pattern,
                "action": r.action.value,
                "conditions": r.conditions,
                "reason": r.reason,
            }
            for r in default_policy.rules
        ],
    }

    try:
        with open(policy_path, "w") as f:
            yaml.safe_dump(policy_dict, f, default_flow_style=False)
    except PermissionError as e:
        raise PermissionError(f"Cannot write policy file: {e}")
    except OSError as e:
        raise FileSystemError(f"Cannot write policy file: {e}")


def load_policy(policy_path: Optional[str] = None) -> PolicyConfig:
    """Load policy from file with fallback to defaults."""
    if policy_path is None:
        policy_path = os.path.expanduser("~/.signet/policy.yaml")

    env_path = os.environ.get("SIGNET_POLICY_PATH")
    if env_path:
        policy_path = env_path

    if not os.path.exists(policy_path):
        return get_default_policy()

    try:
        with open(policy_path, "r") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise PolicyParseError(f"Invalid YAML: {e}")
    except OSError:
        return get_default_policy()

    if not data or not isinstance(data, dict):
        return get_default_policy()

    rules = []
    for rd in data.get("rules", []):
        try:
            action = Decision(rd["action"])
            rules.append(PolicyRule(
                name=rd["name"],
                tool_pattern=rd["tool_pattern"],
                action=action,
                conditions=rd.get("conditions", []),
                reason=rd.get("reason"),
            ))
        except (KeyError, ValueError) as e:
            raise RegexCompileError(f"Invalid rule: {e}")
        except ValidationError as e:
            raise RegexCompileError(str(e))

    default_action = Decision(data.get("default_action", "DENY"))
    return PolicyConfig(version=data.get("version", 1), rules=rules, default_action=default_action)


def parse_hook_input(json_input: str) -> ToolUseRequest:
    """Parse and validate Claude Code PreToolUse hook JSON."""
    max_size = 1024 * 1024
    if len(json_input.encode("utf-8")) > max_size:
        raise InputSizeError(f"Input exceeds {max_size} bytes")

    try:
        data = json.loads(json_input)
    except json.JSONDecodeError:
        raise

    if not isinstance(data, dict):
        raise ValidationError("Input must be a JSON object")
    if "tool_name" not in data:
        raise ValidationError("Missing required field: tool_name")

    # Accept both "parameters" and "tool_input" (Claude Code hook format)
    params = data.get("parameters") or data.get("tool_input") or {}
    if not isinstance(params, dict):
        params = {"raw": params}

    return ToolUseRequest(
        tool_name=data["tool_name"],
        parameters=params,
        context={k: v for k, v in data.items() if k not in ("tool_name", "parameters", "tool_input")},
    )


def match_rule_conditions(request: ToolUseRequest, rule: PolicyRule, vault=None) -> bool:
    """Check if tool request matches all conditions in a policy rule."""
    try:
        if not rule._compiled_pattern.search(request.tool_name):
            return False
    except Exception as e:
        raise RegexMatchError(f"Regex matching failed: {e}")

    if not rule.conditions:
        return True

    # Stateful functions available in policy conditions (no-op if no vault)
    def _session_spend(category=""):
        return vault.session_spend(category) if vault else 0.0

    def _total_spend(category="", since=0.0):
        return vault.total_spend(category, since) if vault else 0.0

    def _has_credential(name):
        if not vault:
            return False
        return vault.get_credential(name) is not None

    # Build eval globals with dot-accessible dicts + safe builtins + vault functions
    # Variables must be in globals (not locals) for generator expression scoping
    eval_globals = {
        "__builtins__": {"any": any, "all": all, "str": str, "len": len, "int": int,
                         "float": float, "True": True, "False": False},
        "tool_name": request.tool_name,
        "parameters": _DotDict(request.parameters),
        "context": _DotDict(request.context),
        # Stateful functions
        "session_spend": _session_spend,
        "total_spend": _total_spend,
        "has_credential": _has_credential,
        # Convenience: extract amount from parameters if present
        "amount": float(request.parameters.get("amount", 0)),
    }

    for condition in rule.conditions:
        try:
            if not eval(condition, eval_globals):
                return False
        except Exception as e:
            raise ConditionEvalError(f"Error evaluating condition '{condition}': {e}")

    return True


def evaluate_request(request: ToolUseRequest, policy: PolicyConfig, vault=None) -> EvaluationResult:
    """Evaluate tool use request against policy rules. First-match-wins."""
    start = time.perf_counter()

    try:
        for rule in policy.rules:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if elapsed_ms > 14.0:
                raise EvaluationTimeoutError("Evaluation exceeded 15ms budget")

            try:
                if match_rule_conditions(request, rule, vault=vault):
                    dt = (time.perf_counter() - start) * 1000
                    return EvaluationResult(
                        decision=rule.action,
                        matched_rule=rule.name,
                        reason=rule.reason,
                        evaluation_time_ms=dt,
                    )
            except (RegexMatchError, ConditionEvalError):
                raise
            except Exception:
                continue

        dt = (time.perf_counter() - start) * 1000
        return EvaluationResult(
            decision=policy.default_action,
            matched_rule="",
            reason="No matching rules, using default action",
            evaluation_time_ms=dt,
        )

    except (EvaluationTimeoutError, RegexMatchError, ConditionEvalError):
        raise
    except Exception as e:
        dt = (time.perf_counter() - start) * 1000
        return EvaluationResult(
            decision=Decision.DENY,
            matched_rule="",
            reason=f"Evaluation error: {e}",
            evaluation_time_ms=dt,
        )


def format_output(result: EvaluationResult) -> str:
    """Format evaluation result as JSON."""
    try:
        d = {
            "decision": result.decision.value,
            "matched_rule": result.matched_rule,
            "reason": result.reason,
            "evaluation_time_ms": result.evaluation_time_ms,
        }
        return json.dumps(d, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        raise SerializationError(f"Cannot serialize: {e}")


def _try_load_vault():
    """Try to load vault without passphrase (for hook mode — uses cached session)."""
    try:
        from signet_eval_tool.vault import vault_exists, VAULT_META, VaultMeta, _derive_master_key, _make_key_check, Vault
        if not vault_exists():
            return None
        # In hook mode, we can't prompt for passphrase. Check for session key file.
        session_file = Path.home() / ".signet" / ".session_key"
        if not session_file.exists():
            return None
        import base64
        master_key = base64.b64decode(session_file.read_text().strip())
        meta = VaultMeta.load()
        import hmac, hashlib
        check = hmac.new(master_key, b"signet-vault-check", hashlib.sha256).digest()
        if not hmac.compare_digest(check, meta.master_key_check):
            return None
        return Vault(master_key)
    except Exception:
        return None


def main(args: List[str] = None) -> int:
    """Main CLI entry point."""
    if args is None:
        args = sys.argv[1:]

    try:
        cli_args = parse_args(args)
    except ArgumentError:
        return 2

    # --- Setup vault ---
    if cli_args.setup:
        from signet_eval_tool.vault import setup_vault, vault_exists
        if vault_exists():
            print("Vault already exists at ~/.signet/. To reset, delete ~/.signet/vault.meta first.", file=sys.stderr)
            return 1
        passphrase = getpass.getpass("Create vault passphrase: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            print("Passphrases don't match.", file=sys.stderr)
            return 1
        if len(passphrase) < 8:
            print("Passphrase must be at least 8 characters.", file=sys.stderr)
            return 1
        vault = setup_vault(passphrase)
        # Cache master key for session use (hook mode can't prompt)
        import base64
        session_file = Path.home() / ".signet" / ".session_key"
        session_file.write_text(base64.b64encode(vault._master_key).decode())
        session_file.chmod(0o600)
        print("Vault created. Session key cached at ~/.signet/.session_key")
        print("Policy evaluation can now use stateful conditions (spending limits, etc.)")
        return 0

    # --- Status ---
    if cli_args.status:
        from signet_eval_tool.vault import vault_exists
        if not vault_exists():
            print("No vault. Run: signet-eval --setup")
            return 1
        vault = _try_load_vault()
        if not vault:
            print("Vault locked. Run: signet-eval --unlock")
            return 1
        print(f"Vault: unlocked (session {'valid' if vault.session_valid() else 'expired'})")
        print(f"Credentials: {len(vault.list_credentials())}")
        actions = vault.recent_actions(10)
        if actions:
            print(f"\nRecent actions ({len(actions)}):")
            for a in actions:
                t = time.strftime("%H:%M:%S", time.localtime(a["timestamp"]))
                amt = f" ${a['amount']:.2f}" if a["amount"] else ""
                cat = f" [{a['category']}]" if a["category"] else ""
                print(f"  {t} {a['tool']}{cat}{amt} -> {a['decision']}")
        spend = vault.session_spend()
        if spend > 0:
            print(f"\nSession spend: ${spend:.2f}")
        return 0

    # --- Store credential ---
    if cli_args.store:
        from signet_eval_tool.vault import vault_exists, Tier
        if not vault_exists():
            print("No vault. Run: signet-eval --setup", file=sys.stderr)
            return 1
        vault = _try_load_vault()
        if not vault:
            print("Vault locked.", file=sys.stderr)
            return 1
        name, value = cli_args.store
        vault.store_credential(name, value, Tier.RESTRICTED)
        print(f"Stored '{name}' as Tier 3 (compartment-encrypted)")
        return 0

    # --- Init policy ---
    if cli_args.init:
        try:
            init_policy_file(cli_args.policy_path)
            return 0
        except (FileSystemError, PermissionError, PolicyInitError):
            return 1

    # --- Hook evaluation (default mode) ---
    try:
        policy = load_policy(cli_args.policy_path)
    except (PolicyParseError, RegexCompileError):
        policy = get_default_policy()

    try:
        raw = sys.stdin.read()
        request = parse_hook_input(raw)
    except (json.JSONDecodeError, ValidationError, InputSizeError):
        out = json.dumps({"permissionDecision": "deny", "permissionDecisionReason": "Malformed hook input"})
        print(out)
        return 0

    # Load vault for stateful conditions (optional — works without it)
    vault = _try_load_vault()

    result = evaluate_request(request, policy, vault=vault)

    # Log action to vault if available
    if vault:
        try:
            # Extract amount/category from tool input if present
            amount = float(request.parameters.get("amount", 0))
            category = str(request.parameters.get("category", ""))
            vault.log_action(
                tool=request.tool_name,
                decision=result.decision.value,
                category=category,
                amount=amount if result.decision == Decision.ALLOW else 0.0,
                detail=json.dumps(request.parameters)[:500],
            )
        except Exception:
            pass  # Never let logging break evaluation

    # Emit Claude Code hook response format
    hook_response = {"permissionDecision": result.decision.value.lower()}
    if result.decision != Decision.ALLOW and result.reason:
        hook_response["permissionDecisionReason"] = result.reason

    print(json.dumps(hook_response))
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    # Types
    "Decision", "ToolUseRequest", "PolicyRule", "PolicyConfig", "EvaluationResult", "CliArgs",
    # Functions
    "main", "parse_args", "init_policy_file", "load_policy", "parse_hook_input",
    "evaluate_request", "match_rule_conditions", "format_output", "get_default_policy",
    # Exceptions
    "ArgumentError", "PolicyInitError", "PolicyParseError", "RegexCompileError",
    "ValidationError", "InputSizeError", "EvaluationTimeoutError", "RegexMatchError",
    "ConditionEvalError", "SerializationError", "FileSystemError", "ArgumentParsingError",
]

# Re-export builtins for contract compliance
SystemExit = SystemExit
TimeoutError = TimeoutError
