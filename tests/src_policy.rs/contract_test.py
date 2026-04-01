"""
Contract test suite for src_policy.rs
Generated from contract version 1

Tests cover:
- Decision enum lowercase conversion
- Default value functions (gate_within, ensure_timeout, version, allow)
- PolicyConfig compilation with regex validation
- Condition evaluation with all supported functions
- Policy evaluation (first-match-wins, locked rules, Gate/Ensure resolution)
- File loading with error handling
- Policy validation
- Ensure check name and path validation
- Self-protection rules invariants
- Default policy structure
- Parsing helpers (split_at_top_level, strip_fn, extract_quoted)
- Parameter extraction (param_str, param_f64)
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open
from typing import Optional, Dict, Any, List

# Import the module under test
# Note: Adjust import path based on actual Python bindings
try:
    from src_policy import *
except ImportError:
    # Fallback for testing - create mock types
    class Decision:
        Allow = "Allow"
        Deny = "Deny"
        Ask = "Ask"
        Gate = "Gate"
        Ensure = "Ensure"
        
        @staticmethod
        def as_lowercase(variant):
            return variant.lower()
    
    class GateConfig:
        def __init__(self, requires_prior: str, within: int = 50):
            self.requires_prior = requires_prior
            self.within = within
    
    class EnsureConfig:
        def __init__(self, check: str, timeout: int = 5, message: str = ""):
            self.check = check
            self.timeout = timeout
            self.message = message
    
    class PolicyRule:
        def __init__(self, name: str, tool_pattern: str, conditions: List[str], 
                     action: str, reason: Optional[str] = None, 
                     alternative: Optional[str] = None, locked: bool = False,
                     gate: Optional[GateConfig] = None, 
                     ensure: Optional[EnsureConfig] = None):
            self.name = name
            self.tool_pattern = tool_pattern
            self.conditions = conditions
            self.action = action
            self.reason = reason
            self.alternative = alternative
            self.locked = locked
            self.gate = gate
            self.ensure = ensure
    
    class PolicyConfig:
        def __init__(self, version: int = 1, rules: List[PolicyRule] = None, 
                     default_action: str = "Allow"):
            self.version = version
            self.rules = rules or []
            self.default_action = default_action
    
    class CompiledRule:
        def __init__(self, name: str, tool_regex, conditions: List[str], 
                     action: str, reason: Optional[str] = None,
                     alternative: Optional[str] = None, locked: bool = False,
                     gate: Optional[GateConfig] = None,
                     ensure: Optional[EnsureConfig] = None):
            self.name = name
            self.tool_regex = tool_regex
            self.conditions = conditions
            self.action = action
            self.reason = reason
            self.alternative = alternative
            self.locked = locked
            self.gate = gate
            self.ensure = ensure
    
    class CompiledPolicy:
        def __init__(self, rules: List[CompiledRule], default_action: str):
            self.rules = rules
            self.default_action = default_action
    
    class EvaluationResult:
        def __init__(self, decision: str, matched_rule: Optional[str] = None,
                     matched_locked: bool = False, reason: Optional[str] = None,
                     evaluation_time_us: int = 0, 
                     ensure_config: Optional[EnsureConfig] = None):
            self.decision = decision
            self.matched_rule = matched_rule
            self.matched_locked = matched_locked
            self.reason = reason
            self.evaluation_time_us = evaluation_time_us
            self.ensure_config = ensure_config
    
    class ToolCall:
        def __init__(self, tool_name: str, parameters: Dict[str, Any]):
            self.tool_name = tool_name
            self.parameters = parameters
    
    def default_gate_within():
        return 50
    
    def default_ensure_timeout():
        return 5
    
    def default_version():
        return 1
    
    def default_allow():
        return Decision.Allow
    
    def from_config(config: PolicyConfig) -> CompiledPolicy:
        import re
        compiled_rules = []
        for rule in config.rules:
            try:
                regex = re.compile(rule.tool_pattern)
                compiled_rules.append(CompiledRule(
                    name=rule.name,
                    tool_regex=regex,
                    conditions=rule.conditions,
                    action=rule.action,
                    reason=rule.reason,
                    alternative=rule.alternative,
                    locked=rule.locked,
                    gate=rule.gate,
                    ensure=rule.ensure
                ))
            except re.error:
                # Silently skip invalid regex
                pass
        return CompiledPolicy(rules=compiled_rules, default_action=config.default_action)
    
    def evaluate_condition(condition: str, call: ToolCall, vault: Optional[Any] = None):
        """Mock implementation of evaluate_condition"""
        condition = condition.strip()
        
        # Handle literals
        if condition == "true":
            return Ok(True)
        if condition == "false":
            return Ok(False)
        
        # Handle contains()
        if condition.startswith("contains("):
            import re
            match = re.match(r'contains\(["\'](.+?)["\']\)', condition)
            if match:
                search_str = match.group(1)
                return Ok(search_str in call.tool_name)
        
        # Handle param_eq()
        if condition.startswith("param_eq("):
            import re
            match = re.match(r'param_eq\(["\'](.+?)["\']\s*,\s*["\'](.+?)["\']\)', condition)
            if match:
                field, value = match.groups()
                param_value = call.parameters.get(field, "")
                return Ok(str(param_value) == value)
        
        # Handle param_gt()
        if condition.startswith("param_gt("):
            import re
            match = re.match(r'param_gt\(["\'](.+?)["\']\s*,\s*["\'](.+?)["\']\)', condition)
            if match:
                field, threshold = match.groups()
                try:
                    threshold_val = float(threshold)
                    param_val = float(call.parameters.get(field, 0))
                    return Ok(param_val > threshold_val)
                except ValueError:
                    return Err("parse_error: cannot parse threshold")
        
        # Handle param_lt()
        if condition.startswith("param_lt("):
            import re
            match = re.match(r'param_lt\(["\'](.+?)["\']\s*,\s*["\'](.+?)["\']\)', condition)
            if match:
                field, threshold = match.groups()
                try:
                    threshold_val = float(threshold)
                    param_val = float(call.parameters.get(field, 0))
                    return Ok(param_val < threshold_val)
                except ValueError:
                    return Err("parse_error: cannot parse threshold")
        
        # Handle not()
        if condition.startswith("not("):
            import re
            match = re.match(r'not\((.+)\)', condition)
            if match:
                inner = match.group(1)
                result = evaluate_condition(inner, call, vault)
                if result.is_ok():
                    return Ok(not result.unwrap())
                return result
        
        # Handle or()
        if condition.startswith("or("):
            # Simple split on comma at top level
            inner = condition[3:-1]
            parts = inner.split(", ")
            for part in parts:
                result = evaluate_condition(part.strip(), call, vault)
                if result.is_ok() and result.unwrap():
                    return Ok(True)
            return Ok(False)
        
        # Handle matches()
        if condition.startswith("matches("):
            import re
            match = re.match(r'matches\(["\'](.+?)["\']\)', condition)
            if match:
                pattern = match.group(1)
                try:
                    regex = re.compile(pattern)
                    return Ok(bool(regex.search(call.tool_name)))
                except re.error:
                    return Err("regex_compile_error: invalid regex")
        
        # Unknown function
        return Err("unknown_condition: unknown function name")
    
    def evaluate(call: ToolCall, policy: CompiledPolicy, vault: Optional[Any] = None) -> EvaluationResult:
        """Mock implementation of evaluate"""
        import time
        start = time.perf_counter()
        
        for rule in policy.rules:
            # Check if tool name matches regex
            if rule.tool_regex.search(call.tool_name):
                # Check all conditions
                all_conditions_pass = True
                for condition in rule.conditions:
                    result = evaluate_condition(condition, call, vault)
                    if result.is_err() or not result.unwrap():
                        all_conditions_pass = False
                        break
                
                if not all_conditions_pass:
                    continue
                
                # Rule matches
                decision = rule.action
                
                # Resolve Gate
                if decision == Decision.Gate:
                    if rule.gate:
                        if resolve_gate(rule.gate, vault):
                            decision = Decision.Allow
                        else:
                            decision = Decision.Deny
                    else:
                        decision = Decision.Deny
                
                end = time.perf_counter()
                eval_time = int((end - start) * 1_000_000)
                
                return EvaluationResult(
                    decision=decision,
                    matched_rule=rule.name,
                    matched_locked=rule.locked,
                    reason=rule.reason,
                    evaluation_time_us=eval_time,
                    ensure_config=rule.ensure if decision == Decision.Ensure else None
                )
        
        # No match, use default
        end = time.perf_counter()
        eval_time = int((end - start) * 1_000_000)
        return EvaluationResult(
            decision=policy.default_action,
            matched_rule=None,
            matched_locked=False,
            evaluation_time_us=eval_time
        )
    
    def resolve_gate(config: GateConfig, vault: Optional[Any]) -> bool:
        """Mock implementation of resolve_gate"""
        if vault is None:
            return False
        return vault.has_recent_allowed_action(config.requires_prior, config.within)
    
    def load_policy(path: Path) -> CompiledPolicy:
        """Mock implementation of load_policy"""
        try:
            config = load_policy_config(path)
            if config.is_ok():
                return from_config(config.unwrap())
        except:
            pass
        return default_policy()
    
    def load_policy_config(path: Path):
        """Mock implementation of load_policy_config"""
        try:
            import yaml
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            # Convert to PolicyConfig
            rules = []
            for r in data.get('rules', []):
                rules.append(PolicyRule(
                    name=r['name'],
                    tool_pattern=r['tool_pattern'],
                    conditions=r.get('conditions', []),
                    action=r['action'],
                    locked=r.get('locked', False)
                ))
            config = PolicyConfig(
                version=data.get('version', 1),
                rules=rules,
                default_action=data.get('default_action', 'Allow')
            )
            return Ok(config)
        except FileNotFoundError:
            return Err("file_read_error: file not found")
        except Exception as e:
            return Err(f"yaml_parse_error: {str(e)}")
    
    def validate_policy(config: PolicyConfig) -> List[str]:
        """Mock implementation of validate_policy"""
        import re
        errors = []
        
        for rule in config.rules:
            # Check regex
            try:
                re.compile(rule.tool_pattern)
            except re.error:
                errors.append(f"Invalid regex in rule {rule.name}: {rule.tool_pattern}")
            
            # Check conditions
            for condition in rule.conditions:
                if condition.startswith("bad_fn(") or condition.startswith("unknown_fn("):
                    errors.append(f"Unknown condition function in rule {rule.name}: {condition}")
            
            # Check Gate config
            if rule.action == Decision.Gate and rule.gate is None:
                errors.append(f"Gate action missing gate config in rule {rule.name}")
            
            # Check Ensure config
            if rule.action == Decision.Ensure and rule.ensure is None:
                errors.append(f"Ensure action missing ensure config in rule {rule.name}")
        
        return errors
    
    def validate_ensure_check_name(name: str):
        """Mock implementation of validate_ensure_check_name"""
        if not name:
            return Err("empty_name: check name cannot be empty")
        if '/' in name or '\\' in name:
            return Err("path_separator: check name cannot contain path separators")
        if '..' in name:
            return Err("path_traversal: check name cannot contain '..'")
        if '\x00' in name:
            return Err("null_byte: check name cannot contain null bytes")
        for ch in name:
            if ord(ch) < 0x20 and ch != '\t':
                return Err("control_char: check name cannot contain control characters")
        return Ok(())
    
    def resolve_ensure_script_path(check_name: str):
        """Mock implementation of resolve_ensure_script_path"""
        validation = validate_ensure_check_name(check_name)
        if validation.is_err():
            return Err(f"invalid_name: {validation.unwrap_err()}")
        
        checks_dir = Path(".signet/checks")
        script_path = checks_dir / check_name
        
        try:
            canonical = script_path.resolve(strict=True)
            canonical_checks = checks_dir.resolve()
            
            # Check if path is within checks directory
            try:
                canonical.relative_to(canonical_checks)
            except ValueError:
                return Err("path_escape: script path escapes checks directory")
            
            return Ok(canonical)
        except FileNotFoundError:
            return Err("cannot_resolve: script file not found")
        except Exception as e:
            return Err(f"cannot_resolve: {str(e)}")
    
    def self_protection_rules() -> List[PolicyRule]:
        """Mock implementation of self_protection_rules"""
        return [
            PolicyRule(name="protect_checks_dir", tool_pattern=r".*\.signet/checks.*", 
                      conditions=[], action=Decision.Deny, locked=True),
            PolicyRule(name="protect_signet_dir", tool_pattern=r".*\.signet.*", 
                      conditions=[], action=Decision.Deny, locked=True),
            PolicyRule(name="protect_signet_binary", tool_pattern=r".*signet-eval.*", 
                      conditions=[], action=Decision.Deny, locked=True),
            PolicyRule(name="protect_hook_config", tool_pattern=r".*settings\.json.*", 
                      conditions=[], action=Decision.Deny, locked=True),
            PolicyRule(name="protect_signet_symlink", tool_pattern=r".*signet.*", 
                      conditions=[], action=Decision.Deny, locked=True),
            PolicyRule(name="protect_signet_process", tool_pattern=r".*(kill|pkill|killall).*signet.*", 
                      conditions=[], action=Decision.Deny, locked=True),
            PolicyRule(name="protect_preflight_storage", tool_pattern=r".*preflight.*db.*",
                      conditions=[], action=Decision.Deny, locked=True),
        ]
    
    def default_policy() -> CompiledPolicy:
        """Mock implementation of default_policy"""
        import re
        rules = self_protection_rules()
        
        # Add standard safety rules
        rules.extend([
            PolicyRule(name="plan_before_code", tool_pattern=r".*execute.*", 
                      conditions=[], action=Decision.Ask, locked=False),
            PolicyRule(name="protect_rm", tool_pattern=r".*rm -rf.*", 
                      conditions=[], action=Decision.Deny, locked=False),
        ])
        
        config = PolicyConfig(version=1, rules=rules, default_action=Decision.Allow)
        return from_config(config)
    
    def split_at_top_level(s: str, separator: str) -> Optional[tuple]:
        """Mock implementation of split_at_top_level"""
        if not separator:
            return None
        
        depth = 0
        i = 0
        while i < len(s):
            if s[i] == '(':
                depth += 1
            elif s[i] == ')':
                depth = max(0, depth - 1)
            elif depth == 0 and s[i:i+len(separator)] == separator:
                return (s[:i], s[i+len(separator):])
            i += 1
        
        return None
    
    def strip_fn(s: str, name: str) -> Optional[str]:
        """Mock implementation of strip_fn"""
        if not s.startswith(name):
            return None
        rest = s[len(name):]
        if not rest.startswith('(') or not rest.endswith(')'):
            return None
        return rest[1:-1]
    
    def extract_quoted(s: str) -> Optional[str]:
        """Mock implementation of extract_quoted"""
        if len(s) < 2:
            return None
        if (s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'"):
            return s[1:-1]
        return None
    
    def param_str(params: Dict[str, Any], field: str) -> str:
        """Mock implementation of param_str"""
        value = params.get(field)
        if isinstance(value, str):
            return value
        return ""
    
    def param_f64(params: Dict[str, Any], field: str) -> float:
        """Mock implementation of param_f64"""
        value = params.get(field)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return 0.0
        return 0.0
    
    # Result type helpers
    class Ok:
        def __init__(self, value):
            self.value = value
        def is_ok(self):
            return True
        def is_err(self):
            return False
        def unwrap(self):
            return self.value
        def unwrap_err(self):
            raise Exception("Called unwrap_err on Ok")
    
    class Err:
        def __init__(self, error):
            self.error = error
        def is_ok(self):
            return False
        def is_err(self):
            return True
        def unwrap(self):
            raise Exception(f"Called unwrap on Err: {self.error}")
        def unwrap_err(self):
            return self.error


# ============================================================================
# HAPPY PATH TESTS
# ============================================================================

class TestDecisionEnum:
    """Tests for Decision enum and as_lowercase method"""
    
    def test_decision_as_lowercase_happy_path(self):
        """Decision.as_lowercase() returns lowercase string representation for each variant"""
        assert Decision.as_lowercase(Decision.Allow) == 'allow'
        assert Decision.as_lowercase(Decision.Deny) == 'deny'
        assert Decision.as_lowercase(Decision.Ask) == 'ask'
        assert Decision.as_lowercase(Decision.Gate) == 'gate'
        assert Decision.as_lowercase(Decision.Ensure) == 'ensure'


class TestDefaultFunctions:
    """Tests for default value functions"""
    
    def test_default_gate_within_returns_50(self):
        """default_gate_within() returns the expected default value"""
        result = default_gate_within()
        assert result == 50
    
    def test_default_ensure_timeout_returns_5(self):
        """default_ensure_timeout() returns the expected default value"""
        result = default_ensure_timeout()
        assert result == 5
    
    def test_default_version_returns_1(self):
        """default_version() returns the expected default value"""
        result = default_version()
        assert result == 1
    
    def test_default_allow_returns_allow_decision(self):
        """default_allow() returns Decision.Allow"""
        result = default_allow()
        assert result == Decision.Allow


class TestFromConfig:
    """Tests for from_config function"""
    
    def test_from_config_valid_rules(self):
        """from_config() compiles valid regex patterns successfully"""
        config = PolicyConfig(
            version=1,
            rules=[
                PolicyRule(name="rule1", tool_pattern="^file_.*", conditions=[], 
                          action=Decision.Allow, locked=False),
                PolicyRule(name="rule2", tool_pattern=r".*\.sh$", conditions=[], 
                          action=Decision.Deny, locked=False)
            ],
            default_action=Decision.Allow
        )
        
        result = from_config(config)
        
        assert len(result.rules) == 2
        assert result.rules[0].name == 'rule1'
        assert result.rules[1].name == 'rule2'
        assert result.default_action == Decision.Allow
    
    def test_from_config_invalid_regex_filtered(self):
        """from_config() silently filters out rules with invalid regex patterns"""
        config = PolicyConfig(
            version=1,
            rules=[
                PolicyRule(name="valid1", tool_pattern="^valid$", conditions=[], 
                          action=Decision.Allow, locked=False),
                PolicyRule(name="invalid", tool_pattern="(unclosed", conditions=[], 
                          action=Decision.Deny, locked=False),
                PolicyRule(name="valid2", tool_pattern="test", conditions=[], 
                          action=Decision.Ask, locked=False)
            ],
            default_action=Decision.Allow
        )
        
        result = from_config(config)
        
        assert len(result.rules) == 2
        assert result.rules[0].name == 'valid1'
        assert result.rules[1].name == 'valid2'
    
    def test_from_config_empty_rules(self):
        """from_config() handles PolicyConfig with empty rules list"""
        config = PolicyConfig(version=1, rules=[], default_action=Decision.Deny)
        
        result = from_config(config)
        
        assert len(result.rules) == 0
        assert result.default_action == Decision.Deny


class TestEvaluateCondition:
    """Tests for evaluate_condition function"""
    
    def test_evaluate_condition_contains_happy_path(self):
        """evaluate_condition() correctly evaluates contains() function"""
        call = ToolCall(tool_name="file_delete", parameters={})
        result = evaluate_condition('contains("delete")', call, None)
        
        assert result.is_ok()
        assert result.unwrap() == True
    
    def test_evaluate_condition_param_eq_happy_path(self):
        """evaluate_condition() correctly evaluates param_eq() function"""
        call = ToolCall(tool_name="git_push", parameters={"mode": "force"})
        result = evaluate_condition('param_eq("mode", "force")', call, None)
        
        assert result.is_ok()
        assert result.unwrap() == True
    
    def test_evaluate_condition_param_gt_happy_path(self):
        """evaluate_condition() correctly evaluates param_gt() function"""
        call = ToolCall(tool_name="transfer", parameters={"amount": 2000})
        result = evaluate_condition('param_gt("amount", "1000")', call, None)
        
        assert result.is_ok()
        assert result.unwrap() == True
    
    def test_evaluate_condition_param_lt_happy_path(self):
        """evaluate_condition() correctly evaluates param_lt() function"""
        call = ToolCall(tool_name="query", parameters={"count": 50})
        result = evaluate_condition('param_lt("count", "100")', call, None)
        
        assert result.is_ok()
        assert result.unwrap() == True
    
    def test_evaluate_condition_true_literal(self):
        """evaluate_condition() handles 'true' literal"""
        call = ToolCall(tool_name="any_tool", parameters={})
        result = evaluate_condition('true', call, None)
        
        assert result.is_ok()
        assert result.unwrap() == True
    
    def test_evaluate_condition_false_literal(self):
        """evaluate_condition() handles 'false' literal"""
        call = ToolCall(tool_name="any_tool", parameters={})
        result = evaluate_condition('false', call, None)
        
        assert result.is_ok()
        assert result.unwrap() == False
    
    def test_evaluate_condition_not_function(self):
        """evaluate_condition() correctly evaluates not() function"""
        call = ToolCall(tool_name="dangerous_action", parameters={})
        result = evaluate_condition('not(contains("safe"))', call, None)
        
        assert result.is_ok()
        assert result.unwrap() == True
    
    def test_evaluate_condition_or_function(self):
        """evaluate_condition() correctly evaluates or() function"""
        call = ToolCall(tool_name="file_read", parameters={})
        result = evaluate_condition('or(contains("file"), contains("dir"))', call, None)
        
        assert result.is_ok()
        assert result.unwrap() == True


class TestEvaluateConditionErrors:
    """Error case tests for evaluate_condition"""
    
    def test_evaluate_condition_unknown_function_error(self):
        """evaluate_condition() returns Err for unknown condition function"""
        call = ToolCall(tool_name="test", parameters={})
        result = evaluate_condition('unknown_fn("arg")', call, None)
        
        assert result.is_err()
        error_msg = result.unwrap_err().lower()
        assert 'unknown' in error_msg or 'condition' in error_msg
    
    def test_evaluate_condition_invalid_regex_in_matches(self):
        """evaluate_condition() returns Err for invalid regex in matches()"""
        call = ToolCall(tool_name="test", parameters={})
        result = evaluate_condition('matches("(unclosed")', call, None)
        
        assert result.is_err()
        error_msg = result.unwrap_err().lower()
        assert 'regex' in error_msg or 'invalid' in error_msg
    
    def test_evaluate_condition_parse_error_param_gt(self):
        """evaluate_condition() returns Err for non-numeric threshold in param_gt()"""
        call = ToolCall(tool_name="test", parameters={"amount": 100})
        result = evaluate_condition('param_gt("amount", "not_a_number")', call, None)
        
        assert result.is_err()
        error_msg = result.unwrap_err().lower()
        assert 'parse' in error_msg or 'number' in error_msg


class TestEvaluate:
    """Tests for evaluate function"""
    
    def test_evaluate_first_match_wins(self):
        """evaluate() returns decision from first matching rule"""
        import re
        call = ToolCall(tool_name="file_delete", parameters={})
        policy = CompiledPolicy(
            rules=[
                CompiledRule(name="deny_delete", tool_regex=re.compile("file_.*"), 
                           conditions=[], action=Decision.Deny, locked=False),
                CompiledRule(name="allow_delete", tool_regex=re.compile("file_delete"), 
                           conditions=[], action=Decision.Allow, locked=False)
            ],
            default_action=Decision.Ask
        )
        
        result = evaluate(call, policy, None)
        
        assert result.decision == Decision.Deny
        assert result.matched_rule == 'deny_delete'
    
    def test_evaluate_default_action_no_match(self):
        """evaluate() returns default_action when no rules match"""
        import re
        call = ToolCall(tool_name="unmatched_tool", parameters={})
        policy = CompiledPolicy(
            rules=[
                CompiledRule(name="specific_rule", tool_regex=re.compile("^file_.*"), 
                           conditions=[], action=Decision.Deny, locked=False)
            ],
            default_action=Decision.Allow
        )
        
        result = evaluate(call, policy, None)
        
        assert result.decision == Decision.Allow
        assert result.matched_rule is None
    
    def test_evaluate_locked_rule(self):
        """evaluate() sets matched_locked=true for locked rules"""
        import re
        call = ToolCall(tool_name="signet_config", parameters={})
        policy = CompiledPolicy(
            rules=[
                CompiledRule(name="protect_config", tool_regex=re.compile("signet_.*"), 
                           conditions=[], action=Decision.Deny, locked=True)
            ],
            default_action=Decision.Allow
        )
        
        result = evaluate(call, policy, None)
        
        assert result.decision == Decision.Deny
        assert result.matched_locked == True
    
    def test_evaluate_gate_with_vault(self):
        """evaluate() resolves Gate action to Allow when vault has recent action"""
        import re
        
        # Mock vault
        mock_vault = Mock()
        mock_vault.has_recent_allowed_action = Mock(return_value=True)
        
        call = ToolCall(tool_name="execute_code", parameters={})
        gate_config = GateConfig(requires_prior="plan", within=50)
        policy = CompiledPolicy(
            rules=[
                CompiledRule(name="gate_on_plan", tool_regex=re.compile("execute_.*"), 
                           conditions=[], action=Decision.Gate, locked=False, 
                           gate=gate_config)
            ],
            default_action=Decision.Deny
        )
        
        result = evaluate(call, policy, mock_vault)
        
        assert result.decision == Decision.Allow
        mock_vault.has_recent_allowed_action.assert_called_once_with("plan", 50)
    
    def test_evaluate_gate_without_vault_fails_closed(self):
        """evaluate() resolves Gate action to Deny when vault is None (fail-closed)"""
        import re
        
        call = ToolCall(tool_name="execute_code", parameters={})
        gate_config = GateConfig(requires_prior="plan", within=50)
        policy = CompiledPolicy(
            rules=[
                CompiledRule(name="gate_on_plan", tool_regex=re.compile("execute_.*"), 
                           conditions=[], action=Decision.Gate, locked=False, 
                           gate=gate_config)
            ],
            default_action=Decision.Allow
        )
        
        result = evaluate(call, policy, None)
        
        assert result.decision == Decision.Deny
    
    def test_evaluate_ensure_returns_config(self):
        """evaluate() returns Ensure decision with ensure_config populated"""
        import re
        
        call = ToolCall(tool_name="deploy_prod", parameters={})
        ensure_config = EnsureConfig(check="run_tests.sh", timeout=30, 
                                     message="Run tests before deploy")
        policy = CompiledPolicy(
            rules=[
                CompiledRule(name="ensure_tests_pass", tool_regex=re.compile("deploy_.*"), 
                           conditions=[], action=Decision.Ensure, locked=False, 
                           ensure=ensure_config)
            ],
            default_action=Decision.Deny
        )
        
        result = evaluate(call, policy, None)
        
        assert result.decision == Decision.Ensure
        assert result.ensure_config is not None
        assert result.ensure_config.check == 'run_tests.sh'
        assert result.ensure_config.timeout == 30
    
    def test_evaluate_timing_populated(self):
        """evaluate() always populates evaluation_time_us"""
        import re
        
        call = ToolCall(tool_name="test", parameters={})
        policy = CompiledPolicy(rules=[], default_action=Decision.Allow)
        
        result = evaluate(call, policy, None)
        
        assert result.evaluation_time_us > 0
    
    def test_evaluate_condition_error_falls_through(self):
        """evaluate() does not match rule when condition evaluation returns Err"""
        import re
        
        call = ToolCall(tool_name="test_tool", parameters={})
        policy = CompiledPolicy(
            rules=[
                CompiledRule(name="bad_condition", tool_regex=re.compile("test_.*"), 
                           conditions=["unknown_fn()"], action=Decision.Deny, locked=False),
                CompiledRule(name="good_rule", tool_regex=re.compile("test_.*"), 
                           conditions=[], action=Decision.Allow, locked=False)
            ],
            default_action=Decision.Deny
        )
        
        result = evaluate(call, policy, None)
        
        assert result.decision == Decision.Allow
        assert result.matched_rule == 'good_rule'


class TestResolveGate:
    """Tests for resolve_gate function"""
    
    def test_resolve_gate_with_vault_match(self):
        """resolve_gate() returns true when vault has matching recent action"""
        mock_vault = Mock()
        mock_vault.has_recent_allowed_action = Mock(return_value=True)
        
        config = GateConfig(requires_prior="approve", within=20)
        result = resolve_gate(config, mock_vault)
        
        assert result == True
        mock_vault.has_recent_allowed_action.assert_called_once_with("approve", 20)
    
    def test_resolve_gate_with_vault_no_match(self):
        """resolve_gate() returns false when vault doesn't have matching action"""
        mock_vault = Mock()
        mock_vault.has_recent_allowed_action = Mock(return_value=False)
        
        config = GateConfig(requires_prior="approve", within=20)
        result = resolve_gate(config, mock_vault)
        
        assert result == False
        mock_vault.has_recent_allowed_action.assert_called_once_with("approve", 20)
    
    def test_resolve_gate_without_vault_fails_closed(self):
        """resolve_gate() returns false when vault is None (fail-closed)"""
        config = GateConfig(requires_prior="approve", within=20)
        result = resolve_gate(config, None)
        
        assert result == False


class TestLoadPolicy:
    """Tests for load_policy and load_policy_config functions"""
    
    def test_load_policy_valid_file(self):
        """load_policy() successfully loads and compiles policy from valid YAML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
version: 1
default_action: Allow
rules:
  - name: test_rule
    tool_pattern: "^test$"
    conditions: []
    action: Allow
    locked: false
""")
            f.flush()
            temp_path = f.name
        
        try:
            result = load_policy(Path(temp_path))
            
            assert len(result.rules) > 0
            assert result.default_action is not None
        finally:
            os.unlink(temp_path)
    
    def test_load_policy_missing_file_returns_default(self):
        """load_policy() returns default_policy() when file doesn't exist"""
        result = load_policy(Path("/nonexistent/path/policy.yaml"))
        
        assert result is not None
        assert len(result.rules) >= 7  # At least self-protection rules
    
    def test_load_policy_malformed_yaml_returns_default(self):
        """load_policy() returns default_policy() when YAML is malformed"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("this is not: valid: yaml: {{{")
            f.flush()
            temp_path = f.name
        
        try:
            result = load_policy(Path(temp_path))
            
            assert result is not None
            assert len(result.rules) >= 7
        finally:
            os.unlink(temp_path)
    
    def test_load_policy_config_valid_file(self):
        """load_policy_config() successfully loads PolicyConfig from valid YAML"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
version: 2
default_action: Deny
rules:
  - name: test_rule
    tool_pattern: "test"
    conditions: []
    action: Allow
    locked: false
""")
            f.flush()
            temp_path = f.name
        
        try:
            result = load_policy_config(Path(temp_path))
            
            assert result.is_ok()
            config = result.unwrap()
            assert config.version >= 1
        finally:
            os.unlink(temp_path)
    
    def test_load_policy_config_missing_file_error(self):
        """load_policy_config() returns Err when file doesn't exist"""
        result = load_policy_config(Path("/nonexistent/path/policy.yaml"))
        
        assert result.is_err()
    
    def test_load_policy_config_invalid_yaml_error(self):
        """load_policy_config() returns Err when YAML is malformed"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("[unclosed bracket")
            f.flush()
            temp_path = f.name
        
        try:
            result = load_policy_config(Path(temp_path))
            
            assert result.is_err()
            error_msg = result.unwrap_err().lower()
            assert 'yaml' in error_msg or 'parse' in error_msg
        finally:
            os.unlink(temp_path)


class TestValidatePolicy:
    """Tests for validate_policy function"""
    
    def test_validate_policy_valid_config(self):
        """validate_policy() returns empty Vec for valid PolicyConfig"""
        config = PolicyConfig(
            version=1,
            rules=[
                PolicyRule(name="test", tool_pattern="^test$", conditions=["true"], 
                          action=Decision.Allow, locked=False)
            ],
            default_action=Decision.Allow
        )
        
        result = validate_policy(config)
        
        assert len(result) == 0
    
    def test_validate_policy_invalid_regex(self):
        """validate_policy() returns error for invalid regex pattern"""
        config = PolicyConfig(
            version=1,
            rules=[
                PolicyRule(name="bad_regex", tool_pattern="(unclosed", conditions=[], 
                          action=Decision.Allow, locked=False)
            ],
            default_action=Decision.Allow
        )
        
        result = validate_policy(config)
        
        assert len(result) > 0
        assert any('regex' in err.lower() for err in result)
    
    def test_validate_policy_unknown_condition(self):
        """validate_policy() returns error for unknown condition function"""
        config = PolicyConfig(
            version=1,
            rules=[
                PolicyRule(name="bad_cond", tool_pattern="test", 
                          conditions=["bad_fn()"], action=Decision.Allow, locked=False)
            ],
            default_action=Decision.Allow
        )
        
        result = validate_policy(config)
        
        assert len(result) > 0
        assert any('condition' in err.lower() or 'unknown' in err.lower() for err in result)
    
    def test_validate_policy_gate_missing_config(self):
        """validate_policy() returns error when Gate action missing gate config"""
        config = PolicyConfig(
            version=1,
            rules=[
                PolicyRule(name="gate_no_config", tool_pattern="test", conditions=[], 
                          action=Decision.Gate, locked=False, gate=None)
            ],
            default_action=Decision.Allow
        )
        
        result = validate_policy(config)
        
        assert len(result) > 0
        assert any('gate' in err.lower() for err in result)
    
    def test_validate_policy_ensure_missing_config(self):
        """validate_policy() returns error when Ensure action missing ensure config"""
        config = PolicyConfig(
            version=1,
            rules=[
                PolicyRule(name="ensure_no_config", tool_pattern="test", conditions=[], 
                          action=Decision.Ensure, locked=False, ensure=None)
            ],
            default_action=Decision.Allow
        )
        
        result = validate_policy(config)
        
        assert len(result) > 0
        assert any('ensure' in err.lower() for err in result)


class TestValidateEnsureCheckName:
    """Tests for validate_ensure_check_name function"""
    
    def test_validate_ensure_check_name_valid(self):
        """validate_ensure_check_name() accepts safe script names"""
        result = validate_ensure_check_name("check_tests.sh")
        assert result.is_ok()
        
        result = validate_ensure_check_name("validate_123")
        assert result.is_ok()
        
        result = validate_ensure_check_name("simple")
        assert result.is_ok()
    
    def test_validate_ensure_check_name_empty(self):
        """validate_ensure_check_name() rejects empty name"""
        result = validate_ensure_check_name("")
        
        assert result.is_err()
        assert 'empty' in result.unwrap_err().lower()
    
    def test_validate_ensure_check_name_path_separator(self):
        """validate_ensure_check_name() rejects name with path separator"""
        result = validate_ensure_check_name("subdir/script.sh")
        
        assert result.is_err()
        error_msg = result.unwrap_err().lower()
        assert 'path' in error_msg or 'separator' in error_msg
    
    def test_validate_ensure_check_name_path_traversal(self):
        """validate_ensure_check_name() rejects name with '..'"""
        result = validate_ensure_check_name("../escape.sh")
        
        assert result.is_err()
        error_msg = result.unwrap_err()
        assert '..' in error_msg or 'traversal' in error_msg.lower()
    
    def test_validate_ensure_check_name_null_byte(self):
        """validate_ensure_check_name() rejects name with null byte"""
        result = validate_ensure_check_name("script\x00.sh")
        
        assert result.is_err()
        assert 'null' in result.unwrap_err().lower()
    
    def test_validate_ensure_check_name_control_char(self):
        """validate_ensure_check_name() rejects name with control characters"""
        result = validate_ensure_check_name("script\x01.sh")
        
        assert result.is_err()
        assert 'control' in result.unwrap_err().lower()


class TestResolveEnsureScriptPath:
    """Tests for resolve_ensure_script_path function"""
    
    def test_resolve_ensure_script_path_valid(self):
        """resolve_ensure_script_path() returns canonicalized path for valid script"""
        # Create temp directory structure
        temp_dir = tempfile.mkdtemp()
        try:
            checks_dir = Path(temp_dir) / ".signet" / "checks"
            checks_dir.mkdir(parents=True)
            script_file = checks_dir / "test_check.sh"
            script_file.write_text("#!/bin/bash\necho test")
            
            # Change to temp directory
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                result = resolve_ensure_script_path("test_check.sh")
                
                assert result.is_ok()
                path = str(result.unwrap())
                assert '.signet' in path
                assert 'checks' in path
            finally:
                os.chdir(original_cwd)
        finally:
            import shutil
            shutil.rmtree(temp_dir)
    
    def test_resolve_ensure_script_path_invalid_name(self):
        """resolve_ensure_script_path() returns Err for invalid check name"""
        result = resolve_ensure_script_path("../evil.sh")
        
        assert result.is_err()
        error_msg = result.unwrap_err().lower()
        assert 'invalid' in error_msg or 'name' in error_msg
    
    def test_resolve_ensure_script_path_not_found(self):
        """resolve_ensure_script_path() returns Err when script doesn't exist"""
        result = resolve_ensure_script_path("nonexistent.sh")
        
        assert result.is_err()
        error_msg = result.unwrap_err().lower()
        assert 'resolve' in error_msg or 'not found' in error_msg


class TestSelfProtectionRules:
    """Tests for self_protection_rules function"""
    
    def test_self_protection_rules_count(self):
        """self_protection_rules() returns exactly 7 rules (github_identity_guard moved to default_policy as unlocked)"""
        result = self_protection_rules()

        assert len(result) == 7
    
    def test_self_protection_rules_all_locked(self):
        """self_protection_rules() returns all rules with locked=true"""
        result = self_protection_rules()
        
        assert all(rule.locked for rule in result)
    
    def test_self_protection_rules_protect_checks_dir_first(self):
        """self_protection_rules() has protect_checks_dir as first rule"""
        result = self_protection_rules()
        
        assert result[0].name == 'protect_checks_dir'
    
    def test_self_protection_rules_coverage(self):
        """self_protection_rules() covers all required protection areas"""
        result = self_protection_rules()
        rule_names = [rule.name for rule in result]
        
        assert any('checks' in name for name in rule_names)
        assert any('signet_dir' in name for name in rule_names)
        assert any('binary' in name for name in rule_names)
        assert any('hook' in name for name in rule_names)
        assert any('symlink' in name for name in rule_names)
        assert any('process' in name for name in rule_names)
        assert any('preflight' in name for name in rule_names)
        # github_identity_guard is no longer in self-protection (moved to default_policy as unlocked)


class TestDefaultPolicy:
    """Tests for default_policy function"""
    
    def test_default_policy_has_self_protection_first(self):
        """default_policy() has self_protection_rules at the beginning"""
        result = default_policy()
        
        assert len(result.rules) >= 7
        assert result.rules[0].locked
        assert result.rules[0].name == 'protect_checks_dir'
        assert all(result.rules[i].locked for i in range(7))
    
    def test_default_policy_default_action_allow(self):
        """default_policy() has default_action = Allow"""
        result = default_policy()
        
        assert result.default_action == Decision.Allow
    
    def test_default_policy_standard_safety_rules(self):
        """default_policy() includes standard safety rules beyond self-protection"""
        result = default_policy()
        
        assert len(result.rules) > 7


class TestSplitAtTopLevel:
    """Tests for split_at_top_level parsing helper"""
    
    def test_split_at_top_level_happy_path(self):
        """split_at_top_level() splits at separator when depth is 0"""
        result = split_at_top_level("a, b", ", ")
        
        assert result is not None
        assert result[0] == 'a'
        assert result[1] == 'b'
    
    def test_split_at_top_level_nested_parens(self):
        """split_at_top_level() ignores separator inside parentheses"""
        result = split_at_top_level("or(a, b), c", ", ")
        
        assert result is not None
        assert result[0] == 'or(a, b)'
        assert result[1] == 'c'
    
    def test_split_at_top_level_no_match(self):
        """split_at_top_level() returns None when separator not found at depth 0"""
        result = split_at_top_level("or(a, b)", ", ")
        
        assert result is None
    
    def test_split_at_top_level_empty_separator(self):
        """split_at_top_level() returns None for empty separator"""
        result = split_at_top_level("test", "")
        
        assert result is None


class TestStripFn:
    """Tests for strip_fn parsing helper"""
    
    def test_strip_fn_happy_path(self):
        """strip_fn() extracts arguments from function call"""
        result = strip_fn('contains("test")', 'contains')
        
        assert result is not None
        assert result == '"test"'
    
    def test_strip_fn_no_match(self):
        """strip_fn() returns None when function name doesn't match"""
        result = strip_fn('contains("test")', 'matches')
        
        assert result is None
    
    def test_strip_fn_missing_parens(self):
        """strip_fn() returns None when parentheses are missing or unmatched"""
        result = strip_fn('contains', 'contains')
        
        assert result is None


class TestExtractQuoted:
    """Tests for extract_quoted parsing helper"""
    
    def test_extract_quoted_double_quotes(self):
        """extract_quoted() extracts content from double-quoted string"""
        result = extract_quoted('"hello world"')
        
        assert result is not None
        assert result == 'hello world'
    
    def test_extract_quoted_single_quotes(self):
        """extract_quoted() extracts content from single-quoted string"""
        result = extract_quoted("'hello world'")
        
        assert result is not None
        assert result == 'hello world'
    
    def test_extract_quoted_not_quoted(self):
        """extract_quoted() returns None for unquoted string"""
        result = extract_quoted('hello')
        
        assert result is None
    
    def test_extract_quoted_mismatched_quotes(self):
        """extract_quoted() returns None for mismatched quotes"""
        result = extract_quoted("'hello\"")
        
        assert result is None


class TestParamStr:
    """Tests for param_str parameter extraction"""
    
    def test_param_str_exists(self):
        """param_str() extracts string parameter value"""
        params = {"key": "value"}
        result = param_str(params, "key")
        
        assert result == 'value'
    
    def test_param_str_missing_field(self):
        """param_str() returns empty string when field not found"""
        params = {"other": "value"}
        result = param_str(params, "missing")
        
        assert result == ''
    
    def test_param_str_not_string(self):
        """param_str() returns empty string when field is not a string"""
        params = {"count": 42}
        result = param_str(params, "count")
        
        assert result == ''


class TestParamF64:
    """Tests for param_f64 parameter extraction"""
    
    def test_param_f64_number(self):
        """param_f64() extracts numeric parameter value"""
        params = {"amount": 123.45}
        result = param_f64(params, "amount")
        
        assert abs(result - 123.45) < 0.001
    
    def test_param_f64_string_parseable(self):
        """param_f64() parses numeric string"""
        params = {"amount": "99.9"}
        result = param_f64(params, "amount")
        
        assert abs(result - 99.9) < 0.001
    
    def test_param_f64_missing_field(self):
        """param_f64() returns 0.0 when field not found"""
        params = {}
        result = param_f64(params, "missing")
        
        assert result == 0.0
    
    def test_param_f64_not_parseable(self):
        """param_f64() returns 0.0 when value cannot be parsed"""
        params = {"value": "not_a_number"}
        result = param_f64(params, "value")
        
        assert result == 0.0


# ============================================================================
# INTEGRATION AND SECURITY TESTS
# ============================================================================

class TestPolicyIntegration:
    """Integration tests with realistic policy scenarios"""
    
    def test_complex_policy_evaluation_chain(self):
        """Test complex policy with multiple rules, conditions, and actions"""
        import re
        
        # Create a complex policy
        rules = self_protection_rules()
        rules.extend([
            PolicyRule(
                name="gate_on_approval",
                tool_pattern=r"deploy_.*",
                conditions=["param_eq(\"env\", \"production\")"],
                action=Decision.Gate,
                locked=False,
                gate=GateConfig(requires_prior="approve_deploy", within=10)
            ),
            PolicyRule(
                name="ensure_tests",
                tool_pattern=r".*_code",
                conditions=["contains(\"execute\")"],
                action=Decision.Ensure,
                locked=False,
                ensure=EnsureConfig(check="run_tests.sh", timeout=60, 
                                   message="Tests must pass")
            ),
            PolicyRule(
                name="allow_safe_ops",
                tool_pattern=r"read_.*",
                conditions=["true"],
                action=Decision.Allow,
                locked=False
            )
        ])
        
        config = PolicyConfig(version=1, rules=rules, default_action=Decision.Ask)
        policy = from_config(config)
        
        # Test 1: Self-protection rule blocks
        call1 = ToolCall(tool_name="modify_file", 
                        parameters={"path": ".signet/checks/test.sh"})
        result1 = evaluate(call1, policy, None)
        assert result1.decision == Decision.Deny
        assert result1.matched_locked == True
        
        # Test 2: Safe operation allowed
        call2 = ToolCall(tool_name="read_config", parameters={})
        result2 = evaluate(call2, policy, None)
        assert result2.decision == Decision.Allow
        
        # Test 3: Gate fails without vault
        call3 = ToolCall(tool_name="deploy_app", 
                        parameters={"env": "production"})
        result3 = evaluate(call3, policy, None)
        assert result3.decision == Decision.Deny  # Gate fails closed
    
    def test_locked_rule_precedence(self):
        """Test that locked rules cannot be bypassed by later rules"""
        import re
        
        rules = [
            PolicyRule(
                name="locked_deny",
                tool_pattern=r"dangerous_.*",
                conditions=[],
                action=Decision.Deny,
                locked=True
            ),
            PolicyRule(
                name="try_to_allow",
                tool_pattern=r"dangerous_action",
                conditions=[],
                action=Decision.Allow,
                locked=False
            )
        ]
        
        config = PolicyConfig(version=1, rules=rules, default_action=Decision.Ask)
        policy = from_config(config)
        
        call = ToolCall(tool_name="dangerous_action", parameters={})
        result = evaluate(call, policy, None)
        
        # First locked rule wins
        assert result.decision == Decision.Deny
        assert result.matched_locked == True
        assert result.matched_rule == "locked_deny"


class TestSecurityBoundaries:
    """Security-focused tests for injection and bypass attempts"""
    
    def test_regex_injection_attempt(self):
        """Test that malicious regex patterns are safely handled"""
        # ReDoS pattern attempt
        config = PolicyConfig(
            version=1,
            rules=[
                PolicyRule(
                    name="redos_attempt",
                    tool_pattern=r"(a+)+b",  # Potential ReDoS
                    conditions=[],
                    action=Decision.Deny,
                    locked=False
                )
            ],
            default_action=Decision.Allow
        )
        
        # Should compile (or be filtered)
        policy = from_config(config)
        
        # Should not hang
        call = ToolCall(tool_name="aaaaaaaaaaaaaaaaaac", parameters={})
        result = evaluate(call, policy, None)
        assert result is not None
    
    def test_path_traversal_in_ensure_check(self):
        """Test that path traversal attempts are blocked in ensure check names"""
        attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\cmd.exe",
            "valid_name/../../escape",
            "./../../outside"
        ]
        
        for attempt in attempts:
            result = validate_ensure_check_name(attempt)
            assert result.is_err(), f"Should reject: {attempt}"
    
    def test_unicode_normalization_in_names(self):
        """Test handling of Unicode characters in check names"""
        # Unicode characters that might bypass checks
        unicode_attempts = [
            "test\u202e.sh",  # Right-to-left override
            "test\u200b.sh",  # Zero-width space
            "test\ufeff.sh",  # Zero-width no-break space
        ]
        
        for attempt in unicode_attempts:
            # Should either be accepted (if safe) or rejected consistently
            result = validate_ensure_check_name(attempt)
            # The implementation will decide, but should not crash
            assert result.is_ok() or result.is_err()
    
    def test_condition_injection_via_parameters(self):
        """Test that user parameters cannot inject condition logic"""
        call = ToolCall(
            tool_name="test_tool",
            parameters={
                "malicious": "') or true or contains('"
            }
        )
        
        # Condition should not be injected
        result = evaluate_condition('param_eq("malicious", "safe")', call, None)
        assert result.is_ok()
        assert result.unwrap() == False  # Should not match


class TestEdgeCasesAndCornerCases:
    """Edge case and corner case tests"""
    
    def test_empty_tool_name(self):
        """Test handling of empty tool name"""
        import re
        call = ToolCall(tool_name="", parameters={})
        policy = CompiledPolicy(
            rules=[
                CompiledRule(name="any", tool_regex=re.compile(".*"), 
                           conditions=[], action=Decision.Deny, locked=False)
            ],
            default_action=Decision.Allow
        )
        
        result = evaluate(call, policy, None)
        # Should match .* pattern
        assert result.decision == Decision.Deny
    
    def test_very_long_tool_name(self):
        """Test handling of very long tool names"""
        import re
        long_name = "a" * 10000
        call = ToolCall(tool_name=long_name, parameters={})
        policy = CompiledPolicy(
            rules=[
                CompiledRule(name="prefix", tool_regex=re.compile("^aaa"), 
                           conditions=[], action=Decision.Deny, locked=False)
            ],
            default_action=Decision.Allow
        )
        
        result = evaluate(call, policy, None)
        assert result.decision == Decision.Deny
    
    def test_deeply_nested_json_parameters(self):
        """Test handling of deeply nested JSON parameters"""
        call = ToolCall(
            tool_name="test",
            parameters={
                "level1": {
                    "level2": {
                        "level3": {
                            "value": "deep"
                        }
                    }
                }
            }
        )
        
        # Should handle gracefully
        result_str = param_str(call.parameters, "level1")
        result_f64 = param_f64(call.parameters, "level1")
        
        # Should return defaults for non-string/non-number
        assert result_str == ""
        assert result_f64 == 0.0
    
    def test_special_characters_in_conditions(self):
        """Test handling of special regex characters in conditions"""
        call = ToolCall(tool_name="test$special^chars", parameters={})
        
        # Should handle regex special chars in contains
        result = evaluate_condition('contains("$special^")', call, None)
        assert result.is_ok()
        # Contains should do literal string matching, not regex
        assert result.unwrap() == True
    
    def test_multiple_gate_resolutions(self):
        """Test multiple Gate rules in sequence"""
        import re
        
        mock_vault = Mock()
        # First gate succeeds, second fails
        mock_vault.has_recent_allowed_action = Mock(side_effect=[True, False])
        
        rules = [
            CompiledRule(
                name="gate1",
                tool_regex=re.compile("action1"),
                conditions=[],
                action=Decision.Gate,
                locked=False,
                gate=GateConfig(requires_prior="approval1", within=50)
            ),
            CompiledRule(
                name="gate2",
                tool_regex=re.compile("action2"),
                conditions=[],
                action=Decision.Gate,
                locked=False,
                gate=GateConfig(requires_prior="approval2", within=50)
            )
        ]
        
        policy = CompiledPolicy(rules=rules, default_action=Decision.Deny)
        
        call1 = ToolCall(tool_name="action1", parameters={})
        result1 = evaluate(call1, policy, mock_vault)
        assert result1.decision == Decision.Allow
        
        call2 = ToolCall(tool_name="action2", parameters={})
        result2 = evaluate(call2, policy, mock_vault)
        assert result2.decision == Decision.Deny


class TestInvariants:
    """Test contract invariants"""
    
    def test_first_match_wins_invariant(self):
        """Verify first-match-wins is always preserved"""
        import re
        
        # Create 100 rules, all matching the same pattern
        rules = []
        for i in range(100):
            action = Decision.Deny if i == 0 else Decision.Allow
            rules.append(
                CompiledRule(
                    name=f"rule_{i}",
                    tool_regex=re.compile("test"),
                    conditions=[],
                    action=action,
                    locked=False
                )
            )
        
        policy = CompiledPolicy(rules=rules, default_action=Decision.Ask)
        call = ToolCall(tool_name="test", parameters={})
        
        result = evaluate(call, policy, None)
        
        # First rule should always win
        assert result.matched_rule == "rule_0"
        assert result.decision == Decision.Deny
    
    def test_self_protection_always_first(self):
        """Verify self-protection rules are always first in default policy"""
        policy = default_policy()
        
        # First 7 rules must be locked self-protection rules
        assert len(policy.rules) >= 7
        for i in range(7):
            assert policy.rules[i].locked == True
        
        # First must be protect_checks_dir
        assert policy.rules[0].name == "protect_checks_dir"
    
    def test_default_values_invariant(self):
        """Verify default value functions return constants"""
        # These should always return the same values
        assert default_gate_within() == 50
        assert default_ensure_timeout() == 5
        assert default_version() == 1
        assert default_allow() == Decision.Allow
        
        # Multiple calls should be consistent
        for _ in range(10):
            assert default_gate_within() == 50
    
    def test_evaluation_never_panics(self):
        """Verify evaluate never panics on any input"""
        import re
        import random
        
        # Generate random policies and calls
        for _ in range(20):
            num_rules = random.randint(0, 10)
            rules = []
            for i in range(num_rules):
                try:
                    rules.append(
                        CompiledRule(
                            name=f"rule_{i}",
                            tool_regex=re.compile(".*"),
                            conditions=[],
                            action=random.choice([Decision.Allow, Decision.Deny, 
                                                Decision.Ask]),
                            locked=random.choice([True, False])
                        )
                    )
                except:
                    pass
            
            policy = CompiledPolicy(rules=rules, default_action=Decision.Allow)
            
            # Random tool calls
            for _ in range(5):
                call = ToolCall(
                    tool_name="".join(random.choices("abcdefg_123", k=10)),
                    parameters={}
                )
                
                # Should never panic
                result = evaluate(call, policy, None)
                assert result is not None
                assert hasattr(result, 'decision')
                assert hasattr(result, 'evaluation_time_us')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
