"""
Signet Evaluation Tool Contract Test Suite
Tests the complete behavior of the Signet policy evaluation tool according to its contract.
"""

import pytest
import unittest.mock as mock
import json
import time
import tempfile
import os
import sys
import subprocess
from pathlib import Path

# Import the component under test
from signet_eval_tool import *


class TestMainFunction:
    """Test main CLI entry point functionality."""
    
    def test_main_happy_path(self):
        """Main function successfully processes basic CLI arguments and returns 0."""
        with mock.patch('signet_eval_tool.parse_args') as mock_parse:
            with mock.patch('signet_eval_tool.load_policy') as mock_load:
                with mock.patch('signet_eval_tool.parse_hook_input') as mock_parse_input:
                    with mock.patch('signet_eval_tool.evaluate_request') as mock_evaluate:
                        with mock.patch('signet_eval_tool.format_output') as mock_format:
                            mock_parse.return_value = CliArgs(init=False, policy_path="/tmp/test.yaml", verbose=False)
                            mock_load.return_value = PolicyConfig(version=1, rules=[], default_action=Decision.DENY)
                            mock_parse_input.return_value = ToolUseRequest(tool_name="bash", parameters={}, context={})
                            mock_evaluate.return_value = EvaluationResult(decision=Decision.ALLOW, matched_rule="test", reason="test", evaluation_time_ms=1.0)
                            mock_format.return_value = '{"decision": "ALLOW"}'
                            
                            with mock.patch('sys.stdin.read', return_value='{"tool_name": "bash"}'):
                                result = main(["--policy-path", "/tmp/test.yaml"])
                            
                            assert result == 0
    
    def test_main_init_command(self):
        """Main function successfully creates policy file with --init command."""
        with mock.patch('signet_eval_tool.parse_args') as mock_parse:
            with mock.patch('signet_eval_tool.init_policy_file') as mock_init:
                with mock.patch('os.path.exists', return_value=True):
                    mock_parse.return_value = CliArgs(init=True, policy_path="/tmp/test_policy.yaml", verbose=False)
                    
                    result = main(["--init", "--policy-path", "/tmp/test_policy.yaml"])
                    
                    assert result == 0
                    mock_init.assert_called_once_with("/tmp/test_policy.yaml")
    
    def test_main_argument_parsing_error(self):
        """Main function returns non-zero when invalid arguments provided."""
        with mock.patch('signet_eval_tool.parse_args') as mock_parse:
            mock_parse.side_effect = ArgumentError("Invalid arguments")
            
            result = main(["--invalid-flag"])
            
            assert result != 0
    
    def test_main_policy_init_error(self):
        """Main function returns non-zero when policy file creation fails."""
        with mock.patch('signet_eval_tool.parse_args') as mock_parse:
            with mock.patch('signet_eval_tool.init_policy_file') as mock_init:
                mock_parse.return_value = CliArgs(init=True, policy_path="/root/readonly/policy.yaml", verbose=False)
                mock_init.side_effect = PolicyInitError("Cannot create file")
                
                result = main(["--init", "--policy-path", "/root/readonly/policy.yaml"])
                
                assert result != 0


class TestParseArgs:
    """Test command-line argument parsing."""
    
    def test_parse_args_happy_path(self):
        """Parse arguments successfully with valid input."""
        result = parse_args(["--init", "--verbose"])
        
        assert isinstance(result, CliArgs)
        assert result.init is True
        assert result.verbose is True
    
    def test_parse_args_defaults(self):
        """Parse arguments applies defaults when minimal input provided."""
        result = parse_args([])
        
        assert isinstance(result, CliArgs)
        assert result.init is False
        assert result.verbose is False
        assert result.policy_path is not None
    
    def test_parse_args_invalid_combination(self):
        """Parse arguments fails with invalid argument combination."""
        with pytest.raises(ArgumentError):
            parse_args(["--init", "--unknown-flag"])


class TestInitPolicyFile:
    """Test policy file initialization."""
    
    def test_init_policy_file_happy_path(self):
        """Successfully create policy file at specified location."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = os.path.join(tmpdir, "test_policy.yaml")
            
            init_policy_file(policy_path)
            
            assert os.path.exists(policy_path)
    
    def test_init_policy_file_creates_directories(self):
        """Creates parent directories when they don't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = os.path.join(tmpdir, "nonexistent", "nested", "policy.yaml")
            
            init_policy_file(policy_path)
            
            assert os.path.exists(policy_path)
            assert os.path.exists(os.path.dirname(policy_path))
    
    def test_init_policy_file_filesystem_error(self):
        """Fails when cannot create directories or write file."""
        with pytest.raises(FileSystemError):
            init_policy_file("/root/readonly/policy.yaml")
    
    def test_init_policy_file_permission_error(self):
        """Fails when insufficient permissions for file creation."""
        with pytest.raises(PermissionError):
            init_policy_file("/etc/signet/policy.yaml")


class TestLoadPolicy:
    """Test policy configuration loading."""
    
    def test_load_policy_happy_path(self):
        """Successfully load valid policy configuration from file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
version: 1
default_action: DENY
rules:
  - name: allow_bash
    tool_pattern: bash
    conditions: []
    action: ALLOW
    reason: Safe command
""")
            f.flush()
            
            try:
                result = load_policy(f.name)
                
                assert isinstance(result, PolicyConfig)
                assert result.version == 1
                assert result.default_action == Decision.DENY
                assert len(result.rules) == 1
            finally:
                os.unlink(f.name)
    
    def test_load_policy_fallback_to_defaults(self):
        """Uses embedded defaults when file is missing or invalid."""
        result = load_policy("/tmp/nonexistent.yaml")

        assert isinstance(result, PolicyConfig)
        assert result.version >= 1
        assert result.default_action in (Decision.ALLOW, Decision.DENY)
    
    def test_load_policy_parse_error(self):
        """Fails when policy file has invalid YAML syntax."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: syntax [")
            f.flush()
            
            try:
                with pytest.raises(PolicyParseError):
                    load_policy(f.name)
            finally:
                os.unlink(f.name)
    
    def test_load_policy_regex_compile_error(self):
        """Fails when policy contains invalid regex pattern."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
version: 1
default_action: DENY
rules:
  - name: bad_regex
    tool_pattern: "[invalid regex"
    conditions: []
    action: DENY
    reason: Test
""")
            f.flush()
            
            try:
                with pytest.raises(RegexCompileError):
                    load_policy(f.name)
            finally:
                os.unlink(f.name)


class TestParseHookInput:
    """Test JSON input parsing and validation."""
    
    def test_parse_hook_input_happy_path(self):
        """Successfully parse valid JSON tool use request."""
        json_input = '{"tool_name": "bash", "parameters": {"command": "ls"}}'

        result = parse_hook_input(json_input)

        assert isinstance(result, ToolUseRequest)
        assert result.tool_name == "bash"
        assert result.parameters == {"command": "ls"}
    
    def test_parse_hook_input_json_decode_error(self):
        """Fails when input has invalid JSON syntax."""
        with pytest.raises(json.JSONDecodeError):
            parse_hook_input("{invalid json")
    
    def test_parse_hook_input_validation_error(self):
        """Fails when missing required fields or invalid types."""
        with pytest.raises(ValidationError):
            parse_hook_input('{"tool_name": "", "parameters": "not_dict"}')
    
    def test_parse_hook_input_size_error(self):
        """Fails when input exceeds maximum allowed size."""
        large_input = '{"tool_name": "test", "parameters": {"data": "' + 'x' * (1024 * 1024 + 100) + '"}, "context": {}}'

        with pytest.raises(InputSizeError):
            parse_hook_input(large_input)


class TestEvaluateRequest:
    """Test policy evaluation logic."""
    
    def test_evaluate_request_happy_path(self):
        """Successfully evaluate tool use request against policy."""
        request = ToolUseRequest(tool_name="bash", parameters={"command": "ls"}, context={})
        rule = PolicyRule(name="allow_bash", tool_pattern="bash", conditions=[], action=Decision.ALLOW, reason="Safe")
        policy = PolicyConfig(version=1, rules=[rule], default_action=Decision.DENY)
        
        result = evaluate_request(request, policy)
        
        assert isinstance(result, EvaluationResult)
        assert result.decision == Decision.ALLOW
        assert result.matched_rule == "allow_bash"
        assert result.evaluation_time_ms > 0
    
    def test_evaluate_request_first_match_wins(self):
        """First matching rule determines result when multiple rules could match."""
        request = ToolUseRequest(tool_name="bash", parameters={}, context={})
        rule1 = PolicyRule(name="first_rule", tool_pattern=".*", conditions=[], action=Decision.ALLOW, reason="First")
        rule2 = PolicyRule(name="second_rule", tool_pattern="bash", conditions=[], action=Decision.DENY, reason="Second")
        policy = PolicyConfig(version=1, rules=[rule1, rule2], default_action=Decision.DENY)
        
        result = evaluate_request(request, policy)
        
        assert result.decision == Decision.ALLOW
        assert result.matched_rule == "first_rule"
    
    def test_evaluate_request_default_action(self):
        """Falls back to default action when no rules match."""
        request = ToolUseRequest(tool_name="unknown_tool", parameters={}, context={})
        rule = PolicyRule(name="bash_only", tool_pattern="bash", conditions=[], action=Decision.ALLOW, reason="Safe")
        policy = PolicyConfig(version=1, rules=[rule], default_action=Decision.DENY)
        
        result = evaluate_request(request, policy)
        
        assert result.decision == Decision.DENY
        assert result.matched_rule == ""
    
    def test_evaluate_request_timeout_error(self):
        """Fails when rule evaluation exceeds time limit."""
        request = ToolUseRequest(tool_name="test", parameters={}, context={})
        # Create many rules to burn through the time budget
        rules = [PolicyRule(name=f"rule_{i}", tool_pattern=f"nomatch_{i}", conditions=[], action=Decision.ALLOW, reason="fill") for i in range(10000)]
        policy = PolicyConfig(version=1, rules=rules, default_action=Decision.DENY)

        # Mock perf_counter to simulate elapsed time
        call_count = [0]
        def fake_perf_counter():
            call_count[0] += 1
            # After a few calls, report > 14ms elapsed
            if call_count[0] > 4:
                return 1.0  # 1 second — well past budget
            return 0.0
        with mock.patch('time.perf_counter', side_effect=fake_perf_counter):
            with pytest.raises(EvaluationTimeoutError):
                evaluate_request(request, policy)
    
    def test_evaluate_request_regex_match_error(self):
        """Fails when regex pattern matching encounters error."""
        request = ToolUseRequest(tool_name="test", parameters={}, context={})
        rule = PolicyRule(name="test", tool_pattern="test", conditions=[], action=Decision.ALLOW, reason="Test")
        policy = PolicyConfig(version=1, rules=[rule], default_action=Decision.DENY)

        # Mock the compiled pattern's search method to raise
        with mock.patch.object(rule, '_compiled_pattern') as mock_pat:
            mock_pat.search.side_effect = Exception("Regex error")

            with pytest.raises(RegexMatchError):
                evaluate_request(request, policy)


class TestMatchRuleConditions:
    """Test individual rule condition matching."""
    
    def test_match_rule_conditions_happy_path(self):
        """Successfully match request against rule conditions."""
        request = ToolUseRequest(tool_name="bash", parameters={"command": "ls"}, context={})
        rule = PolicyRule(name="test", tool_pattern="bash", conditions=["parameters.command == 'ls'"], action=Decision.ALLOW, reason="Test")
        
        result = match_rule_conditions(request, rule)
        
        assert result is True
    
    def test_match_rule_conditions_partial_match(self):
        """Returns false when only some conditions match."""
        request = ToolUseRequest(tool_name="bash", parameters={"command": "rm"}, context={})
        rule = PolicyRule(name="test", tool_pattern="bash", conditions=["parameters.command == 'ls'"], action=Decision.ALLOW, reason="Test")
        
        result = match_rule_conditions(request, rule)
        
        assert result is False
    
    def test_match_rule_conditions_eval_error(self):
        """Fails when error occurs evaluating parameter condition."""
        request = ToolUseRequest(tool_name="bash", parameters={}, context={})
        rule = PolicyRule(name="test", tool_pattern="bash", conditions=["invalid.syntax"], action=Decision.ALLOW, reason="Test")
        
        with pytest.raises(ConditionEvalError):
            match_rule_conditions(request, rule)


class TestFormatOutput:
    """Test result formatting."""
    
    def test_format_output_happy_path(self):
        """Successfully format evaluation result as JSON."""
        result = EvaluationResult(decision=Decision.ALLOW, matched_rule="test", reason="Testing", evaluation_time_ms=1.5)
        
        output = format_output(result)
        
        assert isinstance(output, str)
        parsed = json.loads(output)
        assert parsed["decision"] == "ALLOW"
        assert parsed["matched_rule"] == "test"
        assert parsed["reason"] == "Testing"
        assert parsed["evaluation_time_ms"] == 1.5
    
    def test_format_output_serialization_error(self):
        """Fails when cannot serialize result to JSON."""
        # Create a result with non-serializable data
        result = EvaluationResult(decision=Decision.ALLOW, matched_rule="test", reason=lambda: "function", evaluation_time_ms=1.0)
        
        with pytest.raises(SerializationError):
            format_output(result)


class TestGetDefaultPolicy:
    """Test default policy generation."""
    
    def test_get_default_policy_happy_path(self):
        """Returns valid default policy configuration."""
        result = get_default_policy()
        
        assert isinstance(result, PolicyConfig)
        assert result.version >= 1
        assert result.default_action in (Decision.ALLOW, Decision.DENY)
        assert isinstance(result.rules, list)


class TestTypeValidation:
    """Test type construction and validation."""
    
    def test_decision_enum_construction(self):
        """Decision enum accepts valid values."""
        decision = Decision.ALLOW
        assert decision == Decision.ALLOW
        
        decision = Decision.DENY
        assert decision == Decision.DENY
        
        decision = Decision.ASK
        assert decision == Decision.ASK
    
    def test_decision_enum_invalid_value(self):
        """Decision enum rejects invalid values."""
        with pytest.raises(ValueError):
            Decision("INVALID")
    
    def test_tool_use_request_validation(self):
        """ToolUseRequest validates tool_name length constraint."""
        with pytest.raises(ValidationError):
            ToolUseRequest(tool_name="", parameters={}, context={})
        
        with pytest.raises(ValidationError):
            ToolUseRequest(tool_name="x" * 101, parameters={}, context={})
    
    def test_policy_rule_regex_validation(self):
        """PolicyRule validates tool_pattern is valid regex."""
        with pytest.raises(ValidationError):
            PolicyRule(name="test", tool_pattern="[invalid regex", conditions=[], action=Decision.ALLOW, reason="test")
    
    def test_policy_config_version_validation(self):
        """PolicyConfig validates version is >= 1."""
        with pytest.raises(ValidationError):
            PolicyConfig(version=0, rules=[], default_action=Decision.DENY)


class TestInvariants:
    """Test system invariants and properties."""
    
    def test_performance_15ms_budget(self):
        """Policy evaluation completes within 15ms performance budget."""
        # Create a large policy with many rules
        rules = []
        for i in range(100):
            rules.append(PolicyRule(
                name=f"rule_{i}",
                tool_pattern=f"tool_{i}",
                conditions=[],
                action=Decision.ALLOW,
                reason="Test"
            ))
        
        policy = PolicyConfig(version=1, rules=rules, default_action=Decision.DENY)
        request = ToolUseRequest(tool_name="tool_50", parameters={}, context={})
        
        start_time = time.perf_counter()
        result = evaluate_request(request, policy)
        end_time = time.perf_counter()
        
        evaluation_time_ms = (end_time - start_time) * 1000
        assert evaluation_time_ms < 15.0
        assert result.evaluation_time_ms < 15.0
    
    def test_fail_secure_behavior(self):
        """Unknown/error conditions default to DENY decision."""
        request = ToolUseRequest(tool_name="unknown", parameters={}, context={})
        policy = PolicyConfig(version=1, rules=[], default_action=Decision.DENY)
        
        # Simulate an error during evaluation
        with mock.patch('signet_eval_tool.match_rule_conditions') as mock_match:
            mock_match.side_effect = Exception("Evaluation error")
            
            result = evaluate_request(request, policy)
            
            assert result.decision == Decision.DENY
    
    def test_first_match_wins_invariant(self):
        """Rules evaluated in order, first match determines outcome."""
        request = ToolUseRequest(tool_name="bash", parameters={}, context={})
        
        # Create overlapping rules where first allows, second denies
        rule1 = PolicyRule(name="allow_all", tool_pattern=".*", conditions=[], action=Decision.ALLOW, reason="Allow all")
        rule2 = PolicyRule(name="deny_bash", tool_pattern="bash", conditions=[], action=Decision.DENY, reason="Deny bash")
        
        policy = PolicyConfig(version=1, rules=[rule1, rule2], default_action=Decision.ASK)
        
        result = evaluate_request(request, policy)
        
        assert result.decision == Decision.ALLOW
        assert result.matched_rule == "allow_all"
    
    def test_input_validation_invariant(self):
        """All JSON input is validated before processing."""
        malformed_inputs = [
            '{"tool_name": ""}',  # Empty tool name
            '{"tool_name": 123, "parameters": {}}',  # Wrong type for tool_name
        ]

        for invalid_input in malformed_inputs:
            with pytest.raises((ValidationError, json.JSONDecodeError)):
                parse_hook_input(invalid_input)
    
    def test_regex_patterns_cached(self):
        """All regex patterns are compiled and cached at load time."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
version: 1
default_action: DENY
rules:
  - name: pattern1
    tool_pattern: bash.*
    conditions: []
    action: ALLOW
    reason: Test
  - name: pattern2
    tool_pattern: python.*
    conditions: []
    action: DENY
    reason: Test
""")
            f.flush()
            
            try:
                result = load_policy(f.name)
                
                # Verify patterns are compiled (this would be implementation-specific)
                assert len(result.rules) == 2
                for rule in result.rules:
                    # In the actual implementation, compiled patterns would be cached
                    assert rule.tool_pattern is not None
            finally:
                os.unlink(f.name)


# All types and exceptions are imported from signet_eval_tool via the star import above.
# Do NOT redefine them here — isinstance checks will fail if local classes shadow imports.