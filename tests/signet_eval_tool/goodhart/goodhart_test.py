"""
Adversarial acceptance tests for Signet Evaluation Tool.

These tests are designed to catch implementations that pass visible tests
through shortcuts rather than truly implementing the contract.
"""
import json
import os
import tempfile
import time
from unittest.mock import patch, MagicMock
import pytest
from src.signet_eval_tool import *


def test_goodhart_main_preserves_exit_codes_across_error_types():
    """Main function exit codes should uniquely identify error types for diagnostic purposes"""
    # Test that different error types return different exit codes
    arg_error_code = main(['-invalid-flag', '--unknown-option'])
    init_error_code = main(['--init', '/read-only/path/that/cannot/exist'])
    
    assert arg_error_code != 0
    assert init_error_code != 0
    assert arg_error_code != init_error_code  # Different errors should have different codes


def test_goodhart_parse_args_handles_empty_strings_vs_none():
    """Argument parser should distinguish between empty string values and missing values"""
    # Test empty string vs None for policy_path
    result_empty = parse_args(['--policy-path', ''])
    result_default = parse_args([])
    
    assert result_empty.policy_path == ''
    assert result_empty.policy_path is not None
    assert result_empty.policy_path != result_default.policy_path


def test_goodhart_init_policy_file_atomic_creation():
    """Policy file creation should be atomic to prevent partial writes during interruption"""
    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, 'test_policy.yaml')
        
        # Mock to simulate interruption during file creation
        with patch('builtins.open', side_effect=KeyboardInterrupt):
            try:
                init_policy_file(policy_path)
            except KeyboardInterrupt:
                pass
        
        # File should not exist if creation was interrupted
        assert not os.path.exists(policy_path)


def test_goodhart_load_policy_handles_unicode_patterns():
    """Policy loading should properly handle Unicode characters in regex patterns without corruption"""
    unicode_pattern = 'tööl.*ñamé'
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(f'''
version: 1
default_action: DENY
rules:
  - name: Unicode Test Rule
    tool_pattern: "{unicode_pattern}"
    conditions: []
    action: ALLOW
    reason: "Unicode test"
''')
        f.flush()
        
        try:
            policy = load_policy(f.name)
            # Verify Unicode pattern is preserved exactly
            assert policy.rules[0].tool_pattern.pattern == unicode_pattern
        finally:
            os.unlink(f.name)


def test_goodhart_parse_hook_input_preserves_numeric_precision():
    """JSON parsing should preserve numeric precision without floating-point drift"""
    high_precision_value = "0.1234567890123456789"
    json_input = f'{{"tool_name": "calc", "parameters": {{"value": {high_precision_value}}}, "context": {{}}}}'
    
    request = parse_hook_input(json_input)
    
    # Check that precision is maintained
    assert str(request.parameters['value']).startswith("0.123456789")
    # Ensure we don't lose precision to floating point representation
    assert len(str(request.parameters['value'])) >= 10


def test_goodhart_evaluate_request_rule_order_independence_of_content():
    """Rule evaluation order should depend only on position, not rule content or pattern complexity"""
    request = ToolUseRequest(tool_name='test_tool', parameters={}, context={})
    
    # Create rules where a simple pattern comes before a complex one
    rules = [
        PolicyRule(name='simple_first', tool_pattern='test.*', conditions=[], action=Decision.ALLOW, reason='simple'),
        PolicyRule(name='complex_second', tool_pattern=r'test_tool(?=.*complex)(?!.*exclude).*', conditions=[], action=Decision.DENY, reason='complex'),
        PolicyRule(name='simple_third', tool_pattern='test.*', conditions=[], action=Decision.ASK, reason='simple_later')
    ]
    
    policy = PolicyConfig(version=1, rules=rules, default_action=Decision.DENY)
    result = evaluate_request(request, policy)
    
    # Should match first rule regardless of pattern complexity
    assert result.matched_rule == 'simple_first'
    assert result.decision == Decision.ALLOW


def test_goodhart_match_rule_conditions_empty_conditions_edge():
    """Rules with empty condition lists should match all requests unconditionally"""
    request = ToolUseRequest(tool_name='any_tool', parameters={'x': 'y'}, context={'z': 'w'})
    rule = PolicyRule(
        name='empty_conditions',
        tool_pattern='any.*',
        conditions=[],  # Empty conditions list
        action=Decision.ALLOW,
        reason='no conditions'
    )
    
    result = match_rule_conditions(request, rule)
    assert result == True


def test_goodhart_format_output_preserves_floating_point_precision():
    """JSON output formatting should preserve floating-point precision without rounding errors"""
    precise_time = 1.23456789
    result = EvaluationResult(
        decision=Decision.ALLOW,
        matched_rule='test_rule',
        reason='test',
        evaluation_time_ms=precise_time
    )
    
    output_json = format_output(result)
    parsed = json.loads(output_json)
    
    # Verify precision is maintained
    assert parsed['evaluation_time_ms'] == precise_time
    assert str(precise_time) in output_json


def test_goodhart_get_default_policy_version_consistency():
    """Default policy version should be consistent across multiple calls and system states"""
    policy1 = get_default_policy()
    policy2 = get_default_policy()
    
    # Should return consistent version across calls
    assert policy1.version == policy2.version
    assert policy1.version >= 1
    
    # Default action should be DENY for fail-secure
    assert policy1.default_action == Decision.DENY
    assert policy2.default_action == Decision.DENY


def test_goodhart_tool_name_boundary_exactly_100_chars():
    """Tool name validation should accept exactly 100 characters as valid boundary case"""
    tool_name_100 = 'a' * 100
    
    request = ToolUseRequest(
        tool_name=tool_name_100,
        parameters={},
        context={}
    )
    
    assert len(request.tool_name) == 100
    assert request.tool_name == tool_name_100


def test_goodhart_policy_rule_name_boundary_exactly_200_chars():
    """Policy rule name validation should accept exactly 200 characters as valid boundary case"""
    name_200 = 'x' * 200
    
    rule = PolicyRule(
        name=name_200,
        tool_pattern='.*',
        conditions=[],
        action=Decision.ALLOW,
        reason='test'
    )
    
    assert len(rule.name) == 200
    assert rule.name == name_200


def test_goodhart_regex_compilation_caching_persistence():
    """Compiled regex patterns should remain cached across multiple policy evaluations"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write('''
version: 1
default_action: DENY
rules:
  - name: Test Rule
    tool_pattern: "test.*pattern"
    conditions: []
    action: ALLOW
    reason: "test"
''')
        f.flush()
        
        try:
            policy1 = load_policy(f.name)
            policy2 = load_policy(f.name)
            
            # Compiled patterns should be the same object (cached)
            pattern1 = policy1.rules[0].tool_pattern
            pattern2 = policy2.rules[0].tool_pattern
            
            assert pattern1 is pattern2
            assert id(pattern1) == id(pattern2)
        finally:
            os.unlink(f.name)


def test_goodhart_evaluation_time_measurement_accuracy():
    """Evaluation time measurement should accurately reflect actual processing time"""
    # Create request that requires non-trivial processing
    request = ToolUseRequest(
        tool_name='complex_tool_name_with_parameters',
        parameters={'param1': 'value1', 'param2': 'value2', 'param3': 'value3'},
        context={'context1': 'data1', 'context2': 'data2'}
    )
    
    # Create policy with multiple complex regex patterns
    rules = [
        PolicyRule(name=f'rule_{i}', tool_pattern=f'complex.*{i}.*pattern', conditions=[], action=Decision.DENY, reason='test')
        for i in range(10)
    ]
    policy = PolicyConfig(version=1, rules=rules, default_action=Decision.ALLOW)
    
    start_time = time.perf_counter()
    result = evaluate_request(request, policy)
    actual_time = (time.perf_counter() - start_time) * 1000
    
    # Measured time should be reasonable and positive
    assert result.evaluation_time_ms > 0
    assert result.evaluation_time_ms < 15.0  # Within performance budget
    # Should be somewhat close to actual measurement (within order of magnitude)
    assert result.evaluation_time_ms < actual_time * 10


def test_goodhart_fail_secure_on_malformed_policy_structure():
    """System should fail securely with DENY when policy structure is malformed but parseable"""
    request = ToolUseRequest(tool_name='test', parameters={}, context={})
    
    # Create policy with malformed but valid structure
    malformed_policy = PolicyConfig(
        version=1,
        rules=[],  # Empty rules but valid structure
        default_action=None  # Invalid default action
    )
    
    try:
        result = evaluate_request(request, malformed_policy)
        # Should fail secure with DENY
        assert result.decision == Decision.DENY
    except Exception:
        # If it throws exception, that's also acceptable fail-secure behavior
        pass


def test_goodhart_performance_scales_linearly_with_rules():
    """Policy evaluation performance should scale linearly with number of rules"""
    request = ToolUseRequest(tool_name='test_no_match', parameters={}, context={})
    
    def create_policy_with_rules(count):
        rules = [
            PolicyRule(name=f'rule_{i}', tool_pattern=f'nomatch{i}.*', conditions=[], action=Decision.ALLOW, reason='test')
            for i in range(count)
        ]
        return PolicyConfig(version=1, rules=rules, default_action=Decision.DENY)
    
    # Test with different rule counts
    policy_10 = create_policy_with_rules(10)
    policy_100 = create_policy_with_rules(100)
    policy_1000 = create_policy_with_rules(1000)
    
    # Measure times
    result_10 = evaluate_request(request, policy_10)
    result_100 = evaluate_request(request, policy_100)
    result_1000 = evaluate_request(request, policy_1000)
    
    time_10 = result_10.evaluation_time_ms
    time_100 = result_100.evaluation_time_ms
    time_1000 = result_1000.evaluation_time_ms
    
    # All should be within performance budget
    assert all(t < 15.0 for t in [time_10, time_100, time_1000])
    
    # Scaling should be reasonable (not exponential)
    # 1000 rules shouldn't take more than 10x the time of 100 rules
    assert time_1000 < time_100 * 10