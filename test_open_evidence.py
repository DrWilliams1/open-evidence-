
# Import the authorization evaluator from our standalone module.
from open_evidence import evaluate_action

# Define a synthetic authorization policy for testing.
policy = {
    "agent_alpha": {
        "public_report": ["read", "summarize"],
        "internal_summary": ["read"]
    }
}

# Create a reusable valid action record.
valid_record = {
    "agent": "agent_alpha",
    "resource": "public_report",
    "action": "read"
}

# Define ten ordinary authorization scenarios.
normal_tests = [
    (valid_record, "AUTHORIZED"),
    ({"agent": "agent_alpha", "resource": "public_report", "action": "summarize"}, "AUTHORIZED"),
    ({"agent": "agent_alpha", "resource": "internal_summary", "action": "read"}, "AUTHORIZED"),
    ({"agent": "agent_alpha", "resource": "public_report", "action": "delete"}, "UNAUTHORIZED"),
    ({"agent": "agent_alpha", "resource": "public_report", "action": "edit"}, "UNAUTHORIZED"),
    ({"agent": "agent_alpha", "resource": "internal_summary", "action": "summarize"}, "UNAUTHORIZED"),
    ({"agent": "agent_alpha", "resource": "secret_file", "action": "read"}, "UNAUTHORIZED"),
    ({"agent": "unknown_agent", "resource": "public_report", "action": "read"}, "INDETERMINATE"),
    ({"agent": "agent_alpha", "resource": None, "action": "read"}, "INDETERMINATE"),
    ({"agent": "agent_alpha", "resource": "public_report"}, "INDETERMINATE")
]

# Pair each ordinary test with the valid policy.
test_cases = [
    (record, policy, expected)
    for record, expected in normal_tests
]

# Add seven malformed-input scenarios.
test_cases.extend([
    ("invalid record", policy, "INDETERMINATE"),
    ({"agent": [], "resource": "public_report", "action": "read"}, policy, "INDETERMINATE"),
    ({"agent": "agent_alpha", "resource": "   ", "action": "read"}, policy, "INDETERMINATE"),
    ({"agent": "agent_alpha", "resource": "public_report", "action": ["read"]}, policy, "INDETERMINATE"),
    (valid_record, [], "INDETERMINATE"),
    (valid_record, {"agent_alpha": ["read"]}, "INDETERMINATE"),
    (valid_record, {"agent_alpha": {"public_report": "read"}}, "INDETERMINATE")
])

# Initialize the passing-test counter.
passed = 0

# Execute all seventeen independent test scenarios.
for number, (record, rules, expected) in enumerate(test_cases, start=1):

    # Evaluate the action using the standalone module.
    result = evaluate_action(record, rules)

    # Verify the expected authorization classification.
    assert result["status"] == expected, f"Test {number} failed: {result}"

    # Confirm that every decision contains an explanation.
    assert isinstance(result["reason"], str) and bool(result["reason"].strip())

    # Confirm that evidence authentication is never falsely claimed.
    assert result["evidence_authenticity_verified"] is False

    # Confirm that permission enforcement is never falsely claimed.
    assert result["permissions_enforced"] is False

    # Count the successful test.
    passed += 1

# Display the final test results.
print("STANDALONE TESTS:", len(test_cases))

# Display the number of passing tests.
print("TESTS PASSED:", passed)

# Confirm that all tests succeeded.
print("ALL TESTS PASSED:", passed == len(test_cases))
