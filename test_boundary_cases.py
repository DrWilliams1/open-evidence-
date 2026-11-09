
# Import the standalone authorization evaluator.
from open_evidence import evaluate_action

# Import a library for copying test inputs.
from copy import deepcopy

# Define a valid authorization policy.
policy = {
    "agent_alpha": {
        "public_report": ["read", "summarize"],
        "internal_summary": ["read"]
    }
}

# Define a valid example action.
valid = {
    "agent": "agent_alpha",
    "resource": "public_report",
    "action": "read"
}

# Define additional security-boundary scenarios.
cases = [
    # Confirm exact authorization works.
    ("valid action", valid, policy, "AUTHORIZED"),

    # Confirm action names are case-sensitive.
    ("uppercase action", {**valid, "action": "READ"}, policy, "UNAUTHORIZED"),

    # Confirm resource names are case-sensitive.
    ("uppercase resource", {**valid, "resource": "PUBLIC_REPORT"}, policy, "UNAUTHORIZED"),

    # Reject surrounding whitespace in identifiers.
    ("whitespace", {**valid, "action": "read "}, policy, "INDETERMINATE"),

    # Reject missing agent identifiers.
    ("missing agent", {**valid, "agent": None}, policy, "INDETERMINATE"),

    # Reject unknown agents without supplying authorization.
    ("unknown agent", {**valid, "agent": "unknown"}, policy, "INDETERMINATE"),

    # Reject missing action identifiers.
    ("missing action", {**valid, "action": None}, policy, "INDETERMINATE"),

    # Reject numeric agent identifiers.
    ("numeric agent", {**valid, "agent": 123}, policy, "INDETERMINATE"),

    # Deny resources not in a valid agent policy.
    ("unknown resource", {**valid, "resource": "secret"}, policy, "UNAUTHORIZED"),

    # Treat absent agent policies as indeterminate.
    ("empty policy", valid, {}, "INDETERMINATE"),

    # Deny resources when an agent has no permissions.
    ("empty agent rules", valid, {"agent_alpha": {}}, "UNAUTHORIZED"),

    # Deny actions when the permission list is empty.
    ("empty permissions", valid, {"agent_alpha": {"public_report": []}}, "UNAUTHORIZED"),

    # Reject improperly formatted permission collections.
    ("invalid permissions", valid, {"agent_alpha": {"public_report": "read"}}, "INDETERMINATE"),

    # Reject malformed permissions elsewhere in the agent's policy.
    ("invalid other rule", valid, {"agent_alpha": {"public_report": ["read"], "other": "write"}}, "INDETERMINATE"),

    # Reject malformed resource identifiers within the policy.
    ("invalid resource key", valid, {"agent_alpha": {"public_report": ["read"], "bad ": ["read"]}}, "INDETERMINATE"),

    # Reject an invalid top-level policy structure.
    ("policy list", valid, [], "INDETERMINATE"),

    # Reject an invalid action-record structure.
    ("record list", [], policy, "INDETERMINATE")
]

# Initialize the passing-test counter.
passed = 0

# Evaluate all additional scenarios.
for name, record, rules, expected in cases:

    # Calculate the authorization decision.
    result = evaluate_action(record, rules)

    # Verify the expected classification.
    assert result["status"] == expected, f"{name}: {result}"

    # Confirm no false evidence-authentication claim.
    assert result["evidence_authenticity_verified"] is False

    # Confirm no false permission-enforcement claim.
    assert result["permissions_enforced"] is False

    # Count the successful test.
    passed += 1

# Copy the valid action and policy before evaluation.
original_record = deepcopy(valid)
original_policy = deepcopy(policy)

# Evaluate the inputs without intentionally modifying them.
evaluate_action(valid, policy)

# Verify that the action record was not modified.
assert valid == original_record

# Verify that the authorization policy was not modified.
assert policy == original_policy

# Count the input-preservation test.
passed += 1

# Display the final results.
print("BOUNDARY TESTS:", len(cases) + 1)
print("TESTS PASSED:", passed)
print("ALL TESTS PASSED:", passed == 18)
