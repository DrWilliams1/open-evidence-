
# Define a helper function for standardized audit results.
def make_result(status, reason):

    # Return the status, explanation, and verification limitations.
    return {
        "status": status,
        "reason": reason,
        "evidence_authenticity_verified": False,
        "permissions_enforced": False
    }


# Define a function to check the format of an identifier.
def valid_identifier(value):

    # Accept only nonempty strings without surrounding spaces.
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


# Define the standalone authorization evaluator.
def evaluate_action(record, policy):

    # Check the top-level input types.
    if not isinstance(record, dict) or not isinstance(policy, dict):
        return make_result("INDETERMINATE", "Invalid record or policy structure.")

    # Check that all essential identifiers are valid.
    for field in ("agent", "resource", "action"):

        # Reject missing or malformed identifiers.
        if not valid_identifier(record.get(field)):
            return make_result("INDETERMINATE", f"Invalid or missing field: {field}.")

    # Retrieve the agent identifier.
    agent = record["agent"]

    # Check whether a policy exists for the agent.
    if agent not in policy:
        return make_result("INDETERMINATE", "No policy supplied for this agent.")

    # Retrieve the authorization rules for this agent.
    rules = policy[agent]

    # Validate the agent's policy structure.
    if not isinstance(rules, dict):
        return make_result("INDETERMINATE", "Invalid agent policy.")

    # Inspect each resource and its permitted actions.
    for resource, actions in rules.items():

        # Reject malformed resource identifiers.
        if not valid_identifier(resource):
            return make_result("INDETERMINATE", "Invalid policy resource.")

        # Require a list of permitted actions.
        if not isinstance(actions, list):
            return make_result("INDETERMINATE", "Invalid permission list.")

        # Check every permitted action.
        if not all(valid_identifier(action) for action in actions):
            return make_result("INDETERMINATE", "Invalid permission entry.")

    # Check whether the requested resource is covered.
    if record["resource"] not in rules:
        return make_result("UNAUTHORIZED", "Resource not authorized by the supplied policy.")

    # Check whether the requested action is allowed.
    if record["action"] not in rules[record["resource"]]:
        return make_result("UNAUTHORIZED", "Action not permitted by the supplied policy.")

    # Record a match to an explicit authorization rule.
    return make_result("AUTHORIZED", "Action matches an explicit rule in the supplied policy.")
