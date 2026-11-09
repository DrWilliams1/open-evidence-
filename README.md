
# Open Evidence

## AI-Agent Authorization and Verification Toolkit

Version: 0.2 Prototype

## Purpose

Open Evidence is an independently developed Python prototype for evaluating whether recorded AI-agent actions match explicitly defined authorization policies.

It supports transparent, reproducible examination of policy-based authorization decisions.

## Current Capabilities

- Evaluates supplied agent-action records.
- Checks actions against supplied authorization policies.
- Classifies actions as AUTHORIZED, UNAUTHORIZED, or INDETERMINATE.
- Produces human-readable explanations.
- Includes a synthetic JSON report generated separately in Colab.
- Includes 35 test cases across two standalone test suites.

## Project Files

- open_evidence.py — Authorization evaluator.
- test_open_evidence.py — 17 authorization tests.
- test_boundary_cases.py — 18 boundary tests.
- Open_Evidence_Audit_v02.json — Synthetic demonstration report.

## Running the Tests

Run the following command in Python's working environment:

    python test_open_evidence.py
    python test_boundary_cases.py

## Important Limitations

This prototype does not independently authenticate agent activity records or authorization policies.

It does not enforce permissions or intercept actual agent actions.

AUTHORIZED means that a supplied record matches a rule in the supplied policy. It does not prove that the agent was genuinely authorized in a real environment.

INDETERMINATE must not be treated as permission to execute an action.

The two standalone test suites cover 35 defined scenarios. They do not establish comprehensive security or resistance to adversarial manipulation.

## Research Direction

Future development may include:

- Evidence provenance and integrity validation.
- More extensive adversarial testing.
- Reproducible evaluation datasets.
- Improved audit reporting.
- Independent technical review.

## Status

Research prototype. Not approved for operational security enforcement.

Public release and intellectual-property review are pending.

## Verified Prototype Scope

The standalone module provides the evaluate_action() function.

It checks supplied action records against supplied authorization rules
and returns a classification, explanation, and limitation flags.

The JSON demonstration report was generated separately in Google Colab.
Standalone JSON report generation is not yet implemented.

## Verification Boundaries

The prototype currently does not:

- Authenticate agent identities.
- Verify the origin or integrity of action records.
- Authenticate authorization policies.
- Enforce permissions or intercept agent tool calls.
- Prove that an agent performed a recorded action.
- Provide cryptographic attestation of AI behavior.

The current 35 passing test cases cover defined scenarios.
They do not demonstrate comprehensive security.

The prototype is not intended for operational enforcement.

## Research and Publication Status

Open Evidence is a separate, independently developed research project.
It does not incorporate WolfTrack's existing proprietary code.

Public release and intellectual-property review remain pending.

## License

MIT License. See LICENSE. Public release remains pending.
