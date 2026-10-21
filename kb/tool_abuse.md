# Tool Abuse

## What it is
Coercing an AI agent into invoking its available tools/functions in unintended ways
- e.g. calling `transfer_funds` or `delete_account` without the required user
consent or authorization. Often chained from prompt injection.

## Tools to use (in order)
1. Enumerate the agent's declared tools and their arguments.
2. Manual: craft a request that makes the agent call a privileged tool directly.
3. Chain from prompt injection: inject an instruction that triggers the tool, bypassing the consent step.

## What to look for
- a tool call executed without the expected authorization/consent gate
- tool arguments you controlled end-to-end
- an actual state change (balance moved, record deleted, email sent)

## If tool fails
- try indirect injection or role confusion ("the user already approved this")
- multi-step: have the agent stage the action, then confirm it on the victim's behalf

## What to note down
- tool name and the exact arguments invoked
- the consent/guardrail that was bypassed
- evidence the action actually executed (state before/after)

## What NOT to do
- only trigger reversible/non-destructive proof within the challenge
- never move real funds or destroy real data

## Submission checklist
- [ ] reproduction steps
- [ ] impact statement
- [ ] CVSS estimate

## Impact
Unauthorized privileged actions performed through the agent - fund transfer, data deletion, message sending - without user consent.

## Remediation
Enforce authorization and consent server-side per tool; validate tool arguments; never let model output alone authorize a sensitive action; log and rate-limit privileged tool calls.
