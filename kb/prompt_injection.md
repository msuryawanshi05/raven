# Prompt Injection

## What it is
Attacker-controlled text makes an LLM agent ignore its real instructions and follow
the attacker's instead - either directly (via the user message) or indirectly (via
content the agent reads from a tool, document, or web page).

## Tools to use (in order)
1. Manual: send crafted messages to the agent endpoint (`curl`/the chat UI).
2. Try instruction-override payloads: "ignore previous instructions and ...", role-play framing, fake system/developer turns.
3. Indirect: plant the payload in data the agent later reads (a field, file, or page it fetches).

## What to look for
- the agent obeying the injected instruction over its own
- it revealing its system prompt / hidden config
- it calling a tool or performing an action it was told not to

## If tool fails
- rephrase with delimiters, encodings, or multi-step setup
- switch from direct to indirect injection via a data channel the agent trusts

## What to note down
- exact payload and where it was placed (direct vs indirect)
- endpoint / conversation context
- the restricted behaviour triggered, with transcript

## What NOT to do
- stay within the challenge scope; do not exfiltrate real user data
- do not attack models/endpoints outside the brief

## Submission checklist
- [ ] reproduction steps (exact payload + context)
- [ ] impact statement
- [ ] CVSS estimate

## Impact
The agent executes restricted actions, leaks its instructions/data, or bypasses its guardrails on attacker command.

## Remediation
Isolate and label untrusted input; filter inputs/outputs; give tools least privilege; require explicit human confirmation for sensitive actions rather than trusting model output alone.
