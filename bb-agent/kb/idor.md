# Insecure Direct Object Reference (IDOR)

## What it is
An object identifier (id, uuid, filename) in a request is not authorisation-checked,
so changing it exposes another user's data.

## Tools to use (in order)
1. Two accounts (A and B). Capture A's requests referencing object ids.
2. Manual: replay A's request substituting B's id; check whether B's data returns
3. `curl` with each session cookie to compare responses

## What to look for
- another user's data returned for an id you shouldn't access
- `200 OK` where `403`/`404` was expected
- sequential/guessable ids

## If tool fails
- try numeric +/-1, UUID from another session, base64-decoded ids
- check PUT/DELETE, not just GET

## What to note down
- endpoint + id parameter
- account A vs B, the swapped id
- response diff proving cross-account access

## What NOT to do
- only use objects you own or test accounts; never real users' data

## Submission checklist
- [ ] reproduction steps (two accounts)
- [ ] impact (data exposure / modification)
- [ ] CVSS estimate

## Impact
Access or modify other users' data (horizontal or vertical privilege escalation).

## Remediation
Enforce object-level authorization server-side on every request; use unguessable, per-user scoped references.
