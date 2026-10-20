# Server-Side Request Forgery (SSRF)

## What it is
The server fetches a URL supplied by the user, letting an attacker reach internal
services, cloud metadata, or scan the internal network.

## Tools to use (in order)
1. Find URL-ish params (`url=`, `next=`, `image=`, `webhook=`) via `gau {domain}`
2. Manual: point the param at a Burp Collaborator / your own listener; watch for a callback
3. Manual: try `http://169.254.169.254/latest/meta-data/` (cloud metadata) only if in scope

## What to look for
- an HTTP callback to your listener
- internal IPs/hostnames in responses
- differing timing/errors for internal vs external targets

## If tool fails
- try alternate schemes: `file://`, `gopher://`, `dict://`
- try DNS-rebinding / `127.0.0.1` decimal/hex encodings

## What to note down
- parameter, payload URL, callback evidence
- any internal data returned

## What NOT to do
- do not pivot into internal systems beyond proof
- avoid hammering cloud metadata repeatedly

## Submission checklist
- [ ] reproduction steps + callback proof
- [ ] impact (internal access, metadata/creds)
- [ ] CVSS estimate
