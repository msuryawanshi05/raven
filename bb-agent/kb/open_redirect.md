# Open Redirect

## What it is
A redirect parameter sends users to any attacker-supplied URL, useful for phishing
and sometimes chaining into SSRF/OAuth token theft.

## Tools to use (in order)
1. `gau {domain}` — find `redirect=`, `next=`, `url=`, `return=` params
2. Manual: set the param to `https://evil.example` and follow the redirect
3. `curl -I "<url>"` — inspect the `Location` header without following

## What to look for
- `Location:` header pointing to your external domain
- `3xx` status with attacker-controlled host
- bypasses via `//evil.example`, `https:evil.example`, `@` tricks

## If tool fails
- try protocol-relative `//`, whitelisted-domain prefix tricks
- test path-based redirects, not just query params

## What to note down
- URL + parameter
- payload and resulting `Location`

## What NOT to do
- don't use the redirect to actually phish anyone

## Submission checklist
- [ ] reproduction steps
- [ ] impact (phishing, token leak chain)
- [ ] CVSS estimate
