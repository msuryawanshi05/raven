# CORS Misconfiguration

## What it is
Over-permissive CORS headers let a malicious origin read authenticated responses,
leaking user data cross-site.

## Tools to use (in order)
1. `curl -s -I -H "Origin: https://evil.example" <url>`
2. Inspect `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`
3. Repeat with a reflected-origin and a null origin

## What to look for
- `Access-Control-Allow-Origin` reflecting your arbitrary Origin
- `Access-Control-Allow-Origin: null`
- `Access-Control-Allow-Credentials: true` combined with the above

## If tool fails
- try subdomain-suffix tricks (`evil.target.com`, `target.com.evil.com`)
- test on authenticated endpoints specifically

## What to note down
- endpoint, request Origin, response ACAO/ACAC headers

## What NOT to do
- exfiltrate only your own test account's data as proof

## Submission checklist
- [ ] reproduction steps (curl with Origin)
- [ ] impact (cross-origin data theft, requires creds reflected)
- [ ] CVSS estimate

## Impact
Cross-origin theft of authenticated responses, exposing user data to a malicious site.

## Remediation
Reflect Access-Control-Allow-Origin only for an allowlist; never combine wildcard/null origin with Allow-Credentials: true.
