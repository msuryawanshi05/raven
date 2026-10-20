# Cross-Site Scripting (XSS)

## What it is
Untrusted input is reflected or stored into a page without proper encoding, letting
an attacker run JavaScript in a victim's browser session.

## Tools to use (in order)
1. `gau {domain}` or `waybackurls {domain}` — collect URLs with parameters
2. `httpx -silent` — confirm which are live
3. Manual: inject a unique marker, e.g. `?q=bbagentXSS1` and grep the response for it reflected unencoded
4. `dalfox url <url>` — automated reflected XSS testing (ask before running; active)

## What to look for
- your marker reflected inside HTML/JS/attribute context without encoding
- `Content-Type: text/html` with no `Content-Security-Policy`
- payload surviving in stored locations (profile, comments)

## If tool fails
- manual: test context by context (HTML body, attribute, JS string, URL)
- dork: `site:{domain} inurl:?` to find parameterised endpoints

## What to note down
- URL + exact parameter
- injection context (HTML/attr/JS)
- payload used and the reflected response snippet

## What NOT to do
- no `alert()` storms on production; use a harmless unique string
- never target other users' real sessions

## Submission checklist
- [ ] reproduction steps (exact URL + payload)
- [ ] impact (session theft, account takeover)
- [ ] CVSS estimate

## Impact
Execute arbitrary JavaScript in victims' browsers — session/cookie theft, account takeover, UI defacement.

## Remediation
Context-aware output encoding; Content-Security-Policy; HttpOnly cookies; rely on framework auto-escaping.
