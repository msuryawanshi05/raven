# Subdomain Takeover

## What it is
A DNS record points to a deprovisioned third-party service; an attacker can claim
that service and serve content from the victim's subdomain.

## Tools to use (in order)
1. `subfinder -d {domain}` then `httpx -silent` to find live/dead hosts
2. `dig <sub>` / `nslookup <sub>` - inspect CNAME targets
3. `nuclei -t takeovers` or `subzy run --target <sub>` (confirm fingerprint)

## What to look for
- CNAME to S3/GitHub Pages/Heroku/Azure with a dangling "NoSuchBucket" / "There isn't a GitHub Pages site here" fingerprint
- dangling CNAME to an unregistered service

## If tool fails
- manually match the body against can-i-take-over-xyz fingerprints
- check NS and MX records too

## What to note down
- subdomain, CNAME target, service fingerprint string

## What NOT to do
- claim the resource only if the program explicitly allows PoC; otherwise just report the dangling record

## Submission checklist
- [ ] reproduction (CNAME + fingerprint)
- [ ] impact (content control on victim subdomain)
- [ ] CVSS estimate

## Impact
Full content control on a victim subdomain - phishing, cookie theft, and abuse of domain trust.

## Remediation
Remove dangling DNS records; de-provision in the correct order (remove the DNS record last); monitor CNAME targets.
