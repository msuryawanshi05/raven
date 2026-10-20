# Local File Inclusion (LFI) / Path Traversal

## What it is
A file-path parameter is used without sanitisation, letting an attacker read
arbitrary files or include local files into the response.

## Tools to use (in order)
1. `gau {domain}` — find `file=`, `page=`, `path=`, `template=` params
2. Manual: `?file=../../../../etc/passwd` and encoded variants
3. `ffuf` with an LFI wordlist on the parameter (active; ask first)

## What to look for
- `root:x:0:0:` (etc/passwd) or Windows `[fonts]` win.ini content
- PHP wrappers working: `php://filter/convert.base64-encode/resource=`
- error messages leaking absolute paths

## If tool fails
- try URL/double-URL encoding, null byte (legacy), nested `....//`
- try absolute paths and log-poisoning for RCE chains

## What to note down
- parameter, exact traversal payload, file contents proof (first line only)

## What NOT to do
- read only enough to prove the issue; no credential/key harvesting

## Submission checklist
- [ ] reproduction steps
- [ ] impact (file read scope, RCE potential)
- [ ] CVSS estimate
