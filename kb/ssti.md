# Server-Side Template Injection (SSTI)

## What it is
User input is embedded into a server-side template and evaluated, often leading to
RCE depending on the engine.

## Tools to use (in order)
1. Find reflective inputs; inject `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`
2. If `49` appears, fingerprint the engine (Jinja2, Twig, Freemarker, ERB)
3. `tplmap -u "<url>"` to confirm and identify engine (active; ask first)

## What to look for
- arithmetic evaluated (`{{7*7}}` renders `49`)
- engine-specific errors
- object access working (`{{config}}`, `{{7*'7'}}`)

## If tool fails
- rotate syntaxes per engine; test different contexts
- check error pages and email/templated features

## What to note down
- parameter, polyglot payload, evaluated output
- identified template engine

## What NOT to do
- stop at proof (`7*7`); do NOT run OS commands on production

## Submission checklist
- [ ] reproduction steps
- [ ] impact (RCE potential, engine)
- [ ] CVSS estimate

## Impact
Frequently leads to remote code execution on the server (engine-dependent) plus data exposure.

## Remediation
Never concatenate user input into templates; use logic-less or sandboxed engines; pass data only as context variables.
