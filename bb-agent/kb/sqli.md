# SQL Injection (SQLi)

## What it is
User input reaches a SQL query unsanitised, letting an attacker alter the query to
read/modify data or bypass auth.

## Tools to use (in order)
1. `gau {domain}` — find parameterised endpoints
2. Manual: append `'` and a balanced `' AND 1=1-- -` / `' AND 1=2-- -` pair; compare responses
3. `sqlmap -u "<url>" --batch --level 2` — confirm (active; always ask first)

## What to look for
- `error in your SQL syntax`, ODBC/PDO exceptions, stack traces
- boolean-based response differences (true vs false condition)
- time delays with `SLEEP(5)` style payloads

## If tool fails
- try different parameter positions and POST bodies
- dork: `site:{domain} inurl:id=`

## What to note down
- URL + parameter + injection type (error/boolean/time)
- DBMS fingerprint
- a single safe proof payload (no data exfiltration dumps)

## What NOT to do
- do NOT dump tables or run destructive queries
- no `DROP`, `DELETE`, `UPDATE`

## Submission checklist
- [ ] reproduction steps
- [ ] impact (data exposure scope)
- [ ] CVSS estimate
