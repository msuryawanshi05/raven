"""Report builder: turn a session JSONL (+ notes.md) into a submission-ready report.

Works offline on existing session files - no live recon. If notes.md is missing it
degrades to JSONL only. KB impact/remediation sections are pulled via kb_loader.
"""
import json
import re
from pathlib import Path

from agent import kb_loader

ROOT = Path(__file__).resolve().parent.parent

# class -> (CWE, CVSS base estimate). Severity is derived from the score.
VULN_META = {
    "xss": ("CWE-79", 6.1), "sqli": ("CWE-89", 8.6), "ssrf": ("CWE-918", 8.6),
    "idor": ("CWE-639", 6.5), "open_redirect": ("CWE-601", 4.7),
    "cors": ("CWE-942", 6.5), "subdomain_takeover": ("CWE-350", 8.1),
    "lfi": ("CWE-22", 7.5), "ssti": ("CWE-1336", 9.0),
    "prompt_injection": ("CWE-1427", 8.1), "indirect_prompt_injection": ("CWE-1427", 8.1),
    "tool_abuse": ("CWE-285", 7.5),
}
VULN_NAMES = {
    "xss": "XSS", "sqli": "SQL Injection", "ssrf": "SSRF", "idor": "IDOR",
    "open_redirect": "Open Redirect", "cors": "CORS Misconfiguration",
    "subdomain_takeover": "Subdomain Takeover", "lfi": "LFI", "ssti": "SSTI",
    "prompt_injection": "Prompt Injection",
    "indirect_prompt_injection": "Indirect Prompt Injection", "tool_abuse": "Tool Abuse",
}
_URL_RE = re.compile(r"https?://[^\s'\"]+")


def severity_from_cvss(score: float) -> str:
    return ("critical" if score >= 9 else "high" if score >= 7
            else "medium" if score >= 4 else "low")


def _records(jsonl_path: Path):
    out = []
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _kb_section(md: str, *headings) -> str:
    """Return the body of the first '## <heading>' that exists, else ''."""
    if not md or md.startswith("[no KB entry"):
        return ""
    for h in headings:
        m = re.search(rf"^##\s+{re.escape(h)}\s*$\n(.*?)(?=^##\s|\Z)",
                      md, re.S | re.M | re.I)
        if m:
            return m.group(1).strip()
    return ""


def _target(records, jsonl_path: Path) -> str:
    for r in records:
        if r.get("target"):
            return r["target"]
    m = re.match(r"^(.*)_\d{8}_\d{6}$", jsonl_path.stem)
    return m.group(1) if m else jsonl_path.stem


def _vuln_class(records) -> str:
    consulted = [r["kb_consulted"] for r in records if r.get("kb_consulted")]
    return (consulted[-1].lower() if consulted else "unknown")


def build(jsonl_path, config) -> dict:
    jsonl_path = Path(jsonl_path)
    records = _records(jsonl_path)
    notes_path = jsonl_path.with_name(jsonl_path.stem + "_notes.md")
    notes = notes_path.read_text(encoding="utf-8") if notes_path.is_file() else ""

    target = _target(records, jsonl_path)
    vclass = _vuln_class(records)
    name = VULN_NAMES.get(vclass, vclass.replace("_", " ").title())
    cwe, cvss = VULN_META.get(vclass, ("CWE-noinfo", 5.0))
    severity = severity_from_cvss(cvss)

    steps = [r for r in records if r.get("command")]
    findings = [r for r in records if r.get("finding")]
    failed = [r for r in records if r.get("status") == "failed"]
    times = [r["timestamp"] for r in records if r.get("timestamp")]

    finding_cmd = findings[-1]["command"] if findings and findings[-1].get("command") else ""
    endpoint = ""
    for r in findings + steps:
        m = _URL_RE.search(r.get("command", ""))
        if m:
            endpoint = m.group(0)
            break
    endpoint = endpoint or target
    pm = re.search(r"[?&](\w+)=", endpoint)
    parameter = pm.group(1) if pm else "(fill in)"
    payload = finding_cmd or (steps[-1]["command"] if steps else "")

    kb_md = kb_loader.get_technique(vclass, config) if vclass != "unknown" else ""
    impact = _kb_section(kb_md, "Impact", "What it is") or "(fill in - see KB / OWASP)"
    remediation = _kb_section(kb_md, "Remediation") or "(fill in - see KB / OWASP)"

    finding_text = "; ".join(f"{r['finding']} (step {r.get('step','?')})" for r in findings)
    summary = (
        f"During an authorized assessment of {target}, bb-agent "
        + (f"flagged a potential {name} ({finding_text}) at {endpoint}. "
           if findings else f"ran reconnaissance against {endpoint} but did not confirm a {name}. ")
        + f"Estimated severity: {severity} (CVSS {cvss}, {cwe})."
    )

    model = {
        "prefix": jsonl_path.stem,
        "target": target,
        "vuln_class": vclass,
        "vuln_name": name,
        "cwe": cwe,
        "cvss": cvss,
        "severity": severity,
        "title": f"[{name}] Potential {name} on {endpoint}",
        "endpoint": endpoint,
        "parameter": parameter,
        "payload": payload,
        "summary": summary,
        "impact": impact,
        "remediation": remediation,
        "finding_text": finding_text or "(no automated finding; manual review needed)",
        "steps": [f"Run `{r['command']}` - {r.get('status','?')}"
                  + (f": {r['output_summary'][:160]}" if r.get("output_summary") else "")
                  for r in steps],
        "tried": [r["command"] for r in failed],
        "timeline": (min(times), max(times)) if times else ("", ""),
        "notes_found": bool(notes),
    }

    report_path = _reports_dir(config) / f"{model['prefix']}_report.md"
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(_render(model), encoding="utf-8")
    model["report_path"] = report_path
    return model


def _reports_dir(config) -> Path:
    p = Path(config.get("reports_dir", "./reports"))
    return p if p.is_absolute() else (ROOT / p)


def _render(m: dict) -> str:
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(m["steps"], 1)) or "_none recorded_"
    tried = "\n".join(f"- `{c}`" for c in m["tried"]) or "_none_"
    return f"""# Bug Report: {m['vuln_name']} on {m['target']}

## Summary
{m['summary']}

## Target
- Domain: {m['target']}
- Endpoint: {m['endpoint']}
- Parameter: {m['parameter']}

## Vulnerability Details
- Type: {m['vuln_name']}
- CWE: {m['cwe']}
- CVSS estimate: {m['cvss']} ({m['severity']})

## Steps to Reproduce
{steps}

## Payload Used
```
{m['payload'] or '(none)'}
```

## Evidence
_Placeholder - attach screenshots / Burp output / response captures here before submitting._

## Impact
{m['impact']}

## What I Tried (that didn't work)
{tried}

## Remediation
{m['remediation']}

---
_Timeline: {m['timeline'][0]} -> {m['timeline'][1]}. Generated by bb-agent from {m['prefix']}.jsonl._
"""
