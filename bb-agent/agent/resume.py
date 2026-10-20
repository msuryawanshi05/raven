"""Session resume: rebuild context from a past JSONL and continue the hunt."""
import json
import re
from pathlib import Path


def load(jsonl_path) -> dict:
    path = Path(jsonl_path)
    recs = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

    target = next((r["target"] for r in recs if r.get("target")), None)
    if not target:
        m = re.match(r"^(.*)_\d{8}_\d{6}$", path.stem)
        target = m.group(1) if m else path.stem

    tried = [r["command"] for r in recs if r.get("command")]
    steps = [r["step"] for r in recs if isinstance(r.get("step"), int)]
    last_step = max(steps) if steps else 0
    findings = [r for r in recs if r.get("finding")]
    consulted = sorted({r["kb_consulted"] for r in recs if r.get("kb_consulted")})

    parts = [f"Previous session summary for {target}: {last_step} steps run."]
    if consulted:
        parts.append("Vuln classes explored: " + ", ".join(consulted) + ".")
    done = [f"{r['command']} ({r.get('status')})" for r in recs if r.get("command")]
    if done:
        parts.append("Commands already tried: " + "; ".join(done[-10:]) + ".")
    if findings:
        parts.append("Potential findings: "
                     + "; ".join(f"{r['finding']} via {r.get('command', '?')}" for r in findings) + ".")
    parts.append("Continue from where you left off; do not repeat tried commands.")

    return {"target": target, "tried": tried, "last_step": last_step,
            "summary": " ".join(parts), "findings": findings}
