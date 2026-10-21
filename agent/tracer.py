"""LLM call tracer: per-call cost and latency, written to a trace JSONL.

Token counts are estimates (len // 4); without a provider SDK returning real usage
there is no exact counter. Costs use the rate table below.
"""
import json
from datetime import datetime
from pathlib import Path

from rich.table import Table

RATES = {
    "llama3.1": {"input": 0.0, "output": 0.0},
    "gemini-flash": {"input": 0.000_000_075, "output": 0.000_000_30},
    "claude-sonnet": {"input": 0.000_003, "output": 0.000_015},
    "gpt-4o": {"input": 0.000_005, "output": 0.000_015},
}


def _rate(model):
    if model in RATES:
        return RATES[model]
    for name in RATES:  # tolerate "gemini-1.5-flash" -> "gemini-flash" etc.
        if name in model or model in name:
            return RATES[name]
    return {"input": 0.0, "output": 0.0}


class LLMTracer:
    def __init__(self, path):
        self.path = Path(path)
        self.entries = []

    def record(self, agent_name, model, messages, response, latency_ms):
        pt = sum(len(m.get("content", "")) for m in messages) // 4
        ct = len(response or "") // 4
        r = _rate(model)
        entry = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "agent_name": agent_name,
            "model": model,
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "latency_ms": round(latency_ms, 1),
            "cost_usd": round(pt * r["input"] + ct * r["output"], 6),
        }
        self.entries.append(entry)
        try:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:  # a trace write must never break a hunt
            pass
        return entry

    def summary_table(self) -> Table:
        agg = {}
        for e in self.entries:
            a = agg.setdefault(e["agent_name"], {"calls": 0, "tok": 0, "cost": 0.0, "lat": 0.0})
            a["calls"] += 1
            a["tok"] += e["prompt_tokens"] + e["completion_tokens"]
            a["cost"] += e["cost_usd"]
            a["lat"] += e["latency_ms"]
        table = Table(title="LLM usage")
        for col in ("Agent", "Calls", "Tokens", "Cost USD", "Avg latency ms"):
            table.add_column(col)
        for name, d in sorted(agg.items()):
            avg = d["lat"] / d["calls"] if d["calls"] else 0
            table.add_row(name, str(d["calls"]), str(d["tok"]), f"{d['cost']:.6f}", f"{avg:.0f}")
        return table
