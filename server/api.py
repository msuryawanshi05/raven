"""REST API: sessions, findings, graph, reports, config, and hunt control."""
import asyncio
import json
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from agent import memory
from reporter import builder
from . import runner

router = APIRouter()
ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config.yaml"


def load_cfg():
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8")) if CONFIG.is_file() else {}


def _session_files():
    d = memory.SESSIONS_DIR
    if not Path(d).is_dir():
        return []
    return [f for f in sorted(Path(d).glob("*.jsonl")) if not f.stem.endswith("_trace")]


def _records(path):
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _session_meta(path):
    recs = _records(path)
    target = next((r["target"] for r in recs if r.get("target")), path.stem)
    started = next((r["timestamp"] for r in recs if r.get("timestamp")), "")
    findings = sum(1 for r in recs if r.get("finding"))
    status = "complete" if any(r.get("kind") in ("final", "max_steps_reached", "error")
                               or r.get("type") == "done" for r in recs) else "running"
    return {"id": path.stem, "target": target, "started_at": started,
            "finding_count": findings, "status": status}


@router.get("/sessions")
def list_sessions():
    return [_session_meta(f) for f in _session_files()]


def _find(session_id):
    f = Path(memory.SESSIONS_DIR) / f"{session_id}.jsonl"
    if not f.is_file():
        raise HTTPException(404, "session not found")
    return f


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    return _records(_find(session_id))


@router.get("/sessions/{session_id}/notes")
def get_notes(session_id: str):
    notes = Path(memory.SESSIONS_DIR) / f"{session_id}_notes.md"
    return {"notes": notes.read_text(encoding="utf-8") if notes.is_file() else ""}


@router.get("/findings")
def findings(severity: str = "", target: str = ""):
    out = []
    for f in _session_files():
        meta = _session_meta(f)
        for r in _records(f):
            if not r.get("finding"):
                continue
            item = {"target": meta["target"], "vuln": r["finding"],
                    "severity": r.get("severity") or r.get("status") or "unknown",
                    "session": meta["id"], "discovered_at": r.get("timestamp", ""),
                    "command": r.get("command", "")}
            if severity and item["severity"].lower() != severity.lower():
                continue
            if target and target.lower() not in item["target"].lower():
                continue
            out.append(item)
    return out


@router.get("/graph")
def graph(session_id: str = ""):
    d = Path(memory.SESSIONS_DIR)
    if session_id:
        g = d / f"{session_id}_graph.json"
    else:
        graphs = sorted(d.glob("*_graph.json"))
        g = graphs[-1] if graphs else None
    if not g or not g.is_file():
        return {"nodes": [], "links": []}
    return json.loads(g.read_text(encoding="utf-8"))


@router.get("/reports/{session_id}")
def report(session_id: str):
    path = _find(session_id)
    model = builder.build(path, load_cfg())
    return {"markdown": Path(model["report_path"]).read_text(encoding="utf-8")}


@router.get("/config")
def config():
    cfg = load_cfg()
    # Explicit, non-secret projection: never echo LLM/notify keys or tokens.
    return {
        "scope": cfg.get("scope", {}),
        "rate_limits": cfg.get("rate_limits", {}),
        "nuclei_enabled": bool((cfg.get("nuclei") or {}).get("enabled", False)),
        "notify_enabled": bool((cfg.get("notify") or {})),
        "llm_provider": (cfg.get("llm") or {}).get("provider", "ollama"),
    }


class HuntRequest(BaseModel):
    target: str
    mode: str = "auto"
    platform: str = ""
    ai_mode: bool = False
    owasp_only: bool = False


@router.post("/hunt")
async def start(req: HuntRequest):
    if not req.target.strip():
        raise HTTPException(400, "target is required")
    loop = asyncio.get_running_loop()
    sid = runner.start_hunt(req.model_dump(), load_cfg(), loop)
    return {"session_id": sid}


@router.delete("/hunt/{session_id}")
def stop(session_id: str):
    return {"stopped": runner.stop_hunt(session_id)}
