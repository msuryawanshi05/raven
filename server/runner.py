"""Runs a hunt in a background thread and streams output to the session queue.

Web hunts are headless (no console): passive commands auto-run, active commands
are auto-declined, so a server thread never blocks on a prompt.
"""
import asyncio
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from agent import tools
from agent.loop import run as loop_run
from agent.memory import SessionLog
from agent.scope import ScopeEnforcer
from . import bridge

_EXECUTOR = ThreadPoolExecutor(max_workers=4)
STOP_EVENTS = {}


def _now():
    return datetime.now().isoformat(timespec="seconds")


def start_hunt(params, cfg, loop):
    """Create the session, register its queue, and launch the hunt. Returns session_id."""
    log = SessionLog(params["target"])
    sid = log.path.stem
    bridge.register(sid, asyncio.Queue(maxsize=2000), loop)
    STOP_EVENTS[sid] = threading.Event()
    _EXECUTOR.submit(_run_hunt, sid, log, params, cfg)
    return sid


def stop_hunt(session_id):
    ev = STOP_EVENTS.get(session_id)
    if ev:
        ev.set()
        return True
    return False


def _run_hunt(sid, log, params, cfg):
    target = params["target"]
    model = cfg.get("model", "llama3.1")
    try:
        sr = ScopeEnforcer(cfg.get("scope", {})).check(target)
        if not sr.allowed:
            bridge.put_message(sid, {"type": "error", "content": f"out of scope: {sr.reason}",
                                     "timestamp": _now()})
            log.log("scope_block", target=target, reason=sr.reason)
            return
        reconftw = os.path.expanduser(cfg["reconftw_path"])
        recon = ""
        if os.path.isfile(reconftw):
            recon, _ = tools.run_reconftw(reconftw, f"-d {target} -p")
        else:
            bridge.put_message(sid, {"type": "observation",
                                     "content": "reconftw not installed; running loop without a recon seed",
                                     "timestamp": _now()})
        log.log("recon_seed", target=target, output=recon)

        if params.get("ai_mode") or params.get("owasp_only"):
            from agent import ai_target
            ai_target.run(target, model, cfg, log, mode="auto",
                          owasp_only=bool(params.get("owasp_only")))
        else:
            loop_run(target, recon, model, params.get("mode", "auto"), cfg, log,
                     session_id=sid, headless=True, stop_event=STOP_EVENTS.get(sid))
    except Exception as e:
        bridge.put_message(sid, {"type": "error", "content": str(e), "timestamp": _now()})
        log.log("error", error=str(e))
    finally:
        bridge.put_message(sid, {"type": "done", "content": "", "timestamp": _now()})
