"""Phase 8 regression checks: REST API, WebSocket, bridge, --serve flag."""
import subprocess
import sys
import tempfile
from pathlib import Path

PROJ = str(Path(__file__).resolve().parent)
if PROJ not in sys.path:
    sys.path.insert(0, PROJ)

from fastapi.testclient import TestClient  # noqa: E402

from agent import memory  # noqa: E402
from server import bridge  # noqa: E402
from server.main import create_app  # noqa: E402

client = TestClient(create_app())


def test_api_sessions_empty():
    memory.SESSIONS_DIR = Path(tempfile.mkdtemp())  # redirect to an empty dir
    r = client.get("/api/sessions")
    assert r.status_code == 200 and r.json() == []


def test_api_config_no_keys():
    r = client.get("/api/config")
    assert r.status_code == 200
    blob = str(r.json()).lower()
    # no secret-looking string values should ever be exposed
    import json
    for v in _walk_values(r.json()):
        if isinstance(v, str):
            assert "key" not in v.lower() and "token" not in v.lower(), v
    assert "gemini_api_key" not in blob


def _walk_values(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_values(v)
    else:
        yield obj


def test_ws_connect():
    with client.websocket_connect("/ws/hunt/test123") as ws:
        assert ws is not None  # connected without error


def test_start_hunt_returns_session_id():
    memory.SESSIONS_DIR = Path(tempfile.mkdtemp())
    r = client.post("/api/hunt", json={"target": "example.com", "mode": "auto"})
    assert r.status_code == 200
    assert "session_id" in r.json() and r.json()["session_id"]


def test_serve_flag_registered():
    out = subprocess.run([sys.executable, "bb_agent.py", "--help"],
                         cwd=PROJ, capture_output=True, text=True, timeout=60)
    assert "--serve" in out.stdout


def test_bridge_noop_without_server():
    bridge.put_message("no-such-session", {"type": "thought", "content": "x"})  # must not raise


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("\nALL PHASE 8 CHECKS PASS")
