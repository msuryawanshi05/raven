"""Phase 7 regression checks: tracer, _llm provider switching, graph, orchestrator."""
import sys
import tempfile
import types
import urllib.request
from pathlib import Path

PROJ = str(Path(__file__).resolve().parent)
if PROJ not in sys.path:
    sys.path.insert(0, PROJ)

from agent import _llm, tracer as tracer_mod  # noqa: E402
from agent.graph import HuntGraph  # noqa: E402
from agent.orchestrator import Orchestrator  # noqa: E402


def _fake_ollama(reply="PONG"):
    mod = types.ModuleType("ollama")
    mod.chat = lambda model, messages: {"message": {"content": reply}}
    sys.modules["ollama"] = mod


def test_tracer_cost_and_summary():
    t = tracer_mod.LLMTracer(Path(tempfile.mkdtemp()) / "trace.jsonl")
    t.record("main", "llama3.1", [{"content": "a" * 40}], "b" * 20, 100.0)
    free = t.entries[-1]
    assert free["prompt_tokens"] == 10 and free["completion_tokens"] == 5
    assert free["cost_usd"] == 0.0                                   # llama is free
    t.record("exploit", "gemini-flash", [{"content": "x" * 400}], "y" * 400, 50.0)
    paid = t.entries[-1]
    assert paid["cost_usd"] > 0                                      # gemini has a rate
    assert t.path.read_text().count("\n") == 2                       # both appended
    tbl = t.summary_table()
    assert tbl.row_count == 2                                        # one row per agent


def test_llm_ollama_and_tracing():
    _fake_ollama("hello")
    t = tracer_mod.LLMTracer(Path(tempfile.mkdtemp()) / "t.jsonl")
    out = _llm.chat([{"role": "user", "content": "hi"}], "llama3.1", "main", {}, t)
    assert out == "hello" and len(t.entries) == 1 and t.entries[0]["agent_name"] == "main"


def test_llm_gemini_selection_and_fallback():
    cfg = {"llm": {"provider": "gemini", "gemini_api_key": "K", "ollama_model": "llama3.1"}}
    orig = _llm._gemini
    _llm._gemini = lambda messages, model, key: "GEMINI"
    try:
        assert _llm.chat([{"role": "user", "content": "x"}], "gemini-flash", "main", cfg) == "GEMINI"
        _llm._gemini = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down"))
        _fake_ollama("FALLBACK")
        assert _llm.chat([{"role": "user", "content": "x"}], "gemini-flash", "main", cfg) == "FALLBACK"
    finally:
        _llm._gemini = orig


def test_llm_gemini_rest_build():
    captured = {}

    class _R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self):
            return b'{"candidates":[{"content":{"parts":[{"text":"GEN"}]}}]}'

    def fake_urlopen(req, timeout=60):
        captured["url"] = req.full_url
        return _R()

    orig = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        out = _llm._gemini([{"role": "user", "content": "hi"}], "gemini-flash", "SECRET")
    finally:
        urllib.request.urlopen = orig
    assert out == "GEN"
    assert "gemini-1.5-flash:generateContent" in captured["url"] and "key=SECRET" in captured["url"]


def test_graph_build_and_roundtrip():
    p = Path(tempfile.mkdtemp()) / "g.json"
    g = HuntGraph(p)
    g.add_subdomain("example.com", "api.example.com")
    g.add_endpoint("api.example.com", "/login", "POST")
    g.add_technology("api.example.com", "nginx")
    g.add_finding("api.example.com/login", "sqli", "high")
    assert "api.example.com" in g.neighbors("example.com")
    surface = g.attack_surface()
    assert surface and surface[0]["vuln"] == "sqli" and surface[0]["severity"] == "high"
    assert "sqli" in g.summary() and "Hunt graph" in g.summary()
    g2 = HuntGraph.load(p)                                           # persisted + reloads
    assert g2.attack_surface()[0]["vuln"] == "sqli"


def test_orchestrator_message_flow():
    g = HuntGraph(Path(tempfile.mkdtemp()) / "g.json")
    log = _StubLog()
    orch = Orchestrator("example.com", {"scope": {}}, log, g, "m", mode="auto")
    exploited = []
    orch._recon = lambda: ("recon text", ["a.example.com", "b.example.com"])
    orch._exploit = lambda host: exploited.append(host)
    results = orch.run()
    assert sorted(results) == ["a.example.com", "b.example.com"]
    assert sorted(exploited) == ["a.example.com", "b.example.com"]
    assert "a.example.com" in g.neighbors("example.com")            # recon populated graph


class _StubLog:
    def __init__(self):
        self.records = []
    def log(self, kind, **f):
        self.records.append({"kind": kind, **f})


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("\nALL PHASE 7 CHECKS PASS")
