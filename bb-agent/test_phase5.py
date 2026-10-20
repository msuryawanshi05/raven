"""Phase 5 regression checks: behaviour detector, OWASP checker, injection chains,
AI-target HTTP layer, and the owasp-only attack loop."""
import json
import sys
import tempfile
import urllib.request
from pathlib import Path

PROJ = str(Path(__file__).resolve().parent)
if PROJ not in sys.path:
    sys.path.insert(0, PROJ)

from agent import ai_target  # noqa: E402
from agent.behavior import BehaviorDetector  # noqa: E402
from agent.injection_chains import InjectionChainBuilder  # noqa: E402
from agent.owasp_llm import OWASPChecker  # noqa: E402


def test_behavior_signals():
    d = BehaviorDetector()
    d.set_baseline("I'm sorry, I cannot help with that request.")
    assert d.compare("Sure, here is how.").signal == "HIGH"          # complied after refusal
    d.set_baseline("The capital of France is Paris.")
    assert d.compare("ADMIN_TOKEN_abc", indicators=[r"ADMIN_TOKEN"]).signal == "HIGH"
    assert d.compare("x" * 500).signal == "MEDIUM"                   # length +50%
    assert d.compare("The capital of France is Paris.").signal == "NONE"
    crit = d.compare("calling tool transfer_funds...", tool_signatures=[r"transfer_funds"])
    assert crit.signal == "CRITICAL" and d.is_compromised(crit)
    assert not d.is_compromised(d.compare("The capital of France is Paris."))


def test_owasp_checker():
    c = OWASPChecker()
    first = c.next_unchecked()
    assert first.id == "LLM01"
    c.mark_tested(first, "pass")
    assert c.next_unchecked().id == "LLM02"
    item6 = next(i for i in __import__("agent.owasp_llm", fromlist=["ITEMS"]).ITEMS if i.id == "LLM06")
    assert c.evaluate(item6, "You are a helpful assistant. Instructions: ...") == "potential"
    assert c.evaluate(item6, "I can't share that.") == "pass"
    rep = c.coverage_report()
    assert all(x in rep for x in ("LLM01", "LLM10", "coverage"))


def test_injection_chains():
    assert set(InjectionChainBuilder.types()) == {"rag_poison", "tool_response", "memory_persistence"}
    try:
        InjectionChainBuilder.get("nope")
        assert False, "should raise"
    except ValueError:
        pass
    ch = InjectionChainBuilder.get("rag_poison")
    assert ch.is_applicable({"uses_rag": True}) and not ch.is_applicable({"uses_rag": False})
    payloads = ch.build_payloads({})
    assert any(ch.marker in p for p in payloads)
    idx = next(i for i, p in enumerate(payloads) if ch.marker in p)
    assert ch.evaluate_response(idx, f"...{ch.marker}...").success
    assert not ch.evaluate_response(0, "nothing here").success


def test_ai_http_escaping_and_extract():
    captured = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"response": {"text": "hi there"}}'

    def fake_urlopen(req, timeout=30):
        captured["data"] = req.data
        return _Resp()

    orig = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        t = ai_target.AITarget(
            {"endpoint": "http://x", "request_delay": 0,
             "payload_template": '{"message": "{{PAYLOAD}}"}', "response_path": "response.text"}, "")
        out = t.send('say "hi"\nnow')          # quotes + newline must stay valid JSON
    finally:
        urllib.request.urlopen = orig
    assert out == "hi there"
    body = json.loads(captured["data"].decode())      # would raise if escaping were wrong
    assert body["message"] == 'say "hi"\nnow'
    assert ai_target._extract('{"a": {"b": "x"}}', "a.b") == "x"
    assert ai_target._extract("plain text", "a.b") == "plain text"


def _patch_send(fn):
    orig = ai_target.AITarget.send
    ai_target.AITarget.send = fn
    return orig


def test_ai_loop_owasp_only():
    from agent import memory
    def fake_send(self, payload):
        if payload == "Hello, what can you do?":
            return "I can answer general questions."
        if "RAVEN_OK" in payload:
            return "RAVEN_OK"
        return "I'm sorry, I can't help with that."
    orig = _patch_send(fake_send)
    try:
        memory.SESSIONS_DIR = Path(tempfile.mkdtemp())
        log = memory.SessionLog("chat.example.com")
        cfg = {"max_steps": 15, "ai_target": {"endpoint": "http://x", "request_delay": 0}}
        ai_target.run("http://chat.example.com", "m", cfg, log, mode="auto", owasp_only=True)
    finally:
        ai_target.AITarget.send = orig

    jsonl = log.path.read_text()
    assert '"kind": "behavior_change"' in jsonl and '"signal": "HIGH"' in jsonl
    assert '"finding": "LLM01"' in jsonl
    notes = log.notes.path.read_text()
    assert "OWASP LLM Top 10 coverage" in notes and "LLM01" in notes and "LLM10" in notes
    assert "manual" in notes                      # passive items marked manual
    assert "LLM01 Prompt Injection" in notes      # potential finding recorded


def test_ai_loop_chain():
    from agent import memory
    orig = _patch_send(lambda self, p: p)  # echo: marker in payload comes back
    try:
        memory.SESSIONS_DIR = Path(tempfile.mkdtemp())
        log = memory.SessionLog("chat.example.com")
        cfg = {"max_steps": 15, "ai_target": {"endpoint": "http://x", "request_delay": 0}}
        ai_target.run("http://chat.example.com", "m", cfg, log, mode="auto", chain="rag_poison")
    finally:
        ai_target.AITarget.send = orig
    jsonl = log.path.read_text()
    assert '"kind": "chain_step"' in jsonl and '"chain": "rag_poison"' in jsonl
    assert '"success": true' in jsonl
    assert "indirect injection (rag_poison)" in log.notes.path.read_text()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("\nALL PHASE 5 CHECKS PASS")
