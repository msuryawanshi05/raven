"""Phase 2 regression checks - run with a scripted fake LLM (no ollama needed).

Covers the reviewer's two load-bearing concerns plus the new Phase 2 paths:
- a declined command feeds back to the LLM and the loop continues (not exit)
- VULN_CLASS triggers KB-guide injection before acting
- the failure router walks the fallback chain
- run_command uses no shell (chaining is not executed)
"""
import sys
import tempfile
import types
from pathlib import Path

PROJ = str(Path(__file__).resolve().parent)
if PROJ not in sys.path:
    sys.path.insert(0, PROJ)


def _fake_ollama(replies):
    mod = types.ModuleType("ollama")
    mod.calls = []
    def chat(model, messages):
        mod.calls.append([dict(m) for m in messages])
        return {"message": {"content": replies[len(mod.calls) - 1]}}
    mod.chat = chat
    sys.modules["ollama"] = mod
    return mod


from agent import loop, memory, tools  # noqa: E402

CFG = {"passive_whitelist": ["subfinder", "httpx", "curl", "whois", "dig", "nslookup", "reconftw"],
       "max_steps": 5, "reconftw_path": "x", "kb_path": "./kb",
       "auto_note_findings": True, "finding_keywords": ["reflected"],
       "max_fallback_attempts": 3}


def _tmp_log(target):
    memory.SESSIONS_DIR = Path(tempfile.mkdtemp())
    return memory.SessionLog(target)


def test_decline_feeds_back():
    fake = _fake_ollama([
        "THOUGHT: whois.\nACTION: run_command\nACTION_INPUT: whois example.com",
        "THOUGHT: done.\nFINAL_ANSWER: nothing actioned.",
    ])
    loop.console.input = lambda *a, **k: "n"
    log = _tmp_log("decline.test")
    loop.run("example.com", "seed recon", "m", "ask", CFG, log)
    assert len(fake.calls) == 2, f"loop exited instead of continuing: {len(fake.calls)} calls"
    assert any("declined" in m["content"] for m in fake.calls[1]), "decline not fed back"
    text = log.path.read_text()
    assert '"status": "skipped"' in text and '"kind": "final"' in text


def test_kb_injected():
    fake = _fake_ollama([
        "THOUGHT: test xss.\nVULN_CLASS: xss",
        "THOUGHT: enough.\nFINAL_ANSWER: ok.",
    ])
    loop.console.input = lambda *a, **k: "n"
    log = _tmp_log("kb.test")
    loop.run("example.com", "seed", "m", "ask", CFG, log)
    assert any("Cross-Site Scripting" in m["content"] for m in fake.calls[1]), "KB not injected"
    assert '"kb_consulted": "xss"' in log.path.read_text()


def test_fallback_router():
    def fake_run(cmd):
        if cmd.startswith("subfinder"): return ("subfinder: not found", False)
        if cmd.startswith("amass"):     return ("amass: not found", False)
        if cmd.startswith("curl"):      return ("crt.sh JSON ok", True)
        return ("?", False)
    orig = tools.run_command
    tools.run_command = fake_run
    try:
        r = tools.execute("run_command", "subfinder -d example.com", CFG,
                          approve=lambda c: True, announce=lambda m: None,
                          domain="example.com", url="")
    finally:
        tools.run_command = orig
    assert r["status"] == "fallback_used", r
    assert r["fallback_used"].startswith("curl"), r


def test_no_shell_injection():
    out, _ = tools.run_command("echo safe ; echo pwned")
    # No shell: tokens are literal args to one echo, so ';' and 'echo pwned'
    # come back as text. shell=True would instead run a second command.
    assert out.strip() == "safe ; echo pwned", f"shell may have run: {out!r}"


def test_notes_and_findings():
    p = loop._parse("THOUGHT: x\nNOTE: Subdomains | api.example.com\nNOTE: Vulns | reflected q")
    assert p["notes"] == [("Subdomains", "api.example.com"), ("Vulns", "reflected q")]
    assert loop._finding_hit("value reflected back", CFG) == "reflected"
    assert loop._finding_hit("clean", CFG) is None


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("\nALL PHASE 2 CHECKS PASS")
