"""Phase 4 regression checks: challenge, multi-target, resume, dashboard."""
import json
import sys
import tempfile
import types
from pathlib import Path

PROJ = str(Path(__file__).resolve().parent)
if PROJ not in sys.path:
    sys.path.insert(0, PROJ)

from agent import challenge, multi, resume  # noqa: E402

BRIEF = ("You are testing a stock brokerage AI assistant at https://target.huntr.io\n"
         "It has access to: place_order, get_balance, transfer_funds tools.\n"
         "Objective: force it to execute a restricted action without user consent.")


def test_challenge_parse():
    p = challenge.parse_briefing(BRIEF)
    assert p["url"] == "https://target.huntr.io"
    assert p["target_host"] == "target.huntr.io"
    assert p["tools"] == ["place_order", "get_balance", "transfer_funds"]
    assert "restricted action" in p["objective"]
    assert "without user consent" in p["guardrails"]
    assert p["challenge_id"] == "target"
    cfg = challenge.configure({"scope": {"domains": []}}, p)
    assert cfg["scope"]["domains"] == ["target.huntr.io"]
    inj = challenge.system_injection(p)
    assert "transfer_funds" in inj and "restricted action" in inj and "prompt injection" in inj.lower()


def test_multi_load_and_run():
    d = Path(tempfile.mkdtemp())
    (d / "t.txt").write_text("# comment\nexample.com\n\nacme.com\n", encoding="utf-8")
    assert multi.load_targets(d / "t.txt") == ["example.com", "acme.com"]

    calls = []
    def hunt(t):
        calls.append(t)
        return {"target": t, "findings": 1, "duration": 0.1, "status": "done", "session": "s"}
    res = multi.run_all(["example.com", "acme.com"], hunt, parallel=False)
    assert [r["target"] for r in res] == ["example.com", "acme.com"]
    out = multi.save_summary(res, {"reports_dir": str(d / "reports")})
    assert out.is_file() and "example.com" in out.read_text()


def test_multi_parallel():
    import time
    def hunt(t):
        time.sleep(0.05)
        return {"target": t, "findings": 0, "duration": 0.05, "status": "done", "session": None}
    res = multi.run_all(["a.com", "b.com", "c.com", "d.com"], hunt, parallel=True)
    assert sorted(r["target"] for r in res) == ["a.com", "b.com", "c.com", "d.com"]


def test_resume_load():
    d = Path(tempfile.mkdtemp())
    j = d / "shop.example.com_20261020_120000.jsonl"
    recs = [
        {"timestamp": "t", "kind": "recon_seed", "target": "shop.example.com"},
        {"timestamp": "t", "step": 1, "action": "run_command", "command": "subfinder -d shop.example.com", "status": "success"},
        {"timestamp": "t", "step": 2, "action": "run_command", "command": "curl https://shop.example.com/login", "status": "failed", "finding": None},
        {"timestamp": "t", "step": 3, "status": "kb_consulted", "kb_consulted": "sqli"},
    ]
    j.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")
    st = resume.load(j)
    assert st["target"] == "shop.example.com"
    assert st["last_step"] == 3
    assert "subfinder -d shop.example.com" in st["tried"]
    assert "sqli" in st["summary"] and "subfinder" in st["summary"]


def test_loop_resume_skip_and_step_offset():
    from agent import loop, memory
    mod = types.ModuleType("ollama")
    mod.calls = []
    replies = [
        "THOUGHT: retry.\nACTION: run_command\nACTION_INPUT: whois example.com",  # already tried
        "THOUGHT: done.\nFINAL_ANSWER: finished.",
    ]
    def chat(model, messages):
        mod.calls.append([dict(m) for m in messages])
        return {"message": {"content": replies[len(mod.calls) - 1]}}
    mod.chat = chat
    sys.modules["ollama"] = mod

    ran = []
    from agent import tools
    tools.run_command = lambda c: (ran.append(c), ("out", True))[1]
    loop.console.input = lambda *a, **k: "y"
    memory.SESSIONS_DIR = Path(tempfile.mkdtemp())
    log = memory.SessionLog("resume.test")
    cfg = {"passive_whitelist": ["whois"], "max_steps": 3, "kb_path": "./kb",
           "auto_note_findings": False, "finding_keywords": []}
    loop.run("example.com", "prior summary", "m", "auto", cfg, log,
             start_step=5, skip_commands={"whois example.com"})

    assert not ran, f"a skipped command was executed: {ran}"
    assert any("already tried" in m["content"] for m in mod.calls[1]), "skip not fed back"
    assert '"step": 6' in log.path.read_text(), "step offset not applied (final should be step 6)"


def test_memory_append_and_notes_reload():
    from agent import memory
    memory.SESSIONS_DIR = Path(tempfile.mkdtemp())
    log = memory.SessionLog("append.test")
    log.notes.add("Subdomains", "api.example.com")
    log.log_step(1, action="run_command", command="whois x", status="success")
    first_lines = len(log.path.read_text().splitlines())

    log2 = memory.SessionLog("append.test", path=log.path)  # resume
    assert "api.example.com" in log2.notes.items["Subdomains Found"], "notes not reloaded"
    log2.log_step(2, action="run_command", command="dig x", status="success")
    assert len(log.path.read_text().splitlines()) == first_lines + 1, "did not append to same file"


def test_dashboard_factory_and_view():
    from ui.dashboard import make_dashboard, Dashboard
    from rich.console import Console
    # Non-terminal console here -> plain output (None).
    assert make_dashboard("x", "auto", True, Console()) is None
    assert make_dashboard("x", "ask", True, Console()) is None
    # Dashboard implements the view protocol without an active Live.
    d = Dashboard("example.com", Console())
    d.update(step=7, subdomains=12, findings=1)
    d.panel("thinking about XSS", "THOUGHT (step 7)", "cyan")
    d.line("hello")
    assert d.state["step"] == 7 and d.state["findings"] == 1
    assert len(d.log) == 2


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("\nALL PHASE 4 CHECKS PASS")
