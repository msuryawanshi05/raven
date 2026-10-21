"""Phase 3 regression checks: scope enforcer, loop scope-block, report + formatter."""
import json
import sys
import tempfile
import types
from pathlib import Path

PROJ = str(Path(__file__).resolve().parent)
if PROJ not in sys.path:
    sys.path.insert(0, PROJ)

from agent.scope import ScopeEnforcer, command_target  # noqa: E402
from reporter import builder, formatter  # noqa: E402

SCOPE = {"domains": ["*.example.com", "example.com"],
         "excluded": ["admin.example.com", "*.internal.example.com"],
         "ip_ranges": ["10.0.0.0/8"]}


def test_scope_rules():
    e = ScopeEnforcer(SCOPE)
    assert e.is_in_scope("sub.example.com")
    assert e.is_in_scope("example.com")
    assert e.is_in_scope("a.b.example.com")
    assert not e.is_in_scope("evil.com")
    # wildcard must NOT match the bare apex
    assert not ScopeEnforcer({"domains": ["*.example.com"]}).is_in_scope("example.com")
    # exclusion beats inclusion
    assert e.check("admin.example.com").allowed is False
    assert e.check("x.internal.example.com").allowed is False
    # URL host extraction
    assert e.check("https://admin.example.com/p?q=1").allowed is False
    assert e.check("https://shop.example.com/").allowed is True
    # IP ranges
    assert e.check("10.1.2.3").allowed is True
    assert e.check("8.8.8.8").allowed is False
    # passive OSINT services are exempt
    assert e.check("crt.sh").allowed is True
    # no scope configured => allow all (Phase 1/2 compatibility)
    assert ScopeEnforcer({}).check("anything.net").allowed is True


def test_command_target():
    assert command_target("run_reconftw", "-d example.com -p", "example.com") == "example.com"
    assert command_target("run_command", "subfinder -d admin.example.com", "example.com") == "admin.example.com"
    assert command_target("run_command", "curl https://evil.com/x", "example.com") == "evil.com"
    assert command_target("run_command", "whois example.com", "example.com") == "example.com"


def test_loop_blocks_out_of_scope():
    from agent import loop, memory, tools
    mod = types.ModuleType("ollama")
    mod.calls = []
    replies = [
        "THOUGHT: probe evil.\nACTION: run_command\nACTION_INPUT: curl https://evil.com",
        "THOUGHT: stop.\nFINAL_ANSWER: nothing in scope left.",
    ]
    def chat(model, messages):
        mod.calls.append([dict(m) for m in messages])
        return {"message": {"content": replies[len(mod.calls) - 1]}}
    mod.chat = chat
    sys.modules["ollama"] = mod

    ran = []
    tools.run_command = lambda c: (ran.append(c), ("out", True))[1]  # spy
    loop.console.input = lambda *a, **k: "y"  # would approve - must never be reached
    memory.SESSIONS_DIR = Path(tempfile.mkdtemp())
    log = memory.SessionLog("scope.test")
    cfg = {"passive_whitelist": ["curl"], "max_steps": 4, "kb_path": "./kb",
           "auto_note_findings": False, "finding_keywords": [], "scope": SCOPE}
    loop.run("example.com", "seed", "m", "auto", cfg, log)

    assert not any("evil.com" in c for c in ran), f"out-of-scope command executed: {ran}"
    text = log.path.read_text()
    assert '"kind": "scope_block"' in text and "evil.com" in text
    assert len(mod.calls) == 2, "loop should continue after a scope block"
    assert any("out of scope" in m["content"] for m in mod.calls[1]), "block not fed back to LLM"


def _synthetic_session():
    d = Path(tempfile.mkdtemp())
    jsonl = d / "example.com_20261020_140000.jsonl"
    recs = [
        {"timestamp": "2026-10-20T14:00:00", "kind": "recon_seed", "target": "example.com",
         "status": "success", "output": "www.example.com\napi.example.com"},
        {"timestamp": "2026-10-20T14:00:01", "step": 1, "status": "kb_consulted", "kb_consulted": "xss"},
        {"timestamp": "2026-10-20T14:00:02", "step": 2, "action": "run_command",
         "command": "curl https://example.com/search?q=test", "status": "success",
         "output_summary": "value reflected back in response", "finding": "reflected"},
        {"timestamp": "2026-10-20T14:00:03", "step": 3, "action": "run_command",
         "command": "ffuf -u https://example.com/FUZZ", "status": "failed",
         "output_summary": "all fallbacks failed"},
    ]
    jsonl.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")
    (d / "example.com_20261020_140000_notes.md").write_text(
        "# Recon notes\n## Potential Vulns\n- reflected q param\n", encoding="utf-8")
    return jsonl, d


def test_report_build():
    jsonl, d = _synthetic_session()
    cfg = {"kb_path": "./kb", "reports_dir": str(d / "reports")}
    m = builder.build(jsonl, cfg)
    assert m["vuln_class"] == "xss" and m["cwe"] == "CWE-79"
    assert m["severity"] == "medium" and m["cvss"] == 6.1
    assert m["endpoint"] == "https://example.com/search?q=test"
    assert m["parameter"] == "q"
    assert "arbitrary JavaScript" in m["impact"]        # pulled from kb/xss.md
    assert "Context-aware output encoding" in m["remediation"]
    assert m["tried"] == ["ffuf -u https://example.com/FUZZ"]
    assert len(m["steps"]) == 2
    rp = Path(m["report_path"]).read_text(encoding="utf-8")
    assert "# Bug Report: XSS on example.com" in rp
    assert "CWE-79" in rp and "## Steps to Reproduce" in rp
    assert "What I Tried" in rp and "ffuf" in rp


def test_formatter_all_platforms():
    jsonl, d = _synthetic_session()
    cfg = {"kb_path": "./kb", "reports_dir": str(d / "reports")}
    m = builder.build(jsonl, cfg)
    h1 = formatter.format_report(m, "hackerone", cfg).read_text(encoding="utf-8")
    assert "**Weakness:** CWE-79" in h1 and "**Severity:** medium" in h1
    bc = formatter.format_report(m, "bugcrowd", cfg).read_text(encoding="utf-8")
    assert "P3" in bc and "**Bug URL:**" in bc
    hu = formatter.format_report(m, "huntr", cfg).read_text(encoding="utf-8")
    assert "Challenge ID" in hu and "curl https://example.com/search?q=test" in hu


def test_report_without_notes():
    jsonl, d = _synthetic_session()
    (d / "example.com_20261020_140000_notes.md").unlink()  # notes missing
    m = builder.build(jsonl, {"kb_path": "./kb", "reports_dir": str(d / "reports")})
    assert m["notes_found"] is False and Path(m["report_path"]).is_file()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("\nALL PHASE 3 CHECKS PASS")
