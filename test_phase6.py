"""Phase 6 regression checks: per-target rate limits, nuclei integration, notify."""
import sys
import tempfile
import urllib.request
from pathlib import Path

PROJ = str(Path(__file__).resolve().parent)
if PROJ not in sys.path:
    sys.path.insert(0, PROJ)

import bb_agent  # noqa: E402
from agent import notify as notify_mod  # noqa: E402
from agent import tools  # noqa: E402

RL = {"rate_limits": {"default_delay": 2, "per_target": {"*.hackerone.com": 5, "*.bugcrowd.com": 3}}}


def test_rate_delay_matching():
    assert tools._rate_delay(RL, "a.hackerone.com") == 5
    assert tools._rate_delay(RL, "x.bugcrowd.com") == 3
    assert tools._rate_delay(RL, "example.com") == 2        # falls back to default
    assert tools._rate_delay({}, "example.com") == 0        # no config -> no wait


def test_execute_sleeps_matched_delay():
    slept = []
    orig_sleep, orig_run = tools.time.sleep, tools.run_command
    tools.time.sleep = lambda s: slept.append(s)
    tools.run_command = lambda c: ("out", True)
    try:
        tools.execute("run_command", "curl http://a.hackerone.com", RL,
                      approve=lambda c: True, announce=lambda m: None,
                      domain="a.hackerone.com")
        assert slept == [5], slept                          # matched per_target
        slept.clear()
        tools.execute("run_command", "whois example.com", RL,
                      approve=lambda c: True, announce=lambda m: None, domain="example.com")
        assert slept == [2], slept                          # default_delay
        slept.clear()
        tools.execute("run_command", "whois example.com", {},
                      approve=lambda c: True, announce=lambda m: None, domain="example.com")
        assert slept == [], slept                           # no rate_limits -> no sleep
    finally:
        tools.time.sleep, tools.run_command = orig_sleep, orig_run


def test_run_nuclei_argv():
    captured = {}
    orig = tools._run
    tools._run = lambda argv: (captured.setdefault("argv", argv), ("", True))[1]
    try:
        tools.run_nuclei("hosts.txt", "high,critical")
    finally:
        tools._run = orig
    assert captured["argv"] == ["nuclei", "-l", "hosts.txt", "-severity", "high,critical", "-silent"]


def test_nuclei_hosts_scope_filtered():
    recon = "api.example.com\nwww.example.com\ncrt.sh\nunrelated.com\nexample.com"
    hosts = bb_agent._nuclei_hosts(recon, "example.com", {"scope": {}})
    assert hosts == ["api.example.com", "example.com", "www.example.com"], hosts
    # crt.sh is a passive service, unrelated.com is outside the target domain -> excluded


def test_notify_build_and_message():
    assert notify_mod.build_notifier({}, "telegram", "t") is None           # unconfigured
    cfg = {"notify": {"telegram": {"bot_token": "B", "chat_id": "C"}}}
    fn = notify_mod.build_notifier(cfg, "telegram", "acme.com")
    assert callable(fn)
    sent = {}
    orig = urllib.request.urlopen
    urllib.request.urlopen = lambda req, timeout=10: sent.update(url=req.full_url, data=req.data) or _Null()
    try:
        fn({"finding": "LLM01", "command": "curl x", "status": "potential"})
    finally:
        urllib.request.urlopen = orig
    assert "api.telegram.org/botB/sendMessage" in sent["url"]
    assert b"acme.com" in sent["data"] and b"LLM01" in sent["data"]

    msg = notify_mod._message("acme.com", {"kind": "behavior_change", "signal": "HIGH", "indicator": "x"})
    assert "behaviour HIGH" in msg and "acme.com" in msg


class _Null:
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self): return b""


def test_sessionlog_fires_notifier_on_findings_only():
    from agent import memory
    memory.SESSIONS_DIR = Path(tempfile.mkdtemp())
    log = memory.SessionLog("notify.test")
    fired = []
    log.notifier = lambda rec: fired.append(rec)
    log.log("recon_seed", target="t")                       # not a finding -> no fire
    log.log_step(1, command="whois x", status="success", finding=None)  # no fire
    log.log_step(2, command="curl x", status="potential", finding="LLM01")  # fire
    log.log("behavior_change", signal="HIGH", indicator="y")  # fire
    assert len(fired) == 2, [f.get("finding") or f.get("kind") for f in fired]

    log.notifier = lambda rec: (_ for _ in ()).throw(RuntimeError("boom"))  # must not crash
    log.log_step(3, command="x", status="potential", finding="LLM06")
    assert True  # survived a failing notifier


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("\nALL PHASE 6 CHECKS PASS")
