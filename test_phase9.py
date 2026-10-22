"""Phase 9 regression checks: native engine (no external binaries) + entry point.

All HTTP is mocked by swapping tools.requests, so these run offline.
"""
import contextlib
import inspect
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

PROJ = str(Path(__file__).resolve().parent)
if PROJ not in sys.path:
    sys.path.insert(0, PROJ)

import click  # noqa: E402

import bb_agent  # noqa: E402
from agent import tools  # noqa: E402


class _Resp:
    def __init__(self, text="", status=200, headers=None, url="", history=()):
        self.text = text
        self.status_code = status
        self.headers = headers or {}
        self.url = url
        self.history = history

    def json(self):
        return json.loads(self.text)


class _FakeRequests:
    def __init__(self, handler):
        self.handler = handler

    def get(self, url, **kw):
        return self.handler(url, kw)


@contextlib.contextmanager
def fake(handler):
    orig = tools.requests
    tools.requests = _FakeRequests(handler)
    try:
        yield
    finally:
        tools.requests = orig


def _qval(url):
    return "".join(v for vals in parse_qs(urlsplit(url).query).values() for v in vals)


NO_BRUTE = {"native_tools": {"brute_force_subdomains": False}}


def test_subdomain_enum_crtsh():
    def handler(url, kw):
        if "crt.sh" in url:
            return _Resp(text=json.dumps([{"name_value": "api.example.com\n*.example.com"},
                                          {"name_value": "www.example.com"}]))
        return _Resp(status=404)
    with fake(handler):
        out, ok = tools.subdomain_enum("example.com", NO_BRUTE)
    assert ok
    assert "api.example.com" in out and "www.example.com" in out and "example.com" in out


def test_probe_http_concurrent():
    seen = []

    def handler(url, kw):
        seen.append(url)
        return _Resp(text=f"<title>T {url}</title>", headers={"Server": "nginx"}, url=url)
    with fake(handler):
        out, ok = tools.probe_http("http://a.test http://b.test http://c.test http://d.test http://e.test", {})
    assert ok and len(seen) == 5 and out.count("200") == 5 and "nginx" in out


def test_check_headers_missing():
    with fake(lambda url, kw: _Resp(headers={})):
        out, ok = tools.check_headers("http://x.test", {})
    assert ok
    for name in tools._SEC_HEADERS:
        assert name in out, name


def test_check_xss_reflected():
    # Reflect the injected param value verbatim -> payload present unescaped.
    with fake(lambda url, kw: _Resp(text="echo: " + _qval(url))):
        out, ok = tools.check_xss("http://x.test/?q=1", ["q"], {})
    assert ok and "FINDING" in out and "XSS" in out


def test_check_sqli_error():
    with fake(lambda url, kw: _Resp(text="Unclosed quotation mark after the character string")):
        out, ok = tools.check_sqli("http://x.test/?id=1", ["id"], {})
    assert ok and "SQLi" in out and "Unclosed quotation" in out


def test_check_info_disclosure():
    def handler(url, kw):
        return _Resp(text="ref: refs/heads/main") if url.endswith("/.git/HEAD") else _Resp(status=404)
    with fake(handler):
        out, ok = tools.check_info_disclosure("http://x.test", {})
    assert ok and "/.git/HEAD" in out


def test_check_cors_wildcard():
    def handler(url, kw):
        origin = kw.get("headers", {}).get("Origin", "")
        return _Resp(headers={"Access-Control-Allow-Origin": origin,
                              "Access-Control-Allow-Credentials": "true"})
    with fake(handler):
        out, ok = tools.check_cors("http://x.test", {})
    assert ok and "HIGH" in out


def test_check_ssti_eval():
    def handler(url, kw):
        val = _qval(url)
        # Evaluate the arithmetic payload; do not echo "7*7" back.
        return _Resp(text="result: 49") if "7*7" in val else _Resp(text="nope")
    with fake(handler):
        out, ok = tools.check_ssti("http://x.test/?name=1", ["name"], {})
    assert ok and "CRITICAL" in out and "SSTI" in out


def test_js_analysis_apikey():
    def handler(url, kw):
        if url.endswith(".js"):
            return _Resp(text='var k="AIzaSyD1234567890abcdefghij";')
        return _Resp(text='<script src="/app.js"></script>')
    with fake(handler):
        out, ok = tools.js_analysis("http://x.test", {})
    assert ok and "API key" in out and "AIzaSyD1" in out


def test_no_external_binaries():
    import ast
    src = Path(tools.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    # No subprocess call anywhere passes shell=True.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                assert not (kw.arg == "shell" and getattr(kw.value, "value", None) is True)
    # subprocess.run lives in exactly one guarded chokepoint (_run); the binary
    # wrappers that call it all gate on shutil.which first.
    assert src.count("subprocess.run(") == 1
    assert "shutil.which" in src
    # The native checks themselves contain zero subprocess usage.
    for name in list(tools.NATIVE) + ["native_seed"]:
        fn = getattr(tools, name, None)
        body = inspect.getsource(fn) if (fn and callable(fn)) else ""
        assert "subprocess" not in body, name


def test_startup_no_reconftw():
    bb_agent._require_deps()  # deps are installed -> must not SystemExit
    cfg = {"scope": {}, "reconftw_path": "/no/such/reconftw.sh", "trace": {"enabled": False}}
    orig_run, orig_seed = bb_agent.run, tools.native_seed
    bb_agent.run = lambda *a, **k: None          # skip the real LLM loop
    tools.native_seed = lambda t, c=None: "seed"  # skip real network recon
    try:
        res = bb_agent.hunt_one(cfg, "example.com", "auto", "m",
                                no_dashboard=True, verbose=False, no_trace=True)
    finally:
        bb_agent.run, tools.native_seed = orig_run, orig_seed
    assert res["status"] != "no_reconftw", res


def test_passive_classifier():
    passive = ["subdomain_enum", "probe_http", "check_headers", "check_info_disclosure",
               "check_subdomain_takeover", "check_cors", "js_analysis", "tech_fingerprint"]
    active = ["port_scan", "check_xss", "check_sqli", "check_ssrf",
              "check_open_redirect", "check_idor", "check_ssti"]
    for a in passive:
        assert tools.is_passive(a, "http://x.test", []), a
    for a in active:
        assert not tools.is_passive(a, "http://x.test", []), a


def test_entry_point_registered():
    src = Path(PROJ, "setup.py").read_text(encoding="utf-8")
    assert "raven=bb_agent:cli" in src


def test_cli_callable():
    assert hasattr(bb_agent, "cli")
    assert isinstance(bb_agent.cli, click.Command)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("\nALL PHASE 9 CHECKS PASS")
