"""Tool execution + passive-safety classifier + failure-router orchestration.

Two security boundaries live here:
- is_passive(): decides what auto-runs in --mode auto (unchanged from Phase 1).
- no shell: commands run via shlex.split (list form), never shell=True, so
  chaining/injection (;, &&, |, backticks) cannot execute.
"""
import fnmatch
import os
import re
import shlex
import subprocess
import time

from . import fallback
from . import scope as scope_mod

TIMEOUT = 1800     # seconds; reconftw passive can be slow
MAX_OUTPUT = 8000  # chars fed back to the LLM

_URL_RE = re.compile(r"https?://[^\s'\"]+")


def _run(argv):
    """Run an argv list (no shell). Returns (output, ok)."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return f"[timed out after {TIMEOUT}s]", False
    except FileNotFoundError as e:
        return f"[command not found: {e}]", False
    out = (p.stdout or "") + (p.stderr or "")
    if len(out) > MAX_OUTPUT:
        out = out[:MAX_OUTPUT] + f"\n...[truncated, {len(out)} chars total]"
    return (out.strip() or "[no output]"), (p.returncode == 0)


def run_reconftw(reconftw_path: str, action_input: str):
    path = os.path.expanduser(reconftw_path)
    if not os.path.isfile(path):
        return f"[reconftw not found at {path}]", False
    return _run(["bash", path, *shlex.split(action_input)])


def run_nuclei(list_file: str, severity="medium,high,critical"):
    """Active vuln scan over a host-list file. Returns (output, ok); ok=False with
    a 'command not found' message if nuclei is not installed."""
    return _run(["nuclei", "-l", list_file, "-severity", severity, "-silent"])


def _rate_delay(cfg, host) -> float:
    rl = cfg.get("rate_limits") or {}
    for pattern, delay in (rl.get("per_target") or {}).items():
        if fnmatch.fnmatch(host or "", pattern):
            return delay
    return rl.get("default_delay", 0) or 0


def _rate_sleep(cfg, host, announce=None):
    d = _rate_delay(cfg, host)
    if d and d > 0:
        if announce:
            announce(f"[dim]rate limit: waiting {d}s for {host}[/]")
        time.sleep(d)


def run_command(action_input: str):
    try:
        argv = shlex.split(action_input)
    except ValueError as e:
        return f"[unparseable command: {e}]", False
    if not argv:
        return "[empty command]", False
    return _run(argv)


# --- passive classifier (Phase 1, unchanged) --------------------------------

_ACTIVE_CURL = {"-X", "--request", "-d", "--data", "--data-raw", "--data-binary",
                "-T", "--upload-file", "-F", "--form"}
_ACTIVE_RECONFTW = {"-a", "-r", "-s", "--deep"}


def is_passive(action: str, action_input: str, whitelist) -> bool:
    """True only if this command is safe to auto-run in --mode auto."""
    try:
        tokens = shlex.split(action_input)
    except ValueError:
        return False
    if not tokens:
        return False

    if action == "run_reconftw":
        binary = "reconftw"
        flags = tokens
    else:
        binary = os.path.basename(tokens[0])
        flags = tokens[1:]

    if binary not in whitelist:
        return False

    if binary == "reconftw":
        return "-p" in flags and not (_ACTIVE_RECONFTW & set(flags))
    if binary == "curl":
        if _ACTIVE_CURL & set(flags):
            return False
        return not any(f in ("-X", "--request") for f in flags)  # GET only
    if binary == "httpx":
        return "fuzz" not in action_input.lower()
    return True  # subfinder, whois, dig, nslookup


# --- failure router ---------------------------------------------------------

def url_in(action_input: str) -> str:
    m = _URL_RE.search(action_input)
    return m.group(0) if m else ""


def execute(action, action_input, cfg, approve, announce, domain="", url="", scope=None):
    """Run the primary command; on failure walk the fallback chain.

    approve(cmd)->bool gates each *fallback* (the primary is already approved by
    the caller). announce(msg) reports progress. Returns a result dict with:
    status (success|fallback_used|failed), command, fallback_used, output,
    attempts (list), manual (list of human-only suggestions).

    scope (optional ScopeEnforcer): checked before the primary runs (raises
    scope.ScopeViolation if blocked) and before each fallback (out-of-scope
    fallbacks are skipped, not run).
    """
    tgt = scope_mod.command_target(action, action_input, domain)
    if scope is not None:
        sr = scope.check(tgt)
        if not sr.allowed:
            raise scope_mod.ScopeViolation(tgt, sr.reason)

    _rate_sleep(cfg, tgt, announce)
    if action == "run_reconftw":
        output, ok = run_reconftw(cfg["reconftw_path"], action_input)
    else:
        output, ok = run_command(action_input)

    if ok:
        return {"status": "success", "command": action_input,
                "fallback_used": None, "output": output, "attempts": [], "manual": []}

    attempts = [{"command": action_input, "output": output, "ok": False}]
    manual = []
    announce(f"[red]Tool failed:[/] {action_input}")
    max_fb = cfg.get("max_fallback_attempts", 3)
    tried = 0

    for cmd, is_manual in fallback.fallbacks(action, action_input, domain, url):
        if is_manual:
            manual.append(cmd)
            continue
        if tried >= max_fb:
            break
        if scope is not None and not scope.check(
                scope_mod.command_target("run_command", cmd, domain)).allowed:
            announce(f"[red]Fallback out of scope, skipping:[/] {cmd}")
            attempts.append({"command": cmd, "scope_blocked": True})
            continue
        announce(f"[yellow]Trying fallback:[/] {cmd}")
        if not approve(cmd):
            attempts.append({"command": cmd, "skipped": True})
            continue
        _rate_sleep(cfg, scope_mod.command_target("run_command", cmd, domain), announce)
        fb_out, fb_ok = run_command(cmd)
        tried += 1
        attempts.append({"command": cmd, "output": fb_out, "ok": fb_ok})
        if fb_ok:
            return {"status": "fallback_used", "command": action_input,
                    "fallback_used": cmd, "output": fb_out,
                    "attempts": attempts, "manual": manual}

    return {"status": "failed", "command": action_input, "fallback_used": None,
            "output": output, "attempts": attempts, "manual": manual}
