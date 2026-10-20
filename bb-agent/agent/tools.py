"""Tool definitions and the passive-safety classifier.

The passive check is a security boundary: in --mode auto it decides what runs
without a human. Keep it strict — unknown binaries and active flags fall through
to a prompt rather than auto-executing.
"""
import os
import shlex
import subprocess

TIMEOUT = 1800  # seconds; reconftw passive can be slow
MAX_OUTPUT = 8000  # chars fed back to the LLM


def _run(cmd, shell=False):
    try:
        p = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return f"[timed out after {TIMEOUT}s]"
    out = (p.stdout or "") + (p.stderr or "")
    if len(out) > MAX_OUTPUT:
        out = out[:MAX_OUTPUT] + f"\n...[truncated, {len(out)} chars total]"
    return out.strip() or "[no output]"


def run_reconftw(reconftw_path: str, action_input: str) -> str:
    path = os.path.expanduser(reconftw_path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return _run(["bash", path, *shlex.split(action_input)])


def run_command(action_input: str) -> str:
    return _run(action_input, shell=True)


# --- passive classifier -----------------------------------------------------

_ACTIVE_CURL = {"-X", "--request", "-d", "--data", "--data-raw", "--data-binary",
                "-T", "--upload-file", "-F", "--form"}
_ACTIVE_RECONFTW = {"-a", "-r", "-s", "--deep"}  # all/recon/subdomains-active etc.


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
    # subfinder, whois, dig, nslookup: passive by nature
    return True
