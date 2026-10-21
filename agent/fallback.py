"""Failure router: fallback chains per tool.

Pure policy - no subprocess here. tools.execute() runs the commands; this module
only decides what to try next and which suggestions are human-only ("manual:").
"""
import os
import re
import shlex

FALLBACK_CHAINS = {
    "subfinder": [
        "amass enum -passive -d {domain}",
        "curl -s https://crt.sh/?q=%.{domain}&output=json",
        "manual: query hackertarget.com/subdomain-finder",
    ],
    "httpx": [
        "curl -I {url}",
        "wget --spider {url}",
    ],
    "reconftw_passive": [
        "manual: run subfinder + httpx + waybackurls by hand",
    ],
    "nuclei": [
        "manual: check nuclei-templates locally (vulns/templates/)",
    ],
    "ffuf": [
        "gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt",
        "feroxbuster -u {url}",
    ],
    "waybackurls": [
        "gau {domain}",
        "hakrawler -url {url}",
    ],
}


def chain_key(action: str, action_input: str) -> str:
    if action == "run_reconftw":
        return "reconftw_passive"
    try:
        toks = shlex.split(action_input)
    except ValueError:
        return ""
    return os.path.basename(toks[0]) if toks else ""


def fallbacks(action, action_input, domain="", url=""):
    """Return [(command_or_note, is_manual)] for the failed command.

    A fallback becomes manual (is_manual=True) when it is prefixed "manual:" or
    when a required {placeholder} has no value to fill (so we never run a broken
    command with a literal {url} in it)."""
    vals = {"domain": domain, "url": url}
    out = []
    for fb in FALLBACK_CHAINS.get(chain_key(action, action_input), []):
        if fb.startswith("manual"):
            out.append((fb, True))
            continue
        needed = re.findall(r"{(\w+)}", fb)
        if any(not vals.get(n) for n in needed):
            out.append((f"manual: {fb}", True))
            continue
        out.append((fb.format(**vals), False))
    return out
