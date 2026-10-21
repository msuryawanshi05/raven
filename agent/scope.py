"""Scope enforcement - hard block before any command runs out of scope.

Config (config.yaml):
    scope:
      domains:  ["*.example.com", "example.com"]
      excluded: ["admin.example.com", "*.internal.example.com"]
      ip_ranges: ["10.0.0.0/8"]        # optional
      max_severity_auto: medium        # read by callers, not enforced here

Rules: exclusion beats inclusion; `*.example.com` matches sub.example.com but NOT
example.com itself; an empty scope (no domains and no ip_ranges) allows everything
so Phase 1/2 configs keep working.
"""
import ipaddress
import re
from collections import namedtuple

ScopeResult = namedtuple("ScopeResult", ["allowed", "reason"])

# Known passive OSINT/recon services our tools + fallback chains query. These are
# reached *about* the target, not tested, so they are exempt from scope.
# shortcut: fixed list matches the shipped fallback chains; extend when adding
# fallbacks that call a new third-party service.
PASSIVE_SERVICES = {
    "crt.sh", "www.crt.sh", "hackertarget.com", "api.hackertarget.com",
    "web.archive.org", "otx.alienvault.com", "urlscan.io",
}

_TARGET_FLAGS = {"-d", "--domain", "-u", "--url", "-t", "--target", "--host"}


class ScopeViolation(Exception):
    def __init__(self, target, reason):
        super().__init__(f"{target} out of scope: {reason}")
        self.target = target
        self.reason = reason


def host_of(token: str) -> str:
    """Reduce a URL or bare host[:port]/path to a lowercase hostname."""
    token = re.sub(r"^\w+://", "", token.strip())
    token = token.split("/")[0].split("@")[-1]
    if token.count(":") == 1:  # host:port (not an IPv6 literal)
        token = token.split(":")[0]
    return token.lower().rstrip(".")


def _match(pattern: str, host: str) -> bool:
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def command_target(action: str, action_input: str, session_domain: str) -> str:
    """Best-effort: the host a command is aimed at.

    reconftw -> the session domain; otherwise a value after a target flag, else a
    URL in the command, else the session domain."""
    if action == "run_reconftw":
        return session_domain
    toks = action_input.split()
    for i, t in enumerate(toks[:-1]):
        if t in _TARGET_FLAGS:
            return host_of(toks[i + 1])
    m = re.search(r"https?://[^\s'\"]+", action_input)
    if m:
        return host_of(m.group(0))
    return session_domain


class ScopeEnforcer:
    def __init__(self, scope_cfg: dict):
        scope_cfg = scope_cfg or {}
        self.domains = scope_cfg.get("domains", []) or []
        self.excluded = scope_cfg.get("excluded", []) or []
        self.ip_ranges = [ipaddress.ip_network(r, strict=False)
                          for r in (scope_cfg.get("ip_ranges", []) or [])]
        self.max_severity_auto = scope_cfg.get("max_severity_auto")

    def _as_ip(self, host):
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    def is_excluded(self, target: str) -> bool:
        host = host_of(target)
        return any(_match(p, host) for p in self.excluded)

    def is_in_scope(self, target: str) -> bool:
        host = host_of(target)
        ip = self._as_ip(host)
        if ip is not None:
            return any(ip in net for net in self.ip_ranges)
        return any(_match(p, host) for p in self.domains)

    def check(self, target: str) -> ScopeResult:
        host = host_of(target)
        if self.is_excluded(host):
            return ScopeResult(False, f"{host} is on the exclusion list")
        if host in PASSIVE_SERVICES:
            return ScopeResult(True, "passive OSINT service")
        if not self.domains and not self.ip_ranges:
            return ScopeResult(True, "no scope configured")
        if self.is_in_scope(host):
            return ScopeResult(True, "in scope")
        return ScopeResult(False, f"{host} is not in the defined scope")


def hosts_under(recon_text, target):
    """Hostnames in recon output that belong to the target's own domain."""
    base = host_of(target)
    found = set(re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b",
                           (recon_text or "").lower()))
    found = {h for h in found if h == base or h.endswith("." + base)}
    found.add(base)
    return found
