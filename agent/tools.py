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
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from html import unescape
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

from . import fallback
from . import scope as scope_mod

# Native engine deps (Phase 9). Guarded so importing this module never crashes
# when they are missing; bb_agent.py prints a clean install hint at startup.
try:
    import requests
except ImportError:
    requests = None
try:
    import dns.resolver as _dns
except ImportError:
    _dns = None

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
    a 'command not found' message if nuclei is not installed (optional enhancement
    over the native check_* tools)."""
    if not shutil.which("nuclei"):
        return "[command not found: nuclei]", False
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
    # Optional external binary: only run it if it is actually installed, so a
    # missing tool degrades to a clean message instead of a stack trace.
    if not shutil.which(argv[0]):
        return f"[command not found: {argv[0]} (optional; install it or use a native tool)]", False
    return _run(argv)


# --- passive classifier (Phase 1, unchanged) --------------------------------

_ACTIVE_CURL = {"-X", "--request", "-d", "--data", "--data-raw", "--data-binary",
                "-T", "--upload-file", "-F", "--form"}
_ACTIVE_RECONFTW = {"-a", "-r", "-s", "--deep"}


def is_passive(action: str, action_input: str, whitelist) -> bool:
    """True only if this command is safe to auto-run in --mode auto."""
    if action in NATIVE:
        return NATIVE[action][1]
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
    if action in NATIVE:
        adapter, _passive = NATIVE[action]
        output, ok = adapter(action_input, cfg, scope)
        return {"status": "success" if ok else "failed",
                "command": f"{action} {action_input}", "fallback_used": None,
                "output": output, "manual": [],
                "attempts": [{"command": action_input, "output": output, "ok": ok}]}
    if action == "run_reconftw":
        output, ok = run_reconftw(cfg.get("reconftw_path", ""), action_input)
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


# --- native engine (Phase 9): pure-Python checks, no external binaries -------

_BRUTE_PREFIXES = ["www", "api", "dev", "staging", "admin", "mail", "test", "app",
                   "portal", "beta", "cdn", "static", "auth", "login", "dashboard"]
_DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080,
                  8443, 8888, 9200, 27017]
_PORT_SERVICE = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
                 443: "https", 445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgres",
                 6379: "redis", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
                 9200: "elasticsearch", 27017: "mongodb"}
_SEC_HEADERS = ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options",
                "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"]
_SENSITIVE_PATHS = ["/.git/HEAD", "/.env", "/backup.zip", "/.DS_Store", "/config.yml",
                    "/config.yaml", "/robots.txt", "/sitemap.xml", "/api/swagger.json",
                    "/api/docs", "/phpinfo.php", "/.htaccess", "/web.config",
                    "/server-status", "/actuator", "/actuator/env", "/actuator/health",
                    "/_profiler", "/telescope", "/api/debug"]
_XSS_PAYLOADS = ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "javascript:alert(1)"]
_SQLI_PAYLOADS = ["'", "''", "`", "')", '"', "1' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]
_SQL_ERRORS = ["mysql_fetch", "ORA-", "syntax error", "SQLSTATE", "Unclosed quotation"]
_REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com", "/\\evil.com", "https:evil.com"]
_SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config}}"]
_TAKEOVER_SIGS = ["There isn't a GitHub Pages site here", "NoSuchBucket",
                  "Sorry, We Couldn't Find That Page", "Domain not found"]
_SECRET_RE = [("API key", re.compile(r"AIza[0-9A-Za-z\-_]{10,}")),
              ("LLM/secret key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
              ("GitHub token", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
              ("AWS key", re.compile(r"AKIA[0-9A-Z]{16}"))]
_DEFAULT_PARAMS = ["id", "q", "search", "url", "redirect", "next"]


def _nt(cfg):
    return (cfg or {}).get("native_tools") or {}


def _http_timeout(cfg):
    return _nt(cfg).get("http_timeout", 5)


def _workers(cfg):
    return _nt(cfg).get("concurrent_workers", 10)


def _scheme(u):
    u = (u or "").strip()
    return u if re.match(r"^\w+://", u) else "http://" + u


def _origin(u):
    p = urlsplit(_scheme(u))
    return f"{p.scheme}://{p.netloc}"


def _set_param(url, name, value):
    p = urlsplit(_scheme(url))
    q = parse_qs(p.query)
    q[name] = [value]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q, doseq=True), p.fragment))


def _get(url, cfg=None, **kw):
    """GET via requests; returns a Response or None. Never raises."""
    if requests is None:
        return None
    kw.setdefault("timeout", _http_timeout(cfg))
    kw.setdefault("allow_redirects", True)
    try:
        return requests.get(url, **kw)
    except Exception:
        return None


def _first(action_input):
    toks = (action_input or "").split()
    return toks[0] if toks else (action_input or "")


def _params_from(action_input):
    """A URL plus the param names to test: query-string keys, any extra tokens,
    else a small set of common names so a bare URL is still testable."""
    toks = (action_input or "").split()
    url = toks[0] if toks else ""
    params = list(parse_qs(urlsplit(_scheme(url)).query).keys())
    for extra in toks[1:]:
        params += [x for x in re.split(r"[,\s]+", extra) if x]
    return url, (params or list(_DEFAULT_PARAMS))


def subdomain_enum(domain, cfg=None):
    """Passive subdomain discovery: crt.sh + HackerTarget + DNS brute force."""
    domain = scope_mod.host_of(domain)
    found = set()
    r = _get(f"https://crt.sh/?q=%.{domain}&output=json", cfg, timeout=_http_timeout(cfg) * 3)
    if r is not None and r.status_code == 200:
        try:
            for row in r.json():
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain):
                        found.add(name)
        except Exception:
            pass
    r = _get(f"https://api.hackertarget.com/hostsearch/?q={domain}", cfg)
    if r is not None and r.status_code == 200 and "," in (r.text or ""):
        for line in r.text.splitlines():
            h = line.split(",")[0].strip().lower()
            if h.endswith(domain):
                found.add(h)
    if _nt(cfg).get("brute_force_subdomains", True) and _dns is not None:
        for sub in _BRUTE_PREFIXES:
            host = f"{sub}.{domain}"
            try:
                _dns.resolve(host, "A", lifetime=_http_timeout(cfg))
                found.add(host)
            except Exception:
                pass
    found.discard("")
    hosts = sorted(found)
    if not hosts:
        return f"no subdomains discovered for {domain}", True
    return f"{len(hosts)} subdomains for {domain}:\n" + "\n".join(hosts), True


def probe_http(urls, cfg=None, scope=None):
    """Concurrent HTTP probe: status, title, server, redirect for each URL."""
    if isinstance(urls, str):
        urls = urls.split()
    urls = [_scheme(u) for u in urls]
    if scope is not None:
        urls = [u for u in urls if scope.check(u).allowed]
    if not urls:
        return "no urls to probe", True

    def one(u):
        r = _get(u, cfg)
        if r is None:
            return f"ERR {u}"
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.S | re.I)
        if m:
            title = unescape(m.group(1).strip())[:120]
        redirect = f" -> {r.url}" if getattr(r, "history", None) else ""
        return f"{r.status_code} {u} [{title}] server={r.headers.get('Server', '')}{redirect}"

    with ThreadPoolExecutor(max_workers=_workers(cfg)) as ex:
        lines = list(ex.map(one, urls))
    return "\n".join(lines), True


def port_scan(host, ports=None, cfg=None):
    """TCP connect scan (active). Returns open ports with a service guess."""
    host = scope_mod.host_of(host)
    ports = ports or _DEFAULT_PORTS
    timeout = _nt(cfg).get("port_scan_timeout", 1)

    def probe(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return p if s.connect_ex((host, p)) == 0 else None
        except Exception:
            return None
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=20) as ex:
        open_ports = sorted(p for p in ex.map(probe, ports) if p)
    if not open_ports:
        return f"no open ports on {host}", True
    return (f"open ports on {host}:\n"
            + "\n".join(f"{p}/{_PORT_SERVICE.get(p, '?')}" for p in open_ports)), True


def check_headers(url, cfg=None):
    """Flag missing security headers (MEDIUM) and bad CORS (HIGH)."""
    r = _get(_scheme(url), cfg)
    if r is None:
        return f"could not fetch {url}", False
    h = {k.lower(): v for k, v in r.headers.items()}
    out = [f"[MEDIUM] missing security header: {n}" for n in _SEC_HEADERS if n.lower() not in h]
    if h.get("access-control-allow-origin") == "*" and \
            h.get("access-control-allow-credentials", "").lower() == "true":
        out.append("[HIGH] CORS: wildcard origin with credentials allowed")
    if not out:
        return f"{url}: all checked security headers present", True
    return f"FINDING {url}:\n" + "\n".join(out), True


def check_xss(url, params, cfg=None):
    """Reflected XSS: inject payloads, flag ones echoed back unescaped (active)."""
    hits = []
    for p in params:
        for pay in _XSS_PAYLOADS:
            r = _get(_set_param(url, p, pay), cfg)
            if r is not None and pay in (r.text or ""):
                hits.append(f"[HIGH] XSS: param '{p}' reflects payload unescaped: {pay}")
                break
    if not hits:
        return f"no reflected XSS in params {params}", True
    return "FINDING reflected XSS:\n" + "\n".join(hits), True


def check_sqli(url, params, cfg=None):
    """Error-based SQLi: inject payloads, match known SQL error strings (active)."""
    hits = []
    for p in params:
        for pay in _SQLI_PAYLOADS:
            r = _get(_set_param(url, p, pay), cfg)
            body = (r.text or "") if r is not None else ""
            sig = next((s for s in _SQL_ERRORS if s.lower() in body.lower()), None)
            if sig:
                hits.append(f"[HIGH] SQLi: param '{p}' triggered '{sig}' with {pay}")
                break
    if not hits:
        return f"no SQL errors from params {params}", True
    return "FINDING SQLi:\n" + "\n".join(hits), True


def check_ssrf(url, params, cfg=None):
    """SSRF: inject a canary (interactsh if set, else AWS metadata) and look for a
    metadata/canary response (active)."""
    canary = _nt(cfg).get("interactsh_url") or "http://169.254.169.254/latest/meta-data/"
    hits = []
    for p in params:
        r = _get(_set_param(url, p, canary), cfg)
        body = (r.text or "") if r is not None else ""
        if any(sig in body for sig in ("ami-id", "instance-id", "iam/", "meta-data")) \
                or (canary and canary in body):
            hits.append(f"[HIGH] SSRF: param '{p}' fetched canary {canary}")
    if not hits:
        return f"no SSRF signal from params {params}", True
    return "FINDING SSRF:\n" + "\n".join(hits), True


def check_open_redirect(url, params, cfg=None):
    """Open redirect: inject attacker URLs, flag a redirect to evil.com (active)."""
    hits = []
    for p in params:
        for pay in _REDIRECT_PAYLOADS:
            r = _get(_set_param(url, p, pay), cfg, allow_redirects=False)
            if r is None:
                continue
            loc = r.headers.get("Location", "")
            if "evil.com" in loc or "evil.com" in (r.text or ""):
                hits.append(f"[MEDIUM] open redirect: param '{p}' -> {loc or pay}")
                break
    if not hits:
        return f"no open redirect in params {params}", True
    return "FINDING open redirect:\n" + "\n".join(hits), True


def check_idor(url, cfg=None):
    """IDOR: mutate a numeric id in the URL, flag materially different content (active)."""
    import random
    url = _scheme(url)
    base = _get(url, cfg)
    if base is None:
        return f"could not fetch {url}", False
    base_body = base.text or ""
    base_len = len(base_body)
    nums = re.findall(r"\d+", url)
    if not nums:
        return f"no numeric id in {url} to test for IDOR", True
    n = int(nums[-1])
    candidates = {n + 1, n + 2, max(n - 1, 0), random.randint(100000, 999999)}
    hits = []
    for alt in candidates:
        if alt == n:
            continue
        r = _get(re.sub(r"(\d+)(?!.*\d)", str(alt), url), cfg)
        if r is None or r.status_code != 200:
            continue
        alt_body = r.text or ""
        # A reachable adjacent id returning different, similarly-sized content is
        # a likely horizontal-access (IDOR) signal - works for small records too.
        if (alt_body and alt_body != base_body and base_len > 20
                and 0.5 * base_len <= len(alt_body) <= 2 * base_len):
            hits.append(f"[MEDIUM] possible IDOR: adjacent id {alt} returns different "
                        f"content ({len(alt_body)} bytes vs baseline {base_len})")
    if not hits:
        return f"no IDOR signal mutating id in {url}", True
    return "FINDING IDOR:\n" + "\n".join(hits), True


def check_info_disclosure(url, cfg=None):
    """Probe common sensitive paths concurrently; flag 200 with content (passive)."""
    root = _origin(url)

    def probe(path):
        r = _get(root + path, cfg)
        if r is not None and r.status_code == 200 and (r.text or "").strip():
            return f"[MEDIUM] exposed {path} (200, {len(r.text)} bytes)"
        return None

    with ThreadPoolExecutor(max_workers=_workers(cfg)) as ex:
        hits = [x for x in ex.map(probe, _SENSITIVE_PATHS) if x]
    if not hits:
        return f"no exposed sensitive paths on {root}", True
    return f"FINDING exposed paths on {root}:\n" + "\n".join(hits), True


def check_subdomain_takeover(subdomains, cfg=None, scope=None):
    """Fingerprint dangling subdomains by known takeover response strings (passive).

    shortcut: fingerprints the HTTP body only; add CNAME-vs-unclaimed-service
    resolution when a provider needs DNS-level confirmation."""
    if isinstance(subdomains, str):
        subdomains = subdomains.split()
    subs = [scope_mod.host_of(s) for s in subdomains]
    if scope is not None:
        subs = [s for s in subs if scope.check(s).allowed]
    hits = []
    for sub in subs:
        r = _get(_scheme(sub), cfg)
        if r is None:
            continue
        body = r.text or ""
        sig = next((s for s in _TAKEOVER_SIGS if s in body), None)
        if sig:
            hits.append(f"[HIGH] possible subdomain takeover: {sub} ({sig})")
    if not hits:
        return f"no takeover signatures across {len(subs)} subdomain(s)", True
    return "FINDING subdomain takeover:\n" + "\n".join(hits), True


def check_cors(url, cfg=None):
    """CORS: reflect an arbitrary Origin and 'null'; HIGH if credentials allowed."""
    url = _scheme(url)
    r = _get(url, cfg, headers={"Origin": "https://evil.com"})
    if r is None:
        return f"could not fetch {url}", False
    out = []
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
    if "evil.com" in acao:
        sev = "HIGH" if acac == "true" else "MEDIUM"
        out.append(f"[{sev}] CORS reflects arbitrary origin"
                   + (" with credentials" if acac == "true" else ""))
    elif acao == "*" and acac == "true":
        out.append("[HIGH] CORS: wildcard origin allowed with credentials")
    r2 = _get(url, cfg, headers={"Origin": "null"})
    if r2 is not None and r2.headers.get("Access-Control-Allow-Origin", "") == "null":
        out.append("[MEDIUM] CORS allows the 'null' origin")
    if not out:
        return f"{url}: CORS does not reflect untrusted origins", True
    return f"FINDING CORS on {url}:\n" + "\n".join(out), True


def check_ssti(url, params, cfg=None):
    """SSTI: inject math/config payloads, flag evaluated output (CRITICAL, active)."""
    hits = []
    for p in params:
        for pay in _SSTI_PAYLOADS:
            r = _get(_set_param(url, p, pay), cfg)
            body = (r.text or "") if r is not None else ""
            if pay == "{{config}}":
                if "SECRET_KEY" in body or "Config" in body:
                    hits.append(f"[CRITICAL] SSTI: param '{p}' leaked template config")
                    break
            elif "49" in body and "7*7" not in body:  # evaluated, not merely reflected
                hits.append(f"[CRITICAL] SSTI: param '{p}' evaluated {pay} -> 49")
                break
    if not hits:
        return f"no SSTI signal in params {params}", True
    return "FINDING SSTI:\n" + "\n".join(hits), True


def js_analysis(url, cfg=None):
    """Fetch linked JS, grep for keys, endpoints and hardcoded secrets (passive)."""
    url = _scheme(url)
    r = _get(url, cfg)
    if r is None:
        return f"could not fetch {url}", False
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text or "", re.I)
    out = []
    for src in srcs[:20]:
        jr = _get(urljoin(url, src), cfg)
        if jr is None:
            continue
        body = jr.text or ""
        for label, rx in _SECRET_RE:
            for m in sorted(set(rx.findall(body))):
                out.append(f"[HIGH] {label} in {src}: {m[:8]}...")  # truncated, never log full secret
        for ep in sorted(set(re.findall(r'["\'](/(?:api|v1|v2)/[A-Za-z0-9_\-/]+)', body)))[:10]:
            out.append(f"endpoint in {src}: {ep}")
        for kw in ("password=", "secret=", "token="):
            if kw in body.lower():
                out.append(f"[MEDIUM] hardcoded '{kw}' in {src}")
    if not out:
        return f"no secrets/endpoints in {len(srcs)} JS file(s) on {url}", True
    return f"FINDING JS analysis on {url}:\n" + "\n".join(out), True


def tech_fingerprint(url, cfg=None):
    """Identify server/framework from headers, cookies and HTML (passive)."""
    url = _scheme(url)
    r = _get(url, cfg)
    if r is None:
        return f"could not fetch {url}", False
    h = {k.lower(): v for k, v in r.headers.items()}
    tech = []
    if h.get("server"):
        tech.append(f"Server: {h['server']}")
    if h.get("x-powered-by"):
        tech.append(f"X-Powered-By: {h['x-powered-by']}")
    cookies = r.headers.get("Set-Cookie", "")
    for name, t in (("PHPSESSID", "PHP"), ("JSESSIONID", "Java"), ("ASP.NET_SessionId", "ASP.NET")):
        if name in cookies:
            tech.append(f"session cookie {name} -> {t}")
    body = r.text or ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if m:
        tech.append(f"generator: {m.group(1)}")
    for fw in ("react", "angular", "vue", "jquery"):
        if re.search(r"\b" + fw + r"\b", body, re.I):
            tech.append(f"JS framework signature: {fw}")
    if not tech:
        return f"no tech signatures on {url}", True
    return f"tech on {url}:\n" + "\n".join(tech), True


def native_seed(target, cfg=None):
    """Passive recon seed with native tools: subdomains + an HTTP probe. Replaces
    the reconftw seed when reconftw is not installed."""
    subs, _ = subdomain_enum(target, cfg)
    hosts = [ln for ln in subs.splitlines() if "." in ln and " " not in ln]
    probe, _ = probe_http(hosts[:25] or [scope_mod.host_of(target)], cfg)
    return f"[subdomain_enum]\n{subs}\n\n[probe_http]\n{probe}"


# Adapters: parse the ReAct ACTION_INPUT string into each tool's arguments.
def _a_subdomain(ai, cfg, scope):
    return subdomain_enum(_first(ai), cfg)


def _a_probe(ai, cfg, scope):
    return probe_http(ai, cfg, scope)


def _a_portscan(ai, cfg, scope):
    toks = (ai or "").split()
    host = toks[0] if toks else ai
    ports = [int(x) for x in re.split(r"[,\s]+", " ".join(toks[1:])) if x.isdigit()] or None
    return port_scan(host, ports, cfg)


def _a_takeover(ai, cfg, scope):
    return check_subdomain_takeover(ai, cfg, scope)


def _a_url(fn):
    return lambda ai, cfg, scope: fn(_first(ai), cfg)


def _a_params(fn):
    def inner(ai, cfg, scope):
        url, params = _params_from(ai)
        return fn(url, params, cfg)
    return inner


# name -> (adapter(action_input, cfg, scope)->(text, ok), is_passive)
NATIVE = {
    "subdomain_enum": (_a_subdomain, True),
    "probe_http": (_a_probe, True),
    "check_headers": (_a_url(check_headers), True),
    "check_info_disclosure": (_a_url(check_info_disclosure), True),
    "check_subdomain_takeover": (_a_takeover, True),
    "check_cors": (_a_url(check_cors), True),
    "js_analysis": (_a_url(js_analysis), True),
    "tech_fingerprint": (_a_url(tech_fingerprint), True),
    "port_scan": (_a_portscan, False),
    "check_xss": (_a_params(check_xss), False),
    "check_sqli": (_a_params(check_sqli), False),
    "check_ssrf": (_a_params(check_ssrf), False),
    "check_open_redirect": (_a_params(check_open_redirect), False),
    "check_idor": (_a_url(check_idor), False),
    "check_ssti": (_a_params(check_ssti), False),
}
