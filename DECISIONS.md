# Decisions

Deviations from the phase specs, and the reasoning behind them. Each entry is a
place where the build does something other than the literal spec, on purpose.

## PASSIVE_SERVICES scope exemption (Phase 3)

Spec: block any command aimed at a target not in scope.

Build: `agent/scope.py` keeps a `PASSIVE_SERVICES` set (crt.sh, hackertarget,
web.archive.org, otx.alienvault.com, urlscan.io) that is exempt from the scope
check. These hosts are queried *about* the target during passive recon; they are
not themselves targets. The Phase 2 fallback chains call crt.sh and hackertarget,
so a strict host check would block legitimate recon fallbacks.

Limit: the set is fixed and matches the shipped fallback chains. Adding a fallback
that calls a new third-party service means adding that host here. Marked with a
`shortcut:` comment in `scope.py`.

## Multi-target --parallel uses a thread pool (Phase 4)

Spec: "--parallel runs up to 3 targets concurrently (asyncio)."

Build: `agent/multi.py` drives an `asyncio` event loop over a
`ThreadPoolExecutor(max_workers=3)`. A hunt is blocking work (LLM calls and
subprocess), which bare asyncio coroutines cannot parallelise. The thread pool
runs three hunts at once, which is the stated goal; asyncio is the driver.

## AI-target HTTP uses stdlib urllib, not requests (Phase 5)

Spec note: "requests is stdlib-adjacent (add to requirements.txt if missing)."

Build: `agent/ai_target.py` uses `urllib.request`. The POST, custom headers, and
JSON body are a few lines with the standard library, so no dependency was added.
requirements.txt stays at ollama, click, rich, PyYAML.

## KB guides gained Impact and Remediation sections (Phase 3)

Spec: the report builder fills Impact and Remediation from the KB "if present."

Build: the nine web-vuln guides and the four LLM guides each got an `## Impact`
and `## Remediation` section so reports are populated rather than left with a
placeholder. This is additive content in `kb/`, not a code change.

## UTF-8 stdout at startup (Phase 4/5)

`bb_agent.py` reconfigures stdout and stderr to UTF-8 on startup. Rich prints
box-drawing characters and arrows; on a legacy Windows cp1252 console that raised
`UnicodeEncodeError` and crashed a run. The reconfigure is wrapped in try/except
so it is a no-op where it does not apply.

## Resume skips the startup scope check (Phase 4)

`--resume` does not re-run the startup scope check on the target, because that
target was approved when the original session started. The per-command scope gate
inside the loop still runs on every proposed command and fallback.

## Usage errors exit with code 2 (Phase 5 audit)

The release audit lists "unknown flags exit with code 1." Click, like most Unix
CLIs, exits with code 2 for a usage error (unknown flag, missing required option)
and prints a clean one-line message with no stack trace. The no-stack-trace and
useful-message intent holds; the code is 2, not 1, to match the framework and the
Unix convention rather than override it.

## --owasp-only is deterministic (Phase 5)

`--owasp-only` fires each OWASP item's canned probe without calling raven's LLM,
so the checklist runs offline without ollama. Full `--ai-mode` uses the LLM to
craft and escalate payloads.

## Nuclei auto-scan is active but scope-filtered (Phase 6)

Spec: "called automatically after reconftw passive completes."

Build: nuclei runs automatically in `hunt_one`, but nuclei is an active scanner,
not passive like the rest of the seed step. To keep the scope guarantee, the host
list it scans is pulled from the recon output, bounded to the target's own domain,
filtered through the scope check, and stripped of PASSIVE_SERVICES, so it never
hits an out-of-scope host. It can be turned off with `nuclei.enabled: false`, and
it skips with a warning if nuclei is not installed. The automatic run is a timing
choice; it does not bypass the scope boundary or the human approval that still
gates everything the LLM proposes afterward.

The command is `nuclei -l <file> -severity ...`. The spec wrote `-t
<subdomain_list_file>`, but in nuclei `-t` selects templates and `-l` takes the
host-list file, so the build uses `-l` to match the stated intent.

## Notifications fire from the log write path (Phase 6)

`--notify` attaches a callable to `SessionLog`. `memory.py:_append` fires it on any
record that carries a `finding` or is a `behavior_change`, which is the single
place both `loop.py` and `ai_target.py` record findings. A send failure is
caught and ignored so a down webhook never aborts a hunt.
