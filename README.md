# RAVEN

Agentic bug bounty assistant with a native Python recon-and-scan engine (crt.sh,
HTTP probing, port scan, and checks for headers, XSS, SQLi, SSRF, SSTI, CORS,
IDOR, open redirect, info disclosure, subdomain takeover, JS secrets, tech
fingerprinting) driven by a local-LLM ReAct loop that reads the output, consults
per-vuln technique guides, and proposes the next step. No external binaries are
required; reconftw and nuclei are used automatically only if they are installed.
Every command is gated by human approval, and a failed tool falls back
automatically.

> For authorized testing only. Stay in scope. Follow responsible disclosure.

## Installation

```bash
git clone https://github.com/msuryawanshi05/raven
cd raven
pip install -e .        # installs the `raven` command in the current environment

# ollama (local LLM runtime for the reasoning loop):
ollama serve            # start the daemon
ollama pull llama3.1    # pull the default model
```

That is all. The scan engine is pure Python - no subfinder, httpx, nuclei, nmap,
or reconftw install needed. (reconftw / nuclei are picked up automatically as an
optional enhancement if they happen to be on PATH.)

## Usage

`raven` is the installed command; `python bb_agent.py` works identically without
installing.

```bash
# start the web dashboard
raven --serve

# ask mode: confirm every proposed command (default)
raven --target http://example.com --mode ask

# auto mode: passive commands run automatically, everything else still asks
raven --target http://example.com --mode auto

# different model
raven --target example.com --model qwen2.5

# build a submission-ready report from a past session (no live recon)
python bb_agent.py --report sessions/example.com_<ts>.jsonl
python bb_agent.py --report sessions/example.com_<ts>.jsonl --platform hackerone

# check whether a host is in scope per config.yaml (exit 0 = in, 1 = out)
python bb_agent.py --scope-check sub.example.com

# hunt a list of domains (one per line, # comments); --parallel runs up to 3 at once
python bb_agent.py --targets targets.txt --mode auto
python bb_agent.py --targets targets.txt --parallel

# Huntr 2.0 challenge: parse a briefing, auto-scope + strategy, auto-draft huntr report
python bb_agent.py --challenge briefing.txt

# resume a previous session where it left off
python bb_agent.py --resume sessions/example.com_<ts>.jsonl

# auto mode shows a live dashboard; disable it with:
python bb_agent.py --target example.com --mode auto --no-dashboard

# AI target mode: attack an LLM over HTTP instead of recon
python bb_agent.py --target https://chat.example.com --ai-mode --mode auto
python bb_agent.py --target https://chat.example.com --owasp-only --mode auto
python bb_agent.py --target https://chat.example.com --baseline-only
python bb_agent.py --target https://chat.example.com --chain rag_poison --mode auto

# send a message on each finding (needs notify.<platform> filled in config.yaml)
python bb_agent.py --target example.com --mode auto --notify telegram

# multi-agent: recon and exploit agents run in parallel
python bb_agent.py --target example.com --multi-agent --mode auto

# print the hunt graph from a past session; disable the LLM tracer with --no-trace
python bb_agent.py --graph-summary sessions/example.com_<ts>_graph.json
```

Each recon run:
1. Scope check on `--target` (hard block and exit if out of scope).
2. Seeds the context with native passive recon (`subdomain_enum` + `probe_http`),
   or `reconftw -d <target> -p` instead if reconftw is installed.
3. The LLM replies `THOUGHT / ACTION / ACTION_INPUT`, one command per step.
4. Scope gate: a command aimed at an out-of-scope or excluded host is blocked
   before the human is asked, and the LLM is told to stay in scope.
5. Approval gate: in `--mode ask` every action waits for `y/n`; in `--mode auto`
   only whitelisted passive commands auto-run, active or unknown ones still ask.
6. If the command fails, the failure router walks a fallback chain, re-checking
   each fallback against the scope and approval gates.
7. Before testing a vuln class, the LLM emits `VULN_CLASS: <class>` and is handed
   the matching `kb/<class>.md` technique guide to follow.
8. The observation is fed back, and the loop repeats until `FINAL_ANSWER` or
   `max_steps`.

## Output

`sessions/<target>_<ts>.jsonl` holds one record per step: `timestamp, step,
thought, action, command, status, fallback_used, output_summary, finding,
kb_consulted`.

`sessions/<target>_<ts>_notes.md` is the human-readable companion, with sections
for Subdomains Found, Open Ports, Potential Vulns, and Dead Ends. A finding is
added when the LLM emits `NOTE: <section> | <text>`, or when a `finding_keywords`
string shows up in a command's output.

## Knowledge base (`kb/`)

One markdown guide per vuln class (xss, sqli, ssrf, idor, open_redirect, cors,
subdomain_takeover, lfi, ssti). Each lists tool order, response indicators,
fallbacks, what to record, scope limits, a submission checklist, and Impact plus
Remediation (the report builder reads those last two). `_template.md` is the
format; drop in a new `kb/<name>.md` and it becomes available automatically.

## Scope enforcement (`agent/scope.py`)

Set a `scope` block in `config.yaml`. It is enforced at startup (on `--target`),
before every command the agent proposes, and on each fallback. A block is logged
with `"kind": "scope_block"`, and the LLM is told to stay in scope.

```yaml
scope:
  domains:  ["*.example.com", "example.com"]   # empty = no restriction
  excluded: ["admin.example.com", "*.internal.example.com"]
  ip_ranges: ["10.0.0.0/8"]
```

`*.example.com` matches `sub.example.com` but not `example.com` itself. Exclusion
beats inclusion. Known passive OSINT services (crt.sh, hackertarget) are exempt so
recon fallbacks keep working; see DECISIONS.md for why. An empty or absent scope
allows everything, which is the Phase 1 and 2 behaviour.

## Reports (`reporter/`)

`--report <jsonl>` reads a session log and its `_notes.md` if present, then writes
`reports/<prefix>_report.md`. The report carries a summary, the target with
endpoint and parameter, a CWE and CVSS estimate, steps to reproduce drawn from the
action sequence, the payload, a "What I tried" section built from failed attempts,
and Impact plus Remediation pulled from the KB.

Add `--platform hackerone|bugcrowd|huntr` to also write a platform-shaped draft at
`reports/<prefix>_<platform>.md`, with severity mapped to the platform scale
(Bugcrowd uses P1 to P4). It works offline; if `notes.md` is missing it builds from
the JSONL alone.

## Multi-target (`agent/multi.py`)

`--targets <file>` hunts each in-scope domain in turn and skips out-of-scope ones,
writing one session per target. At the end it prints a summary table (target,
findings, duration, status) and saves `reports/multi_<ts>_summary.md`. `--parallel`
runs up to 3 at once, which turns the dashboard off and can interleave ask-mode
prompts, so pair it with `--mode auto`.

## Huntr challenge mode (`agent/challenge.py`)

`--challenge <briefing.txt>` parses a Huntr 2.0 briefing for the target URL, the AI
agent's tools, the objective, and any stated guardrails. It scopes the run to the
challenge host, injects a prompt-injection and tool-abuse strategy, logs to
`sessions/huntr_<id>_<ts>.jsonl`, and auto-drafts a Huntr report at the end. It
adds two KB guides, `kb/prompt_injection.md` and `kb/tool_abuse.md`.

## Resume (`agent/resume.py`)

`--resume <jsonl>` rebuilds context from a past session (subdomains, tried
commands, findings), appends to the same session file and notes, and continues
from the next step number. With `resume_skip_duplicates: true` it skips commands
already run. It does not re-run the startup scope check, because that target was
approved when the original session started; the per-command scope gate still runs.

## Live dashboard (`ui/dashboard.py`)

In `--mode auto` on a wide enough TTY, a Rich `Live` layout shows the target and
step, recon counts, the current action, the latest thought, the finding count, and
a tail of the log. It falls back to plain panels when the terminal is narrow or not
a TTY, or when you pass `--no-dashboard`. It is imported only when auto mode asks
for it.

## AI target mode (`agent/ai_target.py`)

For LLM targets such as chatbots or assistant APIs, `--ai-mode` replaces reconftw
with an HTTP interaction layer. Each action is a prompt POSTed to the target, and
the reply is scored rather than parsed as a shell command.

The loop sends a baseline prompt, builds a target profile from the reply, then
walks the OWASP LLM Top 10 checklist (`agent/owasp_llm.py`). For each item it
crafts a payload (raven's LLM in full `--ai-mode`, or the canned probe with
`--owasp-only`), sends it, and runs the behaviour detector (`agent/behavior.py`)
on the response. A compromise signal, such as complying after an earlier refusal,
a success-indicator match, or a tool firing, is logged as `behavior_change` and
recorded as a potential finding. On a weakness the loop escalates with an indirect
injection chain from `agent/injection_chains.py` (`rag_poison`, `tool_response`,
or `memory_persistence`). An OWASP coverage table is appended to `notes.md` at the
end.

- `--owasp-only`: run just the checklist, deterministic and with no raven LLM.
- `--baseline-only`: record baseline behaviour and the target profile, no attack.
- `--chain <type>`: run one injection chain after the baseline.
- The target host is scope-checked at startup, and `request_delay` throttles sends.
- The endpoint comes from `--target` and overrides `ai_target.endpoint`. Shape the
  request with `ai_target.payload_template` (the `{{PAYLOAD}}` marker is
  JSON-escaped) and read the reply with `response_path`, a dot-path into the JSON.

Added KB guides: `kb/llm01_prompt_injection.md`, `kb/llm06_data_disclosure.md`,
`kb/llm07_plugin_abuse.md`, `kb/llm08_excessive_agency.md`. Each adds Injection
Chains, Win Condition, and Evasion Techniques sections to the standard format.

## Rate limits, nuclei, notifications (Phase 6)

Rate limits throttle requests per target. `tools.execute` waits before each
command and fallback, using the first `rate_limits.per_target` wildcard the host
matches, otherwise `rate_limits.default_delay`. With no `rate_limits` block the
delay is 0, so older configs are unchanged.

```yaml
rate_limits:
  default_delay: 2
  per_target:
    "*.hackerone.com": 5
    "*.bugcrowd.com": 3
```

After passive recon, `hunt_one` runs nuclei (`nuclei -l <hosts> -severity ...`)
against the in-scope hosts it pulls from the recon output, and feeds the results
to the LLM as part of the seed context. The host list is filtered to the target's
own domain and run through the scope check first, and passive OSINT services are
excluded, so nuclei never scans an out-of-scope host. nuclei is an active scanner;
set `nuclei.enabled: false` to turn it off. If nuclei is not installed the scan is
skipped with a warning.

`--notify telegram` or `--notify discord` sends a one-line message on every
finding, taken from each finding record `memory.py` writes (a `log_step` with a
`finding`, or a `behavior_change`). The message carries the target, vuln class,
severity, and endpoint. A failed send is swallowed so it never aborts a hunt; an
unconfigured platform prints one warning and is skipped.

```yaml
notify:
  telegram: { bot_token: "", chat_id: "" }
  discord:  { webhook_url: "" }
```

## Tracing, graph, multi-agent (Phase 7)

Every LLM call goes through `agent/_llm.py:chat`, which selects the provider from
`llm.provider` (ollama or gemini) and records the call when a tracer is active.
Gemini runs over REST with stdlib urllib and no SDK; on any Gemini failure the call
falls back to `llm.ollama_model`. The key is read from config or `GEMINI_API_KEY`
and is never logged.

`agent/tracer.py` writes one entry per call to
`sessions/<target>_<ts>_trace.jsonl` (timestamp, agent, model, estimated tokens,
latency, cost from a rate table) and prints a per-agent summary table at the end.
Token counts are `len // 4` estimates; without a provider SDK returning usage there
is no exact count. `--no-trace` or `trace.enabled: false` turns it off.

`agent/graph.py` keeps a networkx DiGraph of the hunt (domains, subdomains, ports,
endpoints, technologies, vulns) saved to `sessions/<target>_<ts>_graph.json`. Writes
take a lock; reads do not. In multi-agent runs the loop updates it on each `NOTE:`
or finding and injects `graph.summary()` into every step. Read a saved graph with
`--graph-summary <file>`.

`--multi-agent` runs `agent/orchestrator.py`: a ReconAgent (passive recon + nuclei,
populates the graph, posts findings to a Queue) and an ExploitAgent (consumes
findings, runs the exploit loop per host) on a 2-thread pool sharing one graph and
SessionLog. The ExploitAgent stops once recon is complete and the queue drains.
Single-agent mode is the default and is unchanged.

## Web dashboard (Phase 8)

`raven --serve [--port 8080]` starts a FastAPI server on localhost, opens the
browser, and does not launch a hunt by itself; the dashboard is the launcher. The
server (`server/`) exposes REST under `/api` (sessions, findings, graph, reports,
config, and hunt start/stop) and a WebSocket at `/ws/hunt/{session_id}` that
streams live thought/action/observation/finding events. It serves the UI from
`web/dist/`.

The shipped UI is a build-free `web/dist/index.html` (React via CDN), so
`raven --serve` works with no build step. The browser hunt is headless: passive
commands auto-run and active commands are auto-declined, because there is no
operator at the server console to approve them. Out-of-scope targets are rejected
by the same scope enforcer. The config endpoint returns only non-secret fields and
never LLM or notify keys.

```
# run the dashboard with the prebuilt UI
raven --serve

# optional: rebuild the UI from the Vite source (React, Tailwind, Zustand, React Flow)
cd web && npm install && npm run build
raven --serve
```

## Native engine (Phase 9)

The scan engine (`agent/tools.py`) is pure Python and needs no external binaries.
Fifteen tools the ReAct loop can call, all returning a plain-text observation:

- Passive (auto-run in `--mode auto`): `subdomain_enum` (crt.sh + HackerTarget +
  DNS brute force), `probe_http`, `check_headers`, `check_info_disclosure`,
  `check_subdomain_takeover`, `check_cors`, `js_analysis`, `tech_fingerprint`.
- Active (asked for in ask mode, auto-run in auto mode): `port_scan`, `check_xss`,
  `check_sqli`, `check_ssrf`, `check_open_redirect`, `check_idor`, `check_ssti`.

The passive/active split is the same auto-mode safety boundary as before, and the
scope enforcer still gates every call. reconftw, nuclei, and any command passed to
`run_command` are used only when that binary is on PATH (checked with
`shutil.which`), as an optional enhancement; otherwise the native tools do the job.
Tunables live under `native_tools` in `config.yaml` (workers, timeouts, brute
force toggle, SSRF `interactsh_url`).

## Config (`config.yaml`)

- `model` / `reconftw_path` (optional) / `max_steps`
- `native_tools`: concurrent_workers, http_timeout, port_scan_timeout,
  brute_force_subdomains, js_analysis, interactsh_url (see Phase 9 above)
- `kb_path`: knowledge-base dir (a relative path resolves to the project root)
- `max_fallback_attempts`: fallbacks tried per failed command
- `auto_note_findings` + `finding_keywords`: keyword auto-noting
- `passive_whitelist`: binaries allowed to auto-run in `--mode auto` (reconftw
  auto-runs only with `-p`; curl is GET-only; httpx rejects fuzzing)
- `scope`: see Scope enforcement above
- `reports_dir` / `default_platform`: report output dir and the `--platform` default
- `resume_skip_duplicates`: on `--resume`, skip commands already run
- `ai_target`: endpoint, method, headers, payload_template, response_path, and
  request_delay for `--ai-mode` (see AI target mode above)
- `rate_limits` / `nuclei` / `notify`: see the Phase 6 section above
- `llm` / `trace`: provider selection and LLM call tracing (see Phase 7 above)

## Safety

Commands run through `shlex.split` as an argv list, never `shell=True`, so shell
chaining with `;`, `&&`, `|`, or backticks is passed as literal text and not
executed. The passive classifier in `agent/tools.py:is_passive` is the auto-mode
boundary: an unknown binary or an active flag always falls through to a prompt.

## Tests

```bash
python test_passive.py   # passive classifier (auto-mode boundary)
python test_phase2.py    # decline-feedback loop, KB injection, fallback, no-shell
python test_phase3.py    # scope enforcer, scope-block in loop, report + formatter
python test_phase4.py    # challenge parse, multi-target, resume, dashboard
python test_phase5.py    # behaviour detector, OWASP checker, chains, AI-target loop
python test_phase6.py    # per-target rate limits, nuclei integration, notify
python test_phase7.py    # tracer, LLM provider switching, graph, orchestrator
python test_phase8.py    # REST API, WebSocket, bridge, --serve flag
```

## Errors it handles

- reconftw not installed: clear message and install link, and the session is still
  logged.
- ollama not running or model missing: clear message with the `ollama serve` and
  `ollama pull` commands to fix it.
