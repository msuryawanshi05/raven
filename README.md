# RAVEN

Agentic bug bounty assistant. It wraps [reconftw](https://github.com/six2dez/reconftw)
passive recon with a local-LLM ReAct loop that reads the recon output, consults
per-vuln technique guides, and proposes the next command. Every command is gated
by human approval, and a failed tool falls back to alternatives automatically.

> For authorized testing only. Stay in scope. Follow responsible disclosure.

## Setup

```bash
pip install -r requirements.txt

# reconftw (recon engine), install on a Linux recon box:
#   https://github.com/six2dez/reconftw
# then set reconftw_path in config.yaml (default: ~/reconftw/reconftw.sh)

# ollama (local LLM runtime):
ollama serve            # start the daemon
ollama pull llama3.1    # pull the default model
```

## Usage

```bash
# ask mode: confirm every proposed command (default)
python bb_agent.py --target example.com --mode ask

# auto mode: passive commands run automatically, everything else still asks
python bb_agent.py --target example.com --mode auto

# different model
python bb_agent.py --target example.com --model qwen2.5

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
```

Each recon run:
1. Scope check on `--target` (hard block and exit if out of scope).
2. Runs `reconftw -d <target> -p` (passive) to seed the context.
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

## Config (`config.yaml`)

- `model` / `reconftw_path` / `max_steps`
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
```

## Errors it handles

- reconftw not installed: clear message and install link, and the session is still
  logged.
- ollama not running or model missing: clear message with the `ollama serve` and
  `ollama pull` commands to fix it.
