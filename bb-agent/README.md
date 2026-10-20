# bb-agent

Agentic bug bounty assistant. Wraps [reconftw](https://github.com/six2dez/reconftw)
passive recon with a local-LLM ReAct loop that reasons over the output, consults
per-vuln technique guides, and proposes next steps — every command gated by human
approval, with automatic fallback when a tool fails.

> For authorized testing only. Stay in scope. Follow responsible disclosure.

## Setup

```bash
pip install -r requirements.txt

# reconftw (recon engine) — install on a Linux recon box:
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
```

Each run:
1. Runs `reconftw -d <target> -p` (passive) to seed the context.
2. The LLM replies `THOUGHT / ACTION / ACTION_INPUT` (one command per step).
3. Approval gate: in `--mode ask` every action waits for `y/n`; in `--mode auto`
   only whitelisted passive commands auto-run, active/unknown ones still ask.
4. If the command fails, the **failure router** walks a fallback chain (each
   fallback re-checked against the same approval gate).
5. Before testing a vuln class, the LLM emits `VULN_CLASS: <class>` and is handed
   the matching `kb/<class>.md` technique guide to follow.
6. Observation is fed back; loop repeats until `FINAL_ANSWER` or `max_steps`.

## Output

- `sessions/<target>_<ts>.jsonl` — one record per step:
  `timestamp, step, thought, action, command, status, fallback_used,
  output_summary, finding, kb_consulted`.
- `sessions/<target>_<ts>_notes.md` — human-readable, auto-filled sections:
  Subdomains Found / Open Ports / Potential Vulns / Dead Ends. Findings are added
  when the LLM emits `NOTE: <section> | <text>` or when a `finding_keywords` string
  appears in output.

## Knowledge base (`kb/`)

One markdown guide per vuln class (xss, sqli, ssrf, idor, open_redirect, cors,
subdomain_takeover, lfi, ssti), each with tool order, indicators, fallbacks,
what to note, scope limits, and a submission checklist. `_template.md` is the
format — drop in a new `kb/<name>.md` and it becomes available automatically.

## Config (`config.yaml`)

- `model` / `reconftw_path` / `max_steps`
- `kb_path` — knowledge-base dir (relative paths resolve to the project root)
- `max_fallback_attempts` — fallbacks tried per failed command
- `auto_note_findings` + `finding_keywords` — keyword auto-noting
- `passive_whitelist` — binaries allowed to auto-run in `--mode auto`
  (reconftw auto-runs only with `-p`; curl GET-only; httpx no fuzzing)

## Safety

- Commands run via `shlex.split` (argv list), **never** `shell=True` — shell
  chaining (`;`, `&&`, `|`, backticks) is passed as literal text, not executed.
- The passive classifier (`agent/tools.py:is_passive`) is the auto-mode boundary;
  unknown binaries and active flags always fall through to a prompt.

## Tests

```bash
python test_passive.py   # passive classifier (auto-mode boundary)
python test_phase2.py    # decline-feedback loop, KB injection, fallback, no-shell
```

## Errors it handles

- reconftw not installed → clear message + install link (session still logged)
- ollama not running / model missing → clear message + `ollama serve` / `ollama pull`
