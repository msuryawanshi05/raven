# bb-agent

Agentic bug bounty assistant (Phase 1). Wraps [reconftw](https://github.com/six2dez/reconftw)
passive recon with a local-LLM ReAct loop that reasons over the output and proposes
next steps — every command gated by human approval.

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
1. Runs `reconftw -d <target> -p` (passive).
2. Feeds the output to the LLM, which replies `THOUGHT / ACTION / ACTION_INPUT`.
3. In `--mode ask` every action waits for `y/n`. In `--mode auto` only
   whitelisted passive commands auto-run; active/unknown ones still ask.
4. Observation is fed back; loop repeats until `FINAL_ANSWER` or `max_steps`.

Everything (reasoning, commands, output) is logged to `sessions/<target>_<ts>.jsonl`.

## Config (`config.yaml`)

- `model` — default ollama model
- `reconftw_path` — path to `reconftw.sh`
- `max_steps` — loop cap
- `passive_whitelist` — binaries allowed to auto-run in `--mode auto`
  (reconftw auto-runs only in `-p` passive mode; curl GET-only; httpx no fuzzing —
  enforced in `agent/tools.py`)

## Test

```bash
python -m pytest test_passive.py   # or: python test_passive.py
```

## Errors it handles

- reconftw not installed → clear message + install link
- ollama not running / model missing → clear message + `ollama serve` / `ollama pull`
