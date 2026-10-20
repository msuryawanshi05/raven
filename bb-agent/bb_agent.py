#!/usr/bin/env python3
"""bb-agent: agentic bug bounty assistant.

Runs reconftw passive recon, then an LLM ReAct loop reasons over the output,
consults per-vuln technique guides, and proposes next steps under human approval
with automatic fallback when a tool fails.
"""
import os
from pathlib import Path

import click
import yaml
from rich.console import Console

from agent import tools
from agent.loop import run
from agent.memory import SessionLog

console = Console()
CONFIG_DEFAULT = Path(__file__).resolve().parent / "config.yaml"


@click.command()
@click.option("--target", required=True, help="Target domain, e.g. example.com")
@click.option("--mode", type=click.Choice(["ask", "auto"]), default="ask",
              help="ask: confirm every command. auto: auto-run passive, ask for the rest.")
@click.option("--model", default=None, help="ollama model (overrides config.yaml)")
@click.option("--config", "config_path", default=str(CONFIG_DEFAULT),
              type=click.Path(), help="Path to config.yaml")
def main(target, mode, model, config_path):
    cfg = yaml.safe_load(Path(config_path).read_text())
    model = model or cfg.get("model", "llama3.1")

    # Open the session log first so even a failed run leaves a record.
    log = SessionLog(target)
    console.print(f"[bold]bb-agent[/] target=[cyan]{target}[/] mode=[cyan]{mode}[/] "
                  f"model=[cyan]{model}[/]")
    console.print(f"Session log: [dim]{log.path}[/]")
    console.print(f"Notes:       [dim]{log.notes.path}[/]")

    reconftw = os.path.expanduser(cfg["reconftw_path"])
    if not os.path.isfile(reconftw):
        console.print(f"[red]reconftw not found at {reconftw}[/]")
        console.print("Install it: [cyan]https://github.com/six2dez/reconftw[/] "
                      "then set reconftw_path in config.yaml")
        log.log("error", error=f"reconftw not found at {reconftw}")
        raise SystemExit(1)

    console.print("[bold]Running passive recon (reconftw -p)...[/]")
    recon, ok = tools.run_reconftw(reconftw, f"-d {target} -p")
    log.log("recon_seed", target=target, status="success" if ok else "failed",
            output=recon)

    try:
        run(target, recon, model, mode, cfg, log)
    except RuntimeError as e:  # ollama not running / model missing
        console.print(f"[red]{e}[/]")
        log.log("error", error=str(e))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
