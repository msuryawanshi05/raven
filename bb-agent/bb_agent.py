#!/usr/bin/env python3
"""bb-agent: agentic bug bounty assistant.

Modes:
  recon   python bb_agent.py --target example.com [--mode ask|auto]
  report  python bb_agent.py --report sessions/<file>.jsonl [--platform h1|bugcrowd|huntr]
  scope   python bb_agent.py --scope-check sub.example.com
"""
import os
from pathlib import Path

import click
import yaml
from rich.console import Console

from agent import tools
from agent.loop import run
from agent.memory import SessionLog
from agent.scope import ScopeEnforcer
from reporter import builder, formatter

console = Console()
CONFIG_DEFAULT = Path(__file__).resolve().parent / "config.yaml"
_PLATFORM_ALIAS = {"h1": "hackerone"}


@click.command()
@click.option("--target", default=None, help="Target domain, e.g. example.com")
@click.option("--mode", type=click.Choice(["ask", "auto"]), default="ask",
              help="ask: confirm every command. auto: auto-run passive, ask for the rest.")
@click.option("--model", default=None, help="ollama model (overrides config.yaml)")
@click.option("--config", "config_path", default=str(CONFIG_DEFAULT),
              type=click.Path(), help="Path to config.yaml")
@click.option("--report", "report_path", default=None, type=click.Path(),
              help="Build a report from a session JSONL (no live recon).")
@click.option("--platform", is_flag=False, flag_value="__default__", default=None,
              help="With --report: also build a platform draft (hackerone|bugcrowd|huntr).")
@click.option("--scope-check", "scope_check", default=None,
              help="Print whether a domain is in scope per config, then exit.")
def main(target, mode, model, config_path, report_path, platform, scope_check):
    cfg = yaml.safe_load(Path(config_path).read_text())

    if scope_check:
        _do_scope_check(cfg, scope_check)
        return
    if report_path:
        _do_report(cfg, report_path, platform)
        return

    if not target:
        raise click.UsageError("one of --target, --report, or --scope-check is required")
    _do_recon(cfg, target, mode, model)


def _do_scope_check(cfg, domain):
    sr = ScopeEnforcer(cfg.get("scope", {})).check(domain)
    tag = "[green]IN SCOPE[/]" if sr.allowed else "[red]OUT OF SCOPE[/]"
    console.print(f"{tag}: {domain} — {sr.reason}")
    raise SystemExit(0 if sr.allowed else 1)


def _do_report(cfg, report_path, platform):
    if not Path(report_path).is_file():
        console.print(f"[red]session file not found: {report_path}[/]")
        raise SystemExit(1)
    model = builder.build(report_path, cfg)
    console.print(f"[green]Report written:[/] {model['report_path']}")
    if not model["notes_found"]:
        console.print("[yellow]note: notes.md not found — built from JSONL only.[/]")
    if platform:
        name = cfg.get("default_platform", "hackerone") if platform == "__default__" else platform
        name = _PLATFORM_ALIAS.get(name.lower(), name.lower())
        try:
            out = formatter.format_report(model, name, cfg)
        except ValueError as e:
            console.print(f"[red]{e}[/]")
            raise SystemExit(1)
        console.print(f"[green]{name} draft written:[/] {out}")


def _do_recon(cfg, target, mode, model):
    model = model or cfg.get("model", "llama3.1")

    sr = ScopeEnforcer(cfg.get("scope", {})).check(target)
    if not sr.allowed:
        console.print(f"[red bold]Target out of scope:[/] {target} — {sr.reason}")
        console.print("Adjust the [cyan]scope[/] block in config.yaml if this is wrong.")
        raise SystemExit(1)

    log = SessionLog(target)  # open first so even a failed run leaves a record
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
