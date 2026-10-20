#!/usr/bin/env python3
"""bb-agent: agentic bug bounty assistant.

Modes:
  recon      python bb_agent.py --target example.com [--mode ask|auto]
  multi      python bb_agent.py --targets targets.txt [--parallel]
  challenge  python bb_agent.py --challenge briefing.txt        (Huntr 2.0)
  resume     python bb_agent.py --resume sessions/<file>.jsonl
  report     python bb_agent.py --report sessions/<file>.jsonl [--platform h1|bugcrowd|huntr]
  scope      python bb_agent.py --scope-check sub.example.com
"""
import os
import sys
import time
from pathlib import Path

import click
import yaml
from rich.console import Console

# Rich emits box-drawing / unicode; force UTF-8 so legacy Windows consoles
# (cp1252) don't crash with UnicodeEncodeError.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

from agent import challenge, multi, resume, tools
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
@click.option("--challenge", "challenge_path", default=None, type=click.Path(),
              help="Huntr challenge mode: parse a briefing file and hunt.")
@click.option("--targets", "targets_path", default=None, type=click.Path(),
              help="Multi-target mode: one domain per line (# comments).")
@click.option("--resume", "resume_path", default=None, type=click.Path(),
              help="Resume a previous session JSONL.")
@click.option("--parallel", is_flag=True, help="With --targets: up to 3 concurrent.")
@click.option("--no-dashboard", is_flag=True, help="Disable the live dashboard in auto mode.")
def main(target, mode, model, config_path, report_path, platform, scope_check,
         challenge_path, targets_path, resume_path, parallel, no_dashboard):
    cfg = yaml.safe_load(Path(config_path).read_text())

    if scope_check:
        return _do_scope_check(cfg, scope_check)
    if report_path:
        return _do_report(cfg, report_path, platform)
    if challenge_path:
        return _do_challenge(cfg, challenge_path, mode, model, no_dashboard)
    if resume_path:
        return _do_resume(cfg, resume_path, mode, model, no_dashboard)
    if targets_path:
        return _do_targets(cfg, targets_path, mode, model, parallel, no_dashboard)
    if not target:
        raise click.UsageError(
            "need one of --target, --targets, --challenge, --resume, --report, --scope-check")
    _do_recon(cfg, target, mode, model, no_dashboard)


# --- helpers ----------------------------------------------------------------

def _model(cfg, model):
    return model or cfg.get("model", "llama3.1")


def _make_dash(cfg, target, mode, no_dashboard):
    if mode != "auto" or no_dashboard:
        return None
    from ui.dashboard import make_dashboard  # lazy
    return make_dashboard(target, mode, True, console)


def _count_findings(log):
    return len(log.notes.items["Potential Vulns"])


def hunt_one(cfg, target, mode, model, no_dashboard=False, verbose=True):
    """Run the full hunt for one target. Returns a summary dict for multi-target."""
    t0 = time.time()

    def summary(findings, status, log):
        return {"target": target, "findings": findings, "duration": time.time() - t0,
                "status": status, "session": str(log.path) if log else None}

    if not ScopeEnforcer(cfg.get("scope", {})).check(target).allowed:
        if verbose:
            console.print(f"[red]out of scope, skipping:[/] {target}")
        return summary(0, "out_of_scope", None)

    log = SessionLog(target)
    if verbose:
        console.print(f"[bold]hunt[/] [cyan]{target}[/] ({mode}) -> [dim]{log.path}[/]")

    reconftw = os.path.expanduser(cfg["reconftw_path"])
    if not os.path.isfile(reconftw):
        if verbose:
            console.print(f"[red]reconftw not found at {reconftw}[/] — "
                          "install: https://github.com/six2dez/reconftw")
        log.log("error", error=f"reconftw not found at {reconftw}")
        return summary(0, "no_reconftw", log)

    if verbose:
        console.print("[bold]Running passive recon (reconftw -p)...[/]")
    recon, ok = tools.run_reconftw(reconftw, f"-d {target} -p")
    log.log("recon_seed", target=target, status="success" if ok else "failed", output=recon)

    dash = _make_dash(cfg, target, mode, no_dashboard)
    status = "done"
    try:
        run(target, recon, _model(cfg, model), mode, cfg, log, dashboard=dash)
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        log.log("error", error=str(e))
        status = "llm_error"
    return summary(_count_findings(log), status, log)


# --- mode handlers ----------------------------------------------------------

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


def _do_recon(cfg, target, mode, model, no_dashboard):
    res = hunt_one(cfg, target, mode, model, no_dashboard)
    if res["status"] in ("out_of_scope", "no_reconftw", "llm_error"):
        raise SystemExit(1)
    console.print(f"[green]done[/] — {res['findings']} potential finding(s). "
                  f"Report with: python bb_agent.py --report {res['session']}")


def _do_targets(cfg, targets_path, mode, model, parallel, no_dashboard):
    targets = multi.load_targets(targets_path)
    if not targets:
        console.print(f"[red]no targets in {targets_path}[/]")
        raise SystemExit(1)
    nd = no_dashboard or parallel  # parallel Live panes would collide
    if parallel:
        console.print("[yellow]--parallel: dashboard off; ask-mode prompts may interleave.[/]")
    results = multi.run_all(targets, lambda t: hunt_one(cfg, t, mode, _model(cfg, model),
                                                        no_dashboard=nd, verbose=True),
                            parallel=parallel)
    multi.render_table(results, console)
    console.print(f"[green]summary saved:[/] {multi.save_summary(results, cfg)}")


def _do_challenge(cfg, challenge_path, mode, model, no_dashboard):
    text = Path(challenge_path).read_text(encoding="utf-8")
    parsed = challenge.parse_briefing(text)
    cfg = challenge.configure(cfg, parsed)
    console.print(f"[bold]Huntr challenge[/] id=[cyan]{parsed['challenge_id']}[/] "
                  f"target=[cyan]{parsed['target_host'] or parsed['url']}[/]")
    console.print(f"tools: {', '.join(parsed['tools']) or '(none parsed)'}")
    console.print(f"objective: {parsed['objective']}")

    log = SessionLog(f"huntr_{parsed['challenge_id']}")
    console.print(f"Session log: [dim]{log.path}[/]")
    target = parsed["target_host"] or parsed["url"] or f"huntr_{parsed['challenge_id']}"
    dash = _make_dash(cfg, target, mode, no_dashboard)
    try:
        run(target, f"Challenge briefing:\n{text}", _model(cfg, model), mode, cfg, log,
            extra_system=challenge.system_injection(parsed), dashboard=dash)
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        log.log("error", error=str(e))
        raise SystemExit(1)

    m = builder.build(log.path, cfg)
    out = formatter.format_report(m, "huntr", cfg)
    console.print(f"[green]Report:[/] {m['report_path']}")
    console.print(f"[green]Huntr draft:[/] {out}")


def _do_resume(cfg, resume_path, mode, model, no_dashboard):
    if not Path(resume_path).is_file():
        console.print(f"[red]session file not found: {resume_path}[/]")
        raise SystemExit(1)
    st = resume.load(resume_path)
    log = SessionLog(st["target"], path=resume_path)  # append to the same session
    console.print(f"[bold]Resuming[/] [cyan]{st['target']}[/] from step "
                  f"{st['last_step'] + 1} ({len(st['tried'])} commands already tried)")
    skip = st["tried"] if cfg.get("resume_skip_duplicates", True) else None
    dash = _make_dash(cfg, st["target"], mode, no_dashboard)
    # No startup scope re-check: the target was approved in the original session.
    try:
        run(st["target"], st["summary"], _model(cfg, model), mode, cfg, log,
            start_step=st["last_step"] + 1, skip_commands=skip, dashboard=dash)
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        log.log("error", error=str(e))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
