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
import re
import sys
import tempfile
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

from agent import ai_target, challenge, multi, notify as notify_mod, resume, tools
from agent.graph import HuntGraph
from agent.injection_chains import InjectionChainBuilder
from agent.loop import run
from agent.memory import SessionLog
from agent.orchestrator import Orchestrator
from agent.scope import PASSIVE_SERVICES, ScopeEnforcer, host_of
from agent.tracer import LLMTracer
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
@click.option("--ai-mode", "ai_mode", is_flag=True, help="Attack an LLM target over HTTP (no recon).")
@click.option("--owasp-only", "owasp_only", is_flag=True, help="AI mode: run only the OWASP LLM Top 10 checklist.")
@click.option("--chain", "chain", default=None,
              help="AI mode: run one injection chain (rag_poison|tool_response|memory_persistence).")
@click.option("--baseline-only", "baseline_only", is_flag=True, help="AI mode: record baseline behaviour only.")
@click.option("--notify", "notify", type=click.Choice(["telegram", "discord"]), default=None,
              help="Send a message on each finding (needs notify.<platform> in config).")
@click.option("--multi-agent", "multi_agent", is_flag=True,
              help="Run ReconAgent + ExploitAgent in parallel instead of one loop.")
@click.option("--no-trace", "no_trace", is_flag=True, help="Disable the LLM call tracer.")
@click.option("--graph-summary", "graph_summary", default=None, type=click.Path(),
              help="Print the hunt-graph summary for a past session's _graph.json.")
@click.option("--serve", "serve", is_flag=True, help="Start the web dashboard instead of a hunt.")
@click.option("--port", "port", default=8080, type=int, help="Port for --serve (default 8080).")
def main(target, mode, model, config_path, report_path, platform, scope_check,
         challenge_path, targets_path, resume_path, parallel, no_dashboard,
         ai_mode, owasp_only, chain, baseline_only, notify,
         multi_agent, no_trace, graph_summary, serve, port):
    cfg = yaml.safe_load(Path(config_path).read_text())

    if serve:
        return _do_serve(port)
    if graph_summary:
        return _do_graph_summary(graph_summary)
    if scope_check:
        return _do_scope_check(cfg, scope_check)
    if report_path:
        return _do_report(cfg, report_path, platform)
    if challenge_path:
        return _do_challenge(cfg, challenge_path, mode, model, no_dashboard, notify, no_trace)
    if resume_path:
        return _do_resume(cfg, resume_path, mode, model, no_dashboard, notify, no_trace)
    if targets_path:
        return _do_targets(cfg, targets_path, mode, model, parallel, no_dashboard, notify, no_trace)
    if ai_mode or owasp_only or chain or baseline_only:
        if not target:
            raise click.UsageError("AI mode needs --target <llm-url>")
        return _do_ai_target(cfg, target, mode, model, no_dashboard,
                             owasp_only, baseline_only, chain, notify, no_trace)
    if multi_agent:
        if not target:
            raise click.UsageError("--multi-agent needs --target")
        return _do_multi_agent(cfg, target, mode, model, no_dashboard, notify, no_trace)
    if not target:
        raise click.UsageError(
            "need one of --target, --targets, --challenge, --resume, --report, --scope-check")
    _do_recon(cfg, target, mode, model, no_dashboard, notify, no_trace)


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


def _tracer(cfg, log, no_trace):
    tconf = cfg.get("trace") or {}
    if no_trace or not tconf.get("enabled", True):
        return None
    return LLMTracer(log.path.with_name(log.path.stem + "_trace.jsonl"))


def _trace_done(tracer, cfg):
    if tracer and tracer.entries and (cfg.get("trace") or {}).get("show_summary", True):
        console.print(tracer.summary_table())


def _attach_notify(log, cfg, platform, target):
    if not platform:
        return
    fn = notify_mod.build_notifier(cfg, platform, target)
    if fn:
        log.notifier = fn
    else:
        console.print(f"[yellow]--notify {platform}: not configured in config.yaml; skipping.[/]")


def _nuclei_hosts(recon, target, cfg):
    """In-scope hosts under the target's domain, pulled from the recon output."""
    base = host_of(target)
    found = set(re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b",
                           (recon or "").lower()))
    found = {h for h in found if h == base or h.endswith("." + base)}
    found.add(base)
    enforcer = ScopeEnforcer(cfg.get("scope", {}))
    return sorted(h for h in found
                  if h not in PASSIVE_SERVICES and enforcer.check(h).allowed)


def _nuclei_scan(cfg, target, recon, log, verbose):
    """Auto active-scan after passive recon. Scope-filtered; skipped if nuclei
    is absent. Returns output text (fed to the LLM) or ''."""
    nconf = cfg.get("nuclei") or {}
    if not nconf.get("enabled", True):
        return ""
    hosts = _nuclei_hosts(recon, target, cfg)
    if not hosts:
        return ""
    fd, path = tempfile.mkstemp(prefix="raven_nuclei_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(hosts))
    try:
        if verbose:
            console.print(f"[bold]nuclei[/] scanning {len(hosts)} in-scope host(s)...")
        out, ok = tools.run_nuclei(path, nconf.get("severity", "medium,high,critical"))
    finally:
        os.unlink(path)
    if not ok and "command not found" in out:
        console.print("[yellow]nuclei not installed; skipping active scan.[/]")
        log.log("nuclei", status="skipped", reason="not installed")
        return ""
    log.log("nuclei", status="done" if ok else "error", hosts=len(hosts), output=out[:500])
    return out


def hunt_one(cfg, target, mode, model, no_dashboard=False, verbose=True, notify=None, no_trace=False):
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
    _attach_notify(log, cfg, notify, target)
    if verbose:
        console.print(f"[bold]hunt[/] [cyan]{target}[/] ({mode}) -> [dim]{log.path}[/]")

    reconftw = os.path.expanduser(cfg["reconftw_path"])
    if not os.path.isfile(reconftw):
        if verbose:
            console.print(f"[red]reconftw not found at {reconftw}[/] - "
                          "install: https://github.com/six2dez/reconftw")
        log.log("error", error=f"reconftw not found at {reconftw}")
        return summary(0, "no_reconftw", log)

    if verbose:
        console.print("[bold]Running passive recon (reconftw -p)...[/]")
    recon, ok = tools.run_reconftw(reconftw, f"-d {target} -p")
    log.log("recon_seed", target=target, status="success" if ok else "failed", output=recon)

    nuclei_out = _nuclei_scan(cfg, target, recon, log, verbose)
    seed = recon + (f"\n\n[nuclei results]\n{nuclei_out}" if nuclei_out else "")

    dash = _make_dash(cfg, target, mode, no_dashboard)
    tracer = _tracer(cfg, log, no_trace)
    status = "done"
    try:
        run(target, seed, _model(cfg, model), mode, cfg, log, dashboard=dash, tracer=tracer)
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        log.log("error", error=str(e))
        status = "llm_error"
    _trace_done(tracer, cfg)
    return summary(_count_findings(log), status, log)


# --- mode handlers ----------------------------------------------------------

def _do_scope_check(cfg, domain):
    sr = ScopeEnforcer(cfg.get("scope", {})).check(domain)
    tag = "[green]IN SCOPE[/]" if sr.allowed else "[red]OUT OF SCOPE[/]"
    console.print(f"{tag}: {domain} - {sr.reason}")
    raise SystemExit(0 if sr.allowed else 1)


def _do_report(cfg, report_path, platform):
    if not Path(report_path).is_file():
        console.print(f"[red]session file not found: {report_path}[/]")
        raise SystemExit(1)
    model = builder.build(report_path, cfg)
    console.print(f"[green]Report written:[/] {model['report_path']}")
    if not model["notes_found"]:
        console.print("[yellow]note: notes.md not found - built from JSONL only.[/]")
    if platform:
        name = cfg.get("default_platform", "hackerone") if platform == "__default__" else platform
        name = _PLATFORM_ALIAS.get(name.lower(), name.lower())
        try:
            out = formatter.format_report(model, name, cfg)
        except ValueError as e:
            console.print(f"[red]{e}[/]")
            raise SystemExit(1)
        console.print(f"[green]{name} draft written:[/] {out}")


def _do_recon(cfg, target, mode, model, no_dashboard, notify=None, no_trace=False):
    res = hunt_one(cfg, target, mode, model, no_dashboard, notify=notify, no_trace=no_trace)
    if res["status"] in ("out_of_scope", "no_reconftw", "llm_error"):
        raise SystemExit(1)
    console.print(f"[green]done[/] - {res['findings']} potential finding(s). "
                  f"Report with: python bb_agent.py --report {res['session']}")


def _do_targets(cfg, targets_path, mode, model, parallel, no_dashboard, notify=None, no_trace=False):
    targets = multi.load_targets(targets_path)
    if not targets:
        console.print(f"[red]no targets in {targets_path}[/]")
        raise SystemExit(1)
    nd = no_dashboard or parallel  # parallel Live panes would collide
    if parallel:
        console.print("[yellow]--parallel: dashboard off; ask-mode prompts may interleave.[/]")
    results = multi.run_all(targets, lambda t: hunt_one(cfg, t, mode, _model(cfg, model),
                                                        no_dashboard=nd, verbose=True,
                                                        notify=notify, no_trace=no_trace),
                            parallel=parallel)
    multi.render_table(results, console)
    console.print(f"[green]summary saved:[/] {multi.save_summary(results, cfg)}")


def _do_challenge(cfg, challenge_path, mode, model, no_dashboard, notify=None, no_trace=False):
    text = Path(challenge_path).read_text(encoding="utf-8")
    parsed = challenge.parse_briefing(text)
    cfg = challenge.configure(cfg, parsed)
    console.print(f"[bold]Huntr challenge[/] id=[cyan]{parsed['challenge_id']}[/] "
                  f"target=[cyan]{parsed['target_host'] or parsed['url']}[/]")
    console.print(f"tools: {', '.join(parsed['tools']) or '(none parsed)'}")
    console.print(f"objective: {parsed['objective']}")

    log = SessionLog(f"huntr_{parsed['challenge_id']}")
    target = parsed["target_host"] or parsed["url"] or f"huntr_{parsed['challenge_id']}"
    _attach_notify(log, cfg, notify, target)
    console.print(f"Session log: [dim]{log.path}[/]")
    dash = _make_dash(cfg, target, mode, no_dashboard)
    tracer = _tracer(cfg, log, no_trace)
    try:
        run(target, f"Challenge briefing:\n{text}", _model(cfg, model), mode, cfg, log,
            extra_system=challenge.system_injection(parsed), dashboard=dash, tracer=tracer)
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        log.log("error", error=str(e))
        raise SystemExit(1)
    _trace_done(tracer, cfg)

    m = builder.build(log.path, cfg)
    out = formatter.format_report(m, "huntr", cfg)
    console.print(f"[green]Report:[/] {m['report_path']}")
    console.print(f"[green]Huntr draft:[/] {out}")


def _do_ai_target(cfg, target, mode, model, no_dashboard, owasp_only, baseline_only, chain, notify=None, no_trace=False):
    if chain and chain not in InjectionChainBuilder.types():
        console.print(f"[red]unknown chain '{chain}'[/]; choose from "
                      f"{', '.join(InjectionChainBuilder.types())}")
        raise SystemExit(1)

    sr = ScopeEnforcer(cfg.get("scope", {})).check(target)
    if not sr.allowed:
        console.print(f"[red bold]Target out of scope:[/] {target} - {sr.reason}")
        raise SystemExit(1)

    log = SessionLog(host_of(target) or "ai_target")
    _attach_notify(log, cfg, notify, target)
    console.print(f"[bold]bb-agent AI mode[/] target=[cyan]{target}[/] mode=[cyan]{mode}[/]")
    console.print(f"Session log: [dim]{log.path}[/]")
    if not (cfg.get("ai_target") or {}).get("endpoint") and "{{PAYLOAD}}" not in \
            (cfg.get("ai_target") or {}).get("payload_template", "{{PAYLOAD}}"):
        console.print("[yellow]warning: ai_target.payload_template has no {{PAYLOAD}} marker.[/]")

    dash = _make_dash(cfg, target, mode, no_dashboard)
    tracer = _tracer(cfg, log, no_trace)
    try:
        ai_target.run(target, _model(cfg, model), cfg, log, mode=mode,
                      owasp_only=owasp_only, baseline_only=baseline_only,
                      chain=chain, dashboard=dash, tracer=tracer)
    except RuntimeError as e:  # raven LLM unavailable (full ai-mode crafting)
        console.print(f"[red]{e}[/]")
        log.log("error", error=str(e))
        raise SystemExit(1)
    _trace_done(tracer, cfg)
    console.print(f"[green]AI session done.[/] Report with: "
                  f"python bb_agent.py --report {log.path}")


def _do_resume(cfg, resume_path, mode, model, no_dashboard, notify=None, no_trace=False):
    if not Path(resume_path).is_file():
        console.print(f"[red]session file not found: {resume_path}[/]")
        raise SystemExit(1)
    st = resume.load(resume_path)
    log = SessionLog(st["target"], path=resume_path)  # append to the same session
    _attach_notify(log, cfg, notify, st["target"])
    console.print(f"[bold]Resuming[/] [cyan]{st['target']}[/] from step "
                  f"{st['last_step'] + 1} ({len(st['tried'])} commands already tried)")
    skip = st["tried"] if cfg.get("resume_skip_duplicates", True) else None
    dash = _make_dash(cfg, st["target"], mode, no_dashboard)
    tracer = _tracer(cfg, log, no_trace)
    # No startup scope re-check: the target was approved in the original session.
    try:
        run(st["target"], st["summary"], _model(cfg, model), mode, cfg, log,
            start_step=st["last_step"] + 1, skip_commands=skip, dashboard=dash, tracer=tracer)
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        log.log("error", error=str(e))
        raise SystemExit(1)
    _trace_done(tracer, cfg)


def _do_multi_agent(cfg, target, mode, model, no_dashboard, notify=None, no_trace=False):
    sr = ScopeEnforcer(cfg.get("scope", {})).check(target)
    if not sr.allowed:
        console.print(f"[red bold]Target out of scope:[/] {target} - {sr.reason}")
        raise SystemExit(1)
    log = SessionLog(target)
    _attach_notify(log, cfg, notify, target)
    tracer = _tracer(cfg, log, no_trace)
    graph = HuntGraph(log.path.with_name(log.path.stem + "_graph.json"))
    console.print(f"[bold]multi-agent[/] target=[cyan]{target}[/] -> [dim]{log.path}[/]")
    Orchestrator(target, cfg, log, graph, _model(cfg, model), mode=mode, tracer=tracer).run()
    _trace_done(tracer, cfg)
    try:
        m = builder.build(log.path, cfg)
        console.print(f"[green]Report:[/] {m['report_path']}")
    except Exception as e:
        console.print(f"[yellow]report skipped: {e}[/]")


def _do_graph_summary(graph_path):
    if not Path(graph_path).is_file():
        console.print(f"[red]graph file not found: {graph_path}[/]")
        raise SystemExit(1)
    console.print(HuntGraph.load(graph_path).summary())


def _do_serve(port):
    import webbrowser
    import uvicorn
    url = f"http://localhost:{port}"
    console.print(f"raven dashboard running at {url}")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    uvicorn.run("server.main:app", host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
