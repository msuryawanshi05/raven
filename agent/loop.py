"""ReAct loop: reason over recon, consult the KB, act with human approval.

Output goes through a `view` object so the same loop drives either plain Rich
panels (default / ask mode) or the live dashboard (auto mode). Phase 4 added the
optional kwargs on run(): extra_system, seed_context, start_step, skip_commands,
dashboard - all default to the Phase 1-3 behaviour.
"""
import re

from rich.console import Console
from rich.panel import Panel

from . import _llm, kb_loader, tools
from .scope import ScopeEnforcer, ScopeViolation, command_target as scope_command_target
from .prompts import system_prompt, initial_user_prompt

try:  # live web streaming; a no-op in CLI-only mode
    from server.bridge import put_message
except Exception:
    def put_message(*_a, **_k):
        return None


def _now_iso():
    from datetime import datetime
    return datetime.now().isoformat(timespec="seconds")

console = Console()


class PlainView:
    """Default output: Rich panels straight to the console (ask-mode behaviour)."""
    def __init__(self, console):
        self.console = console

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def panel(self, body, title, style):
        self.console.print(Panel(body, title=title, border_style=style))

    def line(self, text):
        self.console.print(text)

    def update(self, **state):
        pass


def _parse(text: str) -> dict:
    def grab(label):
        m = re.search(rf"{label}:\s*(.+?)(?=\n[A-Z_]+:|\Z)", text, re.S)
        return m.group(1).strip() if m else None

    notes = re.findall(r"NOTE:\s*([^|\n]+?)\s*\|\s*(.+)", text)
    return {
        "thought": grab("THOUGHT"),
        "action": grab("ACTION"),
        "action_input": grab("ACTION_INPUT"),
        "final": grab("FINAL_ANSWER"),
        "vuln_class": grab("VULN_CLASS"),
        "notes": notes,
    }


def _graph_note(graph, target, section, text):
    s = section.strip().lower()
    if s.startswith("sub"):
        graph.add_subdomain(target, text.split()[0] if text.split() else text)
    elif s.startswith("vuln"):
        graph.add_finding(target, text, "medium")


def _finding_hit(output, cfg):
    if not cfg.get("auto_note_findings", True):
        return None
    low = (output or "").lower()
    for kw in cfg.get("finding_keywords", []):
        if kw.lower() in low:
            return kw
    return None


def _approver(mode, whitelist, view, headless=False):
    """Return approve(cmd)->bool for fallback commands, honouring mode + passive gate."""
    def approve(cmd):
        if mode == "auto" and tools.is_passive("run_command", cmd, whitelist):
            view.line("[green]auto: passive fallback, executing.[/]")
            return True
        if headless:  # no console (web): never run active commands unattended
            return False
        prompt = "active/non-whitelisted" if mode == "auto" else "ask mode"
        return console.input(
            f"[bold yellow]Run fallback? ({prompt}) [y/N] [/]"
        ).strip().lower().startswith("y")
    return approve


def _observation(result):
    r = result
    if r["status"] == "success":
        return r["output"]
    if r["status"] == "fallback_used":
        head = f"`{r['command']}` failed; fallback `{r['fallback_used']}` succeeded."
    else:
        tried = [a["command"] for a in r["attempts"][1:] if "output" in a]
        head = (f"`{r['command']}` failed"
                + (f", tried {', '.join(tried)}, all failed." if tried else ", no runnable fallback."))
    manual = ("\nManual options: " + "; ".join(r["manual"])) if r["manual"] else ""
    return f"{head}{manual}\nRaw output:\n{r['output']}"


def run(target, recon_summary, model, mode, config, log,
        extra_system="", seed_context="", start_step=1,
        skip_commands=None, dashboard=None, tracer=None, graph=None, agent_name="main",
        session_id=None, headless=False, stop_event=None):
    classes = kb_loader.available(config)
    sys_prompt = system_prompt(classes) + (f"\n\n{extra_system}" if extra_system else "")
    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user", "content": initial_user_prompt(target, recon_summary)},
    ]
    if seed_context:
        messages.append({"role": "user", "content": seed_context})

    whitelist = config.get("passive_whitelist", [])
    max_steps = config.get("max_steps", 15)
    view = dashboard if dashboard is not None else PlainView(console)
    approve_fb = _approver(mode, whitelist, view, headless)
    enforcer = ScopeEnforcer(config.get("scope", {}))
    consulted = set()
    skip = set(skip_commands or [])

    def stats():
        n = log.notes.items
        view.update(subdomains=len(n["Subdomains Found"]), ports=len(n["Open Ports"]),
                    findings=len(n["Potential Vulns"]))

    with view:
        for i in range(max_steps):
            if stop_event is not None and stop_event.is_set():
                put_message(session_id, {"type": "done", "content": "stopped", "timestamp": _now_iso()})
                return
            step = start_step + i
            view.update(step=step)
            # Graph memory (multi-agent): inject the live graph each step.
            call_msgs = messages + ([{"role": "user", "content": graph.summary()}] if graph else [])
            reply = _llm.chat(call_msgs, model, agent_name, config, tracer)
            messages.append({"role": "assistant", "content": reply})
            parsed = _parse(reply)

            if parsed["thought"]:
                view.panel(parsed["thought"], f"THOUGHT (step {step})", "cyan")
                view.update(thought=parsed["thought"])
                put_message(session_id, {"type": "thought", "content": parsed["thought"],
                                         "timestamp": _now_iso()})

            for section, text in parsed["notes"]:
                log.notes.add(section, text)
                if graph:
                    _graph_note(graph, target, section, text)
                view.line(f"[dim]noted ({section.strip()}): {text}[/]")
            stats()

            if parsed["final"]:
                view.panel(parsed["final"], "FINAL ANSWER", "green")
                log.log("final", step=step, text=parsed["final"])
                return

            # Consult the technique guide before testing a vuln class.
            vc = parsed["vuln_class"]
            if vc and vc.lower() not in consulted:
                consulted.add(vc.lower())
                guide = kb_loader.get_technique(vc, config)
                view.panel(guide[:1500], f"KB: {vc}", "yellow")
                log.log_step(step, thought=parsed["thought"], status="kb_consulted",
                             kb_consulted=vc)
                messages.append({"role": "user",
                                 "content": f"Technique guide for {vc}. Follow it strictly:\n{guide}"})
                continue

            action, action_input = parsed["action"], parsed["action_input"]
            if not action or not action_input:
                messages.append({"role": "user",
                                 "content": "Reply using the strict format with one ACTION."})
                continue

            # Resume: skip a command already run in a previous session.
            if action_input.strip() in skip:
                view.line(f"[dim]skip (already tried): {action_input}[/]")
                messages.append({"role": "user",
                                 "content": f"OBSERVATION: `{action_input}` was already tried in a previous session; propose a different step."})
                continue

            view.panel(f"[bold]{action}[/]\n{action_input}",
                       f"PROPOSED ACTION (step {step})", "magenta")
            view.update(tool=action, command=action_input, status="proposed")
            put_message(session_id, {"type": "action", "content": f"{action} {action_input}",
                                     "timestamp": _now_iso()})

            # Scope gate: hard block before the human is even asked.
            tgt = scope_command_target(action, action_input, target)
            sr = enforcer.check(tgt)
            if not sr.allowed:
                view.line(f"[red bold]SCOPE BLOCK:[/] {tgt} - {sr.reason}")
                log.log("scope_block", step=step, target=tgt, reason=sr.reason,
                        command=action_input)
                messages.append({"role": "user",
                                 "content": f"OBSERVATION: Target {tgt} is out of scope. Do not test it. Propose an in-scope step or give FINAL_ANSWER."})
                continue

            # Approval gate. In auto mode, passive commands and the native checks
            # auto-run (the native tools are in-process and scope-gated; Phase 9:
            # "active checks run freely in auto mode"); arbitrary external commands
            # still prompt. In ask mode everything prompts.
            passive = tools.is_passive(action, action_input, whitelist)
            if mode == "auto" and (passive or action in tools.NATIVE):
                view.line("[green]auto: executing (passive/native).[/]")
            elif headless:  # no console (web): decline active commands, keep going
                view.line("[yellow]headless: active command auto-declined.[/]")
                log.log_step(step, thought=parsed["thought"], action=action,
                             command=action_input, status="skipped")
                messages.append({"role": "user",
                                 "content": "OBSERVATION: active command auto-declined (no operator at the console). Propose a passive step or give FINAL_ANSWER."})
                continue
            else:
                why = "active/non-whitelisted" if mode == "auto" else "ask mode"
                if not console.input(f"[bold yellow]Run this? ({why}) [y/N] [/]").strip().lower().startswith("y"):
                    view.line("[red]Skipped.[/]")
                    log.log_step(step, thought=parsed["thought"], action=action,
                                 command=action_input, status="skipped")
                    messages.append({"role": "user",
                                     "content": "OBSERVATION: user declined to run that command. Propose a different step or give FINAL_ANSWER."})
                    continue

            view.update(status="running")
            try:
                result = tools.execute(action, action_input, config, approve_fb,
                                       view.line, domain=target,
                                       url=tools.url_in(action_input), scope=enforcer)
            except ScopeViolation as e:  # safety net (e.g. a host the pre-check missed)
                view.line(f"[red bold]SCOPE BLOCK:[/] {e.target} - {e.reason}")
                log.log("scope_block", step=step, target=e.target, reason=e.reason,
                        command=action_input)
                messages.append({"role": "user",
                                 "content": f"OBSERVATION: Target {e.target} is out of scope. Do not test it."})
                continue

            finding = _finding_hit(result["output"], config)
            if finding:
                log.notes.add("Potential Vulns",
                              f"[auto:'{finding}'] after `{action_input}`")
                if graph:
                    graph.add_finding(tools.url_in(action_input) or target, finding, "medium")
                put_message(session_id, {"type": "finding",
                                         "content": {"vuln": finding, "target": target,
                                                     "command": action_input, "severity": "medium"},
                                         "timestamp": _now_iso()})
            if result["status"] == "failed":
                log.notes.add("Dead Ends", f"`{action_input}` - all fallbacks failed")

            view.panel(result["output"][:2000],
                       f"OBSERVATION ({result['status']})", "blue")
            view.update(status=result["status"])
            put_message(session_id, {"type": "observation",
                                     "content": result["output"][:500], "timestamp": _now_iso()})
            stats()
            log.log_step(step, thought=parsed["thought"], action=action,
                         command=action_input, status=result["status"],
                         fallback_used=result["fallback_used"], output=result["output"],
                         finding=finding)
            messages.append({"role": "user", "content": f"OBSERVATION: {_observation(result)}"})

        view.line("[yellow]Reached max_steps without a FINAL_ANSWER.[/]")
        log.log("max_steps_reached", steps=max_steps)
