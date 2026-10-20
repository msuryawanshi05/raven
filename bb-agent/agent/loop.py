"""ReAct loop: reason over recon, consult the KB, act with human approval."""
import re

from rich.console import Console
from rich.panel import Panel

from . import kb_loader, tools
from .prompts import system_prompt, initial_user_prompt

console = Console()


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


def _chat(model, messages):
    import ollama  # lazy: dry runs and clear errors work without the SDK installed
    try:
        resp = ollama.chat(model=model, messages=messages)
    except Exception as e:  # ollama down, model missing, etc.
        raise RuntimeError(
            f"ollama call failed: {e}\n"
            "Is ollama running? Start it with:  ollama serve\n"
            f"Is the model pulled?  ollama pull {model}"
        )
    return resp["message"]["content"]


def _finding_hit(output, cfg):
    if not cfg.get("auto_note_findings", True):
        return None
    low = (output or "").lower()
    for kw in cfg.get("finding_keywords", []):
        if kw.lower() in low:
            return kw
    return None


def _approver(mode, whitelist):
    """Return approve(cmd)->bool for fallback commands, honouring mode + passive gate."""
    def approve(cmd):
        if mode == "auto" and tools.is_passive("run_command", cmd, whitelist):
            console.print("[green]auto: passive fallback, executing.[/]")
            return True
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


def run(target, recon_summary, model, mode, config, log):
    classes = kb_loader.available(config)
    messages = [
        {"role": "system", "content": system_prompt(classes)},
        {"role": "user", "content": initial_user_prompt(target, recon_summary)},
    ]
    whitelist = config.get("passive_whitelist", [])
    max_steps = config.get("max_steps", 15)
    approve_fb = _approver(mode, whitelist)
    consulted = set()

    for step in range(1, max_steps + 1):
        reply = _chat(model, messages)
        messages.append({"role": "assistant", "content": reply})
        parsed = _parse(reply)

        if parsed["thought"]:
            console.print(Panel(parsed["thought"], title=f"THOUGHT (step {step})",
                                border_style="cyan"))

        for section, text in parsed["notes"]:
            log.notes.add(section, text)
            console.print(f"[dim]noted ({section.strip()}): {text}[/]")

        if parsed["final"]:
            console.print(Panel(parsed["final"], title="FINAL ANSWER", border_style="green"))
            log.log("final", step=step, text=parsed["final"])
            return

        # Consult the technique guide before testing a vuln class.
        vc = parsed["vuln_class"]
        if vc and vc.lower() not in consulted:
            consulted.add(vc.lower())
            guide = kb_loader.get_technique(vc, config)
            console.print(Panel(guide[:1500], title=f"KB: {vc}", border_style="yellow"))
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

        console.print(Panel(f"[bold]{action}[/]\n{action_input}",
                            title=f"PROPOSED ACTION (step {step})", border_style="magenta"))

        # Approval gate (Phase 1 behaviour, preserved).
        passive = tools.is_passive(action, action_input, whitelist)
        if mode == "auto" and passive:
            console.print("[green]auto: passive command, executing.[/]")
        else:
            why = "active/non-whitelisted" if mode == "auto" else "ask mode"
            if not console.input(f"[bold yellow]Run this? ({why}) [y/N] [/]").strip().lower().startswith("y"):
                console.print("[red]Skipped.[/]")
                log.log_step(step, thought=parsed["thought"], action=action,
                             command=action_input, status="skipped")
                messages.append({"role": "user",
                                 "content": "OBSERVATION: user declined to run that command. Propose a different step or give FINAL_ANSWER."})
                continue

        result = tools.execute(action, action_input, config, approve_fb,
                               console.print, domain=target,
                               url=tools.url_in(action_input))
        finding = _finding_hit(result["output"], config)
        if finding:
            log.notes.add("Potential Vulns",
                          f"[auto:'{finding}'] after `{action_input}`")
        if result["status"] == "failed":
            log.notes.add("Dead Ends", f"`{action_input}` — all fallbacks failed")

        console.print(Panel(result["output"][:2000],
                            title=f"OBSERVATION ({result['status']})", border_style="blue"))
        log.log_step(step, thought=parsed["thought"], action=action,
                     command=action_input, status=result["status"],
                     fallback_used=result["fallback_used"], output=result["output"],
                     finding=finding)
        messages.append({"role": "user", "content": f"OBSERVATION: {_observation(result)}"})

    console.print("[yellow]Reached max_steps without a FINAL_ANSWER.[/]")
    log.log("max_steps_reached", steps=max_steps)
