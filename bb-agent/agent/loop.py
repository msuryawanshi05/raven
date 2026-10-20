"""ReAct loop: reason over recon output, act with human approval."""
import re

import ollama
from rich.console import Console
from rich.panel import Panel

from . import tools
from .prompts import SYSTEM_PROMPT, initial_user_prompt

console = Console()


def _parse(text: str) -> dict:
    """Pull the fields out of one LLM turn."""
    def grab(label):
        m = re.search(rf"{label}:\s*(.+?)(?=\n[A-Z_]+:|\Z)", text, re.S)
        return m.group(1).strip() if m else None

    return {
        "thought": grab("THOUGHT"),
        "action": grab("ACTION"),
        "action_input": grab("ACTION_INPUT"),
        "final": grab("FINAL_ANSWER"),
    }


def _chat(model, messages):
    try:
        resp = ollama.chat(model=model, messages=messages)
    except Exception as e:  # ollama down, model missing, etc.
        raise RuntimeError(
            f"ollama call failed: {e}\n"
            "Is ollama running? Start it with:  ollama serve\n"
            f"Is the model pulled?  ollama pull {model}"
        )
    return resp["message"]["content"]


def run(target, recon_summary, model, mode, config, log):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": initial_user_prompt(target, recon_summary)},
    ]
    whitelist = config.get("passive_whitelist", [])
    max_steps = config.get("max_steps", 15)

    for step in range(1, max_steps + 1):
        reply = _chat(model, messages)
        messages.append({"role": "assistant", "content": reply})
        parsed = _parse(reply)

        if parsed["thought"]:
            console.print(Panel(parsed["thought"], title=f"THOUGHT (step {step})",
                                border_style="cyan"))
            log.log("thought", step=step, text=parsed["thought"])

        if parsed["final"]:
            console.print(Panel(parsed["final"], title="FINAL ANSWER",
                                border_style="green"))
            log.log("final", step=step, text=parsed["final"])
            return

        action, action_input = parsed["action"], parsed["action_input"]
        if not action or not action_input:
            console.print("[yellow]No actionable step parsed; asking the model to continue.[/]")
            messages.append({"role": "user",
                             "content": "Reply using the strict format with one ACTION."})
            continue

        console.print(Panel(f"[bold]{action}[/]\n{action_input}",
                            title=f"PROPOSED ACTION (step {step})", border_style="magenta"))
        log.log("action", step=step, action=action, action_input=action_input)

        passive = tools.is_passive(action, action_input, whitelist)
        if mode == "auto" and passive:
            console.print("[green]auto: passive command, executing.[/]")
        else:
            why = "active/non-whitelisted" if mode == "auto" else "ask mode"
            if not console.input(f"[bold yellow]Run this? ({why}) [y/N] [/]").strip().lower().startswith("y"):
                console.print("[red]Skipped.[/]")
                log.log("skipped", step=step, action_input=action_input)
                messages.append({"role": "user",
                                 "content": "OBSERVATION: user declined to run that command. Propose a different step or give FINAL_ANSWER."})
                continue

        if action == "run_reconftw":
            try:
                output = tools.run_reconftw(config["reconftw_path"], action_input)
            except FileNotFoundError as e:
                console.print(f"[red]reconftw not found at {e}. "
                              "Install: https://github.com/six2dez/reconftw[/]")
                log.log("error", step=step, error=f"reconftw missing: {e}")
                return
        else:
            output = tools.run_command(action_input)

        console.print(Panel(output[:2000], title="OBSERVATION", border_style="blue"))
        log.log("observation", step=step, output=output)
        messages.append({"role": "user", "content": f"OBSERVATION: {output}"})

    console.print("[yellow]Reached max_steps without a FINAL_ANSWER.[/]")
    log.log("max_steps_reached", steps=max_steps)
