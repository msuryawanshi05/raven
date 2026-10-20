"""Live Rich dashboard for --mode auto. Implements the loop's `view` interface
(panel / line / update + context manager). Returns None (plain output) unless the
terminal is a wide enough TTY, so it never fights a dumb/narrow terminal."""
from collections import deque

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel

MIN_WIDTH = 80


def make_dashboard(target, mode, enabled, console):
    if mode != "auto" or not enabled:
        return None
    if not console.is_terminal or console.size.width < MIN_WIDTH:
        return None
    return Dashboard(target, console)


class Dashboard:
    def __init__(self, target, console):
        self.console = console
        self.live = None
        self.log = deque(maxlen=5)
        self.state = {"target": target, "step": 0, "subdomains": 0, "ports": 0,
                      "findings": 0, "tool": "-", "command": "-", "status": "idle",
                      "thought": ""}

    # --- view interface ---
    def __enter__(self):
        self.live = Live(self._render(), console=self.console,
                         refresh_per_second=4, screen=False)
        self.live.start()
        return self

    def __exit__(self, *exc):
        if self.live:
            self.live.stop()
        return False

    def panel(self, body, title, style):
        self.line(f"[{style}]{title.split('(')[0].strip()}[/]: {_first(body)}")

    def line(self, text):
        self.log.append(str(text))
        self._refresh()

    def update(self, **state):
        self.state.update({k: v for k, v in state.items() if v is not None})
        self._refresh()

    # --- rendering ---
    def _refresh(self):
        if self.live:
            self.live.update(self._render(), refresh=True)

    def _render(self):
        s = self.state
        layout = Layout()
        layout.split_column(
            Layout(Panel(f"[bold]RAVEN[/]   target: [cyan]{s['target']}[/]   "
                         f"step: {s['step']}", border_style="white"), size=3, name="head"),
            Layout(name="mid"),
            Layout(Panel("\n".join(self.log) or "_no events yet_", title="LOG",
                         border_style="grey50"), size=9, name="log"),
        )
        recon = Panel(f"Subdomains: [bold]{s['subdomains']}[/]\nPorts: [bold]{s['ports']}[/]",
                      title="RECON", border_style="blue")
        action = Panel(f"Tool: {s['tool']}\nCMD:  {_first(s['command'])}\nStatus: {s['status']}",
                       title="CURRENT ACTION", border_style="magenta")
        findings = Panel(f"[red]\\[!] {s['findings']} potential[/]" if s["findings"]
                         else "none yet", title="FINDINGS", border_style="red")
        thought = Panel(_first(s["thought"], 180) or "...", title="LLM THOUGHT",
                        border_style="cyan")
        layout["mid"].split_column(Layout(name="row1"), Layout(name="row2"))
        layout["mid"]["row1"].split_row(Layout(recon), Layout(action))
        layout["mid"]["row2"].split_row(Layout(findings), Layout(thought))
        return layout


def _first(text, n=70):
    line = str(text or "").strip().splitlines()[0] if str(text or "").strip() else ""
    return line[:n] + ("..." if len(line) > n else "")
