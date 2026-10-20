"""Multi-target mode: hunt a list of domains sequentially or up to 3 in parallel."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from rich.table import Table

from reporter.builder import _reports_dir

MAX_PARALLEL = 3


def load_targets(path) -> list:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def run_all(targets, hunt_one, parallel=False) -> list:
    """hunt_one(target) -> summary dict {target, findings, duration, status, session}."""
    if not parallel:
        return [hunt_one(t) for t in targets]

    async def main():
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as ex:
            return await asyncio.gather(*[loop.run_in_executor(ex, hunt_one, t) for t in targets])

    return list(asyncio.run(main()))


def render_table(results, console):
    table = Table(title="Multi-target summary")
    for col in ("Target", "Findings", "Duration", "Status"):
        table.add_column(col)
    for r in results:
        table.add_row(r["target"], str(r["findings"]),
                      f"{r['duration']:.0f}s", r["status"])
    console.print(table)


def save_summary(results, config) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = _reports_dir(config) / f"multi_{ts}_summary.md"
    path.parent.mkdir(exist_ok=True)
    rows = "\n".join(f"| {r['target']} | {r['findings']} | {r['duration']:.0f}s | {r['status']} |"
                     for r in results)
    path.write_text(
        f"# Multi-target summary ({ts})\n\n"
        "| Target | Findings | Duration | Status |\n"
        "|---|---|---|---|\n" + rows + "\n", encoding="utf-8")
    return path
