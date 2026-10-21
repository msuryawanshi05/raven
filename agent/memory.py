"""Session logging: a JSONL event stream + a human-readable notes.md.

JSONL per step uses the Phase 2 schema. notes.md is a living markdown file with
fixed sections, rewritten on every add so ordering stays clean.
"""
import json
from datetime import datetime
from pathlib import Path

SESSIONS_DIR = Path(__file__).resolve().parent.parent / "sessions"
SECTIONS = ["Subdomains Found", "Open Ports", "Potential Vulns", "Dead Ends"]
_ALIASES = {"subdomain": "Subdomains Found", "sub": "Subdomains Found",
            "port": "Open Ports", "vuln": "Potential Vulns",
            "deadend": "Dead Ends", "dead": "Dead Ends"}


def _now():
    return datetime.now().isoformat(timespec="seconds")


class NotesFile:
    def __init__(self, path: Path, target: str, load: bool = False):
        self.path = path
        self.target = target
        self.items = {s: [] for s in SECTIONS}
        if load and path.is_file():
            self._load()      # resume: keep what the previous session wrote
        else:
            self._write()

    def _load(self):
        section = None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.startswith("## "):
                section = self._match(line[3:])
            elif line.startswith("- ") and section:
                self.items[section].append(line[2:].strip())

    def _match(self, section: str) -> str:
        s = section.strip().lower()
        for k in SECTIONS:
            if s and (k.lower().startswith(s) or s in k.lower()):
                return k
        for key, k in _ALIASES.items():
            if s.startswith(key):
                return k
        return "Potential Vulns"

    def add(self, section: str, text: str):
        self.items[self._match(section)].append(text.strip())
        self._write()

    def _write(self):
        lines = [f"# Recon notes - {self.target}", ""]
        for s in SECTIONS:
            lines.append(f"## {s}")
            lines += ([f"- {t}" for t in self.items[s]] if self.items[s]
                      else ["_none yet_"])
            lines.append("")
        self.path.write_text("\n".join(lines), encoding="utf-8")


class SessionLog:
    def __init__(self, target: str, path=None):
        SESSIONS_DIR.mkdir(exist_ok=True)
        self.notifier = None  # set by bb_agent when --notify is used
        if path is not None:  # resume: append to an existing session + notes
            self.path = Path(path)
            notes_path = self.path.with_name(self.path.stem + "_notes.md")
            self.notes = NotesFile(notes_path, target, load=True)
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = target.replace("/", "_").replace(":", "_")
        self.path = SESSIONS_DIR / f"{safe}_{ts}.jsonl"
        self.notes = NotesFile(SESSIONS_DIR / f"{safe}_{ts}_notes.md", target)

    def _append(self, record: dict):
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        if self.notifier and (record.get("finding") or record.get("kind") == "behavior_change"):
            try:
                self.notifier(record)
            except Exception:  # a failed notification must never abort the hunt
                pass
        return record

    def log(self, kind: str, **fields):
        """Non-step events: recon_seed, final, error, skipped, max_steps."""
        return self._append({"timestamp": _now(), "kind": kind, **fields})

    def log_step(self, step, thought=None, action=None, command=None,
                 status=None, fallback_used=None, output="", finding=None,
                 kb_consulted=None):
        return self._append({
            "timestamp": _now(),
            "step": step,
            "thought": thought,
            "action": action,
            "command": command,
            "status": status,
            "fallback_used": fallback_used,
            "output_summary": (output or "")[:500],
            "finding": finding,
            "kb_consulted": kb_consulted,
        })
