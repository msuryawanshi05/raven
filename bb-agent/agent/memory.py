"""Session logger: append one JSON object per event to sessions/<target>_<ts>.jsonl."""
import json
import time
from datetime import datetime
from pathlib import Path

SESSIONS_DIR = Path(__file__).resolve().parent.parent / "sessions"


class SessionLog:
    def __init__(self, target: str):
        SESSIONS_DIR.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = target.replace("/", "_").replace(":", "_")
        self.path = SESSIONS_DIR / f"{safe}_{ts}.jsonl"

    def log(self, kind: str, **fields):
        """kind is e.g. 'thought', 'action', 'observation', 'final', 'error'."""
        record = {"ts": time.time(), "kind": kind, **fields}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record
