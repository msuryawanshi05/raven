"""Technique knowledge-base loader: read kb/<vuln_class>.md on demand."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _kb_dir(cfg) -> Path:
    p = Path(cfg.get("kb_path", "./kb"))
    return p if p.is_absolute() else (ROOT / p)


def available(cfg):
    d = _kb_dir(cfg)
    if not d.is_dir():
        return []
    return sorted(f.stem for f in d.glob("*.md") if not f.stem.startswith("_"))


def get_technique(vuln_class: str, cfg) -> str:
    name = vuln_class.strip().lower().replace(" ", "_")
    f = _kb_dir(cfg) / f"{name}.md"
    if f.is_file():
        return f.read_text(encoding="utf-8")
    return (f"[no KB entry for '{vuln_class}'. Available: "
            f"{', '.join(available(cfg)) or 'none'}]")
