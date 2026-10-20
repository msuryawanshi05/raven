"""Platform formatter: reshape a built report model into a platform draft.

Platforms: hackerone, bugcrowd, huntr. Output: reports/<prefix>_<platform>.md
"""
from .builder import _reports_dir

PLATFORMS = ("hackerone", "bugcrowd", "huntr")
_BUGCROWD_P = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}


def _steps(model):
    return "\n".join(f"{i}. {s}" for i, s in enumerate(model["steps"], 1)) or "_none recorded_"


def _hackerone(m):
    return f"""# [{m['vuln_name']}] Potential {m['vuln_name']} on {m['endpoint']}

**Severity:** {m['severity']}
**Weakness:** {m['cwe']}

## Steps to Reproduce
{_steps(m)}

## Impact
{m['impact']}
"""


def _bugcrowd(m):
    return f"""# [{m['vuln_name']}] Potential {m['vuln_name']} on {m['endpoint']}

**Bug URL:** {m['endpoint']}
**Severity:** {_BUGCROWD_P.get(m['severity'], 'P4')} ({m['severity']})

## Description
{m['summary']}

### Steps
{_steps(m)}
"""


def _huntr(m):
    return f"""# [{m['vuln_name']}] Potential {m['vuln_name']}

**Challenge ID:** _(fill in)_

## Attack description
{m['summary']}

## Payload
```
{m['payload'] or '(none)'}
```

## Result
{m['finding_text']}
"""


_RENDER = {"hackerone": _hackerone, "bugcrowd": _bugcrowd, "huntr": _huntr}


def format_report(model, platform, config):
    platform = platform.lower()
    if platform not in _RENDER:
        raise ValueError(f"unknown platform '{platform}'; choose from {', '.join(PLATFORMS)}")
    path = _reports_dir(config) / f"{model['prefix']}_{platform}.md"
    path.parent.mkdir(exist_ok=True)
    path.write_text(_RENDER[platform](model), encoding="utf-8")
    return path
