"""Finding notifications to Telegram or Discord.

build_notifier() returns a callable that memory.SessionLog fires on every finding
record (log_step with a finding, or a behavior_change). It returns None when the
chosen platform is not configured, so the caller can warn once.
"""
import json
import urllib.parse
import urllib.request


def build_notifier(cfg, platform, target):
    conf = (cfg.get("notify") or {}).get(platform) or {}
    if platform == "telegram" and conf.get("bot_token") and conf.get("chat_id"):
        return lambda rec: _telegram(conf, _message(target, rec))
    if platform == "discord" and conf.get("webhook_url"):
        return lambda rec: _discord(conf, _message(target, rec))
    return None


def _message(target, rec) -> str:
    if rec.get("kind") == "behavior_change":
        return (f"[raven] finding on {target}: behaviour {rec.get('signal')} "
                f"({rec.get('indicator')})")
    return (f"[raven] finding on {target}: {rec.get('finding')} "
            f"(severity {rec.get('status') or 'potential'}) via {rec.get('command', '?')}")


def _telegram(conf, text):
    url = f"https://api.telegram.org/bot{conf['bot_token']}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": conf["chat_id"], "text": text}).encode()
    urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)


def _discord(conf, text):
    data = json.dumps({"content": text}).encode()
    req = urllib.request.Request(conf["webhook_url"], data=data,
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)
