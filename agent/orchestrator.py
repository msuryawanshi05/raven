"""Multi-agent runner: a ReconAgent and an ExploitAgent on a 2-thread pool,
sharing a HuntGraph (locked on writes) and a Queue for messages.

Message: {"from": "recon|exploit", "type": "finding|recon_complete|exploit_result|error", "data": {...}}
"""
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, Queue

from rich.console import Console

from . import scope as scope_mod
from . import tools
from .loop import run as loop_run
from .scope import PASSIVE_SERVICES, ScopeEnforcer, hosts_under

console = Console()
IDLE_TIMEOUT = 60  # exploit agent exits if the queue is idle this long after recon_complete


class Orchestrator:
    def __init__(self, target, cfg, log, graph, model, mode="auto", tracer=None):
        self.target = target
        self.cfg = cfg
        self.log = log
        self.graph = graph
        self.model = model
        self.mode = mode
        self.tracer = tracer
        self.q = Queue()
        self.recon_done = threading.Event()
        self.results = []

    # --- recon side (overridable in tests) ---
    def _recon(self):
        """Return (recon_text, in_scope_hosts)."""
        reconftw = os.path.expanduser(self.cfg["reconftw_path"])
        if not os.path.isfile(reconftw):
            return "[reconftw not installed]", []
        text, _ok = tools.run_reconftw(reconftw, f"-d {self.target} -p")
        enforcer = ScopeEnforcer(self.cfg.get("scope", {}))
        hosts = sorted(h for h in hosts_under(text, self.target)
                       if h not in PASSIVE_SERVICES and enforcer.check(h).allowed)
        return text, hosts

    def _recon_agent(self):
        text, hosts = self._recon()
        self.log.log("recon_seed", target=self.target, output=text)
        for h in hosts:
            self.graph.add_subdomain(self.target, h)
            self.q.put({"from": "recon", "type": "finding", "data": {"host": h}})
        self.q.put({"from": "recon", "type": "recon_complete", "data": {"hosts": len(hosts)}})
        self.recon_done.set()

    # --- exploit side (overridable in tests) ---
    def _exploit(self, host):
        loop_run(host, self.graph.summary(), self.model, self.mode, self.cfg, self.log,
                 graph=self.graph, tracer=self.tracer, agent_name="exploit")

    def _exploit_agent(self):
        visited = set()
        while True:
            if self.recon_done.is_set() and self.q.empty():
                break
            try:
                msg = self.q.get(timeout=1)
            except Empty:
                continue
            if msg["type"] == "finding":
                host = msg["data"]["host"]
                if host not in visited:
                    visited.add(host)
                    try:
                        self._exploit(host)
                        self.results.append(host)
                        self.q.put({"from": "exploit", "type": "exploit_result",
                                    "data": {"host": host}})
                    except RuntimeError as e:  # raven LLM unavailable
                        self.q.put({"from": "exploit", "type": "error",
                                    "data": {"error": str(e)}})

    def run(self):
        with ThreadPoolExecutor(max_workers=2) as ex:
            ex.submit(self._recon_agent)
            ex.submit(self._exploit_agent)
        # the executor's __exit__ waits for both agents to finish
        console.print(f"[green]multi-agent run complete[/] - exploited {len(self.results)} host(s)")
        return self.results
