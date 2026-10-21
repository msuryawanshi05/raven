"""Hunt graph: entities and relationships as a networkx DiGraph, JSON-persisted.

Writes take a lock (networkx reads are safe without one, so neighbors/summary/
attack_surface do not lock). Saved on every update in node_link_data format.
"""
import json
import threading
from pathlib import Path

import networkx as nx


class HuntGraph:
    def __init__(self, path):
        self.path = Path(path)
        self.g = nx.DiGraph()
        self._lock = threading.Lock()

    # --- writes (locked) ---
    def _add(self, node, ntype, edges=(), **attrs):
        with self._lock:
            self.g.add_node(node, type=ntype, **attrs)
            for src, rel, dst, dtype in edges:
                self.g.add_node(src) if src not in self.g else None
                self.g.add_node(dst, type=dtype) if dst not in self.g else None
                self.g.add_edge(src, dst, rel=rel)
            self._save()

    def add_subdomain(self, domain, sub):
        self._add(sub, "subdomain", [(domain, "has_subdomain", sub, "subdomain")])

    def add_port(self, host, port, service=""):
        node = f"{host}:{port}"
        self._add(node, "port", [(host, "has_port", node, "port")], service=service)

    def add_endpoint(self, host, path, method="GET"):
        node = f"{host}{path}"
        self._add(node, "endpoint", [(host, "has_endpoint", node, "endpoint")], method=method)

    def add_technology(self, host, tech):
        self._add(tech, "technology", [(host, "runs", tech, "technology")])

    def add_finding(self, endpoint, vuln_class, severity="medium"):
        node = f"{vuln_class}@{endpoint}"
        self._add(node, "vuln", [(endpoint, "vulnerable_to", node, "vuln")],
                  vuln_class=vuln_class, severity=severity)

    def _save(self):
        try:
            data = nx.node_link_data(self.g, edges="links")
        except TypeError:  # older networkx without the edges kwarg
            data = nx.node_link_data(self.g)
        self.path.write_text(json.dumps(data), encoding="utf-8")

    # --- reads (no lock) ---
    def neighbors(self, node):
        return list(self.g.successors(node)) if node in self.g else []

    def attack_surface(self):
        out = []
        for n, d in self.g.nodes(data=True):
            if d.get("type") == "vuln":
                endpoint = next(iter(self.g.predecessors(n)), "?")
                out.append({"node": n, "endpoint": endpoint,
                            "vuln": d.get("vuln_class"), "severity": d.get("severity")})
        return out

    def summary(self) -> str:
        counts = {}
        for _, d in self.g.nodes(data=True):
            counts[d.get("type", "?")] = counts.get(d.get("type", "?"), 0) + 1
        lines = ["## Hunt graph",
                 "Nodes: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"),
                 "", "| Endpoint | Vuln | Severity |", "|---|---|---|"]
        for a in self.attack_surface():
            lines.append(f"| {a['endpoint']} | {a['vuln']} | {a['severity']} |")
        return "\n".join(lines) + "\n"

    @classmethod
    def load(cls, path):
        obj = cls(path)
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        try:
            obj.g = nx.node_link_graph(data, edges="links", directed=True)
        except TypeError:
            obj.g = nx.node_link_graph(data, directed=True)
        return obj
