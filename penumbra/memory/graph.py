"""Layer 2: the temporal knowledge graph.

Slow espionage campaigns only show up as *relationships over time*: user A
touched repo B at 02:14, minted key C at 02:19, then messaged external
entity D. Every edge here carries a timestamp, the evidence event IDs that
support it, and the agent that asserted it, so every claim in the final
brief can be traced back to raw telemetry.

``TemporalGraph`` is an in-memory implementation with zero dependencies, used
by the demo and the tests. ``Neo4jGraph`` writes the same structure to Neo4j
or FalkorDB through the Bolt protocol for production use.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

Listener = Callable[[str, dict[str, Any]], None]


@dataclass
class Node:
    id: str
    type: str
    label: str
    props: dict[str, Any] = field(default_factory=dict)
    risk: float = 0.0  # 0..1, rendered as the node's "heat" in the UI
    first_seen: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type, "label": self.label, "props": self.props,
                "risk": round(self.risk, 3), "first_seen": self.first_seen}


@dataclass
class Edge:
    src: str
    dst: str
    rel: str
    ts: str | None
    evidence: list[str]
    asserted_by: str

    @property
    def id(self) -> str:
        return f"{self.src}|{self.rel}|{self.dst}"

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "src": self.src, "dst": self.dst, "rel": self.rel,
                "ts": self.ts, "evidence": self.evidence, "asserted_by": self.asserted_by}


class TemporalGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[str, Edge] = {}
        self._listeners: list[Listener] = []

    def subscribe(self, fn: Listener) -> None:
        self._listeners.append(fn)

    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        for fn in self._listeners:
            fn(kind, payload)

    # ------------------------------------------------------------------ writes
    def upsert_node(self, node_id: str, type: str, label: str | None = None, *,
                    risk: float | None = None, ts: datetime | str | None = None,
                    **props: Any) -> Node:
        ts_s = ts.isoformat() if isinstance(ts, datetime) else ts
        n = self.nodes.get(node_id)
        if n is None:
            n = Node(node_id, type, label or node_id, dict(props), risk or 0.0, ts_s)
            self.nodes[node_id] = n
        else:
            n.props.update(props)
            if risk is not None:
                n.risk = max(n.risk, risk)
            if label:
                n.label = label
        self._emit("node", n.to_dict())
        return n

    def add_edge(self, src: str, dst: str, rel: str, *, ts: datetime | str | None = None,
                 evidence: list[str] | None = None, asserted_by: str = "system") -> Edge:
        ts_s = ts.isoformat() if isinstance(ts, datetime) else ts
        e = Edge(src, dst, rel, ts_s, list(evidence or []), asserted_by)
        existing = self.edges.get(e.id)
        if existing:
            existing.evidence = sorted(set(existing.evidence) | set(e.evidence))
            e = existing
        else:
            self.edges[e.id] = e
        self._emit("edge", e.to_dict())
        return e

    # ------------------------------------------------------------------- reads
    def neighbors(self, node_id: str) -> list[dict[str, Any]]:
        out = []
        for e in self.edges.values():
            if e.src == node_id or e.dst == node_id:
                other = e.dst if e.src == node_id else e.src
                n = self.nodes.get(other)
                out.append({"edge": e.to_dict(), "node": n.to_dict() if n else {"id": other}})
        return sorted(out, key=lambda x: x["edge"]["ts"] or "")

    def path_timeline(self, node_ids: set[str]) -> list[Edge]:
        """All edges touching the given nodes, in time order."""
        es = [e for e in self.edges.values() if e.src in node_ids or e.dst in node_ids]
        return sorted(es, key=lambda e: e.ts or "")

    def snapshot(self) -> dict[str, Any]:
        return {"nodes": [n.to_dict() for n in self.nodes.values()],
                "edges": [e.to_dict() for e in self.edges.values()]}


class Neo4jGraph(TemporalGraph):  # pragma: no cover - requires a running Neo4j
    """Write-through adapter: keeps the in-memory view for the UI and mirrors
    every write to Neo4j / FalkorDB so investigations persist and can be
    queried with Cypher across incidents.

        export PENUMBRA_NEO4J_URI=bolt://localhost:7687
        export PENUMBRA_NEO4J_AUTH=neo4j/password
    """

    def __init__(self, uri: str, user: str, password: str) -> None:
        super().__init__()
        from neo4j import GraphDatabase  # type: ignore

        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def upsert_node(self, node_id, type, label=None, *, risk=None, ts=None, **props):
        n = super().upsert_node(node_id, type, label, risk=risk, ts=ts, **props)
        with self._driver.session() as s:
            s.run("MERGE (n:Entity {id:$id}) SET n.type=$type, n.label=$label, "
                  "n.risk=$risk, n += $props", id=n.id, type=n.type, label=n.label,
                  risk=n.risk, props={k: str(v) for k, v in n.props.items()})
        return n

    def add_edge(self, src, dst, rel, *, ts=None, evidence=None, asserted_by="system"):
        e = super().add_edge(src, dst, rel, ts=ts, evidence=evidence, asserted_by=asserted_by)
        with self._driver.session() as s:
            s.run("MATCH (a:Entity {id:$src}),(b:Entity {id:$dst}) "
                  "MERGE (a)-[r:REL {rel:$rel}]->(b) SET r.ts=$ts, r.evidence=$ev, r.by=$by",
                  src=src, dst=dst, rel=rel, ts=e.ts, ev=e.evidence, by=asserted_by)
        return e
