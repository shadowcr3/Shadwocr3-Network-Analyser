"""Evidence-aware topology: every edge says how it is known, and the view says it is partial."""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import networkx as nx

from .records import AssetRow, ConnectionRow

PARTIAL_NOTICE = (
    "Partial view: built only from imported captures/logs and scan results. It is not a "
    "complete map of the physical network."
)


@dataclass(frozen=True, slots=True)
class TopologyNode:
    id: str
    label: str
    kind: str  # asset | external
    mac: str | None
    hostname: str | None
    sources: tuple[str, ...]
    first_seen: datetime | None
    uncertain: bool
    degree: int


@dataclass(frozen=True, slots=True)
class TopologyEdge:
    src: str
    dst: str
    protocols: tuple[str, ...]
    ports: tuple[int, ...]
    packets: int | None
    bytes: int | None
    flows: int
    first_seen: datetime
    last_seen: datetime
    kind: str  # observed | inferred
    import_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Topology:
    nodes: tuple[TopologyNode, ...]
    edges: tuple[TopologyEdge, ...]
    components: int
    notice: str = PARTIAL_NOTICE


def build_topology(assets: list[AssetRow], connections: list[ConnectionRow]) -> Topology:
    by_ip = {a.ip: a for a in assets}
    merged: dict[tuple[str, str], dict] = {}
    for c in connections:
        key = (c.src, c.dst)
        m = merged.setdefault(key, {"protocols": set(), "ports": set(), "packets": None,
                                    "bytes": None, "flows": 0, "first": c.first_seen,
                                    "last": c.last_seen, "kind": set(), "imports": set()})
        m["protocols"].add(c.protocol)
        if c.dst_port is not None:
            m["ports"].add(c.dst_port)
        for field, value in (("packets", c.packets), ("bytes", c.bytes)):
            if value is not None:
                m[field] = (m[field] or 0) + value
        m["flows"] += c.flows
        m["first"], m["last"] = min(m["first"], c.first_seen), max(m["last"], c.last_seen)
        m["kind"].add(c.kind)
        if c.import_id is not None:
            m["imports"].add(c.import_id)
    graph: nx.Graph = nx.Graph()
    graph.add_nodes_from(by_ip)
    for (src, dst) in merged:
        graph.add_edge(src, dst)
    nodes = []
    for ip in sorted(graph.nodes, key=_ip_key):
        a = by_ip.get(ip)
        nodes.append(TopologyNode(
            id=ip, label=(a.hostname if a and a.hostname else ip),
            kind="asset" if a else "external", mac=a.mac if a else None,
            hostname=a.hostname if a else None, sources=a.sources if a else (),
            first_seen=a.first_seen if a else None, uncertain=a.uncertain if a else False,
            degree=graph.degree[ip]))
    edges = tuple(
        TopologyEdge(src, dst, tuple(sorted(m["protocols"])), tuple(sorted(m["ports"])),
                     m["packets"], m["bytes"], m["flows"], m["first"], m["last"],
                     "inferred" if m["kind"] == {"inferred"} else "observed",
                     tuple(sorted(m["imports"])))
        for (src, dst), m in sorted(merged.items()))
    return Topology(tuple(nodes), edges, nx.number_connected_components(graph))


def filter_topology(
    topo: Topology, *, text: str | None = None, protocol: str | None = None,
    since: datetime | None = None,
) -> Topology:
    """Filter by node text, edge protocol and observation period. Keeps the partial notice."""
    edges = [e for e in topo.edges
             if (protocol is None or protocol in e.protocols)
             and (since is None or e.last_seen >= since)]
    needle = (text or "").strip().lower()
    if needle:
        hits = {n.id for n in topo.nodes
                if needle in n.id.lower() or needle in n.label.lower()
                or needle in (n.mac or "").lower()}
        edges = [e for e in edges if e.src in hits or e.dst in hits]
        keep = hits | {x for e in edges for x in (e.src, e.dst)}
    else:
        keep = {n.id for n in topo.nodes}
        if protocol is not None or since is not None:
            keep = {x for e in edges for x in (e.src, e.dst)}
    nodes = tuple(n for n in topo.nodes if n.id in keep)
    graph: nx.Graph = nx.Graph()
    graph.add_nodes_from(n.id for n in nodes)
    graph.add_edges_from((e.src, e.dst) for e in edges)
    return Topology(nodes, tuple(edges), nx.number_connected_components(graph), topo.notice)


def is_recent(node: TopologyNode, within: timedelta, now: datetime | None = None) -> bool:
    """True for assets first seen recently, so the view can highlight new devices."""
    now = now or datetime.now(timezone.utc)
    return node.first_seen is not None and now - node.first_seen <= within


def circular_layout(topo: Topology, width: float = 900.0, height: float = 600.0
                    ) -> dict[str, tuple[float, float]]:
    """Deterministic layout: each connected component gets its own circle on a grid."""
    graph: nx.Graph = nx.Graph()
    graph.add_nodes_from(n.id for n in topo.nodes)
    graph.add_edges_from((e.src, e.dst) for e in topo.edges)
    comps = sorted((sorted(c, key=_ip_key) for c in nx.connected_components(graph)),
                   key=lambda c: (-len(c), c[0]))
    if not comps:
        return {}
    cols = math.ceil(math.sqrt(len(comps)))
    rows = math.ceil(len(comps) / cols)
    cell_w, cell_h = width / cols, height / rows
    pos: dict[str, tuple[float, float]] = {}
    for i, comp in enumerate(comps):
        cx, cy = (i % cols + 0.5) * cell_w, (i // cols + 0.5) * cell_h
        radius = min(cell_w, cell_h) * 0.38 if len(comp) > 1 else 0.0
        for k, node in enumerate(comp):
            angle = 2 * math.pi * k / max(len(comp), 1) - math.pi / 2
            pos[node] = (cx + radius * math.cos(angle), cy + radius * math.sin(angle))
    return pos


def _ip_key(ip: str) -> tuple[int, int | str]:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (9, ip)
