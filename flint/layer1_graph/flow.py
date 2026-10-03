"""Flow relation (⇝) and D-avoiding reachability over a PROV graph.

The flow graph uses edge directions set by load.py.  This module provides
helpers to extract the three node sets from the formal model and the core
D-avoiding BFS.
"""
from __future__ import annotations

from collections import deque

import networkx as nx

from flint.spec import ENDORSER, INTEGRITY_KEY, ROLE_KEY, SINK, UNTRUSTED

# ---------------------------------------------------------------------------
# Node-set extractors
# ---------------------------------------------------------------------------

def get_untrusted_sources(G: nx.DiGraph) -> list[str]:
    """U_src: entity nodes labelled ⊥ (adprov:integrity == 'untrusted').

    An entity with no label is not counted here. A deployment that must treat a
    missing label as ⊥ loads with ``load_prov_graph(doc, strict=True)``, which
    writes the ⊥ label in before this function sees the graph.
    """
    return [
        n for n, d in G.nodes(data=True)
        if d.get("node_type") == "entity" and d.get(INTEGRITY_KEY) == UNTRUSTED
    ]


def get_sinks(G: nx.DiGraph) -> frozenset[str]:
    """S: activity nodes with adprov:role == 'sink'.

    S ⊆ Activities: a role on an entity or agent is not a sink.
    """
    return frozenset(
        n for n, d in G.nodes(data=True)
        if d.get("node_type") == "activity" and d.get(ROLE_KEY) == SINK
    )


def get_endorsers(G: nx.DiGraph) -> frozenset[str]:
    """D: activity nodes with adprov:role == 'endorser'.

    D ⊆ Activities. This matters for soundness: if an entity or agent could be
    an endorser, a role mislabelled onto a data node would cut every flow
    through it.
    """
    return frozenset(
        n for n, d in G.nodes(data=True)
        if d.get("node_type") == "activity" and d.get(ROLE_KEY) == ENDORSER
    )


# ---------------------------------------------------------------------------
# Core reachability
# ---------------------------------------------------------------------------

def d_avoiding_reachable(
    G: nx.DiGraph,
    source: str,
    targets: frozenset[str],
    endorsers: frozenset[str],
) -> bool:
    """Return True if any target is reachable from source along a path that
    contains no endorser node (D-avoiding path).

    The source itself is checked first; a node in endorsers is never enqueued,
    so paths through D are pruned at the traversal frontier.
    """
    if source in targets:
        return True
    visited: set[str] = {source}
    queue: deque[str] = deque([source])
    while queue:
        node = queue.popleft()
        for nbr in G.successors(node):
            if nbr in targets:
                return True
            if nbr not in visited and nbr not in endorsers:
                visited.add(nbr)
                queue.append(nbr)
    return False


def check_flow(G: nx.DiGraph) -> bool:
    """f_flow(G) = 1 iff ∃ u ∈ U_src, s ∈ S : u ⇝_D s."""
    sinks = get_sinks(G)
    endorsers = get_endorsers(G)
    if not sinks:
        return False
    for source in get_untrusted_sources(G):
        if d_avoiding_reachable(G, source, sinks, endorsers):
            return True
    return False


def flow_witnesses(G: nx.DiGraph) -> list[tuple[str, str, list[str]]]:
    """Return a list of (source, sink, path) triples for every detected flow.

    Each path is the shortest D-avoiding path from source to sink.
    Useful for debugging and trace interpretation.
    """
    sinks = get_sinks(G)
    endorsers = get_endorsers(G)
    witnesses: list[tuple[str, str, list[str]]] = []

    for source in get_untrusted_sources(G):
        for sink in sinks:
            path = _shortest_d_avoiding_path(G, source, sink, endorsers)
            if path is not None:
                witnesses.append((source, sink, path))
    return witnesses


def _shortest_d_avoiding_path(
    G: nx.DiGraph,
    source: str,
    target: str,
    endorsers: frozenset[str],
) -> list[str] | None:
    """BFS returning the shortest D-avoiding path, or None."""
    if source == target:
        return [source]
    visited: set[str] = {source}
    queue: deque[list[str]] = deque([[source]])
    while queue:
        path = queue.popleft()
        node = path[-1]
        for nbr in G.successors(node):
            if nbr == target:
                return [*path, nbr]
            if nbr not in visited and nbr not in endorsers:
                visited.add(nbr)
                queue.append([*path, nbr])
    return None
