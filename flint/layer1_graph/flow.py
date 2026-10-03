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
    """f_flow(G) = 1 iff ∃ u ∈ U_src, s ∈ S : u ⇝_D s.

    One breadth-first search seeded with every source at once, so the cost is
    O(|N| + |R|) however many untrusted sources the graph has. (Searching from
    each source separately is O(|U_src| · (|N| + |R|)), which is quadratic in a
    session where every step reads external data.)
    """
    sinks = get_sinks(G)
    if not sinks:
        return False
    endorsers = get_endorsers(G)
    sources = get_untrusted_sources(G)
    if any(u in sinks for u in sources):
        return True
    visited: set[str] = set(sources)
    queue: deque[str] = deque(sources)
    while queue:
        node = queue.popleft()
        for nbr in G.successors(node):
            if nbr in sinks:
                return True
            if nbr not in visited and nbr not in endorsers:
                visited.add(nbr)
                queue.append(nbr)
    return False


def flow_witnesses(G: nx.DiGraph) -> list[tuple[str, str, list[str]]]:
    """Return a list of (source, sink, path) triples for every detected flow.

    Each path is the shortest D-avoiding path from source to sink: the BFS-tree
    path, found by one search per source rather than one per (source, sink)
    pair. Useful for debugging and trace interpretation.
    """
    sinks = get_sinks(G)
    if not sinks:
        return []
    endorsers = get_endorsers(G)
    witnesses: list[tuple[str, str, list[str]]] = []

    for source in get_untrusted_sources(G):
        parent = _d_avoiding_bfs_tree(G, source, endorsers)
        for sink in sinks:
            if sink in parent:
                witnesses.append((source, sink, _tree_path(parent, sink)))
    return witnesses


def _d_avoiding_bfs_tree(
    G: nx.DiGraph,
    source: str,
    endorsers: frozenset[str],
) -> dict[str, str | None]:
    """BFS from ``source`` that never enters an endorser; returns parent pointers.

    A node's parent is the node from which it was first reached, so the tree
    path to any node is a shortest D-avoiding path to it.
    """
    parent: dict[str, str | None] = {source: None}
    queue: deque[str] = deque([source])
    while queue:
        node = queue.popleft()
        for nbr in G.successors(node):
            if nbr not in parent and nbr not in endorsers:
                parent[nbr] = node
                queue.append(nbr)
    return parent


def _tree_path(parent: dict[str, str | None], node: str) -> list[str]:
    path = [node]
    while (prev := parent[path[-1]]) is not None:
        path.append(prev)
    path.reverse()
    return path
