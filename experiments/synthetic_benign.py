"""Synthetic benign agent-provenance graph generator.

Purpose (Tier-1 baseline strengthening, see learned_baseline.py): the
benign-trained structural novelty detectors (GNN-AE, WL-IF) are trained on only
~97 real benign traces, so their near-zero injection TPR is dismissable as
*undertraining* rather than a fundamental limit. This module fabricates an
arbitrary number of structurally realistic benign graphs so those detectors can
be retrained on a rich benign manifold; if their clean-injection TPR stays ~0
with thousands of benign training samples, the thesis claim ("a structural
learner cannot see a flow attack, because the distinguishing signal is the
integrity label, not the structure") is robust to the data-volume objection.

Scope and honesty boundary: these graphs are SYNTHETIC and are used ONLY to
augment the *training* set of a baseline we argue against. FLINT's own
f_flow / f_emb numbers, the reported FPR, and all injection TPR are measured on
the real Zenodo corpus; synthetic graphs never enter evaluation. The generator
matches the real benign structural fingerprint (load_prov_graph schema):

    nodes        : node_type in {entity, activity, agent}
    edges        : relation in {used, wasGeneratedBy, wasInformedBy, wasDerivedFrom}
    size         : mean ~12.7 nodes (4..42), drawn per-trace
    node mix     : ~50% entity / ~42% activity / ~8% agent
    relation mix : ~0.26 used / ~0.41 wasGeneratedBy / ~0.33 wasInformedBy
                   (wasDerivedFrom rare, as in the real benign corpus)

The motif is a tool-call chain: activities linked by wasInformedBy (with
occasional branching), each activity consuming input entities (used) and
producing output entities (wasGeneratedBy), with output entities sometimes
chained into the next activity's input.  Edge directions follow the FLINT flow
relation exactly as in flint.layer1_graph.load.
"""
from __future__ import annotations

import random

import networkx as nx


def _draw_k(rng: random.Random) -> int:
    """Activities per trace; yields total nodes ~ matching the real benign set."""
    k = int(round(rng.lognormvariate(1.5, 0.5)))  # median ~4.5, mean ~5
    return max(1, min(19, k))


def generate_benign_graph(rng: random.Random) -> nx.DiGraph:
    """One structurally realistic benign agent-provenance graph."""
    G = nx.DiGraph()
    k = _draw_k(rng)

    # Agent nodes: isolated (wasAssociatedWith is a node attr, not a flow edge),
    # ~1 per trace, occasionally 2 (user + assistant principals).
    n_agents = 1 + (1 if rng.random() < 0.2 else 0)
    for g in range(n_agents):
        G.add_node(f"ag{g}", node_type="agent")

    acts: list[str] = []
    outputs: list[str] = []  # output entities available for downstream use
    eid = 0

    for i in range(k):
        a = f"a{i}"
        G.add_node(a, node_type="activity")
        acts.append(a)

        # wasInformedBy chain (a_{i-1} -> a_i), occasionally branching off an
        # earlier activity to give the benign manifold non-linear topology.
        if i > 0:
            src = acts[i - 1]
            if i >= 2 and rng.random() < 0.15:
                src = rng.choice(acts[:i])
            G.add_edge(src, a, relation="wasInformedBy")

        # used: consume an input entity (reuse a prior output as data-chaining,
        # else a fresh source entity).
        if rng.random() < 0.65:
            if outputs and rng.random() < 0.7:
                e = rng.choice(outputs)
            else:
                e = f"e{eid}"; eid += 1
                G.add_node(e, node_type="entity")
            G.add_edge(e, a, relation="used")

        # wasGeneratedBy: produce one (sometimes two) output entities.
        for _ in range(1 + (1 if rng.random() < 0.08 else 0)):
            e = f"e{eid}"; eid += 1
            G.add_node(e, node_type="entity")
            G.add_edge(a, e, relation="wasGeneratedBy")
            outputs.append(e)

        # Rare entity-to-entity derivation, matching the real benign corpus.
        if rng.random() < 0.05 and len(outputs) >= 2:
            e1, e2 = rng.sample(outputs, 2)
            if not G.has_edge(e1, e2):
                G.add_edge(e1, e2, relation="wasDerivedFrom")

    return G


def generate_benign_graphs(n: int, seed: int = 0) -> list[nx.DiGraph]:
    """Deterministically generate ``n`` synthetic benign graphs."""
    rng = random.Random(seed)
    return [generate_benign_graph(rng) for _ in range(n)]


def _fingerprint(graphs: list[nx.DiGraph]) -> dict:
    """Structural summary, for comparing synthetic vs real distributions."""
    import collections

    nt, rel = collections.Counter(), collections.Counter()
    nodes, edges = [], []
    for G in graphs:
        nodes.append(G.number_of_nodes())
        edges.append(G.number_of_edges())
        for _, d in G.nodes(data=True):
            nt[d.get("node_type")] += 1
        for *_, d in G.edges(data=True):
            rel[d.get("relation")] += 1
    tot_n, tot_e = sum(nt.values()) or 1, sum(rel.values()) or 1
    return {
        "n": len(graphs),
        "nodes_mean": round(sum(nodes) / len(nodes), 1),
        "nodes_min": min(nodes),
        "nodes_max": max(nodes),
        "edges_mean": round(sum(edges) / len(edges), 1),
        "node_type": {k: round(v / tot_n, 3) for k, v in nt.items()},
        "relation": {k: round(v / tot_e, 3) for k, v in rel.items()},
    }


if __name__ == "__main__":
    import json

    g = generate_benign_graphs(2000, seed=0)
    print("synthetic benign fingerprint (target: nodes~12.7, "
          "entity 0.50 / activity 0.42 / agent 0.08, "
          "used 0.26 / wasGeneratedBy 0.41 / wasInformedBy 0.33):")
    print(json.dumps(_fingerprint(g), indent=2))
