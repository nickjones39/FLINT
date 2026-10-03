"""Layer-3 adversaries for P1/P2/P3 evasion tests.

Adversary B variants — synthetic graph mutations applied to an existing flow graph:

  structural_mimicry          — adds a decoy used-edge from each ⊥ entity to a
                                 new neutral activity.  Changes the WL 1-hop
                                 neighborhood hash → evades f_emb (P2/H1).
                                 Does NOT remove any ⊥→sink path → f_flow
                                 still detects (P1/H2).

  trust_attribution_endorser  — re-routes every direct ⊥→sink used-edge through
                                 a D-role endorser.  Blocks D-avoiding reachability
                                 → evades f_flow (P3/H5).

  trust_attribution_endorser_all — the general form: routes every out-edge of
                                 every ⊥ entity through an endorser, so it also
                                 silences indirect flows.  Not in the published
                                 sweep; on that corpus every witness is direct.

  trust_attribution_relabel   — relabels every ⊥ entity as ⊤.  Empties U_src
                                 → evades f_flow (P3/H5).
"""
from __future__ import annotations

import networkx as nx

from flint.layer1_graph.flow import get_sinks, get_untrusted_sources
from flint.layer2_detectors.f_emb import MAX_CANONICAL_OUT
from flint.spec import ENDORSER, INTEGRITY_KEY, NEUTRAL, ROLE_KEY, TRUSTED, UNTRUSTED


def _fresh_id(H: nx.DiGraph, base: str) -> str:
    """``base``, or ``base`` plus a suffix if the graph already has that node.

    Adding an inserted node under an existing id would silently merge the two
    and rewrite the original node's attributes.
    """
    node_id, k = base, 0
    while node_id in H:
        k += 1
        node_id = f"{base}~{k}"
    return node_id


def structural_mimicry(G: nx.DiGraph) -> nx.DiGraph:
    """Push every ⊥ entity's used-out degree above MAX_CANONICAL_OUT.

    Adds enough decoy neutral activities so the total number of `used` out-edges
    on each ⊥ entity exceeds MAX_CANONICAL_OUT, guaranteeing its WL 1-hop hash
    falls outside CANONICAL_INJECTION_HASHES (P2).  The original ⊥→sink flow
    path is left intact, so f_flow still detects (P1).
    """
    H = G.copy()
    decoy_idx = 0
    for src in get_untrusted_sources(H):
        current_used = sum(
            1 for nb in H.successors(src)
            if H.edges[src, nb].get("relation") == "used"
        )
        # Skip entities not yet in the flow path; adding decoys to them would
        # accidentally produce a canonical hash rather than escape it.
        if current_used == 0:
            continue
        n_decoys = MAX_CANONICAL_OUT + 1 - current_used
        for _ in range(n_decoys):
            decoy_id = _fresh_id(H, f"_decoy_neutral_{decoy_idx}")
            decoy_idx += 1
            H.add_node(decoy_id, node_type="activity", **{ROLE_KEY: NEUTRAL})
            H.add_edge(src, decoy_id, relation="used")
    return H


def structural_mimicry_budget(G: nx.DiGraph, n_decoys: int) -> nx.DiGraph:
    """Add exactly n_decoys decoy-activity nodes per ⊥ entity (parametric budget).

    Unlike structural_mimicry (which targets a specific canonical-hash threshold),
    this version adds a fixed number of decoys regardless of current degree.  Used
    for the evasion-budget sweep: n_decoys=0 is identity; n_decoys ≥ 3 guarantees
    evasion of f_emb for entities starting at k=1 used-out edges.

    f_flow is unaffected at any budget because no existing edges are removed.
    """
    if n_decoys <= 0:
        return G.copy()
    H = G.copy()
    decoy_idx = 0
    for src in get_untrusted_sources(H):
        current_used = sum(
            1 for nb in H.successors(src)
            if H.edges[src, nb].get("relation") == "used"
        )
        if current_used == 0:
            continue
        for _ in range(n_decoys):
            decoy_id = _fresh_id(H, f"_decoy_budget_{decoy_idx}")
            decoy_idx += 1
            H.add_node(decoy_id, node_type="activity", **{ROLE_KEY: NEUTRAL})
            H.add_edge(src, decoy_id, relation="used")
    return H


def trust_attribution_endorser(G: nx.DiGraph) -> nx.DiGraph:
    """Re-route every ⊥→sink used-edge through a freshly inserted D-role endorser.

    Removes each direct ⊥ entity → sink edge and replaces it with:
      ⊥ entity  --used-->        endorser (D)
      endorser  --wasInformedBy--> sink

    The D-avoiding reachability check skips endorser nodes, so no D-avoiding
    path from ⊥ to sink exists → f_flow(H) = False.
    """
    H = G.copy()
    sinks = get_sinks(H)
    sources = set(get_untrusted_sources(H))
    endorser_id = _fresh_id(H, "_adversary_endorser")
    H.add_node(endorser_id, node_type="activity", **{ROLE_KEY: ENDORSER})

    to_remove = [
        (u, v)
        for u, v, d in H.edges(data=True)
        if u in sources and v in sinks and d.get("relation") == "used"
    ]
    for u, v in to_remove:
        H.remove_edge(u, v)
        H.add_edge(u, endorser_id, relation="used")
        H.add_edge(endorser_id, v, relation="wasInformedBy")

    return H


def trust_attribution_endorser_all(G: nx.DiGraph) -> nx.DiGraph:
    """Route every flow out of every ⊥ entity through a fabricated endorser.

    The general form of ``trust_attribution_endorser``, which reroutes only
    *direct* ⊥→sink ``used`` edges and so leaves an indirect flow
    (⊥ → activity → entity → sink) standing. Here each out-edge of each ⊥
    entity is replaced by a hop through one inserted D-role endorser:

      ⊥ entity --used--> endorser (D) --wasInformedBy--> activity   (was used)
      ⊥ entity --used--> endorser (D) --wasGeneratedBy--> entity    (was wasDerivedFrom)

    Every flow path from a ⊥ entity starts with one of its out-edges, so every
    such path now passes through D and f_flow(H) = False on any graph. The
    published sweep uses ``trust_attribution_endorser``; on the AgentDojo-PROV
    corpus every witness is direct, so the two agree there.
    """
    H = G.copy()
    sources = get_untrusted_sources(H)
    endorser_id = _fresh_id(H, "_adversary_endorser_all")
    H.add_node(endorser_id, node_type="activity", **{ROLE_KEY: ENDORSER})
    for u in sources:
        for v in list(H.successors(u)):
            if v == endorser_id:
                continue
            H.remove_edge(u, v)
            H.add_edge(u, endorser_id, relation="used")
            onward = "wasGeneratedBy" if H.nodes[v].get("node_type") == "entity" else "wasInformedBy"
            H.add_edge(endorser_id, v, relation=onward)
    return H


def trust_attribution_relabel(G: nx.DiGraph) -> nx.DiGraph:
    """Relabel every ⊥ entity as ⊤ (trusted).

    Empties U_src → no starting nodes for the flow check → f_flow(H) = False.
    The structural pattern of each entity node is unchanged, so f_emb (which
    ignores integrity labels) still detects based on neighborhood hash.
    """
    H = G.copy()
    for n in H.nodes():
        if H.nodes[n].get(INTEGRITY_KEY) == UNTRUSTED:
            H.nodes[n][INTEGRITY_KEY] = TRUSTED
    return H
