"""PROV-JSON → NetworkX DiGraph loader.

Edges are oriented according to the FLINT flow relation (⇝):
  used(a, e)            → e → a
  wasGeneratedBy(e, a)  → a → e
  wasDerivedFrom(e2,e1) → e1 → e2
  wasInformedBy(a2,a1)  → a1 → a2

wasAssociatedWith is a membership relation (agent ↔ activity) and does not
carry information flow; it is stored as a node attribute, not as an edge.
"""
from __future__ import annotations

import json
from pathlib import Path

import networkx as nx


def _add_nodes(G: nx.DiGraph, section: dict, node_type: str) -> None:
    for qid, attrs in section.items():
        G.add_node(qid, node_type=node_type, **attrs)


def load_prov_graph(doc: dict) -> nx.DiGraph:
    """Load a PROV-JSON dict into a flow-directed NetworkX DiGraph.

    Node attributes mirror the PROV-JSON attrs verbatim (prov:label,
    adprov:integrity, adprov:role, etc.) plus a synthetic node_type attribute
    ("entity", "activity", or "agent").
    """
    G = nx.DiGraph()

    _add_nodes(G, doc.get("entity", {}), "entity")
    _add_nodes(G, doc.get("activity", {}), "activity")
    _add_nodes(G, doc.get("agent", {}), "agent")

    # used(a, e)  →  e → a
    for rel in doc.get("used", {}).values():
        activity = rel["prov:activity"]
        entity = rel["prov:entity"]
        G.add_edge(entity, activity, relation="used")

    # wasGeneratedBy(e, a)  →  a → e
    for rel in doc.get("wasGeneratedBy", {}).values():
        entity = rel["prov:entity"]
        activity = rel["prov:activity"]
        G.add_edge(activity, entity, relation="wasGeneratedBy")

    # wasDerivedFrom(e2, e1)  →  e1 → e2
    for rel in doc.get("wasDerivedFrom", {}).values():
        e2 = rel["prov:generatedEntity"]
        e1 = rel["prov:usedEntity"]
        G.add_edge(e1, e2, relation="wasDerivedFrom")

    # wasInformedBy(a2, a1)  →  a1 → a2
    for rel in doc.get("wasInformedBy", {}).values():
        a2 = rel["prov:informed"]
        a1 = rel["prov:informant"]
        G.add_edge(a1, a2, relation="wasInformedBy")

    return G


def load_prov_graph_from_file(path: Path | str) -> nx.DiGraph:
    doc = json.loads(Path(path).read_text())
    return load_prov_graph(doc)
