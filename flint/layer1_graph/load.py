"""PROV-JSON → NetworkX DiGraph loader.

Edges are oriented according to the FLINT flow relation (⇝):
  used(a, e)            → e → a
  wasGeneratedBy(e, a)  → a → e
  wasDerivedFrom(e2,e1) → e1 → e2
  wasInformedBy(a2,a1)  → a1 → a2

The remaining PROV relations (wasAssociatedWith, wasAttributedTo,
actedOnBehalfOf, …) do not carry information flow and are ignored: they produce
neither an edge nor a node attribute.

Two modes
---------
``strict=False`` (default) is the loader the published results were produced
with. On a well-formed document its output is unchanged; it only replaces the
crashes a malformed document used to cause with ``ProvFormatError`` and unwraps
typed literals on the two labels the detector reads.

``strict=True`` is for deployment, where a missing label must not hide a flow.
It reads the input specification (docs/input-format.md) fail-closed:

  * an entity whose ``adprov:integrity`` is missing or not a known value is
    loaded as ``untrusted`` (⊥), and marked with ``flint:integrity_defaulted``;
  * an activity whose ``adprov:role`` is missing or not a known value is
    rejected — guessing "neutral" could hide a sink, guessing "sink" would
    make every unlabelled step an alarm;
  * a relation that names an undeclared node, or a node of the wrong PROV
    type, is rejected — such a node has no type, so it could never be a source;
  * an identifier declared in two node sections is rejected;
  * a document that binds ``adprov`` to a foreign URI, or the ``adprov``
    namespace to another prefix, is rejected — its labels would not be read.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import networkx as nx

from flint.errors import ProvFormatError
from flint.spec import (
    ADPROV_NS,
    ADPROV_PREFIX,
    INTEGRITY_DEFAULTED_KEY,
    INTEGRITY_KEY,
    INTEGRITY_VALUES,
    ROLE_KEY,
    ROLE_VALUES,
    UNTRUSTED,
    literal_value,
)

_NODE_SECTIONS: tuple[tuple[str, str], ...] = (
    ("entity", "entity"),
    ("activity", "activity"),
    ("agent", "agent"),
)

# relation → (flow-source field, its node type, flow-target field, its node type).
# The edge is added source → target, i.e. already oriented along ⇝.
_FLOW_RELATIONS: tuple[tuple[str, str, str, str, str], ...] = (
    ("used",           "prov:entity",      "entity",   "prov:activity",       "activity"),
    ("wasGeneratedBy", "prov:activity",    "activity", "prov:entity",         "entity"),
    ("wasDerivedFrom", "prov:usedEntity",  "entity",   "prov:generatedEntity", "entity"),
    ("wasInformedBy",  "prov:informant",   "activity", "prov:informed",       "activity"),
)


def _section(doc: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    section = doc.get(name, {})
    if not isinstance(section, Mapping):
        raise ProvFormatError(f"'{name}' must be an object, got {type(section).__name__}")
    return section


def _check_prefixes(doc: Mapping[str, Any]) -> None:
    prefixes = _section(doc, "prefix")
    bound = prefixes.get(ADPROV_PREFIX)
    if bound is not None and bound != ADPROV_NS:
        raise ProvFormatError(
            f"prefix '{ADPROV_PREFIX}' is bound to {bound!r}, not {ADPROV_NS!r}"
        )
    for prefix, uri in prefixes.items():
        if uri == ADPROV_NS and prefix != ADPROV_PREFIX:
            raise ProvFormatError(
                f"the adprov namespace is bound to prefix '{prefix}'; FLINT reads "
                f"labels only under '{ADPROV_PREFIX}:'"
            )


def _node_attrs(qid: str, attrs: Any, node_type: str, strict: bool) -> dict[str, Any]:
    if not isinstance(attrs, Mapping):
        raise ProvFormatError(f"{node_type} {qid!r}: attributes must be an object")
    out = dict(attrs)
    for key in (INTEGRITY_KEY, ROLE_KEY):
        if key in out:
            out[key] = literal_value(out[key])
    if not strict:
        return out

    if node_type == "entity":
        label = out.get(INTEGRITY_KEY)
        if not (isinstance(label, str) and label in INTEGRITY_VALUES):
            out[INTEGRITY_KEY] = UNTRUSTED
            out[INTEGRITY_DEFAULTED_KEY] = attrs.get(INTEGRITY_KEY)
    elif node_type == "activity":
        role = out.get(ROLE_KEY)
        if not (isinstance(role, str) and role in ROLE_VALUES):
            raise ProvFormatError(
                f"activity {qid!r}: {ROLE_KEY} is {role!r}; "
                f"expected one of {sorted(ROLE_VALUES)}"
            )
    return out


def _endpoint(rel_name: str, rid: str, rel: Mapping[str, Any], field: str) -> str:
    if field not in rel:
        raise ProvFormatError(f"{rel_name} {rid!r}: missing '{field}'")
    value = rel[field]
    if not isinstance(value, str):
        raise ProvFormatError(
            f"{rel_name} {rid!r}: '{field}' must be a qualified name, got {value!r}"
        )
    return value


def load_prov_graph(doc: Mapping[str, Any], *, strict: bool = False) -> nx.DiGraph:
    """Load a PROV-JSON document into a flow-directed NetworkX DiGraph.

    Node attributes mirror the PROV-JSON attributes (prov:label, adprov:integrity,
    adprov:role, …) plus a synthetic ``node_type`` ("entity", "activity" or
    "agent"). The two labels the detector reads are unwrapped from typed literals.
    Edges carry a ``relation`` attribute naming the PROV relation they came from.

    ``strict=True`` validates the document against docs/input-format.md and reads
    it fail-closed; see the module docstring. Raises ``ProvFormatError`` if the
    document cannot be loaded.
    """
    if not isinstance(doc, Mapping):
        raise ProvFormatError(f"a PROV-JSON document must be an object, got {type(doc).__name__}")
    if strict:
        _check_prefixes(doc)

    G: nx.DiGraph[str] = nx.DiGraph()
    for section_name, node_type in _NODE_SECTIONS:
        for qid, attrs in _section(doc, section_name).items():
            if strict and qid in G:
                raise ProvFormatError(
                    f"{qid!r} is declared as both {G.nodes[qid]['node_type']} and {node_type}"
                )
            G.add_node(qid, node_type=node_type, **_node_attrs(qid, attrs, node_type, strict))

    for rel_name, src_field, src_type, dst_field, dst_type in _FLOW_RELATIONS:
        for rid, rel in _section(doc, rel_name).items():
            if not isinstance(rel, Mapping):
                raise ProvFormatError(f"{rel_name} {rid!r}: must be an object")
            src = _endpoint(rel_name, rid, rel, src_field)
            dst = _endpoint(rel_name, rid, rel, dst_field)
            if strict:
                for node, field, expected in ((src, src_field, src_type), (dst, dst_field, dst_type)):
                    if node not in G:
                        raise ProvFormatError(
                            f"{rel_name} {rid!r}: '{field}' names undeclared node {node!r}"
                        )
                    if G.nodes[node]["node_type"] != expected:
                        raise ProvFormatError(
                            f"{rel_name} {rid!r}: '{field}' names {node!r}, a "
                            f"{G.nodes[node]['node_type']}, not an {expected}"
                        )
            G.add_edge(src, dst, relation=rel_name)

    return G


def load_prov_graph_from_file(path: Path | str, *, strict: bool = False) -> nx.DiGraph:
    """Read a PROV-JSON file and load it with ``load_prov_graph``."""
    doc = json.loads(Path(path).read_text())
    return load_prov_graph(doc, strict=strict)
