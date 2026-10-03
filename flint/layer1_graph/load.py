"""PROV-JSON → NetworkX DiGraph loader.

Edges are oriented according to the FLINT flow relation (⇝):
  used(a, e)            → e → a
  wasGeneratedBy(e, a)  → a → e
  wasDerivedFrom(e2,e1) → e1 → e2
  wasInformedBy(a2,a1)  → a1 → a2

wasAssociatedWith, wasAttributedTo and actedOnBehalfOf do not carry
information flow and are ignored: they produce neither an edge nor a node
attribute.

A record may be one JSON object or, as PROV-JSON allows when several records
share an identifier, a list of objects. Every instance of a flow relation becomes
an edge; the instances of a node are merged into one node.

Two modes
---------
``strict=False`` (default) is the loader the published results were produced
with. On a well-formed document its output is unchanged. It only replaces the
crashes a malformed document used to cause with ``ProvFormatError``, unwraps
typed literals on the two labels the detector reads, and accepts the list form
above. Sections it does not model (bundles, other PROV relations) are ignored.

``strict=True`` is for deployment, where nothing the producer wrote may be
silently dropped. It reads the input specification (docs/input-format.md)
fail-closed:

  * an entity whose ``adprov:integrity`` is missing or not a known value is
    loaded as ``untrusted`` (⊥), and marked with ``flint:integrity_defaulted``;
  * an activity whose ``adprov:role`` is missing or not a known value is
    rejected — guessing "neutral" could hide a sink, guessing "sink" would
    make every unlabelled step an alarm;
  * an ``adprov:role`` on an entity or agent is rejected: S and D are sets of
    activities, so the label can only be a producer bug;
  * a top-level section outside the known set is rejected — a ``bundle`` or a
    PROV relation FLINT does not model (``wasStartedBy``, ``hadMember``,
    ``wasInfluencedBy``, …) could carry a flow the detector would never see;
  * a relation that names an undeclared node, or a node of the wrong PROV
    type, is rejected — such a node has no type, so it could never be a source;
  * an identifier declared in two node sections, or with conflicting labels
    across its instances, is rejected;
  * a document that binds ``adprov`` to a foreign URI, or the ``adprov``
    namespace to another prefix, is rejected — its labels would not be read.
"""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
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

# PROV relations that carry no information flow; accepted and ignored in both modes.
_NON_FLOW_RELATIONS: frozenset[str] = frozenset(
    {"wasAssociatedWith", "wasAttributedTo", "actedOnBehalfOf"}
)

# Every top-level section strict mode accepts.
STRICT_SECTIONS: frozenset[str] = frozenset(
    {"prefix"}
    | {name for name, _ in _NODE_SECTIONS}
    | {rel[0] for rel in _FLOW_RELATIONS}
    | _NON_FLOW_RELATIONS
)

# Node attributes the loader writes itself; a document may not supply them.
_RESERVED_ATTRS: frozenset[str] = frozenset({"node_type"})

# Fields PROV-DM lets a producer omit, but without which FLINT cannot place the edge.
_OPTIONAL_IN_PROV: frozenset[tuple[str, str]] = frozenset(
    {("used", "prov:entity"), ("wasGeneratedBy", "prov:activity")}
)


def _section(doc: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    section = doc.get(name, {})
    if not isinstance(section, Mapping):
        raise ProvFormatError(f"'{name}' must be an object, got {type(section).__name__}")
    return section


def _instances(kind: str, qid: object, value: object) -> Sequence[Mapping[str, Any]]:
    """The instances of one record: a single object, or a non-empty list of objects."""
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list) and value and all(isinstance(v, Mapping) for v in value):
        return value
    raise ProvFormatError(f"{kind} {qid!r}: must be an object or a non-empty list of objects")


def _check_sections(doc: Mapping[str, Any]) -> None:
    for name in doc:
        if name in STRICT_SECTIONS:
            continue
        if name == "bundle":
            raise ProvFormatError(
                "bundles are not supported: a flow inside a bundle would not be checked"
            )
        raise ProvFormatError(
            f"section {name!r} is not one FLINT models; a flow it expresses would not "
            f"be checked (accepted: {sorted(STRICT_SECTIONS)})"
        )


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


def _merge_instances(
    qid: str, node_type: str, instances: Sequence[Mapping[str, Any]], strict: bool
) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for inst in instances:
        for key, value in inst.items():
            if not isinstance(key, str):
                raise ProvFormatError(f"{node_type} {qid!r}: attribute name {key!r} is not a string")
            if key in _RESERVED_ATTRS:
                raise ProvFormatError(f"{node_type} {qid!r}: attribute {key!r} is reserved by FLINT")
            if (strict and key in (INTEGRITY_KEY, ROLE_KEY) and key in merged
                    and literal_value(merged[key]) != literal_value(value)):
                raise ProvFormatError(
                    f"{node_type} {qid!r}: instances disagree on {key} "
                    f"({merged[key]!r} vs {value!r})"
                )
            merged[key] = value
    return merged


def _node_attrs(qid: str, attrs: dict[str, Any], node_type: str, strict: bool) -> dict[str, Any]:
    out = dict(attrs)
    for key in (INTEGRITY_KEY, ROLE_KEY):
        if key in out:
            out[key] = literal_value(out[key])
    if not strict:
        return out

    if node_type != "activity" and ROLE_KEY in out:
        raise ProvFormatError(
            f"{node_type} {qid!r}: {ROLE_KEY} is only meaningful on activities"
        )
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


def _endpoint(rel_name: str, rid: object, rel: Mapping[str, Any], field: str) -> str:
    if field not in rel:
        hint = (
            " (PROV allows omitting it, but FLINT cannot place a flow through an "
            "unidentified node)" if (rel_name, field) in _OPTIONAL_IN_PROV else ""
        )
        raise ProvFormatError(f"{rel_name} {rid!r}: missing '{field}'{hint}")
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
        _check_sections(doc)
        _check_prefixes(doc)

    G: nx.DiGraph[str] = nx.DiGraph()
    for section_name, node_type in _NODE_SECTIONS:
        for qid, value in _section(doc, section_name).items():
            if not isinstance(qid, str):
                raise ProvFormatError(f"{node_type} identifier {qid!r} is not a string")
            if strict and qid in G:
                raise ProvFormatError(
                    f"{qid!r} is declared as both {G.nodes[qid]['node_type']} and {node_type}"
                )
            attrs = _merge_instances(qid, node_type, _instances(node_type, qid, value), strict)
            G.add_node(qid, **{"node_type": node_type, **_node_attrs(qid, attrs, node_type, strict)})

    for rel_name, src_field, src_type, dst_field, dst_type in _FLOW_RELATIONS:
        for rid, value in _section(doc, rel_name).items():
            for rel in _instances(rel_name, rid, value):
                src = _endpoint(rel_name, rid, rel, src_field)
                dst = _endpoint(rel_name, rid, rel, dst_field)
                if strict:
                    for node, field, expected in (
                        (src, src_field, src_type), (dst, dst_field, dst_type)
                    ):
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
    """Read a PROV-JSON file (UTF-8, as RFC 8259 requires) and load it."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return load_prov_graph(doc, strict=strict)
