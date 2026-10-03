"""Property-based and metamorphic tests (hypothesis).

Random PROV-JSON documents, mostly well-typed and sometimes not, with every kind
of valid, missing and invalid label. Each property must hold for all of them.
"""
from __future__ import annotations

import copy
import time
from collections import deque
from itertools import pairwise

import networkx as nx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import flint
from flint import ProvFormatError, f_flow, f_flow_detailed, load_prov_graph
from flint.layer1_graph.flow import (
    check_flow,
    flow_witnesses,
    get_endorsers,
    get_sinks,
    get_untrusted_sources,
)
from flint.layer2_detectors.f_emb import f_emb
from flint.layer3_orchestration.adversary import (
    structural_mimicry,
    structural_mimicry_budget,
    trust_attribution_endorser,
    trust_attribution_relabel,
)

PROPS = settings(max_examples=300, deadline=None, suppress_health_check=list(HealthCheck))

_INTEGRITY = st.sampled_from([
    "trusted", "untrusted", None, "Trusted", {"$": "untrusted", "type": "xsd:string"}, ["untrusted"],
])
_ROLE = st.sampled_from(["neutral", "sink", "endorser", None, "Sink", {"$": "sink"}])


@st.composite
def prov_docs(draw) -> dict:
    E = [f"adprov:e{i}" for i in range(draw(st.integers(0, 6)))]
    A = [f"adprov:a{i}" for i in range(draw(st.integers(0, 6)))]
    doc: dict = {"prefix": {"adprov": flint.ADPROV_NS}, "entity": {}, "activity": {},
                 "agent": {"adprov:ag": {}}}
    for e in E:
        v = draw(_INTEGRITY)
        doc["entity"][e] = {} if v is None else {"adprov:integrity": v}
    for a in A:
        v = draw(_ROLE)
        doc["activity"][a] = {} if v is None else {"adprov:role": v}
    anything = E + A + ["adprov:ghost"] * draw(st.integers(0, 1))
    mistyped = draw(st.booleans()) and draw(st.booleans())

    def rel(kind: str, f1: str, f2: str, pool1: list, pool2: list, n: int) -> None:
        if mistyped:
            pool1 = pool2 = anything
        if pool1 and pool2 and n:
            doc[kind] = {f"adprov:{kind}{i}": {f1: draw(st.sampled_from(pool1)),
                                               f2: draw(st.sampled_from(pool2))} for i in range(n)}

    rel("used", "prov:activity", "prov:entity", A, E, draw(st.integers(0, 8)))
    rel("wasGeneratedBy", "prov:entity", "prov:activity", E, A, draw(st.integers(0, 8)))
    rel("wasDerivedFrom", "prov:generatedEntity", "prov:usedEntity", E, E, draw(st.integers(0, 4)))
    rel("wasInformedBy", "prov:informed", "prov:informant", A, A, draw(st.integers(0, 4)))
    return doc


def _load(doc: dict, strict: bool) -> nx.DiGraph | None:
    try:
        return load_prov_graph(doc, strict=strict)
    except ProvFormatError:
        return None


# ---------------------------------------------------------------------------
# Reference implementation: the per-(source, sink) BFS of 0.2.0, kept as an
# oracle for the linear-time search that replaced it.
# ---------------------------------------------------------------------------

def _reference_path(G, source, target, endorsers):
    if source == target:
        return [source]
    visited, queue = {source}, deque([[source]])
    while queue:
        path = queue.popleft()
        for nbr in G.successors(path[-1]):
            if nbr == target:
                return [*path, nbr]
            if nbr not in visited and nbr not in endorsers:
                visited.add(nbr)
                queue.append([*path, nbr])
    return None


def _reference_witnesses(G):
    sinks, endorsers = get_sinks(G), get_endorsers(G)
    out = []
    for source in get_untrusted_sources(G):
        for sink in sinks:
            path = _reference_path(G, source, sink, endorsers)
            if path is not None:
                out.append((source, sink, path))
    return out


@PROPS
@given(prov_docs())
def test_linear_search_matches_reference(doc):
    G = _load(doc, False)
    if G is None:
        return
    reference = _reference_witnesses(G)
    assert flow_witnesses(G) == reference          # same paths, same order
    assert check_flow(G) == bool(reference)


@PROPS
@given(prov_docs())
def test_witnesses_are_shortest_and_complete(doc):
    G = _load(doc, False)
    if G is None:
        return
    r = f_flow_detailed(G)
    assert r.detected == f_flow(G)
    D = get_endorsers(G)
    H = G.subgraph(set(G) - D)
    found = set()
    for u, s, path in r.witnesses:
        found.add((u, s))
        assert path[0] == u and path[-1] == s
        assert not set(path[1:-1]) & D
        assert all(G.has_edge(a, b) for a, b in pairwise(path))
        assert len(path) - 1 == nx.shortest_path_length(H, u, s)
    for u in get_untrusted_sources(G):
        for s in get_sinks(G):
            if nx.has_path(H, u, s):
                assert (u, s) in found


# ---------------------------------------------------------------------------
# Strict mode
# ---------------------------------------------------------------------------

@PROPS
@given(prov_docs())
def test_strict_never_detects_less(doc):
    """Fail-closed: where both modes load, strict detects at least what default does."""
    d, s = _load(doc, False), _load(doc, True)
    if d is not None and s is not None:
        assert f_flow(s) >= f_flow(d)


@PROPS
@given(prov_docs())
def test_strict_graphs_are_fully_labelled(doc):
    G = _load(doc, True)
    if G is None:
        return
    for _, d in G.nodes(data=True):
        assert d["node_type"] in {"entity", "activity", "agent"}
        if d["node_type"] == "entity":
            assert d[flint.INTEGRITY_KEY] in flint.INTEGRITY_VALUES
        if d["node_type"] == "activity":
            assert d[flint.ROLE_KEY] in flint.ROLE_VALUES


# ---------------------------------------------------------------------------
# Metamorphic
# ---------------------------------------------------------------------------

@PROPS
@given(prov_docs(), st.randoms(use_true_random=False))
def test_renaming_and_reordering_preserve_the_verdict(doc, rnd):
    ids = sorted({k for sec in ("entity", "activity", "agent") for k in doc[sec]} | {"adprov:ghost"})
    shuffled = ids[:]
    rnd.shuffle(shuffled)
    rename = {old: f"adprov:z{i}" for i, old in enumerate(shuffled)}

    def ren(o):
        if isinstance(o, dict):
            items = list(o.items())
            rnd.shuffle(items)
            return {rename.get(k, k): ren(v) for k, v in items}
        return rename.get(o, o) if isinstance(o, str) else o

    for strict in (False, True):
        G, G2 = _load(doc, strict), _load(ren(doc), strict)
        assert (G is None) == (G2 is None)
        if G is not None:
            assert f_flow(G) == f_flow(G2)


@PROPS
@given(prov_docs())
def test_unrelated_trusted_material_does_not_change_the_verdict(doc):
    for strict in (False, True):
        G = _load(doc, strict)
        if G is None:
            continue
        d2 = copy.deepcopy(doc)
        d2["entity"]["adprov:extra_t"] = {"adprov:integrity": "trusted"}
        d2["activity"]["adprov:extra_n"] = {"adprov:role": "neutral"}
        d2.setdefault("used", {})["adprov:extra_u"] = {
            "prov:activity": "adprov:extra_n", "prov:entity": "adprov:extra_t"}
        G2 = _load(d2, strict)
        assert G2 is not None and f_flow(G2) == f_flow(G)


# ---------------------------------------------------------------------------
# Adversaries (P1 / P3) on arbitrary graphs
# ---------------------------------------------------------------------------

@PROPS
@given(prov_docs())
def test_adversary_invariants(doc):
    G = _load(doc, False)
    if G is None:
        return
    before = nx.node_link_data(G, edges="links")
    base = f_flow(G)
    assert f_flow(structural_mimicry(G)) == base                    # P1
    for k in (0, 1, 4):
        assert f_flow(structural_mimicry_budget(G, k)) == base
    assert not f_flow(trust_attribution_relabel(G))                 # P3
    assert f_flow(trust_attribution_endorser(G)) <= base
    assert f_emb(trust_attribution_relabel(G)) == f_emb(G)          # relabel is invisible to structure
    assert nx.node_link_data(G, edges="links") == before            # inputs untouched


# ---------------------------------------------------------------------------
# Robustness: arbitrary JSON only ever raises ProvFormatError
# ---------------------------------------------------------------------------

_KEYS = st.sampled_from([
    "entity", "activity", "agent", "used", "wasGeneratedBy", "wasDerivedFrom", "wasInformedBy",
    "prefix", "bundle", "prov:activity", "prov:entity", "prov:usedEntity", "prov:generatedEntity",
    "prov:informed", "prov:informant", "adprov:integrity", "adprov:role", "$", "adprov",
    "node_type", "adprov:e", "adprov:a",
]) | st.text(max_size=3)
_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=5) | st.floats(allow_nan=False),
    lambda c: st.lists(c, max_size=4) | st.dictionaries(_KEYS, c, max_size=5),
    max_leaves=40,
)


@PROPS
@given(_JSON, st.booleans())
def test_arbitrary_json_only_raises_prov_format_error(doc, strict):
    try:
        G = load_prov_graph(doc, strict=strict)
    except ProvFormatError:
        return
    f_flow_detailed(G)
    f_emb(G)
    structural_mimicry(G)
    trust_attribution_endorser(G)
    trust_attribution_relabel(G)


# ---------------------------------------------------------------------------
# Scaling: linear in graph size however many untrusted sources there are
# ---------------------------------------------------------------------------

def _session(steps: int, flow: bool) -> nx.DiGraph:
    """Every step reads an untrusted tool output; no sink is reachable unless flow."""
    G = nx.DiGraph()
    for i in range(steps):
        G.add_node(f"a{i}", node_type="activity", **{"adprov:role": "neutral"})
        G.add_node(f"e{i}", node_type="entity", **{"adprov:integrity": "untrusted"})
        G.add_edge(f"a{i}", f"e{i}", relation="wasGeneratedBy")
        if i:
            G.add_edge(f"a{i - 1}", f"a{i}", relation="wasInformedBy")
            G.add_edge(f"e{i - 1}", f"a{i}", relation="used")
    G.add_node("s", node_type="activity", **{"adprov:role": "sink" if flow else "neutral"})
    G.add_edge(f"a{steps - 1}", "s", relation="wasInformedBy")
    G.add_node("unreachable_sink", node_type="activity", **{"adprov:role": "sink"})
    return G


def test_many_sources_stay_linear():
    # 0.2.0 needed ~3 s for 4,000 steps and grew quadratically; this is ~20,000 steps.
    G = _session(10_000, flow=False)
    t = time.perf_counter()
    assert not f_flow(G)
    assert time.perf_counter() - t < 1.0


@pytest.mark.parametrize("steps", [2, 3, 50])
def test_session_witnesses_reach_the_sink(steps):
    G = _session(steps, flow=True)
    r = f_flow_detailed(G)
    assert r.detected and r.n_sources == steps
    # every output but the last is consumed downstream, so steps - 1 of them reach s
    assert sorted(u for u, s, _ in r.witnesses) == sorted(f"e{i}" for i in range(steps - 1))
    assert {s for _, s, _ in r.witnesses} == {"s"}


def test_detailed_scales_with_many_sources():
    G = _session(2_000, flow=True)          # 0.2.0: ~11 s at this size
    t = time.perf_counter()
    assert len(f_flow_detailed(G).witnesses) == 1_999
    assert time.perf_counter() - t < 10.0
