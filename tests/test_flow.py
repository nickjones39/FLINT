"""Tests for Layer 1 (graph/flow) + Layer 2 (f_flow).

All tests use synthetic PROV-JSON documents; no model calls required.
"""
from __future__ import annotations

import networkx as nx
import pytest

from flint.layer1_graph.flow import (
    check_flow,
    d_avoiding_reachable,
    flow_witnesses,
    get_endorsers,
    get_sinks,
    get_untrusted_sources,
)
from flint.layer1_graph.load import load_prov_graph
from flint.layer2_detectors.f_flow import f_flow, f_flow_detailed

# ---------------------------------------------------------------------------
# Helpers — build synthetic PROV-JSON documents
# ---------------------------------------------------------------------------

def _injection_doc() -> dict:
    """Minimal injection trace: read emails (⊥) → send_email (sink)."""
    return {
        "prefix": {"flint": "http://flint.example.org/ns#"},
        "entity": {
            "adprov:e_user_query": {"prov:label": "user_query", "adprov:integrity": "trusted"},
            "adprov:e_email_out":  {"prov:label": "get_received_emails_output", "adprov:integrity": "untrusted"},
        },
        "activity": {
            "adprov:a_read":  {"prov:label": "get_received_emails", "adprov:role": "neutral"},
            "adprov:a_send":  {"prov:label": "send_email",           "adprov:role": "sink"},
        },
        "agent": {
            "adprov:ag_llm": {"prov:label": "llm_agent", "adprov:integrity": "trusted"},
        },
        "wasGeneratedBy": {
            "adprov:wgb1": {"prov:entity": "adprov:e_email_out", "prov:activity": "adprov:a_read", "prov:time": "T"},
        },
        "used": {
            "adprov:u1": {"prov:activity": "adprov:a_send", "prov:entity": "adprov:e_email_out", "prov:time": "T"},
        },
        "wasAssociatedWith": {
            "adprov:waw1": {"prov:activity": "adprov:a_read", "prov:agent": "adprov:ag_llm"},
            "adprov:waw2": {"prov:activity": "adprov:a_send", "prov:agent": "adprov:ag_llm"},
        },
    }


def _benign_doc() -> dict:
    """Benign read-only trace: only a calendar lookup, no sink activity."""
    return {
        "prefix": {"flint": "http://flint.example.org/ns#"},
        "entity": {
            "adprov:e_user_query": {"prov:label": "user_query", "adprov:integrity": "trusted"},
            "adprov:e_cal_out":    {"prov:label": "get_day_calendar_events_output", "adprov:integrity": "untrusted"},
        },
        "activity": {
            "adprov:a_cal": {"prov:label": "get_day_calendar_events", "adprov:role": "neutral"},
        },
        "agent": {
            "adprov:ag_llm": {"prov:label": "llm_agent", "adprov:integrity": "trusted"},
        },
        "wasGeneratedBy": {
            "adprov:wgb1": {"prov:entity": "adprov:e_cal_out", "prov:activity": "adprov:a_cal", "prov:time": "T"},
        },
    }


def _endorsed_doc() -> dict:
    """Injection trace where the flow path passes through an endorser (D).

    e_email_out → a_validate(D) → a_send(S)
    D-avoiding path does not exist → f_flow = 0.
    """
    return {
        "prefix": {"flint": "http://flint.example.org/ns#"},
        "entity": {
            "adprov:e_email_out": {"prov:label": "read_output", "adprov:integrity": "untrusted"},
        },
        "activity": {
            "adprov:a_read":     {"prov:label": "get_received_emails", "adprov:role": "neutral"},
            "adprov:a_validate": {"prov:label": "validate",            "adprov:role": "endorser"},
            "adprov:a_send":     {"prov:label": "send_email",          "adprov:role": "sink"},
        },
        "wasGeneratedBy": {
            "adprov:wgb1": {"prov:entity": "adprov:e_email_out", "prov:activity": "adprov:a_read", "prov:time": "T"},
        },
        "used": {
            # e_email_out → a_validate(D) only — no direct edge to sink
            "adprov:u1": {"prov:activity": "adprov:a_validate", "prov:entity": "adprov:e_email_out", "prov:time": "T"},
            # validate → send via wasInformedBy (activity-to-activity, through D)
        },
        "wasInformedBy": {
            "adprov:wi1": {"prov:informed": "adprov:a_send", "prov:informant": "adprov:a_validate"},
        },
    }


# ---------------------------------------------------------------------------
# load.py
# ---------------------------------------------------------------------------

class TestLoadProvGraph:
    def test_nodes_present(self):
        G = load_prov_graph(_injection_doc())
        assert "adprov:e_email_out" in G
        assert "adprov:a_send" in G
        assert "adprov:ag_llm" in G

    def test_used_edge_direction(self):
        G = load_prov_graph(_injection_doc())
        # used(a_send, e_email_out) → edge e_email_out → a_send
        assert G.has_edge("adprov:e_email_out", "adprov:a_send")

    def test_was_generated_by_edge_direction(self):
        G = load_prov_graph(_injection_doc())
        # wasGeneratedBy(e_email_out, a_read) → edge a_read → e_email_out
        assert G.has_edge("adprov:a_read", "adprov:e_email_out")

    def test_was_informed_by_edge_direction(self):
        doc = _endorsed_doc()
        G = load_prov_graph(doc)
        # wasInformedBy(a_send, a_validate) → edge a_validate → a_send
        assert G.has_edge("adprov:a_validate", "adprov:a_send")

    def test_node_attributes_preserved(self):
        G = load_prov_graph(_injection_doc())
        assert G.nodes["adprov:e_email_out"]["adprov:integrity"] == "untrusted"
        assert G.nodes["adprov:a_send"]["adprov:role"] == "sink"

    def test_agent_node_type(self):
        G = load_prov_graph(_injection_doc())
        assert G.nodes["adprov:ag_llm"]["node_type"] == "agent"


# ---------------------------------------------------------------------------
# flow.py
# ---------------------------------------------------------------------------

class TestNodeSets:
    def test_untrusted_sources(self):
        G = load_prov_graph(_injection_doc())
        sources = get_untrusted_sources(G)
        assert "adprov:e_email_out" in sources
        assert "adprov:e_user_query" not in sources

    def test_sinks(self):
        G = load_prov_graph(_injection_doc())
        sinks = get_sinks(G)
        assert "adprov:a_send" in sinks
        assert "adprov:a_read" not in sinks

    def test_endorsers(self):
        G = load_prov_graph(_endorsed_doc())
        endorsers = get_endorsers(G)
        assert "adprov:a_validate" in endorsers

    def test_no_sinks_in_benign(self):
        G = load_prov_graph(_benign_doc())
        assert len(get_sinks(G)) == 0


class TestDAvoidingReachability:
    def test_direct_path_reachable(self):
        G = load_prov_graph(_injection_doc())
        sinks = get_sinks(G)
        endorsers = get_endorsers(G)
        assert d_avoiding_reachable(G, "adprov:e_email_out", sinks, endorsers)

    def test_endorsed_path_blocked(self):
        """Path only goes through D node → not D-avoiding → not reachable."""
        G = load_prov_graph(_endorsed_doc())
        sinks = get_sinks(G)
        endorsers = get_endorsers(G)
        # e_email_out → a_validate(D) → a_send: D node blocks the path
        assert not d_avoiding_reachable(G, "adprov:e_email_out", sinks, endorsers)

    def test_trusted_source_not_reachable_as_u_src(self):
        G = load_prov_graph(_injection_doc())
        sinks = get_sinks(G)
        endorsers = get_endorsers(G)
        # e_user_query is trusted — not in U_src but let's check it can reach sink
        # (it has no edge to a_send, so should be False)
        assert not d_avoiding_reachable(G, "adprov:e_user_query", sinks, endorsers)


class TestCheckFlow:
    def test_injection_trace_flagged(self):
        """P1/P3 core: injection trace with direct ⊥→sink path → f_flow=1."""
        G = load_prov_graph(_injection_doc())
        assert check_flow(G) is True

    def test_benign_trace_cleared(self):
        """Benign read-only trace has no sink → f_flow=0."""
        G = load_prov_graph(_benign_doc())
        assert check_flow(G) is False

    def test_endorsed_trace_cleared(self):
        """Flow path only via D node → D-avoiding path absent → f_flow=0."""
        G = load_prov_graph(_endorsed_doc())
        assert check_flow(G) is False

    def test_empty_graph_cleared(self):
        G = nx.DiGraph()
        assert check_flow(G) is False


class TestFlowWitnesses:
    def test_injection_has_witness(self):
        G = load_prov_graph(_injection_doc())
        w = flow_witnesses(G)
        assert len(w) >= 1
        source, sink, path = w[0]
        assert source == "adprov:e_email_out"
        assert sink == "adprov:a_send"
        assert path[0] == source and path[-1] == sink

    def test_benign_no_witnesses(self):
        G = load_prov_graph(_benign_doc())
        assert flow_witnesses(G) == []


# ---------------------------------------------------------------------------
# f_flow detector (Layer 2)
# ---------------------------------------------------------------------------

class TestFFlowDetector:
    def test_f_flow_flags_injection(self):
        G = load_prov_graph(_injection_doc())
        assert f_flow(G) is True

    def test_f_flow_clears_benign(self):
        G = load_prov_graph(_benign_doc())
        assert f_flow(G) is False

    def test_f_flow_detailed_contains_witnesses(self):
        G = load_prov_graph(_injection_doc())
        result = f_flow_detailed(G)
        assert result.detected is True
        assert result.n_sinks == 1
        assert result.n_sources >= 1
        assert len(result.witnesses) >= 1

    def test_f_flow_detailed_bool_coercion(self):
        G = load_prov_graph(_injection_doc())
        result = f_flow_detailed(G)
        assert bool(result) is True



# ---------------------------------------------------------------------------
# S and D are sets of activities (v0.2.1)
# ---------------------------------------------------------------------------

class TestRolesOnlyCountOnActivities:
    def _graph(self, role_holder_type: str, role: str) -> nx.DiGraph:
        G = nx.DiGraph()
        G.add_node("u", node_type="entity", **{"adprov:integrity": "untrusted"})
        G.add_node("x", node_type=role_holder_type, **{"adprov:role": role})
        G.add_node("s", node_type="activity", **{"adprov:role": "sink"})
        G.add_edge("u", "x")
        G.add_edge("x", "s")
        return G

    @pytest.mark.parametrize("holder", ["entity", "agent"])
    def test_non_activity_endorser_does_not_block(self, holder):
        G = self._graph(holder, "endorser")
        assert get_endorsers(G) == frozenset()
        assert f_flow(G)

    def test_activity_endorser_still_blocks(self):
        G = self._graph("activity", "endorser")
        assert get_endorsers(G) == frozenset({"x"})
        assert not f_flow(G)

    @pytest.mark.parametrize("holder", ["entity", "agent"])
    def test_non_activity_sink_is_not_a_sink(self, holder):
        G = self._graph(holder, "sink")
        assert get_sinks(G) == frozenset({"s"})

    def test_untyped_node_is_neither(self):
        G = nx.DiGraph()
        G.add_node("x", **{"adprov:role": "sink"})
        G.add_node("y", **{"adprov:role": "endorser"})
        assert get_sinks(G) == get_endorsers(G) == frozenset()


class TestReachabilityEdges:
    def test_source_that_is_a_target(self):
        G = nx.DiGraph()
        G.add_node("a")
        assert d_avoiding_reachable(G, "a", frozenset({"a"}), frozenset())

    def test_no_sinks_short_circuits(self):
        G = load_prov_graph(_benign_doc())
        assert not check_flow(G)
        assert flow_witnesses(G) == []
