"""P1/P2/P3 claim tests: adversarial evasion.

P1 (H2): structural_mimicry cannot evade f_flow — the flow path persists.
P2 (H1): structural_mimicry CAN evade f_emb — neighborhood hash changes.
P3 (H5): evading f_flow requires trust-attribution (endorser insertion or
         integrity relabelling), not structural change alone.

All tests use synthetic PROV-JSON traces; no model calls required.
"""
from __future__ import annotations

import pytest
import networkx as nx

from flint.layer1_graph.load import load_prov_graph
from flint.layer1_graph.flow import get_sinks, get_untrusted_sources
from flint.layer2_detectors.f_flow import f_flow
from flint.layer2_detectors.f_emb import f_emb, _INJECTION_HASH, _structural_node_hash
from flint.layer3_orchestration.adversary import (
    structural_mimicry,
    trust_attribution_endorser,
    trust_attribution_relabel,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _injection_doc() -> dict:
    """Minimal injection trace: read emails (⊥) → send_email (sink)."""
    return {
        "prefix": {"flint": "http://flint.example.org/ns#"},
        "entity": {
            "adprov:e_user_query": {"prov:label": "user_query",                       "adprov:integrity": "trusted"},
            "adprov:e_email_out":  {"prov:label": "get_received_emails_output",        "adprov:integrity": "untrusted"},
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
    }


def _benign_doc() -> dict:
    """Benign read-only trace: calendar lookup, no sink."""
    return {
        "prefix": {"flint": "http://flint.example.org/ns#"},
        "entity": {
            "adprov:e_user_query": {"prov:label": "user_query",                          "adprov:integrity": "trusted"},
            "adprov:e_cal_out":    {"prov:label": "get_day_calendar_events_output",       "adprov:integrity": "untrusted"},
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


# ---------------------------------------------------------------------------
# Baseline sanity: both detectors work on raw graphs
# ---------------------------------------------------------------------------

class TestBaselineDetection:
    def test_f_flow_flags_injection(self):
        G = load_prov_graph(_injection_doc())
        assert f_flow(G) is True

    def test_f_flow_clears_benign(self):
        G = load_prov_graph(_benign_doc())
        assert f_flow(G) is False

    def test_f_emb_flags_injection(self):
        G = load_prov_graph(_injection_doc())
        assert f_emb(G) is True

    def test_f_emb_clears_benign(self):
        G = load_prov_graph(_benign_doc())
        assert f_emb(G) is False

    def test_injection_entity_matches_canonical_hash(self):
        """e_email_out has exactly the injection structural signature."""
        G = load_prov_graph(_injection_doc())
        h = _structural_node_hash(G, "adprov:e_email_out")
        assert h == _INJECTION_HASH

    def test_benign_entity_does_not_match_hash(self):
        G = load_prov_graph(_benign_doc())
        h = _structural_node_hash(G, "adprov:e_cal_out")
        assert h != _INJECTION_HASH


# ---------------------------------------------------------------------------
# P1 (H2): structural_mimicry cannot evade f_flow
# ---------------------------------------------------------------------------

class TestP1StructuralMimicryCannotEvadeFFlow:
    def test_f_flow_still_flags_after_mimicry(self):
        """P1: structural change leaves the ⊥→sink flow path intact."""
        G = load_prov_graph(_injection_doc())
        H = structural_mimicry(G)
        assert f_flow(H) is True

    def test_original_flow_edge_survives(self):
        """Direct ⊥ entity → sink edge must not be touched by mimicry."""
        G = load_prov_graph(_injection_doc())
        H = structural_mimicry(G)
        assert H.has_edge("adprov:e_email_out", "adprov:a_send")

    def test_mimicry_adds_decoy_nodes(self):
        G = load_prov_graph(_injection_doc())
        H = structural_mimicry(G)
        assert H.number_of_nodes() > G.number_of_nodes()

    def test_mimicry_adds_extra_used_edge(self):
        G = load_prov_graph(_injection_doc())
        H = structural_mimicry(G)
        email_out_successors = list(H.successors("adprov:e_email_out"))
        assert len(email_out_successors) >= 2  # original sink + at least one decoy


# ---------------------------------------------------------------------------
# P2 (H1): structural_mimicry CAN evade f_emb
# ---------------------------------------------------------------------------

class TestP2StructuralMimicryEvadesFeEmb:
    def test_f_emb_misses_after_mimicry(self):
        """P2: extra used out-edge changes the neighborhood hash → no match."""
        G = load_prov_graph(_injection_doc())
        H = structural_mimicry(G)
        assert f_emb(H) is False

    def test_hash_changes_after_mimicry(self):
        G = load_prov_graph(_injection_doc())
        H = structural_mimicry(G)
        h_before = _structural_node_hash(G, "adprov:e_email_out")
        h_after = _structural_node_hash(H, "adprov:e_email_out")
        assert h_before == _INJECTION_HASH
        assert h_after != _INJECTION_HASH

    def test_divergence_p1_p2(self):
        """Core P1/P2 result: after mimicry f_flow detects; f_emb does not."""
        G = load_prov_graph(_injection_doc())
        H = structural_mimicry(G)
        assert f_flow(H) is True    # P1
        assert f_emb(H) is False    # P2


# ---------------------------------------------------------------------------
# P3 (H5): evading f_flow requires trust-attribution, not structural change
# ---------------------------------------------------------------------------

class TestP3TrustAttributionEvadesFFlow:
    def test_structural_mimicry_cannot_evade_f_flow(self):
        """P3 necessary condition: structural-only change is insufficient."""
        G = load_prov_graph(_injection_doc())
        H = structural_mimicry(G)
        assert f_flow(H) is True

    def test_endorser_evades_f_flow(self):
        """P3: inserting a D-node on the path blocks D-avoiding reachability."""
        G = load_prov_graph(_injection_doc())
        H = trust_attribution_endorser(G)
        assert f_flow(H) is False

    def test_relabel_evades_f_flow(self):
        """P3: relabelling ⊥→⊤ empties U_src → no flow detected."""
        G = load_prov_graph(_injection_doc())
        H = trust_attribution_relabel(G)
        assert f_flow(H) is False

    def test_endorser_preserves_f_emb_detection(self):
        """Trust-attribution via endorser: structural pattern unchanged → f_emb still flags."""
        G = load_prov_graph(_injection_doc())
        H = trust_attribution_endorser(G)
        # ⊥ entity now has: wasGeneratedBy-in + used-out (to endorser) — same hash
        assert f_emb(H) is True

    def test_relabel_preserves_f_emb_detection(self):
        """Relabelling changes integrity semantics but not graph structure → f_emb still flags."""
        G = load_prov_graph(_injection_doc())
        H = trust_attribution_relabel(G)
        assert f_emb(H) is True

    def test_endorser_removes_direct_sink_edge(self):
        """Endorser variant must remove the direct ⊥→sink path."""
        G = load_prov_graph(_injection_doc())
        H = trust_attribution_endorser(G)
        assert not H.has_edge("adprov:e_email_out", "adprov:a_send")

    def test_endorser_inserts_d_node(self):
        G = load_prov_graph(_injection_doc())
        H = trust_attribution_endorser(G)
        endorsers = [n for n, d in H.nodes(data=True) if d.get("adprov:role") == "endorser"]
        assert len(endorsers) >= 1

    def test_relabel_empties_untrusted_sources(self):
        G = load_prov_graph(_injection_doc())
        H = trust_attribution_relabel(G)
        from flint.layer1_graph.flow import get_untrusted_sources
        assert len(get_untrusted_sources(H)) == 0
