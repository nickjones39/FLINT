"""P1/P2/P3 claim tests: adversarial evasion.

P1 (H2): structural_mimicry cannot evade f_flow — the flow path persists.
P2 (H1): structural_mimicry CAN evade f_emb — neighborhood hash changes.
P3 (H5): evading f_flow requires trust-attribution (endorser insertion or
         integrity relabelling), not structural change alone.

All tests use synthetic PROV-JSON traces; no model calls required.
"""
from __future__ import annotations

import networkx as nx
import pytest

from flint.layer1_graph.flow import get_endorsers, get_untrusted_sources
from flint.layer1_graph.load import load_prov_graph
from flint.layer2_detectors.f_emb import (
    _INJECTION_HASH,
    _structural_node_hash,
    build_benign_profile,
    f_emb,
    f_emb_novelty,
    f_emb_novelty_score,
    f_emb_score,
)
from flint.layer2_detectors.f_flow import f_flow
from flint.layer3_orchestration.adversary import (
    structural_mimicry,
    structural_mimicry_budget,
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
        assert len(get_untrusted_sources(H)) == 0


# ---------------------------------------------------------------------------
# Inserted nodes never merge into existing ones; the budget variant (v0.2.1)
# ---------------------------------------------------------------------------

class TestInsertedIdsAreFresh:
    def test_endorser_id_collision_leaves_existing_node_intact(self):
        G = load_prov_graph(_injection_doc())
        G.add_node("_adversary_endorser", node_type="entity", **{"adprov:integrity": "trusted"})
        H = trust_attribution_endorser(G)
        assert H.nodes["_adversary_endorser"] == {"node_type": "entity", "adprov:integrity": "trusted"}
        assert len(get_endorsers(H)) == 1
        assert not f_flow(H)

    def test_decoy_id_collision_leaves_existing_node_intact(self):
        G = load_prov_graph(_injection_doc())
        G.add_node("_decoy_neutral_0", node_type="entity", **{"adprov:integrity": "untrusted"})
        H = structural_mimicry(G)
        assert H.nodes["_decoy_neutral_0"]["node_type"] == "entity"
        assert not f_emb(H)
        assert f_flow(H)

    def test_ids_unchanged_when_nothing_collides(self):
        H = structural_mimicry(load_prov_graph(_injection_doc()))
        assert {n for n in H if n.startswith("_decoy")} == {
            f"_decoy_neutral_{i}" for i in range(3)
        }


class TestMimicryBudget:
    def test_zero_budget_is_an_identity_copy(self):
        G = load_prov_graph(_injection_doc())
        H = structural_mimicry_budget(G, 0)
        assert H is not G
        assert nx.utils.graphs_equal(G, H)

    @pytest.mark.parametrize("k", [1, 2, 3, 5])
    def test_f_flow_unaffected_at_any_budget(self, k):
        assert f_flow(structural_mimicry_budget(load_prov_graph(_injection_doc()), k))

    def test_budget_three_evades_f_emb(self):
        assert not f_emb(structural_mimicry_budget(load_prov_graph(_injection_doc()), 3))


class TestFEmbScores:
    def test_score_bounds(self):
        G = load_prov_graph(_injection_doc())
        assert 0.0 < f_emb_score(G) <= 1.0
        assert f_emb_score(structural_mimicry(G)) == 0.0
        assert f_emb_score(nx.DiGraph()) == 0.0

    def test_novelty_against_own_profile_is_zero(self):
        G = load_prov_graph(_injection_doc())
        profile = build_benign_profile([G])
        assert not f_emb_novelty(G, profile)
        assert f_emb_novelty_score(G, profile) == 0.0

    def test_mimicry_is_novel_against_unattacked_profile(self):
        G = load_prov_graph(_injection_doc())
        profile = build_benign_profile([G])
        H = structural_mimicry(G)
        assert f_emb_novelty(H, profile)
        assert f_emb_novelty_score(H, profile) > 0.0
        assert f_emb_novelty_score(nx.DiGraph(), profile) == 0.0


class TestFEmbNonStringFeatures:
    def test_none_node_type_and_relation_do_not_crash(self):
        G = nx.DiGraph()
        G.add_node("e", node_type="entity")
        G.add_node("a", node_type=None)
        G.add_node("b", node_type="activity")
        G.add_edge("a", "e", relation="wasGeneratedBy")
        G.add_edge("b", "e", relation=None)
        assert f_emb(G) is False
        assert _structural_node_hash(G, "e") == _structural_node_hash(
            nx.relabel_nodes(G, {"a": "a2"}), "e")

    def test_string_features_hash_as_before(self):
        # the k=1 canonical shape must still produce the published constant
        G = load_prov_graph(_injection_doc())
        assert _INJECTION_HASH in {_structural_node_hash(G, n) for n in G}


# ---------------------------------------------------------------------------
# The documented scope of each adversary, and the general endorser
# ---------------------------------------------------------------------------

from flint.layer3_orchestration.adversary import trust_attribution_endorser_all  # noqa: E402


def _indirect_flow() -> nx.DiGraph:
    """u(⊥) --used--> a --wasGeneratedBy--> e2 --used--> s(sink)."""
    H = nx.DiGraph()
    H.add_node("u", node_type="entity", **{"adprov:integrity": "untrusted"})
    H.add_node("a", node_type="activity", **{"adprov:role": "neutral"})
    H.add_node("e2", node_type="entity", **{"adprov:integrity": "trusted"})
    H.add_node("s", node_type="activity", **{"adprov:role": "sink"})
    H.add_edge("u", "a", relation="used")
    H.add_edge("a", "e2", relation="wasGeneratedBy")
    H.add_edge("e2", "s", relation="used")
    return H


class TestAdversaryScope:
    def test_direct_only_endorser_leaves_an_indirect_flow(self):
        assert f_flow(trust_attribution_endorser(_indirect_flow()))

    def test_general_endorser_silences_an_indirect_flow(self):
        G = _indirect_flow()
        H = trust_attribution_endorser_all(G)
        assert f_flow(G) and not f_flow(H)
        assert H.edges["_adversary_endorser_all", "a"]["relation"] == "wasInformedBy"
        assert not G.has_node("_adversary_endorser_all")          # input untouched

    def test_general_endorser_reroutes_derivations_as_generation(self):
        G = _indirect_flow()
        G.add_node("d", node_type="entity", **{"adprov:integrity": "trusted"})
        G.add_edge("u", "d", relation="wasDerivedFrom")
        G.add_edge("d", "s", relation="used")
        H = trust_attribution_endorser_all(G)
        assert H.edges["_adversary_endorser_all", "d"]["relation"] == "wasGeneratedBy"
        assert not f_flow(H)

    def test_mimicry_does_not_evade_f_emb_through_a_trusted_canonical_entity(self):
        G = nx.DiGraph()
        G.add_node("r", node_type="activity", **{"adprov:role": "neutral"})
        G.add_node("t", node_type="entity", **{"adprov:integrity": "trusted"})
        G.add_node("s", node_type="activity", **{"adprov:role": "sink"})
        G.add_edge("r", "t", relation="wasGeneratedBy")
        G.add_edge("t", "s", relation="used")
        assert f_emb(G) and f_emb(structural_mimicry(G))
