"""Verifiable trust attribution (manuscript §V): Definitions 5 and 6, Theorem 3.

The protocol logic is tested with a stdlib HMAC signer, so it runs on a
core-only install; the Ed25519 implementation has its own tests at the end.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json

import networkx as nx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import flint
from flint import (
    f_flow,
    issue_capability,
    load_prov_graph,
    sign_source_label,
    structural_mimicry,
    structural_mimicry_budget,
    trust_attribution_endorser,
    trust_attribution_endorser_all,
    trust_attribution_relabel,
    verify_attribution,
)
from flint.attribution import (
    ACTION_KEY,
    CAPABILITY_KEY,
    LABEL_SIG_KEY,
    Signer,
    Verifier,
    capability_message,
    decode_capability,
    source_label_message,
)


class HmacKey:
    """A Signer and Verifier over one shared secret; test stand-in for Ed25519."""

    def __init__(self, kid: str) -> None:
        self.kid = kid
        self.secret = hashlib.sha256(kid.encode()).digest()

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self.secret, message, hashlib.sha256).digest()


class HmacRing:
    def __init__(self, *keys: HmacKey, revoked: tuple[str, ...] = ()) -> None:
        self.keys = {k.kid: k for k in keys}
        self.revoked = set(revoked)

    def verify(self, kid: str, message: bytes, signature: bytes) -> bool:
        key = self.keys.get(kid)
        return (kid not in self.revoked and key is not None
                and hmac.compare_digest(key.sign(message), signature))


REC = HmacKey("rec-2026-10")        # sk_rec: the recorder
CAP = HmacKey("cap-2026-10")        # sk_cap: the authorising principal
LABELS, CAPS = HmacRing(REC), HmacRing(CAP)
TRACE = "application-42"


def test_stand_ins_satisfy_the_protocols():
    assert isinstance(REC, Signer)
    assert isinstance(LABELS, Verifier)


def _signed_doc(*, endorse: bool = False) -> dict:
    """query(⊤) and mail(⊥) are read; mail flows to send(S), through approve(D) if endorse."""
    doc: dict = {
        "prefix": {"adprov": flint.ADPROV_NS},
        "entity": {
            "adprov:e_query": sign_source_label(REC, "adprov:e_query", "user", "trusted", "sha256:q"),
            "adprov:e_mail": sign_source_label(REC, "adprov:e_mail", "email", "untrusted", "sha256:m"),
        },
        "activity": {
            "adprov:a_read": {"adprov:role": "neutral", ACTION_KEY: "read_email"},
            "adprov:a_send": {"adprov:role": "sink", ACTION_KEY: "send_email"},
        },
        "wasGeneratedBy": {"adprov:g1": {"prov:entity": "adprov:e_mail", "prov:activity": "adprov:a_read"}},
        "used": {"adprov:u1": {"prov:activity": "adprov:a_send", "prov:entity": "adprov:e_mail"}},
    }
    doc["entity"]["adprov:e_query"]["adprov:content_hash"] = "sha256:q"
    doc["entity"]["adprov:e_mail"]["adprov:content_hash"] = "sha256:m"
    if endorse:
        doc["activity"]["adprov:a_approve"] = {
            "adprov:role": "endorser", ACTION_KEY: "approve_send",
            CAPABILITY_KEY: issue_capability(CAP, "approve_send", {"trace": TRACE}),
        }
        doc["used"]["adprov:u1"] = {"prov:activity": "adprov:a_approve", "prov:entity": "adprov:e_mail"}
        doc["wasInformedBy"] = {"adprov:i1": {"prov:informed": "adprov:a_send", "prov:informant": "adprov:a_approve"}}
    return doc


def _verify(G: nx.DiGraph, **kw) -> flint.AttributionResult:
    return verify_attribution(G, labels=LABELS, capabilities=CAPS, **kw)


# ---------------------------------------------------------------------------
# Canonical messages
# ---------------------------------------------------------------------------

class TestMessages:
    def test_field_boundaries_are_unambiguous(self):
        assert source_label_message("ab", "c", "trusted") != source_label_message("a", "bc", "trusted")

    def test_contexts_are_domain_separated(self):
        assert not capability_message("x", {}, None, "n").startswith(b"FLINT/source-label")
        assert source_label_message("x", "", "", None)[:20] != capability_message("x", {}, None, "")[:20]

    def test_scope_is_order_independent_and_typed(self):
        a = capability_message("act", {"b": "1", "a": ["x", "y"]}, None, "n")
        b = capability_message("act", {"a": ["x", "y"], "b": "1"}, None, "n")
        assert a == b
        assert capability_message("act", {"a": "x"}, None, "n") != capability_message("act", {"a": ["x"]}, None, "n")
        assert capability_message("act", {"a": ["x,y"]}, None, "n") != capability_message("act", {"a": ["x", "y"]}, None, "n")

    def test_expiry_and_absent_content_hash_are_signed(self):
        assert capability_message("a", {}, 1, "n") != capability_message("a", {}, None, "n")
        assert source_label_message("e", "c", "trusted") == source_label_message("e", "c", "trusted", "")
        assert source_label_message("e", "c", "trusted") != source_label_message("e", "c", "trusted", "h")


# ---------------------------------------------------------------------------
# Definition 5: signed source attribution
# ---------------------------------------------------------------------------

class TestSignedLabels:
    def test_honest_graph_is_unchanged(self):
        G = load_prov_graph(_signed_doc(), strict=True)
        r = _verify(G)
        assert not r.downgraded and not r.rejected_endorsers
        assert nx.utils.graphs_equal(r.graph, G)
        assert G.nodes["adprov:e_query"]["adprov:integrity"] == "trusted"

    def test_input_graph_is_not_mutated(self):
        G = trust_attribution_relabel(load_prov_graph(_signed_doc()))
        before = copy.deepcopy(dict(G.nodes(data=True)))
        _verify(G)
        assert dict(G.nodes(data=True)) == before

    @pytest.mark.parametrize("tamper,reason", [
        (lambda d: d.pop(LABEL_SIG_KEY), "no label signature"),
        (lambda d: d.update({"adprov:source_channel": "email"}), "does not verify"),    # wrong channel
        (lambda d: d.update({"adprov:content_hash": "sha256:other"}), "does not verify"),
        (lambda d: d.pop("adprov:content_hash"), "does not verify"),
        (lambda d: d.update({"adprov:label_kid": "nobody"}), "does not verify"),
        (lambda d: d.update({LABEL_SIG_KEY: "!!not base64!!"}), "malformed"),
        (lambda d: d.update({LABEL_SIG_KEY: 7}), "malformed"),
    ])
    def test_a_trusted_label_that_does_not_verify_reads_untrusted(self, tamper, reason):
        doc = _signed_doc()
        tamper(doc["entity"]["adprov:e_query"])
        G = load_prov_graph(doc)
        r = _verify(G)
        assert r.graph.nodes["adprov:e_query"]["adprov:integrity"] == "untrusted"
        assert reason in r.downgraded["adprov:e_query"]

    def test_signature_is_bound_to_the_entity(self):
        doc = _signed_doc()
        doc["entity"]["adprov:e_other"] = dict(doc["entity"]["adprov:e_query"])   # copied wholesale
        r = _verify(load_prov_graph(doc))
        assert "adprov:e_other" in r.downgraded and "adprov:e_query" not in r.downgraded

    def test_relabelling_an_untrusted_entity_is_undone(self):
        """P3's relabel attack: ⊥ → ⊤ needs a signature over 'trusted', which it lacks."""
        doc = _signed_doc()
        doc["entity"]["adprov:e_mail"]["adprov:integrity"] = "trusted"
        G = load_prov_graph(doc)
        assert not f_flow(G)                      # evades the unverified detector
        r = _verify(G)
        assert r.downgraded == {"adprov:e_mail": "label signature does not verify"}
        assert f_flow(r.graph)

    @pytest.mark.parametrize("label", [None, "Trusted", ["trusted"]])
    def test_missing_or_unrecognised_label_reads_untrusted(self, label):
        doc = _signed_doc()
        e = doc["entity"]["adprov:e_query"]
        if label is None:
            del e["adprov:integrity"]
        else:
            e["adprov:integrity"] = label
        r = _verify(load_prov_graph(doc))
        assert r.graph.nodes["adprov:e_query"]["adprov:integrity"] == "untrusted"

    def test_untrusted_needs_no_signature(self):
        doc = _signed_doc()
        del doc["entity"]["adprov:e_mail"][LABEL_SIG_KEY]
        assert "adprov:e_mail" not in _verify(load_prov_graph(doc)).downgraded

    def test_revoked_label_key_fails_safe(self):
        r = verify_attribution(load_prov_graph(_signed_doc()),
                               labels=HmacRing(REC, revoked=(REC.kid,)), capabilities=CAPS)
        assert r.graph.nodes["adprov:e_query"]["adprov:integrity"] == "untrusted"

    def test_rotation_keeps_old_labels_verifiable(self):
        new = HmacKey("rec-2026-11")
        r = verify_attribution(load_prov_graph(_signed_doc()), labels=HmacRing(REC, new), capabilities=CAPS)
        assert not r.downgraded


# ---------------------------------------------------------------------------
# Definition 6: capability-bound endorsement
# ---------------------------------------------------------------------------

class TestCapabilities:
    def test_valid_capability_keeps_the_endorser(self):
        G = load_prov_graph(_signed_doc(endorse=True), strict=True)
        r = _verify(G, trace_id=TRACE)
        assert not r.rejected_endorsers
        assert not f_flow(r.graph)

    def _reject(self, doc: dict, **kw) -> str:
        r = _verify(load_prov_graph(doc), **kw)
        assert r.graph.nodes["adprov:a_approve"]["adprov:role"] == "neutral"
        assert f_flow(r.graph)
        return r.rejected_endorsers["adprov:a_approve"]

    def test_no_capability(self):
        doc = _signed_doc(endorse=True)
        del doc["activity"]["adprov:a_approve"][CAPABILITY_KEY]
        assert self._reject(doc) == "no capability"

    def test_capability_for_another_action(self):
        doc = _signed_doc(endorse=True)
        doc["activity"]["adprov:a_approve"][ACTION_KEY] = "approve_payment"
        assert "not 'approve_payment'" in self._reject(doc)

    def test_endorser_without_declared_action(self):
        doc = _signed_doc(endorse=True)
        del doc["activity"]["adprov:a_approve"][ACTION_KEY]
        assert "no adprov:action" in self._reject(doc)

    def test_expiry(self):
        doc = _signed_doc(endorse=True)
        doc["activity"]["adprov:a_approve"][CAPABILITY_KEY] = issue_capability(
            CAP, "approve_send", {"trace": TRACE}, expires_at=1_000)
        assert self._reject(doc, now=1_000) == "capability expired"
        assert not _verify(load_prov_graph(doc), now=999).rejected_endorsers

    def test_trace_binding(self):
        assert "another trace" in self._reject(_signed_doc(endorse=True), trace_id="application-43")

    def test_scope_check_hook(self):
        def only_pdfs(n, attrs, cap):
            return cap.scope.get("artefacts") == ["sha256:cv"]
        assert "does not cover" in self._reject(_signed_doc(endorse=True), scope_check=only_pdfs)

    def test_one_capability_endorses_one_activity(self):
        doc = _signed_doc(endorse=True)
        doc["activity"]["adprov:a_copy"] = dict(doc["activity"]["adprov:a_approve"])
        r = _verify(load_prov_graph(doc))
        assert set(r.rejected_endorsers) == {"adprov:a_approve", "adprov:a_copy"}

    def test_key_separation(self):
        """A capability signed with the recorder's key does not verify as a capability."""
        doc = _signed_doc(endorse=True)
        doc["activity"]["adprov:a_approve"][CAPABILITY_KEY] = issue_capability(REC, "approve_send", {"trace": TRACE})
        assert "does not verify" in self._reject(doc)
        # …and a label signed with the capability key does not verify as a label.
        doc = _signed_doc()
        doc["entity"]["adprov:e_query"].update(
            sign_source_label(CAP, "adprov:e_query", "user", "trusted", "sha256:q"))
        assert "adprov:e_query" in _verify(load_prov_graph(doc)).downgraded

    def test_tampered_payload(self):
        doc = _signed_doc(endorse=True)
        prefix, body, sig = doc["activity"]["adprov:a_approve"][CAPABILITY_KEY].split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=="))
        payload["scope"]["trace"] = "application-99"
        forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        doc["activity"]["adprov:a_approve"][CAPABILITY_KEY] = f"{prefix}.{forged}.{sig}"
        assert "does not verify" in self._reject(doc)

    @pytest.mark.parametrize("token", [
        "garbage", 7, None, "flintcap1.a.b", "flintcap2.e30.AA",
        "flintcap1." + base64.urlsafe_b64encode(b'{"kid":"k","kid":"x"}').decode() + ".AA",
        "flintcap1." + base64.urlsafe_b64encode(
            b'{"kid":"k","action":"a","scope":{},"exp":true,"nonce":"n"}').decode() + ".AA",
        "flintcap1." + base64.urlsafe_b64encode(
            b'{"kid":"k","action":"a","scope":{"x":[1]},"exp":null,"nonce":"n"}').decode() + ".AA",
    ])
    def test_malformed_tokens_never_endorse(self, token):
        assert decode_capability(token) is None
        doc = _signed_doc(endorse=True)
        doc["activity"]["adprov:a_approve"][CAPABILITY_KEY] = token
        assert self._reject(doc) in {"malformed capability", "no capability"}

    def test_forged_endorser_attack_is_undone(self):
        """P3's endorser attack inserts an endorser it cannot issue a capability for."""
        G = load_prov_graph(_signed_doc())
        for attack in (trust_attribution_endorser, trust_attribution_endorser_all):
            H = attack(G)
            assert not f_flow(H)
            assert f_flow(_verify(H).graph)


class TestSinkPolicy:
    def test_a_relabelled_sink_is_restored(self):
        doc = _signed_doc()
        doc["activity"]["adprov:a_send"]["adprov:role"] = "neutral"     # drop the sink
        G = load_prov_graph(doc)
        assert not f_flow(G)
        r = _verify(G, sink_actions={"send_email"})
        assert r.added_sinks == ("adprov:a_send",)
        assert f_flow(r.graph)

    def test_sink_wins_over_an_endorsement_on_itself(self):
        doc = _signed_doc()
        doc["activity"]["adprov:a_send"].update({
            "adprov:role": "endorser",
            CAPABILITY_KEY: issue_capability(CAP, "send_email", {"trace": TRACE}),
        })
        r = _verify(load_prov_graph(doc), sink_actions={"send_email"})
        assert r.rejected_endorsers["adprov:a_send"] == "action is a sink under the policy"
        assert f_flow(r.graph)


# ---------------------------------------------------------------------------
# Theorem 3: without sk_rec or sk_cap, no attack lowers the verified verdict
# ---------------------------------------------------------------------------

@st.composite
def honest_signed_graphs(draw) -> nx.DiGraph:
    G = nx.DiGraph()
    ne, na = draw(st.integers(1, 6)), draw(st.integers(1, 6))
    for i in range(ne):
        label = draw(st.sampled_from(["trusted", "untrusted"]))
        G.add_node(f"e{i}", node_type="entity", **sign_source_label(REC, f"e{i}", "ch", label))
    for i in range(na):
        role = draw(st.sampled_from(["neutral", "sink", "endorser"]))
        attrs = {"adprov:role": role, ACTION_KEY: f"act{i}"}
        if role == "endorser":
            attrs[CAPABILITY_KEY] = issue_capability(CAP, f"act{i}", {"trace": TRACE})
        G.add_node(f"a{i}", node_type="activity", **attrs)
    nodes = list(G)
    for _ in range(draw(st.integers(0, 3 * (ne + na)))):
        u, v = draw(st.sampled_from(nodes)), draw(st.sampled_from(nodes))
        if u != v:
            G.add_edge(u, v, relation="used")
    return G


ATTACKS = [
    trust_attribution_relabel,
    trust_attribution_endorser,
    trust_attribution_endorser_all,
    structural_mimicry,
    lambda G: structural_mimicry_budget(G, 3),
    lambda G: trust_attribution_endorser_all(trust_attribution_relabel(G)),
]


@settings(max_examples=300, deadline=None, suppress_health_check=list(HealthCheck))
@given(honest_signed_graphs(), st.sampled_from(range(len(ATTACKS))))
def test_theorem_3_no_evasion_without_the_keys(G, i):
    honest = _verify(G, trace_id=TRACE)
    assert not honest.downgraded and not honest.rejected_endorsers   # nothing true is withdrawn
    assert f_flow(honest.graph) == f_flow(G)
    attacked = _verify(ATTACKS[i](G), trace_id=TRACE)
    assert f_flow(attacked.graph) >= f_flow(honest.graph)


# ---------------------------------------------------------------------------
# Ed25519 ([attribution] extra)
# ---------------------------------------------------------------------------

class TestEd25519:
    @pytest.fixture(autouse=True)
    def _need_cryptography(self):
        pytest.importorskip("cryptography")

    def test_round_trip_and_tamper(self):
        from flint.attribution.ed25519 import Ed25519Signer, Ed25519Verifier
        rec = Ed25519Signer.generate("rec-1")
        ring = Ed25519Verifier.of(rec)
        assert ring.verify("rec-1", b"m", rec.sign(b"m"))
        assert not ring.verify("rec-1", b"x", rec.sign(b"m"))
        assert not ring.verify("rec-2", b"m", rec.sign(b"m"))
        assert not Ed25519Verifier.of(rec, revoked=["rec-1"]).verify("rec-1", b"m", rec.sign(b"m"))

    def test_raw_public_key_bytes(self):
        from flint.attribution.ed25519 import Ed25519Signer, Ed25519Verifier
        rec = Ed25519Signer.generate("rec-1")
        ring = Ed25519Verifier({"rec-1": rec.public_key.public_bytes_raw()})
        assert ring.verify("rec-1", b"m", rec.sign(b"m"))

    def test_end_to_end_with_real_keys(self):
        from flint.attribution.ed25519 import Ed25519Signer, Ed25519Verifier
        rec, cap = Ed25519Signer.generate("rec"), Ed25519Signer.generate("cap")
        doc = {
            "entity": {"adprov:e": sign_source_label(rec, "adprov:e", "web", "untrusted")},
            "activity": {
                "adprov:ok": {"adprov:role": "endorser", ACTION_KEY: "approve",
                              CAPABILITY_KEY: issue_capability(cap, "approve", {"trace": "t"})},
                "adprov:s": {"adprov:role": "sink"},
            },
            "used": {"adprov:u": {"prov:activity": "adprov:ok", "prov:entity": "adprov:e"}},
            "wasInformedBy": {"adprov:i": {"prov:informed": "adprov:s", "prov:informant": "adprov:ok"}},
        }
        labels, caps = Ed25519Verifier.of(rec), Ed25519Verifier.of(cap)
        G = load_prov_graph(doc, strict=True)
        r = verify_attribution(G, labels=labels, capabilities=caps, trace_id="t")
        assert not r.rejected_endorsers and not f_flow(r.graph)    # the real approval holds
        # Remove the real approval: the flow is now unendorsed, and a forged endorser
        # (no capability: the attacker lacks the cap key) cannot hide it.
        bare = G.copy()
        bare.remove_node("adprov:ok")
        bare.add_edge("adprov:e", "adprov:s", relation="used")
        forged = trust_attribution_endorser_all(bare)
        assert not f_flow(forged)
        assert f_flow(verify_attribution(forged, labels=labels, capabilities=caps).graph)


# ---------------------------------------------------------------------------
# Relation commitment: an omitted (or added) edge is detected
# ---------------------------------------------------------------------------

from flint import commit_relations  # noqa: E402
from flint.attribution import relations_root  # noqa: E402


class TestRelationCommitment:
    def test_rfc6962_vectors(self):
        from flint.attribution import _merkle_root
        assert _merkle_root([]).hex() == hashlib.sha256(b"").hexdigest()
        # MTH of one empty leaf = SHA-256(0x00)
        assert _merkle_root([b""]).hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        a, b, c = (hashlib.sha256(b"\x00" + x).digest() for x in (b"a", b"b", b"c"))
        ab = hashlib.sha256(b"\x01" + a + b).digest()
        assert _merkle_root([b"a", b"b", b"c"]) == hashlib.sha256(b"\x01" + ab + c).digest()

    def test_root_is_order_independent(self):
        G = load_prov_graph(_signed_doc(endorse=True))
        H = nx.DiGraph()
        H.add_nodes_from(reversed(list(G.nodes(data=True))))
        H.add_edges_from(reversed(list(G.edges(data=True))))
        assert relations_root(G) == relations_root(H)

    def test_honest_record_is_complete(self):
        G = load_prov_graph(_signed_doc(endorse=True), strict=True)
        token = commit_relations(REC, G, TRACE)
        r = _verify(G, relations=token, trace_id=TRACE)
        assert r.record_complete is True and r.record_issue is None
        assert r.alert is False                      # endorsed flow, complete record

    def test_omitted_edge_is_an_alert(self):
        """The edge-omission variant the paper leaves open: drop the edge into the sink."""
        G = load_prov_graph(_signed_doc(), strict=True)
        token = commit_relations(REC, G, TRACE)
        H = G.copy()
        H.remove_edge("adprov:e_mail", "adprov:a_send")
        assert not f_flow(H)                          # the flow is gone from the record
        r = _verify(H, relations=token, trace_id=TRACE)
        assert r.record_complete is False
        assert "differ" in r.record_issue
        assert r.alert is True

    def test_added_edge_is_detected(self):
        G = load_prov_graph(_signed_doc(), strict=True)
        token = commit_relations(REC, G, TRACE)
        r = _verify(structural_mimicry(G), relations=token, trace_id=TRACE)
        assert r.record_complete is False

    def test_relation_type_is_committed(self):
        G = load_prov_graph(_signed_doc(), strict=True)
        token = commit_relations(REC, G, TRACE)
        H = G.copy()
        H.edges["adprov:e_mail", "adprov:a_send"]["relation"] = "wasDerivedFrom"
        assert _verify(H, relations=token).record_complete is False

    @pytest.mark.parametrize("mutate,reason", [
        (lambda t: None, "no relation commitment"),
        (lambda t: "garbage", "malformed"),
        (lambda t: t.replace("flintrel1", "flintrel2"), "malformed"),
        (lambda t: t[:-4] + ("AAAA" if not t.endswith("AAAA") else "BBBB"), "does not verify"),
    ])
    def test_bad_tokens(self, mutate, reason):
        G = load_prov_graph(_signed_doc(), strict=True)
        r = _verify(G, relations=mutate(commit_relations(REC, G, TRACE)) or 0)
        assert r.record_complete is False and reason in r.record_issue

    def test_trace_binding_and_key_separation(self):
        G = load_prov_graph(_signed_doc(), strict=True)
        assert "another trace" in _verify(
            G, relations=commit_relations(REC, G, TRACE), trace_id="other").record_issue
        # committed with the capability key: not the recorder, so it does not verify
        assert "does not verify" in _verify(
            G, relations=commit_relations(CAP, G, TRACE)).record_issue

    def test_without_a_commitment_the_check_is_off(self):
        r = _verify(load_prov_graph(_signed_doc()))
        assert r.record_complete is None and r.alert == f_flow(r.graph)


def _omit_edge(G: nx.DiGraph, k: int) -> nx.DiGraph:
    H = G.copy()
    edges = list(H.edges)
    if edges:
        H.remove_edge(*edges[k % len(edges)])
    return H


@settings(max_examples=300, deadline=None, suppress_health_check=list(HealthCheck))
@given(honest_signed_graphs(), st.sampled_from(range(len(ATTACKS) + 1)), st.integers(0, 50))
def test_theorem_3_with_omission(G, i, k):
    """With the relation commitment, omitting an edge joins the attacks that cannot
    lower the deployed decision (``alert``) without a key."""
    token = commit_relations(REC, G, TRACE)
    honest = _verify(G, trace_id=TRACE, relations=token)
    assert honest.record_complete is True and honest.alert == f_flow(G)
    attack = ATTACKS[i] if i < len(ATTACKS) else (lambda g: _omit_edge(g, k))
    H = attack(G)
    attacked = _verify(H, trace_id=TRACE, relations=token)
    assert attacked.alert >= honest.alert
