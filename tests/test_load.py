"""Loader hardening: malformed input, typed literals, strict (fail-closed) mode.

The default loader must keep producing exactly the graphs the published results
came from; strict mode must never let a missing label or a dangling reference
hide an untrusted→sink flow.
"""
from __future__ import annotations

import copy
import subprocess
import sys

import pytest

import flint
from flint import ProvFormatError, f_flow, load_prov_graph
from flint.layer1_graph.flow import get_untrusted_sources
from flint.spec import ADPROV_NS, INTEGRITY_DEFAULTED_KEY, INTEGRITY_KEY, ROLE_KEY


def _doc() -> dict:
    """read_email (neutral) → e_mail (⊥) → send_email (sink): one flow."""
    return {
        "prefix": {"adprov": ADPROV_NS},
        "entity": {
            "adprov:e_query": {"prov:label": "user_query", "adprov:integrity": "trusted"},
            "adprov:e_mail":  {"prov:label": "read_email_output", "adprov:integrity": "untrusted"},
        },
        "activity": {
            "adprov:a_read": {"prov:label": "read_email", "adprov:role": "neutral"},
            "adprov:a_send": {"prov:label": "send_email", "adprov:role": "sink"},
        },
        "agent": {"adprov:ag": {"prov:label": "llm_agent", "adprov:integrity": "trusted"}},
        "wasGeneratedBy": {
            "adprov:g1": {"prov:entity": "adprov:e_mail", "prov:activity": "adprov:a_read"},
        },
        "used": {
            "adprov:u1": {"prov:activity": "adprov:a_send", "prov:entity": "adprov:e_mail"},
        },
        "wasAssociatedWith": {
            "adprov:w1": {"prov:activity": "adprov:a_send", "prov:agent": "adprov:ag"},
        },
    }


@pytest.fixture(params=[False, True], ids=["default", "strict"])
def strict(request) -> bool:
    return request.param


# ---------------------------------------------------------------------------
# Both modes
# ---------------------------------------------------------------------------

class TestBothModes:
    def test_well_formed_doc_detects(self, strict):
        assert f_flow(load_prov_graph(_doc(), strict=strict))

    def test_modes_agree_on_well_formed_doc(self):
        a, b = load_prov_graph(_doc()), load_prov_graph(_doc(), strict=True)
        assert list(a.nodes(data=True)) == list(b.nodes(data=True))
        assert list(a.edges(data=True)) == list(b.edges(data=True))

    def test_was_associated_with_is_ignored(self, strict):
        G = load_prov_graph(_doc(), strict=strict)
        assert not G.has_edge("adprov:ag", "adprov:a_send")
        assert not G.has_edge("adprov:a_send", "adprov:ag")
        assert {k for k in G.nodes["adprov:a_send"]} == {"node_type", "prov:label", ROLE_KEY}

    @pytest.mark.parametrize("rel,field", [
        ("used", "prov:activity"), ("used", "prov:entity"),
        ("wasGeneratedBy", "prov:activity"), ("wasGeneratedBy", "prov:entity"),
    ])
    def test_missing_relation_field_is_a_format_error(self, strict, rel, field):
        doc = _doc()
        rid = next(iter(doc[rel]))
        del doc[rel][rid][field]
        with pytest.raises(ProvFormatError, match=field):
            load_prov_graph(doc, strict=strict)

    def test_non_string_endpoint_is_a_format_error(self, strict):
        doc = _doc()
        doc["used"]["adprov:u1"]["prov:entity"] = {"$": "adprov:e_mail", "type": "prov:QUALIFIED_NAME"}
        with pytest.raises(ProvFormatError, match="qualified name"):
            load_prov_graph(doc, strict=strict)

    @pytest.mark.parametrize("bad", [[], "x", 3, None])
    def test_non_object_document_or_section(self, strict, bad):
        with pytest.raises(ProvFormatError):
            load_prov_graph(bad, strict=strict)  # type: ignore[arg-type]
        if bad is not None:
            doc = _doc()
            doc["entity"] = bad
            with pytest.raises(ProvFormatError):
                load_prov_graph(doc, strict=strict)

    def test_format_error_is_a_value_error(self):
        assert issubclass(ProvFormatError, ValueError)

    @pytest.mark.parametrize("literal", [
        {"$": "untrusted", "type": "xsd:string"},
        {"$": "untrusted", "lang": "en"},
    ])
    def test_typed_integrity_literal_is_read(self, strict, literal):
        doc = _doc()
        doc["entity"]["adprov:e_mail"][INTEGRITY_KEY] = literal
        G = load_prov_graph(doc, strict=strict)
        assert G.nodes["adprov:e_mail"][INTEGRITY_KEY] == "untrusted"
        assert f_flow(G)

    def test_typed_role_literal_is_read(self, strict):
        doc = _doc()
        doc["activity"]["adprov:a_send"][ROLE_KEY] = {"$": "sink", "type": "xsd:string"}
        assert f_flow(load_prov_graph(doc, strict=strict))

    def test_input_is_not_mutated(self, strict):
        doc = _doc()
        doc["entity"]["adprov:e_mail"][INTEGRITY_KEY] = {"$": "untrusted", "type": "xsd:string"}
        del doc["entity"]["adprov:e_query"][INTEGRITY_KEY]
        before = copy.deepcopy(doc)
        load_prov_graph(doc, strict=strict)
        assert doc == before


# ---------------------------------------------------------------------------
# Default mode keeps its published behaviour
# ---------------------------------------------------------------------------

class TestDefaultModeUnchanged:
    def test_unlabelled_entity_is_not_a_source(self):
        doc = _doc()
        del doc["entity"]["adprov:e_mail"][INTEGRITY_KEY]
        G = load_prov_graph(doc)
        assert get_untrusted_sources(G) == []
        assert not f_flow(G)

    def test_dangling_reference_creates_untyped_node(self):
        doc = _doc()
        doc["used"]["adprov:u1"]["prov:entity"] = "adprov:e_ghost"
        G = load_prov_graph(doc)
        assert "node_type" not in G.nodes["adprov:e_ghost"]


# ---------------------------------------------------------------------------
# Strict mode: fail closed
# ---------------------------------------------------------------------------

class TestStrictFailClosed:
    @pytest.mark.parametrize("label", [None, "Trusted", "", "⊤", ["trusted"], 1])
    def test_missing_or_invalid_integrity_is_untrusted(self, label):
        doc = _doc()
        # Hide the flow's source label: the attack must still be caught.
        if label is None:
            del doc["entity"]["adprov:e_mail"][INTEGRITY_KEY]
        else:
            doc["entity"]["adprov:e_mail"][INTEGRITY_KEY] = label
        G = load_prov_graph(doc, strict=True)
        node = G.nodes["adprov:e_mail"]
        assert node[INTEGRITY_KEY] == "untrusted"
        assert node[INTEGRITY_DEFAULTED_KEY] == label
        assert f_flow(G)

    def test_valid_labels_are_not_marked_defaulted(self):
        G = load_prov_graph(_doc(), strict=True)
        assert all(INTEGRITY_DEFAULTED_KEY not in d for _, d in G.nodes(data=True))

    def test_agent_integrity_is_not_checked(self):
        doc = _doc()
        del doc["agent"]["adprov:ag"][INTEGRITY_KEY]
        G = load_prov_graph(doc, strict=True)
        assert INTEGRITY_KEY not in G.nodes["adprov:ag"]

    @pytest.mark.parametrize("role", [None, "Sink", "privileged", ""])
    def test_missing_or_invalid_role_is_rejected(self, role):
        doc = _doc()
        if role is None:
            del doc["activity"]["adprov:a_send"][ROLE_KEY]
        else:
            doc["activity"]["adprov:a_send"][ROLE_KEY] = role
        with pytest.raises(ProvFormatError, match="adprov:a_send"):
            load_prov_graph(doc, strict=True)

    @pytest.mark.parametrize("field", ["prov:entity", "prov:activity"])
    def test_undeclared_node_is_rejected(self, field):
        doc = _doc()
        doc["used"]["adprov:u1"][field] = "adprov:ghost"
        with pytest.raises(ProvFormatError, match="undeclared"):
            load_prov_graph(doc, strict=True)

    def test_wrong_node_type_is_rejected(self):
        doc = _doc()
        # used(a, e) whose "entity" is actually an activity
        doc["used"]["adprov:u1"]["prov:entity"] = "adprov:a_read"
        with pytest.raises(ProvFormatError, match="not an entity"):
            load_prov_graph(doc, strict=True)

    def test_identifier_declared_twice_is_rejected(self):
        doc = _doc()
        doc["agent"]["adprov:e_mail"] = {"prov:label": "shadow"}
        with pytest.raises(ProvFormatError, match="declared as both"):
            load_prov_graph(doc, strict=True)

    def test_foreign_adprov_prefix_is_rejected(self):
        doc = _doc()
        doc["prefix"]["adprov"] = "http://example.org/other#"
        with pytest.raises(ProvFormatError, match="bound to"):
            load_prov_graph(doc, strict=True)

    def test_adprov_namespace_under_other_prefix_is_rejected(self):
        doc = _doc()
        doc["prefix"]["ap"] = ADPROV_NS
        with pytest.raises(ProvFormatError, match="'ap'"):
            load_prov_graph(doc, strict=True)

    def test_undeclared_adprov_prefix_is_accepted(self):
        doc = _doc()
        del doc["prefix"]
        assert f_flow(load_prov_graph(doc, strict=True))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class TestPublicAPI:
    def test_all_names_resolve(self):
        for name in flint.__all__:
            assert hasattr(flint, name), name

    def test_core_import_needs_only_networkx(self):
        code = (
            "import sys, flint\n"
            "heavy = {'pandas', 'pyarrow', 'yaml', 'prov', 'pydot', 'numpy', 'torch', 'sklearn'}\n"
            "loaded = heavy & {m.split('.')[0] for m in sys.modules}\n"
            "assert not loaded, loaded\n"
        )
        subprocess.run([sys.executable, "-c", code], check=True)


# ---------------------------------------------------------------------------
# v0.2.1: sections, roles on non-activities, reserved keys, list instances
# ---------------------------------------------------------------------------

def _flow_in_bundle() -> dict:
    inner = _doc()
    del inner["prefix"]
    return {"prefix": {"adprov": ADPROV_NS}, "bundle": {"adprov:b1": inner}}


class TestStrictSections:
    def test_bundle_rejected_in_strict(self):
        with pytest.raises(ProvFormatError, match="bundle"):
            load_prov_graph(_flow_in_bundle(), strict=True)

    def test_bundle_ignored_in_default(self):
        assert load_prov_graph(_flow_in_bundle()).number_of_nodes() == 0

    @pytest.mark.parametrize("section", [
        "wasStartedBy", "wasEndedBy", "hadMember", "wasInfluencedBy",
        "specializationOf", "alternateOf", "wasInvalidatedBy", "mentionOf", "notAProvKey",
    ])
    def test_unmodelled_section_rejected_in_strict(self, section):
        doc = _doc()
        doc[section] = {"adprov:r": {"prov:trigger": "adprov:e_mail"}}
        with pytest.raises(ProvFormatError, match=section):
            load_prov_graph(doc, strict=True)
        assert f_flow(load_prov_graph(doc))   # default: ignored, as published

    @pytest.mark.parametrize("section", ["wasAttributedTo", "actedOnBehalfOf", "wasAssociatedWith"])
    def test_non_flow_relations_accepted_in_strict(self, section):
        doc = _doc()
        doc[section] = {"adprov:r": {"prov:entity": "adprov:e_mail", "prov:agent": "adprov:ag"}}
        assert f_flow(load_prov_graph(doc, strict=True))

    def test_strict_section_set_is_exported(self):
        from flint.layer1_graph.load import STRICT_SECTIONS
        assert {"prefix", "entity", "used", "wasAssociatedWith"} <= STRICT_SECTIONS
        assert "bundle" not in STRICT_SECTIONS


class TestRoleOnlyOnActivities:
    def _endorser_entity_on_path(self) -> dict:
        # e_mail(⊥) → a_read → e_copy → send(S); e_copy wrongly carries role=endorser
        doc = _doc()
        doc["entity"]["adprov:e_copy"] = {"adprov:integrity": "trusted", "adprov:role": "endorser"}
        doc["used"] = {
            "adprov:u0": {"prov:activity": "adprov:a_read", "prov:entity": "adprov:e_mail"},
            "adprov:u1": {"prov:activity": "adprov:a_send", "prov:entity": "adprov:e_copy"},
        }
        doc["wasGeneratedBy"]["adprov:g2"] = {"prov:entity": "adprov:e_copy", "prov:activity": "adprov:a_read"}
        return doc

    def test_endorser_role_on_entity_does_not_cut_the_flow(self):
        assert f_flow(load_prov_graph(self._endorser_entity_on_path()))

    def test_endorser_role_on_entity_rejected_in_strict(self):
        with pytest.raises(ProvFormatError, match="only meaningful on activities"):
            load_prov_graph(self._endorser_entity_on_path(), strict=True)

    def test_sink_role_on_entity_is_not_a_sink(self):
        doc = _doc()
        doc["activity"]["adprov:a_send"]["adprov:role"] = "neutral"
        doc["entity"]["adprov:e_query"]["adprov:role"] = "sink"
        doc["used"]["adprov:u1"]["prov:entity"] = "adprov:e_mail"
        assert not f_flow(load_prov_graph(doc))

    def test_role_on_agent_rejected_in_strict(self):
        doc = _doc()
        doc["agent"]["adprov:ag"]["adprov:role"] = "endorser"
        with pytest.raises(ProvFormatError, match="agent"):
            load_prov_graph(doc, strict=True)


class TestReservedAndNonStringKeys:
    def test_node_type_attribute_rejected(self, strict):
        doc = _doc()
        doc["entity"]["adprov:e_mail"]["node_type"] = "activity"
        with pytest.raises(ProvFormatError, match="reserved"):
            load_prov_graph(doc, strict=strict)

    def test_non_string_attribute_name_rejected(self, strict):
        doc = _doc()
        doc["entity"]["adprov:e_mail"][7] = "x"
        with pytest.raises(ProvFormatError, match="not a string"):
            load_prov_graph(doc, strict=strict)

    def test_non_string_identifier_rejected(self, strict):
        doc = _doc()
        doc["entity"][7] = {"adprov:integrity": "trusted"}
        with pytest.raises(ProvFormatError, match="not a string"):
            load_prov_graph(doc, strict=strict)


class TestMultiInstanceRecords:
    def test_relation_list_gives_one_edge_per_instance(self, strict):
        doc = _doc()
        doc["used"]["adprov:u1"] = [
            {"prov:activity": "adprov:a_send", "prov:entity": "adprov:e_mail"},
            {"prov:activity": "adprov:a_read", "prov:entity": "adprov:e_query"},
        ]
        G = load_prov_graph(doc, strict=strict)
        assert G.has_edge("adprov:e_mail", "adprov:a_send")
        assert G.has_edge("adprov:e_query", "adprov:a_read")
        assert f_flow(G)

    def test_node_instances_are_merged(self, strict):
        doc = _doc()
        doc["entity"]["adprov:e_mail"] = [
            {"prov:label": "read_email_output"},
            {"adprov:integrity": "untrusted"},
        ]
        G = load_prov_graph(doc, strict=strict)
        assert G.nodes["adprov:e_mail"]["prov:label"] == "read_email_output"
        assert f_flow(G)

    def test_conflicting_labels_rejected_in_strict(self):
        doc = _doc()
        doc["entity"]["adprov:e_mail"] = [
            {"adprov:integrity": "untrusted"},
            {"adprov:integrity": "trusted"},
        ]
        with pytest.raises(ProvFormatError, match="disagree"):
            load_prov_graph(doc, strict=True)

    def test_equal_labels_across_instances_accepted_in_strict(self):
        doc = _doc()
        doc["entity"]["adprov:e_mail"] = [
            {"adprov:integrity": "untrusted"},
            {"adprov:integrity": {"$": "untrusted", "type": "xsd:string"}},
        ]
        assert f_flow(load_prov_graph(doc, strict=True))

    @pytest.mark.parametrize("bad", [[], [1], [{"prov:activity": "adprov:a_send"}, "x"]])
    def test_malformed_lists_rejected(self, strict, bad):
        doc = _doc()
        doc["used"]["adprov:u1"] = bad
        with pytest.raises(ProvFormatError):
            load_prov_graph(doc, strict=strict)


class TestOptionalProvFields:
    @pytest.mark.parametrize("rel,field", [("used", "prov:entity"), ("wasGeneratedBy", "prov:activity")])
    def test_omitted_optional_field_explains_itself(self, strict, rel, field):
        doc = _doc()
        rid = next(iter(doc[rel]))
        del doc[rel][rid][field]
        with pytest.raises(ProvFormatError, match="unidentified"):
            load_prov_graph(doc, strict=strict)


class TestFileEncoding:
    def test_utf8_file_loads_under_a_non_utf8_locale(self, tmp_path):
        import json
        doc = _doc()
        doc["entity"]["adprov:e_mail"]["prov:label"] = "Résumé — Zoë"
        p = tmp_path / "trace.json"
        p.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        code = (
            "import locale, sys\n"
            "from flint import load_prov_graph_from_file, f_flow\n"
            "enc = locale.getpreferredencoding(False).lower().replace('-', '')\n"
            "if enc == 'utf8': sys.exit(3)\n"
            f"G = load_prov_graph_from_file({str(p)!r})\n"
            "assert G.nodes['adprov:e_mail']['prov:label'] == 'Résumé — Zoë'\n"
            "assert f_flow(G)\n"
        )
        env = {"LC_ALL": "C", "LANG": "C", "PYTHONCOERCECLOCALE": "0", "PYTHONUTF8": "0"}
        r = subprocess.run([sys.executable, "-X", "utf8=0", "-c", code], env=env, capture_output=True, text=True)
        if r.returncode == 3:
            pytest.skip("cannot force a non-UTF-8 locale on this platform")
        assert r.returncode == 0, r.stderr
