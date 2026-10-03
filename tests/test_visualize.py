"""visualize.py: FLINT colours over the W3C PROV notation ([viz] extra)."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("prov")
pytest.importorskip("pydot")

from prov.dot import prov_to_dot

from flint.layer1_graph import visualize as viz
from flint.layer1_graph.load import load_prov_graph
from flint.spec import ADPROV_NS


def _doc() -> dict:
    return {
        "prefix": {"adprov": ADPROV_NS},
        "entity": {
            "adprov:e_unlabelled": {"prov:label": "no label"},
            "adprov:e_trusted": {"adprov:integrity": "trusted"},
        },
        "activity": {
            "adprov:a_sink": {"adprov:role": {"$": "sink", "type": "xsd:string"}},
            "adprov:a_end": {"adprov:role": "endorser"},
            "adprov:a_neutral": {"adprov:role": "neutral"},
        },
        "used": {"adprov:u": {"prov:activity": "adprov:a_sink", "prov:entity": "adprov:e_unlabelled"}},
    }


def _fills(doc: dict) -> dict[str, str]:
    dot = prov_to_dot(viz.validate_prov_json(doc), use_labels=True)
    viz._apply_flint_colors(dot, load_prov_graph(doc))
    out = {}
    for node in dot.get_node_list():
        url = node.get_attributes().get("URL")
        qid = viz._url_to_qid(url) if url else None
        if qid:
            out[qid] = node.get_attributes().get("fillcolor")
    return out


def test_colours():
    fills = _fills(_doc())
    assert fills["adprov:e_unlabelled"] == viz._COLOR_ENTITY_UNTRUSTED   # missing ⇒ untrusted
    assert fills["adprov:e_trusted"] == viz._COLOR_ENTITY_TRUSTED
    assert fills["adprov:a_sink"] == viz._COLOR_ACTIVITY_SINK            # typed literal read
    assert fills["adprov:a_end"] == viz._COLOR_ACTIVITY_ENDORSER
    assert fills["adprov:a_neutral"] == viz._COLOR_ACTIVITY_NEUTRAL


def test_list_valued_role_does_not_crash():
    doc = _doc()
    doc["activity"]["adprov:a_neutral"]["adprov:role"] = ["sink", "neutral"]
    assert _fills(doc)["adprov:a_neutral"] == viz._COLOR_ACTIVITY_NEUTRAL


def test_dot_string_escapes_quotes_and_backslashes():
    assert viz._dot_string('a "b" c\\d') == '"a \\"b\\" c\\\\d"'


def test_url_outside_adprov_is_ignored():
    assert viz._url_to_qid('"http://example.org/x"') is None


@pytest.mark.skipif(shutil.which("dot") is None, reason="needs the Graphviz `dot` binary")
def test_render_keeps_dots_in_stem_and_quotes_in_title(tmp_path: Path):
    written = viz.render_prov_json(_doc(), tmp_path / "llama-3.3_trace", title='say "hi"',
                                   formats=("svg",))
    assert written == [tmp_path / "llama-3.3_trace.svg"]
    assert 'say &quot;hi&quot;' in written[0].read_text(encoding="utf-8")
