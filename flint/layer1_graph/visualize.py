"""W3C PROV graph visualizer for FLINT.

Loads a PROV-JSON document through the standard `prov` library (validates the
document in the process), renders it with `prov.dot` so the output follows the
W3C PROV visual notation exactly, then post-processes the pydot graph to apply
FLINT-specific colours on top of the W3C palette:

  W3C PROV visual notation
  ────────────────────────
  Entity    oval      #FFFC87  (yellow)
  Activity  box       #9FB1FC  (blue)
  Agent     house     #FED37F  (orange)

  FLINT overlay (integrity λ and role)
  ─────────────────────────────────────
  Entity  λ=trusted    #FFFC87  (standard W3C yellow — unchanged)
  Entity  λ=untrusted  #FFAAAA  (light salmon — marks taint sources)
  Activity role=neutral   #9FB1FC  (standard W3C blue — unchanged)
  Activity role=sink      #B02E2E  (dark red — privileged write/send)
  Activity role=endorser  #B8CCF8  (light blue — trust endorsement)
  Agent                   #FED37F  (standard W3C orange — unchanged)

An entity with no integrity label is drawn as untrusted, matching the
fail-closed reading in docs/input-format.md.

Annotation side-tables (the note-shaped nodes for attributes) are kept: they
show the adprov:integrity, adprov:role, and adprov:content_hash values inline,
which is standard W3C PROV style.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx
import prov.model as pm
import pydot
from prov.dot import prov_to_dot

from flint.layer1_graph.load import load_prov_graph
from flint.spec import (
    ADPROV_NS,
    ADPROV_PREFIX,
    ENDORSER,
    INTEGRITY_KEY,
    ROLE_KEY,
    SINK,
    TRUSTED,
)

# ── FLINT colour overrides (applied over W3C defaults) ───────────────────────
_COLOR_ENTITY_TRUSTED    = "#FFFC87"   # W3C default yellow — keep
_COLOR_ENTITY_UNTRUSTED  = "#FFAAAA"   # salmon — taint source
_COLOR_ACTIVITY_NEUTRAL  = "#9FB1FC"   # W3C default blue — keep
_COLOR_ACTIVITY_SINK     = "#B02E2E"   # dark red — privileged sink.
#   NB: must stay clearly darker than _COLOR_ENTITY_UNTRUSTED. The two were
#   once #FF9999 / #FFAAAA, a luminance gap of 13, which read as one colour
#   on screen and as one grey in print; the gap is now ~120. The fill is dark
#   enough that sink labels are drawn in white (see _apply_flint_colors).
_COLOR_ACTIVITY_ENDORSER = "#B8CCF8"   # light blue — endorser/D-node


def _url_to_qid(url_attr: str) -> str | None:
    """Convert the pydot URL attribute value to an adprov: qualified ID.

    prov.dot stores URLs as quoted strings, e.g. '"https://.../ns#e_foo"'.
    """
    url = url_attr.strip('"')
    if url.startswith(ADPROV_NS):
        return f"{ADPROV_PREFIX}:" + url[len(ADPROV_NS):]
    return None


def _apply_flint_colors(dot: pydot.Dot, G: nx.DiGraph) -> None:
    """Post-process pydot graph: apply FLINT integrity/role colours to n* nodes.

    Labels are read from the loaded graph ``G``, so typed literals and
    multi-instance records are already normalised.
    """
    for node in dot.get_node_list():
        attrs = node.get_attributes()
        url_val = attrs.get("URL")
        if url_val is None:
            continue  # annotation (ann*) or n-ary relation (b*) — skip
        qid = _url_to_qid(url_val)
        if qid is None:
            continue

        if qid not in G:
            continue
        data = G.nodes[qid]
        if data.get("node_type") == "entity":
            untrusted = data.get(INTEGRITY_KEY) != TRUSTED   # missing ⇒ untrusted
            node.set_fillcolor(_COLOR_ENTITY_UNTRUSTED if untrusted else _COLOR_ENTITY_TRUSTED)
            if untrusted:
                node.set_color("#CC4444")   # darker border to emphasise taint

        elif data.get("node_type") == "activity":
            role = data.get(ROLE_KEY)
            if not isinstance(role, str):   # missing, or e.g. a list: unhashable
                role = None
            color = {
                SINK: _COLOR_ACTIVITY_SINK,
                ENDORSER: _COLOR_ACTIVITY_ENDORSER,
            }.get(role or "", _COLOR_ACTIVITY_NEUTRAL)
            node.set_fillcolor(color)
            if role == SINK:
                node.set_color("#6E1414")
                node.set_fontcolor("white")   # dark fill needs a light label
            elif role == ENDORSER:
                node.set_color("#2244AA")


def _dot_string(text: str) -> str:
    """Quote ``text`` as a Graphviz string literal."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def validate_prov_json(doc_dict: dict[str, Any]) -> pm.ProvDocument:
    """Parse and validate a PROV-JSON dict via the W3C prov library.

    Raises prov.model.ProvException (or similar) on invalid documents.
    Returns the parsed ProvDocument on success.
    """
    return pm.ProvDocument.deserialize(content=json.dumps(doc_dict), format="json")


def render_prov_graph(
    doc_dict: dict[str, Any],
    out_path: Path | str,
    title: str = "",
    formats: tuple[str, ...] = ("svg", "png"),
    show_element_attributes: bool = True,
    direction: str = "LR",
) -> list[Path]:
    """Validate doc_dict as W3C PROV-JSON, render to SVG and/or PNG.

    out_path is the file stem (without extension), e.g. 'results/prov/task_6_benign';
    each format's extension is appended to it, so a stem may itself contain dots.
    Raises on invalid PROV-JSON (validation happens inside validate_prov_json).
    Returns list of written paths.

    ``show_element_attributes`` and ``direction`` are passed through to
    ``prov.dot``. The defaults reproduce the diagnostic render used by
    scripts/regen.sh; a figure for publication generally wants
    ``show_element_attributes=False`` (the attribute side-tables dominate the
    canvas) and ``direction="TB"`` (fits a journal column).
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    doc = validate_prov_json(doc_dict)

    dot = prov_to_dot(
        doc,
        use_labels=True,
        show_element_attributes=show_element_attributes,
        show_relation_attributes=False,
        direction=direction,
    )

    # Inject title into graph label
    if title:
        dot.set_label(_dot_string(title))
        dot.set_labelloc("t")
        dot.set_fontname("Helvetica")
        dot.set_fontsize("11")

    # Apply FLINT colours
    _apply_flint_colors(dot, load_prov_graph(doc_dict))

    written: list[Path] = []
    for fmt in formats:
        dest = out_path.with_name(f"{out_path.name}.{fmt}")
        if fmt == "svg":
            dot.write_svg(str(dest))
        elif fmt == "png":
            dot.write_png(str(dest))
        else:
            dot.write(str(dest), format=fmt)
        written.append(dest)

    return written


# Alias used by the PROV-render step in scripts/regen.sh
def render_prov_json(
    doc: dict[str, Any],
    out_path: Path | str,
    title: str = "",
    formats: tuple[str, ...] = ("svg", "png"),
) -> list[Path]:
    return render_prov_graph(doc, out_path, title=title, formats=formats)
