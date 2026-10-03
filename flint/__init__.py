"""FLINT — flow-typed provenance security for LLM agents.

The names exported here are FLINT's versioned public API: they keep their
signatures and meaning within a minor version. Everything else (the layer
modules, ``paths``, the sweep runner) is reachable but may change between
releases.

Importing ``flint`` needs only networkx. The sweep runner needs the ``[sweep]``
extra, the PROV renderer the ``[viz]`` extra, and the Ed25519 keys in
``flint.attribution.ed25519`` the ``[attribution]`` extra.

    import flint
    G = flint.load_prov_graph(doc, strict=True)
    if flint.f_flow(G):
        ...
"""
from __future__ import annotations

__version__ = "0.3.3"

from flint.attribution import (
    AttributionResult,
    Signer,
    Verifier,
    argument_scope,
    commit_record,
    commit_relations,
    issue_capability,
    sign_source_label,
    verify_attribution,
)
from flint.errors import ProvFormatError
from flint.layer1_graph.flow import flow_witnesses
from flint.layer1_graph.load import load_prov_graph, load_prov_graph_from_file, parse_prov_json
from flint.layer2_detectors.f_flow import FlowDetectionResult, f_flow, f_flow_detailed
from flint.layer3_orchestration.adversary import (
    structural_mimicry,
    structural_mimicry_budget,
    trust_attribution_endorser,
    trust_attribution_endorser_all,
    trust_attribution_relabel,
    trust_attribution_relabel_rederived,
)
from flint.spec import (
    ADPROV_NS,
    ADPROV_PREFIX,
    ENDORSER,
    INTEGRITY_DEFAULTED_KEY,
    INTEGRITY_KEY,
    INTEGRITY_VALUES,
    NEUTRAL,
    ROLE_KEY,
    ROLE_VALUES,
    SINK,
    TRUSTED,
    UNTRUSTED,
)

__all__ = [  # noqa: RUF022 — grouped by role, not sorted
    "__version__",
    # loading
    "load_prov_graph",
    "load_prov_graph_from_file",
    "parse_prov_json",
    "ProvFormatError",
    # detection
    "f_flow",
    "f_flow_detailed",
    "FlowDetectionResult",
    "flow_witnesses",
    # adversaries (the evasion testbed)
    "structural_mimicry",
    "structural_mimicry_budget",
    "trust_attribution_endorser",
    "trust_attribution_endorser_all",
    "trust_attribution_relabel",
    "trust_attribution_relabel_rederived",
    # verifiable trust attribution (manuscript §V; flint.attribution)
    "verify_attribution",
    "AttributionResult",
    "sign_source_label",
    "issue_capability",
    "commit_relations",
    "commit_record",
    "argument_scope",
    "Signer",
    "Verifier",
    # input vocabulary (docs/input-format.md)
    "ADPROV_NS",
    "ADPROV_PREFIX",
    "INTEGRITY_KEY",
    "INTEGRITY_VALUES",
    "TRUSTED",
    "UNTRUSTED",
    "ROLE_KEY",
    "ROLE_VALUES",
    "NEUTRAL",
    "SINK",
    "ENDORSER",
    "INTEGRITY_DEFAULTED_KEY",
]
