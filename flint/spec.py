"""FLINT's input vocabulary — the PROV extension attributes the detector reads.

The full specification, written for anyone producing PROV-JSON for FLINT, is
``docs/input-format.md``. This module is its machine-readable half: every place in
the package that reads a label goes through these names.

The vocabulary was fixed by the AgentDojo-PROV corpus (DOI 10.5281/zenodo.21052314),
which FLINT was evaluated on, and is unchanged here.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

ADPROV_PREFIX: Final = "adprov"
ADPROV_NS: Final = "https://nickjones39.github.io/agentdojo-prov/ns#"

# Entity integrity λ(e) ∈ {⊥, ⊤}.
INTEGRITY_KEY: Final = "adprov:integrity"
UNTRUSTED: Final = "untrusted"          # ⊥ — the source set U_src
TRUSTED: Final = "trusted"              # ⊤
INTEGRITY_VALUES: Final = frozenset({UNTRUSTED, TRUSTED})

# Activity role: privileged sink S, endorsement D, or neither.
ROLE_KEY: Final = "adprov:role"
NEUTRAL: Final = "neutral"
SINK: Final = "sink"
ENDORSER: Final = "endorser"
ROLE_VALUES: Final = frozenset({NEUTRAL, SINK, ENDORSER})

# Set by the strict loader on an entity whose integrity label was missing or
# invalid and was therefore read as ⊥ (fail-closed). Value: the original label,
# or None if there was none.
INTEGRITY_DEFAULTED_KEY: Final = "flint:integrity_defaulted"


def literal_value(value: Any) -> Any:
    """Unwrap a PROV-JSON typed literal (``{"$": v, "type": ...}``) to ``v``.

    PROV-JSON lets any attribute value be written either bare or as a typed /
    language-tagged literal. Both mean the same label, so both must compare equal
    to it; anything else is returned unchanged.
    """
    if isinstance(value, Mapping) and "$" in value:
        return value["$"]
    return value
