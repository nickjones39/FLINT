"""f_flow detector — Layer 2.

Wraps the flow reachability logic from layer1_graph.flow into the detector
interface used by the Layer-3 orchestration runner.

  f_flow(G) → bool   (True = attack detected)

Also exposes a richer result type for debugging and metrics collection.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from flint.layer1_graph.flow import (
    check_flow,
    flow_witnesses,
    get_endorsers,
    get_sinks,
    get_untrusted_sources,
)


@dataclass
class FlowDetectionResult:
    detected: bool
    n_sources: int
    n_sinks: int
    n_endorsers: int
    witnesses: list[tuple[str, str, list[str]]]

    def __bool__(self) -> bool:
        return self.detected


def f_flow(G: nx.DiGraph) -> bool:
    """Return True iff the graph contains a D-avoiding flow path from ⊥ to S."""
    return check_flow(G)


def f_flow_detailed(G: nx.DiGraph) -> FlowDetectionResult:
    """Return a FlowDetectionResult with full witness paths for debugging."""
    sources = get_untrusted_sources(G)
    sinks = get_sinks(G)
    endorsers = get_endorsers(G)
    witnesses = flow_witnesses(G)
    return FlowDetectionResult(
        detected=bool(witnesses),
        n_sources=len(sources),
        n_sinks=len(sinks),
        n_endorsers=len(endorsers),
        witnesses=witnesses,
    )
