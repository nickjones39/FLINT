"""Layer-3 orchestration runner.

Config-driven sweep over detector x adversary, emitting a flat
DataFrame of raw results.  Use metrics.compute_metrics to aggregate into
per-group accuracy numbers, and metrics.save_parquet to persist.

CLI:
    python -m flint.layer3_orchestration.runner \\
        --config configs/sweep.yaml \\
        --traces results/traces/  \\
        --out    results/sweep.parquet
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
import pandas as pd
import yaml

from flint.layer1_graph.load import load_prov_graph
from flint.layer2_detectors.f_emb import f_emb
from flint.layer2_detectors.f_flow import f_flow
from flint.layer3_orchestration.adversary import (
    structural_mimicry,
    trust_attribution_endorser,
    trust_attribution_endorser_all,
    trust_attribution_relabel,
)
from flint.layer3_orchestration.metrics import compute_metrics, save_parquet
from flint.paths import iter_files

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

# Tasks whose benign run legitimately flows untrusted tool output into a sink
# (read-external-content → write/send/act).  These produce FPs under pure taint
# analysis because the user AUTHORIZED the read→write flow; a full endorsement
# mechanism would be needed to suppress them.
#
# Workspace entries use bare task IDs ("user_task_N"); other suites use
# suite-prefixed IDs ("banking_user_task_N") because the same task number can
# be read-only in one suite and write-involving in another.
#
# Derived empirically: every benign trace that triggers f_flow was examined;
# all such traces involve reading EXTERNAL_CONTENT_TOOLS output then calling a
# SINK_TOOLS action as the user explicitly requested.
WRITE_INVOLVING_TASKS: frozenset[str] = frozenset({
    # workspace — bare task IDs (suite prefix stripped by _task_subtype)
    "user_task_4",  "user_task_6",  "user_task_7",  "user_task_8",  "user_task_9",
    "user_task_12", "user_task_13", "user_task_15", "user_task_18", "user_task_19",
    "user_task_20", "user_task_21", "user_task_23", "user_task_25", "user_task_29",
    "user_task_31", "user_task_32", "user_task_33", "user_task_34", "user_task_35",
    "user_task_36", "user_task_37", "user_task_38", "user_task_39",
    # banking — read transaction/file then send_money / update account
    "banking_user_task_0",  "banking_user_task_2",  "banking_user_task_3",
    "banking_user_task_4",  "banking_user_task_5",  "banking_user_task_6",
    "banking_user_task_10", "banking_user_task_11", "banking_user_task_12",
    "banking_user_task_13", "banking_user_task_14", "banking_user_task_15",
    # travel — read reviews/recommendations then reserve
    "travel_user_task_0",  "travel_user_task_1",  "travel_user_task_3",
    "travel_user_task_4",  "travel_user_task_6",  "travel_user_task_7",
    "travel_user_task_8",
    # slack — read channel/inbox then send/invite/post
    "slack_user_task_1",  "slack_user_task_2",  "slack_user_task_3",
    "slack_user_task_4",  "slack_user_task_5",  "slack_user_task_6",
    "slack_user_task_7",  "slack_user_task_8",  "slack_user_task_9",
    "slack_user_task_10", "slack_user_task_11", "slack_user_task_12",
    "slack_user_task_13", "slack_user_task_14", "slack_user_task_15",
    "slack_user_task_16", "slack_user_task_17", "slack_user_task_18",
    "slack_user_task_19", "slack_user_task_20",
    # slack_user_task_5 / _12: user authorises reading the channel/user listing
    # (external content) then posting to a channel — a read-external→sink flow,
    # so write-involving despite no inbound message read. Both DeepSeek-V3.2 and
    # GPT-5-nano agents take this path; classifying them read-only would mis-score
    # the f_flow/f_emb read-only FPR.
})


_KNOWN_SUITES: frozenset[str] = frozenset({"workspace", "banking", "travel", "slack"})


@dataclass
class Trace:
    """A single PROV-JSON trace with ground-truth label."""
    doc: dict
    trace_id: str
    ground_truth: bool   # True = injection / attack trace
    task_subtype: str = "unknown"  # "read_only" | "write_involving" | "injection"
    suite: str = "workspace"       # AgentDojo suite name
    attack_type: str = "unknown"   # "direct" | "injecagent" | ... | "benign"


@dataclass
class SweepConfig:
    detectors: list[str]    = field(default_factory=lambda: ["f_flow", "f_emb"])
    adversaries: list[str]  = field(default_factory=lambda: ["none"])

    def __post_init__(self) -> None:
        # An unknown name must fail loudly: a misspelt adversary used to run as
        # "none" and report un-attacked results under the misspelt label.
        for kind, names, registry in (
            ("detector", self.detectors, _DETECTOR_FNS),
            ("adversary", self.adversaries, _ADVERSARY_FNS),
        ):
            if isinstance(names, str) or not isinstance(names, list):
                raise ValueError(f"{kind}s must be a list of names, got {names!r}")
            unknown = [n for n in names if n not in registry]
            if unknown:
                raise ValueError(f"unknown {kind}(s) {unknown}; known: {sorted(registry)}")

    @classmethod
    def from_yaml(cls, path: Path | str) -> SweepConfig:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ValueError(f"{path}: a sweep config must be a mapping, got {type(data).__name__}")
        known = set(cls.__dataclass_fields__)
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(f"{path}: unknown key(s) {unknown}; known: {sorted(known)}")
        return cls(**data)



# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------

_DETECTOR_FNS: dict[str, Callable[[nx.DiGraph], bool]] = {
    "f_flow": f_flow,
    "f_emb": f_emb,
}

_ADVERSARY_FNS: dict[str, Callable[[nx.DiGraph], nx.DiGraph] | None] = {
    "none": None,
    "structural_mimicry": structural_mimicry,
    "trust_attribution_endorser": trust_attribution_endorser,
    "trust_attribution_endorser_all": trust_attribution_endorser_all,
    "trust_attribution_relabel": trust_attribution_relabel,
}


COMPRESSION = "kappa_none"   # constant: the sweep no longer has a compression axis


# ---------------------------------------------------------------------------
# Core sweep
# ---------------------------------------------------------------------------

def run_sweep(traces: list[Trace], config: SweepConfig) -> pd.DataFrame:
    """Run the full detector x adversary sweep.

    Returns a flat DataFrame with one row per
    (trace_id, detector, compression, adversary).
    """
    rows: list[dict] = []
    for trace in traces:
        G = load_prov_graph(trace.doc)
        n_orig = G.number_of_nodes()
        e_orig = G.number_of_edges()

        for adv_name in config.adversaries:
            adv_fn = _ADVERSARY_FNS.get(adv_name)
            A = adv_fn(G) if adv_fn is not None else G

            for det_name in config.detectors:
                det_fn = _DETECTOR_FNS[det_name]
                detected = bool(det_fn(A))
                rows.append({
                    "trace_id":            trace.trace_id,
                    "ground_truth":        trace.ground_truth,
                    "task_subtype":        trace.task_subtype,
                    "suite":               trace.suite,
                    "attack_type":         trace.attack_type,
                    "detector":            det_name,
                    # Retained as a constant so the (detector, compression,
                    # adversary) key downstream consumers group by is unchanged.
                    "compression":         COMPRESSION,
                    "adversary":           adv_name,
                    "detected":            detected,
                    "n_nodes_orig":        n_orig,
                    "n_edges_orig":        e_orig,
                    "n_nodes_after":       A.number_of_nodes(),
                    "n_edges_after":       A.number_of_edges(),
                })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Trace loader (for CLI)
# ---------------------------------------------------------------------------

def _task_subtype(stem: str, ground_truth: bool) -> str:
    """Derive task_subtype from the PROV file stem.

    Handles two naming conventions:
    - Suite-prefixed non-workspace: "banking_user_task_0_benign" → checks
      "banking_user_task_0" directly against WRITE_INVOLVING_TASKS.
    - Workspace with prefix: "workspace_user_task_13_benign" → strips "workspace_"
      then checks "user_task_13" (workspace entries are stored without suite prefix
      for backward compatibility with older flat-file traces).
    - Legacy bare workspace: "user_task_6_benign" → checks "user_task_6" directly.
    """
    if ground_truth:
        return "injection"
    base = stem.replace("_benign", "")
    # Direct match — covers suite-prefixed entries and bare legacy workspace entries
    if base in WRITE_INVOLVING_TASKS:
        return "write_involving"
    # Workspace-only: strip "workspace_" prefix and check bare task id
    if base.startswith("workspace_"):
        bare = base[len("workspace_"):]
        if bare in WRITE_INVOLVING_TASKS:
            return "write_involving"
    return "read_only"


def _suite_from_stem(stem: str) -> str:
    """Extract the AgentDojo suite name from a PROV-JSON filename stem.

    Corpus files (produced by AgentDojo-PROV) are prefixed with the suite name
    (e.g. "banking_user_task_0_benign").  Unprefixed files default to
    "workspace" (the original corpus).
    """
    for suite in _KNOWN_SUITES:
        if stem.startswith(suite + "_"):
            return suite
    return "workspace"


def _prov_json_files(directory: Path) -> list[Path]:
    """PROV-JSON files in `directory`, EXCLUDING the `*.transcript.json` sidecars.

    The capture layer writes two files per trace (`*.prov.json` content lives in
    `*.json`, plus `*.transcript.json`); a bare `*.json` glob also matches the
    transcripts and would load them as empty graphs — doubling the corpus and
    corrupting every metric.
    """
    return [p for p in iter_files(directory, "*.json")
            if not p.name.endswith(".transcript.json")]


_NODE_SECTIONS = ("entity", "activity", "agent")


def _read_trace(p: Path) -> dict:
    """Read one PROV-JSON trace, refusing a JSON file that is not one.

    Any other JSON in a trace directory (a manifest, a config) would otherwise
    load as an empty graph and be scored as a benign trace, inflating TN.
    """
    doc = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not any(k in doc for k in _NODE_SECTIONS):
        raise ValueError(
            f"{p}: not a PROV-JSON trace (no entity/activity/agent section); "
            "point --traces at the prov/ directory of a corpus"
        )
    return doc


def load_traces_from_dir(trace_dir: Path) -> list[Trace]:
    """Load PROV-JSON traces from trace_dir, handling both flat and subdirectory layouts.

    Flat layout (legacy):
        trace_dir/*.json  — attack_type inferred as "benign" or "unknown"

    Subdirectory layout (current):
        trace_dir/benign/*.json
        trace_dir/direct/*.json
        trace_dir/injecagent/*.json
        trace_dir/important_instructions_no_model_name/*.json
        ...

    The parent folder name becomes attack_type.  Filename suffix (_benign /
    _injection) determines ground_truth.

    Raises ``ValueError`` for a mixed layout (top-level traces *and* attack
    subdirectories: one of the two would be silently ignored) and for a JSON
    file that is not a PROV-JSON trace.
    """
    trace_dir = Path(trace_dir)
    if not trace_dir.is_dir():
        raise NotADirectoryError(f"trace directory not found: {trace_dir}")
    traces: list[Trace] = []

    json_files = _prov_json_files(trace_dir)
    subdirs = sorted(p for p in trace_dir.iterdir() if p.is_dir())
    if json_files and any(_prov_json_files(d) for d in subdirs):
        raise ValueError(
            f"{trace_dir}: holds both top-level traces and attack subdirectories; "
            "use one layout"
        )
    if json_files:
        # Flat layout
        for p in json_files:
            doc = _read_trace(p)
            ground_truth = "injection" in p.stem.lower()
            attack_type = "benign" if not ground_truth else "unknown"
            traces.append(Trace(
                doc=doc, trace_id=p.stem, ground_truth=ground_truth,
                task_subtype=_task_subtype(p.stem, ground_truth),
                suite=_suite_from_stem(p.stem),
                attack_type=attack_type,
            ))
    else:
        # Subdirectory layout — each subfolder is an attack type
        for subdir in subdirs:
            attack_type = subdir.name  # "benign", "direct", "injecagent", ...
            for p in _prov_json_files(subdir):
                doc = _read_trace(p)
                ground_truth = "injection" in p.stem.lower()
                # The same (suite, user_task, injection_task) stem is reused across
                # attack subdirs (direct/important_instructions/injecagent), so the
                # bare stem is NOT unique.  Prefix with attack_type to keep trace_id
                # unique — otherwise any per-trace join/dedup collapses the three
                # attacks into one.  _task_subtype / _suite_from_stem still operate
                # on the bare stem, so labelling is unaffected.
                traces.append(Trace(
                    doc=doc, trace_id=f"{attack_type}/{p.stem}", ground_truth=ground_truth,
                    task_subtype=_task_subtype(p.stem, ground_truth),
                    suite=_suite_from_stem(p.stem),
                    attack_type=attack_type,
                ))

    return traces


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli() -> None:
    parser = argparse.ArgumentParser(description="FLINT sweep runner")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--traces", required=True, type=Path,
                        help="Directory of *.json PROV-JSON trace files")
    parser.add_argument("--out", default="results/sweep.parquet", type=Path,
                        help="Output Parquet path for raw results")
    parser.add_argument("--metrics-out", default="results/metrics.parquet", type=Path,
                        help="Output Parquet path for aggregated metrics")
    args = parser.parse_args()

    config = SweepConfig.from_yaml(args.config)
    traces = load_traces_from_dir(args.traces)
    if not traces:
        # Fail, rather than exit 0 and leave a previous run's outputs looking current.
        sys.exit(f"No trace files found in {args.traces}")

    print(f"Running sweep: {len(traces)} traces x "
          f"{len(config.detectors)} detectors x "
          f"{len(config.adversaries)} adversaries")

    results = run_sweep(traces, config)
    save_parquet(results, args.out)
    print(f"Raw results -> {args.out}")

    metrics = compute_metrics(results)
    save_parquet(metrics, args.metrics_out)
    print(f"Metrics     -> {args.metrics_out}")
    print(metrics.to_string(index=False))


if __name__ == "__main__":
    _cli()
