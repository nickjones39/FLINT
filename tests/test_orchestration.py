"""Tests for Layer-3 orchestration runner and metrics.

Uses synthetic traces only; no model calls required.
Verifies that the sweep produces the expected shape and that the metrics
encode the P1/P2/P3/P4 thesis results.
"""
from __future__ import annotations

import math
from pathlib import Path

import pandas as pd
import pytest

from flint.layer3_orchestration.runner import SweepConfig, Trace, run_sweep
from flint.layer3_orchestration.metrics import compute_metrics


# ---------------------------------------------------------------------------
# Synthetic traces
# ---------------------------------------------------------------------------

def _injection_doc() -> dict:
    return {
        "prefix": {"flint": "http://flint.example.org/ns#"},
        "entity": {
            "adprov:e_email_out": {"prov:label": "email_output", "adprov:integrity": "untrusted"},
        },
        "activity": {
            "adprov:a_read": {"prov:label": "get_received_emails", "adprov:role": "neutral"},
            "adprov:a_send": {"prov:label": "send_email",           "adprov:role": "sink"},
        },
        "agent": {"adprov:ag_llm": {"prov:label": "llm_agent", "adprov:integrity": "trusted"}},
        "wasGeneratedBy": {
            "adprov:wgb1": {"prov:entity": "adprov:e_email_out", "prov:activity": "adprov:a_read", "prov:time": "T"},
        },
        "used": {
            "adprov:u1": {"prov:activity": "adprov:a_send", "prov:entity": "adprov:e_email_out", "prov:time": "T"},
        },
    }


def _benign_doc() -> dict:
    return {
        "prefix": {"flint": "http://flint.example.org/ns#"},
        "entity": {
            "adprov:e_cal_out": {"prov:label": "calendar_output", "adprov:integrity": "untrusted"},
        },
        "activity": {
            "adprov:a_cal": {"prov:label": "get_day_calendar_events", "adprov:role": "neutral"},
        },
        "agent": {"adprov:ag_llm": {"prov:label": "llm_agent", "adprov:integrity": "trusted"}},
        "wasGeneratedBy": {
            "adprov:wgb1": {"prov:entity": "adprov:e_cal_out", "prov:activity": "adprov:a_cal", "prov:time": "T"},
        },
    }


def _make_traces() -> list[Trace]:
    return [
        Trace(doc=_injection_doc(), trace_id="inj_01", ground_truth=True),
        Trace(doc=_benign_doc(),    trace_id="ben_01", ground_truth=False),
    ]


def _full_config() -> SweepConfig:
    return SweepConfig(
        detectors=["f_flow", "f_emb"],
        adversaries=["none", "structural_mimicry",
                     "trust_attribution_endorser", "trust_attribution_relabel"],
    )


# ---------------------------------------------------------------------------
# Runner shape tests
# ---------------------------------------------------------------------------

class TestRunSweepShape:
    def test_row_count(self):
        """2 traces x 2 detectors x 4 adversaries = 16 rows."""
        config = _full_config()
        traces = _make_traces()
        df = run_sweep(traces, config)
        expected = len(traces) * len(config.detectors) * len(config.adversaries)
        assert len(df) == expected

    def test_required_columns(self):
        df = run_sweep(_make_traces(), _full_config())
        for col in ("trace_id", "ground_truth", "detector", "compression",
                    "adversary", "detected", "n_nodes_orig", "n_edges_orig"):
            assert col in df.columns, f"missing column: {col}"

    def test_detected_is_bool(self):
        df = run_sweep(_make_traces(), _full_config())
        assert df["detected"].dtype == bool or df["detected"].map(type).eq(bool).all()

    def test_all_detectors_present(self):
        config = _full_config()
        df = run_sweep(_make_traces(), config)
        assert set(df["detector"].unique()) == set(config.detectors)

    def test_compression_column_is_a_constant(self):
        """The axis is gone but the column remains, so the downstream grouping
        key (detector, compression, adversary) is unchanged."""
        from flint.layer3_orchestration.runner import COMPRESSION
        df = run_sweep(_make_traces(), _full_config())
        assert set(df["compression"].unique()) == {COMPRESSION}

    def test_all_adversaries_present(self):
        config = _full_config()
        df = run_sweep(_make_traces(), config)
        assert set(df["adversary"].unique()) == set(config.adversaries)


# ---------------------------------------------------------------------------
# Thesis claim verification via sweep results
# ---------------------------------------------------------------------------

class TestThesisClaimsInSweep:
    """The sweep must reproduce the P1/P2/P3/P4 results numerically."""

    def _get(self, df: pd.DataFrame, detector: str, compression: str,
             adversary: str, trace_id: str) -> bool:
        row = df[
            (df["detector"] == detector) &
            (df["compression"] == compression) &
            (df["adversary"] == adversary) &
            (df["trace_id"] == trace_id)
        ]
        assert len(row) == 1, f"expected 1 row, got {len(row)}"
        return bool(row["detected"].iloc[0])

    def test_p1_f_flow_not_evaded_by_mimicry(self):
        """P1: f_flow detects injection even after structural_mimicry."""
        df = run_sweep(_make_traces(), _full_config())
        assert self._get(df, "f_flow", "kappa_none", "structural_mimicry", "inj_01") is True

    def test_p2_f_emb_evaded_by_mimicry(self):
        """P2: f_emb misses injection after structural_mimicry."""
        df = run_sweep(_make_traces(), _full_config())
        assert self._get(df, "f_emb", "kappa_none", "structural_mimicry", "inj_01") is False

    def test_p3_endorser_evades_f_flow(self):
        """P3: trust-attribution via endorser evades f_flow."""
        df = run_sweep(_make_traces(), _full_config())
        assert self._get(df, "f_flow", "kappa_none", "trust_attribution_endorser", "inj_01") is False

    def test_p3_relabel_evades_f_flow(self):
        """P3: relabelling ⊥→⊤ evades f_flow."""
        df = run_sweep(_make_traces(), _full_config())
        assert self._get(df, "f_flow", "kappa_none", "trust_attribution_relabel", "inj_01") is False

    def test_baseline_f_flow_detects_injection(self):
        df = run_sweep(_make_traces(), _full_config())
        assert self._get(df, "f_flow", "kappa_none", "none", "inj_01") is True

    def test_baseline_f_flow_clears_benign(self):
        df = run_sweep(_make_traces(), _full_config())
        assert self._get(df, "f_flow", "kappa_none", "none", "ben_01") is False

    def test_baseline_f_emb_detects_injection(self):
        df = run_sweep(_make_traces(), _full_config())
        assert self._get(df, "f_emb", "kappa_none", "none", "inj_01") is True

    def test_baseline_f_emb_clears_benign(self):
        df = run_sweep(_make_traces(), _full_config())
        assert self._get(df, "f_emb", "kappa_none", "none", "ben_01") is False


# ---------------------------------------------------------------------------
# SweepConfig YAML loading
# ---------------------------------------------------------------------------

class TestSweepConfig:
    def test_from_yaml(self, tmp_path: Path):
        import yaml
        cfg = {
            "detectors": ["f_flow"],
            "adversaries": ["none"],
        }
        p = tmp_path / "cfg.yaml"
        p.write_text(yaml.safe_dump(cfg))
        loaded = SweepConfig.from_yaml(p)
        assert loaded.detectors == ["f_flow"]
        assert loaded.adversaries == ["none"]

    def test_defaults(self):
        cfg = SweepConfig()
        assert "f_flow" in cfg.detectors
        assert "none" in cfg.adversaries


# ---------------------------------------------------------------------------
# Metrics tests
# ---------------------------------------------------------------------------

class TestComputeMetrics:
    def _results(self) -> pd.DataFrame:
        return run_sweep(_make_traces(), _full_config())

    def test_metrics_shape(self):
        df = self._results()
        m = compute_metrics(df)
        # 2 detectors x 4 adversaries = 8 groups (compression is constant)
        assert len(m) == 2 * 4

    def test_metrics_columns(self):
        m = compute_metrics(self._results())
        for col in ("detector", "compression", "adversary",
                    "tp", "fp", "tn", "fn", "tpr", "fpr", "precision"):
            assert col in m.columns

    def test_tpr_range(self):
        m = compute_metrics(self._results())
        valid = m["tpr"].dropna()
        assert (valid >= 0).all() and (valid <= 1).all()

    def test_f_flow_baseline_tpr_is_1(self):
        """With no adversary, f_flow should flag every injection trace (TPR=1)."""
        m = compute_metrics(self._results())
        row = m[(m["detector"] == "f_flow") &
                (m["compression"] == "kappa_none") &
                (m["adversary"] == "none")]
        assert len(row) == 1
        assert row["tpr"].iloc[0] == 1.0

    def test_f_flow_baseline_fpr_is_0(self):
        """With no adversary, f_flow should not flag any benign trace (FPR=0)."""
        m = compute_metrics(self._results())
        row = m[(m["detector"] == "f_flow") &
                (m["compression"] == "kappa_none") &
                (m["adversary"] == "none")]
        assert row["fpr"].iloc[0] == 0.0

    def test_f_emb_tpr_drops_under_mimicry(self):
        """P2: f_emb TPR should be 0 under structural_mimicry."""
        m = compute_metrics(self._results())
        row = m[(m["detector"] == "f_emb") &
                (m["compression"] == "kappa_none") &
                (m["adversary"] == "structural_mimicry")]
        assert len(row) == 1
        assert row["tpr"].iloc[0] == 0.0

    def test_f_flow_tpr_drops_under_endorser(self):
        """P3: f_flow TPR should be 0 under trust_attribution_endorser."""
        m = compute_metrics(self._results())
        row = m[(m["detector"] == "f_flow") &
                (m["compression"] == "kappa_none") &
                (m["adversary"] == "trust_attribution_endorser")]
        assert len(row) == 1
        assert row["tpr"].iloc[0] == 0.0

    def test_parquet_roundtrip(self, tmp_path: Path):
        from flint.layer3_orchestration.metrics import save_parquet
        df = self._results()
        p = tmp_path / "sweep.parquet"
        save_parquet(df, p)
        loaded = pd.read_parquet(p)
        assert len(loaded) == len(df)
        assert set(loaded.columns) == set(df.columns)
