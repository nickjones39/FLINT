"""Tests for Layer-3 orchestration runner and metrics.

Uses synthetic traces only; no model calls required.
Verifies that the sweep produces the expected shape and that the metrics
encode the P1/P2/P3/P4 thesis results.
"""
from __future__ import annotations

from pathlib import Path

import pytest

# The sweep runner is the [sweep] extra; skip cleanly on a core-only install.
pd = pytest.importorskip("pandas")
pytest.importorskip("yaml")
pytest.importorskip("pyarrow")

from flint.layer3_orchestration.metrics import compute_metrics  # noqa: E402
from flint.layer3_orchestration.runner import SweepConfig, Trace, run_sweep  # noqa: E402

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


# ---------------------------------------------------------------------------
# Config validation, trace loading, CLI, metrics edge cases (v0.2.1)
# ---------------------------------------------------------------------------

import json  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402

from flint.layer3_orchestration.runner import load_traces_from_dir  # noqa: E402


class TestSweepConfigValidation:
    @pytest.mark.parametrize("field,value", [
        ("adversaries", ["trust_attribution_relable"]),
        ("detectors", ["f_flw"]),
    ])
    def test_unknown_name_raises(self, field, value):
        with pytest.raises(ValueError, match="unknown"):
            SweepConfig(**{field: value})

    def test_bare_string_raises(self):
        with pytest.raises(ValueError, match="list"):
            SweepConfig(adversaries="none")  # type: ignore[arg-type]

    def test_empty_yaml_gives_defaults(self, tmp_path: Path):
        p = tmp_path / "cfg.yaml"
        p.write_text("")
        assert SweepConfig.from_yaml(p) == SweepConfig()

    @pytest.mark.parametrize("text,match", [
        ("- f_flow\n", "mapping"),
        ("detectors: [f_flow]\ncompressions: [kappa_none]\n", "unknown key"),
        ("adversaries: [nope]\n", "unknown adversary"),
    ])
    def test_bad_yaml_raises(self, tmp_path: Path, text, match):
        p = tmp_path / "cfg.yaml"
        p.write_text(text)
        with pytest.raises(ValueError, match=match):
            SweepConfig.from_yaml(p)


def _write(p: Path, doc: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc), encoding="utf-8")


class TestLoadTracesFromDir:
    def test_subdirectory_layout(self, tmp_path: Path):
        _write(tmp_path / "benign" / "banking_user_task_0_benign.json", _benign_doc())
        _write(tmp_path / "direct" / "workspace_user_task_13_injection_task_1.json", _injection_doc())
        _write(tmp_path / "direct" / "workspace_user_task_13_injection_task_1.transcript.json", {})
        (tmp_path / "direct" / "._workspace_user_task_13_injection_task_1.json").write_bytes(b"\x00\x05")
        traces = load_traces_from_dir(tmp_path)
        assert [(t.trace_id, t.ground_truth, t.attack_type, t.suite, t.task_subtype) for t in traces] == [
            ("benign/banking_user_task_0_benign", False, "benign", "banking", "write_involving"),
            ("direct/workspace_user_task_13_injection_task_1", True, "direct", "workspace", "injection"),
        ]

    def test_flat_layout(self, tmp_path: Path):
        _write(tmp_path / "user_task_1_benign.json", _benign_doc())
        _write(tmp_path / "user_task_1_injection_task_0.json", _injection_doc())
        traces = load_traces_from_dir(tmp_path)
        assert [(t.trace_id, t.attack_type, t.task_subtype) for t in traces] == [
            ("user_task_1_benign", "benign", "read_only"),
            ("user_task_1_injection_task_0", "unknown", "injection"),
        ]


class TestCLI:
    def test_cli_writes_sweep_and_metrics(self, tmp_path: Path):
        _write(tmp_path / "traces" / "benign" / "user_task_1_benign.json", _benign_doc())
        _write(tmp_path / "traces" / "direct" / "user_task_1_injection_task_0.json", _injection_doc())
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("detectors: [f_flow]\nadversaries: [none, trust_attribution_relabel]\n")
        out, metrics = tmp_path / "o" / "sweep.parquet", tmp_path / "o" / "metrics.parquet"
        r = subprocess.run(
            [sys.executable, "-m", "flint.layer3_orchestration.runner", "--config", str(cfg),
             "--traces", str(tmp_path / "traces"), "--out", str(out), "--metrics-out", str(metrics)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr
        m = pd.read_parquet(metrics).set_index("adversary")
        assert m.loc["none", "tpr"] == 1.0
        assert m.loc["trust_attribution_relabel", "tpr"] == 0.0
        assert len(pd.read_parquet(out)) == 4


class TestComputeMetricsEdgeCases:
    def test_object_dtype_is_rejected(self):
        df = run_sweep(_make_traces(), _full_config())
        df["detected"] = df["detected"].astype(object)
        with pytest.raises(ValueError, match="bool dtype"):
            compute_metrics(df)

    def test_empty_results(self):
        m = compute_metrics(pd.DataFrame())
        assert m.empty
        assert list(m.columns)[:3] == ["detector", "compression", "adversary"]


class TestTraceDirGuards:
    def test_non_prov_json_is_rejected(self, tmp_path: Path):
        # --traces pointed at a model dir: manifest.json beside prov/
        _write(tmp_path / "manifest.json", {"dataset": "AgentDojo-PROV", "corpus_version": "2.3"})
        _write(tmp_path / "prov" / "direct" / "user_task_1_injection_task_0.json", _injection_doc())
        with pytest.raises(ValueError, match="not a PROV-JSON trace"):
            load_traces_from_dir(tmp_path)

    def test_mixed_layout_is_rejected(self, tmp_path: Path):
        _write(tmp_path / "user_task_1_benign.json", _benign_doc())
        _write(tmp_path / "direct" / "user_task_1_injection_task_0.json", _injection_doc())
        with pytest.raises(ValueError, match="one layout"):
            load_traces_from_dir(tmp_path)

    def test_missing_directory(self, tmp_path: Path):
        with pytest.raises(NotADirectoryError):
            load_traces_from_dir(tmp_path / "nope")

    def test_subdirs_without_traces_are_not_mixed(self, tmp_path: Path):
        _write(tmp_path / "user_task_1_benign.json", _benign_doc())
        (tmp_path / "figures").mkdir()
        assert len(load_traces_from_dir(tmp_path)) == 1

    def test_cli_fails_on_empty_trace_dir_and_keeps_no_stale_success(self, tmp_path: Path):
        (tmp_path / "empty").mkdir()
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("detectors: [f_flow]\n")
        r = subprocess.run(
            [sys.executable, "-m", "flint.layer3_orchestration.runner", "--config", str(cfg),
             "--traces", str(tmp_path / "empty"), "--out", str(tmp_path / "s.parquet"),
             "--metrics-out", str(tmp_path / "m.parquet")],
            capture_output=True, text=True,
        )
        assert r.returncode != 0
        assert "No trace files found" in r.stderr
