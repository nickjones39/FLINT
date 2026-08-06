"""Layer-3 metrics aggregation.

Converts the flat sweep DataFrame produced by runner.run_sweep into per-group
accuracy metrics and writes the results to Parquet.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd


def compute_metrics(results: pd.DataFrame) -> pd.DataFrame:
    """Compute TPR / FPR / precision per (detector, compression, adversary) group.

    Input DataFrame must have columns:
      detected (bool), ground_truth (bool),
      detector (str), compression (str), adversary (str).

    Returns one row per group with columns:
      tp, fp, tn, fn, tpr, fpr, precision, n_traces.
    """
    rows: list[dict] = []
    for (detector, compression, adversary), grp in results.groupby(
        ["detector", "compression", "adversary"]
    ):
        tp = int(((grp["detected"]) & (grp["ground_truth"])).sum())
        fp = int(((grp["detected"]) & (~grp["ground_truth"])).sum())
        tn = int(((~grp["detected"]) & (~grp["ground_truth"])).sum())
        fn = int(((~grp["detected"]) & (grp["ground_truth"])).sum())

        tpr = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
        fpr = fp / (fp + tn) if (fp + tn) > 0 else float("nan")
        precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")

        rows.append({
            "detector": detector,
            "compression": compression,
            "adversary": adversary,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "tpr": tpr, "fpr": fpr, "precision": precision,
            "n_traces": len(grp),
        })
    return pd.DataFrame(rows)


def save_parquet(df: pd.DataFrame, path: Path | str) -> None:
    """Write DataFrame to Parquet, creating parent directories as needed."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(p, index=False)
