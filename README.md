# FLINT — Flow-INtegrity Tracking

Flow-typed provenance security for LLM agents.

FLINT takes an LLM agent's execution captured as [W3C PROV](https://www.w3.org/TR/prov-overview/),
detects prompt-injection attacks by information-flow reachability, compresses the
provenance graph while preserving that detection, and runs an evasion testbed against
both a structural detector and a trust-attribution attacker.

This is the standalone, open-source detection/compression/evasion framework. It is the
capstone software of the thesis *Provenance-Based Cybersecurity for Large Language
Models* (Nicholas Jones, Torrens University Australia) and the manuscript *Trust
Attribution, Not Graph Structure: Locating the Security Signal in Provenance-Based
Defences for LLM Agents*. The manuscript, experiment scripts, and generated
figures/tables live in a separate (private) repository; this repo is the reusable
library and detector implementations.

> **What FLINT does not do.** FLINT does not run agents or capture provenance. It
> consumes PROV-JSON traces produced elsewhere — e.g. by the companion
> [AgentDojo-PROV](https://doi.org/10.5281/zenodo.21052314) corpus (17,664 traces
> across six LLM backends, published on Zenodo) — and performs detection, compression,
> and adversarial evaluation on them.

---

## What's here

1. **Graph layer** (`flint/layer1_graph/`) — PROV-JSON → a typed NetworkX graph with
   flow-relation edge orientations, plus compression operators:
   - `κ_none` — identity (no compression)
   - `κ_naive` — top-K downsampling (a reachability-lossy baseline)
   - `κ_flow` — a flow-preserving structural merge that provably preserves `f_flow`'s
     verdict
2. **Detectors** (`flint/layer2_detectors/`):
   - `f_flow` — a label-aware detector: fires iff untrusted-origin data reaches a
     privileged sink along a path with no authorised endorsement (a Biba/Denning-style
     integrity reachability predicate).
   - `f_emb` — a structural, integrity-agnostic neighbourhood-hash baseline (a
     Prov-HIDS-style detector), used to demonstrate that graph *shape* alone is an
     insufficient security signal.
3. **Orchestration** (`flint/layer3_orchestration/`) — a config-driven sweep over
   detector × compression × adversary, an adversary module (`adversary.py`) implementing
   structural mimicry and trust-attribution attacks (label relabelling, forged
   endorsements), and metrics aggregation.

The central result the framework is built to demonstrate: structural mimicry cannot
evade `f_flow` (the untrusted→sink path is constitutive of the attack), but it *can*
evade a purely structural detector — so evading `f_flow` necessarily requires attacking
trust attribution (the integrity labels or the endorsement set), not graph shape.
Full proofs and the empirical evaluation are in the manuscript.

---

## Repo layout

```
flint/
  paths.py               # corpus_root()/output_root() — override via FLINT_CORPUS_ROOT /
                         #   FLINT_OUTPUT_ROOT env vars
  layer1_graph/          # load.py, flow.py, compress.py (κ_none/κ_naive/κ_flow),
                         # structural_hash.py (κ_flow merge engine), visualize.py
  layer2_detectors/      # f_flow.py (D-avoiding BFS/DFS) · f_emb.py (WL neighbourhood hash)
  layer3_orchestration/  # runner.py (sweep) · budget_sweep.py · metrics.py · adversary.py
configs/sweep.yaml        # example detector x adversary sweep config
tests/                    # pytest suite — no corpus/model required
```

---

## Install

Requires Python ≥ 3.12.

```bash
python -m venv .venv && source .venv/bin/activate   # or conda create -n flint python=3.12
pip install -e .
```

Verify the install (no corpus or model needed):

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

---

## Usage

FLINT expects a corpus of PROV-JSON traces laid out as `<root>/<model>/prov/<attack>/*.json`
(see [`flint/paths.py`](flint/paths.py)), with two PROV extension attributes baked in at
capture time:

- entity nodes: `adprov:integrity` ∈ `{trusted, untrusted}`
- activity nodes: `adprov:role` ∈ `{neutral, sink, endorser}`

Point FLINT at a corpus and run the detector × compression × adversary sweep:

```bash
export FLINT_CORPUS_ROOT=/path/to/corpus-prov   # a Zenodo download or your own capture
python -m flint.layer3_orchestration.runner \
    --config configs/sweep.yaml \
    --traces "$FLINT_CORPUS_ROOT/<model>/prov" \
    --out    results/sweep.parquet \
    --metrics-out results/metrics.parquet
```

`results/sweep.parquet` then holds one row per (trace, detector, compression, adversary),
with predicted/actual labels for computing TPR/FPR and conditional-detection rates.

The [AgentDojo-PROV](https://doi.org/10.5281/zenodo.21052314) corpus (six agent backends,
17,664 traces) is a ready-made corpus in this format if you don't have your own captures.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Citation

If you use FLINT, please cite:

```
Nicholas Jones. Provenance-Based Cybersecurity for Large Language Models.
Torrens University Australia, 2026. Code: https://github.com/nickjones39/FLINT
```
