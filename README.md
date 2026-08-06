# FLINT — Flow-INtegrity Tracking

Flow-typed provenance security for LLM agents.

FLINT takes an LLM agent's execution captured as [W3C PROV](https://www.w3.org/TR/prov-overview/)
and decides whether untrusted-origin data reached a privileged action along a path with
no authorised endorsement — the signature of a successful prompt injection. Around that
detector it ships an evasion testbed demonstrating that structural graph attacks cannot
silence it; only attacks on the trust labels themselves can.

This is the standalone, open-source detection/evasion framework. It is the capstone
software of the thesis *Provenance-Aware Security for Large Language Model Systems*
(Nicholas Jones, Torrens University Australia) and the manuscript *Trust
Attribution, Not Graph Structure: Locating the Security Signal in Provenance-Based
Defences for LLM Agents*. The manuscript, its experiment scripts (learned structural
baselines, white-box adaptive mimicry, endorsement and signed-label studies, cross-model
analysis), and the generated figures/tables are not included in this repository, as the
framework's purpose is to be a reference tool for other experiments or research.

> **What FLINT does not do.** FLINT does not run agents or capture provenance. It
> consumes PROV-JSON traces produced elsewhere — e.g. by the companion
> [AgentDojo-PROV](https://doi.org/10.5281/zenodo.21052314) corpus (17,664 traces
> across six LLM backends, published on Zenodo) — and performs detection and
> adversarial evaluation on them. It also does not compress provenance graphs:
> lossless provenance-graph compression is a separate published contribution
> (N. Jones, M. Whaiduzzaman, T. Jan, IEEE Trans. Artificial Intelligence, 2026,
> doi:10.1109/TAI.2026.3678891) and is not part of this framework.

---

## What's here

1. **Graph layer** (`flint/layer1_graph/`) — PROV-JSON → a typed NetworkX graph; the
   flow relation (information-bearing orientations of `used`, `wasGeneratedBy`,
   `wasDerivedFrom`, `wasInformedBy`); endorsement-avoiding reachability with witness
   extraction; a Graphviz renderer in W3C PROV visual notation.
2. **Detectors** (`flint/layer2_detectors/`):
   - `f_flow` — the label-aware detector: fires iff untrusted-origin data reaches a
     privileged sink along a path with no authorised endorsement (a Biba/Denning-style
     integrity-reachability predicate). `f_flow_detailed` also returns the witness paths.
   - `f_emb` — a deliberately integrity-agnostic structural baseline (WL 1-hop
     neighbourhood hash), with continuous-score and benign-profile novelty variants.
     It is the in-package, dependency-light stand-in for "detection by graph shape"
     that keeps the evasion sweep self-contained; the manuscript's headline structural
     baselines are learned models (GNN autoencoder, WL-feature detectors), which live
     with the experiment scripts in the manuscript repository.
3. **Evasion + orchestration** (`flint/layer3_orchestration/`) — a config-driven sweep
   over detector × adversary with parquet output and metrics aggregation, and the
   adversary module (`adversary.py`):
   - `structural_mimicry` (plus a budget-parametric variant) — adds benign-looking
     decoy substructure around untrusted entities; evades `f_emb`, never `f_flow`.
   - `trust_attribution_relabel` — forges source-integrity labels (⊥→⊤), emptying the
     untrusted-source set.
   - `trust_attribution_endorser` — fabricates endorsements, rerouting ⊥→sink flows
     through an inserted endorser.

The claim the framework exists to demonstrate (Theorems 1–2 of the manuscript): no
structural transformation can silence `f_flow`, because the untrusted→sink flow is
constitutive of the attack — so an evading adversary must forge a source-integrity
label or fabricate an endorsement, and no third option exists. The security signal in
agent provenance is trust attribution, not graph shape. In the sweep this appears as a
clean fingerprint: mimicry leaves `f_flow` untouched but evades the structural
baseline, while the relabel/endorser attacks evade `f_flow` and leave the structural
baseline untouched. Full proofs and the empirical evaluation (six agent backends,
learned baselines, adaptive mimicry, signed labels and capability-bound endorsements)
are in the manuscript.

---

## Repo layout

```
flint/
  paths.py               # corpus_root()/output_root() + corpus file iterators —
                         #   override via FLINT_CORPUS_ROOT / FLINT_OUTPUT_ROOT
  layer1_graph/          # load.py (PROV-JSON → typed graph) · flow.py (flow relation,
                         #   D-avoiding reachability, witnesses) · visualize.py
                         #   (Graphviz, W3C PROV visual notation)
  layer2_detectors/      # f_flow.py (D-avoiding reachability + witness API) ·
                         #   f_emb.py (WL neighbourhood hash + score/novelty variants)
  layer3_orchestration/  # runner.py (detector × adversary sweep, CLI) · adversary.py ·
                         #   metrics.py
configs/sweep.yaml        # example detector × adversary sweep config
tests/                    # 68-test pytest suite — no corpus/model required
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

Rendering PROV graphs with `visualize.py` additionally needs the Graphviz `dot`
binary on PATH; detection and the sweep do not.

---

## Usage

FLINT expects a corpus of PROV-JSON traces laid out as `<root>/<model>/prov/<attack>/*.json`
(see [`flint/paths.py`](flint/paths.py)), with two PROV extension attributes baked in at
capture time:

- entity nodes: `adprov:integrity` ∈ `{trusted, untrusted}`
- activity nodes: `adprov:role` ∈ `{neutral, sink, endorser}`

Point FLINT at a corpus and run the detector × adversary sweep:

```bash
export FLINT_CORPUS_ROOT=/path/to/corpus-prov   # a Zenodo download or your own capture
python -m flint.layer3_orchestration.runner \
    --config configs/sweep.yaml \
    --traces "$FLINT_CORPUS_ROOT/<model>/prov" \
    --out    results/sweep.parquet \
    --metrics-out results/metrics.parquet
```

`results/sweep.parquet` then holds one row per (trace, detector, adversary), with
ground truth, suite/attack metadata, and the detector verdict for computing TPR/FPR and
conditional-detection rates. (Rows also carry a constant `compression = "kappa_none"`
column, retained only so older downstream grouping keys keep working.)

The [AgentDojo-PROV](https://doi.org/10.5281/zenodo.21052314) corpus (six agent backends,
17,664 traces) is a ready-made corpus in this format if you don't have your own captures.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Citation

If you use FLINT, please cite:

```
Nicholas Jones. Provenance-Aware Security for Large Language Model Systems.
Torrens University Australia, 2026. Code: https://github.com/nickjones39/FLINT
```
