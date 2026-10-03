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
  __init__.py            # the versioned public API (flint.__all__)
  spec.py                # the input vocabulary (adprov: labels) as constants
  errors.py              # ProvFormatError
  paths.py               # corpus_root()/output_root() + corpus file iterators —
                         #   override via FLINT_CORPUS_ROOT / FLINT_OUTPUT_ROOT
  layer1_graph/          # load.py (PROV-JSON → typed graph) · flow.py (flow relation,
                         #   D-avoiding reachability, witnesses) · visualize.py
                         #   (Graphviz, W3C PROV visual notation)
  layer2_detectors/      # f_flow.py (D-avoiding reachability + witness API) ·
                         #   f_emb.py (WL neighbourhood hash + score/novelty variants)
  layer3_orchestration/  # runner.py (detector × adversary sweep, CLI) · adversary.py ·
                         #   metrics.py
experiments/             # the learned structural baselines and the white-box adaptive
                         #   mimicry — run in place, not installed; see "Learned baselines"
configs/sweep.yaml       # example detector × adversary sweep config
docs/input-format.md     # the PROV-JSON input specification
tests/                   # pytest suite — no corpus/model required
pyproject.toml, uv.lock  # dependencies and extras; the lockfile CI installs from
CHANGELOG.md
```

---

## Learned baselines

`experiments/` holds the scripts behind the paper's learned structural detectors,
released so the reported protocol can be checked and re-run rather than taken on
trust.

| Script | What it runs |
|---|---|
| `learned_baseline.py` | GNN-AE and WL-IF (benign-trained novelty), GCN-CLF and WL-LR (supervised), plus the synthetic-benign retraining sweep |
| `label_aware_baseline.py` | the integrity-agnostic vs label-aware GCN transfer study |
| `adaptive_mimicry.py` | the white-box adaptive attacker against GNN-AE |
| `synthetic_benign.py` | the synthetic benign graphs used for the augmentation sweep |

These need PyTorch and scikit-learn, which the detector itself does not:

```bash
uv sync --extra experiments
uv run python experiments/learned_baseline.py --corpus <root>/<model>/prov
```

Each script writes the result JSON the paper's numbers are generated from.

**The protocol is in the code, not only in the paper.** Split fraction, epoch
counts, seed counts, layer widths, learning rate and decision threshold are
module-level constants in `learned_baseline.py` and `label_aware_baseline.py`
(`SPLIT_FRACTION`, `SUP_EPOCHS`, `SUP_SEEDS`, `AE_EPOCHS`, `NOVELTY_FOLDS`,
`LA_EPOCHS`, `LA_SEEDS`, …). The paper's protocol appendix imports and prints
those same names, so a change here changes the paper rather than silently
contradicting it. Two protocol notes worth knowing before comparing numbers:

- The supervised detectors take a `SPLIT_FRACTION` split of each class
  separately and then **balance the injection training pool down to the benign
  training size**, so most injection traces are never trained on; evaluation and
  the adversary transforms use the held-out injection graphs only.
- The novelty detectors never see an injection trace in training. They are
  fitted under `NOVELTY_FOLDS`-fold cross-validation over the benign class, with
  the threshold set to the maximum anomaly score on the *real* training benign
  (so training-benign false positives are zero by construction). Synthetic
  benign graphs enter training only and are never evaluated on.
- `learned_baseline.py` and `label_aware_baseline.py` are **separate runs with
  different epoch and seed counts**, so their numbers are not commensurable with
  each other. Compare within a script, not across the two.

Nothing is early-stopped and nothing is tuned: there is no validation set and no
hyperparameter search, so the constants are the defaults the first run used.

---

## Install

Requires Python ≥ 3.12. The distribution is **`flint-prov`**, and it imports as
**`flint`**. (`flint` on PyPI is an unrelated project, and `python-flint` also
imports as `flint`, so do not install either alongside it.) The detector depends only
on networkx; everything else is an extra.

| Extra | Adds | For |
|---|---|---|
| *(none)* | networkx | `load_prov_graph`, `f_flow`, the adversaries |
| `sweep` | pyyaml, pandas, pyarrow | the detector × adversary sweep (`runner.py`) |
| `viz` | prov, pydot | PROV rendering (`visualize.py`); also needs the Graphviz `dot` binary |
| `experiments` | numpy, torch, scikit-learn (+ `sweep`) | the learned baselines in `experiments/` |
| `all` | all of the above | |

### Developing (uv)

The repo is managed with [uv](https://docs.astral.sh/uv/). `uv.lock` pins every
dependency, and the `dev` group (pytest, ruff, mypy) is installed by default.

```bash
uv sync                     # core + dev tools
uv sync --all-extras        # everything (on Linux, torch comes from the CPU-only index)
uv run pytest -q            # no corpus or model needed
uv run ruff check flint tests
uv run mypy
```

On a core-only sync the sweep tests skip, and the rest still run. CI
(`.github/workflows/ci.yml`) runs both configurations: a core-only job on Python
3.12 and 3.13, and an all-extras job that also lints, type-checks and builds the
distribution.

### Using it from another project

```bash
uv add "flint-prov @ git+https://github.com/nickjones39/FLINT"            # core
uv add "flint-prov[sweep] @ git+https://github.com/nickjones39/FLINT"     # + sweep
uv add --editable ../flint-framework                                     # a local checkout
```

`pip install "flint-prov @ git+https://github.com/nickjones39/FLINT"` works the same
way if you do not use uv. Pin a release tag in production, e.g.
`flint-prov @ git+https://github.com/nickjones39/FLINT@v0.2.1`.

---

## Using FLINT in an application

```python
import flint

G = flint.load_prov_graph(doc, strict=True)   # doc: a PROV-JSON dict
result = flint.f_flow_detailed(G)
if result:
    for source, sink, path in result.witnesses:
        ...   # block, or ask the user
```

- **Write the labels FLINT reads.** Every entity needs `adprov:integrity` and every
  activity `adprov:role`. The vocabulary is specified in
  [`docs/input-format.md`](docs/input-format.md).
- **Load with `strict=True` in deployment.** Strict mode fails closed. An entity
  with a missing or unrecognised integrity label is treated as untrusted. A document
  raises `flint.ProvFormatError` if it has any of:
  - an unlabelled activity, or a role label on an entity or agent;
  - a dangling reference;
  - a bundle, or a PROV relation FLINT does not model;
  - a conflicting `adprov` prefix. The default mode
  (`strict=False`) is the one the published results use; on well-formed input the
  two give identical graphs.
- **Pin a version.** Only the names in `flint.__all__` form the versioned API.
- **Endorsements are not yet authenticated.** A forged `endorser` role or a relabelled
  entity evades `f_flow` by design. That is the trust attack the theory isolates.
  Signed labels and capability-bound endorsements are planned for v0.3.0.

---

## Usage

FLINT expects a corpus of PROV-JSON traces laid out as `<root>/<model>/prov/<attack>/*.json`
(see [`flint/paths.py`](flint/paths.py)), with two PROV extension attributes baked in at
capture time (full specification: [`docs/input-format.md`](docs/input-format.md)):

- entity nodes: `adprov:integrity` ∈ `{trusted, untrusted}`
- activity nodes: `adprov:role` ∈ `{neutral, sink, endorser}`

Point FLINT at a corpus and run the detector × adversary sweep (needs `[sweep]`):

```bash
export FLINT_CORPUS_ROOT=/path/to/corpus-prov   # a Zenodo download or your own capture
uv run python -m flint.layer3_orchestration.runner \
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

Citation metadata is in [`CITATION.cff`](CITATION.cff) (GitHub's "Cite this
repository" button reads it). Please cite the version you used. If you use FLINT,
please cite:

```
Nicholas Jones. Provenance-Aware Security for Large Language Model Systems.
Torrens University Australia, 2026. Code: https://github.com/nickjones39/FLINT
```
