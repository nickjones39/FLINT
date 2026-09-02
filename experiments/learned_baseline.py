"""Learned embedding-detector baselines for the P2/P3 robustness claims.

Reviewer concern: the paper's f_emb is a deterministic WL 1-hop hash, not a
*trained* graph encoder, so "embedding detectors remain evadable" would be
stronger with learned, SOTA-style baselines (Kairos/MAGIC/FLASH family).

This script adds two *trained-on-benign* anomaly detectors and re-tests the two
robustness propositions on them:

  * GNN-AE  — a MAGIC-style graph autoencoder (2-layer GCN encoder, linear
              feature decoder; anomaly = mean node-feature reconstruction error).
  * WL-IF   — a StreamSpot/Unicorn-style Weisfeiler-Lehman subtree histogram
              (feature-hashed) scored by an IsolationForest.

Both use ONLY structural features (node_type + per-relation in/out degree for the
GNN; node_type + relation labels for WL). Neither reads adprov:integrity or
adprov:role.  Consequences this script measures empirically:

  P2 (H1): structural mimicry (adversary.structural_mimicry) should still drive
           injection TPR down — a *learned* encoder is evadable too.
  P3 (H5): a trust-attribution relabel (adversary.trust_attribution_relabel)
           changes only integrity labels, which are NOT in the features, so the
           embeddings are unchanged and injection TPR should be preserved — the
           complementarity that defeats f_flow does NOT defeat a structural
           encoder.

Calibration: 5-fold over the benign traces.  In each fold the detector is fit on
4/5 of benign; the decision threshold is the max anomaly score over the training
benign (0% train-benign FPR); held-out benign give the reported FPR and all
injection traces give TPR.  Adversary transforms are applied to injection traces
only (the deployment framing), benign FPR is reported on clean held-out benign.

Run:
    conda run -n flint python experiments/learned_baseline.py \
        --corpus results/corpus-prov/prov-deepseek-chat/prov
"""
from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path

from flint.paths import corpus_dir

import numpy as np

from flint.layer1_graph.load import load_prov_graph
from flint.layer3_orchestration.adversary import (
    structural_mimicry,
    trust_attribution_relabel,
)
from flint.layer3_orchestration.runner import load_traces_from_dir

try:  # works as `python experiments/learned_baseline.py` and `python -m experiments...`
    from experiments.synthetic_benign import generate_benign_graphs
except ModuleNotFoundError:
    from synthetic_benign import generate_benign_graphs

SEED = 0

# ---------------------------------------------------------------------------
# Protocol constants. Named rather than inlined so the manuscript's appendix can
# import and print them: the reported protocol is then the executed protocol by
# construction, not a prose transcription of it that can drift.
# ---------------------------------------------------------------------------
SPLIT_FRACTION = 0.7      # supervised: train fraction, benign and injection separately
SUP_EPOCHS = 150          # supervised classifier training epochs (fixed, no early stopping)
SUP_SEEDS = 3             # supervised: split seeds averaged over
AE_EPOCHS = 200           # benign-trained autoencoder training epochs (fixed)
NOVELTY_FOLDS = 5         # benign-trained novelty: cross-validation folds over benign
HIDDEN_DIM = 16           # GCN layer 1 width
EMBED_DIM = 8             # GCN layer 2 width
LR = 1e-2                 # Adam learning rate
WEIGHT_DECAY = 1e-4       # Adam weight decay
DECISION_THRESHOLD = 0.5  # supervised: sigmoid cut
WL_DEPTH = 2              # Weisfeiler-Lehman iterations
WL_DIM = 1024             # WL feature-hashing dimension
IFOREST_TREES = 200       # IsolationForest estimators
LOGREG_MAX_ITER = 2000    # logistic-regression solver cap

NODE_TYPES = ("entity", "activity", "agent")
REL_TYPES = ("used", "wasGeneratedBy", "wasDerivedFrom", "wasInformedBy")


# ---------------------------------------------------------------------------
# Structural featurisation (integrity- AND role-agnostic)
# ---------------------------------------------------------------------------

def node_feature_matrix(G) -> tuple[np.ndarray, dict[str, int]]:
    """N x F structural node features: node_type one-hot + per-relation out/in degree."""
    nodes = list(G.nodes())
    idx = {n: i for i, n in enumerate(nodes)}
    F = len(NODE_TYPES) + 2 * len(REL_TYPES)
    X = np.zeros((len(nodes), F), dtype=np.float32)
    for n, i in idx.items():
        nt = G.nodes[n].get("node_type", "?")
        if nt in NODE_TYPES:
            X[i, NODE_TYPES.index(nt)] = 1.0
        for nb in G.successors(n):
            r = G.edges[n, nb].get("relation", "?")
            if r in REL_TYPES:
                X[i, len(NODE_TYPES) + REL_TYPES.index(r)] += 1.0
        for nb in G.predecessors(n):
            r = G.edges[nb, n].get("relation", "?")
            if r in REL_TYPES:
                X[i, len(NODE_TYPES) + len(REL_TYPES) + REL_TYPES.index(r)] += 1.0
    return X, idx


def norm_adj(G, idx: dict[str, int]) -> np.ndarray:
    """Symmetric-normalised adjacency with self-loops:  D^-1/2 (A+I) D^-1/2."""
    n = len(idx)
    A = np.eye(n, dtype=np.float32)
    for u, v in G.edges():
        i, j = idx[u], idx[v]
        A[i, j] = 1.0
        A[j, i] = 1.0  # treat as undirected for message passing
    deg = A.sum(1)
    dinv = np.where(deg > 0, deg ** -0.5, 0.0)
    return (dinv[:, None] * A) * dinv[None, :]


# ---------------------------------------------------------------------------
# GNN-AE (MAGIC-style graph autoencoder, pure torch, dense adjacency)
# ---------------------------------------------------------------------------

def _build_gnn(in_dim: int, hid: int = HIDDEN_DIM, emb: int = EMBED_DIM):
    import torch
    import torch.nn as nn

    class GCNAE(nn.Module):
        def __init__(self):
            super().__init__()
            self.w1 = nn.Linear(in_dim, hid)
            self.w2 = nn.Linear(hid, emb)
            self.dec = nn.Linear(emb, in_dim)

        def forward(self, X, Ah):
            h = torch.relu(Ah @ self.w1(X))
            z = Ah @ self.w2(h)
            return self.dec(z)

    return GCNAE()


def gnn_scores(train_graphs, eval_graphs, epochs: int = AE_EPOCHS) -> tuple[np.ndarray, np.ndarray]:
    """Train GCN-AE on benign train_graphs; return (train_scores, eval_scores)."""
    import torch

    torch.manual_seed(SEED)
    in_dim = len(NODE_TYPES) + 2 * len(REL_TYPES)
    model = _build_gnn(in_dim)
    opt = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)

    tens = []
    for G in train_graphs:
        X, idx = node_feature_matrix(G)
        if X.shape[0] == 0:
            continue
        tens.append((torch.tensor(X), torch.tensor(norm_adj(G, idx))))

    model.train()
    for _ in range(epochs):
        random.shuffle(tens)
        for X, Ah in tens:
            opt.zero_grad()
            loss = ((model(X, Ah) - X) ** 2).mean()
            loss.backward()
            opt.step()

    model.eval()

    def score(graphs):
        out = []
        with torch.no_grad():
            for G in graphs:
                X, idx = node_feature_matrix(G)
                if X.shape[0] == 0:
                    out.append(0.0)
                    continue
                Xt, Ah = torch.tensor(X), torch.tensor(norm_adj(G, idx))
                out.append(float(((model(Xt, Ah) - Xt) ** 2).mean()))
        return np.array(out)

    return score(train_graphs), score


# ---------------------------------------------------------------------------
# WL subtree histogram + IsolationForest
# ---------------------------------------------------------------------------

def wl_features(G, h: int = WL_DEPTH, dim: int = WL_DIM) -> np.ndarray:
    """Feature-hashed Weisfeiler-Lehman subtree histogram (structural only)."""
    import hashlib

    def bucket(s: str) -> int:
        return int(hashlib.md5(s.encode()).hexdigest(), 16) % dim

    colors = {n: f"nt:{G.nodes[n].get('node_type', '?')}" for n in G.nodes()}
    vec = np.zeros(dim, dtype=np.float32)
    for c in colors.values():
        vec[bucket(c)] += 1.0
    for _ in range(h):
        nxt = {}
        for n in G.nodes():
            nbrs = sorted(
                [f">{G.edges[n, nb].get('relation', '?')}|{colors[nb]}" for nb in G.successors(n)]
                + [f"<{G.edges[nb, n].get('relation', '?')}|{colors[nb]}" for nb in G.predecessors(n)]
            )
            nxt[n] = "wl|" + colors[n] + "|" + "|".join(nbrs)
        colors = nxt
        for c in colors.values():
            vec[bucket(c)] += 1.0
    return vec


def wl_if_scores(train_graphs, eval_graphs):
    from sklearn.ensemble import IsolationForest

    Xtr = np.array([wl_features(G) for G in train_graphs])
    clf = IsolationForest(n_estimators=IFOREST_TREES, random_state=SEED).fit(Xtr)
    # higher score_samples = more normal; anomaly = negated
    train_scores = -clf.score_samples(Xtr)

    def score(graphs):
        return -clf.score_samples(np.array([wl_features(G) for G in graphs]))

    return train_scores, score


# ---------------------------------------------------------------------------
# Evaluation harness
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Supervised structural classifiers (the learned analogue of the f_emb pattern
# detector: trained to recognise the injection STRUCTURE, integrity-agnostic)
# ---------------------------------------------------------------------------

def gcn_clf_fit(train_graphs, labels, epochs: int = SUP_EPOCHS):
    """Supervised 2-layer GCN graph classifier (mean-pool + linear head)."""
    import torch
    import torch.nn as nn

    torch.manual_seed(SEED)
    in_dim = len(NODE_TYPES) + 2 * len(REL_TYPES)

    class GCNClf(nn.Module):
        def __init__(self):
            super().__init__()
            self.w1 = nn.Linear(in_dim, HIDDEN_DIM)
            self.w2 = nn.Linear(HIDDEN_DIM, EMBED_DIM)
            self.head = nn.Linear(EMBED_DIM, 1)

        def forward(self, X, Ah):
            h = torch.relu(Ah @ self.w1(X))
            z = Ah @ self.w2(h)
            return self.head(z.mean(0))  # graph-level logit

    model = GCNClf()
    opt = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    lossf = nn.BCEWithLogitsLoss()

    data = []
    for G, y in zip(train_graphs, labels):
        X, idx = node_feature_matrix(G)
        if X.shape[0] == 0:
            continue
        data.append((torch.tensor(X), torch.tensor(norm_adj(G, idx)), torch.tensor([float(y)])))

    model.train()
    for _ in range(epochs):
        random.shuffle(data)
        for X, Ah, y in data:
            opt.zero_grad()
            lossf(model(X, Ah), y).backward()
            opt.step()
    model.eval()

    def predict(graphs):
        out = []
        with torch.no_grad():
            for G in graphs:
                X, idx = node_feature_matrix(G)
                if X.shape[0] == 0:
                    out.append(0.0)
                    continue
                p = torch.sigmoid(model(torch.tensor(X), torch.tensor(norm_adj(G, idx))))
                out.append(float(p))
        return np.array(out)

    return predict


def wl_lr_fit(train_graphs, labels):
    """WL subtree histogram + standardised logistic regression."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    X = np.array([wl_features(G) for G in train_graphs])
    scaler = StandardScaler().fit(X)
    clf = LogisticRegression(max_iter=LOGREG_MAX_ITER, class_weight="balanced").fit(scaler.transform(X), labels)

    def predict(graphs):
        return clf.predict_proba(scaler.transform(np.array([wl_features(G) for G in graphs])))[:, 1]

    return predict


@dataclass
class Row:
    detector: str
    kind: str
    fpr: float
    tpr_clean: float
    tpr_mimicry: float
    tpr_relabel: float
    n_synth: int = 0  # synthetic benign graphs added to TRAINING only (0 = real-only baseline)


def _novelty_rows(benign, inj, inj_mim, inj_rel, folds: int, synth_benign=()) -> list[Row]:
    """Benign-trained novelty detectors, optionally augmented with synthetic benign.

    Synthetic benign graphs enter the *training* set only; the decision threshold
    is calibrated on the real training benign (0% real-train FPR, comparable
    across synth sizes), FPR is measured on real held-out benign, and TPR on the
    real injection traces. Synthetic graphs never appear in evaluation.
    """
    detectors = {"GNN-AE": gnn_scores, "WL-IF": wl_if_scores}
    synth_benign = list(synth_benign)
    rows: list[Row] = []
    for name, fit_fn in detectors.items():
        order = list(range(len(benign)))
        random.shuffle(order)
        fold_sz = max(1, len(order) // folds)
        fp = bn = 0
        tc, tm, tr = [], [], []
        for f in range(folds):
            test_ids = set(order[f * fold_sz:(f + 1) * fold_sz]) if f < folds - 1 else set(order[f * fold_sz:])
            real_train = [benign[i] for i in order if i not in test_ids]
            held = [benign[i] for i in test_ids]
            if not real_train or not held:
                continue
            _, scorer = fit_fn(real_train + synth_benign, None)
            thr = float(scorer(real_train).max())  # calibrate on REAL benign only
            fp += int((scorer(held) > thr).sum())
            bn += len(held)
            tc.append(float((scorer(inj) > thr).mean()))
            tm.append(float((scorer(inj_mim) > thr).mean()))
            tr.append(float((scorer(inj_rel) > thr).mean()))
        rows.append(Row(name, "novelty(benign-trained)", fp / bn if bn else float("nan"),
                        float(np.mean(tc)), float(np.mean(tm)), float(np.mean(tr)),
                        n_synth=len(synth_benign)))
    return rows


def _novelty_sweep(benign, inj, inj_mim, inj_rel, folds, synth_sizes, synth_seed) -> list[Row]:
    """Run the benign-trained novelty detectors across a range of synthetic-benign
    training-set sizes. A flat clean-injection TPR as the benign training set grows
    is the answer to the ``undertrained baseline'' objection."""
    rows: list[Row] = []
    for s in synth_sizes:
        synth = generate_benign_graphs(s, seed=synth_seed) if s else []
        print(f"[synth={s}] training novelty detectors on real+{s} benign ...")
        rows += _novelty_rows(benign, inj, inj_mim, inj_rel, folds, synth)
    return rows


def _supervised_rows(benign, inj, inj_mim, inj_rel, seeds: int = SUP_SEEDS) -> list[Row]:
    """Train benign-vs-injection on a balanced split; eval on held-out injection."""
    detectors = {"GCN-CLF": gcn_clf_fit, "WL-LR": wl_lr_fit}
    rows: list[Row] = []
    for name, fit_fn in detectors.items():
        fprs, tcs, tms, trs = [], [], [], []
        for s in range(seeds):
            rng = random.Random(SEED + s)
            b_order, i_order = list(range(len(benign))), list(range(len(inj)))
            rng.shuffle(b_order)
            rng.shuffle(i_order)
            b_cut, i_cut = int(SPLIT_FRACTION * len(benign)), int(SPLIT_FRACTION * len(inj))
            b_tr, b_te = b_order[:b_cut], b_order[b_cut:]
            i_tr_all, i_te = i_order[:i_cut], i_order[i_cut:]
            i_tr = i_tr_all[:len(b_tr)]  # balance training set to benign size
            tr_graphs = [benign[i] for i in b_tr] + [inj[i] for i in i_tr]
            tr_labels = [0] * len(b_tr) + [1] * len(i_tr)
            predict = fit_fn(tr_graphs, tr_labels)
            fprs.append(float((predict([benign[i] for i in b_te]) > DECISION_THRESHOLD).mean()))
            tcs.append(float((predict([inj[i] for i in i_te]) > DECISION_THRESHOLD).mean()))
            tms.append(float((predict([inj_mim[i] for i in i_te]) > DECISION_THRESHOLD).mean()))
            trs.append(float((predict([inj_rel[i] for i in i_te]) > DECISION_THRESHOLD).mean()))
        rows.append(Row(name, "supervised(struct.)", float(np.mean(fprs)),
                        float(np.mean(tcs)), float(np.mean(tms)), float(np.mean(trs))))
    return rows


def evaluate(corpus: Path, folds: int = NOVELTY_FOLDS, synth_sizes=(0,), synth_seed: int = 0,
             include_supervised: bool = True) -> list[Row]:
    random.seed(SEED)
    np.random.seed(SEED)
    traces = load_traces_from_dir(corpus)
    benign = [load_prov_graph(t.doc) for t in traces if not t.ground_truth]
    inj = [load_prov_graph(t.doc) for t in traces if t.ground_truth]
    print(f"Loaded {len(benign)} benign + {len(inj)} injection graphs from {corpus}")
    inj_mim = [structural_mimicry(G) for G in inj]
    inj_rel = [trust_attribution_relabel(G) for G in inj]
    rows = _novelty_sweep(benign, inj, inj_mim, inj_rel, folds, synth_sizes, synth_seed)
    # The supervised classifiers are synth-independent; we omit them from a synth
    # *sweep* so the novelty trend writes to its own file and the canonical
    # learned_baseline.json (with supervised rows) stays byte-stable.
    if include_supervised:
        rows += _supervised_rows(benign, inj, inj_mim, inj_rel)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, default=corpus_dir("prov-deepseek-chat") / "prov")
    ap.add_argument("--out", type=Path, default=None,
                    help="output JSON (default: results/learned_baseline.json for the "
                         "canonical run, results/learned_baseline_synth.json for a sweep).")
    ap.add_argument("--synth-benign", default="0",
                    help="comma-separated synthetic-benign training sizes to sweep "
                         "(novelty detectors only), e.g. '0,500,2000,5000'. "
                         "0 = real-only baseline. Synthetic benign augments TRAINING "
                         "only; FPR/TPR are always measured on real data.")
    ap.add_argument("--synth-seed", type=int, default=0)
    args = ap.parse_args()

    synth_sizes = [int(x) for x in str(args.synth_benign).split(",") if x.strip() != ""]
    sweeping = any(s > 0 for s in synth_sizes)
    out = args.out or Path("results/learned_baseline_synth.json" if sweeping
                           else "results/learned_baseline.json")
    rows = evaluate(args.corpus, synth_sizes=synth_sizes, synth_seed=args.synth_seed,
                    include_supervised=not sweeping)

    print(f"\n{'detector':9s} {'paradigm':24s} {'n_synth':>7s} {'FPR':>6s} "
          f"{'TPR_clean':>10s} {'TPR_mim':>8s} {'TPR_rel':>8s}")
    print("-" * 80)
    for r in rows:
        print(f"{r.detector:9s} {r.kind:24s} {r.n_synth:7d} {r.fpr:6.1%} "
              f"{r.tpr_clean:10.1%} {r.tpr_mimicry:8.1%} {r.tpr_relabel:8.1%}")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([r.__dict__ for r in rows], indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
