"""Label-aware structural baseline — reviewer ablation.

Question: does *simple feature augmentation* close the gap with f_flow? We give a
supervised GCN the two signals f_flow uses --- the integrity label (bottom/top) and
the sink/endorser role --- as node features on top of the structural features, and
compare against:
  * the integrity-AGNOSTIC GCN (the paper's GCN-CLF baseline), and
  * f_flow itself,
under no adversary, structural mimicry (P2), and a trust-attribution relabel (P3).

Finding (see the printout / results JSON): label-awareness moves the learned
detector toward f_flow's operating point --- confirming the integrity label, not
graph structure, is the discriminating signal --- but (a) it does NOT exceed f_flow,
and (b) by *consuming* the label it inherits f_flow's relabel vulnerability (its TPR
collapses under the P3 relabel, whereas the integrity-agnostic GCN is unaffected),
empirically realising the transfer-to-the-defence-class proposition: any
label-consuming detector is evaded by the same trust-attribution attack, and only
*signing* the label closes it. The learned model also lacks f_flow's PROVABLE
mimicry-robustness and its determinism.

Run:
    conda run -n flint python experiments/label_aware_baseline.py \
        results/corpus-prov/prov-deepseek-chat results/corpus-prov/prov-gpt-5-nano
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import numpy as np

from flint.layer1_graph.flow import check_flow
from flint.layer1_graph.load import load_prov_graph
from flint.layer3_orchestration.adversary import (
    structural_mimicry,
    trust_attribution_relabel,
)
from flint.layer3_orchestration.runner import load_traces_from_dir

try:
    from experiments.learned_baseline import (  # noqa: F401
        NODE_TYPES, REL_TYPES, SEED, norm_adj,
        DECISION_THRESHOLD, EMBED_DIM, HIDDEN_DIM, LR, SPLIT_FRACTION, WEIGHT_DECAY,
    )
except ModuleNotFoundError:
    from learned_baseline import (  # noqa: F401
        NODE_TYPES, REL_TYPES, SEED, norm_adj,
        DECISION_THRESHOLD, EMBED_DIM, HIDDEN_DIM, LR, SPLIT_FRACTION, WEIGHT_DECAY,
    )

INTEG = ("untrusted", "trusted")  # bottom, top; absent -> all-zero
ROLES = ("sink", "endorser")      # neutral -> all-zero


def feat(G, label_aware: bool):
    """Structural features, optionally augmented with integrity + role one-hots."""
    nodes = list(G.nodes())
    idx = {n: i for i, n in enumerate(nodes)}
    Fs = len(NODE_TYPES) + 2 * len(REL_TYPES)
    Fl = (len(INTEG) + len(ROLES)) if label_aware else 0
    X = np.zeros((len(nodes), Fs + Fl), dtype=np.float32)
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
        if label_aware:
            ig = G.nodes[n].get("adprov:integrity")
            if ig in INTEG:
                X[i, Fs + INTEG.index(ig)] = 1.0
            ro = G.nodes[n].get("adprov:role")
            if ro in ROLES:
                X[i, Fs + len(INTEG) + ROLES.index(ro)] = 1.0
    return X, idx


LA_EPOCHS = 250   # label-aware transfer study: training epochs (fixed, no early stopping)
LA_SEEDS = 5      # label-aware transfer study: seeds averaged over (model init AND split vary)


def gcn_fit(train_graphs, labels, label_aware: bool, seed: int = SEED, epochs: int = LA_EPOCHS):
    import torch
    import torch.nn as nn

    torch.manual_seed(seed)
    shuffler = random.Random(seed)  # local RNG -> deterministic, independent of global state
    in_dim = len(NODE_TYPES) + 2 * len(REL_TYPES) + (
        (len(INTEG) + len(ROLES)) if label_aware else 0)

    class GCNClf(nn.Module):
        def __init__(self):
            super().__init__()
            self.w1 = nn.Linear(in_dim, HIDDEN_DIM)
            self.w2 = nn.Linear(HIDDEN_DIM, EMBED_DIM)
            self.head = nn.Linear(EMBED_DIM, 1)

        def forward(self, X, Ah):
            h = torch.relu(Ah @ self.w1(X))
            z = Ah @ self.w2(h)
            return self.head(z.mean(0))

    model = GCNClf()
    opt = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    lossf = nn.BCEWithLogitsLoss()
    data = []
    for G, y in zip(train_graphs, labels):
        X, idx = feat(G, label_aware)
        if X.shape[0] == 0:
            continue
        data.append((torch.tensor(X), torch.tensor(norm_adj(G, idx)), torch.tensor([float(y)])))
    model.train()
    for _ in range(epochs):
        shuffler.shuffle(data)
        for X, Ah, y in data:
            opt.zero_grad()
            lossf(model(X, Ah), y).backward()
            opt.step()
    model.eval()

    def predict(graphs):
        import torch
        out = []
        with torch.no_grad():
            for G in graphs:
                X, idx = feat(G, label_aware)
                if X.shape[0] == 0:
                    out.append(0.0)
                    continue
                out.append(float(torch.sigmoid(model(torch.tensor(X), torch.tensor(norm_adj(G, idx))))))
        return np.array(out)

    return predict


def run(corpus: Path, seeds: int = LA_SEEDS) -> dict:
    random.seed(SEED)
    np.random.seed(SEED)
    # Accept either the model dir (results/corpus-prov/<model>) or its prov/
    # subdir.  load_traces_from_dir on the model dir would pick up manifest.json
    # as a lone "flat" trace and miss the corpus entirely, so descend into prov/.
    prov_dir = corpus / "prov" if (corpus / "prov").is_dir() else corpus
    traces = load_traces_from_dir(prov_dir)
    benign = [load_prov_graph(t.doc) for t in traces if not t.ground_truth]
    inj = [load_prov_graph(t.doc) for t in traces if t.ground_truth]
    inj_mim = [structural_mimicry(G) for G in inj]
    inj_rel = [trust_attribution_relabel(G) for G in inj]
    print(f"  loaded {len(benign)} benign + {len(inj)} injection graphs")

    out: dict = {}
    for la, name in [(False, "GCN (struct., agnostic)"), (True, "GCN (label-aware)")]:
        fp, tc, tm, tr = [], [], [], []
        for s in range(seeds):
            rng = random.Random(SEED + s)
            bo, io = list(range(len(benign))), list(range(len(inj)))
            rng.shuffle(bo)
            rng.shuffle(io)
            bc, ic = int(SPLIT_FRACTION * len(benign)), int(SPLIT_FRACTION * len(inj))
            b_tr, b_te = bo[:bc], bo[bc:]
            i_tr_all, i_te = io[:ic], io[ic:]
            i_tr = i_tr_all[:len(b_tr)]
            tg = [benign[i] for i in b_tr] + [inj[i] for i in i_tr]
            tl = [0] * len(b_tr) + [1] * len(i_tr)
            pred = gcn_fit(tg, tl, la, seed=SEED + s)
            fp.append(float((pred([benign[i] for i in b_te]) > DECISION_THRESHOLD).mean()))
            tc.append(float((pred([inj[i] for i in i_te]) > DECISION_THRESHOLD).mean()))
            tm.append(float((pred([inj_mim[i] for i in i_te]) > DECISION_THRESHOLD).mean()))
            tr.append(float((pred([inj_rel[i] for i in i_te]) > DECISION_THRESHOLD).mean()))
        out[name] = dict(fpr=float(np.mean(fp)), tpr=float(np.mean(tc)),
                         tpr_mim=float(np.mean(tm)), tpr_rel=float(np.mean(tr)))

    # f_flow reference (deterministic; full sets)
    out["f_flow (ours)"] = dict(
        fpr=float(np.mean([check_flow(G) for G in benign])),
        tpr=float(np.mean([check_flow(G) for G in inj])),
        tpr_mim=float(np.mean([check_flow(G) for G in inj_mim])),
        tpr_rel=float(np.mean([check_flow(G) for G in inj_rel])),
    )
    return out


def main(argv):
    results = {}
    for c in argv:
        cp = Path(c)
        name = cp.parent.name if cp.name == "prov" else cp.name
        print(f"\n=== {name} ===")
        r = run(Path(c))
        results[name] = r
        print(f"  {'detector':24s} {'FPR':>6s} {'TPR':>6s} {'TPR_mim(P2)':>12s} {'TPR_rel(P3)':>12s}")
        for det, m in r.items():
            print(f"  {det:24s} {m['fpr']:6.1%} {m['tpr']:6.1%} "
                  f"{m['tpr_mim']:12.1%} {m['tpr_rel']:12.1%}")
    dest = Path("results/label_aware_baseline.json")
    dest.parent.mkdir(parents=True, exist_ok=True)   # else FileNotFoundError after training
    dest.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {dest}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1:])
