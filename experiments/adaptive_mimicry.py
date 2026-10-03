"""Adaptive white-box mimicry against the trained GNN-AE (realises Prop 2 for a
learned encoder; re-confirms Prop 1).

Open item closed: flint_tdsc.tex notes that structural mimicry as aimed at the
hand-crafted f_emb does NOT evade the *trained* graph autoencoder---it inflates
its anomaly ("novelty paradox", TPR_mim > TPR_clean)---so "a white-box adaptive
mimicry realising Proposition 2's existence claim against a fixed trained encoder
remains future work." This script supplies that mimicry.

Mechanism. The GNN-AE scores a graph by its *mean* per-node reconstruction error
(graph-level anomaly = mean over nodes), the agent analogue of the aggregate
encodings the OS mimicry literature evades. A white-box attacker who knows the
fixed encoder appends benign-typical substructure (synthetic_benign motifs) as
addition-only camouflage; because the benign-trained AE reconstructs benign
motifs with low error, each addition pulls the graph's mean error down toward the
benign per-node mean, eventually below the decision threshold. This is an
addition-only transform Theta with f_AE(G + Theta) = 0.

Crucially the camouflage is provably inert to f_flow: motif nodes carry no
adprov:integrity / adprov:role, so get_untrusted_sources / get_sinks never admit
them and no new untrusted->sink path is created (verified per graph). The attack
therefore evades the learned encoder while f_flow is unchanged (Prop 1).

We start the attacker from the *naively mimicked* injection graph---the graphs the
AE actually detects (TPR_mim ~ 46-58%)---and show the white-box continuation drives
that detection toward zero, while f_flow detection is preserved.

Run:
    conda run -n flint python experiments/adaptive_mimicry.py \
        --corpus results/corpus-prov/prov-deepseek-chat/prov
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from flint.paths import corpus_dir

import networkx as nx
import numpy as np

from flint.layer1_graph.load import load_prov_graph
from flint.layer2_detectors.f_flow import f_flow
from flint.layer3_orchestration.adversary import structural_mimicry
from flint.layer3_orchestration.runner import load_traces_from_dir

try:  # works both as a script and as a module
    from experiments.learned_baseline import gnn_scores
    from experiments.synthetic_benign import generate_benign_graph
except ModuleNotFoundError:
    from learned_baseline import gnn_scores
    from synthetic_benign import generate_benign_graph

SEED = 0
# Motif budget per graph for the white-box adaptive attacker. Named so the
# manuscript's protocol appendix can import and print it rather than restating it.
MOTIF_BUDGET = 40


def _attach(H, motif, rng):
    """Union ``motif`` into ``H`` and attach it to an existing node, as T_struct
    requires ("it attaches substructures to existing nodes").

    The motif is labelled as an honest recorder would label benign material
    (entities trusted, activities neutral) and hangs off one existing node: an
    activity informs the motif's first activity, or, if the graph has none, an
    entity is used by it. The motif holds no sink, so no new untrusted-to-sink
    path can appear and f_flow is untouched (checked below).
    """
    H2 = nx.union(H, motif)
    for n, d in motif.nodes(data=True):
        if d.get("node_type") == "entity":
            H2.nodes[n]["adprov:integrity"] = "trusted"
        elif d.get("node_type") == "activity":
            H2.nodes[n]["adprov:role"] = "neutral"
    motif_acts = [n for n, d in motif.nodes(data=True) if d.get("node_type") == "activity"]
    acts = [n for n, d in H.nodes(data=True) if d.get("node_type") == "activity"]
    ents = [n for n, d in H.nodes(data=True) if d.get("node_type") == "entity"]
    if motif_acts and acts:
        H2.add_edge(rng.choice(acts), motif_acts[0], relation="wasInformedBy")
    elif motif_acts and ents:
        H2.add_edge(rng.choice(ents), motif_acts[0], relation="used")
    return H2


def adaptive_mimicry(G, scorer, thr, rng, max_motifs: int = MOTIF_BUDGET):
    """Greedily attach benign motifs (addition-only) to drive the AE's mean
    reconstruction error below ``thr``. Returns (H, nodes_added, final_score)."""
    H = G.copy()
    cur = float(scorer([H])[0])
    added = 0
    for k in range(max_motifs):
        if cur <= thr:
            break
        motif = generate_benign_graph(rng)
        motif = nx.relabel_nodes(motif, {n: f"__mim{k}__{n}" for n in motif.nodes()})
        H2 = _attach(H, motif, rng)
        s = float(scorer([H2])[0])
        if s < cur:  # keep only additions that lower the aggregate anomaly
            H, cur = H2, s
            added += motif.number_of_nodes()
    return H, added, cur


def evaluate(corpus: Path, max_motifs: int = MOTIF_BUDGET, max_graphs: int = 0) -> dict:
    random.seed(SEED)
    np.random.seed(SEED)
    traces = load_traces_from_dir(corpus)
    benign = [load_prov_graph(t.doc) for t in traces if not t.ground_truth]
    inj = [load_prov_graph(t.doc) for t in traces if t.ground_truth]
    if max_graphs:
        inj = inj[:max_graphs]
    print(f"Loaded {len(benign)} benign + {len(inj)} injection graphs from {corpus}")

    # Fixed trained encoder + threshold (0% train-benign FPR).
    train_scores, scorer = gnn_scores(benign, None)
    thr = float(train_scores.max())

    clean_scores = scorer(inj)
    fflow_clean = [bool(f_flow(G)) for G in inj]
    naive = [structural_mimicry(G) for G in inj]
    naive_scores = scorer(naive)

    rng = random.Random(SEED)
    adaptive_final = list(naive_scores)  # default: unchanged where AE already misses
    detected = evaded = 0
    nodes_added: list[int] = []
    fflow_preserved = fflow_checked = 0

    for i, (base, bscore, ff) in enumerate(zip(naive, naive_scores, fflow_clean)):
        if bscore <= thr:
            continue  # AE already misses this mimicked graph; nothing to evade
        detected += 1
        H, added, cur = adaptive_mimicry(base, scorer, thr, rng, max_motifs)
        adaptive_final[i] = cur
        if cur <= thr:
            evaded += 1
            nodes_added.append(added)
        # f_flow must be unchanged from the ORIGINAL attack graph.
        fflow_checked += 1
        if bool(f_flow(H)) == ff:
            fflow_preserved += 1

    adaptive_final = np.array(adaptive_final)
    out = {
        "corpus": str(corpus),
        "n_injection": len(inj),
        "ae_threshold": thr,
        "ae_tpr_clean": float((clean_scores > thr).mean()),
        "ae_tpr_naive_mimicry": float((naive_scores > thr).mean()),
        "ae_tpr_adaptive_mimicry": float((adaptive_final > thr).mean()),
        "adaptive_detected": detected,          # AE-detected under naive mimicry
        "adaptive_evaded": evaded,              # driven below threshold within budget
        "evasion_rate": (evaded / detected) if detected else float("nan"),
        "median_nodes_added": float(np.median(nodes_added)) if nodes_added else float("nan"),
        "mean_nodes_added": float(np.mean(nodes_added)) if nodes_added else float("nan"),
        "fflow_tpr_clean": float(np.mean(fflow_clean)),
        "fflow_preserved_rate": (fflow_preserved / fflow_checked) if fflow_checked else float("nan"),
        "max_motifs_budget": max_motifs,
    }
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, default=corpus_dir("prov-deepseek-chat") / "prov")
    ap.add_argument("--out", type=Path, default=None,
                    help="default: results/adaptive_mimicry[_gpt].json by corpus name")
    ap.add_argument("--max-motifs", type=int, default=40)
    ap.add_argument("--max-graphs", type=int, default=0, help="0 = all injection graphs")
    args = ap.parse_args()

    res = evaluate(args.corpus, max_motifs=args.max_motifs, max_graphs=args.max_graphs)

    print("\n--- Adaptive white-box mimicry vs trained GNN-AE ---")
    for k, v in res.items():
        print(f"  {k:26s} {v}")

    out = args.out or Path(
        "results/adaptive_mimicry_gpt.json" if "gpt" in str(args.corpus)
        else "results/adaptive_mimicry.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
