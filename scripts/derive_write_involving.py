"""Derive runner.WRITE_INVOLVING_TASKS from AgentDojo's own ground truth.

A benign user task is *write-involving* iff the benchmark's reference solution
(``task.ground_truth(env)``, AgentDojo v1.2.2) calls a privileged sink, as
AgentDojo-PROV's labelling policy defines one (``labeling.SINK_TOOLS``, the same
S the detector uses). Everything else is *read-only*. Before 2026-10-03 the list
was curated by hand from inspected false positives, which made "0% read-only
FPR" partly true by construction and disagreed with the reference calls on five
tasks.

FLINT does not depend on agentdojo, so this script is run once, in an
environment that has both ``agentdojo==0.1.35`` and ``agentdojo_prov`` (the
AgentDojo-PROV env), and its output replaces the constant in runner.py:

    /path/to/adprov/python scripts/derive_write_involving.py          # v1.2.2
    /path/to/adprov/python scripts/derive_write_involving.py v1       # AgentDojo's own runs
"""
from __future__ import annotations

import warnings

warnings.filterwarnings("ignore")

from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from agentdojo_prov.labeling import SINK_TOOLS  # noqa: E402

BENCHMARK = "v1.2.2"
SUITES = ("workspace", "banking", "travel", "slack")


def derive(benchmark: str = BENCHMARK) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, suite in get_suites(benchmark).items():
        if name not in SUITES:
            continue
        env = suite.load_and_inject_default_environment({})
        rows = []
        for tid, task in suite.user_tasks.items():
            calls = {c.function for c in task.ground_truth(env.model_copy(deep=True))}
            if calls & set(SINK_TOOLS):
                rows.append(tid)
        out[name] = sorted(rows, key=lambda t: int(t.rsplit("_", 1)[1]))
    return out


def main() -> None:
    import sys
    benchmark = sys.argv[1] if len(sys.argv) > 1 else BENCHMARK
    d = derive(benchmark)
    print(f"# AgentDojo {benchmark}: user tasks whose ground-truth calls include a sink")
    for name in SUITES:
        ids = [t if name == "workspace" else f"{name}_{t}" for t in d[name]]
        print(f"    # {name} ({len(ids)})")
        for i in range(0, len(ids), 5):
            print("    " + " ".join(f'"{x}",' for x in ids[i:i + 5]))


if __name__ == "__main__":
    main()
