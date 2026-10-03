"""Derive runner.OUT_OF_SCOPE_GOALS: injection goals that are not privileged actions.

An injection goal is *in scope* iff achieving it takes a call to a sink in
AgentDojo-PROV's labelling policy (``labeling.SINK_TOOLS``), the S that f_flow
monitors. A goal met by the agent's reply alone, or by a read, is out of scope:
when such an attack succeeds on a user task that itself writes, f_flow fires on
the user's own read-then-write, and counting that as a detection credits the
detector with a coincidence. Conditional detection is reported over in-scope
successes; out-of-scope ones are reported separately.

Decided from the injection task's own reference solution (``task.ground_truth``):
in scope iff it calls a sink. AgentDojo v1.2 added eight workspace injection tasks
(6-13) whose reference solution is unimplemented (``return []``); for those the
decision falls back to the task's success check, which is in scope iff it reads
the post-attack environment (a state change, which only a writing tool makes).
All eight are, and their goals all send mail to the attacker.

FLINT does not depend on agentdojo, so this runs once in an environment with both
``agentdojo==0.1.35`` and ``agentdojo_prov`` and its output replaces the constant:

    /path/to/adprov/python scripts/derive_goal_scope.py
"""
from __future__ import annotations

import inspect
import warnings

warnings.filterwarnings("ignore")

from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from agentdojo_prov.labeling import SINK_TOOLS  # noqa: E402

# v1: AgentDojo's own published runs; v1.2.2: the AgentDojo-PROV release.
VERSIONS = ("v1", "v1.2.2")
SUITES = ("workspace", "banking", "travel", "slack")


def derive() -> dict[str, list[tuple[str, str]]]:
    out = {}
    for version in VERSIONS:
        rows = []
        for name, suite in get_suites(version).items():
            if name not in SUITES:
                continue
            env = suite.load_and_inject_default_environment({})
            for tid, task in suite.injection_tasks.items():
                calls = [c.function for c in task.ground_truth(env.model_copy(deep=True))]
                if calls:
                    in_scope, how = bool(set(calls) & set(SINK_TOOLS)), "reference solution"
                else:
                    in_scope = "post_environment." in inspect.getsource(type(task).security)
                    how = "success check (no reference solution)"
                if not in_scope:
                    rows.append((f"{name}/{tid}", how))
        out[version] = sorted(rows)
    return out


def main() -> None:
    for version, rows in derive().items():
        print(f'    "{version}": frozenset({{')
        for key, how in rows:
            print(f'        "{key}",   # {how}')
        print("    }),")


if __name__ == "__main__":
    main()
