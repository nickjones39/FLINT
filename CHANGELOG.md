# Changelog

## 0.2.1 — 2026-10-03

The first published release. It fixes what a full lint, fuzz and code review of
0.2.0 found. Two issues let a flow go undetected even under `strict=True`. Detection
results are unchanged: on the full AgentDojo-PROV corpus (v2.3, six backends, 17,664
traces), the default loader's graphs, witnesses, sweep rows and metrics are again
byte-identical to 0.1.0, strict mode gives the same graphs, and PROV renders are
byte-identical.

### Fixed
- **Sinks and endorsers must be activities** (`get_sinks`, `get_endorsers`). Before
  this, an entity or agent labelled `adprov:role: endorser` acted as an endorsement
  and cut every flow through it, in both modes. Strict mode now rejects a role on a
  non-activity.
- **Strict mode rejects sections it does not model.** That covers `bundle` and any
  PROV relation besides the four flow relations and `wasAssociatedWith`,
  `wasAttributedTo` and `actedOnBehalfOf`. Before, they were dropped silently, so a
  flow inside a bundle, or one carried by `wasStartedBy` and similar relations, was
  invisible. The default loader still ignores them.
- An attribute named `node_type`, a non-string attribute name and a non-string
  identifier now raise `ProvFormatError`, not a bare `TypeError`.
- `load_prov_graph_from_file`, the sweep's trace loader and `SweepConfig.from_yaml`
  read UTF-8 explicitly. Before, they used the platform's locale encoding, which fails
  on non-ASCII traces under Windows or a C locale.
- `SweepConfig` rejects unknown detector and adversary names and unknown config
  keys. Before, a misspelt adversary ran as "none" and reported un-attacked results
  under the misspelt label. An empty YAML file now gives the defaults instead of
  crashing.
- `compute_metrics` rejects a non-boolean `detected` or `ground_truth` column. `~` on
  an object column inverts Python bools to -1/-2 and corrupts every count. Empty
  input now returns an empty table.
- Adversary-inserted nodes get fresh identifiers instead of merging into an existing
  node of the same name. The names are unchanged when nothing collides.
- `visualize.py` no longer truncates an output stem at a dot (`llama-3.3_x` used to
  become `llama-3.svg`), escapes quotes in titles, reads labels through the loader
  (typed literals, multi-instance records), draws unlabelled entities as untrusted,
  and no longer crashes on a list-valued role.

### Added
- PROV-JSON multi-instance records, i.e. a list of objects under one identifier, as
  the `prov` library writes them. Strict mode rejects instances whose labels disagree.
- A clearer error for `used` without `prov:entity` and `wasGeneratedBy` without
  `prov:activity`, which PROV allows but FLINT cannot place.
- 83 tests (206 in total; coverage 63% → 93%): sections and roles, multi-instance
  records, a forced non-UTF-8 locale, the trace loader and CLI, config validation,
  `paths`, `visualize`, the budgeted mimicry and the `f_emb` score and novelty
  functions.

## 0.2.0 — 2026-10-03 (tagged, not released)

Detection results are unchanged. On the full AgentDojo-PROV corpus (v2.3, six
backends, 17,664 traces), the default loader produces graphs, witnesses, sweep rows
and metrics byte-identical to 0.1.0. Strict mode produces the same graphs on every
corpus trace.

### Added
- `load_prov_graph(doc, strict=True)`, a fail-closed loader for deployment. A missing
  or invalid entity integrity label is read as `untrusted` and marked
  `flint:integrity_defaulted`. An unlabelled activity, a relation to an undeclared or
  wrongly-typed node, a duplicate identifier, or a conflicting `adprov` prefix raises
  an error.
- `flint.ProvFormatError` (a `ValueError`), the single error type for documents FLINT
  cannot load.
- A public API in `flint/__init__.py` (`flint.__all__`), plus `flint.__version__`.
- `flint/spec.py` and `docs/input-format.md`, which specify the `adprov:` input
  vocabulary.
- `py.typed`, with mypy configuration and type checking of the package.
- GitHub Actions CI with a core-only job (Python 3.12 and 3.13) and an all-extras job
  (ruff, mypy, pytest and a distribution build).

### Changed
- **The distribution is renamed `flint` → `flint-prov`.** The import name is still
  `flint`. Plain `flint` is taken on PyPI, and `python-flint` also imports as `flint`.
- The project is managed with uv. `uv.lock` pins the dependency set. Dev tools are a
  PEP 735 `dev` dependency group, not an extra. On Linux, torch resolves from the
  CPU-only PyTorch index.
- `experiments/` is no longer installed as a top-level `experiments` package. The
  scripts run in place as before.
- Dependencies are split. The core needs only `networkx`, and the rest moved to the
  `[sweep]`, `[viz]`, `[experiments]` and `[all]` extras. matplotlib is no
  longer a dependency, because the package never imported it.
- Typed PROV-JSON literals (`{"$": "untrusted", ...}`) on `adprov:integrity` and
  `adprov:role` are now unwrapped. Before, they silently failed the label check.
- A relation missing a required field raises `ProvFormatError` instead of a bare
  `KeyError`.
- The sweep tests skip cleanly when the `[sweep]` extra is not installed.

### Fixed
- The `load.py` docstring claimed `wasAssociatedWith` was stored as a node attribute.
  It is, and always was, ignored.

## 0.1.0

The initial standalone release of the detection and evasion framework.
