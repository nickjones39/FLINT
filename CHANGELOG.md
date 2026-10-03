# Changelog

## 0.2.0 — 2026-10-03

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
