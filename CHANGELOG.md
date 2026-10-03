# Changelog

## 0.3.1 — 2026-10-03

### Added
- `commit_record(signer, G, trace_id)` commits to the whole record: every flow edge,
  every node, each entity's integrity label, and each activity's role and action.
  `verify_attribution(..., relations=token)` accepts it as it accepts a
  `commit_relations` token, whose format is unchanged. A sink demoted to neutral
  after recording silences f_flow; it fails the record check, and the edge-only
  commitment cannot see it.
- Capabilities can bind argument values. `argument_scope(args, names)` builds
  `arg:<name>` scope entries; an endorser keeps its capability only if its
  recorded `adprov:args` hold exactly those values. This is a capability "bound
  to the recipient", with no `scope_check` callback needed.

### Changed
- `experiments/adaptive_mimicry.py` attaches each motif to an existing node, by
  `wasInformedBy` from an activity or `used` from an entity, and labels it as an
  honest recorder would. Before, motifs were added as disconnected components,
  which the manuscript's structural attacker ("attaches substructures to existing
  nodes") does not cover.

## 0.3.0 — 2026-10-03

Verifiable trust attribution: the manuscript's §V, Definitions 5 and 6. Nothing
existing changes: `f_flow`, the loader and the adversaries behave exactly as in
0.2.1. Verification is a separate, opt-in step before detection.

### Added
- **`flint.attribution`.** It provides `verify_attribution(G, labels=…,
  capabilities=…)`, which returns the graph with every unverified trust claim
  withdrawn:
  - an entity stays `trusted` only with a valid recorder signature over its id,
    channel, label and content hash, and anything else reads `untrusted`
    (fail-closed);
  - an activity stays an endorser only with a valid capability for its declared
    action, unexpired, scoped to the trace and used by no other activity.

  A `sink_actions` policy makes sinks unremovable. The producer side is
  `sign_source_label` and `issue_capability`. The recorder and capability keys are
  separate parameters, and neither verifies as the other.
- **Relation commitment.** `commit_relations(signer, G, trace_id)` signs an
  RFC 6962 Merkle root over every flow edge. `verify_attribution(...,
  relations=token)` reports `record_complete`, and `AttributionResult.alert`
  combines it with f_flow. This closes the edge-omission variant the manuscript's
  §V left open: a record that loses the edge carrying a flow after recording now
  alerts instead of passing. A relation the recorder never observed is still out
  of reach.
- **`Signer` / `Verifier` protocols.** FLINT never holds keys. `flint.attribution`
  needs only the core.
- **`flint.attribution.ed25519`.** Ed25519 implementations with key ids, rotation
  and fail-safe revocation, in a new `[attribution]` extra (cryptography).
- **Tests (60 new).** The relabel and both endorser attacks fail once verification
  is on. Property tests check Theorem 3, including edge omission: without either
  key, no attack lowers the deployed decision. RFC 6962 known-answer vectors cover
  the Merkle hashing.
- **A measured result on the AgentDojo-PROV corpus.** All six backends' injection
  traces were signed with real Ed25519 keys. The relabel, endorser and general
  endorser attacks cut f_flow to 0% unverified; verification restores exactly the
  undefended rate on every backend (e.g. DeepSeek 58.9%). Signing and verification
  take about 0.12 ms and 0.13 ms per trace.

## 0.2.1 — 2026-10-03 (tagged, not released)

It fixes what three rounds of linting, fuzzing, property-based testing and code
review of 0.2.0 found. Two of those issues let a flow go undetected even under
`strict=True`. Detection results are unchanged: on the full AgentDojo-PROV corpus (v2.3, six backends, 17,664
traces), the default loader's graphs, witnesses, sweep rows and metrics are again
byte-identical to 0.1.0, strict mode gives the same graphs, and PROV renders are
byte-identical.

### Fixed
- **Strict parsing rejects duplicate JSON keys.** Python keeps the last value of a
  duplicated key and other parsers keep the first, so a file listing
  `adprov:integrity` as `untrusted` and then `trusted` loaded as **trusted**. The
  producer and FLINT could disagree on a label. `strict=True` file loading now
  rejects duplicate keys, as well as the non-standard `NaN`/`Infinity` literals.
- **File loading has one error type.** Invalid JSON, nesting too deep for the parser
  (which crashed it with `RecursionError`), non-UTF-8 bytes and a byte-order mark
  used to escape as `JSONDecodeError`, `RecursionError` and `UnicodeDecodeError`.
  They now raise `ProvFormatError`, and a leading byte-order mark is tolerated.
- **Witness order is deterministic.** `flow_witnesses` iterated the sink
  `frozenset`, whose order changes per process with Python's string-hash
  randomisation. On the corpus, 442 DeepSeek traces have several witnessed sinks.
  Sinks are now taken in graph order; the paths are unchanged.
- **The README no longer overstates two adversaries.** Mimicry evades `f_emb` on the
  corpus but not on every graph. `trust_attribution_endorser` reroutes only *direct*
  ⊥→sink edges, which is every witness on the corpus, so an indirect flow survives it.
  The README also said the endorser attack left the structural baseline untouched; it
  shifts it slightly.
- **f_flow is linear in graph size, however many untrusted sources there are.**
  `check_flow` ran one search per source, so it was quadratic when every step reads
  external data and nothing reaches a sink, which is the common benign case: 3.2 s at
  8,000 nodes. It is now a single search seeded with all sources, taking milliseconds
  at that size. `flow_witnesses` used one search per (source, sink) pair (11 s at
  4,000 nodes) and now uses one per source, with paths and order identical to the old
  search's. That was checked on every corpus trace and by property tests against the
  old code kept as a reference. Latency on the single-source scaling benchmark is
  unchanged.
- **The sweep's trace loader refuses JSON that is not a PROV trace.** It also refuses
  a directory holding both top-level traces and attack subdirectories. Before, pointing
  `--traces` at a model directory scored `manifest.json` as a benign trace and
  silently ignored the real traces.
- The sweep CLI exits non-zero when it finds no traces. Before, it exited 0 and left a
  previous run's outputs in place, looking current. A missing directory gives a clear
  `NotADirectoryError`.
- The build requires `setuptools>=77`, the first release that accepts the PEP 639
  `license = "MIT"` form. The declared `>=68` could not build the package. CI now also
  builds against the minimum.
- `f_emb`'s structural hash no longer crashes on a non-string `node_type` or relation
  in a hand-built graph. Every string feature hashes exactly as before.
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
- `trust_attribution_endorser_all`: the general endorser attack, which routes every
  out-edge of every untrusted entity through a fabricated endorser and silences
  `f_flow` on any graph. It is registered with the sweep runner. The published sweep
  keeps `trust_attribution_endorser`, which is unchanged; the two agree on all 17,664
  corpus traces.
- `parse_prov_json(text_or_bytes, strict=...)`: the parser behind
  `load_prov_graph_from_file`, exported for callers holding PROV-JSON text.
- Python 3.14 in the CI matrix and classifiers.
- `docs/input-format.md` states that FLINT implements the two-point {⊥, ⊤} lattice,
  and documents the parsing rules.
- PROV-JSON multi-instance records, i.e. a list of objects under one identifier, as
  the `prov` library writes them. Strict mode rejects instances whose labels disagree.
- A clearer error for `used` without `prov:entity` and `wasGeneratedBy` without
  `prov:activity`, which PROV allows but FLINT cannot place.
- Property-based tests (Hypothesis, now in the `dev` group) for: the new search
  against the old per-pair search; shortest and complete witnesses; strict mode never
  detecting less than default; strict graphs being fully labelled; invariance under
  renaming, reordering and unrelated additions; the P1/P3 adversary invariants and
  input immutability; arbitrary JSON raising only `ProvFormatError`; and many-source
  scaling.
- 123 tests (246 in total; coverage 63% → 93%): sections and roles, multi-instance
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
