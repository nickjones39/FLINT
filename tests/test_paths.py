"""flint.paths: corpus/output roots and AppleDouble-safe file iteration."""
from __future__ import annotations

from pathlib import Path

import pytest

from flint import paths


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("FLINT_CORPUS_ROOT", raising=False)
    monkeypatch.delenv("FLINT_OUTPUT_ROOT", raising=False)


def test_env_overrides(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("FLINT_CORPUS_ROOT", str(tmp_path / "c"))
    monkeypatch.setenv("FLINT_OUTPUT_ROOT", str(tmp_path / "o"))
    assert paths.corpus_dir("m") == tmp_path / "c" / "m"
    assert paths.output_dir("m") == tmp_path / "o" / "m"


def test_candidates_probed_in_order(monkeypatch, tmp_path: Path):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    assert paths.corpus_root() == Path(paths.DEFAULT_CORPUS_ROOT)   # none exist
    second = tmp_path / "AgentDojo-PROV-framework" / "corpus" / "corpus-prov"
    second.mkdir(parents=True)
    assert paths.corpus_root() == Path(paths._CORPUS_CANDIDATES[1])
    (tmp_path / "agentdojo-prov" / "corpus" / "corpus-prov").mkdir(parents=True)
    assert paths.corpus_root() == Path(paths._CORPUS_CANDIDATES[0])


def test_default_output_root():
    assert paths.output_root() == Path(paths.DEFAULT_OUTPUT_ROOT)


def test_iterators_skip_sidecars_and_transcripts(tmp_path: Path):
    a = tmp_path / "prov" / "direct"
    a.mkdir(parents=True)
    for name in ("b.json", "a.json", "a.transcript.json", "._a.json", "._a.transcript.json"):
        (a / name).write_text("{}")
    assert [p.name for p in paths.iter_files(a, "*.json")] == ["a.json", "a.transcript.json", "b.json"]
    assert [p.name for p in paths.prov_docs(a)] == ["a.json", "b.json"]
    assert [p.name for p in paths.transcripts(tmp_path)] == ["a.transcript.json"]
