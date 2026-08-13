"""
Offline unit tests for benchmarks/scaled_evals/datasets/prepare_hardened_dataset.py.

Covers the split/tagging logic only (_split_ingested_held_out,
_tag_ops_visibility) — pure, deterministic, no network. The actual CUAD/CFPB
fetch functions (_load_cuad, _load_cfpb) need live network access and are
exercised manually (see plans/vanilla-target-agent.md — already verified
live once while building this script), not covered by the offline suite,
same convention as prepare_healthcare.py's HealthCareMagic download.
"""
from unittest.mock import patch

from benchmarks.scaled_evals.datasets.prepare_hardened_dataset import (
    _split_ingested_held_out,
    _tag_ops_visibility,
    prepare,
)


def _pool(n: int, source: str) -> list[dict]:
    return [{"id": f"{source}_{i:04d}", "document_text": f"doc {i}", "source": source} for i in range(n)]


class TestSplitIngestedHeldOut:
    def test_split_respects_ratio(self):
        pool = _pool(100, "cuad")
        ingested, held_out = _split_ingested_held_out(pool, ingested_ratio=0.7, seed=42)
        assert len(ingested) == 70
        assert len(held_out) == 30

    def test_no_overlap_between_ingested_and_held_out(self):
        pool = _pool(100, "cuad")
        ingested, held_out = _split_ingested_held_out(pool, ingested_ratio=0.7, seed=42)
        ingested_ids = {r["id"] for r in ingested}
        held_out_ids = {r["id"] for r in held_out}
        assert ingested_ids.isdisjoint(held_out_ids)

    def test_every_record_accounted_for_exactly_once(self):
        pool = _pool(100, "cuad")
        ingested, held_out = _split_ingested_held_out(pool, ingested_ratio=0.7, seed=42)
        assert len(ingested) + len(held_out) == len(pool)
        all_ids = {r["id"] for r in ingested} | {r["id"] for r in held_out}
        assert all_ids == {r["id"] for r in pool}

    def test_deterministic_given_same_seed(self):
        pool = _pool(50, "cfpb")
        ingested_a, _ = _split_ingested_held_out(pool, 0.7, seed=7)
        ingested_b, _ = _split_ingested_held_out(pool, 0.7, seed=7)
        assert [r["id"] for r in ingested_a] == [r["id"] for r in ingested_b]

    def test_different_seeds_produce_different_splits(self):
        pool = _pool(100, "cfpb")
        ingested_a, _ = _split_ingested_held_out(pool, 0.7, seed=1)
        ingested_b, _ = _split_ingested_held_out(pool, 0.7, seed=2)
        assert [r["id"] for r in ingested_a] != [r["id"] for r in ingested_b]

    def test_original_pool_not_mutated(self):
        pool = _pool(10, "cuad")
        original_order = [r["id"] for r in pool]
        _split_ingested_held_out(pool, 0.7, seed=42)
        assert [r["id"] for r in pool] == original_order


class TestTagOpsVisibility:
    def test_correct_fraction_tagged(self):
        ingested = _pool(100, "cuad")
        _tag_ops_visibility(ingested, fraction=0.2, seed=42)
        n_visible = sum(1 for r in ingested if r["ops_visible"])
        assert n_visible == 20

    def test_every_record_gets_the_field(self):
        ingested = _pool(50, "cfpb")
        _tag_ops_visibility(ingested, fraction=0.2, seed=42)
        assert all("ops_visible" in r for r in ingested)
        assert all(isinstance(r["ops_visible"], bool) for r in ingested)

    def test_empty_pool_does_not_crash(self):
        ingested: list[dict] = []
        _tag_ops_visibility(ingested, fraction=0.2, seed=42)
        assert ingested == []

    def test_zero_fraction_tags_nothing(self):
        ingested = _pool(50, "cuad")
        _tag_ops_visibility(ingested, fraction=0.0, seed=42)
        assert not any(r["ops_visible"] for r in ingested)

    def test_deterministic_given_same_seed(self):
        ingested_a = _pool(50, "cuad")
        ingested_b = _pool(50, "cuad")
        _tag_ops_visibility(ingested_a, 0.2, seed=99)
        _tag_ops_visibility(ingested_b, 0.2, seed=99)
        assert [r["ops_visible"] for r in ingested_a] == [r["ops_visible"] for r in ingested_b]


class TestPrepareIdempotency:
    """Regression test for a real bug found running this in Docker Compose:
    prepare-hardened had no guard against re-running when output already
    exists, unlike seed.py -- and CFPB's API is a live feed, so a re-run
    isn't guaranteed to reproduce the same sample, silently desyncing the
    dataset files from whatever's already embedded in ChromaDB."""

    def test_skips_regeneration_when_both_files_already_exist(self, tmp_path, monkeypatch):
        import benchmarks.scaled_evals.datasets.prepare_hardened_dataset as mod

        ingested_path = tmp_path / "hardened_dataset_ingested.json"
        held_out_path = tmp_path / "hardened_dataset_held_out.json"
        ingested_path.write_text("[]", encoding="utf-8")
        held_out_path.write_text("[]", encoding="utf-8")
        monkeypatch.setattr(mod, "_INGESTED_OUTPUT", ingested_path)
        monkeypatch.setattr(mod, "_HELD_OUT_OUTPUT", held_out_path)

        with patch.object(mod, "_load_cuad") as mock_cuad, patch.object(mod, "_load_cfpb") as mock_cfpb:
            prepare(force=False)
            mock_cuad.assert_not_called()
            mock_cfpb.assert_not_called()

    def test_force_regenerates_even_if_files_exist(self, tmp_path, monkeypatch):
        import benchmarks.scaled_evals.datasets.prepare_hardened_dataset as mod

        ingested_path = tmp_path / "hardened_dataset_ingested.json"
        held_out_path = tmp_path / "hardened_dataset_held_out.json"
        ingested_path.write_text("[]", encoding="utf-8")
        held_out_path.write_text("[]", encoding="utf-8")
        monkeypatch.setattr(mod, "_INGESTED_OUTPUT", ingested_path)
        monkeypatch.setattr(mod, "_HELD_OUT_OUTPUT", held_out_path)

        with patch.object(mod, "_load_cuad", return_value=[]) as mock_cuad, \
             patch.object(mod, "_load_cfpb", return_value=[]) as mock_cfpb:
            prepare(force=True)
            mock_cuad.assert_called_once()
            mock_cfpb.assert_called_once()

    def test_regenerates_when_a_file_is_missing(self, tmp_path, monkeypatch):
        import benchmarks.scaled_evals.datasets.prepare_hardened_dataset as mod

        ingested_path = tmp_path / "hardened_dataset_ingested.json"
        held_out_path = tmp_path / "hardened_dataset_held_out.json"
        ingested_path.write_text("[]", encoding="utf-8")
        # held_out_path deliberately not created
        monkeypatch.setattr(mod, "_INGESTED_OUTPUT", ingested_path)
        monkeypatch.setattr(mod, "_HELD_OUT_OUTPUT", held_out_path)

        with patch.object(mod, "_load_cuad", return_value=[]) as mock_cuad, \
             patch.object(mod, "_load_cfpb", return_value=[]) as mock_cfpb:
            prepare(force=False)
            mock_cuad.assert_called_once()
            mock_cfpb.assert_called_once()
