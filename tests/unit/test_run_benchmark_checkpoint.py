"""
Regression tests for run_benchmark()'s checkpoint handling (fixed
2026-08-14 after a real incident: a live IKEA run against hardened_agent
gracefully returned 113 partial findings after a network failure, the
checkpoint was deleted immediately since execute() didn't raise, and then
compute_metrics() itself stalled for hours on a slow local ROUGE-L/CRR
computation with nothing left to recover from if it had failed).

Current behavior (2026-08-14, second pass): the checkpoint is never
auto-deleted at all, by design -- a harmless leftover file next to a
completed run is a smaller cost than any residual risk of losing real
findings. See scripts/run_benchmark.py's inline comments for the full
incident note and the reasoning for removing cleanup entirely rather than
just re-ordering it.

No API keys or network access required -- attack_cls, compute_metrics, and
generate_markdown_report are all mocked.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# scripts/ has no __init__.py but is still importable as an implicit
# namespace package (Python 3.3+) once the repo root is on sys.path --
# already true during a pytest run (testpaths=["tests"], pyproject.toml),
# same as tests/unit/test_compare_benchmark_runs.py's own
# `from scripts.compare_benchmark_runs import ...`. Fixed 2026-08-21: the
# previous `sys.path.insert(...)` + bare `import run_benchmark` worked at
# runtime but static analyzers (Pylance/Pyright) can't resolve a module
# added to sys.path at runtime, so the import line showed as unresolved in
# the IDE even though the test suite passed. This form resolves cleanly
# both ways.
import scripts.run_benchmark as run_benchmark

from aginiti.attacks.base import LeakFinding


def _finding(i: int = 0) -> LeakFinding:
    return LeakFinding(
        attack_type="DRA",
        tier_used="black_box",
        confidence=0.7,
        confirmed=True,
        leaked_content=f"leaked {i}",
        probe_used=f"probe {i}",
        trace_span_id="",
        recommendation="rec",
        severity="medium",
        full_response=f"leaked {i}",
        leak_type="sensitive_data",
        reasoning="reason",
    )


class _FakeAttack:
    """Minimal stand-in for IKEAAttack -- execute() returns canned findings,
    refused_queries is a plain attribute, same shape run_benchmark() expects."""

    def __init__(self, findings, **kwargs):
        self._findings = findings
        self.refused_queries = []
        self._llm_call_count = 5
        self.prefilter_skips = 0

    def execute(self, **kwargs):
        return self._findings


@pytest.fixture
def run_kwargs(tmp_path, monkeypatch):
    """Common run_benchmark() call setup: fake ground truth, fake keys, no
    real network/embedding/markdown-generation calls."""
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(json.dumps([{"id": "d1", "document_text": "some ground truth text"}]), encoding="utf-8")

    output = tmp_path / "results" / "fake_run.json"

    monkeypatch.setattr(run_benchmark, "_key_for", lambda model: "fake-key")
    monkeypatch.setattr(run_benchmark, "_fallback_key_for", lambda model: None)
    monkeypatch.setattr(run_benchmark, "generate_markdown_report", MagicMock())

    return dict(
        attack="ikea",
        agent_url="http://localhost:8001",
        ground_truth=str(gt_path),
        topic="some topic",
        queries=10,
        llm_provider="gemini/gemini-3.5-flash",
        output=str(output),
        configure_logging=False,
    ), output


def _fake_metrics(**overrides) -> dict:
    base = dict(asr=1.0, ee=0.5, crr_mean=0.3, ss_mean=0.4, total_findings=1, refusals_filtered=0)
    base.update(overrides)
    return base


def _seed_checkpoint(output: Path) -> Path:
    checkpoint_file = Path(output).with_suffix(".checkpoint.json")
    checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_file.write_text(json.dumps([{"placeholder": True}]), encoding="utf-8")
    return checkpoint_file


class TestCheckpointNeverAutoDeleted:
    def test_checkpoint_survives_a_fully_successful_run(self, run_kwargs, monkeypatch):
        kwargs, output = run_kwargs
        checkpoint_file = _seed_checkpoint(output)

        findings = [_finding(0)]
        monkeypatch.setitem(run_benchmark.ATTACK_REGISTRY, "ikea", lambda **kw: _FakeAttack(findings))
        monkeypatch.setattr(run_benchmark, "compute_metrics", MagicMock(return_value=_fake_metrics()))

        run_benchmark.run_benchmark(**kwargs)

        # Deliberately left in place even after a clean, fully successful
        # run -- no cleanup step exists anymore, by design.
        assert checkpoint_file.exists()
        assert Path(output).exists()

    def test_checkpoint_survives_when_metrics_fail(self, run_kwargs, monkeypatch):
        kwargs, output = run_kwargs
        checkpoint_file = _seed_checkpoint(output)

        findings = [_finding(0), _finding(1)]
        monkeypatch.setitem(run_benchmark.ATTACK_REGISTRY, "ikea", lambda **kw: _FakeAttack(findings))
        monkeypatch.setattr(
            run_benchmark, "compute_metrics",
            MagicMock(side_effect=RuntimeError("simulated slow-CRR crash")),
        )

        report = run_benchmark.run_benchmark(**kwargs)

        assert checkpoint_file.exists()
        # And findings still make it into the final report regardless,
        # metrics explicitly marked unavailable rather than silently dropped.
        assert len(report["findings"]) == 2
        assert report["metrics"] is None
        assert "simulated slow-CRR crash" in report["run_metadata"]["metrics_error"]

    def test_checkpoint_survives_if_final_write_itself_never_completes(self, run_kwargs, monkeypatch):
        # The scenario the whole fix protects against: something after
        # execute() returns prevents the final report from ever being
        # written (a hang, a crash, anything) -- the checkpoint must still
        # be there afterward, since it's the only thing that preserved the
        # findings.
        kwargs, output = run_kwargs
        checkpoint_file = _seed_checkpoint(output)

        findings = [_finding(0)]
        monkeypatch.setitem(run_benchmark.ATTACK_REGISTRY, "ikea", lambda **kw: _FakeAttack(findings))
        monkeypatch.setattr(run_benchmark, "compute_metrics", MagicMock(return_value=_fake_metrics()))
        monkeypatch.setattr(
            Path, "write_text",
            MagicMock(side_effect=OSError("simulated disk failure during final write")),
        )

        with pytest.raises(OSError, match="simulated disk failure"):
            run_benchmark.run_benchmark(**kwargs)

        assert checkpoint_file.exists()

    def test_report_written_to_disk_even_when_metrics_fail(self, run_kwargs, monkeypatch):
        kwargs, output = run_kwargs
        findings = [_finding(0)]
        monkeypatch.setitem(run_benchmark.ATTACK_REGISTRY, "ikea", lambda **kw: _FakeAttack(findings))
        monkeypatch.setattr(
            run_benchmark, "compute_metrics",
            MagicMock(side_effect=RuntimeError("boom")),
        )

        run_benchmark.run_benchmark(**kwargs)

        assert Path(output).exists()
        on_disk = json.loads(Path(output).read_text(encoding="utf-8"))
        assert len(on_disk["findings"]) == 1
        assert on_disk["metrics"] is None


class TestExplicitCheckpointFile:
    """
    Regression tests for the ``checkpoint_file`` parameter (added
    2026-08-16) -- lets a caller decouple the checkpoint's identity from
    ``output``. Motivating bug: scripts/run_ikea_hardened.py stamped a
    fresh timestamp into ``output`` on every invocation, so the
    output-derived checkpoint path was ALSO different every time -- a
    from-scratch re-run could never find a previous interrupted run's
    checkpoint on its own. See that script's own inline comments for the
    fix using this parameter.
    """

    class _RecordingAttack:
        """Captures whatever checkpoint_file execute() was actually given,
        so tests can assert on it directly -- IKEAAttack itself decides
        what to do with that path (load/resume from it), this fake only
        needs to prove run_benchmark() computed/passed the RIGHT one."""

        last_checkpoint_file_seen: str | None = None

        def __init__(self, findings, **kwargs):
            self._findings = findings
            self.refused_queries = []
            self._llm_call_count = 5
            self.prefilter_skips = 0

        def execute(self, **kwargs):
            TestExplicitCheckpointFile._RecordingAttack.last_checkpoint_file_seen = kwargs.get("checkpoint_file")
            return self._findings

    def test_defaults_to_output_derived_path_when_not_given(self, run_kwargs, monkeypatch):
        # Unchanged behavior for every existing caller that doesn't pass
        # checkpoint_file at all.
        kwargs, output = run_kwargs
        findings = [_finding(0)]
        monkeypatch.setitem(
            run_benchmark.ATTACK_REGISTRY, "ikea",
            lambda **kw: TestExplicitCheckpointFile._RecordingAttack(findings),
        )
        monkeypatch.setattr(run_benchmark, "compute_metrics", MagicMock(return_value=_fake_metrics()))

        run_benchmark.run_benchmark(**kwargs)

        expected = str(Path(output).with_suffix(".checkpoint.json"))
        assert TestExplicitCheckpointFile._RecordingAttack.last_checkpoint_file_seen == expected

    def test_explicit_checkpoint_file_overrides_output_derived_default(self, run_kwargs, tmp_path, monkeypatch):
        kwargs, output = run_kwargs
        custom_checkpoint = str(tmp_path / "my_stable_checkpoint.json")
        findings = [_finding(0)]
        monkeypatch.setitem(
            run_benchmark.ATTACK_REGISTRY, "ikea",
            lambda **kw: TestExplicitCheckpointFile._RecordingAttack(findings),
        )
        monkeypatch.setattr(run_benchmark, "compute_metrics", MagicMock(return_value=_fake_metrics()))

        run_benchmark.run_benchmark(checkpoint_file=custom_checkpoint, **kwargs)

        assert TestExplicitCheckpointFile._RecordingAttack.last_checkpoint_file_seen == custom_checkpoint
        # And the output-derived default path was NOT what got used.
        default_path = str(Path(output).with_suffix(".checkpoint.json"))
        assert TestExplicitCheckpointFile._RecordingAttack.last_checkpoint_file_seen != default_path

    def test_explicit_checkpoint_path_is_stable_across_different_output_timestamps(self, run_kwargs, tmp_path, monkeypatch):
        # The exact scenario the fix targets: two "different" invocations
        # (different output filenames, as if stamped with different
        # timestamps) must still resolve to the SAME checkpoint path when
        # the caller passes the same explicit checkpoint_file both times.
        kwargs, _output = run_kwargs
        custom_checkpoint = str(tmp_path / "persona_topic_queries.checkpoint.json")
        findings = [_finding(0)]
        monkeypatch.setitem(
            run_benchmark.ATTACK_REGISTRY, "ikea",
            lambda **kw: TestExplicitCheckpointFile._RecordingAttack(findings),
        )
        monkeypatch.setattr(run_benchmark, "compute_metrics", MagicMock(return_value=_fake_metrics()))

        kwargs_run1 = dict(kwargs, output=str(tmp_path / "run_20260812T000000Z.json"))
        kwargs_run2 = dict(kwargs, output=str(tmp_path / "run_20260813T000000Z.json"))

        run_benchmark.run_benchmark(checkpoint_file=custom_checkpoint, **kwargs_run1)
        seen_1 = TestExplicitCheckpointFile._RecordingAttack.last_checkpoint_file_seen
        run_benchmark.run_benchmark(checkpoint_file=custom_checkpoint, **kwargs_run2)
        seen_2 = TestExplicitCheckpointFile._RecordingAttack.last_checkpoint_file_seen

        assert seen_1 == seen_2 == custom_checkpoint
