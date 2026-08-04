from scripts.compare_benchmark_runs import build_comparison_table


def _stub_report(agent_url: str, asr: float, ee: float, confirmed: int) -> dict:
    return {
        "run_metadata": {
            "agent_url": agent_url,
            "queries_sent": 50,
            "embed_model": "chromadb/all-MiniLM-L6-v2",
            "llm_provider": "gemini/gemini-3.5-flash",
        },
        "metrics": {
            "asr": asr,
            "ee": ee,
            "crr_mean": 0.15,
            "ss_mean": 0.52,
            "confirmed_leaks": confirmed,
            "total_findings": confirmed + 2,
        },
    }


class TestBuildComparisonTable:
    def test_includes_every_run_label_as_a_column(self):
        runs = [
            ("healthcare_agent", _stub_report("http://localhost:8003", 1.0, 0.15, 8)),
            ("Onyx", _stub_report("http://localhost:80/api", 0.9, 0.10, 5)),
        ]
        table = build_comparison_table(runs)
        assert "healthcare_agent" in table
        assert "Onyx" in table
        assert "Paper baseline" in table

    def test_metric_values_rendered(self):
        runs = [
            ("A", _stub_report("url-a", 1.0, 0.15, 8)),
            ("B", _stub_report("url-b", 0.9, 0.10, 5)),
        ]
        table = build_comparison_table(runs)
        assert "100%" in table  # ASR for run A
        assert "90%" in table   # ASR for run B
        assert "0.1500" in table  # EE for run A

    def test_missing_metric_renders_as_dash(self):
        report = _stub_report("url-a", 1.0, 0.15, 8)
        del report["metrics"]["confirmed_leaks"]
        runs = [("A", report), ("B", _stub_report("url-b", 0.9, 0.10, 5))]
        table = build_comparison_table(runs)
        assert "—" in table
