"""Slice F re-verification of scripts/run_campaign.py's new CLI
(--agent-url/--tier/--budget/--model), run with explicit user approval
(2026-08-21): confirms all 4 --tier values actually work against the real
Docker-hosted reference_agent_blackbox, not just mocked/unit-level checks.

Each tier is invoked via `subprocess` -- not by calling main() directly in
this process -- specifically because that's the ONLY faithful way to test
this: --model's env-var-before-import trick only works once per Python
process (aginiti.operators.deep_attack_operators is cached in sys.modules
after its first import), so a real fresh `python scripts/run_campaign.py
...` subprocess per tier is what an actual user running this CLI
experiences, not an in-process shortcut that could silently pass for the
wrong reason.

Small, explicit deep-attack query budgets throughout (env vars) -- this is
a wiring/correctness smoke test of the CLI itself, not a benchmark run.
Same discipline as every other smoke_test_*.py in this directory: NOT
trying to find anything, trying to NOT CRASH and to produce
plausible-looking, correctly-tier-scoped output.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("run_campaign_cli_smoke_test")

REPO_ROOT = Path(__file__).parent.parent
PYTHON = sys.executable
TARGET_URL = os.environ.get("IKEA_TARGET_URL", "http://localhost:8001")

_SMALL_DEEP_ATTACK_ENV = {
    **os.environ,
    "IKEA_OPERATOR_MAX_QUERIES": "2",
    "SECRET_OPERATOR_MAX_QUERIES": "2",
    "SECRET_OPERATOR_PHASE1_N_ITER": "1",
    "SECRET_OPERATOR_PHASE1_N_CAND": "1",
    "MIA_OPERATOR_N_PROBE_QUESTIONS": "1",
}

_RESULTS: dict[str, dict] = {}


def _run_tier(tier: str, budget: int) -> dict:
    cmd = [
        PYTHON, "scripts/run_campaign.py",
        "--agent-url", TARGET_URL,
        "--tier", tier,
        "--budget", str(budget),
    ]
    logger.info("Running: %s", " ".join(cmd))
    proc = subprocess.run(
        cmd, cwd=REPO_ROOT, env=_SMALL_DEEP_ATTACK_ENV,
        capture_output=True, text=True, timeout=300,
    )
    detail = {
        "tier": tier,
        "budget": budget,
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-1500:] if proc.returncode != 0 else "",
    }
    ok = proc.returncode == 0 and "OUTCOME:" in proc.stdout
    logger.info(
        "tier=%s: returncode=%d outcome_line=%r",
        tier, proc.returncode,
        next((l for l in proc.stdout.splitlines() if l.startswith("OUTCOME:")), None),
    )
    _RESULTS[tier] = {"ok": ok, **detail}
    return detail


def main() -> None:
    logger.info("=== run_campaign.py CLI smoke test START (2026-08-21) ===")
    logger.info("Target: %s", TARGET_URL)

    _run_tier("discovery_recon", budget=5)
    _run_tier("unauthorized_actions", budget=6)
    _run_tier("data_leakage", budget=8)
    _run_tier("full_assessment", budget=10)

    out_path = REPO_ROOT / "experiments/results/runs_smoke_test_2026_08_21_run_campaign_cli.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(_RESULTS, indent=2, default=str), encoding="utf-8")
    logger.info("=== DONE -- results written to %s ===", out_path)

    all_ok = all(r["ok"] for r in _RESULTS.values())
    logger.info("=== OVERALL: %s ===", "ALL PASSED" if all_ok else "AT LEAST ONE FAILED")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
