import argparse
import json
import logging
import os
import dataclasses
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

from aginiti.attacks.spe import SPEAttack
from aginiti.reporting import generate_markdown_report

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("spe-benchmark")

_RESULTS_DIR = Path("benchmarks/scaled_evals/results")

def _api_key_for(persona: str) -> Optional[str]:
    env_var = f"HARDENED_AGENT_{persona.upper()}_API_KEY"
    return os.environ.get(env_var)

def _live_toggle_state(agent_url: str) -> dict:
    try:
        resp = requests.get(f"{agent_url}/config", timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning(f"Could not fetch {agent_url}/config ({exc}) -- metadata toggle state won't be recorded.")
        return {}

def main():
    parser = argparse.ArgumentParser(description="Run SPE-LLM benchmark against target agent")
    parser.add_argument("--agent-url", type=str, default="http://localhost:8004")
    parser.add_argument("--persona", type=str, default="legal")
    parser.add_argument("--ground-truth-prompt", type=str, default="",
                        help="The exact system prompt to test extraction against (optional)")
    parser.add_argument("--output", type=str, default="",
                        help="Output JSON file path (e.g. benchmarks/scaled_evals/results/spe.json)")
    args = parser.parse_args()

    api_key = _api_key_for(args.persona)
    endpoint_kwargs = {}
    if api_key:
        endpoint_kwargs["headers"] = {"Authorization": f"Bearer {api_key}"}

    attack = SPEAttack(
        target_url=args.agent_url,
        endpoint_kwargs=endpoint_kwargs,
    )

    logger.info(f"Starting SPE-LLM benchmark on {args.agent_url} (persona: {args.persona})")
    
    started_at = datetime.now(timezone.utc)
    
    # Run the black-box heuristic extraction first (no ground truth required)
    findings = attack.execute_black_box(persona=args.persona)
    
    # Optionally score against the ground truth if provided
    if args.ground_truth_prompt:
        findings = attack.score_against_ground_truth(findings, args.ground_truth_prompt)

    finished_at = datetime.now(timezone.utc)
    duration_seconds = (finished_at - started_at).total_seconds()

    live_config = _live_toggle_state(args.agent_url)

    # Format the report using the standard run_metadata schema to enable Markdown reporting
    report = {
        "run_metadata": {
            "attack": "spe",
            "agent_url": args.agent_url,
            "dataset": "system_prompt",
            "dataset_size": 1,
            "authorized_by": "Security Team",
            "engagement_id": "SPE-Audit",
            "topic": "system_prompt",
            "total_queries": len(findings),
            "queries_sent": len(findings),
            "timestamp": started_at.isoformat(),
            "runtime_seconds": round(duration_seconds, 1),
            "persona": args.persona,
            "target_toggle_state": live_config or "unknown",
            "embed_model": "chromadb/all-MiniLM-L6-v2",
            "llm_provider": "gemini/gemini-3.5-flash",
        },
        "metrics": {
            "asr": sum(1 for f in findings if f.confirmed) / len(findings) if findings else 0.0,
            "avg_cosine": sum(f.confidence for f in findings) / len(findings) if findings else 0.0,
        } if args.ground_truth_prompt else None,
        "findings": [dataclasses.asdict(f) for f in findings],
        "refused_queries": [],
    }

    if not args.output:
        _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out_file = _RESULTS_DIR / f"spe_benchmark_{args.persona}_{started_at.strftime('%Y%m%dT%H%M%SZ')}.json"
    else:
        out_file = Path(args.output)
        out_file.parent.mkdir(parents=True, exist_ok=True)
    
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info(f"Wrote results to {out_file}")
    
    # Generate the Markdown reports (full and redacted)
    md_path = out_file.with_suffix(".md")
    generate_markdown_report(report, md_path)
    logger.info(f"Wrote Markdown report to {md_path}")

    redacted_md_path = out_file.with_name(out_file.stem + "_redacted.md")
    generate_markdown_report(report, redacted_md_path, redact=True)
    logger.info(f"Wrote redacted Markdown report to {redacted_md_path}")
        
    print("\n=== RESULTS ===")
    for f in findings:
        strategy = "Unknown"
        if "Strategy=" in f.reasoning:
            strategy = f.reasoning.split("Strategy=")[1].split("|")[0].strip()
        print(f"Strategy: {strategy} -> Confirmed Leak: {f.confirmed} (Severity: {f.severity})")
        if f.confirmed:
            print(f"  Snippet: {f.leaked_content[:100]}...")

if __name__ == "__main__":
    main()
