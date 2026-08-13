import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from aginiti.attacks.spe import SPEAttack

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("spe-benchmark")

_RESULTS_DIR = Path("benchmarks/scaled_evals/results")

def main():
    parser = argparse.ArgumentParser(description="Run SPE-LLM benchmark against target agent")
    parser.add_argument("--agent-url", type=str, default="http://localhost:8004")
    parser.add_argument("--persona", type=str, default="legal")
    parser.add_argument("--ground-truth-prompt", type=str, required=True,
                        help="The exact system prompt to test extraction against")
    parser.add_argument("--output", type=str, default="",
                        help="Output JSON file path (e.g. scripts/results/spe.json)")
    args = parser.parse_args()

    attack = SPEAttack(
        target_url=args.agent_url,
    )

    logger.info(f"Starting SPE-LLM benchmark on {args.agent_url} (persona: {args.persona})")
    
    findings = attack.execute_black_box(
        persona=args.persona,
        ground_truth_prompt=args.ground_truth_prompt
    )

    if not args.output:
        _RESULTS_DIR = Path("benchmarks/scaled_evals/results")
        _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out_file = _RESULTS_DIR / f"spe_benchmark_{args.persona}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    else:
        out_file = Path(args.output)
        out_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "attack": "SPE-LLM",
                "target_url": args.agent_url,
                "persona": args.persona,
                "ground_truth_prompt": args.ground_truth_prompt,
                "findings": [
                    {
                        "strategy": f.reasoning.split("|")[0].replace("Strategy=", "").strip(),
                        "probe": f.probe_used,
                        "response": f.full_response,
                        "em": int(f.reasoning.split("EM=")[1].split("|")[0].strip()),
                        "sm": int(f.reasoning.split("SM=")[1].split("|")[0].strip()),
                        "cosine": float(f.reasoning.split("Cosine=")[1].strip()),
                        "asr_success": f.confirmed,
                    }
                    for f in findings
                ],
                "summary": {
                    "total_strategies": len(findings),
                    "asr_successes": sum(1 for f in findings if f.confirmed)
                }
            },
            f, indent=2
        )
        
    logger.info(f"\nSPE-LLM Benchmark Complete. Results saved to {out_file}")
    
    print("\n=== RESULTS ===")
    for f in findings:
        print(f"{f.reasoning} -> ASR Success: {f.confirmed}")

if __name__ == "__main__":
    main()
