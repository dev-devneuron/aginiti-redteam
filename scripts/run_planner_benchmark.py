"""Run the 4-condition benchmark (design doc Section 20) and print the
summary comparison. Full per-trial logs are written to runs/<run_id>/.

Usage:
  python scripts/run_benchmark.py [n_trials] [resume_run_id]

If resume_run_id is given, continues that run -- skipping any
(condition, trial) pair already logged on disk -- instead of starting a
fresh run_id. Use this after hitting an API rate limit mid-run.
"""
import sys

from aginiti.core.benchmark import run_benchmark
from aginiti.core.scenarios import multi_path_mission

n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else 5
resume_run_id = sys.argv[2] if len(sys.argv) > 2 else None

mission = multi_path_mission()

out = run_benchmark(mission, n_trials=n_trials, resume_run_id=resume_run_id)

print("\n" + "=" * 100)
print(f"RUN {out['run_id']}  ({n_trials} trials/condition)  ->  {out['out_dir']}")
print("=" * 100)
header = (f"{'condition':14s} {'succ':>5s} {'rate':>6s} {'avg$':>6s} {'avg$|win':>9s} "
          f"{'exec':>5s} {'considr':>8s} {'reject':>7s} {'useful':>7s} {'signal%':>8s} {'belief':>7s}")
print(header)
for s in out["summaries"]:
    win_cost = f"{s.mean_prompts_used_on_success:.1f}" if s.mean_prompts_used_on_success is not None else "n/a"
    print(f"{s.condition:14s} {s.successes:>3d}/{s.trials:<2d} {s.success_rate*100:5.0f}% "
          f"{s.mean_prompts_used:6.1f} {win_cost:>9s} {s.mean_operators_executed:5.1f} "
          f"{s.mean_operators_considered:8.1f} {s.mean_operators_rejected:7.1f} "
          f"{s.mean_useful_observations:7.1f} {s.signal_efficiency*100:7.0f}% {s.belief_accuracy*100:6.0f}%")
    if s.winning_paths:
        print(f"{'':14s}   winning paths: {s.winning_paths}")
