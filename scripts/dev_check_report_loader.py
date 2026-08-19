"""Dev-only sanity check of aginiti.report.load_run against whatever partial
run data currently exists on disk -- not a pytest (needs real run output)."""
import glob
import os
import sys

from aginiti.report import load_run

run_dirs = sorted(glob.glob("runs/*"))
if not run_dirs:
    print("no runs found")
    sys.exit(1)

run_dir = run_dirs[-1] if len(sys.argv) < 2 else os.path.join("runs", sys.argv[1])
data = load_run(run_dir)
print("run_id:", data["run_id"])
print("mission:", data["mission"])
for cond, summary in data["summaries"].items():
    print(f"  {cond:14s} {summary}")
print("comparisons:", [(c.baseline, c.p_value) for c in data["comparisons"]])
