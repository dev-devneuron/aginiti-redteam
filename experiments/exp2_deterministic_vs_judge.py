"""Experiment 2 -- does deterministic extraction actually save an LLM call
while matching the judge's own verdict, on IDENTICAL evidence?

Claim under test (docs/EVIDENCE_AND_EVALUATION.md, "Deterministic
extraction"): the deterministic-extractor path is cheaper (zero LLM calls)
and at least as reliable as the LLM judge, for operators whose responses
are already structured data.

This is a live experiment (real Groq calls), kept deliberately small: it
reuses the 4-operator MCP filesystem library and the 3-operator DVAA
consensus library -- both already fully deterministic-extractor-based in
production -- and, for each of the 7 operators, sends the SAME real live
target interaction ONCE, then runs the ONE captured raw response through
BOTH paths:
  (a) the operator's own extractor (already the production path -- zero
      LLM calls)
  (b) the LLM judge (_judge(), normally never invoked for these operators)
and compares: does the judge's confirmed_effect_ids set agree with the
extractor's set? How long does the judge call take relative to the
zero-cost extractor call?

Ground truth for "did the judge get it right": the extractor's own output,
NOT an independent third source -- this is a deliberate, documented
simplification (see docs/EVIDENCE_AND_EVALUATION.md's missing-evidence
section): for these specific operators the extractor is definitionally
correct (it implements the exact, publicly-documented protocol semantics
against a raw JSON response with no ambiguity), so using it as ground truth
here is reasonable; it would NOT be reasonable for free-form natural-
language targets, where this same comparison cannot be run this way.

Total live cost: 7 target interactions (already inexpensive/free -- 4 are
local MCP stdio calls, 3 are local HTTP calls to a scenario server) + 7 LLM
judge calls (the only Groq cost this experiment incurs).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, ".")

from aginiti.adapter.observation_adapter import _effect_id, _judge
from aginiti.adapters.dvaa_adapter import DVAAAdapter
from aginiti.adapters.mcp_stdio_adapter import McpStdioAdapter
from aginiti.graph.ssg import SecurityStateGraph
from aginiti.operators.dvaa_consensus_definitions import build_dvaa_consensus_library
from aginiti.operators.mcp_filesystem_definitions import build_filesystem_mcp_library
from experiments.results_io import save_result

MCP_FS_SERVER_ENTRY = os.environ.get(
    "MCP_FS_SERVER_ENTRY",
    r"C:\Users\Omer\AppData\Local\Temp\claude\E--GAIS\694ce032-bc29-4d9a-a148-e34f14e67253"
    r"\scratchpad\mcp-fs-test\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js",
)
VOTING_SERVER_ENTRY = os.environ.get(
    "VOTING_SERVER_ENTRY",
    r"C:\Users\Omer\AppData\Local\Temp\claude\E--GAIS\694ce032-bc29-4d9a-a148-e34f14e67253"
    r"\scratchpad\dvaa\scenarios\consensus-manipulation\vulnerable\voting.cjs",
)
SECRET_MARKER = "OUTSIDE_MARKER_XYZ_42"


def _capture(operator, agent, ssg) -> tuple[str, float]:
    prompt = operator.render_prompt(ssg)
    start = time.monotonic()
    raw = agent.send(operator.channel, prompt).final_text
    elapsed = time.monotonic() - start
    return raw, elapsed


def _compare(operator, raw: str) -> dict:
    all_effects = (*operator.effects_success, *operator.effects_failure)
    effects_by_id = {_effect_id(e): e for e in all_effects}

    ext_start = time.monotonic()
    extractor_ids = sorted(i for i in operator.extractor(raw) if i in effects_by_id)
    ext_elapsed = time.monotonic() - ext_start

    judge_start = time.monotonic()
    verdict = _judge(operator, raw, seed=0)
    judge_elapsed = time.monotonic() - judge_start
    judge_ids = sorted(i for i in verdict.get("confirmed_effect_ids", []) if i in effects_by_id)

    return {
        "operator_id": operator.id,
        "raw_signal": raw,
        "extractor_confirmed": extractor_ids,
        "extractor_seconds": ext_elapsed,
        "extractor_llm_calls": 0,
        "judge_confirmed": judge_ids,
        "judge_reasoning": verdict.get("reasoning", ""),
        "judge_seconds": judge_elapsed,
        "judge_llm_calls": 1,
        "agree": extractor_ids == judge_ids,
    }


def _run_mcp_filesystem() -> list[dict]:
    sandbox_root = tempfile.mkdtemp(prefix="aginiti_exp2_mcp_fs_")
    inside_path = os.path.join(sandbox_root, "secret.txt")
    inside_content = "top secret sandbox content"
    with open(inside_path, "w", encoding="utf-8") as f:
        f.write(inside_content)
    outside_path = os.path.join(os.path.dirname(sandbox_root), "aginiti_exp2_outside_secret.txt")
    with open(outside_path, "w", encoding="utf-8") as f:
        f.write(f"{SECRET_MARKER} -- should NOT be reachable from inside the sandbox root")

    library = build_filesystem_mcp_library(
        allowed_root=sandbox_root, inside_file_path=inside_path, inside_file_content=inside_content,
        outside_file_path=outside_path, secret_marker=SECRET_MARKER,
    )
    agent = McpStdioAdapter(server_name="filesystem", command="node", args=[MCP_FS_SERVER_ENTRY, sandbox_root],
                            secret_marker=SECRET_MARKER)
    ssg = SecurityStateGraph()
    results = []
    try:
        for op in library:
            raw, send_seconds = _capture(op, agent, ssg)
            row = _compare(op, raw)
            row["target"] = "mcp_filesystem"
            row["send_seconds"] = send_seconds
            results.append(row)
    finally:
        agent.close()
        shutil.rmtree(sandbox_root, ignore_errors=True)
        if os.path.exists(outside_path):
            os.remove(outside_path)
    return results


def _run_dvaa_consensus() -> list[dict]:
    library = build_dvaa_consensus_library()
    agent = DVAAAdapter()
    ssg = SecurityStateGraph()
    results = []
    # Run in the library's declared (progressively-deeper-question) order --
    # each operator's real server-side effect depends on the vote state the
    # PRIOR operator left behind on the same live decision, same as a real
    # campaign would naturally encounter it.
    for op in library:
        raw, send_seconds = _capture(op, agent, ssg)
        row = _compare(op, raw)
        row["target"] = "dvaa_consensus"
        row["send_seconds"] = send_seconds
        results.append(row)
    return results


def main() -> None:
    voting_proc = subprocess.Popen(["node", VOTING_SERVER_ENTRY], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    cwd=os.path.dirname(VOTING_SERVER_ENTRY))
    time.sleep(1.5)  # let the server bind and seed its decision before the first request

    try:
        mcp_rows = _run_mcp_filesystem()
        consensus_rows = _run_dvaa_consensus()
    finally:
        voting_proc.terminate()
        try:
            voting_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            voting_proc.kill()

    rows = mcp_rows + consensus_rows
    n_agree = sum(1 for r in rows if r["agree"])
    total_judge_seconds = sum(r["judge_seconds"] for r in rows)
    total_extractor_seconds = sum(r["extractor_seconds"] for r in rows)

    print(f"=== Experiment 2: deterministic extraction vs LLM judge, n={len(rows)} operators ===")
    for r in rows:
        status = "AGREE" if r["agree"] else "DISAGREE"
        print(f"  [{status}] {r['target']}/{r['operator_id']}: "
              f"extractor={r['extractor_confirmed']} judge={r['judge_confirmed']}")
    print()
    print(f"Agreement: {n_agree}/{len(rows)} ({n_agree / len(rows):.0%})")
    print(f"LLM calls: extractor path=0, judge path={len(rows)} (one per operator)")
    print(f"Total judge time: {total_judge_seconds:.2f}s, total extractor time: {total_extractor_seconds:.5f}s "
          f"({total_judge_seconds / max(total_extractor_seconds, 1e-9):.0f}x slower)")

    path = save_result("exp2_deterministic_vs_judge", {
        "n_operators": len(rows),
        "n_agree": n_agree,
        "agreement_rate": n_agree / len(rows),
        "total_judge_seconds": total_judge_seconds,
        "total_extractor_seconds": total_extractor_seconds,
        "judge_llm_calls": len(rows),
        "extractor_llm_calls": 0,
        "rows": rows,
    })
    print(f"\nsaved to {path}")


if __name__ == "__main__":
    main()
