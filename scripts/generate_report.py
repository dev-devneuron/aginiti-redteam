"""Render a benchmark run's on-disk JSON logs into a self-contained HTML
report: summary comparison, a success-rate chart, statistical comparison,
and per-trial verifiable evidence (raw target transcripts + decision
traces), not just aggregate claims.
"""
from __future__ import annotations

import glob
import html
import os
import sys

from aginiti.operators.definitions import build_library
from aginiti.core.report import CONDITION_LABELS, CONDITION_ORDER, load_run

CONDITION_EXPLAIN = {
    "random": ("Floor baseline.", "Uniformly picks among whatever operators currently satisfy "
               "their preconditions. Doesn't use outcomes or the SSG's confidence/graph at all -- "
               "required so any measured advantage means something (design doc Section 20)."),
    "static": ("garak/PyRIT-style systematic probing.", "Always attempts operators in one fixed, "
               "declared checklist order (aginiti/operators/definitions.py's list order), skipping "
               "whichever aren't eligible yet. Never re-ranks based on what it learns."),
    "memory_guided": ("AutoRedTeamer-style attack-outcome memory.", "Weights operator selection by "
               "historical success rate, carried across this condition's own trials -- but has no "
               "model of *this specific target's* structure, only \"what has worked before\" in "
               "general. Cross-trial memory, not within-campaign target modeling."),
    "aginiti": ("The system under test.", "Ranks eligible operators by a constrained utility "
               "combining information gain and business impact, computed from the live Security "
               "State Graph -- the only condition that reasons about what THIS target has revealed "
               "about itself so far."),
}


def op_summary_row(op) -> str:
    pre = ", ".join(f"{p.key}={p.status.value}" for p in op.preconditions) or "none"
    return (f'<tr><td><code>{esc(op.id)}</code></td><td>{esc(op.description)}</td>'
            f'<td class="tabular">{esc(pre)}</td><td class="tabular">{esc(op.risk_tier.value)}</td>'
            f'<td class="tabular">{esc(op.cost_prompts)}</td></tr>')

# Categorical slots 1-4 (blue/orange/aqua/yellow) from the validated default
# palette, adjacent-pairlist-safe for bar charts in both light and dark mode.
CONDITION_COLOR_VAR = {
    "random": "--series-1",
    "static": "--series-2",
    "memory_guided": "--series-3",
    "aginiti": "--series-4",
}


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def fmt_pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def fmt_num(x, digits=1) -> str:
    if x is None:
        return "n/a"
    return f"{x:.{digits}f}"


def render_chart(summaries: dict) -> str:
    rows = []
    row_h, gap, label_w, chart_w, bar_h = 34, 14, 150, 420, 20
    total_h = len(CONDITION_ORDER) * (row_h + gap)
    for i, cond in enumerate(CONDITION_ORDER):
        s = summaries[cond]
        rate = s["success_rate"]
        y = i * (row_h + gap)
        bar_w = max(2, rate * chart_w) if s["trials"] else 0
        color_var = CONDITION_COLOR_VAR[cond]
        label = esc(CONDITION_LABELS[cond])
        n_label = f"{s['successes']}/{s['trials']}" if s["trials"] else "no data"
        rows.append(f'''
        <g class="bar-row">
          <text x="{label_w - 10}" y="{y + row_h/2 + 4}" text-anchor="end" class="bar-label">{label}</text>
          <rect x="{label_w}" y="{y + (row_h-bar_h)/2}" width="{chart_w}" height="{bar_h}" class="bar-track" rx="3"/>
          <rect x="{label_w}" y="{y + (row_h-bar_h)/2}" width="{bar_w:.1f}" height="{bar_h}"
                fill="var({color_var})" rx="3">
            <title>{label}: {fmt_pct(rate)} ({esc(n_label)})</title>
          </rect>
          <text x="{label_w + chart_w + 12}" y="{y + row_h/2 + 4}" class="bar-value">{fmt_pct(rate)}
            <tspan class="bar-value-sub"> ({esc(n_label)})</tspan></text>
        </g>''')
    width = label_w + chart_w + 130
    gridlines = "".join(
        f'<line x1="{label_w + f*chart_w:.1f}" y1="0" x2="{label_w + f*chart_w:.1f}" y2="{total_h - gap}" class="gridline"/>'
        for f in (0, 0.25, 0.5, 0.75, 1.0)
    )
    return f'''<svg viewBox="0 0 {width} {total_h - gap + 10}" class="chart" role="img"
      aria-label="Mission success rate by condition">{gridlines}{''.join(rows)}</svg>'''


def render_trial(t: dict) -> str:
    outcome = t.get("outcome", "?")
    badge_cls = "badge-good" if outcome == "SUCCESS" else "badge-muted"
    gt = t.get("ground_truth_mission_achieved")
    gt_badge = ('<span class="badge badge-good">ground truth: mission achieved</span>' if gt
                else '<span class="badge badge-muted">ground truth: no mission achieved</span>')
    exec_rows = []
    for e in t.get("execution_log", []):
        status = "confirmed effect" if e.get("overall_success") else "no confirmed effect"
        prompt_sent = e.get("prompt_sent", "")
        prompt_block = (
            f'<div class="exec-field"><span class="muted">sent to target:</span></div>'
            f'<div class="exec-transcript">{esc(prompt_sent)}</div>'
            if prompt_sent else ""
        )
        exec_rows.append(f'''
        <div class="exec-row">
          <div class="exec-head"><code>{esc(e.get("operator_id"))}</code> <span class="muted">-- {esc(status)}</span></div>
          {prompt_block}
          <div class="exec-field"><span class="muted">target's visible response:</span></div>
          <div class="exec-transcript">{esc(e.get("raw_signal", ""))}</div>
          <div class="exec-field"><span class="muted">confirmed keys:</span> {esc(", ".join(e.get("confirmed_keys", [])) or "none")}</div>
          <div class="exec-field"><span class="muted">judge reasoning:</span> {esc(e.get("reasoning", ""))}</div>
        </div>''')
    decision_rows = "".join(
        f'<tr><td>{d.get("step")}</td><td>{esc(d.get("chosen_operator_id"))}</td>'
        f'<td class="tabular">{fmt_num(d.get("score"), 2)}</td>'
        f'<td class="tabular">{d.get("candidates_considered")}</td></tr>'
        for d in t.get("decision_log", [])
    )
    claims_rows = "".join(
        f'<tr><td>{esc(c.get("key"))}</td><td>{esc(c.get("status"))}</td><td>{esc(c.get("confidence"))}</td></tr>'
        for c in t.get("final_claims", [])
    )
    return f'''
    <details class="trial">
      <summary>
        <span class="badge {badge_cls}">{esc(outcome)}</span>
        trial {t.get("trial")} &middot; seed {esc(t.get("seed"))} &middot;
        {t.get("prompts_used")} prompts &middot; {len(t.get("operators_executed", []))} operators
        {gt_badge}
      </summary>
      <div class="trial-body">
        <h4>Decision trace</h4>
        <div class="table-scroll"><table class="mini-table">
          <thead><tr><th>step</th><th>chosen</th><th>score</th><th>considered</th></tr></thead>
          <tbody>{decision_rows}</tbody>
        </table></div>
        <h4>Execution log (raw target transcripts + judge verdicts)</h4>
        {"".join(exec_rows)}
        <h4>Final Security State Graph claims</h4>
        <div class="table-scroll"><table class="mini-table">
          <thead><tr><th>key</th><th>status</th><th>confidence</th></tr></thead>
          <tbody>{claims_rows}</tbody>
        </table></div>
      </div>
    </details>'''


def render_report(data: dict) -> str:
    mission = data["mission"] or {}
    summaries = data["summaries"]
    comparisons = data["comparisons"]
    library = build_library()

    condition_explain_rows = "".join(
        f'''<tr><td><span class="swatch" style="background:var({CONDITION_COLOR_VAR[c]})"></span>
             {esc(CONDITION_LABELS[c])}</td><td><strong>{esc(CONDITION_EXPLAIN[c][0])}</strong></td>
             <td>{esc(CONDITION_EXPLAIN[c][1])}</td></tr>'''
        for c in CONDITION_ORDER
    )
    operator_rows = "".join(op_summary_row(op) for op in library)

    summary_rows = []
    efficiency_rows = []
    winning_path_rows = []
    for cond in CONDITION_ORDER:
        s = summaries[cond]
        swatch = f'<span class="swatch" style="background:var({CONDITION_COLOR_VAR[cond]})"></span>'
        summary_rows.append(f'''
        <tr>
          <td>{swatch}{esc(CONDITION_LABELS[cond])}</td>
          <td class="tabular">{s["successes"]}/{s["trials"]}</td>
          <td class="tabular">{fmt_pct(s["success_rate"])}</td>
          <td class="tabular">{fmt_num(s["mean_prompts_used"])}</td>
          <td class="tabular">{fmt_num(s["mean_prompts_used_on_success"])}</td>
          <td class="tabular">{fmt_pct(s["belief_accuracy"])}</td>
        </tr>''')
        efficiency_rows.append(f'''
        <tr>
          <td>{swatch}{esc(CONDITION_LABELS[cond])}</td>
          <td class="tabular">{fmt_num(s["mean_operators_considered"])}</td>
          <td class="tabular">{fmt_num(s["mean_operators_rejected"])}</td>
          <td class="tabular">{fmt_num(s["mean_operators_executed"])}</td>
          <td class="tabular">{fmt_num(s["mean_useful_observations"])}</td>
          <td class="tabular">{fmt_pct(s["signal_efficiency"])}</td>
        </tr>''')
        if s["winning_paths"]:
            paths_str = ", ".join(f"{esc(k)}: {v}" for k, v in s["winning_paths"].items())
        else:
            paths_str = '<span class="muted">no successes yet</span>'
        winning_path_rows.append(f'<tr><td>{swatch}{esc(CONDITION_LABELS[cond])}</td><td>{paths_str}</td></tr>')

    comparison_rows = "".join(
        f'''<tr><td>Aginiti vs {esc(c.baseline)}</td>
             <td class="tabular">{c.aginiti_successes}/{c.aginiti_trials}</td>
             <td class="tabular">{c.baseline_successes}/{c.baseline_trials}</td>
             <td class="tabular">{c.p_value:.3f}</td>
             <td>{esc(c.interpret())}</td></tr>'''
        for c in comparisons
    ) or '<tr><td colspan="5" class="muted">No Aginiti trials completed yet -- comparisons pending.</td></tr>'

    trial_sections = []
    for cond in CONDITION_ORDER:
        trials = data["trials_by_condition"][cond]
        if not trials:
            continue
        trial_sections.append(f'<h3>{esc(CONDITION_LABELS[cond])}</h3>' + "".join(render_trial(t) for t in trials))

    total_trials = sum(s["trials"] for s in summaries.values())

    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aginiti Phase 0 -- Benchmark Report {esc(data["run_id"])}</title>
<style>
  :root {{
    color-scheme: light;
    --surface-1: #fcfcfb; --page: #f9f9f7;
    --text-primary: #0b0b0b; --text-secondary: #52514e; --text-muted: #898781;
    --gridline: #e1e0d9; --baseline: #c3c2b7; --border: rgba(11,11,11,0.10);
    --series-1: #2a78d6; --series-2: #eb6834; --series-3: #1baf7a; --series-4: #eda100;
    --good: #006300; --good-bg: rgba(12,163,12,0.12);
    --muted-badge-bg: rgba(137,135,129,0.16);
  }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) {{
      color-scheme: dark;
      --surface-1: #1a1a19; --page: #0d0d0d;
      --text-primary: #ffffff; --text-secondary: #c3c2b7; --text-muted: #898781;
      --gridline: #2c2c2a; --baseline: #383835; --border: rgba(255,255,255,0.10);
      --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70; --series-4: #c98500;
      --good: #0ca30c; --good-bg: rgba(12,163,12,0.18);
      --muted-badge-bg: rgba(137,135,129,0.22);
    }}
  }}
  :root[data-theme="dark"] {{
    color-scheme: dark;
    --surface-1: #1a1a19; --page: #0d0d0d;
    --text-primary: #ffffff; --text-secondary: #c3c2b7; --text-muted: #898781;
    --gridline: #2c2c2a; --baseline: #383835; --border: rgba(255,255,255,0.10);
    --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70; --series-4: #c98500;
    --good: #0ca30c; --good-bg: rgba(12,163,12,0.18);
    --muted-badge-bg: rgba(137,135,129,0.22);
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--page); color: var(--text-primary);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 40px 24px 80px; }}
  header.report-header {{ margin-bottom: 32px; }}
  .eyebrow {{ font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }}
  h1 {{ font-size: 26px; margin: 6px 0 4px; text-wrap: balance; }}
  .subtitle {{ color: var(--text-secondary); font-size: 15px; margin: 0; }}
  .meta-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; margin-top: 20px; padding: 16px; background: var(--surface-1);
    border: 1px solid var(--border); border-radius: 8px;
  }}
  .meta-item .k {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); }}
  .meta-item .v {{ font-size: 14px; margin-top: 2px; }}
  section {{ margin: 40px 0; }}
  h2 {{ font-size: 18px; border-bottom: 1px solid var(--gridline); padding-bottom: 8px; }}
  h3 {{ font-size: 15px; color: var(--text-secondary); margin-top: 28px; }}
  h4 {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin: 16px 0 6px; }}
  p {{ color: var(--text-secondary); }}
  .table-scroll {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--gridline); }}
  th {{ color: var(--text-muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; }}
  .tabular {{ font-variant-numeric: tabular-nums; }}
  .swatch {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 8px; }}
  .chart {{ width: 100%; height: auto; margin-top: 8px; }}
  .bar-label {{ font-size: 12px; fill: var(--text-secondary); }}
  .bar-value {{ font-size: 13px; fill: var(--text-primary); font-variant-numeric: tabular-nums; }}
  .bar-value-sub {{ fill: var(--text-muted); font-size: 11px; }}
  .bar-track {{ fill: var(--gridline); }}
  .gridline {{ stroke: var(--gridline); stroke-width: 1; }}
  .badge {{
    display: inline-block; font-size: 11px; font-weight: 600; padding: 2px 8px;
    border-radius: 99px; margin-right: 8px; text-transform: uppercase; letter-spacing: 0.02em;
  }}
  .badge-good {{ background: var(--good-bg); color: var(--good); }}
  .badge-muted {{ background: var(--muted-badge-bg); color: var(--text-muted); }}
  .muted {{ color: var(--text-muted); }}
  details.trial {{
    background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px;
    margin: 10px 0; padding: 10px 14px;
  }}
  details.trial summary {{ cursor: pointer; font-size: 13.5px; }}
  .trial-body {{ margin-top: 14px; }}
  .mini-table {{ font-size: 12.5px; }}
  .exec-row {{ border-top: 1px solid var(--gridline); padding: 10px 0; }}
  .exec-head {{ font-size: 13px; margin-bottom: 4px; }}
  .exec-field {{ font-size: 12.5px; color: var(--text-secondary); margin: 2px 0; }}
  .exec-transcript {{
    margin-top: 6px; padding: 8px 10px; background: var(--page); border-radius: 6px;
    font-size: 12.5px; color: var(--text-secondary); white-space: pre-wrap;
  }}
  code {{ background: var(--page); padding: 1px 5px; border-radius: 4px; font-size: 12.5px; }}
  footer {{ margin-top: 60px; padding-top: 16px; border-top: 1px solid var(--gridline); color: var(--text-muted); font-size: 12.5px; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="report-header">
    <div class="eyebrow">Aginiti &middot; Phase 0 Benchmark</div>
    <h1>{esc(mission.get("goal", "Benchmark report"))}</h1>
    <p class="subtitle">Random / Static-enumeration / Memory-guided / Aginiti, run against the same reference
      target under the same budget -- the experiment design doc Section 20 defines to test the Core Hypothesis (RQ1).</p>
    <div class="meta-grid">
      <div class="meta-item"><div class="k">Run ID</div><div class="v">{esc(data["run_id"])}</div></div>
      <div class="meta-item"><div class="k">Budget</div><div class="v">{esc(mission.get("budget", "?"))} prompts</div></div>
      <div class="meta-item"><div class="k">Risk threshold</div><div class="v">{esc(mission.get("risk_threshold", "?"))}</div></div>
      <div class="meta-item"><div class="k">Trials completed</div><div class="v">{total_trials} total</div></div>
      <div class="meta-item"><div class="k">Base seed</div><div class="v">{esc(data.get("base_seed", "?"))}</div></div>
    </div>
  </header>

  <section>
    <h2>What this experiment tests</h2>
    <p>Aginiti's core hypothesis (design doc Section 5.1) is that maintaining an evidence-linked, continuously
      updated structural model of a target -- a <strong>Security State Graph (SSG)</strong> -- lets an adaptive
      planner find higher-impact attack paths at equal or lower cost than static or memory-guided alternatives.
      This benchmark is the experiment that tests it: the same reference target, the same mission and budget,
      four different policies deciding what to try next.</p>
    <p>The SSG itself is simple in structure but load-bearing for everything above it: every fact Aginiti
      believes about the target is a <strong>Claim</strong> (an assertion with a status -- hypothesized,
      confirmed, or refuted -- and a confidence derived from evidence), and every Claim is backed by one or more
      <strong>Observations</strong> (a timestamped record of what the target actually said). Claims are
      append-only -- a revised belief supersedes the old Claim rather than overwriting it, so the full history of
      what Aginiti believed, and when, is always reconstructable. Only Aginiti's own policy reads this graph to
      decide what to do next; the three baselines below share the same precondition bookkeeping (an operator
      still can't run before its prerequisites are met) but do not use the graph's confidence or claims to rank
      anything.</p>

    <h3>The four conditions</h3>
    <div class="table-scroll">
    <table>
      <thead><tr><th>Condition</th><th>Represents</th><th>How it decides what to try next</th></tr></thead>
      <tbody>{condition_explain_rows}</tbody>
    </table>
    </div>

    <h3>Aginiti's ranking formula</h3>
    <p>For each eligible operator <em>a</em>, Aginiti computes
      <code>utility(a) = &alpha;&middot;I(a) + &beta;&middot;B(a)</code>, where <code>I(a)</code> is information
      gain (a weighted count of Claims this operator could newly confirm or refute -- an unresolved claim is
      worth more than one already settled) and <code>B(a)</code> is business impact (the fraction of the
      mission's still-unmet success criteria this operator could satisfy). <code>&alpha;</code> starts high and
      decays across the campaign; <code>&beta;</code> starts low and rises -- so early steps favor learning about
      the target, later steps favor closing out the mission (design doc Section 12.1). Risk tier and remaining
      budget are hard constraints on the candidate set, not extra terms in the formula -- a high predicted impact
      can never numerically buy its way past a risk limit.</p>

    <h3>The mission and reference target</h3>
    <p>Every trial, in every condition, faces the same mission: <em>{esc(mission.get("goal", ""))}</em>, budget
      {esc(mission.get("budget", "?"))} prompts, risk threshold {esc(mission.get("risk_threshold", "?"))}. The
      target is a mock internal assistant ("Aria") with Payroll/Slack/GitHub tools -- see
      <code>aginiti/target/demo_agent.py</code>. It has one deliberate vulnerability (it's instructed to trust
      messages posted by "HR-Bot" in the #payroll-ops Slack channel as pre-approved) and one deliberate defense
      (it's instructed to be skeptical of a user's unverified claim of manager approval). Which of those two
      properties actually decides a campaign's outcome is exactly what's supposed to vary run to run -- the
      target is a live LLM, not a scripted state machine.</p>

    <h3>Operator library: attacking mindfully, not blindly</h3>
    <p>Two properties of the operator library exist specifically so an "attack" isn't a canned script fired
      regardless of context. First, a <strong>relevance gate</strong>: every operator that asks the target to
      modify payroll now requires <code>payroll_api_exists</code> to be at least hypothesized first -- no
      condition is allowed to demand a payroll write before confirming the target has payroll access at all.
      Second, <strong>context-aware prompts</strong>: the injection and social-engineering operators below
      contain a <code>{{payroll_detail}}</code> slot that gets filled in at execution time with whatever specific
      fact (a name, a salary figure) the judge actually extracted from an earlier response -- not a static
      placeholder. The per-trial evidence section shows the exact rendered prompt each operator sent, so this is
      checkable, not just claimed.</p>
    <div class="table-scroll">
    <table>
      <thead><tr><th>Operator</th><th>What it does</th><th>Precondition</th><th>Risk</th><th>Cost</th></tr></thead>
      <tbody>{operator_rows}</tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>Mission success rate by condition</h2>
    {render_chart(summaries)}
  </section>

  <section>
    <h2>Outcomes and cost</h2>
    <div class="table-scroll">
    <table>
      <thead><tr><th>Condition</th><th>Successes</th><th>Success rate</th><th>Avg prompts (all)</th>
        <th>Avg prompts (wins)</th><th>Belief accuracy</th></tr></thead>
      <tbody>{"".join(summary_rows)}</tbody>
    </table>
    </div>
    <p><strong>Belief accuracy</strong> = fraction of trials where the SSG's claimed outcome (SUCCESS or not)
      matched ground truth (whether a compromise actually happened, checked independently of Aginiti's own
      belief graph) -- a direct check against the "planner hallucination" failure mode the design doc names
      in Section 19.</p>
  </section>

  <section>
    <h2>Search efficiency</h2>
    <p>Success rate alone can't distinguish a selective planner from an exhaustive one if the operator library
      is small enough that everyone eventually gets there. These numbers can: how much of what was <em>considered</em>
      actually got <em>executed</em>, and how much of what got executed actually taught the SSG something
      (<em>useful observations</em> -- confirmed at least one effect, success or defender-block) versus burned a
      prompt for nothing.</p>
    <div class="table-scroll">
    <table>
      <thead><tr><th>Condition</th><th>Considered</th><th>Rejected</th><th>Executed</th>
        <th>Useful observations</th><th>Signal efficiency</th></tr></thead>
      <tbody>{"".join(efficiency_rows)}</tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>Which path won</h2>
    <p>The mission has four independent success criteria (design doc reviewer's core ask: real branching, not
      one linear chain). This shows which one each condition's successful trials actually achieved -- if every
      condition always wins the same way, the environment isn't exercising the branching it's supposed to.</p>
    <div class="table-scroll">
    <table>
      <thead><tr><th>Condition</th><th>Winning paths (claim key: count)</th></tr></thead>
      <tbody>{"".join(winning_path_rows)}</tbody>
    </table>
    </div>
  </section>

  <section>
    <h2>Statistical comparison (Fisher's exact, two-sided)</h2>
    <div class="table-scroll">
    <table>
      <thead><tr><th>Comparison</th><th>Aginiti</th><th>Baseline</th><th>p-value</th><th>Interpretation</th></tr></thead>
      <tbody>{comparison_rows}</tbody>
    </table>
    </div>
    <p>Design doc Section 20 requires a pre-registered minimum effect size and multiple-comparison correction
      before treating a result as supporting RQ1 -- neither is applied here. At the trial counts Phase 0 can
      afford on a free-tier API budget, this table is a directional read, not a validated finding.</p>
  </section>

  <section>
    <h2>Per-trial evidence</h2>
    <p>Every row below is a real transcript from the live target and the judge's verdict on it -- not a
      summary claim. Expand any trial to check the aggregate numbers above against what actually happened.</p>
    {"".join(trial_sections) if trial_sections else "<p class='muted'>No trials logged yet.</p>"}
  </section>

  <footer>
    Generated from runs/{esc(data["run_id"])}/*.json by scripts/generate_report.py.
    Reference target and operator library are described in aginiti/target/ and aginiti/operators/.
  </footer>
</div>
</body>
</html>'''


def main():
    args = [a for a in sys.argv[1:] if a != "--pdf"]
    want_pdf = "--pdf" in sys.argv[1:]

    run_dirs = sorted(glob.glob("runs/*"))
    if not run_dirs:
        print("no runs found under runs/")
        sys.exit(1)
    run_dir_path = run_dirs[-1] if not args else os.path.join("runs", args[0])
    data = load_run(run_dir_path)
    html_out = render_report(data)
    out_path = os.path.join(run_dir_path, "report.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    print(f"wrote {out_path}")

    if want_pdf:
        from aginiti.core.pdf_export import html_to_pdf
        pdf_path = html_to_pdf(out_path)
        print(f"wrote {pdf_path}")


if __name__ == "__main__":
    main()
