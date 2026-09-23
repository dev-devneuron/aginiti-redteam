"""
``aginiti`` -- the command-line entry point for the aginiti-redteam attack
library. Lets a security auditor run a real assessment from a terminal,
with no Python code and no git clone required (``pip install
aginiti-redteam`` alone is enough for every subcommand below).

Three subcommands:

    aginiti scan    High-level, use-case-driven campaign (--tier/
                    --attack-category), wrapping the adaptive planner
                    (aginiti/core/campaign_builder.py, the same logic
                    scripts/run_campaign.py uses -- one source of truth).
                    --budget controls how many DIFFERENT techniques it
                    tries (breadth); --deep-attack-queries controls how
                    deep IKEA/SECRET/MIA each go once picked (depth) --
                    two separate knobs, not the same thing.
    aginiti attack  One of the 4 standalone, paper-faithful attacks
                    (ikea/secret/mia/spe) run directly against a target.
    aginiti report  Convert a previously-saved findings.json into a
                    Markdown report on its own, without re-running anything.

Every ``scan``/``attack`` run prints one authorized-use reminder, then
auto-saves ``findings.json`` (the full structured result),
``aginiti_assessment_report.md`` (a human-readable, OWASP-Top-10-mapped
Markdown report), and ``aginiti_assessment_report.html`` (the same report,
styled for a browser) into their own fresh, timestamped subdirectory of
``--output-dir`` (default: ``./results``) -- e.g.
``results/2026-09-23_154012/findings.json`` -- so a later run never
overwrites an earlier one's results; sort ``--output-dir``'s contents by
name (or "date modified") descending to see the most recent run first.
Then opens that HTML report in the default browser automatically
(``--no-open-report`` to skip this, e.g. in a headless/CI/Docker
environment).

Authorized use only. This tool is intended exclusively for security testing
of systems you own or have explicit written permission to test.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import sys
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_AUTH_BANNER = (
    "aginiti-redteam -- for authorized security testing only. "
    "Run this only against systems you own or have explicit permission to test."
)

# ---------------------------------------------------------------------------
# Model auto-detection -- standard AI-ecosystem env var conventions. Order
# is the fixed priority when more than one provider's key is present.
# ---------------------------------------------------------------------------
_PROVIDER_DEFAULTS: list[tuple[str, str]] = [
    ("GEMINI_API_KEY", "gemini/gemini-3.5-flash"),
    ("OPENAI_API_KEY", "openai/gpt-4o-mini"),
    ("GROQ_API_KEY", "groq/openai/gpt-oss-120b"),
    ("ANTHROPIC_API_KEY", "anthropic/claude-3-5-haiku-latest"),
    ("MISTRAL_API_KEY", "mistral/mistral-small-latest"),
]
_PROVIDER_ENV_FOR = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "groq": "GROQ_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}


def _resolve_model(explicit: Optional[str]) -> tuple[str, str]:
    """
    Resolve ``(model, api_key)`` for the attacker/judge LLM.

    Without ``--model``: the first provider (in the fixed order above)
    whose API key is set in the environment. With ``--model``: uses that
    model string, paired with its own provider's key if resolvable, else
    the first available key found (litellm raises its own clear error if
    that key doesn't actually match the model's provider).

    Raises ``SystemExit`` with an actionable message if no key can be
    found at all -- never proceeds with an attack that would silently fail
    every call.
    """
    if explicit:
        provider = explicit.split("/", 1)[0]
        env_var = _PROVIDER_ENV_FOR.get(provider)
        if env_var and os.environ.get(env_var):
            return explicit, os.environ[env_var]
        for env_var, _ in _PROVIDER_DEFAULTS:
            if os.environ.get(env_var):
                return explicit, os.environ[env_var]
        raise SystemExit(
            f"--model {explicit!r} was passed, but no matching API key was found in the "
            f"environment. Set one of: {', '.join(v for v, _ in _PROVIDER_DEFAULTS)}."
        )

    for env_var, default_model in _PROVIDER_DEFAULTS:
        if os.environ.get(env_var):
            return default_model, os.environ[env_var]

    raise SystemExit(
        "No LLM API key found. Set one of "
        + ", ".join(v for v, _ in _PROVIDER_DEFAULTS)
        + " (in your environment or a .env file), or pass --model explicitly."
    )


def _resolve_secret_optimizer(primary_model: str, primary_key: str) -> tuple[str, str]:
    """
    Resolve SECRET Phase 1's optimizer LLM.

    Safety-aligned commercial models (Gemini, GPT) tend to refuse the
    Optimizer's own "author a jailbreak candidate" framing outright --
    Phase 1 then silently produces nothing (a real, previously-confirmed
    failure mode; see docs/USAGE.md's SECRET gotcha). If a Groq key is
    available and the primary model isn't already Groq, prefer Groq for
    this one role specifically. Otherwise falls back to the primary model
    and prints a loud warning, since that combination is known to
    underperform by default.
    """
    if os.environ.get("GROQ_API_KEY") and not primary_model.startswith("groq/"):
        return "groq/openai/gpt-oss-120b", os.environ["GROQ_API_KEY"]
    print(
        "WARNING: SECRET's jailbreak-optimizer step is using the same model as "
        f"extraction ({primary_model!r}). Safety-aligned models often refuse this "
        "step's own framing, silently producing a weak/empty jailbreak. Set "
        "GROQ_API_KEY for a model that reliably complies, or pass --optimizer-model.",
        file=sys.stderr,
    )
    return primary_model, primary_key


# ---------------------------------------------------------------------------
# Logging -- clean, single-line-per-event terminal output. LiteLLM and its
# own HTTP client log at INFO by default (confirmed live: every single
# completion() call emits two colored "LiteLLM completion()"/"Wrapper:
# Completed Call" lines) -- silenced here unless --verbose is passed.
# ---------------------------------------------------------------------------
def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING, format="%(message)s")
    # aginiti's own campaign/attack progress logs stay visible even in the
    # default (non-verbose) mode -- only third-party HTTP/LLM noise is
    # raised to WARNING.
    logging.getLogger("aginiti").setLevel(logging.INFO)
    if not verbose:
        for noisy in ("litellm", "LiteLLM", "httpx", "httpcore", "urllib3"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Output helpers -- every scan/attack run auto-saves findings.json +
# aginiti_assessment_report.md.
# ---------------------------------------------------------------------------
def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {path}")


def _new_run_dir(base_dir: Path) -> Path:
    """Creates and returns a fresh, timestamped subdirectory of `base_dir`
    for exactly one run's output files.

    Previously every `scan`/`attack`/`report` run wrote `findings.json`/
    `aginiti_assessment_report.{md,html}` directly into `--output-dir`, so
    a second run silently overwrote the first run's results with no trace
    they ever existed. Now each run gets its own directory, named
    `YYYY-MM-DD_HHMMSS` (UTC -- plain lexicographic sort order still
    matches chronological order despite the added hyphens, so sorting
    `base_dir`'s contents by name is the same as sorting by run time; sort
    descending, or by "date modified" in a file browser, to see the most
    recent run first). A numeric suffix is appended only on the rare
    same-second collision, so a run directory is never silently reused."""
    base_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
    run_dir = base_dir / stamp
    suffix = 2
    while run_dir.exists():
        run_dir = base_dir / f"{stamp}_{suffix}"
        suffix += 1
    run_dir.mkdir(parents=True)
    return run_dir


def _open_report(html_path: Path) -> None:
    """Best-effort: opens the just-written HTML report in the user's
    default browser. `webbrowser.open()` is the one stdlib call that
    already handles this across all three OSes with no branching here --
    `os.startfile` on Windows, `open` on macOS, `xdg-open`/a registered
    handler on Linux -- so nothing OS-specific lives in this function.

    Never raises: a headless/CI/Docker environment with no browser
    available (or no display at all) must not turn an otherwise-successful
    scan/attack/report run into a crash on its very last line -- the
    findings/report files are already written and their paths already
    printed above regardless of whether this succeeds."""
    try:
        opened = webbrowser.open(html_path.resolve().as_uri())
    except Exception:
        opened = False
    if not opened:
        print(f"(Could not auto-open {html_path} in a browser -- open it manually.)")


def _write_attack_outputs(
    output_dir: Path, report_name: str, attack: str, target: str,
    findings: list, started: float, embed_model: str, llm_provider: str,
    redact: bool, open_report: bool = True,
) -> None:
    """Shared output path for all 4 `aginiti attack` subcommands -- creates
    a fresh, timestamped subdirectory of `output_dir` (see `_new_run_dir`)
    and writes findings.json (run_metadata + raw findings),
    aginiti_assessment_report.md (the same OWASP-mapped generator every
    other report in this project uses), and its .html sibling -- a
    self-contained, styled version of the exact same report, meant to be
    opened straight in a browser rather than read as plain text -- into it,
    so a later run never overwrites an earlier one's results."""
    from aginiti.reporting import generate_html_report, generate_markdown_report

    run_dir = _new_run_dir(output_dir)
    report = {
        "run_metadata": {
            "attack": attack,
            "agent_url": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_queries": len(findings),
            "runtime_seconds": time.monotonic() - started,
            "embed_model": embed_model,
            "llm_provider": llm_provider,
        },
        "findings": [dataclasses.asdict(f) for f in findings],
    }
    _write_json(run_dir / "findings.json", report)
    # generate_markdown_report()/generate_html_report() both return the
    # rendered document STRING (and write it to output_path as a side
    # effect) -- not a Path, unlike generate_markdown_report_from_file()
    # below. Print the path we passed in, not the return value.
    md_path = run_dir / report_name
    generate_markdown_report(report, md_path, redact=redact)
    print(f"Wrote {md_path}")

    html_path = md_path.with_suffix(".html")
    generate_html_report(report, html_path, redact=redact)
    print(f"Wrote {html_path}")

    confirmed = sum(1 for f in findings if f.confirmed)
    print(f"\n{len(findings)} finding(s), {confirmed} confirmed.")

    if open_report:
        _open_report(html_path)


def _format_owasp_category(raw: str) -> str:
    """"LLM07:2025_system_prompt_leakage" -> "LLM07:2025 - System Prompt
    Leakage" -- matches the exact style aginiti/reporting/markdown_report.py's
    own _OWASP_MAPPING already hardcodes for DRA/MIA/SPE, so a campaign
    step's finding reads identically to a direct attack's."""
    code, _, rest = raw.partition("_")
    return f"{code} - {rest.replace('_', ' ').title()}"


def _operator_owasp_category(library, operator_id: str) -> Optional[str]:
    try:
        op = library.get(operator_id)
        effect = op.effects_success[0] if op.effects_success else None
    except Exception:
        return None
    return effect.owasp_llm_category if effect and effect.owasp_llm_category else None


def _collect_scan_findings(execution_log, library) -> list[dict]:
    """Translate a campaign's execution_log into LeakFinding-shaped dicts,
    so `aginiti scan` can reuse the exact same rich, severity-sorted
    generate_markdown_report() renderer `aginiti attack` already uses,
    instead of a separate, thinner hand-rolled summary.

    Deep-attack steps (IKEA/SECRET/MIA/SPE wrapped as an Operator) keep
    their own real LeakFinding objects (ExecutionResult.deep_attack_findings)
    verbatim -- full per-query probe/response/confidence/severity detail,
    identical to what `aginiti attack` produces for the same technique.
    Every other (cheap prompt-operator) step is synthesized into ONE
    finding -- confirmed steps as a real reportable finding (severity
    "high": a confirmed claim is by construction a genuine compromise, not
    a guess), everything else as a leak_type="none" non-finding, so the
    report's ASR/Non-Findings-Summary counts include every step the
    campaign actually ran, not just the deep-attack ones.
    """
    import dataclasses as _dc

    results: list[dict] = []
    for entry in execution_log:
        if entry.deep_attack_findings:
            results.extend(_dc.asdict(f) for f in entry.deep_attack_findings)
            continue

        owasp_raw = _operator_owasp_category(library, entry.operator_id)
        confirmed = entry.overall_success
        results.append({
            "attack_type": "CAMPAIGN",
            "tier_used": "black_box",
            "confidence": 0.75 if confirmed else 0.0,
            "confirmed": confirmed,
            "leaked_content": entry.raw_signal if confirmed else "",
            "probe_used": entry.prompt_sent,
            "trace_span_id": "",
            "recommendation": (
                f"Review the target's handling of this operator ({entry.operator_id})."
                if confirmed else ""
            ),
            "severity": "high" if confirmed else "low",
            "full_response": entry.raw_signal,
            "leak_type": "sensitive_data" if confirmed else "none",
            "reasoning": entry.reasoning,
            "owasp_override": _format_owasp_category(owasp_raw) if owasp_raw else None,
        })
    return results


def _write_scan_outputs(output_dir: Path, report_name: str, target: Optional[str], result, library,
                         started: float, open_report: bool = True) -> None:
    """`aginiti scan`'s output writer -- reuses generate_markdown_report()/
    generate_html_report() (the same OWASP-mapped, severity-sorted reports
    `aginiti attack` produces) over findings translated from the campaign's
    execution_log by `_collect_scan_findings`, rather than a separate,
    thinner format. Creates a fresh, timestamped subdirectory of
    `output_dir` (see `_new_run_dir`) so a later run never overwrites an
    earlier one's results."""
    from aginiti.reporting import generate_html_report, generate_markdown_report

    from aginiti.providers.llm import active_provider_name

    run_dir = _new_run_dir(output_dir)
    findings = _collect_scan_findings(result.execution_log, library)

    report = {
        "run_metadata": {
            "attack": "scan",
            "agent_url": target or "(in-memory demo agent)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_queries": result.prompts_used,
            "runtime_seconds": time.monotonic() - started,
            "embed_model": "",
            # The core judge/planner's own auto-detected provider -- a
            # campaign's deep-attack steps (if any) may use a separately
            # configured provider for their own reasoning, so this
            # specifically describes the judge, not necessarily every LLM
            # call this run made.
            "llm_provider": f"{active_provider_name()} (judge)",
        },
        "findings": findings,
        "decision_log": [dataclasses.asdict(d) for d in result.decision_log],
        "execution_log": [dataclasses.asdict(e) for e in result.execution_log],
    }
    _write_json(run_dir / "findings.json", report)

    md_path = run_dir / report_name
    generate_markdown_report(report, md_path)
    print(f"Wrote {md_path}")

    html_path = md_path.with_suffix(".html")
    generate_html_report(report, html_path)
    print(f"Wrote {html_path}")

    confirmed = sum(1 for f in findings if f.get("confirmed"))
    print(f"\n{len(findings)} step(s) evaluated, {confirmed} confirmed.")

    if open_report:
        _open_report(html_path)


# ---------------------------------------------------------------------------
# aginiti scan
# ---------------------------------------------------------------------------
def _cmd_scan(args: argparse.Namespace) -> None:
    from aginiti.core.campaign import run_campaign
    from aginiti.core.campaign_builder import CampaignBuildError, build_campaign

    if args.model:
        model, _ = _resolve_model(args.model)
        os.environ["IKEA_OPERATOR_LLM_PROVIDER"] = model
        os.environ["SECRET_OPERATOR_LLM_PROVIDER"] = model
        os.environ["MIA_OPERATOR_LLM_PROVIDER"] = model

    # Sets the SAME env vars deep_attack_operators.py's own _load_*_config()
    # functions read -- this only works because those now resolve fresh on
    # every deep_attack_operators() call (this module's own real,
    # confirmed-and-fixed bug: they used to be frozen module-level
    # constants, computed once, the first time anything imported that
    # module -- which happens via _build_parser()'s own TIER_CHOICES
    # import, BEFORE this function or its arguments even exist. Setting an
    # env var here used to be silently pointless for exactly that reason;
    # see deep_attack_operators.py's module docstring for the full
    # root-cause writeup). Always overrides, same precedence as --model
    # above, regardless of any pre-existing env var -- an explicit CLI flag
    # is the most explicit signal available.
    if args.deep_attack_queries is not None:
        os.environ["IKEA_OPERATOR_MAX_QUERIES"] = str(args.deep_attack_queries)
        os.environ["SECRET_OPERATOR_MAX_QUERIES"] = str(args.deep_attack_queries)
        os.environ["MIA_OPERATOR_N_PROBE_QUESTIONS"] = str(args.deep_attack_queries)

    # flush=True: without it, this can appear AFTER the attack's own
    # (auto-flushed, e.g. via logging) progress output when stdout is
    # redirected to a file/pipe rather than a TTY -- Python switches to
    # full block buffering in that case, so a plain print() can sit
    # buffered while other output flushes immediately, reordering what the
    # user actually sees despite this line executing first.
    print(_AUTH_BANNER, flush=True)
    started = time.monotonic()

    try:
        library, mission, agent = build_campaign(
            agent_url=args.target, tier=args.tier, attack_category=args.attack_category,
            budget=args.budget,
        )
    except CampaignBuildError as exc:
        raise SystemExit(str(exc)) from exc

    try:
        # stop_on_mission_success=False: run_campaign()'s own default
        # (True) is deliberate for the project's benchmark suite (stopping
        # the instant a mission is satisfied is how "prompts used to
        # success" is measured there) -- but for `aginiti scan`, the whole
        # point of the budget is to spend it finding as much as possible,
        # not to stop at the first confirmed finding. max_steps is raised
        # to match the budget (its own default, 25, otherwise caps a large
        # --budget's step count before the budget itself is actually
        # exhausted, on a library with enough eligible operators).
        result = run_campaign(mission, library, agent=agent,
                               stop_on_mission_success=False, max_steps=max(25, mission.budget))
        print(f"\nOutcome: {result.outcome} | steps: {result.steps_executed} | "
              f"prompts used: {result.prompts_used}/{mission.budget}")
        _write_scan_outputs(Path(args.output_dir), args.report, args.target, result, library, started,
                            open_report=not args.no_open_report)
    finally:
        if args.target and agent is not None:
            agent.endpoint.close()


# ---------------------------------------------------------------------------
# aginiti attack {ikea,secret,mia,spe}
# ---------------------------------------------------------------------------
def _cmd_attack_ikea(args: argparse.Namespace) -> None:
    from aginiti.attacks.dra.ikea import IKEAAttack

    model, key = _resolve_model(args.model)
    # flush=True: without it, this can appear AFTER the attack's own
    # (auto-flushed, e.g. via logging) progress output when stdout is
    # redirected to a file/pipe rather than a TTY -- Python switches to
    # full block buffering in that case, so a plain print() can sit
    # buffered while other output flushes immediately, reordering what the
    # user actually sees despite this line executing first.
    print(_AUTH_BANNER, flush=True)
    started = time.monotonic()
    attack = IKEAAttack(target_url=args.target, llm_provider=model, api_key=key)
    findings = attack.execute_black_box(topic=args.topic, max_queries=args.queries)
    _write_attack_outputs(
        Path(args.output_dir), args.report, "ikea", args.target, findings, started,
        embed_model="chromadb/all-MiniLM-L6-v2", llm_provider=model, redact=args.redact,
        open_report=not args.no_open_report,
    )


def _cmd_attack_secret(args: argparse.Namespace) -> None:
    from aginiti.attacks.dra.secret import SECRETAttack

    model, key = _resolve_model(args.model)
    if args.optimizer_model:
        optimizer_model, optimizer_key = _resolve_model(args.optimizer_model)
    else:
        optimizer_model, optimizer_key = _resolve_secret_optimizer(model, key)

    if args.corpus:
        corpus = [line.strip() for line in Path(args.corpus).read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        # SECRET requires a non-empty external_corpus (Global Exploration's
        # natural-text sampling pool) even against a target with no real
        # corpus of your own to supply -- these two generic, unrelated
        # sentences are the same placeholder this project's own scripts use.
        corpus = ["A sentence about something unrelated.", "Another unrelated sentence."]

    # flush=True: without it, this can appear AFTER the attack's own
    # (auto-flushed, e.g. via logging) progress output when stdout is
    # redirected to a file/pipe rather than a TTY -- Python switches to
    # full block buffering in that case, so a plain print() can sit
    # buffered while other output flushes immediately, reordering what the
    # user actually sees despite this line executing first.
    print(_AUTH_BANNER, flush=True)
    started = time.monotonic()
    attack = SECRETAttack(
        target_url=args.target, llm_provider=model, api_key=key,
        optimizer_llm_provider=optimizer_model, optimizer_api_key=optimizer_key,
        external_corpus=corpus, phase1_n_iter=args.phase1_iter, phase1_n_cand=args.phase1_cand,
    )
    findings = attack.execute_black_box(domain=args.domain, max_queries=args.queries)
    _write_attack_outputs(
        Path(args.output_dir), args.report, "secret", args.target, findings, started,
        embed_model="chromadb/all-MiniLM-L6-v2", llm_provider=model, redact=args.redact,
        open_report=not args.no_open_report,
    )


def _cmd_attack_mia(args: argparse.Namespace) -> None:
    from aginiti.attacks.mia.interrogation import InterrogationAttack

    model, key = _resolve_model(args.model)

    dataset = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    documents = dataset.get("documents")
    non_member_reference_docs = dataset.get("non_member_reference_docs")
    if not documents or not non_member_reference_docs:
        raise SystemExit(
            f"{args.dataset} must contain both a non-empty \"documents\" list (the candidates "
            "to test) and a non-empty \"non_member_reference_docs\" list (calibration "
            "documents known NOT to be in the target's knowledge base), each a list of "
            "{\"id\": ..., \"text\": ...} objects."
        )

    # flush=True: without it, this can appear AFTER the attack's own
    # (auto-flushed, e.g. via logging) progress output when stdout is
    # redirected to a file/pipe rather than a TTY -- Python switches to
    # full block buffering in that case, so a plain print() can sit
    # buffered while other output flushes immediately, reordering what the
    # user actually sees despite this line executing first.
    print(_AUTH_BANNER, flush=True)
    started = time.monotonic()
    attack = InterrogationAttack(
        target_url=args.target, llm_provider=model, api_key=key,
        non_member_reference_docs=non_member_reference_docs, n_probe_questions=args.probes,
    )
    findings = attack.execute_black_box(documents=documents)
    _write_attack_outputs(
        Path(args.output_dir), args.report, "mia", args.target, findings, started,
        embed_model="", llm_provider=model, redact=args.redact,
        open_report=not args.no_open_report,
    )


def _cmd_attack_spe(args: argparse.Namespace) -> None:
    from aginiti.attacks.spe.spe_llm import SPEAttack

    # SPE never raises on a missing classifier key -- it silently returns
    # confirmed=False for every probe, indistinguishable from a genuinely
    # clean target (see docs/USAGE.md's SPE gotcha). _resolve_model's own
    # SystemExit on "no key at all" is exactly the loud failure this needs;
    # never let this subcommand construct SPEAttack with no key resolved.
    model, key = _resolve_model(args.model)

    # flush=True: without it, this can appear AFTER the attack's own
    # (auto-flushed, e.g. via logging) progress output when stdout is
    # redirected to a file/pipe rather than a TTY -- Python switches to
    # full block buffering in that case, so a plain print() can sit
    # buffered while other output flushes immediately, reordering what the
    # user actually sees despite this line executing first.
    print(_AUTH_BANNER, flush=True)
    started = time.monotonic()
    attack = SPEAttack(target_url=args.target, classifier_llm_provider=model, classifier_api_key=key)
    findings = attack.execute_black_box()
    _write_attack_outputs(
        Path(args.output_dir), args.report, "spe", args.target, findings, started,
        embed_model="", llm_provider=model, redact=args.redact,
        open_report=not args.no_open_report,
    )


# ---------------------------------------------------------------------------
# aginiti report
# ---------------------------------------------------------------------------
def _cmd_report(args: argparse.Namespace) -> None:
    from aginiti.reporting import generate_html_report, generate_markdown_report

    # Read once, write both formats from the same in-memory report dict --
    # generate_markdown_report_from_file() would re-read the same file
    # internally for the .md side alone, an unnecessary second read now
    # that this also needs the parsed dict for the .html side.
    input_path = Path(args.input)
    report = json.loads(input_path.read_text(encoding="utf-8"))

    if args.output:
        md_path = Path(args.output)
    else:
        # Same default-naming convention generate_markdown_report_from_file()
        # itself uses: alongside the input, .md suffix (or _redacted.md).
        suffix = "_redacted.md" if args.redact else ".md"
        md_path = input_path.with_name(input_path.stem + suffix)

    generate_markdown_report(report, md_path, redact=args.redact)
    print(f"Wrote {md_path}")

    html_path = md_path.with_suffix(".html")
    generate_html_report(report, html_path, redact=args.redact)
    print(f"Wrote {html_path}")

    if not args.no_open_report:
        _open_report(html_path)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def _add_common_output_args(parser: argparse.ArgumentParser, default_report: str) -> None:
    parser.add_argument("--output-dir", default="results", help="Parent directory for this run's own timestamped results folder (findings.json/report inside it). Default: ./results")
    parser.add_argument("--report", default=default_report, help=f"Markdown report filename. Default: {default_report}")
    parser.add_argument("--redact", action="store_true", help="Also write a PII-redacted copy of the report.")
    parser.add_argument("--model", default=None, help="Attacker/judge LLM, e.g. openai/gpt-4o. Default: auto-detected from whichever *_API_KEY is set.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full LiteLLM/HTTP logs instead of the default clean output.")
    parser.add_argument("--no-open-report", action="store_true", help="Don't automatically open the HTML report in a browser when the run finishes.")


def _build_parser() -> argparse.ArgumentParser:
    from aginiti.core.campaign_builder import TIER_CHOICES
    from aginiti.core.graph.attack_category import ALL_CATEGORIES

    parser = argparse.ArgumentParser(prog="aginiti", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Use-case-driven adaptive campaign (--tier/--attack-category).")
    p_scan.add_argument("--target", required=True, help="Base URL of the target agent, e.g. http://localhost:8001")
    _tier_group = p_scan.add_mutually_exclusive_group()
    _tier_group.add_argument("--tier", default=None, choices=TIER_CHOICES, help="Coarse test tier. Default: full_assessment (no filter).")
    _tier_group.add_argument("--attack-category", nargs="+", default=None, metavar="CATEGORY", choices=sorted(ALL_CATEGORIES), help="One or more precise attack-methodology categories (union). See --list-attack-categories.")
    p_scan.add_argument("--list-attack-categories", action="store_true", help="Print every valid --attack-category value and exit.")
    p_scan.add_argument("--budget", type=int, default=None, help="How many techniques the campaign gets to try in total (breadth) -- NOT how deep any one deep-attack goes; see --deep-attack-queries for that.")
    p_scan.add_argument("--deep-attack-queries", type=int, default=None, help="Override IKEA/SECRET's own query budget and MIA's probe-question count for THIS scan (depth, not breadth -- default: 20/10/4). Same effect as setting IKEA_OPERATOR_MAX_QUERIES/SECRET_OPERATOR_MAX_QUERIES/MIA_OPERATOR_N_PROBE_QUESTIONS yourself.")
    _add_common_output_args(p_scan, "aginiti_assessment_report.md")
    p_scan.set_defaults(func=_cmd_scan)

    p_attack = sub.add_parser("attack", help="Run one standalone attack directly.")
    attack_sub = p_attack.add_subparsers(dest="technique", required=True)

    p_ikea = attack_sub.add_parser("ikea", help="Benign-query RAG knowledge extraction (ICLR 2026).")
    p_ikea.add_argument("--target", required=True)
    p_ikea.add_argument("--topic", required=True, help='Topic keyword for the target\'s knowledge base, e.g. "HR records".')
    p_ikea.add_argument("--queries", type=int, default=20, help="Query budget. Default: 20.")
    _add_common_output_args(p_ikea, "aginiti_assessment_report.md")
    p_ikea.set_defaults(func=_cmd_attack_ikea)

    p_secret = attack_sub.add_parser("secret", help="Jailbreak-optimized extraction attack (IEEE TIFS 2026).")
    p_secret.add_argument("--target", required=True)
    p_secret.add_argument("--domain", default="the target's knowledge base", help='Domain description for the classifier, e.g. "HR records".')
    p_secret.add_argument("--queries", type=int, default=20, help="Phase 2 (extraction) query budget. Default: 20.")
    p_secret.add_argument("--phase1-iter", type=int, default=3, help="Phase 1 jailbreak-calibration iterations. Default: 3.")
    p_secret.add_argument("--phase1-cand", type=int, default=2, help="Phase 1 candidates drafted per iteration. Default: 2.")
    p_secret.add_argument("--corpus", default=None, help="Path to a text file, one sentence per line, for Global Exploration. Default: a small generic placeholder.")
    p_secret.add_argument("--optimizer-model", default=None, help="Override the Phase 1 optimizer's model (default: auto-prefers Groq -- see docs).")
    _add_common_output_args(p_secret, "aginiti_assessment_report.md")
    p_secret.set_defaults(func=_cmd_attack_secret)

    p_mia = attack_sub.add_parser("mia", help="Membership inference against specific documents you hold (ACM CCS 2025).")
    p_mia.add_argument("--target", required=True)
    p_mia.add_argument("--dataset", required=True, help='JSON file: {"documents": [{"id","text"}...], "non_member_reference_docs": [{"id","text"}...]}')
    p_mia.add_argument("--probes", type=int, default=10, help="Probe questions per document. Default: 10.")
    _add_common_output_args(p_mia, "aginiti_assessment_report.md")
    p_mia.set_defaults(func=_cmd_attack_mia)

    p_spe = attack_sub.add_parser("spe", help="System prompt extraction, 3 fixed probes (ICLR 2026).")
    p_spe.add_argument("--target", required=True)
    _add_common_output_args(p_spe, "aginiti_assessment_report.md")
    p_spe.set_defaults(func=_cmd_attack_spe)

    p_report = sub.add_parser("report", help="Convert a saved findings.json into a Markdown report.")
    p_report.add_argument("--input", required=True, help="Path to a findings.json produced by scan/attack.")
    p_report.add_argument("--output", default=None, help="Output .md path. Default: alongside --input.")
    p_report.add_argument("--redact", action="store_true", help="Write a PII-redacted report instead.")
    p_report.add_argument("--no-open-report", action="store_true", help="Don't automatically open the HTML report in a browser.")
    p_report.set_defaults(func=_cmd_report)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    from dotenv import load_dotenv
    load_dotenv()

    parser = _build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "list_attack_categories", False):
        from aginiti.core.campaign_builder import print_attack_categories
        print_attack_categories()
        return

    _configure_logging(getattr(args, "verbose", False))

    try:
        args.func(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
