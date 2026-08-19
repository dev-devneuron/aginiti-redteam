"""Project-wide regression guard, added 2026-08-12 during a full
architecture review: a judge-path operator (extractor is None) whose
effect has neither a per-effect ClaimEffect.description NOR an entry in
observation_adapter.KEY_DESCRIPTIONS silently degrades to the bare claim
key as the judge's only signal for what that effect means (see
_build_candidates()'s `effect.description or KEY_DESCRIPTIONS.get(effect.key,
effect.key)` fallback chain) -- readable-ish for a key like
`system_prompt_disclosed`, genuinely lossy for anything less self-
explanatory, and previously ONLY guarded per-pack (data_exposure.py,
injecagent) rather than for the whole library at once.

An operator with a deterministic `extractor` is exempt: extractor-based
operators never call the judge or read KEY_DESCRIPTIONS at all (see
observation_adapter.ObservationAdapter.execute()'s branching), so a
missing description there is genuinely inert, not a bug -- asserting on
it would create false-positive noise on operators like every
anythingllm_multitool_definitions.py / dvaa's MCP-registration operator
that deliberately bypass the judge on purpose.

Every builder function below needs a real, harmless placeholder argument
only (canary strings, listener URLs, file paths) -- none of this touches
a live target or LLM."""
from aginiti.adapter.observation_adapter import KEY_DESCRIPTIONS
from aginiti.operators.anythingllm_automatic_definitions import build_anythingllm_automatic_library
from aginiti.operators.anythingllm_definitions import build_anythingllm_library
from aginiti.operators.anythingllm_markdown_exfil_definitions import build_anythingllm_markdown_exfil_library
from aginiti.operators.anythingllm_multitool_definitions import build_anythingllm_multitool_library
from aginiti.operators.data_exposure import data_exposure_operators
from aginiti.operators.definitions import build_library
from aginiti.operators.dvaa_consensus_definitions import build_dvaa_consensus_library
from aginiti.operators.dvaa_definitions import build_dvaa_library
from aginiti.operators.dvla_definitions import build_dvla_library
from aginiti.operators.encoding_variants import build_encoding_evasion_operators
from aginiti.operators.mcp_filesystem_definitions import build_filesystem_mcp_library


def _all_judge_path_libraries():
    return {
        "mock": build_library(),
        "data_exposure": data_exposure_operators(),
        "anythingllm_rag": build_anythingllm_library("CANARY-1"),
        "anythingllm_automatic": build_anythingllm_automatic_library("CANARY-2", "http://listener.example"),
        "anythingllm_markdown": build_anythingllm_markdown_exfil_library("CANARY-3", "http://listener.example"),
        "anythingllm_multitool": build_anythingllm_multitool_library("CANARY-4", "http://listener.example"),
        "dvaa": build_dvaa_library(),
        "dvaa_consensus": build_dvaa_consensus_library(),
        "dvla": build_dvla_library(),
        "encoding_variants": build_encoding_evasion_operators(),
        "mcp_filesystem": build_filesystem_mcp_library(
            "/allowed", "/allowed/in.txt", "harmless content", "/etc/passwd", "SECRET-MARKER-XYZ",
        ),
    }


def test_every_judge_path_effect_has_a_real_description_somewhere():
    missing = []
    for pack_name, library in _all_judge_path_libraries().items():
        for op in library:
            if op.extractor is not None:
                continue  # deterministic path -- KEY_DESCRIPTIONS/description is never consulted
            for effect in (*op.effects_success, *op.effects_failure):
                has_description = bool(effect.description) or effect.key in KEY_DESCRIPTIONS
                if not has_description:
                    missing.append(f"{pack_name}:{op.id}:{effect.key}")
    assert not missing, (
        f"{len(missing)} judge-path effect(s) have neither a ClaimEffect.description nor a "
        f"KEY_DESCRIPTIONS entry, so the judge only ever sees the bare key as their meaning: "
        f"{missing}"
    )
