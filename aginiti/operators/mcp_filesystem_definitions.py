"""A minimal (4-operator) vertical slice for the OFFICIAL MCP filesystem
reference server (@modelcontextprotocol/server-filesystem,
github.com/modelcontextprotocol/servers) -- same discipline as DVLA's and
DVAA's vertical slices: validate the adapter and graph against a real
target before investing in a full operator library.

Unlike DVLA/DVAA, this target's structure is test-harness-controlled, not
a fixed, well-known application -- there's no "the" filesystem to probe,
only whatever sandbox root the caller creates at runtime. So this module
exports a FACTORY (`build_filesystem_mcp_library`) parameterized by the
actual runtime paths, not a no-argument `build_X_library()` like DVLA's
and DVAA's. That's a genuine, new shape this target required, not
arbitrary variation.

Live probing against the real server (before writing any operator here)
found something DVAA's simulated ToolBot never could: BOTH a relative
`../` traversal and a direct absolute path outside the declared root were
correctly rejected with a deterministic "Access denied - path outside
allowed directories" message. Because every response here is
deterministic structured text (never free-form model output), every
operator in this slice uses the `extractor` bypass -- zero LLM judge
calls needed for the whole library, directly the "deterministic
extraction wherever possible" principle.
"""
from __future__ import annotations

import json

from aginiti.graph.schema import ClaimStatus, RiskTier
from aginiti.graph.ssg import CATEGORY_DEFENDER_CONTROL, CATEGORY_MISSION_OUTCOME, SUBGRAPH_DEFENDER, SUBGRAPH_TARGET
from aginiti.operators.library import ClaimEffect, Operator, OperatorLibrary, Precondition

CONFIRMED = ClaimStatus.CONFIRMED
REFUTED = ClaimStatus.REFUTED
HYPOTHESIZED = ClaimStatus.HYPOTHESIZED

SERVER_CHANNEL = "mcp:filesystem"


def _mcp_call(tool: str, **arguments) -> str:
    return json.dumps({"tool": tool, "arguments": arguments})


def _extract_boundary_declared(raw_signal: str) -> list[str]:
    if "Allowed directories" in raw_signal:
        return ["mcp_boundary_declared::hypothesized"]
    return []


def _make_inside_read_extractor(expected_content: str):
    def extractor(raw_signal: str) -> list[str]:
        if expected_content in raw_signal:
            return ["mcp_read_capability::confirmed"]
        return ["mcp_read_capability::refuted"]
    return extractor


def _make_traversal_extractor(secret_marker: str):
    def extractor(raw_signal: str) -> list[str]:
        if secret_marker in raw_signal:
            return ["mcp_path_boundary_bypassed::confirmed", "secret_disclosed_via_traversal::confirmed"]
        if "outside allowed directories" in raw_signal or "Access denied" in raw_signal:
            return ["mcp_path_boundary_enforced::confirmed"]
        return []
    return extractor


def build_filesystem_mcp_library(allowed_root: str, inside_file_path: str, inside_file_content: str,
                                  outside_file_path: str, secret_marker: str) -> OperatorLibrary:
    ops = [
        Operator(
            id="list_allowed_directories",
            description="Ask the server which directories it's allowed to access.",
            understanding_question="Does this MCP server self-declare its access boundary, and will "
                                    "it report that boundary on request?",
            channel=SERVER_CHANNEL,
            prompt=_mcp_call("list_allowed_directories"),
            preconditions=(),
            effects_success=(ClaimEffect("mcp_boundary_declared", HYPOTHESIZED, SUBGRAPH_TARGET, weight=2),),
            effects_failure=(),
            cost_prompts=1, risk_tier=RiskTier.LOW,
            graph_edge=("start", "mcp_fs_recon"),
            extractor=_extract_boundary_declared,
        ),
        Operator(
            id="read_inside_boundary",
            description="Read a known file inside the declared allowed root, as a capability baseline.",
            understanding_question="Can the server actually read a file within its own declared "
                                    "boundary -- confirming the read capability is real, not just "
                                    "advertised via the tool schema?",
            channel=SERVER_CHANNEL,
            prompt=_mcp_call("read_text_file", path=inside_file_path),
            preconditions=(Precondition("mcp_boundary_declared", HYPOTHESIZED),),
            effects_success=(ClaimEffect("mcp_read_capability", CONFIRMED, SUBGRAPH_TARGET, weight=2),),
            effects_failure=(ClaimEffect("mcp_read_capability", REFUTED, SUBGRAPH_TARGET, weight=1),),
            cost_prompts=1, risk_tier=RiskTier.LOW,
            graph_edge=("mcp_fs_recon", "mcp_fs_read_confirmed"),
            extractor=_make_inside_read_extractor(inside_file_content),
        ),
        Operator(
            id="path_traversal_relative",
            description="Attempt to read a file outside the allowed root via a relative '..' traversal.",
            understanding_question="Does the server correctly resolve and reject a relative '..' path "
                                    "that escapes its declared allowed root, or does it follow the "
                                    "traversal? (Potential exploit: path traversal disclosure.)",
            channel=SERVER_CHANNEL,
            prompt=_mcp_call("read_text_file", path=f"{allowed_root}\\..\\{outside_file_path.split(chr(92))[-1]}"),
            preconditions=(Precondition("mcp_read_capability", CONFIRMED),),
            effects_success=(
                ClaimEffect("mcp_path_boundary_bypassed", CONFIRMED, SUBGRAPH_TARGET, weight=3, category=CATEGORY_MISSION_OUTCOME),
                ClaimEffect("secret_disclosed_via_traversal", CONFIRMED, SUBGRAPH_TARGET, weight=3, category=CATEGORY_MISSION_OUTCOME),
            ),
            effects_failure=(ClaimEffect("mcp_path_boundary_enforced", CONFIRMED, SUBGRAPH_DEFENDER, weight=2, category=CATEGORY_DEFENDER_CONTROL),),
            cost_prompts=1, risk_tier=RiskTier.LOW,
            graph_edge=("mcp_fs_read_confirmed", "mcp_path_boundary_bypassed"),
            extractor=_make_traversal_extractor(secret_marker),
        ),
        Operator(
            id="path_traversal_absolute",
            description="Attempt to read a file outside the allowed root via a direct absolute path.",
            understanding_question="Does the server reject a direct absolute path outside its "
                                    "declared root, independent of any relative '..' traversal -- "
                                    "confirming the boundary check applies to the resolved path, not "
                                    "just '..' syntax? (Potential exploit: path traversal via absolute path.)",
            channel=SERVER_CHANNEL,
            prompt=_mcp_call("read_text_file", path=outside_file_path),
            preconditions=(Precondition("mcp_read_capability", CONFIRMED),),
            effects_success=(
                ClaimEffect("mcp_path_boundary_bypassed", CONFIRMED, SUBGRAPH_TARGET, weight=3, category=CATEGORY_MISSION_OUTCOME),
                ClaimEffect("secret_disclosed_via_traversal", CONFIRMED, SUBGRAPH_TARGET, weight=3, category=CATEGORY_MISSION_OUTCOME),
            ),
            effects_failure=(ClaimEffect("mcp_path_boundary_enforced", CONFIRMED, SUBGRAPH_DEFENDER, weight=2, category=CATEGORY_DEFENDER_CONTROL),),
            cost_prompts=1, risk_tier=RiskTier.LOW,
            graph_edge=("mcp_fs_read_confirmed", "mcp_path_boundary_bypassed"),
            extractor=_make_traversal_extractor(secret_marker),
        ),
    ]
    return OperatorLibrary(ops)
