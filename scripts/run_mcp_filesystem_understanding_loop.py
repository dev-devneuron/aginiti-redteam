"""Runs the understanding loop live against the OFFICIAL MCP filesystem
reference server (@modelcontextprotocol/server-filesystem,
github.com/modelcontextprotocol/servers) -- the first real target reached
over genuine MCP stdio transport with a real initialize handshake, not a
simulated HTTP JSON-RPC stand-in.

Setup (one-time):
    npm install @modelcontextprotocol/server-filesystem
Then point SERVER_ENTRY below at
    <install dir>/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js
"""
from __future__ import annotations

import os
import shutil
import tempfile

from aginiti.adapters.mcp_stdio_adapter import McpStdioAdapter
from aginiti.graph.persistence import save_ssg
from aginiti.graph.target_profile import build_target_profile, render_markdown
from aginiti.operators.mcp_filesystem_definitions import build_filesystem_mcp_library
from aginiti.scenarios import filesystem_mcp_mission
from aginiti.understanding_loop import run_understanding_loop

TARGET_NAME = "MCP Filesystem Server (official reference implementation)"
SERVER_ENTRY = os.environ.get(
    "MCP_FS_SERVER_ENTRY",
    # 2026-08-12: moved off C:\...\Temp\claude\... onto E:\Aginiti-Extended\targets
    # -- this project's own permanent home for the target apps it depends on.
    r"E:\Aginiti-Extended\targets\mcp-fs-test\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js",
)
SECRET_MARKER = "OUTSIDE_MARKER_XYZ_42"


def main() -> None:
    sandbox_root = tempfile.mkdtemp(prefix="aginiti_mcp_fs_")
    inside_path = os.path.join(sandbox_root, "secret.txt")
    inside_content = "top secret sandbox content"
    with open(inside_path, "w", encoding="utf-8") as f:
        f.write(inside_content)

    outside_path = os.path.join(os.path.dirname(sandbox_root), "aginiti_mcp_outside_secret.txt")
    with open(outside_path, "w", encoding="utf-8") as f:
        f.write(f"{SECRET_MARKER} -- should NOT be reachable from inside the sandbox root")

    library = build_filesystem_mcp_library(
        allowed_root=sandbox_root, inside_file_path=inside_path, inside_file_content=inside_content,
        outside_file_path=outside_path, secret_marker=SECRET_MARKER,
    )
    mission = filesystem_mcp_mission()

    print(f"=== running the understanding loop live against {TARGET_NAME} ===")
    print(f"sandbox root: {sandbox_root}")
    agent = McpStdioAdapter(server_name="filesystem", command="node", args=[SERVER_ENTRY, sandbox_root],
                             secret_marker=SECRET_MARKER)
    try:
        result = run_understanding_loop(mission, library, agent=agent, target_name=TARGET_NAME,
                                         max_rounds=len(library))
        for r in result.rounds:
            gap_summary = ", ".join(f"[{i.category.value}] {i.statement[:70]}" for i in r.new_insights) or "(none)"
            print(f"round {r.round_num}: chose {r.chosen_operator_id} "
                  f"(success={r.execution.overall_success}) -- new insights: {gap_summary}")

        print(f"\nprompts_used={result.prompts_used} rounds={len(result.rounds)} "
              f"ground_truth_mission_achieved={agent.ground_truth_mission_achieved()}")

        os.makedirs("runs", exist_ok=True)
        graph_path = os.path.join("runs", "mcp_filesystem_ssg.json")
        save_ssg(result.ssg, graph_path)
        print(f"saved graph to {graph_path}")

        profile = build_target_profile(result.ssg, library, mission, target_name=TARGET_NAME,
                                        prompts_used=result.prompts_used)
        markdown = render_markdown(profile)
        profile_path = os.path.join("runs", "mcp_filesystem_target_profile.md")
        with open(profile_path, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"wrote {profile_path}\n")
        print(markdown)
    finally:
        agent.close()
        shutil.rmtree(sandbox_root, ignore_errors=True)
        if os.path.exists(outside_path):
            os.remove(outside_path)


if __name__ == "__main__":
    main()
