"""Sets up a garak-compatible target for competitor comparison, per the
2026-08-09 production-readiness/competitor-comparison directive: "prepare
for the next exp ... we'll do Competitor-level comparison ... on it."

Creates ONE hardened AnythingLLM workspace through the SAME gateway
(localhost:3002) Aginiti's own adapter uses -- same HARDENED_PROMPT, same
document-sanitization/output-redaction/service-account-tier/human-
approval/adaptive-lockout controls from aginiti/target_hardening/ -- so a
garak run and an Aginiti run face an identical target, not two different
ones. Prints the workspace slug and writes garak_rest_generator.json
(the REST generator config garak needs) pointed at that workspace's real
chat endpoint.

SCOPING CAVEAT, stated here because it matters for a fair comparison, not
buried in a report afterward: garak's RestGenerator is a plain text-in/
text-out interface. It has no concept of tool calls or network egress, so
it can only ever probe the L0 (model behavior) / L1 (does the model
comply with text found in context) layer of this project's own L0-L5
taxonomy (aginiti/graph/security_boundary.py) -- never the L2-L5
tool-invocation/exfiltration mechanisms Aginiti's own AnythingLLM chains
also test. Using chatMode="chat" (not "automatic") here reflects that
honestly, rather than configuring automatic mode and pretending garak can
assess something it structurally cannot observe. A fair headline
comparison must be scoped to "who complies with the same class of
attack garak can actually see," not "who wins overall" -- Aginiti's own
multi-step/tool-invocation findings are simply out of garak's reach by
design, not because Aginiti's target was made easier for it."""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests

from hardened_target_v2_config import HARDENED_PROMPT_V2, HARDENED_WORKSPACE_SETTINGS_V2  # noqa: E402

GATEWAY_BASE_URL = "http://localhost:3002"
GATEWAY_KEY = "gw-full-admin-key"
CONFIG_OUT_PATH = os.path.join(os.path.dirname(__file__), "garak_rest_generator.json")


def create_garak_workspace(name: str | None = None) -> str:
    name = name or f"garak-compare-{int(time.time())}"
    resp = requests.post(
        f"{GATEWAY_BASE_URL}/api/v1/workspace/new",
        headers={"Authorization": f"Bearer {GATEWAY_KEY}", "Content-Type": "application/json"},
        json={"name": name, "chatMode": "chat", "openAiPrompt": HARDENED_PROMPT_V2},
        timeout=30)
    resp.raise_for_status()
    slug = resp.json()["workspace"]["slug"]
    resp2 = requests.post(
        f"{GATEWAY_BASE_URL}/api/v1/workspace/{slug}/update",
        headers={"Authorization": f"Bearer {GATEWAY_KEY}", "Content-Type": "application/json"},
        json={"chatMode": "chat", "openAiPrompt": HARDENED_PROMPT_V2, **HARDENED_WORKSPACE_SETTINGS_V2}, timeout=30)
    resp2.raise_for_status()
    return slug


def write_generator_config(slug: str) -> str:
    config = {
        "rest": {
            "RestGenerator": {
                "name": "aginiti-hardened-anythingllm-via-gateway",
                "uri": f"{GATEWAY_BASE_URL}/api/v1/workspace/{slug}/chat",
                "method": "post",
                "headers": {
                    "Authorization": f"Bearer {GATEWAY_KEY}",
                    "Content-Type": "application/json",
                },
                "req_template_json_object": {
                    "message": "$INPUT",
                    "mode": "chat",
                },
                "response_json": True,
                "response_json_field": "textResponse",
            }
        }
    }
    with open(CONFIG_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    return CONFIG_OUT_PATH


def main():
    slug = create_garak_workspace()
    path = write_generator_config(slug)
    print(f"Workspace created: {slug}")
    print(f"Generator config written: {path}")
    print(f"\nSmoke test: garak --model_type rest -G {path} --probes test.Test")
    return slug, path


if __name__ == "__main__":
    main()
