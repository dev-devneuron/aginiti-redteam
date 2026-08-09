"""A real Flask reverse proxy that sits in front of the live AnythingLLM
server, enforcing every control in policy.py that can only be enforced at
this layer (see this package's __init__.py for why). Callers (Aginiti's
existing, UNCHANGED AnythingLLMAdapter) point `base_url` at this gateway
and `api_key` at a GATEWAY-issued key (policy.GATEWAY_KEYS) instead of
AnythingLLM's own admin key -- the gateway holds the real admin key
internally and substitutes it on every forwarded request, so a "chat_only"
caller never sees it. Reuses the exact `Authorization: Bearer <key>` header
AnythingLLMAdapter already sends, so no adapter code changes are needed --
only different constructor arguments.

Run standalone: `python -m aginiti.target_hardening.gateway_server`
(reads ANYTHINGLLM_BASE_URL, ANYTHINGLLM_ADMIN_KEY, GATEWAY_PORT from the
environment, with the live values used throughout this project as
defaults)."""
from __future__ import annotations

import json
import os
import re
import time

import requests
from flask import Flask, Response, request

from aginiti.target_hardening.policy import (
    SuspicionTracker,
    check_gateway_key,
    check_url_allowed,
    required_capability,
    requires_approval,
    scan_and_redact_output,
    scan_and_sanitize_document,
)

TARGET_BASE_URL = os.environ.get("ANYTHINGLLM_BASE_URL", "http://localhost:3001")
ADMIN_KEY = os.environ.get("ANYTHINGLLM_ADMIN_KEY", "5YAK747-MJ64GZW-HTSYBY7-HBF1E2A")
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "3002"))
AUDIT_LOG_PATH = os.environ.get(
    "GATEWAY_AUDIT_LOG",
    r"C:\Users\Omer\AppData\Local\Temp\claude\E--GAIS\06641ac5-f731-4953-a632-5e6f756984e9"
    r"\scratchpad\gateway_audit.log",
)

app = Flask(__name__)
_suspicion = SuspicionTracker()  # module-level: shared across every request this process handles
_CHAT_PATH_RE = re.compile(r"^/api/v1/workspace/([^/]+)/chat$")


def _workspace_from_request() -> str | None:
    """Best-effort workspace identification across the 3 routes that carry
    one -- None (no enforcement) for anything else, e.g. workspace
    creation itself, which has no suspicion history to check yet."""
    path = "/" + request.path.lstrip("/")
    m = _CHAT_PATH_RE.match(path)
    if m:
        return m.group(1)
    if path == "/api/v1/document/upload":
        return request.form.get("addToWorkspaces")
    if path == "/api/v1/document/upload-link":
        body = request.get_json(force=True, silent=True) or {}
        return body.get("addToWorkspaces")
    return None


def _audit(event: dict) -> None:
    event["ts"] = time.time()
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def _extract_gateway_key() -> str | None:
    auth = request.headers.get("Authorization", "")
    return auth.split(" ", 1)[1] if auth.startswith("Bearer ") else None


def _forward_headers(drop_content_type: bool = False) -> dict:
    # Strip the caller's gateway-key Authorization header and substitute the
    # REAL AnythingLLM admin key -- the caller (a "chat_only" service
    # account) never sees or needs it. `drop_content_type` is required
    # whenever this gateway builds a NEW request body (e.g. re-encoding a
    # multipart upload after sanitizing it) -- forwarding the caller's
    # ORIGINAL multipart boundary alongside a body `requests` re-encodes
    # with its OWN new boundary is a real bug this surfaced live: the
    # mismatched boundary made AnythingLLM's own upload parser fail with
    # "Unexpected end of form". Letting `requests` set a fresh
    # Content-Type for the body it actually sends fixes it.
    drop = {"host", "content-length", "authorization"}
    if drop_content_type:
        drop.add("content-type")
    headers = {k: v for k, v in request.headers.items() if k.lower() not in drop}
    headers["Authorization"] = f"Bearer {ADMIN_KEY}"
    return headers


@app.before_request
def _enforce_gateway_key_and_approval():
    path = "/" + request.path.lstrip("/")
    gateway_key = _extract_gateway_key()
    ok, reason = check_gateway_key(gateway_key, path)
    if not ok:
        _audit({"event": "denied_service_account_tier", "path": path, "reason": reason})
        return Response(json.dumps({"error": reason}), status=403, mimetype="application/json")
    if requires_approval(path):
        _audit({"event": "denied_no_human_approval", "path": path})
        return Response(
            json.dumps({"error": "This action requires human approval, which is not available "
                                  "in this automated context. Denied by policy."}),
            status=403, mimetype="application/json")

    # Adaptive defense (2026-08-09) -- see policy.SuspicionTracker's own
    # docstring. Checked AFTER the static tier/approval gates (those never
    # depend on history), BEFORE the route handler runs.
    workspace = _workspace_from_request()
    if workspace is not None:
        if _suspicion.is_locked_out(workspace):
            _audit({"event": "denied_locked_out", "path": path, "workspace": workspace,
                    "suspicion_count": _suspicion.count(workspace)})
            return Response(
                json.dumps({"error": f"Workspace locked out after {_suspicion.count(workspace)} "
                                      "flagged events -- denied by adaptive defense policy."}),
                status=403, mimetype="application/json")
        capability = required_capability(path)
        if capability == "upload_document" and _suspicion.is_escalated(workspace):
            # Real bug found live (2026-08-09): once escalated, this branch
            # short-circuits BEFORE the route handler runs -- which is
            # exactly where note_suspicious() used to live, so a workspace
            # that kept probing after escalation got stuck at the
            # escalation count forever and could never reach lockout.
            # Fixed the way a real production system would: CONTINUING to
            # probe a denied action after a warning is itself an
            # escalating signal, so this denial also counts.
            count = _suspicion.note_suspicious(workspace)
            _audit({"event": "denied_escalated_document_action", "path": path, "workspace": workspace,
                    "suspicion_count": count})
            return Response(
                json.dumps({"error": "This workspace has repeated flagged activity -- further document/tool "
                                      "actions are suspended pending review. Chat remains available."}),
                status=403, mimetype="application/json")
    return None  # continue to the matched route


@app.route("/api/v1/document/upload", methods=["POST"])
def document_upload():
    """Real document trust labeling / retrieval filtering: the uploaded
    file's text content is sanitized (policy.scan_and_sanitize_document)
    BEFORE being forwarded to the real AnythingLLM upload endpoint -- what
    actually gets ingested and embedded is the sanitized version, not the
    raw upload."""
    uploaded = request.files.get("file")
    if uploaded is None:
        return Response(json.dumps({"error": "no file field"}), status=400,
                         mimetype="application/json")
    raw_text = uploaded.read().decode("utf-8", errors="replace")
    scan = scan_and_sanitize_document(raw_text)
    if scan.was_flagged:
        workspace = request.form.get("addToWorkspaces")
        _audit({"event": "document_sanitized", "filename": uploaded.filename,
                "flagged_sentences": scan.flagged_sentences,
                "suspicion_count": _suspicion.note_suspicious(workspace) if workspace else None})
    resp = requests.post(
        f"{TARGET_BASE_URL}/api/v1/document/upload",
        headers=_forward_headers(drop_content_type=True),
        files={"file": (uploaded.filename, scan.sanitized_text.encode("utf-8"), "text/plain")},
        data=request.form.to_dict(),
        timeout=60,
    )
    return Response(resp.content, status=resp.status_code, content_type=resp.headers.get("Content-Type"))


@app.route("/api/v1/document/upload-link", methods=["POST"])
def document_upload_link():
    """Tool-argument / URL validation for the one document-ingestion path
    that reaches AnythingLLM directly from Aginiti's adapter (the agent's
    OWN web-scraping tool calls are covered server-side, in the live
    collector's urlPolicy.js patch instead -- see this package's __init__).
    """
    body = request.get_json(force=True, silent=True) or {}
    link = body.get("link", "")
    allowed, reason = check_url_allowed(link)
    if not allowed:
        workspace = body.get("addToWorkspaces")
        _audit({"event": "upload_link_blocked", "link": link, "reason": reason,
                "suspicion_count": _suspicion.note_suspicious(workspace) if workspace else None})
        return Response(
            json.dumps({"url": link, "success": False,
                        "reason": f"Blocked by egress policy: {reason}", "documents": []}),
            status=200, mimetype="application/json")
    resp = requests.post(f"{TARGET_BASE_URL}/api/v1/document/upload-link",
                          headers=_forward_headers(), json=body, timeout=60)
    return Response(resp.content, status=resp.status_code, content_type=resp.headers.get("Content-Type"))


@app.route("/api/v1/workspace/<slug>/chat", methods=["POST"])
def workspace_chat(slug: str):
    """Output filtering / secret redaction on the way OUT: scans
    AnythingLLM's real response for secret-shaped patterns and redacts
    them before returning to the caller, while preserving the raw
    pre-redaction text in the gateway's own audit log -- see policy.py's
    scan_and_redact_output docstring for why that distinction matters."""
    body = request.get_json(force=True, silent=True) or {}
    resp = requests.post(f"{TARGET_BASE_URL}/api/v1/workspace/{slug}/chat",
                          headers=_forward_headers(), json=body, timeout=180)
    if resp.status_code != 200:
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get("Content-Type"))
    try:
        payload = resp.json()
    except ValueError:
        return Response(resp.content, status=resp.status_code, content_type=resp.headers.get("Content-Type"))

    text = payload.get("textResponse") or ""
    scan = scan_and_redact_output(text)
    if scan.would_have_leaked:
        _audit({"event": "output_redacted", "workspace": slug, "raw_text": scan.raw_text,
                "secrets_found": scan.secrets_found, "would_have_leaked": True,
                "suspicion_count": _suspicion.note_suspicious(slug)})
        payload["textResponse"] = scan.redacted_text
        payload["_gateway_redacted"] = True
    return Response(json.dumps(payload), status=200, mimetype="application/json")


@app.route("/<path:anything>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def passthrough(anything: str):
    """Everything not specifically intercepted above (workspace creation,
    system settings, chats history, etc.) is forwarded unmodified -- the
    gateway is additive hardening on specific real attack surfaces, not a
    reimplementation of AnythingLLM's whole API."""
    url = f"{TARGET_BASE_URL}/{anything}"
    resp = requests.request(
        method=request.method, url=url, headers=_forward_headers(),
        params=request.args, data=request.get_data(), timeout=60,
    )
    return Response(resp.content, status=resp.status_code, content_type=resp.headers.get("Content-Type"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=GATEWAY_PORT)
