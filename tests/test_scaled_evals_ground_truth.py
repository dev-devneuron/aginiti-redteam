"""Offline, deterministic tests for aginiti/adapters/scaled_evals_ground_truth.py
-- the verbatim-window index + RBAC out-of-scope check used by the
healthcare_agent/hardened_agent adapters (experiments/exp21_*.py). No
network, no LLM calls."""
from aginiti.adapters.scaled_evals_ground_truth import (
    DocRef,
    VerbatimDisclosureIndex,
    is_out_of_scope_for_persona,
)

_LEGAL_DOC = {
    "id": "cuad_0001",
    "source": "cuad",
    "ops_visible": False,
    "document_text": (
        "This agreement shall terminate automatically upon thirty days written notice by "
        "either party to the other party at the address specified in section twelve below "
        "unless renewed in writing prior to the expiration of the initial term."
    ),
}
_SUPPORT_DOC = {
    "id": "cfpb_0001",
    "source": "cfpb",
    "ops_visible": True,
    "document_text": (
        "I contacted the company multiple times about an incorrect charge on my account and "
        "each representative gave me a different explanation for why the fee had been applied "
        "without any prior notice being sent to me in writing or by email."
    ),
}


def _build_index(window: int = 8) -> VerbatimDisclosureIndex:
    idx = VerbatimDisclosureIndex(window=window)
    idx.add_records([_LEGAL_DOC, _SUPPORT_DOC])
    return idx


def test_exact_verbatim_window_is_detected():
    idx = _build_index()
    excerpt = "This agreement shall terminate automatically upon thirty days written notice"
    hit = idx.check(f"Sure, here's what I found: {excerpt} -- hope that helps!")
    assert hit is not None
    assert hit.doc_id == "cuad_0001"
    assert hit.source == "cuad"


def test_unrelated_text_is_not_a_false_positive():
    idx = _build_index()
    hit = idx.check("The weather today is sunny with a light breeze from the northwest.")
    assert hit is None


def test_short_text_below_window_never_matches():
    idx = _build_index(window=8)
    hit = idx.check("too short")
    assert hit is None


def test_case_and_punctuation_insensitive_match():
    idx = _build_index()
    excerpt = "THIS AGREEMENT SHALL TERMINATE AUTOMATICALLY UPON THIRTY DAYS, WRITTEN NOTICE!!"
    hit = idx.check(excerpt)
    assert hit is not None
    assert hit.doc_id == "cuad_0001"


def test_from_json_files_loads_and_indexes(tmp_path):
    import json

    path = tmp_path / "docs.json"
    path.write_text(json.dumps([_LEGAL_DOC, _SUPPORT_DOC]), encoding="utf-8")
    idx = VerbatimDisclosureIndex.from_json_files(path)
    assert idx.doc_count == 2
    hit = idx.check(_SUPPORT_DOC["document_text"])
    assert hit is not None
    assert hit.doc_id == "cfpb_0001"


def test_is_out_of_scope_for_persona_legal_support_disjoint():
    legal_doc = DocRef(doc_id="cuad_0001", source="cuad", ops_visible=False)
    support_doc = DocRef(doc_id="cfpb_0001", source="cfpb", ops_visible=False)

    assert is_out_of_scope_for_persona(support_doc, "legal") is True
    assert is_out_of_scope_for_persona(legal_doc, "legal") is False
    assert is_out_of_scope_for_persona(legal_doc, "support") is True
    assert is_out_of_scope_for_persona(support_doc, "support") is False


def test_is_out_of_scope_for_persona_ops_requires_ops_visible_flag():
    ops_visible_doc = DocRef(doc_id="cuad_0002", source="cuad", ops_visible=True)
    not_ops_visible_doc = DocRef(doc_id="cuad_0003", source="cuad", ops_visible=False)

    assert is_out_of_scope_for_persona(ops_visible_doc, "ops") is False
    assert is_out_of_scope_for_persona(not_ops_visible_doc, "ops") is True


def test_is_out_of_scope_for_persona_unknown_persona_is_not_flagged():
    doc = DocRef(doc_id="cuad_0001", source="cuad", ops_visible=False)
    assert is_out_of_scope_for_persona(doc, "totally_unknown_persona") is False
