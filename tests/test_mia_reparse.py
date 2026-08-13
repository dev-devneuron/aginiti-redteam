import copy

import pytest

from aginiti.reporting.mia_reparse import (
    _score_paper_official,
    parse_yes_no_unk_reparsed,
    reparse_results,
    reparse_results_paper_formula,
)


# ---------------------------------------------------------------------------
# parse_yes_no_unk_reparsed is now a thin delegate to
# aginiti.attacks.mia.interrogation._parse_yes_no_unk (2026-08-13 — the
# reported-speech fallback moved into the live classifier itself; see that
# module's own TestParseYesNoUnkReportedSpeechFallback for the real-capture
# regression tests). Only verify the delegation here, not re-test the logic.
# ---------------------------------------------------------------------------

def test_delegates_to_live_classifier():
    from aginiti.attacks.mia.interrogation import _parse_yes_no_unk
    samples = [
        "Yes, that is correct.",
        "I don't know.",
        "The consumer states that the debt was paid in full.",
        "The weather is nice today.",
    ]
    for s in samples:
        assert parse_yes_no_unk_reparsed(s) == _parse_yes_no_unk(s)


# ---------------------------------------------------------------------------
# reparse_results -- end-to-end recompute from a synthetic results dict
# ---------------------------------------------------------------------------

def _synthetic_report():
    return {
        "run": {"attack": "mia_interrogation_benchmark"},
        "metrics": {"auc_roc": 0.5},
        "scored_documents": [
            {
                "id": "doc_a",
                "score": -0.5,
                "is_member": True,
                "detail": [
                    {
                        "probe_question": "Q1?", "shadow_answer": "yes",
                        "target_response": "The consumer states that the payment was made.",
                        "target_answer": "unk", "match": False,
                    },
                    {
                        "probe_question": "Q2?", "shadow_answer": "no",
                        "target_response": "No, that did not happen.",
                        "target_answer": "no", "match": True,
                    },
                ],
            },
            {
                "id": "doc_b",
                "score": -1.0,
                "is_member": False,
                "detail": [
                    {
                        "probe_question": "Q1?", "shadow_answer": "yes",
                        "target_response": "No, that is not the case here.",
                        "target_answer": "no", "match": False,
                    },
                    {
                        "probe_question": "Q2?", "shadow_answer": "no",
                        "target_response": "No, that did not happen.",
                        "target_answer": "no", "match": True,
                    },
                ],
            },
        ],
    }


class TestReparseResults:
    def test_does_not_mutate_original_report(self):
        original = _synthetic_report()
        snapshot = copy.deepcopy(original)
        reparse_results(original)
        assert original == snapshot

    def test_adds_v2_fields_without_removing_originals(self):
        out = reparse_results(_synthetic_report())
        detail = out["scored_documents"][0]["detail"]
        assert detail[0]["target_answer"] == "unk"          # original preserved
        assert detail[0]["target_answer_v2"] == "yes"        # recovered
        assert detail[0]["match_v2"] is True
        assert detail[1]["target_answer_v2"] == "no"          # unaffected, unchanged value

    def test_recomputes_document_score_v2(self):
        out = reparse_results(_synthetic_report())
        doc = out["scored_documents"][0]
        # Q1: originally unk -> penalized -lambda; now "yes"==shadow "yes" -> +1
        # Q2: unchanged, "no"==shadow "no" -> +1 both before and after
        assert doc["score_v2"] == pytest.approx(1.0)  # (1+1)/2

    def test_reports_flip_counts(self):
        out = reparse_results(_synthetic_report())
        flips = out["reparse"]["parser_fix"]
        assert flips["probes_flipped_unk_to_yes"] == 1
        assert flips["probes_flipped_unk_to_no"] == 0
        assert flips["probes_flipped_total"] == 1

    def test_top_level_metrics_is_the_revised_number(self):
        # 2026-08-13: top-level "metrics" now IS the corrected (fixed-
        # parser) result, not the untouched original -- the original moves
        # to "metrics_original" so the fix isn't hidden behind a
        # differently-named field.
        out = reparse_results(_synthetic_report())
        assert out["metrics"]["auc_roc"] == pytest.approx(out["reparse"]["all_metrics_side_by_side"][
            "REVISED -- our formula, fixed parser (now the top-level 'metrics')"
        ]["auc_roc"])
        assert out["metrics"] != out["metrics_original"]

    def test_metrics_original_preserved_unchanged(self):
        original = _synthetic_report()
        out = reparse_results(original)
        assert out["metrics_original"] == original["metrics"]

    def test_paper_formula_variants_present(self):
        out = reparse_results(_synthetic_report())
        doc = out["scored_documents"][0]
        assert "score_paper_formula" in doc
        assert "score_paper_formula_v2" in doc
        assert "metrics_paper_formula" in out
        assert "metrics_paper_formula_v2" in out


# ---------------------------------------------------------------------------
# _score_paper_official / reparse_results_paper_formula -- the scoring
# formula actually used by external_repos/RAG_MIA (verified 2026-08-13
# directly against mia_utils/mia.py::calculate_score and
# analysis.ipynb::get_mia_scores), NOT the lambda-penalized formula this
# library implements. Provided for offline comparison only.
# ---------------------------------------------------------------------------

class TestScorePaperOfficial:
    def test_plain_fraction_no_penalty(self):
        # 2/4 match, no UNK involved -- plain fraction, unlike our formula
        # which would also be 2/4 here (no unk to penalize) -- same result
        # when there's no UNK, they diverge specifically ON unk.
        ground_truths = ["yes", "no", "yes", "no"]
        responses = ["yes", "no", "no", "yes"]
        assert _score_paper_official(ground_truths, responses) == pytest.approx(0.5)

    def test_unk_unk_pair_counts_as_a_match(self):
        # This is the key documented divergence from our own
        # InterrogationAttack._score_document: official code does bare
        # string equality with no special-casing, so "unk"=="unk" scores
        # as a match, not a penalty.
        ground_truths = ["yes", "unk"]
        responses = ["yes", "unk"]
        assert _score_paper_official(ground_truths, responses) == pytest.approx(1.0)

    def test_no_lambda_penalty_applied(self):
        # Our own formula would apply -lambda_unk here; the official
        # formula just doesn't count it as correct -- no negative score
        # possible at all.
        ground_truths = ["yes", "yes"]
        responses = ["unk", "unk"]
        assert _score_paper_official(ground_truths, responses) == pytest.approx(0.0)
        assert _score_paper_official(ground_truths, responses) >= 0.0  # never negative


class TestReparseResultsPaperFormula:
    def test_does_not_mutate_original_report(self):
        original = _synthetic_report()
        snapshot = copy.deepcopy(original)
        reparse_results_paper_formula(original)
        assert original == snapshot

    def test_adds_score_paper_formula_field(self):
        out = reparse_results_paper_formula(_synthetic_report())
        doc = out["scored_documents"][0]
        assert "score_paper_formula" in doc
        # doc_a: Q1 unk!=yes (miss), Q2 no==no (match) -> 1/2
        assert doc["score_paper_formula"] == pytest.approx(0.5)

    def test_metrics_paper_formula_present(self):
        out = reparse_results_paper_formula(_synthetic_report())
        assert "metrics_paper_formula" in out
        assert "auc_roc" in out["metrics_paper_formula"]
