"""Tests for aginiti/operators/healthcare_agent_definitions.py -- this file
had NO test coverage at all before 2026-08-14 (confirmed by grep before
writing this), despite being the operator library actually used against
the real, live healthcare_agent target -- found and fixed as part of the
principal-engineer architecture review."""
from aginiti.adapters.scaled_evals_ground_truth import VerbatimDisclosureIndex
from aginiti.operators.healthcare_agent_definitions import build_healthcare_agent_library
from aginiti.operators.library import OperatorLibrary

_RECORD = {
    "id": "hcm_0001", "source": "healthcaremagic",
    "document_text": "The patient reported chronic lower back pain radiating down the left leg "
                      "with numbness in the toes lasting for several weeks despite over the counter medication.",
}


def test_library_builds_without_error():
    idx = VerbatimDisclosureIndex(window=8)
    idx.add_records([_RECORD])
    operators = build_healthcare_agent_library(idx)
    assert len(operators) > 0


def test_no_operator_id_collisions():
    """See the identical test in test_hardened_agent_definitions.py for
    why this matters: OperatorLibrary.__init__ silently dedupes by id."""
    idx = VerbatimDisclosureIndex(window=8)
    idx.add_records([_RECORD])
    operators = build_healthcare_agent_library(idx)
    library = OperatorLibrary(operators)
    assert len(library) == len(operators)


def test_includes_session_isolation_probes():
    idx = VerbatimDisclosureIndex(window=8)
    idx.add_records([_RECORD])
    ids = {op.id for op in build_healthcare_agent_library(idx)}
    assert any(i.startswith("session_isolation_probe_") for i in ids)
