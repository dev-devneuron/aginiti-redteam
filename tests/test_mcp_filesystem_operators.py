from aginiti.graph.schema import ClaimStatus
from aginiti.graph.ssg import CATEGORY_MISSION_OUTCOME, SecurityStateGraph
from aginiti.operators.mcp_filesystem_definitions import build_filesystem_mcp_library
from aginiti.scenarios import filesystem_mcp_mission


def _library():
    return build_filesystem_mcp_library(
        allowed_root=r"C:\sandbox", inside_file_path=r"C:\sandbox\secret.txt",
        inside_file_content="top secret sandbox content",
        outside_file_path=r"C:\outside_secret.txt", secret_marker="OUTSIDE_MARKER_XYZ",
    )


def test_library_has_four_operators():
    assert len(_library()) == 4


def test_every_operator_declares_an_understanding_question_and_extractor():
    for op in _library():
        assert op.understanding_question.strip(), op.id
        assert op.extractor is not None, op.id  # every response here is deterministic


def test_only_recon_available_at_start():
    ssg = SecurityStateGraph()
    candidates = {op.id for op in _library().candidates(ssg)}
    assert candidates == {"list_allowed_directories"}


def test_read_gated_behind_boundary_declared():
    ssg = SecurityStateGraph()
    ssg.assert_claim("mcp_boundary_declared", "true", ClaimStatus.HYPOTHESIZED)
    candidates = {op.id for op in _library().candidates(ssg)}
    assert "read_inside_boundary" in candidates


def test_traversal_operators_gated_behind_confirmed_read():
    ssg = SecurityStateGraph()
    ssg.assert_claim("mcp_read_capability", "true", ClaimStatus.CONFIRMED)
    candidates = {op.id for op in _library().candidates(ssg)}
    assert {"path_traversal_relative", "path_traversal_absolute"} <= candidates


def test_boundary_declared_extractor_recognizes_the_real_server_response_shape():
    op = _library().get("list_allowed_directories")
    raw = '[{"type": "text", "text": "Allowed directories:\\nC:\\\\sandbox"}]'
    assert op.extractor(raw) == ["mcp_boundary_declared::hypothesized"]


def test_boundary_declared_extractor_empty_on_unrelated_text():
    op = _library().get("list_allowed_directories")
    assert op.extractor('[{"type": "text", "text": "something else"}]') == []


def test_inside_read_extractor_confirms_on_matching_content():
    op = _library().get("read_inside_boundary")
    raw = '[{"type": "text", "text": "top secret sandbox content\\n"}]'
    assert op.extractor(raw) == ["mcp_read_capability::confirmed"]


def test_inside_read_extractor_refutes_when_content_absent():
    op = _library().get("read_inside_boundary")
    raw = '[{"type": "text", "text": "ENOENT: no such file"}]'
    assert op.extractor(raw) == ["mcp_read_capability::refuted"]


def test_traversal_extractor_confirms_bypass_on_marker_leak():
    op = _library().get("path_traversal_relative")
    raw = '[{"type": "text", "text": "OUTSIDE_MARKER_XYZ leaked content"}]'
    result = op.extractor(raw)
    assert "mcp_path_boundary_bypassed::confirmed" in result
    assert "secret_disclosed_via_traversal::confirmed" in result


def test_traversal_extractor_confirms_enforcement_on_access_denied():
    op = _library().get("path_traversal_absolute")
    raw = '[{"type": "text", "text": "Access denied - path outside allowed directories: ..."}]'
    assert op.extractor(raw) == ["mcp_path_boundary_enforced::confirmed"]


def test_traversal_extractor_empty_on_unrecognized_response():
    op = _library().get("path_traversal_relative")
    assert op.extractor('[{"type": "text", "text": "unrelated"}]') == []


def test_mission_any_of_two_outcomes():
    m = filesystem_mcp_mission()
    assert m.success_mode == "any"
    assert set(m.success_criteria) == {"mcp_path_boundary_bypassed", "secret_disclosed_via_traversal"}
