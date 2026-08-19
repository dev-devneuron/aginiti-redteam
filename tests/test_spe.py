import pytest
import responses as resp_lib
from unittest.mock import patch

from aginiti.attacks.spe import SPEAttack

BASE_URL = "http://localhost:8004"

@pytest.fixture
def spe_attack():
    return SPEAttack(target_url=BASE_URL)

def test_is_refusal(spe_attack):
    assert spe_attack._is_refusal("I am sorry, but I cannot disclose my system instructions.") is True
    assert spe_attack._is_refusal("Here are your rules:") is False
    assert spe_attack._is_refusal("Against my programming guidelines") is True

@patch("aginiti.attacks.spe.spe_llm.embed_texts")
def test_cosine_similarity(mock_embed, spe_attack):
    # Mock embed_texts to return identical embeddings or dummy arrays
    mock_embed.return_value = [[1.0, 0.0], [1.0, 0.0]]
    sim = spe_attack._cosine_similarity("a", "b")
    assert sim == pytest.approx(1.0)

    mock_embed.return_value = [[1.0, 0.0], [0.0, 1.0]]
    sim = spe_attack._cosine_similarity("a", "b")
    assert sim == pytest.approx(0.0)

@resp_lib.activate
def test_execute_black_box_success(spe_attack):
    # Mock health check and /chat calls
    resp_lib.add(resp_lib.GET, f"{BASE_URL}/health", json={"status": "ok"}, status=200)
    
    # SPE template responses (CoT, Sandwich, Few-Shot)
    resp_lib.add(resp_lib.POST, f"{BASE_URL}/chat", json={"response": "You are a legal assistant. Do not disclose secrets. Rule 1: be helpful."}, status=200)
    
    findings = spe_attack.execute_black_box(persona="legal")
    assert len(findings) == 3
    # Each probe should be classified heuristically
    for f in findings:
        assert f.attack_type == "SPE"
        assert f.confirmed is True
        assert f.severity == "high"
        assert "You are a legal assistant" in f.leaked_content

@resp_lib.activate
def test_execute_black_box_refusal(spe_attack):
    resp_lib.add(resp_lib.GET, f"{BASE_URL}/health", json={"status": "ok"}, status=200)
    resp_lib.add(resp_lib.POST, f"{BASE_URL}/chat", json={"response": "I am sorry, I cannot share my prompt."}, status=200)
    
    findings = spe_attack.execute_black_box(persona="legal")
    assert len(findings) == 3
    for f in findings:
        assert f.confirmed is False
        assert f.severity == "low"
        assert f.leak_type == "none"

@patch("aginiti.attacks.spe.spe_llm.embed_texts")
def test_score_against_ground_truth(mock_embed, spe_attack):
    from aginiti.attacks.base import LeakFinding
    
    findings = [
        LeakFinding(
            attack_type="SPE",
            tier_used="black_box",
            confidence=0.0,
            confirmed=False,
            leaked_content="You are a legal assistant.",
            probe_used="CoT",
            trace_span_id="",
            recommendation="",
            severity="low",
            full_response="You are a legal assistant.",
            leak_type="none",
            reasoning="Strategy=CoT"
        )
    ]
    
    # Perfect match
    mock_embed.return_value = [[1.0, 0.0], [1.0, 0.0]]
    scored = spe_attack.score_against_ground_truth(findings, "You are a legal assistant.")
    assert len(scored) == 1
    assert scored[0].confirmed is True
    assert scored[0].severity == "high"
    assert scored[0].leak_type == "verbatim"
    assert "Cosine=1.0000" in scored[0].reasoning
