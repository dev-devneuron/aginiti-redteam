from aginiti.stats import compare_to_aginiti, fisher_exact_two_sided


def test_fisher_matches_known_tea_tasting_value():
    # Classic Fisher "tea tasting" table: [[3,1],[1,3]] -> two-sided p ~= 0.4857
    p = fisher_exact_two_sided(3, 1, 1, 3)
    assert abs(p - 0.4857142857) < 1e-6


def test_fisher_perfect_separation_is_significant():
    p = fisher_exact_two_sided(5, 0, 0, 5)
    assert p < 0.01


def test_fisher_p_value_bounded():
    for a, b, c, d in [(0, 0, 0, 0), (2, 2, 2, 2), (10, 0, 10, 0)]:
        p = fisher_exact_two_sided(a, b, c, d)
        assert 0.0 <= p <= 1.0


def test_compare_to_aginiti_flags_underpowered_result():
    comp = compare_to_aginiti(5, 5, "random", 0, 5)
    verdict = comp.interpret()
    assert "too small" in verdict or "no significant difference" in verdict
