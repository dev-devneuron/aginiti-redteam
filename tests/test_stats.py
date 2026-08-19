from aginiti.stats import bootstrap_mean_ci, compare_to_aginiti, fisher_exact_two_sided, sign_test


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


def test_sign_test_all_positive_is_significant():
    a = [5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
    b = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    result = sign_test(a, b)
    assert result.n_positive == 10
    assert result.n_negative == 0
    assert result.p_value < 0.01


def test_sign_test_no_difference_is_not_significant():
    a = [1, 2, 3, 4, 5, 6]
    b = [1, 2, 3, 4, 5, 6]
    result = sign_test(a, b)
    assert result.n_ties == 6
    assert result.p_value == 1.0


def test_sign_test_mismatched_lengths_raises():
    try:
        sign_test([1, 2], [1])
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_sign_test_interpret_flags_small_n():
    result = sign_test([2, 2, 2], [1, 1, 1])
    assert "hint, not a finding" in result.interpret()


def test_bootstrap_ci_contains_true_mean_for_low_variance_sample():
    values = [10.0] * 20
    ci = bootstrap_mean_ci(values, n_resamples=500)
    assert ci.lo <= 10.0 <= ci.hi


def test_bootstrap_ci_widens_with_more_variance():
    tight = bootstrap_mean_ci([5.0, 5.0, 5.0, 5.0], n_resamples=500)
    wide = bootstrap_mean_ci([1.0, 5.0, 9.0, 13.0], n_resamples=500)
    assert (wide.hi - wide.lo) > (tight.hi - tight.lo)


def test_bootstrap_ci_single_value_is_a_point():
    ci = bootstrap_mean_ci([7.0])
    assert ci.lo == ci.hi == 7.0
