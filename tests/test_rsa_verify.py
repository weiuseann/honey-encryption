"""Public factor verification preserves all matches rather than assuming one PIN."""

import pytest

from attacks.rsa_verify import find_real_prime


def test_finds_true_factor_among_nondivisors():
    candidates = [("0000", 17), ("0042", 11), ("9999", 19)]
    assert find_real_prime(candidates, 143) == [("0042", 11)]


def test_preserves_both_factors_duplicate_pairs_and_input_order():
    candidates = [("0000", 17), ("0042", 11), ("1234", 13),
                  ("9999", 11), ("0042", 11)]
    original = list(candidates)
    assert find_real_prime(candidates, 143) == [
        ("0042", 11), ("1234", 13), ("9999", 11), ("0042", 11),
    ]
    assert candidates == original


def test_returns_empty_when_no_candidate_matches():
    assert find_real_prime([("0000", 17), ("0042", 19)], 143) == []
    assert find_real_prime([], 143) == []


def test_excludes_trivial_negative_zero_and_out_of_range_divisors():
    candidates = [("0000", -11), ("0001", 0), ("0002", 1),
                  ("0003", 143), ("0004", 286), ("0042", 11)]
    assert find_real_prime(candidates, 143) == [("0042", 11)]


def test_verifies_divisibility_without_requiring_a_prime_candidate():
    # Primality is the DTE's job; verification only needs a proper divisor.
    assert find_real_prime([("0042", 15), ("0000", 14)], 225) == [("0042", 15)]


@pytest.mark.parametrize("modulus", [True, False, 143.0, "143", None])
def test_rejects_non_integer_modulus(modulus):
    with pytest.raises(TypeError, match="N must be an integer RSA modulus"):
        find_real_prime([], modulus)


@pytest.mark.parametrize("modulus", [-143, -1, 0, 1, 2, 3])
def test_rejects_invalid_modulus_values_even_without_candidates(modulus):
    with pytest.raises(ValueError, match="N must be greater than 3"):
        find_real_prime([], modulus)
