import random

import pytest

from dte.luhn import is_luhn_valid, luhn_check_digit


@pytest.mark.parametrize("number", ["79927398713", "4111111111111111", "5555555555554444", "0000000000000000"])
def test_known_valid(number):
    assert is_luhn_valid(number)
    assert luhn_check_digit(number[:-1]) == number[-1]


@pytest.mark.parametrize("number", ["79927398710", "4111111111111112", "", "1", "41111111111111a1"])
def test_known_invalid(number):
    assert not is_luhn_valid(number)


def test_check_digit_always_validates():
    rng = random.Random(0)
    for _ in range(1000):
        partial = f"{rng.randrange(10**15):015d}"
        assert is_luhn_valid(partial + luhn_check_digit(partial))


def test_single_digit_error_detected():
    # Luhn catches every single-digit typo; this is why decoys must pass it to look real.
    card = "4111111111111111"
    for pos in range(16):
        for d in "0123456789":
            if d != card[pos]:
                assert not is_luhn_valid(card[:pos] + d + card[pos + 1:])
