"""Luhn check digit, shared by the good card DTE, the format filter and the card pair generator.

The Luhn checksum is not cryptographic: it only catches typos (any single wrong digit and most
swaps of adjacent digits). It matters here because it is a free public test. Every real card passes
it, so a decoy that fails it is an obvious fake (see attacks/format_filter.py).
"""


def _luhn_sum(digits: str, double_rightmost: bool) -> int:
    total = 0
    # Walk from the right, doubling every second digit. A doubled digit above 9 has 9 subtracted,
    # which is the same as adding its two decimal digits (e.g. 7*2 = 14 -> 1+4 = 5 = 14-9).
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if (i % 2 == 0) == double_rightmost:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total


def luhn_check_digit(partial: str) -> str:
    """The digit to append to `partial` so the full number passes the Luhn check."""
    if not partial.isdigit():
        raise ValueError(f"expected digits, got {partial!r}")
    # Once the check digit is appended it becomes the rightmost (undoubled) digit, so the current
    # rightmost digit of `partial` is the first one to double.
    return str((10 - _luhn_sum(partial, double_rightmost=True) % 10) % 10)


def is_luhn_valid(number: str) -> bool:
    """True if `number` (a digit string, check digit included) passes the Luhn check."""
    if not number.isdigit() or len(number) < 2:
        return False
    return _luhn_sum(number, double_rightmost=False) % 10 == 0
