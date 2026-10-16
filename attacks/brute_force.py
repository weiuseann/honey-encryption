"""Brute force: decrypt under every one of the 10,000 PINs.

This is the attacker's first step in every scenario. Against ordinary
encryption it ends the attack, because only the right PIN gives readable
output. Against honey encryption every PIN gives a plausible message, so it
only produces the candidate list. The attacks in this folder then try to pick
the real message out of that list.

Works with any DTE (cards, RSA primes, ...), because it relies only on
framework.he.decrypt.
"""

from dte.base import DTE
from framework.he import ALL_PINS, Ciphertext, decrypt


def brute_force(ciphertext: Ciphertext, dte: DTE) -> list[tuple[str, object]]:
    """Return [(pin, candidate_message)] for all 10,000 PINs, in PIN order."""
    return [(pin, decrypt(dte, ciphertext, pin)) for pin in ALL_PINS]
