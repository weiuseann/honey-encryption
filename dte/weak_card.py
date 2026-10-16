"""Weak credit card DTE: every 16-digit string is equally likely.

Why this is weak: real card numbers are NOT uniform 16-digit strings. They
start with a real network prefix and BIN, and they end in a Luhn check digit.
Decoys from this DTE are uniform, so most of them fail those format checks
(attacks/format_filter.py), while the real card always passes. This is the
"distribution mismatch" case: the DTE models the wrong message distribution.

The seed encoding itself is sound. We deliberately avoid the naive version,
seed = card_number.to_bytes(8). That leaks: the real seed is always < 10^16,
but a random 8-byte seed is < 10^16 only about 1 time in 1844, so an attacker
could pick out the real card just by checking which seed is small. Instead:

    encode(m) = r * 10^16 + m   for a random r, written as 16 bytes (128 bits)
    decode(s) = int(s) mod 10^16

so each card number corresponds to many seeds, and encode picks one at random.
Every 16-digit string then gets almost exactly the same share of the 2^128
seeds. 2^128 is not a multiple of 10^16, so some strings get one extra seed:
the relative bias is at most 10^16 / 2^128, about 3e-23, which is negligible.
"""

from random import Random

from dte.base import DTE, default_rng

N_DIGITS = 16
MODULUS = 10**N_DIGITS  # number of possible 16-digit strings


class WeakCardDTE(DTE):
    seed_length = 16  # 128-bit seed; see the bias argument in the module docstring

    # Number of full blocks of size MODULUS inside the seed space. Picking r
    # below this keeps r * MODULUS + m < 2^128, so the seed always fits.
    _MAX_R = 2 ** (8 * seed_length) // MODULUS

    def encode(self, message: str, rng: Random | None = None) -> bytes:
        if len(message) != N_DIGITS or not message.isdigit():
            raise ValueError(f"expected a {N_DIGITS}-digit string, got {message!r}")
        rng = rng or default_rng()
        m = int(message)
        r = rng.randrange(self._MAX_R)
        return (r * MODULUS + m).to_bytes(self.seed_length, "big")

    def decode(self, seed: bytes) -> str:
        # Total function: every 16-byte seed maps to some 16-digit string.
        m = int.from_bytes(seed, "big") % MODULUS
        return f"{m:0{N_DIGITS}d}"  # keep leading zeros so the string stays 16 digits
