"""[STUB] RSA prime DTE: every wrong PIN decodes to a valid prime of the right size.

What goes here (Scenario B, owner: RSA half):
  Message = one RSA prime factor p (real size, e.g. 1024-bit for RSA-2048).
  Next-prime DTE idea:
    decode(seed) = nextprime(x), where x is the seed mapped into the prime range
    encode(p)    = a random x in the gap (previous prime, p], so that
                   nextprime(x) == p
  The encode range must match the exact nextPrime convention of the library
  we use (sympy.nextprime(n) returns the smallest prime STRICTLY greater
  than n). An off-by-one here breaks round-tripping at the boundary.

Required (agreed):
  - generate_real_prime() must draw the "real" primes from the same range the
    DTE covers, so every real prime can be encoded.
  - Tests: round trip; decoys are prime and have the intended bit length;
    boundary cases (smallest/largest prime in range) and prime-gap cases.
  - Bias, stated openly: nextprime picks p with probability proportional to
    the gap before p, so primes after large gaps are favoured. We do NOT claim
    this matches the distribution of real RSA key generation.

The matching attack is attacks/rsa_verify.py. It works no matter how good this
DTE is.
"""

from random import Random

from dte.base import DTE


def generate_real_prime(bits: int, rng: Random | None = None) -> int:
    """Generate a 'real' prime from the exact range the DTE covers."""
    raise NotImplementedError


class RSAPrimeDTE(DTE):
    seed_length: int  # depends on prime size + slack bits

    def __init__(self, bits: int):
        self.bits = bits

    def encode(self, message: int, rng: Random | None = None) -> bytes:
        raise NotImplementedError

    def decode(self, seed: bytes) -> int:
        raise NotImplementedError
