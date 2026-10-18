"""RSA prime DTE with reversible encoding and separate real-prime generation.

What goes here (Scenario B, owner: RSA half):
  Message = one RSA prime factor p (real size, e.g. 1024-bit for RSA-2048).
  Next-prime DTE idea:
    decode(seed) = nextprime(x), where x is the seed mapped into the prime range
    encode(p)    = a random x in [previous prime, p - 1], clipped to our range, so that
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

from sympy import isprime, nextprime, prevprime

from dte.base import DTE, default_rng


def _sample_seed_integer(residue_min: int, residue_max: int, modulus: int,
                         seed_space_size: int, rng: Random) -> int:
    """Uniformly sample seeds whose remainder is in the inclusive residue interval.

    Equal-probability (residue, repetition) proposals give each valid seed one
    representation. Retry proposals beyond the seed space's partial last block.
    """
    max_repetition = seed_space_size // modulus
    while True:
        residue = rng.randrange(residue_min, residue_max + 1)
        repetition = rng.randrange(max_repetition + 1)
        seed_integer = repetition * modulus + residue
        if seed_integer < seed_space_size:
            return seed_integer


def generate_real_prime(bits: int, rng: Random | None = None) -> int:
    """Sample odd candidates uniformly, rejecting composites in the DTE's domain."""
    domain = RSAPrimeDTE(bits)
    rng = rng or default_rng()
    while True:
        candidate = rng.randrange(domain.lower_bound + 1, domain.max_prime + 1, 2)
        if isprime(candidate):
            return candidate


class RSAPrimeDTE(DTE):
    """Prepare a domain covering every prime of the requested bit length.

    A b-bit positive integer lies in [2**(b-1), 2**b - 1]. Decoding
    applies nextprime(x), so x must stop BEFORE the largest allowed prime.
    For bits=4, primes are 11 and 13; x ranges from 7 through 12 inclusive.

    Real-prime generation samples independently of the decoder's gap-biased output.
    """

    def __init__(self, bits: int):
        # bool is an int subclass in Python, but is not a meaningful bit count.
        if isinstance(bits, bool) or not isinstance(bits, int):
            raise TypeError("bits must be an integer")
        if bits < 3:
            raise ValueError("bits must be at least 3")

        self.bits = bits
        self.lower_bound = 2 ** (bits - 1)
        self.upper_bound = 2**bits - 1
        # prevprime is strict: +1 includes upper_bound if it is itself prime.
        self.max_prime = int(prevprime(self.upper_bound + 1))

        # Residues 0..modulus-1 map to x_min..max_prime-1.
        # Starting just below lower_bound keeps the smallest prime reachable.
        self.x_min = self.lower_bound - 1
        self.modulus = self.max_prime - self.x_min

        # Extra seed bits reduce modulo bias; they do not remove prime-gap bias.
        # Adding 7 before integer division rounds up to a whole number of bytes.
        self.seed_length = (bits + 128 + 7) // 8
        self.seed_space_size = 2 ** (8 * self.seed_length)

    def encode(self, message: int, rng: Random | None = None) -> bytes:
        """Choose a random fixed-length seed that decodes to the given prime."""
        if isinstance(message, bool) or not isinstance(message, int):
            raise TypeError("message must be an integer prime")
        if not self.lower_bound <= message <= self.max_prime:
            raise ValueError(f"message must be a {self.bits}-bit prime")
        if not isprime(message):
            raise ValueError("message must be prime")

        # nextprime is strict, so its preimage ends at message-1, not message.
        x_min = max(self.x_min, int(prevprime(message)))
        x_max = message - 1
        seed_integer = _sample_seed_integer(
            x_min - self.x_min, x_max - self.x_min,
            self.modulus, self.seed_space_size, rng or default_rng(),
        )
        return seed_integer.to_bytes(self.seed_length, "big")

    def decode(self, seed: bytes) -> int:
        """Map every correctly sized seed to a prime of the configured bit length."""
        if len(seed) != self.seed_length:
            raise ValueError(f"seed must be exactly {self.seed_length} bytes")

        seed_integer = int.from_bytes(seed, "big")
        residue = seed_integer % self.modulus
        x = self.x_min + residue
        return int(nextprime(x))
