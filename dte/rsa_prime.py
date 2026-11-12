"""A simple DTE that turns seeds into RSA prime factors.

Every seed becomes a prime of the chosen bit size. Encoding works backwards by
choosing a seed that will return the prime we started with. This is a teaching
example rather than a production RSA key generator.
"""

from random import Random

from sympy import isprime, nextprime, prevprime

from dte.base import DTE, default_rng


def _sample_seed_integer(residue_min: int, residue_max: int, modulus: int,
                         seed_space_size: int, rng: Random) -> int:
    """Pick a random seed that gives one of the allowed remainders."""
    # work out how many times the remainder pattern fits inside the seed space
    max_repetition = seed_space_size // modulus
    # keep trying until the chosen seed fits inside the fixed seed size
    while True:
        residue = rng.randrange(residue_min, residue_max + 1)
        repetition = rng.randrange(max_repetition + 1)
        seed_integer = repetition * modulus + residue
        if seed_integer < seed_space_size:
            return seed_integer


def generate_real_prime(bits: int, rng: Random | None = None) -> int:
    """Generate a real prime with the requested number of bits."""
    # try random odd numbers until one of them is prime
    domain = RSAPrimeDTE(bits)
    rng = rng or default_rng()
    while True:
        candidate = rng.randrange(domain.lower_bound + 1, domain.max_prime + 1, 2)
        if isprime(candidate):
            return candidate


class RSAPrimeDTE(DTE):
    """Encode and decode primes of one chosen bit size."""

    def __init__(self, bits: int):
        # check that the bit size is a normal integer and is large enough to use
        if isinstance(bits, bool) or not isinstance(bits, int):
            raise TypeError("bits must be an integer")
        if bits < 3:
            raise ValueError("bits must be at least 3")

        # set the smallest and largest numbers that can have this many bits
        self.bits = bits
        self.lower_bound = 2 ** (bits - 1)
        self.upper_bound = 2**bits - 1

        # find the largest prime that still fits inside the chosen bit size
        self.max_prime = int(prevprime(self.upper_bound + 1))

        # build the internal range used before calling nextprime
        self.x_min = self.lower_bound - 1
        self.modulus = self.max_prime - self.x_min

        # add extra space and round up so every seed has a whole number of bytes
        self.seed_length = (bits + 128 + 7) // 8
        self.seed_space_size = 2 ** (8 * self.seed_length)

    def encode(self, message: int, rng: Random | None = None) -> bytes:
        """Turn a prime into a random seed that will decode back to it."""
        # make sure the message is an integer and not a boolean value
        if isinstance(message, bool) or not isinstance(message, int):
            # stop because the DTE only accepts integer primes
            raise TypeError("message must be an integer prime")

        # make sure the prime fits inside the bit range chosen for this DTE
        if not self.lower_bound <= message <= self.max_prime:
            # stop because a prime outside this range has the wrong bit size
            raise ValueError(f"message must be a {self.bits}-bit prime")

        # make sure the number is actually prime
        if not isprime(message):
            # stop because composite numbers are not valid RSA prime factors here
            raise ValueError("message must be prime")

        # find the first internal number whose next prime is the message
        x_min = max(self.x_min, int(prevprime(message)))

        # stop one number before the message because nextprime skips the message itself
        x_max = message - 1

        # choose a random seed whose remainder points somewhere between x_min and x_max
        seed_integer = _sample_seed_integer(
            x_min - self.x_min, x_max - self.x_min,
            self.modulus, self.seed_space_size, rng or default_rng(),
        )

        # turn the chosen seed number into fixed-length bytes for AES encryption
        return seed_integer.to_bytes(self.seed_length, "big")

    def decode(self, seed: bytes) -> int:
        """Turn any correctly sized seed into a prime of the chosen bit size."""
        # make sure the seed has the exact size expected by this DTE
        if len(seed) != self.seed_length:
            # stop because a different seed size belongs to a different setup
            raise ValueError(f"seed must be exactly {self.seed_length} bytes")

        # turn the seed bytes into one large number
        seed_integer = int.from_bytes(seed, "big")

        # shrink the number into a position inside the internal range
        residue = seed_integer % self.modulus

        # move that position up to the correct bit range
        x = self.x_min + residue

        # return the first prime after x as the decoded message
        return int(nextprime(x))
