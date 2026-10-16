"""Abstract base class for distribution-transforming encoders (DTEs).

A DTE is the half of honey encryption that makes wrong keys produce believable
decoys. Encryption (framework/he.py) never sees the message itself, only the
seed bytes the DTE produces:

    message --encode--> seed --AES-CTR(key from PIN)--> ciphertext

Decrypting with a wrong PIN gives a seed that is effectively uniformly random.
So the security of the whole scheme rests on this: decoding a uniformly random
seed should give a message that looks like it came from the real message
distribution.
"""

import secrets
from abc import ABC, abstractmethod
from random import Random


def default_rng() -> Random:
    """The rng used when the caller passes none.

    SystemRandom reads from the OS CSPRNG (os.urandom) and subclasses
    random.Random, so it has the same randbytes/randrange interface as a
    seeded Random. Experiments pass random.Random(seed) for reproducibility.
    Real usage must use this default, because a seeded Random makes the salt,
    nonce and DTE padding predictable.
    """
    return secrets.SystemRandom()


class DTE(ABC):
    """Interface every DTE must implement.

    Contract (the tests for each DTE should check all three):
      1. Correctness: decode(encode(m)) == m for every valid message m.
      2. Totality: decode(s) never raises for ANY seed s of length seed_length.
         A wrong PIN decrypts to random bytes. If decode raised (or returned
         an obviously invalid message) on those bytes, the attacker would learn
         "wrong PIN" and HE would collapse back to ordinary brute force.
      3. Uniformity (security goal, not checked by a unit test): if m is drawn
         from the real message distribution, encode(m) should be close to
         uniform over all seeds. Equivalently, decode(uniform seed) should
         follow the real message distribution. How well a DTE achieves this is
         exactly what our attacks measure.
    """

    #: Length of every seed in bytes. Fixed per DTE so that all ciphertexts
    #: have the same length and the length alone reveals nothing.
    seed_length: int

    @abstractmethod
    def encode(self, message, rng: Random | None = None) -> bytes:
        """Map a message to a seed of exactly seed_length bytes.

        Usually randomised: many seeds decode to the same message, and encode
        picks one of them at random using rng (default: default_rng()).
        """

    @abstractmethod
    def decode(self, seed: bytes):
        """Map any seed of seed_length bytes back to a message. Must never raise."""
