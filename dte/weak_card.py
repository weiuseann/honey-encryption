from random import Random

from dte.base import DTE, default_rng

N_DIGITS = 16
MODULUS = 10**N_DIGITS  #number of possible 16digit strings


class WeakCardDTE(DTE):
    seed_length = 16  # 16x8=128-bit seed

    #below this keeps r * MODULUS + m < 2^128, so the seed always fits.
    _MAX_R = 2 ** (8 * seed_length) // MODULUS

    def encode(self, message: str, rng: Random | None = None) -> bytes:
        if len(message) != N_DIGITS or not message.isdigit():
            raise ValueError(f"expected a {N_DIGITS}-digit string, got {message!r}")
        rng = rng or default_rng()
        m = int(message)
        #make sure r dont exceed 2^128 bits
        r = rng.randrange(self._MAX_R)
        return (r * MODULUS + m).to_bytes(self.seed_length, "big")

    def decode(self, seed: bytes) -> str:
        #convert byte to int and remove the front random numbers by modulus
        m = int.from_bytes(seed, "big") % MODULUS
        return f"{m:0{N_DIGITS}d}"  #keep zeroes in front so its always 16 digits
