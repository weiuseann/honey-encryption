"""Minimal honey encryption framework: PIN -> key, then AES-CTR over a DTE seed.

    encrypt: message --dte.encode--> seed --AES-CTR(key, nonce)--> body
    decrypt: body --AES-CTR(key, nonce)--> seed --dte.decode--> message

Why AES-CTR and nothing else:
  CTR turns AES into a stream cipher: body = seed XOR keystream(key, nonce).
  It has no padding and no authentication tag, so decrypting with ANY key
  succeeds and gives some seed. A wrong key gives a keystream unrelated to the
  real one, so the "seed" is effectively uniformly random, which is exactly
  what the DTE needs in order to produce a decoy.
  - AES-GCM would reject wrong keys (tag mismatch), telling the attacker
    "wrong PIN" for free.
  - AES-CBC with PKCS#7 padding would fail the padding check on most wrong
    keys, which leaks the same information.
  (Side demo: experiments/aes_mode_pitfall.py.)

We never attack AES. Every attack in this project targets the small PIN space
and the DTE.
"""

import hashlib
from dataclasses import dataclass
from random import Random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from dte.base import DTE, default_rng

SALT_LEN = 16
NONCE_LEN = 16  # the cryptography library's CTR mode takes a full 16-byte initial counter block

ALL_PINS = [f"{i:04d}" for i in range(10_000)]


@dataclass(frozen=True)
class Ciphertext:
    """Everything an attacker sees. The salt and nonce are public by design."""

    salt: bytes
    nonce: bytes
    body: bytes  # AES-CTR encryption of the DTE seed; same length as the seed

    def to_bytes(self) -> bytes:
        return self.salt + self.nonce + self.body

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ciphertext":
        return cls(
            salt=data[:SALT_LEN],
            nonce=data[SALT_LEN : SALT_LEN + NONCE_LEN],
            body=data[SALT_LEN + NONCE_LEN :],
        )


def _check_pin(pin: str) -> None:
    if len(pin) != 4 or not pin.isdigit():
        raise ValueError(f"PIN must be exactly 4 digits, got {pin!r}")


def derive_key(pin: str, salt: bytes) -> bytes:
    """AES-256 key = SHA-256(salt || pin).

    This KDF is deliberately weak (fast, one hash). A slow KDF such as Argon2
    would NOT fix it: slowness multiplies the cost of every guess by a
    constant, and with only 10^4 PINs even 10^4 * (1 second) is under three
    hours. With a 10,000-PIN space, HE's protection has to come from the
    decoys, not from making brute force expensive.

    The random per-ciphertext salt stops an attacker precomputing one
    PIN -> key table and reusing it across every ciphertext.
    """
    _check_pin(pin)
    return hashlib.sha256(salt + pin.encode("ascii")).digest()


def _aes_ctr(key: bytes, nonce: bytes, data: bytes) -> bytes:
    # In CTR mode encryption and decryption are the same XOR with the keystream.
    # Works for any data length (no block alignment or padding needed), so
    # DTEs can use any seed_length.
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    ctx = cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def encrypt(dte: DTE, message, pin: str, rng: Random | None = None) -> Ciphertext:
    """Honey-encrypt message under pin.

    rng supplies the salt, the nonce and the DTE's encoding randomness.
    Leave it as None (OS CSPRNG) for real use; experiments pass
    random.Random(seed) so that runs are reproducible.
    """
    rng = rng or default_rng()
    salt = rng.randbytes(SALT_LEN)
    nonce = rng.randbytes(NONCE_LEN)  # fresh per ciphertext: reusing (key, nonce) in CTR leaks seed XORs
    seed = dte.encode(message, rng)
    if len(seed) != dte.seed_length:
        raise ValueError(f"DTE returned {len(seed)} bytes, expected {dte.seed_length}")
    body = _aes_ctr(derive_key(pin, salt), nonce, seed)
    return Ciphertext(salt=salt, nonce=nonce, body=body)


def decrypt(dte: DTE, ciphertext: Ciphertext, pin: str):
    """Decrypt under pin. Never fails: a wrong PIN returns a decoy message."""
    seed = _aes_ctr(derive_key(pin, ciphertext.salt), ciphertext.nonce, ciphertext.body)
    return dte.decode(seed)
