"""Compare wrong-PIN acceptance under AES-CTR, GCM, and CBC with PKCS#7 padding.

Acceptance means the cipher's checks permit a guess, not that it recovers the
original plaintext. CTR has no padding or authentication check to reject PINs.
"""

import argparse
from random import Random

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from framework.he import ALL_PINS, _aes_ctr, derive_key


def _comparison_inputs(seed: int) -> dict:
    """Build shared experiment inputs; each mode gets a suitable separate IV/nonce."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TypeError("seed must be an integer")
    rng = Random(seed)
    return {
        "plaintext": rng.randbytes(16), "salt": rng.randbytes(16),
        "ctr_nonce": rng.randbytes(16), "cbc_iv": rng.randbytes(16),
        "gcm_nonce": rng.randbytes(12), "true_pin": rng.choice(ALL_PINS),
    }


def _unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding; invalid padding raises ValueError."""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def count_accepting_pins(mode: str, seed: int = 2026) -> int:
    """Try every PIN, counting only the mode's tag/padding acceptance checks."""
    if mode not in ("CTR", "GCM", "CBC"):
        raise ValueError("unknown AES mode; expected CTR, GCM, or CBC")
    inputs = _comparison_inputs(seed)
    key = derive_key(inputs["true_pin"], inputs["salt"])
    if mode == "CTR":
        body = _aes_ctr(key, inputs["ctr_nonce"], inputs["plaintext"])
    elif mode == "GCM":
        body = AESGCM(key).encrypt(inputs["gcm_nonce"], inputs["plaintext"], None)
    else:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(inputs["plaintext"]) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(inputs["cbc_iv"])).encryptor()
        body = encryptor.update(padded) + encryptor.finalize()

    accepted = 0
    for pin in ALL_PINS:
        guess_key = derive_key(pin, inputs["salt"])
        if mode == "CTR":
            _aes_ctr(guess_key, inputs["ctr_nonce"], body)
        elif mode == "GCM":
            try:
                AESGCM(guess_key).decrypt(inputs["gcm_nonce"], body, None)
            except InvalidTag:
                continue
        else:
            decryptor = Cipher(algorithms.AES(guess_key), modes.CBC(inputs["cbc_iv"])).decryptor()
            padded = decryptor.update(body) + decryptor.finalize()
            try:
                _unpad(padded)
            except ValueError:
                continue
        accepted += 1
    return accepted


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=2026)
    seed = parser.parse_args().seed
    print(f"seed = {seed}; each mode attempts all {len(ALL_PINS)} PINs")
    for mode in ("CTR", "GCM", "CBC"):
        print(f"{mode}: {count_accepting_pins(mode, seed)} accepted")
    print("Accepted means passing the mode's checks, not necessarily recovering the original seed.")
    print("CBC expects about 40 total acceptances under a random-output approximation; counts vary.")


if __name__ == "__main__":
    main()
