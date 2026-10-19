"""AES mode teaching comparison: CTR implemented; GCM/CBC and CLI still pending.

Acceptance means the cipher's checks permit a guess, not that it recovers the
original plaintext. CTR has no padding or authentication check to reject PINs.
"""

from random import Random

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


def count_accepting_pins(mode: str, seed: int = 2026) -> int:
    """Count accepted PIN guesses for a seeded experiment; currently supports CTR."""
    if mode in ("GCM", "CBC"):
        raise NotImplementedError(f"{mode} comparison is not implemented yet")
    if mode != "CTR":
        raise ValueError("unknown AES mode; expected CTR, GCM, or CBC")
    inputs = _comparison_inputs(seed)
    key = derive_key(inputs["true_pin"], inputs["salt"])
    body = _aes_ctr(key, inputs["ctr_nonce"], inputs["plaintext"])
    accepted = 0
    for pin in ALL_PINS:
        guess_key = derive_key(pin, inputs["salt"])
        _aes_ctr(guess_key, inputs["ctr_nonce"], body)
        accepted += 1  # CTR produces bytes without a padding/tag acceptance check.
    return accepted


if __name__ == "__main__":
    raise NotImplementedError("three-mode CLI will be added with the CBC task")
