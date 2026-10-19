"""CTR acceptance does not mean the guessed PIN recovered the original seed."""

import pytest

from experiments import aes_mode_pitfall as demo
from framework.he import ALL_PINS, _aes_ctr, derive_key


def test_comparison_inputs_are_reproducible_with_suitable_lengths():
    inputs = demo._comparison_inputs(2026)
    assert inputs == demo._comparison_inputs(2026)
    assert inputs != demo._comparison_inputs(7)
    for name in ("plaintext", "salt", "ctr_nonce", "cbc_iv"):
        assert len(inputs[name]) == 16
    assert len(inputs["gcm_nonce"]) == 12
    assert inputs["true_pin"] in ALL_PINS


def test_ctr_attempts_and_accepts_every_pin(monkeypatch):
    attempted = []

    def tracked_derive_key(pin, salt):
        attempted.append(pin)
        return derive_key(pin, salt)

    monkeypatch.setattr(demo, "derive_key", tracked_derive_key)
    assert demo.count_accepting_pins("CTR", seed=2026) == 10_000
    assert attempted == [demo._comparison_inputs(2026)["true_pin"]] + ALL_PINS


def test_ctr_correct_key_recovers_seed_wrong_key_still_produces_bytes():
    inputs = demo._comparison_inputs(2026)
    key = derive_key(inputs["true_pin"], inputs["salt"])
    body = _aes_ctr(key, inputs["ctr_nonce"], inputs["plaintext"])
    assert _aes_ctr(key, inputs["ctr_nonce"], body) == inputs["plaintext"]
    wrong_pin = next(pin for pin in ALL_PINS if pin != inputs["true_pin"])
    wrong_output = _aes_ctr(derive_key(wrong_pin, inputs["salt"]), inputs["ctr_nonce"], body)
    assert len(wrong_output) == len(inputs["plaintext"])
    assert wrong_output != inputs["plaintext"]  # This fixed worked example differs.


def test_ctr_count_is_reproducible():
    assert demo.count_accepting_pins("CTR", 2026) == demo.count_accepting_pins("CTR", 2026)


@pytest.mark.parametrize("mode", ["GCM", "CBC"])
def test_known_unimplemented_modes_are_explicit(mode):
    with pytest.raises(NotImplementedError, match="not implemented yet"):
        demo.count_accepting_pins(mode)


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError, match="unknown AES mode"):
        demo.count_accepting_pins("ECB")


@pytest.mark.parametrize("seed", [True, "2026", None])
def test_fixture_rejects_non_integer_seed(seed):
    with pytest.raises(TypeError, match="seed must be an integer"):
        demo._comparison_inputs(seed)
