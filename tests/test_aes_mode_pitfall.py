"""CTR acceptance does not mean the guessed PIN recovered the original seed."""

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


@pytest.mark.parametrize("mode", ["CTR", "GCM", "CBC"])
def test_each_mode_attempts_every_pin(monkeypatch, mode):
    attempted = []

    def tracked_derive_key(pin, salt):
        attempted.append(pin)
        return derive_key(pin, salt)

    monkeypatch.setattr(demo, "derive_key", tracked_derive_key)
    accepted = demo.count_accepting_pins(mode, seed=2026)
    assert 1 <= accepted <= 10_000
    if mode == "CTR":
        assert accepted == 10_000
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


@pytest.mark.parametrize("mode", ["CTR", "GCM", "CBC"])
def test_mode_counts_are_reproducible(mode):
    assert demo.count_accepting_pins(mode, 2026) == demo.count_accepting_pins(mode, 2026)


def test_gcm_true_pin_authenticates_and_wrong_pin_fails():
    inputs = demo._comparison_inputs(2026)
    key = derive_key(inputs["true_pin"], inputs["salt"])
    body = AESGCM(key).encrypt(inputs["gcm_nonce"], inputs["plaintext"], None)
    assert AESGCM(key).decrypt(inputs["gcm_nonce"], body, None) == inputs["plaintext"]
    for wrong_pin in [pin for pin in ALL_PINS if pin != inputs["true_pin"]][:3]:
        with pytest.raises(InvalidTag):
            AESGCM(derive_key(wrong_pin, inputs["salt"])).decrypt(inputs["gcm_nonce"], body, None)


def test_unexpected_gcm_programming_error_is_not_swallowed(monkeypatch):
    class BrokenGCM:
        def __init__(self, key):
            pass

        def encrypt(self, *args):
            return b"placeholder"

        def decrypt(self, *args):
            raise RuntimeError("unexpected failure")

    monkeypatch.setattr(demo, "AESGCM", BrokenGCM)
    with pytest.raises(RuntimeError, match="unexpected failure"):
        demo.count_accepting_pins("GCM")


def test_cbc_true_pin_decrypts_and_unpads_to_original_seed():
    inputs = demo._comparison_inputs(2026)
    key = derive_key(inputs["true_pin"], inputs["salt"])
    padder = padding.PKCS7(128).padder()
    padded = padder.update(inputs["plaintext"]) + padder.finalize()
    assert len(padded) == 32  # A full input block gets a whole padding block.
    encryptor = Cipher(algorithms.AES(key), modes.CBC(inputs["cbc_iv"])).encryptor()
    body = encryptor.update(padded) + encryptor.finalize()
    decryptor = Cipher(algorithms.AES(key), modes.CBC(inputs["cbc_iv"])).decryptor()
    assert demo._unpad(decryptor.update(body) + decryptor.finalize()) == inputs["plaintext"]


@pytest.mark.parametrize("padded, expected", [
    (b"A" * 15 + b"\x01", b"A" * 15),
    (b"A" * 14 + b"\x02\x02", b"A" * 14),
    (b"\x10" * 16, b""),
])
def test_known_valid_pkcs7_padding(padded, expected):
    assert demo._unpad(padded) == expected


@pytest.mark.parametrize("padded", [b"A" * 16, b"A" * 15 + b"\x00",
                                     b"A" * 14 + b"\x01\x02", b"short"])
def test_known_invalid_pkcs7_padding(padded):
    with pytest.raises(ValueError):
        demo._unpad(padded)


def test_cli_prints_all_three_measured_counts(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["aes_mode_pitfall", "--seed", "2026"])
    demo.main()
    output = capsys.readouterr().out
    assert "seed = 2026" in output
    assert "CTR: 10000 accepted" in output
    assert "GCM:" in output and "CBC:" in output
    assert "not necessarily recovering" in output


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError, match="unknown AES mode"):
        demo.count_accepting_pins("ECB")


@pytest.mark.parametrize("seed", [True, "2026", None])
def test_fixture_rejects_non_integer_seed(seed):
    with pytest.raises(TypeError, match="seed must be an integer"):
        demo._comparison_inputs(seed)
