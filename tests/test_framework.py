import random

import pytest

from attacks.brute_force import brute_force
from dte.weak_card import WeakCardDTE
from framework.he import ALL_PINS, Ciphertext, decrypt, derive_key, encrypt

dte = WeakCardDTE()
CARD = "4111111111111111"


def test_correct_pin_recovers_message():
    ct = encrypt(dte, CARD, "4821")
    assert decrypt(dte, ct, "4821") == CARD


def test_wrong_pin_gives_decoy_not_error():
    ct = encrypt(dte, CARD, "4821")
    decoy = decrypt(dte, ct, "4822")
    assert len(decoy) == 16 and decoy.isdigit()
    assert decoy != CARD  # fails with probability ~1e-16


def test_fresh_salt_and_nonce():
    a, b = encrypt(dte, CARD, "0000"), encrypt(dte, CARD, "0000")
    assert a.salt != b.salt and a.nonce != b.nonce and a.body != b.body


def test_seeded_encrypt_is_reproducible():
    assert encrypt(dte, CARD, "1234", random.Random(7)) == encrypt(dte, CARD, "1234", random.Random(7))


def test_ciphertext_bytes_round_trip():
    ct = encrypt(dte, CARD, "1234")
    assert Ciphertext.from_bytes(ct.to_bytes()) == ct


def test_salt_changes_key():
    assert derive_key("1234", b"\x00" * 16) != derive_key("1234", b"\x01" * 16)


@pytest.mark.parametrize("bad", ["123", "12345", "12a4"])
def test_rejects_bad_pin(bad):
    with pytest.raises(ValueError):
        encrypt(dte, CARD, bad)


def test_brute_force_returns_all_candidates():
    ct = encrypt(dte, CARD, "0042")
    candidates = brute_force(ct, dte)
    assert [pin for pin, _ in candidates] == ALL_PINS
    assert dict(candidates)["0042"] == CARD
