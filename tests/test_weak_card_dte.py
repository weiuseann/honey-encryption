import random

import pytest

from dte.weak_card import WeakCardDTE

dte = WeakCardDTE()


def random_card(rng: random.Random) -> str:
    return f"{rng.randrange(10**16):016d}"


def test_round_trip_random():
    rng = random.Random(0)
    for _ in range(1000):
        card = random_card(rng)
        assert dte.decode(dte.encode(card, rng)) == card


@pytest.mark.parametrize("card", ["0000000000000000", "9999999999999999", "0000000000000001"])
def test_round_trip_edges(card):
    assert dte.decode(dte.encode(card)) == card


def test_seed_length():
    assert len(dte.encode("4111111111111111")) == dte.seed_length


def test_decode_is_total():
    # Contract 2: any seed (what a wrong PIN produces) decodes to a valid-looking message.
    rng = random.Random(1)
    for _ in range(1000):
        out = dte.decode(rng.randbytes(dte.seed_length))
        assert len(out) == 16 and out.isdigit()


def test_encode_is_randomised():
    # Many seeds per card; encode should pick a different one each time.
    card = "4111111111111111"
    assert dte.encode(card) != dte.encode(card)


def test_seeded_rng_is_reproducible():
    card = "4111111111111111"
    assert dte.encode(card, random.Random(42)) == dte.encode(card, random.Random(42))


@pytest.mark.parametrize("bad", ["123", "41111111111111112", "41111111111111a1"])
def test_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        dte.encode(bad)
