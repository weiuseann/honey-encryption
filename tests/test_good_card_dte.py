import random
from collections import Counter

import pytest
from scipy.stats import chisquare

from dte.good_card import MIDDLE_SPACE, BinEntry, GoodCardDTE
from dte.luhn import is_luhn_valid, luhn_check_digit

dte = GoodCardDTE()
TABLE_BINS = {e.bin for e in dte.bins}


def card_from(bin_: str, middle: int) -> str:
    partial = bin_ + f"{middle:09d}"
    return partial + luhn_check_digit(partial)


def seed_for(slot: int, middle: int, r: int = 0) -> bytes:
    """Build the seed that decode maps to (slot, middle), bypassing encode."""
    u = slot * MIDDLE_SPACE + middle
    return (r * dte.total_weight * MIDDLE_SPACE + u).to_bytes(dte.seed_length, "big")


# --- contract 1: round trip -------------------------------------------------------------------

def test_round_trip_sampled_cards():
    rng = random.Random(0)
    for _ in range(2000):
        card = dte.sample(rng)
        assert dte.decode(dte.encode(card, rng)) == card


@pytest.mark.parametrize("which", [0, -1])
@pytest.mark.parametrize("middle", [0, MIDDLE_SPACE - 1])
def test_round_trip_first_and_last_bin(which, middle):
    card = card_from(dte.bins[which].bin, middle)
    assert dte.decode(dte.encode(card)) == card


def test_round_trip_every_bin():
    rng = random.Random(3)
    for e in dte.bins:
        card = card_from(e.bin, rng.randrange(MIDDLE_SPACE))
        for _ in range(20):
            assert dte.decode(dte.encode(card, rng)) == card


def test_encode_stays_inside_bin_block():
    # Encode must pick a slot inside the card's own block, never a neighbour's.
    rng = random.Random(4)
    for i, e in enumerate(dte.bins):
        card = card_from(e.bin, 123456789)
        for _ in range(50):
            u = int.from_bytes(dte.encode(card, rng), "big") % (dte.total_weight * MIDDLE_SPACE)
            assert dte.starts[i] <= u // MIDDLE_SPACE < dte.starts[i] + e.weight


# --- interval boundaries (where off-by-one errors would show up) ------------------------------

def test_block_boundaries_map_to_their_bin():
    for i, e in enumerate(dte.bins):
        first, last = dte.starts[i], dte.starts[i] + e.weight - 1
        for slot in (first, last):
            for middle in (0, MIDDLE_SPACE - 1):
                assert dte.decode(seed_for(slot, middle))[:6] == e.bin


def test_blocks_cover_all_slots_exactly_once():
    assert dte.starts[0] == 0
    for i in range(len(dte.bins) - 1):
        assert dte.starts[i] + dte.bins[i].weight == dte.starts[i + 1]
    assert dte.starts[-1] + dte.bins[-1].weight == dte.total_weight


@pytest.mark.parametrize("x", [0, 1, 2**128 - 1, 2**127])
def test_extreme_seeds_decode_to_valid_cards(x):
    card = dte.decode(x.to_bytes(16, "big"))
    assert len(card) == 16 and is_luhn_valid(card) and card[:6] in TABLE_BINS


# --- contract 2: totality ---------------------------------------------------------------------

def test_decode_is_total_and_always_valid():
    rng = random.Random(1)
    for _ in range(5000):
        card = dte.decode(rng.randbytes(dte.seed_length))
        assert len(card) == 16 and card.isdigit()
        assert is_luhn_valid(card)
        assert card[:6] in TABLE_BINS


# --- contract 3: distribution (chi-square) ----------------------------------------------------

N_SAMPLES = 100_000
ALPHA = 0.001


@pytest.fixture(scope="module")
def decoded_bins():
    rng = random.Random(2)  # fixed seed: the test is deterministic, not flaky
    return Counter(dte.decode(rng.randbytes(16))[:6] for _ in range(N_SAMPLES))


def _expected(weights):
    total = sum(weights)
    return [N_SAMPLES * w / total for w in weights]


def test_bin_frequencies_match_weights(decoded_bins):
    observed = [decoded_bins[e.bin] for e in dte.bins]
    assert chisquare(observed, _expected([e.weight for e in dte.bins])).pvalue > ALPHA


def test_network_frequencies_match_weights(decoded_bins):
    network_of = {e.bin: e.network for e in dte.bins}
    counts = Counter()
    for b, n in decoded_bins.items():
        counts[network_of[b]] += n
    nets = dte.network_weights()
    observed = [counts[n] for n in nets]
    assert chisquare(observed, _expected(list(nets.values()))).pvalue > ALPHA


def test_chi_square_detects_wrong_weights(decoded_bins):
    # Control: the test has power. Against a reversed weight table it must reject.
    observed = [decoded_bins[e.bin] for e in dte.bins]
    wrong = [e.weight for e in reversed(dte.bins)]
    assert chisquare(observed, _expected(wrong)).pvalue < ALPHA


def test_middle_digits_uniform():
    rng = random.Random(5)
    counts = Counter()
    for _ in range(20_000):
        counts.update(dte.decode(rng.randbytes(16))[6:15])
    observed = [counts[str(d)] for d in range(10)]
    assert chisquare(observed).pvalue > ALPHA


# --- randomness -------------------------------------------------------------------------------

def test_seeded_rng_is_reproducible():
    card = card_from("411911", 42)
    assert dte.encode(card, random.Random(42)) == dte.encode(card, random.Random(42))
    assert dte.sample(random.Random(7)) == dte.sample(random.Random(7))


def test_encode_is_randomised():
    card = card_from("411911", 42)
    assert dte.encode(card) != dte.encode(card)


def test_seed_length():
    assert len(dte.encode(card_from("524040", 1))) == dte.seed_length


# --- input and table validation ---------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "4119110000000",           # too short
    "41191100000000000",       # too long
    "41191100000000a0",        # not digits
    "4111111111111111",        # Luhn-valid, but BIN 411111 is not in the table
    "378282246310005",         # Amex, 15 digits
])
def test_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        dte.encode(bad)


def test_rejects_bad_luhn():
    card = card_from("411911", 42)
    bad = card[:-1] + str((int(card[-1]) + 1) % 10)
    with pytest.raises(ValueError):
        dte.encode(bad)


@pytest.mark.parametrize("table", [
    [],
    [BinEntry("411911", "visa", "DBS", "credit", 1), BinEntry("411911", "visa", "DBS", "credit", 2)],
    [BinEntry("411911", "visa", "DBS", "credit", 0)],
    [BinEntry("376212", "amex", "Amex", "credit", 1)],
    [BinEntry("511911", "visa", "DBS", "credit", 1)],   # Mastercard prefix labelled visa
    [BinEntry("41191", "visa", "DBS", "credit", 1)],
])
def test_rejects_bad_table(table):
    with pytest.raises(ValueError):
        GoodCardDTE(table)


def test_custom_table_works():
    small = GoodCardDTE([BinEntry("411911", "visa", "DBS", "credit", 3),
                         BinEntry("222345", "mastercard", "DBS", "credit", 1)])
    card = card_from("222345", 999)
    assert small.decode(small.encode(card)) == card
