import random

import pytest

from attacks.brute_force import brute_force
from attacks.format_filter import STAGES, checks_passed, filter_candidates, funnel, rank_by_format
from attacks.ranking import rank_of
from dte.good_card import GoodCardDTE
from dte.luhn import luhn_check_digit
from dte.weak_card import WeakCardDTE
from framework.he import ALL_PINS, encrypt

good = GoodCardDTE()
weak = WeakCardDTE()
BIN_SET = {e.bin for e in good.bins}
TRUE_PIN = "4821"


def with_check(partial: str) -> str:
    return partial + luhn_check_digit(partial)


def synthetic_candidates(dte, seed: int) -> tuple[list[tuple[str, str]], str]:
    """Same shape as brute_force output, without the AES cost: decoys are decoded random seeds."""
    rng = random.Random(seed)
    real = good.sample(rng)
    cands = [(pin, real if pin == TRUE_PIN else dte.decode(rng.randbytes(16))) for pin in ALL_PINS]
    return cands, real


# --- individual checks ------------------------------------------------------------------------

@pytest.mark.parametrize("card, expected", [
    (with_check("411911" + "123456789"), 3),   # table BIN
    ("4111111111111111", 2),                    # Visa prefix, Luhn-valid, BIN not in table
    ("6011111111111117", 1),                    # Discover: Luhn-valid but not Visa/Mastercard
    ("4111111111111112", 0),                    # bad check digit
    ("378282246310005", 0),                     # Amex, 15 digits
    ("41111111111111a1", 0),
])
def test_checks_passed(card, expected):
    assert checks_passed(card, BIN_SET) == expected


@pytest.mark.parametrize("prefix, is_network", [
    ("222100", True), ("222099", False), ("272099", True), ("272100", False),
    ("510000", True), ("559999", True), ("500000", False), ("560000", False),
])
def test_mastercard_prefix_boundaries(prefix, is_network):
    assert (checks_passed(with_check(prefix + "000000000"), set()) >= 2) == is_network


# --- weak DTE: the funnel ---------------------------------------------------------------------

@pytest.fixture(scope="module")
def weak_case():
    return synthetic_candidates(weak, seed=0)


def test_weak_funnel_shrinks_at_each_stage(weak_case):
    cands, real = weak_case
    f = funnel(cands)
    assert list(f) == list(STAGES)
    assert f["all"] == 10_000
    assert 850 < f["luhn"] < 1150       # about 1/10
    assert 100 < f["network"] < 220     # about 15.5% of the Luhn survivors
    assert 1 <= f["bin"] <= 3           # the real card plus ~0.02 expected decoys
    assert (TRUE_PIN, real) in filter_candidates(cands)["bin"]


def test_weak_real_card_ranked_near_top(weak_case):
    cands, _ = weak_case
    rank = rank_of(rank_by_format(cands, rng=random.Random(1)), TRUE_PIN)
    assert rank <= funnel(cands)["bin"]


def test_weak_end_to_end_with_encryption():
    rng = random.Random(2)
    real = good.sample(rng)
    cands = brute_force(encrypt(weak, real, TRUE_PIN, rng), weak)
    survivors = filter_candidates(cands)["bin"]
    assert (TRUE_PIN, real) in survivors and len(survivors) <= 3


# --- good DTE: every decoy survives -----------------------------------------------------------

def test_good_dte_survives_every_stage():
    cands, _ = synthetic_candidates(good, seed=3)
    assert funnel(cands) == {stage: 10_000 for stage in STAGES}


def test_good_end_to_end_with_encryption():
    rng = random.Random(4)
    cands = brute_force(encrypt(good, good.sample(rng), TRUE_PIN, rng), good)
    assert funnel(cands) == {stage: 10_000 for stage in STAGES}


def test_good_dte_rank_is_uniform():
    # All candidates tie, so the format filter gives no advantage: mean rank about 5,000.
    cands, _ = synthetic_candidates(good, seed=5)
    rng = random.Random(6)
    ranks = [rank_of(rank_by_format(cands, rng=rng), TRUE_PIN) for _ in range(30)]
    assert 3000 < sum(ranks) / len(ranks) < 7000  # mean of 30 uniform ranks: sd about 530
