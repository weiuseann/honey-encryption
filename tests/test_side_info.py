import random
from collections import Counter

import pytest

from attacks.brute_force import brute_force
from attacks.pin_ranking import load_pin_frequencies
from attacks.ranking import rank_of
from attacks.side_info import (consistency_score, matches_bank, matches_last4, rank_by_bank,
                               rank_by_last4, rank_by_side_info)
from dte.good_card import GoodCardDTE
from dte.luhn import luhn_check_digit
from dte.weak_card import WeakCardDTE
from framework.he import ALL_PINS, encrypt

good = GoodCardDTE()
BIN_TO_BANK = {e.bin: e.bank for e in good.bins}
freqs = load_pin_frequencies()
TRUE_PIN = "4821"


def with_check(partial: str) -> str:
    return partial + luhn_check_digit(partial)


DBS_CARD = with_check("411911" + "123456789")       # DBS Visa
POSB_CARD = with_check("526471" + "123456789")      # POSB Mastercard


def synthetic_candidates(seed: int, dte=good) -> tuple[list[tuple[str, str]], str]:
    rng = random.Random(seed)
    real = good.sample(rng)
    cands = [(pin, real if pin == TRUE_PIN else dte.decode(rng.randbytes(16))) for pin in ALL_PINS]
    return cands, real


# --- matching rules ---------------------------------------------------------------------------

def test_matches_bank():
    assert matches_bank(DBS_CARD, "DBS", BIN_TO_BANK)
    assert not matches_bank(DBS_CARD, "OCBC", BIN_TO_BANK)
    assert not matches_bank("4111111111111111", "DBS", BIN_TO_BANK)   # BIN not in table


def test_dbs_and_posb_are_separate_banks():
    assert not matches_bank(POSB_CARD, "DBS", BIN_TO_BANK)
    assert matches_bank(POSB_CARD, "POSB", BIN_TO_BANK)


def test_matches_last4():
    assert matches_last4(DBS_CARD, DBS_CARD[-4:])
    assert not matches_last4(DBS_CARD, "0000" if DBS_CARD[-4:] != "0000" else "1111")


def test_consistency_score_checks_every_known_fact():
    both = consistency_score(bank="DBS", last4=DBS_CARD[-4:])
    assert both(("0000", DBS_CARD)) == 1
    assert both(("0000", POSB_CARD)) == 0                              # wrong bank
    other_last4 = with_check("411911" + "000000000")
    assert both(("0000", other_last4)) == (other_last4[-4:] == DBS_CARD[-4:])
    assert consistency_score()(("0000", "anything")) == 1              # nothing known


@pytest.mark.parametrize("kwargs", [{"bank": "dbs"}, {"bank": "Nonexistent Bank"},
                                    {"last4": "123"}, {"last4": "12a4"}])
def test_rejects_bad_side_info(kwargs):
    with pytest.raises(ValueError):
        consistency_score(**kwargs)


def test_weak_dte_candidates_never_raise():
    cands, real = synthetic_candidates(0, dte=WeakCardDTE())
    ranked = rank_by_side_info(cands, bank=BIN_TO_BANK[real[:6]], last4=real[-4:], freqs=freqs,
                               rng=random.Random(0))
    assert rank_of(ranked, TRUE_PIN) == 1


# --- survivor counts against the good DTE -----------------------------------------------------

@pytest.fixture(scope="module")
def good_case():
    return synthetic_candidates(1)


def test_bank_keeps_about_its_share(good_case):
    cands, real = good_case
    bank = BIN_TO_BANK[real[:6]]
    share = sum(e.weight for e in good.bins if e.bank == bank) / good.total_weight
    survivors = sum(consistency_score(bank=bank)(c) for c in cands)
    expected = 1 + 9999 * share
    assert abs(survivors - expected) < 5 * (9999 * share * (1 - share)) ** 0.5


def test_last4_match_rate_is_about_one_in_ten_thousand():
    # Pooled over many candidate lists: about 1 decoy per 10,000 matches the real last 4.
    rng = random.Random(2)
    decoy_matches = 0
    for _ in range(20):
        real = good.sample(rng)
        decoy_matches += sum(good.decode(rng.randbytes(16))[-4:] == real[-4:] for _ in range(9999))
    assert 5 <= decoy_matches <= 40   # expected about 20


def test_last4_check_digit_is_close_to_uniform():
    # Why last-4 is still ~1/10^4 although the 4th digit is computed: it depends on uniform digits.
    rng = random.Random(3)
    counts = Counter(good.decode(rng.randbytes(16))[-1] for _ in range(20_000))
    assert all(1700 < counts[str(d)] < 2300 for d in range(10))


# --- rankings ---------------------------------------------------------------------------------

def test_rank_by_bank_puts_bank_matches_first(good_case):
    cands, real = good_case
    bank = BIN_TO_BANK[real[:6]]
    ranked = rank_by_bank(cands, bank, rng=random.Random(4))
    flags = [matches_bank(c, bank, BIN_TO_BANK) for _, c in ranked]
    n = sum(flags)
    assert all(flags[:n]) and not any(flags[n:])
    assert rank_of(ranked, TRUE_PIN) <= n


def test_rank_by_last4_puts_real_card_among_few(good_case):
    cands, real = good_case
    ranked = rank_by_last4(cands, real[-4:], rng=random.Random(5))
    assert rank_of(ranked, TRUE_PIN) <= sum(matches_last4(c, real[-4:]) for _, c in cands)


def test_pin_breaks_ties_among_consistent_candidates():
    # Two consistent candidates: the one with the more popular PIN must come first.
    cands = [("1234", DBS_CARD), ("4821", DBS_CARD), ("1111", POSB_CARD)]
    ranked = rank_by_side_info(cands, bank="DBS", freqs=freqs, rng=random.Random(6))
    assert [pin for pin, _ in ranked] == ["1234", "4821", "1111"]


def test_rank_by_side_info_reproducible(good_case):
    cands, real = good_case
    kw = dict(bank=BIN_TO_BANK[real[:6]], last4=real[-4:], freqs=freqs)
    assert rank_by_side_info(cands, rng=random.Random(7), **kw) == rank_by_side_info(cands, rng=random.Random(7), **kw)


def test_end_to_end_bank_and_last4():
    rng = random.Random(8)
    real = good.sample(rng)
    cands = brute_force(encrypt(good, real, TRUE_PIN, rng), good)
    ranked = rank_by_side_info(cands, bank=BIN_TO_BANK[real[:6]], last4=real[-4:], rng=rng)
    survivors = sum(consistency_score(bank=BIN_TO_BANK[real[:6]], last4=real[-4:])(c) for c in cands)
    assert rank_of(ranked, TRUE_PIN) <= survivors <= 4
