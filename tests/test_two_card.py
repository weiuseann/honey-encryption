import random

import pytest

from attacks.pin_ranking import load_pin_frequencies, rank_by_pin_popularity
from attacks.ranking import rank_of
from attacks.two_card import brute_force_wallet, common_bank, rank_wallets, same_bank
from dte.good_card import GoodCardDTE, bank_shares
from dte.luhn import luhn_check_digit
from experiments.card_pairs import encrypt_wallet, generate_wallet
from framework.he import ALL_PINS

good = GoodCardDTE()
BIN_TO_BANK = {e.bin: e.bank for e in good.bins}
SHARES = bank_shares(good.bins)
freqs = load_pin_frequencies()
TRUE_PIN = "4821"


def card(bin_: str, middle: int = 123456789) -> str:
    partial = bin_ + f"{middle:09d}"
    return partial + luhn_check_digit(partial)


DBS = (card("411911"), card("455622"))
MAYBANK = (card("496643", 1), card("496643", 2))
MIXED = (card("411911"), card("524040"))   # DBS + OCBC


def synthetic_wallets(k: int, seed: int) -> tuple[list[tuple[str, tuple]], tuple]:
    """brute_force_wallet-shaped candidates without AES: decoy cards are independent DTE decodes."""
    rng = random.Random(seed)
    real = tuple(generate_wallet(good, k, 1.0, rng))
    cands = [(pin, real if pin == TRUE_PIN else tuple(good.decode(rng.randbytes(16)) for _ in range(k)))
             for pin in ALL_PINS]
    return cands, real


# --- helpers ----------------------------------------------------------------------------------

def test_common_bank():
    assert common_bank(DBS, BIN_TO_BANK) == "DBS"
    assert common_bank(MIXED, BIN_TO_BANK) is None
    assert common_bank(("4111111111111111", "4111111111111111"), BIN_TO_BANK) is None  # not in table
    assert same_bank(MAYBANK, BIN_TO_BANK) and not same_bank(MIXED, BIN_TO_BANK)


def test_brute_force_wallet_groups_by_pin():
    rng = random.Random(0)
    wallet = generate_wallet(good, 2, 1.0, rng)
    cands = brute_force_wallet(encrypt_wallet(good, wallet, TRUE_PIN, rng), good)
    assert [pin for pin, _ in cands] == ALL_PINS
    assert dict(cands)[TRUE_PIN] == tuple(wallet)
    assert all(len(cards) == 2 for _, cards in cands)


# --- simple rule ------------------------------------------------------------------------------

def test_simple_rule_same_bank_first_then_pin():
    cands = [("1332", MIXED), ("1234", MIXED), ("1333", DBS), ("1111", MAYBANK)]
    ranked = rank_wallets(cands, freqs, rng=random.Random(1))
    assert [pin for pin, _ in ranked] == ["1111", "1333", "1234", "1332"]


@pytest.mark.parametrize("k, S", [(2, sum(q**2 for q in SHARES.values())),
                                  (5, sum(q**5 for q in SHARES.values()))])
def test_decoy_same_bank_rate(k, S):
    cands, _ = synthetic_wallets(k, seed=k)
    survivors = sum(same_bank(cards, BIN_TO_BANK) for _, cards in cands) - 1   # minus the real wallet
    assert abs(survivors - 9999 * S) < 5 * (9999 * S * (1 - S)) ** 0.5 + 1


def test_real_wallet_ranked_among_same_bank_sets():
    cands, _ = synthetic_wallets(5, seed=7)
    survivors = sum(same_bank(cards, BIN_TO_BANK) for _, cards in cands)
    assert rank_of(rank_wallets(cands, rng=random.Random(8)), TRUE_PIN) <= survivors


# --- Bayes-optimal rule -----------------------------------------------------------------------

def test_bayes_rare_bank_beats_common_bank():
    # Same (base-tier) PIN probability; a Maybank match is stronger evidence than a DBS match.
    assert freqs["1332"] == freqs["1333"]
    cands = [("1333", DBS), ("1332", MAYBANK)]
    ranked = rank_wallets(cands, freqs, rho=1.0, rng=random.Random(2))
    assert [pin for pin, _ in ranked] == ["1332", "1333"]


def test_bayes_rho_one_drops_mixed_wallets():
    cands = [("1234", MIXED), ("1332", DBS)]
    ranked = rank_wallets(cands, freqs, rho=1.0, rng=random.Random(3))
    assert ranked[0][0] == "1332"


def test_bayes_rho_zero_is_pin_ranking():
    cands, _ = synthetic_wallets(2, seed=4)
    assert rank_wallets(cands, freqs, rho=0.0, rng=random.Random(5)) == \
        rank_by_pin_popularity(cands, freqs, random.Random(5))


def test_bayes_rejects_bad_rho():
    with pytest.raises(ValueError):
        rank_wallets([("1234", DBS)], freqs, rho=1.2)


def test_reproducible_with_seed():
    cands, _ = synthetic_wallets(3, seed=6)
    assert rank_wallets(cands, freqs, rng=random.Random(9)) == rank_wallets(cands, freqs, rng=random.Random(9))
