import random
from collections import Counter

import pytest
from scipy.stats import chisquare

from dte.good_card import GoodCardDTE, bank_shares
from dte.luhn import is_luhn_valid
from experiments.card_pairs import (encrypt_wallet, generate_pair, generate_wallet,
                                    sample_card_from_bank)
from framework.he import decrypt

good = GoodCardDTE()
BIN_TO_BANK = {e.bin: e.bank for e in good.bins}
SHARES = bank_shares(good.bins)
S2 = sum(q**2 for q in SHARES.values())  # P(two independent cards share a bank), about 0.20


def banks(wallet):
    return {BIN_TO_BANK[c[:6]] for c in wallet}


def test_bank_shares_sum_to_one():
    assert sum(SHARES.values()) == pytest.approx(1)
    assert SHARES["DBS"] == pytest.approx(0.33)


def test_sample_card_from_bank():
    rng = random.Random(0)
    for bank in SHARES:
        card = sample_card_from_bank(good, bank, rng)
        assert BIN_TO_BANK[card[:6]] == bank and is_luhn_valid(card)
    with pytest.raises(ValueError):
        sample_card_from_bank(good, "dbs", rng)


@pytest.mark.parametrize("k", [1, 2, 3, 5])
def test_wallet_cards_are_valid(k):
    wallet = generate_wallet(good, k, 0.5, random.Random(k))
    assert len(wallet) == k
    assert all(len(c) == 16 and is_luhn_valid(c) and c[:6] in BIN_TO_BANK for c in wallet)


def test_rho_one_always_same_bank():
    rng = random.Random(1)
    assert all(len(banks(generate_wallet(good, 3, 1.0, rng))) == 1 for _ in range(300))


@pytest.mark.parametrize("rho, expected", [(0.0, S2), (0.5, 0.5 + 0.5 * S2)])
def test_same_bank_rate_matches_rho(rho, expected):
    # Independent wallets still share a bank by chance, so P(same) = rho + (1 - rho) * S2.
    rng = random.Random(2)
    n = 3000
    same = sum(len(banks(generate_wallet(good, 2, rho, rng))) == 1 for _ in range(n))
    sd = (expected * (1 - expected) / n) ** 0.5
    assert abs(same / n - expected) < 4 * sd


def test_single_card_marginal_matches_dte():
    # Correlation must not change what one card looks like: its bank still follows the table.
    rng = random.Random(3)
    counts = Counter(BIN_TO_BANK[generate_wallet(good, 2, 1.0, rng)[0][:6]] for _ in range(5000))
    names = list(SHARES)
    observed = [counts[b] for b in names]
    assert chisquare(observed, [5000 * SHARES[b] for b in names]).pvalue > 0.001


def test_reproducible_with_seed():
    assert generate_wallet(good, 3, 0.7, random.Random(4)) == generate_wallet(good, 3, 0.7, random.Random(4))
    assert generate_pair(random.Random(5), 1.0) == generate_pair(random.Random(5), 1.0)


@pytest.mark.parametrize("k, rho", [(0, 1.0), (2, -0.1), (2, 1.5)])
def test_rejects_bad_parameters(k, rho):
    with pytest.raises(ValueError):
        generate_wallet(good, k, rho, random.Random(0))


def test_encrypt_wallet_uses_fresh_salt_and_nonce():
    rng = random.Random(6)
    wallet = generate_wallet(good, 3, 1.0, rng)
    cts = encrypt_wallet(good, wallet, "1234", rng)
    assert len({ct.salt for ct in cts}) == 3 and len({ct.nonce for ct in cts}) == 3
    assert [decrypt(good, ct, "1234") for ct in cts] == wallet
