"""Generate correlated "real" card wallets (k cards owned by one person) for the two-card attack.

Model (rho = probability that all k cards share one bank):
  - with probability rho: draw one bank by its share of the BIN table, then draw each of the k cards
    from the good DTE conditioned on that bank;
  - otherwise: draw the k cards independently from the good DTE (they may still share a bank by
    chance, with probability sum_b q_b^k).

Each card on its own still has exactly the good DTE's distribution: the bank is drawn with
probability q_b and, given the bank, the BIN and digits are drawn as the DTE would. So a single card
reveals nothing new, and the two-card attack can only exploit the correlation BETWEEN the cards,
which the DTE (decoding each seed independently) cannot reproduce.

Victim side of the experiment. All functions take an rng; experiments pass a seeded random.Random.
"""

from random import Random

from dte.base import default_rng
from dte.good_card import BIN_DIGITS, GoodCardDTE, bank_shares
from framework.he import Ciphertext, encrypt


def sample_card_from_bank(dte: GoodCardDTE, bank: str, rng: Random | None = None) -> str:
    """A card from the good DTE conditioned on its bank (rejection sampling: exact, if not fast)."""
    rng = rng or default_rng()
    bin_to_bank = {e.bin: e.bank for e in dte.bins}
    if bank not in bin_to_bank.values():
        raise ValueError(f"unknown bank {bank!r}")
    # Expected tries are 1/q_bank (about 22 for the smallest bank), which is cheap.
    while True:
        card = dte.sample(rng)
        if bin_to_bank[card[:BIN_DIGITS]] == bank:
            return card


def generate_wallet(dte: GoodCardDTE, k: int, rho: float, rng: Random | None = None) -> list[str]:
    if k < 1:
        raise ValueError(f"k must be at least 1, got {k}")
    if not 0 <= rho <= 1:
        raise ValueError(f"rho must be in [0, 1], got {rho}")
    rng = rng or default_rng()
    if rng.random() < rho:
        shares = bank_shares(dte.bins)
        banks = list(shares)
        bank = rng.choices(banks, weights=[shares[b] for b in banks])[0]
        return [sample_card_from_bank(dte, bank, rng) for _ in range(k)]
    return [dte.sample(rng) for _ in range(k)]


def generate_pair(rng: Random, rho: float, dte: GoodCardDTE | None = None) -> tuple[str, str]:
    a, b = generate_wallet(dte or GoodCardDTE(), 2, rho, rng)
    return a, b


def encrypt_wallet(dte: GoodCardDTE, cards: list[str], pin: str,
                   rng: Random | None = None) -> list[Ciphertext]:
    """Encrypt every card under the same PIN, each with its own salt and nonce.

    A fresh nonce per card matters: reusing (key, nonce) in CTR would reuse the keystream and leak
    the XOR of two seeds. The attack doesn't need that; it simply groups decryptions by PIN.
    """
    return [encrypt(dte, card, pin, rng) for card in cards]
