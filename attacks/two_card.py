"""k cards encrypted under the same PIN: their correlation gives the real wallet away.

The victim encrypts k cards with one PIN (each with its own salt and nonce). Brute force gives one
candidate WALLET per PIN: the k cards decrypted under that PIN. Under a wrong PIN the DTE decodes
the k seeds independently, so the decoys share a bank only by chance, with probability
S_k = sum_b q_b^k (about 0.20 for k = 2, 0.05 for k = 3, 0.0045 for k = 5 with our table). Under the
right PIN, a real wallet with correlated cards (rho = 1: all from one bank) always does.

Simple rule (default): wallets whose cards all share a bank first, then by PIN popularity, then
random. Most wrong PINs drop behind, so the real wallet beats every surviving decoy whose PIN is
less popular. Same idea as the attack on honey-encrypted password vaults (NoCrack).

Bayes-optimal rule (pass rho): score = P(PIN) * P(wallet | real) / P(wallet | decoy). For a wallet
whose cards all come from bank b, the likelihood ratio is rho * q_b^(1-k) + (1 - rho), and for
mixed banks it is 1 - rho. A match on a rare bank is stronger evidence than on a common one. At
rho = 0 this is exactly PIN ranking and at rho = 1 it eliminates every mixed wallet, so an attacker
using it never does worse than PIN-only. Use it whenever rho is swept.

This only works BECAUSE real cards are correlated while the DTE samples each card independently.
Real wallets must come from the correlated model in experiments/card_pairs.py.
"""

from random import Random

from attacks.brute_force import brute_force
from attacks.ranking import order_by_score
from dte.base import DTE
from dte.good_card import BIN_DIGITS, BinEntry, bank_shares, load_bins
from framework.he import Ciphertext


def brute_force_wallet(ciphertexts: list[Ciphertext], dte: DTE) -> list[tuple[str, tuple]]:
    """[(pin, (card_1, ..., card_k))] for all 10,000 PINs: decrypt every card under each PIN."""
    per_card = [brute_force(ct, dte) for ct in ciphertexts]  # each list is in PIN order
    return [(rows[0][0], tuple(card for _, card in rows)) for rows in zip(*per_card)]


def common_bank(cards, bin_to_bank: dict[str, str]) -> str | None:
    """The bank all cards share, or None (mixed banks, or a BIN outside the table)."""
    banks = {bin_to_bank.get(c[:BIN_DIGITS]) if isinstance(c, str) else None for c in cards}
    if len(banks) == 1:
        (bank,) = banks
        return bank
    return None


def same_bank(cards, bin_to_bank: dict[str, str]) -> bool:
    return common_bank(cards, bin_to_bank) is not None


def rank_wallets(candidates: list[tuple[str, tuple]], freqs: dict[str, float] | None = None,
                 rho: float | None = None, bins: list[BinEntry] | None = None,
                 rng: Random | None = None) -> list[tuple[str, tuple]]:
    """Guess order over candidate wallets.

    rho=None: simple rule, (all cards share a bank, P(PIN)).
    rho given: Bayes-optimal score P(PIN) * likelihood ratio (see module docstring).
    Without freqs, PINs are treated as uniform. Ties are broken randomly.
    """
    bins = load_bins() if bins is None else bins
    bin_to_bank = {e.bin: e.bank for e in bins}

    def pin_prob(pin: str) -> float:
        return freqs[pin] if freqs is not None else 1.0

    if rho is None:
        return order_by_score(candidates, lambda c: (same_bank(c[1], bin_to_bank), pin_prob(c[0])), rng)

    if not 0 <= rho <= 1:
        raise ValueError(f"rho must be in [0, 1], got {rho}")
    shares = bank_shares(bins)

    def bayes_score(c) -> float:
        bank = common_bank(c[1], bin_to_bank)
        k = len(c[1])
        ratio = (1 - rho) + (rho * shares[bank] ** (1 - k) if bank is not None else 0)
        return pin_prob(c[0]) * ratio

    return order_by_score(candidates, bayes_score, rng)
