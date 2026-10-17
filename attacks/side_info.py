"""Side information about the victim narrows the candidates.

The good DTE matches the card distribution of the whole population, not of this particular victim.
Any fact the attacker knows about the victim's card is a filter that every decoy must also pass,
and decoys pass it only by chance:
  - bank (e.g. DBS): a decoy matches with probability q = that bank's share of the BIN weights, so
    about 10,000*q candidates survive. Averaged over victims, rank-1 success is roughly
    (number of banks) / 10,000, only a few times the baseline.
  - last 4 digits (printed on receipts, shown in banking apps): the last 4 are 3 uniform middle
    digits plus the Luhn check digit, which is close to uniform because it depends on those uniform
    digits. A decoy matches with probability about 1/10^4, so about one decoy survives and the real
    card is ranked first about 1 - 1/e = 63% of the time.
  - both: about q decoys survive, so rank-1 success is about 90%; ranking survivors by PIN
    popularity pushes it to about 95%.

The candidates matching every known fact are ranked first, then PIN popularity (if given) breaks
ties among them. Candidates matching only some facts are certainly decoys, so their order among
themselves cannot affect the real card's rank; one "consistent with everything" flag is enough.

Assumption: the side information is accurate. If it were wrong, the real card would rank last.
"""

from collections.abc import Callable
from random import Random

from attacks.ranking import order_by_score
from dte.good_card import BIN_DIGITS, BinEntry, load_bins


def _bin_to_bank(bins: list[BinEntry] | None) -> dict[str, str]:
    return {e.bin: e.bank for e in (load_bins() if bins is None else bins)}


def matches_bank(card: str, bank: str, bin_to_bank: dict[str, str]) -> bool:
    # A BIN outside the table (e.g. a weak-DTE decoy) belongs to no known bank, so it never matches.
    return isinstance(card, str) and bin_to_bank.get(card[:BIN_DIGITS]) == bank


def matches_last4(card: str, last4: str) -> bool:
    return isinstance(card, str) and card[-4:] == last4


def consistency_score(bank: str | None = None, last4: str | None = None,
                      bins: list[BinEntry] | None = None) -> Callable[[tuple[str, str]], int]:
    """Score function: 1 if a candidate is consistent with every known fact, else 0.

    A fact left as None is unknown and not checked.
    """
    bin_to_bank = _bin_to_bank(bins)
    if bank is not None and bank not in bin_to_bank.values():
        # Fail loudly: a typo such as "dbs" would otherwise silently match nothing.
        raise ValueError(f"unknown bank {bank!r}; banks in the table: {sorted(set(bin_to_bank.values()))}")
    if last4 is not None and (len(last4) != 4 or not last4.isdigit()):
        raise ValueError(f"last4 must be 4 digits, got {last4!r}")

    def score(candidate: tuple[str, str]) -> int:
        card = candidate[1]
        if bank is not None and not matches_bank(card, bank, bin_to_bank):
            return 0
        if last4 is not None and not matches_last4(card, last4):
            return 0
        return 1

    return score


def rank_by_bank(candidates: list[tuple[str, str]], bank: str, bins: list[BinEntry] | None = None,
                 rng: Random | None = None) -> list[tuple[str, str]]:
    """Guess order: candidates from the victim's bank first, ties in random order."""
    return order_by_score(candidates, consistency_score(bank=bank, bins=bins), rng)


def rank_by_last4(candidates: list[tuple[str, str]], last4: str,
                  rng: Random | None = None) -> list[tuple[str, str]]:
    """Guess order: candidates ending in the known last 4 digits first, ties in random order."""
    return order_by_score(candidates, consistency_score(last4=last4), rng)


def rank_by_side_info(candidates: list[tuple[str, str]], bank: str | None = None,
                      last4: str | None = None, freqs: dict[str, float] | None = None,
                      bins: list[BinEntry] | None = None,
                      rng: Random | None = None) -> list[tuple[str, str]]:
    """The realistic attacker: consistent candidates first, then most popular PIN, then random."""
    consistent = consistency_score(bank=bank, last4=last4, bins=bins)
    if freqs is None:
        return order_by_score(candidates, consistent, rng)
    return order_by_score(candidates, lambda c: (consistent(c), freqs[c[0]]), rng)
