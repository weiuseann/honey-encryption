"""Format filtering: throw away candidates that can't be real card numbers.

Checks applied in order to the brute-force candidates, each using only public knowledge:
  1. luhn     16 digits and a valid Luhn check digit  -> keeps about 1/10 of weak-DTE decoys
  2. network  starts with a Visa (4) or Mastercard (51-55, 2221-2720) prefix -> keeps about 15% of those
  3. bin      the 6-digit BIN is in the public BIN table (data/bin_list.csv) -> about 20 of 10^6 prefixes

For the weak DTE that is 10,000 -> ~1,000 -> ~155 -> ~0.02 expected decoys, so the real card is
usually the only survivor. This is the "distribution mismatch" break: the weak DTE decodes to
uniform 16-digit strings, but real cards are not uniform.

Against the good DTE every decoy passes all three checks by construction (it only emits table BINs
and computes the Luhn digit), so the filter removes nothing and success stays at 1/10,000. We assume
the attacker has the same BIN table as the DTE, which is the matched-DTE setting.
"""

from random import Random

from attacks.ranking import order_by_score
from dte.good_card import BIN_DIGITS, N_DIGITS, NETWORK_PREFIXES, BinEntry, load_bins
from dte.luhn import is_luhn_valid

STAGES = ("all", "luhn", "network", "bin")


def _bin_set(bins: list[BinEntry] | None) -> set[str]:
    return {e.bin for e in (load_bins() if bins is None else bins)}


def checks_passed(card: str, bin_set: set[str]) -> int:
    """How many checks, in order, the card passes before the first failure (0 to 3)."""
    if not (isinstance(card, str) and len(card) == N_DIGITS and is_luhn_valid(card)):
        return 0
    prefix = card[:BIN_DIGITS]
    if not any(matches(prefix) for matches in NETWORK_PREFIXES.values()):
        return 1
    if prefix not in bin_set:
        return 2
    return 3


def filter_candidates(candidates: list[tuple[str, str]],
                      bins: list[BinEntry] | None = None) -> dict[str, list[tuple[str, str]]]:
    """Survivors after each stage, keyed by stage name. Stages are cumulative."""
    bin_set = _bin_set(bins)
    passed = [(c, checks_passed(c[1], bin_set)) for c in candidates]
    return {stage: [c for c, n in passed if n >= i] for i, stage in enumerate(STAGES)}


def funnel(candidates: list[tuple[str, str]], bins: list[BinEntry] | None = None) -> dict[str, int]:
    """Number of survivors after each stage, e.g. {'all': 10000, 'luhn': 1003, 'network': 151, 'bin': 1}."""
    return {stage: len(c) for stage, c in filter_candidates(candidates, bins).items()}


def rank_by_format(candidates: list[tuple[str, str]], bins: list[BinEntry] | None = None,
                   rng: Random | None = None) -> list[tuple[str, str]]:
    """Guess order: candidates that pass more checks first, ties in random order."""
    bin_set = _bin_set(bins)
    return order_by_score(candidates, lambda c: checks_passed(c[1], bin_set), rng)
