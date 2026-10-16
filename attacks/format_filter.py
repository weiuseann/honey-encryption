"""[STUB] Format filtering: throw away candidates that can't be real card numbers.

What goes here (Scenario A):
  Apply increasingly strict checks to the brute-force candidate list:
    1. Luhn check digit valid  -> keeps about 1/10 of weak-DTE decoys
    2. valid network prefix    -> keeps fewer still
    3. BIN in the real BIN table (data/bin_list.csv) -> keeps about 1 decoy
  Report how many candidates survive each stage.

Expected result: breaks WeakCardDTE (distribution mismatch). Against
GoodCardDTE every decoy passes all three checks, so this attack should leave
success at the 1/10,000 baseline.
"""


def luhn_valid(card: str) -> bool:
    raise NotImplementedError


def filter_candidates(candidates: list[tuple[str, str]]) -> dict[str, list[tuple[str, str]]]:
    """Return the surviving candidates after each filter stage, keyed by stage name."""
    raise NotImplementedError
