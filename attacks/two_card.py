"""[STUB] Two cards encrypted under the same PIN: correlation gives the real pair away.

What goes here (Scenario A):
  The victim encrypts two cards with one PIN. Brute force gives one candidate
  PAIR per PIN. Under a wrong PIN, the DTE decodes the two seeds
  independently, so the two decoys are unrelated (usually different banks).
  Under the right PIN, the pair looks like one person's wallet (e.g. the same
  bank). Score each pair by how plausible it is as a single owner's cards and
  rank by that score. Same idea as the attack on honey-encrypted password
  vaults (NoCrack).

Important (agreed): this only works BECAUSE the real cards are correlated
while the DTE samples each card independently. The real test pairs must come
from a correlated model (experiments/card_pairs.py), not from two independent
draws. Otherwise the attack trivially fails and proves nothing.
"""


def pair_score(card_a: str, card_b: str) -> float:
    """How likely it is that the two cards belong to the same person (higher = more likely)."""
    raise NotImplementedError


def rank_pairs(candidate_pairs: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """candidate_pairs: [(pin, card_a, card_b)]. Return them ranked by pair_score."""
    raise NotImplementedError
