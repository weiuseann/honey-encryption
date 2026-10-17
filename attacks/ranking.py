"""Shared helpers: every attack returns the order in which the attacker would guess candidates.

An attack is a scoring rule over the brute-force candidates [(pin, message)]. The attacker guesses
in order of decreasing score, so the output of an attack is a ranked list, and the experiment harness
records the rank of the true PIN in it. Rank 1 means the attacker's first guess is right.
"""

from random import Random

from dte.base import default_rng


def order_by_score(candidates, score, rng: Random | None = None) -> list[tuple[str, object]]:
    """Sort candidates by score (highest first), breaking ties at random.

    Random tie-breaking is essential, not cosmetic. Against the good DTE every candidate passes the
    format filter, so all 10,000 tie. Breaking ties by PIN order would always guess 0000 first, and
    with popular PINs among the victims that would push success above 1/10,000 for no real reason.
    An attacker who can't tell candidates apart can do no better than guessing among them uniformly.
    Experiments pass a seeded rng so the tie order is reproducible.
    """
    rng = rng or default_rng()
    shuffled = list(candidates)
    rng.shuffle(shuffled)
    # sorted() is stable (also with reverse=True), so tied candidates keep their shuffled order.
    return sorted(shuffled, key=score, reverse=True)


def rank_of(ranked: list[tuple[str, object]], true_pin: str) -> int:
    """1-based position of the true PIN in the attacker's guess order."""
    for i, (pin, _) in enumerate(ranked, start=1):
        if pin == true_pin:
            return i
    raise ValueError(f"PIN {true_pin!r} not among the candidates")
