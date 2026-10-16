"""[STUB] Generate correlated "real" card pairs for the two-card attack.

What goes here:
  A simple, documented model of one person owning two cards, e.g. with
  probability rho both cards come from the same bank, otherwise from two
  independently chosen banks. Both cards must still be valid (real BIN, Luhn)
  so that each card on its own looks like a GoodCardDTE output.
  Sweep rho in the experiments: at rho = 0 (no correlation) the attack should
  fall back to the baseline.

Must take a seeded rng (random.Random) for reproducibility.
"""

from random import Random


def generate_pair(rng: Random, rho: float) -> tuple[str, str]:
    raise NotImplementedError
