"""PIN popularity: try likely PINs first.

Real users don't pick PINs uniformly (1234, 1111, 0000, dates, years, ...). The attacker ranks the
brute-force candidates by the prior probability of their PIN (data/pin_frequencies.csv, built from
the DataGenetics analysis, see data/README.md).

This needs no side information and breaks even a perfect DTE, because it attacks the other
assumption behind the 1/10,000 baseline: that PINs are uniform. A perfect DTE makes every candidate
equally plausible as a message, so the only remaining signal is the PIN itself, and the attacker's
rank-1 success becomes the probability of the most popular PIN (1234: 10.7%). That is HE's
security bound with non-uniform keys.

Assumption: the attacker knows the PIN distribution exactly (the same table we use to draw victim
PINs). This is the strongest attacker. Our table understates how concentrated real PINs are (see
DECISIONS.md), so measured success is a conservative lower bound.
"""

import csv
from pathlib import Path
from random import Random

from attacks.ranking import order_by_score
from dte.base import default_rng

PIN_PATH = Path(__file__).resolve().parent.parent / "data" / "pin_frequencies.csv"
UNIFORM_TAIL_PIN_PATH = PIN_PATH.with_name("pin_frequencies_uniform_tail.csv")


def load_pin_frequencies(path: str | Path = PIN_PATH) -> dict[str, float]:
    """All 10,000 PINs (as 4-character strings, leading zeros kept) -> probability."""
    with open(path, newline="") as f:
        freqs = {row["pin"]: float(row["frequency"]) for row in csv.DictReader(f)}
    expected = {f"{i:04d}" for i in range(10_000)}
    if freqs.keys() != expected:
        raise ValueError(f"{path} must list every PIN 0000-9999 exactly once")
    if abs(sum(freqs.values()) - 1) > 1e-6:
        raise ValueError(f"{path}: frequencies sum to {sum(freqs.values())}, not 1")
    return freqs


def rank_by_pin_popularity(candidates: list[tuple[str, object]], freqs: dict[str, float],
                           rng: Random | None = None) -> list[tuple[str, object]]:
    """Guess order: most popular PIN first. PINs with equal probability are tried in random order."""
    return order_by_score(candidates, lambda c: freqs[c[0]], rng)


def sample_pins(freqs: dict[str, float], k: int, rng: Random | None = None) -> list[str]:
    """Draw k victim PINs from the distribution (experiments pass a seeded rng).

    One call for many PINs: the cumulative weights over 10,000 PINs are built once, not per PIN.
    """
    rng = rng or default_rng()
    pins = list(freqs)
    return rng.choices(pins, weights=[freqs[p] for p in pins], k=k)


def sample_pin(freqs: dict[str, float], rng: Random | None = None) -> str:
    """Draw one victim PIN from the distribution."""
    return sample_pins(freqs, 1, rng)[0]
