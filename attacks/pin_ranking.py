"""[STUB] PIN popularity: try likely PINs first.

What goes here (Scenario A, works for any DTE):
  Real users don't pick PINs uniformly (1234, 1111, 0000, birthdays, ...).
  Rank the brute-force candidates by how often their PIN is chosen, using the
  DataGenetics 4-digit PIN frequency analysis (data/pin_frequencies.csv; cite
  it in the slides).

This needs no side information and breaks even a perfect DTE. The 1/10,000
baseline assumes uniform PINs. HE's security bound is roughly the probability
of the most likely PIN, so measure success at rank 1 and compare it with that
bound (experiments/success_vs_baseline.py).
"""


def load_pin_frequencies(path: str = "data/pin_frequencies.csv") -> dict[str, float]:
    raise NotImplementedError


def rank_by_pin_popularity(candidates: list[tuple[str, object]],
                           freqs: dict[str, float]) -> list[tuple[str, object]]:
    """Return candidates sorted from most to least popular PIN."""
    raise NotImplementedError
