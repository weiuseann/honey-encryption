"""[STUB] Good credit card DTE: decoys that match the real card-number distribution.

What goes here (Scenario A, owner: card half):
  Decoding a uniform seed should give a card number distributed like real
  cards. Use inverse-CDF sampling: split the seed into chunks and use each
  chunk to pick, in order,
    1. the network (Visa / Mastercard / ...) by its market share,
    2. a real BIN (first 6-8 digits) within that network, weighted by
       frequency (data/bin_list.csv),
    3. the middle account digits, uniformly,
    4. the Luhn check digit (computed, not sampled).
  encode must invert this: for each step, pick a random seed value inside
  the interval that maps to the real card's choice. This "random point in the
  right interval" step is what makes encode(real card) look uniform. It is
  also the trickiest part to get exactly right (interval boundaries, rounding).

Validation required (agreed):
  - round-trip tests: decode(encode(m)) == m, including first/last BIN in the
    table and boundary seeds
  - totality: decode never raises on random seeds
  - distribution check: decode many random seeds and run a chi-square test
    (scipy.stats.chisquare) of observed network/BIN frequencies against the
    table weights
"""

from random import Random

from dte.base import DTE


class GoodCardDTE(DTE):
    seed_length: int  # to be chosen; leave enough slack bits that rounding bias is negligible

    def encode(self, message: str, rng: Random | None = None) -> bytes:
        raise NotImplementedError

    def decode(self, seed: bytes) -> str:
        raise NotImplementedError
