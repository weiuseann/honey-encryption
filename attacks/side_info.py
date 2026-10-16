"""[STUB] Side information about the victim narrows the candidates.

What goes here (Scenario A):
  The good DTE matches the card distribution of the whole population, not
  of this particular victim. Each piece of public or leaked information
  removes decoys:
    - victim's bank (e.g. DBS): keep only candidates whose BIN belongs to
      that bank; 10,000 candidates drop to a few hundred
    - card product (e.g. a specific DBS Visa): drops to a handful
    - last 4 digits (printed on receipts, shown in apps): about 1 in 10,000
      decoys match, so roughly one decoy plus the real card survive

Evaluate each piece of side info separately (agreed), then optionally combine
them with PIN ranking.
"""


def filter_by_bank(candidates, bank: str):
    raise NotImplementedError


def filter_by_product(candidates, product: str):
    raise NotImplementedError


def filter_by_last4(candidates, last4: str):
    raise NotImplementedError
