"""[STUB] Main experiment: how far does attacker success rise above 1/10,000?

What goes here:
  For each setup (DTE x attack x side info), run about 1,000 trials:
    1. pick a real message and a PIN (uniform, or drawn from the DataGenetics
       PIN distribution, depending on the setup)
    2. encrypt, brute force, apply the attack and get a ranked candidate list
    3. record the rank of the real message
  Report success at rank 1 (plus the rank distribution) next to:
    - the 1/10,000 baseline (uniform PINs, matched DTE, no side info)
    - the theoretical bound: about the probability of the most likely PIN
  Plot with matplotlib.

Reproducibility: every trial MUST use a seeded random.Random passed to
encrypt()/encode(). Record the seed in the output.
"""


def run_trials(setup: str, n_trials: int = 1000, seed: int = 0):
    raise NotImplementedError


if __name__ == "__main__":
    raise NotImplementedError
