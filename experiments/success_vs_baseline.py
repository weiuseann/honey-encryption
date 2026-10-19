"""Reproducible attack trials; currently only uniform matched-DTE baselines run.

Other setup names are validated for later integration, not silently substituted.
Results contain metadata, raw trial records, and a pending summary (None).
Ranks identify the original PIN, not the first equal plaintext.
"""

from random import Random

from attacks.brute_force import brute_force
from attacks.format_filter import funnel, rank_by_format
from attacks.ranking import order_by_score, rank_of
from dte.good_card import GoodCardDTE
from framework.he import ALL_PINS, encrypt


# Allowed DTE names, not an implementation/plugin registry.
SETUPS = {
    "baseline": ("good",), "baseline-format": ("good",),
    "format": ("weak", "good"), "pin": ("weak", "good"),
    "format-pin": ("weak", "good"),
    "side-bank": ("good",), "side-last4": ("good",),
    "side-bank-last4": ("good",), "side-bank-last4-pin": ("good",),
    "wallet-simple": ("good",), "wallet-simple-pin": ("good",),
    "wallet-bayes-pin": ("good",), "rsa-verify": ("rsa",),
}
PRIORS = ("uniform", "calibrated", "uniform-tail")


def validate_setup(setup: str, n_trials: int = 1000, seed: int = 0, *,
                   dte: str = "good", prior: str = "uniform",
                   k: int | None = None, rho: float | None = None) -> dict:
    """Validate and normalize experiment options without loading data or running trials."""
    if not isinstance(setup, str) or setup not in SETUPS:
        raise ValueError(f"unknown setup; choose one of {', '.join(SETUPS)}")
    if isinstance(n_trials, bool) or not isinstance(n_trials, int) or n_trials < 1:
        raise ValueError("n_trials must be a positive integer")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    if dte not in SETUPS[setup]:
        raise ValueError(f"{setup} requires dte in {SETUPS[setup]}")
    if prior not in PRIORS:
        raise ValueError(f"prior must be one of {PRIORS}")
    if setup in ("baseline", "baseline-format", "rsa-verify") and prior != "uniform":
        raise ValueError(f"{setup} requires a uniform prior")

    if setup.startswith("wallet-"):
        k = 2 if k is None else k
        rho = 1.0 if rho is None else rho
        if isinstance(k, bool) or not isinstance(k, int) or k not in (2, 3, 5):
            raise ValueError("wallet k must be 2, 3, or 5")
        if isinstance(rho, bool) or not isinstance(rho, (int, float)) or not 0 <= rho <= 1:
            raise ValueError("rho must be a number in [0, 1]")
        if setup != "wallet-bayes-pin" and rho != 1:
            raise ValueError("rho sweeps require wallet-bayes-pin")
    elif k is not None or rho is not None:
        raise ValueError("k and rho apply only to wallet setups")

    return {"setup": setup, "n_trials": n_trials, "seed": seed,
            "dte": dte, "prior": prior, "k": k, "rho": rho}


def run_trials(setup: str, n_trials: int = 1000, seed: int = 0, *,
               dte: str = "good", prior: str = "uniform",
               k: int | None = None, rho: float | None = None) -> dict:
    """Return seeded raw baseline trials; summaries, saving, and other attacks follow later."""
    options = validate_setup(setup, n_trials, seed, dte=dte, prior=prior, k=k, rho=rho)
    if setup not in ("baseline", "baseline-format"):
        raise NotImplementedError(f"{setup} is defined but not integrated yet")

    rng = Random(seed)
    good = GoodCardDTE()
    trials = []
    for trial in range(1, n_trials + 1):
        card = good.sample(rng)
        pin = rng.choice(ALL_PINS)
        ciphertext = encrypt(good, card, pin, rng)
        candidates = brute_force(ciphertext, good)
        if setup == "baseline":
            ranked = order_by_score(candidates, lambda candidate: 0, rng)
        else:
            ranked = rank_by_format(candidates, good.bins, rng)
        record = {"trial": trial, "setup": setup, "true_pin": pin,
                  "rank": rank_of(ranked, pin), "candidate_count": len(candidates)}
        if setup == "baseline-format":
            record["format_funnel"] = funnel(candidates, good.bins)
        trials.append(record)

    return {
        "metadata": {**options, "candidate_space": len(ALL_PINS),
                     "rank_one_reference": 1 / len(ALL_PINS)},
        "trials": trials,
        "summary": None,
    }


if __name__ == "__main__":
    raise NotImplementedError("Use run_trials directly; the experiment CLI is a later task")
