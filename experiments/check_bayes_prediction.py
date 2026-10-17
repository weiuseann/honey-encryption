"""Check the two-card attack's predicted rank-1 success against a full-pipeline run.

Run from the repo root:
    python -m experiments.check_bayes_prediction                    # k = 5, 1,000 trials
    python -m experiments.check_bayes_prediction --k 3 --trials 0   # prediction only

Prediction (no simulation): with rho = 1, the real wallet's bank B is drawn with probability q_B and
its PIN from the PIN table. Each of the 9,999 wrong PINs independently gives a same-bank decoy wallet
from bank b with probability q_b^k (the DTE decodes the k cards independently); mixed wallets score
0 under both rules and can't beat the real wallet. A decoy beats the real wallet if its score is
higher, and ties are broken randomly. The number of decoys above (or tied with) the real wallet is a
sum of many rare independent events, so we approximate it as Poisson:
    P(win) = exp(-expected decoys above) * E[1 / (1 + ties)],  E[1/(1+X)] = (1 - e^-m) / m for X ~ Poisson(m).
PINs are grouped by probability value (about 40 distinct values), so this takes well under a second.

Measurement: generate wallets (experiments/card_pairs.py), encrypt, brute force, rank with
attacks/two_card.py, and re-check every Bayes ranking against an independently computed score.
"""

import argparse
import math
import random
from collections import defaultdict

from attacks.pin_ranking import load_pin_frequencies, sample_pin
from attacks.ranking import rank_of
from attacks.two_card import brute_force_wallet, rank_wallets
from dte.good_card import BIN_DIGITS, GoodCardDTE, bank_shares
from experiments.card_pairs import encrypt_wallet, generate_wallet

SEED = 7000
DEFAULT_K = 5
DEFAULT_TRIALS = 1000


def predict(score, freqs: dict[str, float], q: dict[str, float], k: int) -> tuple[float, dict[str, float]]:
    """P(real wallet ranked first), overall and per victim bank. score(pin_prob, bank) -> number."""
    pins_with_prob = defaultdict(int)
    for f in freqs.values():
        pins_with_prob[f] += 1
    total = 0.0
    by_bank = defaultdict(float)
    for f_real, n_real in pins_with_prob.items():
        for bank_real, q_real in q.items():
            s_real = score(f_real, bank_real)
            above = tied = 0.0
            for f, n in pins_with_prob.items():
                n_decoys = n - (1 if f == f_real else 0)  # the real PIN is not a decoy
                for b, qb in q.items():
                    expected = n_decoys * qb**k            # expected same-bank decoys of this kind
                    s = score(f, b)
                    if math.isclose(s, s_real, rel_tol=1e-9):
                        tied += expected
                    elif s > s_real:
                        above += expected
            tie_factor = 1.0 if tied == 0 else (1 - math.exp(-tied)) / tied
            p_win = math.exp(-above) * tie_factor
            weight = n_real * f_real * q_real              # P(victim has this PIN value and bank)
            total += weight * p_win
            by_bank[bank_real] += weight * p_win
    return total, {b: by_bank[b] / q[b] for b in q}


def measure(k: int, n_trials: int, good: GoodCardDTE, freqs: dict[str, float], q: dict[str, float]):
    rng = random.Random(SEED)
    bin_to_bank = {e.bin: e.bank for e in good.bins}

    def independent_score(candidate) -> float:
        banks = {bin_to_bank[card[:BIN_DIGITS]] for card in candidate[1]}
        return freqs[candidate[0]] * q[banks.pop()] ** (1 - k) if len(banks) == 1 else 0.0

    hits = {"simple": 0, "bayes": 0}
    by_bank = defaultdict(lambda: [0, 0])  # bank -> [Bayes wins, trials]
    for t in range(n_trials):
        wallet = generate_wallet(good, k, 1.0, rng)
        pin = sample_pin(freqs, rng)
        candidates = brute_force_wallet(encrypt_wallet(good, wallet, pin, rng), good)
        hits["simple"] += rank_of(rank_wallets(candidates, freqs, rng=rng), pin) == 1
        ranked = rank_wallets(candidates, freqs, rho=1.0, rng=rng)
        rank = rank_of(ranked, pin)

        # Independent check: the order must be sorted by score, and the real wallet's rank must fall
        # inside its tie group.
        scores = [independent_score(c) for c in ranked]
        if any(a < b for a, b in zip(scores, scores[1:])):
            raise AssertionError(f"trial {t}: Bayes order is not sorted by score")
        real = independent_score((pin, tuple(wallet)))
        above, tied = sum(s > real for s in scores), sum(s == real for s in scores)
        if not above < rank <= above + tied:
            raise AssertionError(f"trial {t}: rank {rank} inconsistent with scores")

        hits["bayes"] += rank == 1
        bank = bin_to_bank[wallet[0][:BIN_DIGITS]]
        by_bank[bank][0] += rank == 1
        by_bank[bank][1] += 1
        if (t + 1) % 200 == 0:
            print(f"  {t + 1} trials done", flush=True)
    return hits, by_bank


def main(k: int, n_trials: int) -> None:
    good = GoodCardDTE()
    freqs = load_pin_frequencies()
    q = bank_shares(good.bins)

    p_simple, _ = predict(lambda f, b: f, freqs, q, k)  # only same-bank decoys count, so: PIN prob
    p_bayes, bayes_by_bank = predict(lambda f, b: f * q[b] ** (1 - k), freqs, q, k)
    print(f"k = {k}, rho = 1")
    print(f"predicted rank-1 success: simple + PIN {p_simple:.3f}, Bayes {p_bayes:.3f}")
    if n_trials == 0:
        return

    print(f"\nmeasuring: {n_trials} trials, seed {SEED}")
    hits, by_bank = measure(k, n_trials, good, freqs, q)
    for name, h in hits.items():
        p = h / n_trials
        print(f"measured {name}: {p:.3f} (95% CI +/- {1.96 * (p * (1 - p) / n_trials) ** 0.5:.3f})")
    print("\nBayes by victim's bank      share   1/q^(k-1)   predicted   measured")
    for b in sorted(q, key=q.get, reverse=True):
        wins, trials = by_bank[b]
        measured = f"{wins}/{trials} = {wins / trials:.2f}" if trials else "no trials"
        print(f"  {b:24} {q[b]:.3f} {q[b] ** (1 - k):>11,.0f} {bayes_by_bank[b]:>11.3f}   {measured}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--k", type=int, default=DEFAULT_K, help=f"cards per wallet (default {DEFAULT_K})")
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS,
                        help=f"pipeline trials (default {DEFAULT_TRIALS}; 0 = prediction only)")
    args = parser.parse_args()
    main(args.k, args.trials)
