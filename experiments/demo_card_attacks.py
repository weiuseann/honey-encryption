"""Demo: where does the real card land under each attack, for the weak and the good card DTE?

Run from the repo root:  python -m experiments.demo_card_attacks [--trials N]

Real cards are drawn from the good DTE (GoodCardDTE.sample) and victim PINs from the calibrated
DataGenetics model (see DECISIONS.md). The same real card is encrypted under both DTEs, so the only
difference between the two rows is the DTE. The side-info rows (good DTE only) give the attacker the
real card's bank and last 4 digits, assumed accurate. The wallet rows (good DTE only) encrypt k cards
from one bank (rho = 1, experiments/card_pairs.py) under the victim's PIN and rank the candidate
wallets with attacks/two_card.py: "bank" = simple same-bank rule only, "bank+PIN" = simple rule with
PIN popularity, "Bayes" = Bayes-optimal score at rho = 1. This is a quick illustration with a
fixed seed; the full experiment with plots belongs in experiments/success_vs_baseline.py.
"""

import argparse
import random
import statistics

from attacks.brute_force import brute_force
from attacks.format_filter import checks_passed, funnel, rank_by_format
from attacks.pin_ranking import load_pin_frequencies, rank_by_pin_popularity, sample_pin
from attacks.ranking import order_by_score, rank_of
from attacks.side_info import rank_by_bank, rank_by_last4, rank_by_side_info
from attacks.two_card import brute_force_wallet, rank_wallets
from dte.good_card import GoodCardDTE
from dte.weak_card import WeakCardDTE
from experiments.card_pairs import encrypt_wallet, generate_wallet
from framework.he import encrypt

SEED = 2026
N_TRIALS = 200
WALLET_SIZES = (2, 3, 5)


def attack_ranks(candidates, pin, freqs, bins, bin_set, rng) -> dict[str, int]:
    return {
        "format filter": rank_of(rank_by_format(candidates, bins, rng), pin),
        "PIN ranking": rank_of(rank_by_pin_popularity(candidates, freqs, rng), pin),
        # Combined: filter first, then most popular PIN among the survivors.
        "format + PIN": rank_of(
            order_by_score(candidates, lambda c: (checks_passed(c[1], bin_set), freqs[c[0]]), rng), pin),
    }


def side_info_ranks(candidates, card, pin, freqs, bins, rng) -> dict[str, int]:
    bank = {e.bin: e.bank for e in bins}[card[:6]]
    last4 = card[-4:]
    return {
        "bank": rank_of(rank_by_bank(candidates, bank, bins, rng), pin),
        "last-4": rank_of(rank_by_last4(candidates, last4, rng), pin),
        "bank + last-4": rank_of(rank_by_side_info(candidates, bank, last4, bins=bins, rng=rng), pin),
        "bank+last4+PIN": rank_of(rank_by_side_info(candidates, bank, last4, freqs, bins, rng), pin),
    }


def wallet_ranks(good, pin, freqs, bins, rng) -> dict[str, int]:
    ranks = {}
    for k in WALLET_SIZES:
        wallet = generate_wallet(good, k, 1.0, rng)
        candidates = brute_force_wallet(encrypt_wallet(good, wallet, pin, rng), good)
        ranks[f"{k} cards: bank"] = rank_of(rank_wallets(candidates, bins=bins, rng=rng), pin)
        ranks[f"{k} cards: bank+PIN"] = rank_of(rank_wallets(candidates, freqs, bins=bins, rng=rng), pin)
        ranks[f"{k} cards: Bayes"] = rank_of(rank_wallets(candidates, freqs, rho=1.0, bins=bins, rng=rng), pin)
    return ranks


def main(n_trials: int = N_TRIALS) -> None:
    rng = random.Random(SEED)
    freqs = load_pin_frequencies()
    good = GoodCardDTE()
    bins, bin_set = good.bins, {e.bin for e in good.bins}
    dtes = {"weak DTE": WeakCardDTE(), "good DTE": good}
    print(f"seed = {SEED}\n")

    # One worked example.
    card, pin = good.sample(rng), sample_pin(freqs, rng)
    print(f"Worked example: real card {card}, PIN {pin}")
    for name, dte in dtes.items():
        candidates = brute_force(encrypt(dte, card, pin, rng), dte)
        print(f"  {name}: funnel {funnel(candidates, bins)}")
        print(f"  {name}: rank of real card {attack_ranks(candidates, pin, freqs, bins, bin_set, rng)}")
        if dte is good:
            print(f"  {name}: with side info {side_info_ranks(candidates, card, pin, freqs, bins, rng)}")

    # Many trials.
    ranks = {name: {} for name in dtes}
    for _ in range(n_trials):
        card, pin = good.sample(rng), sample_pin(freqs, rng)
        for name, dte in dtes.items():
            candidates = brute_force(encrypt(dte, card, pin, rng), dte)
            results = attack_ranks(candidates, pin, freqs, bins, bin_set, rng)
            if dte is good:
                results |= side_info_ranks(candidates, card, pin, freqs, bins, rng)
                results |= wallet_ranks(good, pin, freqs, bins, rng)
            for attack, r in results.items():
                ranks[name].setdefault(attack, []).append(r)

    print(f"\n{n_trials} trials. Baseline (uniform PINs, matched DTE): rank-1 success 0.0001. "
          f"Most popular PIN: {max(freqs.values()):.4f}")
    print(f"{'':10} {'attack':20} {'rank-1 success':>15} {'median rank':>12}")
    for name, by_attack in ranks.items():
        for attack, rs in by_attack.items():
            success = sum(r == 1 for r in rs) / len(rs)
            print(f"{name:10} {attack:20} {success:>15.3f} {statistics.median(rs):>12g}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--trials", type=int, default=N_TRIALS, help=f"number of trials (default {N_TRIALS})")
    main(parser.parse_args().trials)
