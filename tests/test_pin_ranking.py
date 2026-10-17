import csv
import random
from collections import Counter

import pytest

from attacks.pin_ranking import (PIN_PATH, UNIFORM_TAIL_PIN_PATH, load_pin_frequencies,
                                 rank_by_pin_popularity, sample_pin, sample_pins)
from attacks.ranking import rank_of
from data import build_pin_frequencies as build

freqs = load_pin_frequencies()


def tiers(path=PIN_PATH) -> dict[str, str]:
    with open(path, newline="") as f:
        return {row["pin"]: row["tier"] for row in csv.DictReader(f)}


# --- the data file ----------------------------------------------------------------------------

@pytest.mark.parametrize("path", [PIN_PATH, UNIFORM_TAIL_PIN_PATH])
def test_file_covers_every_pin_and_sums_to_one(path):
    f = load_pin_frequencies(path)  # raises if a PIN is missing or the sum is off
    assert len(f) == 10_000 and "0000" in f and "0042" in f


def test_published_values_are_exact():
    for pin, pct in {**build.TOP_20, **build.BOTTOM_21}.items():
        assert freqs[pin] == pytest.approx(pct / 100, rel=1e-9)


def test_calibrated_to_published_half_mass_point():
    assert build.cumulative(freqs, 426) == pytest.approx(0.5, abs=1e-6)


def test_tier_order():
    t = tiers()
    top = min(freqs[p] for p in build.TOP_20)
    pattern = {freqs[p] for p, tier in t.items() if tier == "pattern"}
    base = {freqs[p] for p, tier in t.items() if tier == "base"}
    assert len(pattern) == 1 and len(base) == 1          # one value per assumed tier
    assert max(base) < min(pattern) < top


@pytest.mark.parametrize("pin, tier", [
    ("1984", "pattern"), ("0704", "pattern"), ("0229", "pattern"), ("4545", "pattern"),
    ("1234", "published"), ("8068", "published"),
    ("1332", "base"), ("0230", "base"), ("1899", "base"),
])
def test_pattern_rules(pin, tier):
    assert tiers()[pin] == tier


def test_committed_csv_matches_generator(tmp_path):
    # The CSV must be reproducible from the script, so nobody hand-edits the assumed numbers.
    for model, path in [(build.calibrated_model, PIN_PATH), (build.uniform_tail_model, UNIFORM_TAIL_PIN_PATH)]:
        out = tmp_path / path.name
        build.write_csv(out, *model())
        assert out.read_text() == path.read_text()


# --- the attack -------------------------------------------------------------------------------

CANDIDATES = [(pin, f"decoy-{pin}") for pin in freqs]


def test_most_popular_pins_first():
    ranked = rank_by_pin_popularity(CANDIDATES, freqs, random.Random(0))
    assert [pin for pin, _ in ranked[:5]] == ["1234", "1111", "0000", "1212", "7777"]
    probs = [freqs[pin] for pin, _ in ranked]
    assert probs == sorted(probs, reverse=True)


def test_ties_reproducible_with_seed():
    a = rank_by_pin_popularity(CANDIDATES, freqs, random.Random(1))
    b = rank_by_pin_popularity(CANDIDATES, freqs, random.Random(1))
    assert a == b


def test_top_pin_always_ranked_first():
    # 1234 is the unique most likely PIN, so a victim with 1234 is always found at rank 1, whatever
    # the tie order. With a perfect DTE, rank-1 success is therefore P(1234) = 10.7%.
    for seed in range(10):
        assert rank_of(rank_by_pin_popularity(CANDIDATES, freqs, random.Random(seed)), "1234") == 1


def test_sample_pin_follows_distribution():
    rng = random.Random(3)
    counts = Counter(sample_pins(freqs, 20_000, rng))
    assert counts["1234"] / 20_000 == pytest.approx(0.10713, abs=0.007)
    assert sample_pin(freqs, random.Random(9)) == sample_pin(freqs, random.Random(9))
