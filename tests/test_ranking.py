import random

import pytest

from attacks.ranking import order_by_score, rank_of

CANDIDATES = [(f"{i:04d}", i % 3) for i in range(30)]  # scores 0, 1, 2 with ten ties each


def test_orders_by_score_descending():
    ranked = order_by_score(CANDIDATES, lambda c: c[1], random.Random(0))
    scores = [c[1] for c in ranked]
    assert scores == sorted(scores, reverse=True)
    assert sorted(ranked) == sorted(CANDIDATES)  # nothing lost or duplicated


def test_ties_are_reproducible_with_seed():
    a = order_by_score(CANDIDATES, lambda c: c[1], random.Random(1))
    b = order_by_score(CANDIDATES, lambda c: c[1], random.Random(1))
    assert a == b


def test_ties_are_shuffled_not_pin_ordered():
    # If ties fell back to PIN order, 0000 would always be guessed first among equals.
    firsts = {order_by_score(CANDIDATES, lambda c: 0, random.Random(s))[0][0] for s in range(50)}
    assert len(firsts) > 10


def test_all_tied_gives_uniform_rank():
    # With no information, the true PIN's rank is uniform: mean about (n + 1) / 2.
    cands = [(f"{i:04d}", None) for i in range(100)]
    rng = random.Random(2)
    ranks = [rank_of(order_by_score(cands, lambda c: 0, rng), "0000") for _ in range(2000)]
    assert 45 < sum(ranks) / len(ranks) < 56


def test_rank_of():
    ranked = [("1234", "a"), ("0000", "b"), ("9999", "c")]
    assert rank_of(ranked, "1234") == 1
    assert rank_of(ranked, "9999") == 3
    with pytest.raises(ValueError):
        rank_of(ranked, "5555")
