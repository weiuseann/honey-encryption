"""RSA domain and decoding tests; encoding is not implemented yet."""

from math import isqrt
from random import Random
from unittest.mock import Mock, call

import pytest
from sympy import nextprime

from dte.rsa_prime import RSAPrimeDTE, _sample_seed_integer


@pytest.mark.parametrize(
    "bits, lower, upper, largest_prime, seed_bytes",
    [
        (3, 4, 7, 7, 17),
        (4, 8, 15, 13, 17),
        (8, 128, 255, 251, 17),
        (16, 32768, 65535, 65521, 18),
    ],
)
def test_domain_boundaries(bits, lower, upper, largest_prime, seed_bytes):
    dte = RSAPrimeDTE(bits)

    assert dte.bits == bits
    assert (dte.lower_bound, dte.upper_bound) == (lower, upper)
    assert dte.max_prime == largest_prime
    assert dte.max_prime.bit_length() == bits
    assert dte.x_min == lower - 1

    last_x = dte.x_min + dte.modulus - 1
    assert last_x == largest_prime - 1
    assert int(nextprime(last_x)) == largest_prime
    assert int(nextprime(dte.x_min)).bit_length() == bits
    assert int(nextprime(largest_prime)) > upper

    assert dte.seed_length == seed_bytes
    assert dte.seed_space_size == 256**seed_bytes
    assert 8 * seed_bytes >= bits + 128
    assert 8 * (seed_bytes - 1) < bits + 128


def test_four_bit_range_covers_exactly_the_allowed_primes():
    dte = RSAPrimeDTE(4)

    assert dte.x_min == 7
    assert dte.modulus == 6
    xs = range(dte.x_min, dte.x_min + dte.modulus)
    assert [int(nextprime(x)) for x in xs] == [11, 11, 11, 11, 13, 13]
    # Using all 4-bit integers directly would allow a 5-bit decoded prime.
    assert int(nextprime(15)) == 17
    assert (17).bit_length() == 5


@pytest.mark.parametrize("bits", [True, False, 4.0, "4", None])
def test_rejects_non_integer_bit_counts(bits):
    with pytest.raises(TypeError, match="bits must be an integer"):
        RSAPrimeDTE(bits)


@pytest.mark.parametrize("bits", [-10, -1, 0, 1, 2])
def test_rejects_bit_counts_below_three(bits):
    with pytest.raises(ValueError, match="bits must be at least 3"):
        RSAPrimeDTE(bits)


def small_is_prime(n):
    """Independent trial-division oracle for the small domains used in tests."""
    return n >= 2 and all(n % divisor for divisor in range(2, isqrt(n) + 1))


@pytest.mark.parametrize("bits", [3, 4, 8])
def test_decode_every_residue_matches_independently_enumerated_primes(bits):
    dte = RSAPrimeDTE(bits)
    primes = [n for n in range(dte.lower_bound, dte.upper_bound + 1) if small_is_prime(n)]
    outputs = set()

    for residue in range(dte.modulus):
        x = dte.x_min + residue
        expected = next(prime for prime in primes if prime > x)
        # Exercise each residue both near zero and near the top of seed space.
        last_seed = dte.seed_space_size - 1
        largest_matching_seed = last_seed - (last_seed - residue) % dte.modulus
        for value in (residue, largest_matching_seed):
            result = dte.decode(value.to_bytes(dte.seed_length, "big"))
            assert type(result) is int
            assert result == expected
            outputs.add(result)

    assert outputs == set(primes)


@pytest.mark.parametrize("bits", [3, 4, 8, 16])
def test_decode_extreme_and_random_seeds_always_gives_valid_prime(bits):
    dte = RSAPrimeDTE(bits)
    rng = Random(2026)
    seeds = [bytes(dte.seed_length), b"\xff" * dte.seed_length]
    seeds += [rng.randbytes(dte.seed_length) for _ in range(200)]

    for seed in seeds:
        result = dte.decode(seed)
        assert type(result) is int
        assert result.bit_length() == bits
        assert small_is_prime(result)


def test_decode_four_bit_boundaries_and_modulo_wrap():
    dte = RSAPrimeDTE(4)
    examples = {0: 11, 3: 11, 4: 13, 5: 13, 6: 11, 10: 13}
    for seed_integer, expected in examples.items():
        assert dte.decode(seed_integer.to_bytes(dte.seed_length, "big")) == expected
    assert int(nextprime(11)) == 13  # The prime input itself is skipped.


@pytest.mark.parametrize("length", [0, 1, 16, 18])
def test_decode_rejects_wrong_seed_length(length):
    dte = RSAPrimeDTE(4)  # Expected seed length is 17 bytes.
    with pytest.raises(ValueError, match="seed must be exactly 17 bytes"):
        dte.decode(bytes(length))


@pytest.mark.parametrize(
    "space_size, modulus, lo, hi",
    [(16, 6, 0, 3), (16, 6, 4, 5), (16, 6, 2, 5),
     (16, 6, 4, 4), (12, 6, 0, 5)],
)
def test_seed_sampler_proposals_cover_each_valid_seed_once(space_size, modulus, lo, hi):
    expected = [z for z in range(space_size) if lo <= z % modulus <= hi]
    accepted = []

    for residue in range(lo, hi + 1):
        for repetition in range(space_size // modulus + 1):
            proposal = repetition * modulus + residue
            rng = Mock(spec=Random)
            # A rejected proposal is followed by the known valid seed lo.
            rng.randrange.side_effect = [residue, repetition, lo, 0]
            result = _sample_seed_integer(lo, hi, modulus, space_size, rng)
            assert rng.randrange.call_args_list[:2] == [
                call(lo, hi + 1), call(space_size // modulus + 1),
            ]
            if proposal < space_size:
                assert result == proposal
                assert rng.randrange.call_count == 2
                accepted.append(result)
            else:
                assert result == lo
                assert rng.randrange.call_count == 4

    # List equality also detects duplicated seeds, not just missing ones.
    assert sorted(accepted) == expected


def test_seed_sampler_toy_prime_thirteen_preimages():
    expected = [4, 5, 10, 11]
    actual = []
    for residue, repetition in [(4, 0), (5, 0), (4, 1), (5, 1)]:
        rng = Mock(spec=Random)
        rng.randrange.side_effect = [residue, repetition]
        actual.append(_sample_seed_integer(4, 5, 6, 16, rng))
    assert actual == expected


def test_seed_sampler_retries_out_of_range_proposal():
    rng = Mock(spec=Random)
    rng.randrange.side_effect = [5, 2, 4, 1]  # Propose 17 (invalid), then 10.
    assert _sample_seed_integer(4, 5, 6, 16, rng) == 10
    assert rng.randrange.call_count == 4


def test_seed_sampler_is_reproducible_and_respects_real_seed_capacity():
    dte = RSAPrimeDTE(4)

    def samples(rng):
        return [_sample_seed_integer(4, 5, dte.modulus, dte.seed_space_size, rng)
                for _ in range(50)]

    first = samples(Random(2026))
    assert first == samples(Random(2026))
    assert len(set(first)) > 1
    for seed_integer in first:
        assert 0 <= seed_integer < dte.seed_space_size
        assert seed_integer % dte.modulus in (4, 5)
        assert dte.decode(seed_integer.to_bytes(dte.seed_length, "big")) == 13
