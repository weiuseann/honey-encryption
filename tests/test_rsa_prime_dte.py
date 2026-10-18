"""RSA domain, sampling, and round-trip tests."""

from math import isqrt
from random import Random
from unittest.mock import Mock, call

import pytest
from sympy import nextprime

from dte.rsa_prime import RSAPrimeDTE, _sample_seed_integer, generate_real_prime


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


@pytest.mark.parametrize("bits", [3, 4, 8])
def test_encode_round_trip_every_prime_in_small_domains(bits):
    dte = RSAPrimeDTE(bits)
    rng = Random(2026)
    for prime in range(dte.lower_bound, dte.upper_bound + 1):
        if small_is_prime(prime):
            for _ in range(3):
                seed = dte.encode(prime, rng)
                assert type(seed) is bytes
                assert len(seed) == dte.seed_length
                assert dte.decode(seed) == prime


def test_encode_round_trip_seeded_sixteen_bit_prime_samples():
    dte = RSAPrimeDTE(16)
    rng = Random(2026)
    for _ in range(100):
        prime = dte.decode(rng.randbytes(dte.seed_length))
        assert dte.decode(dte.encode(prime, rng)) == prime


@pytest.mark.parametrize(
    "bits, prime, first_residue, last_residue",
    [(3, 5, 0, 1), (3, 7, 2, 3), (4, 11, 0, 3), (4, 13, 4, 5),
     (8, 131, 0, 3), (8, 251, 114, 123), (16, 32771, 0, 3)],
)
def test_encode_prime_gap_endpoints(bits, prime, first_residue, last_residue):
    dte = RSAPrimeDTE(bits)
    for residue in (first_residue, last_residue):
        rng = Mock(spec=Random)
        rng.randrange.side_effect = [residue, 0]
        seed = dte.encode(prime, rng)
        assert rng.randrange.call_args_list[0] == call(first_residue, last_residue + 1)
        assert int.from_bytes(seed, "big") == residue
        assert len(seed) == dte.seed_length
        assert dte.decode(seed) == prime


def test_encode_can_choose_distinct_seeds_for_the_same_prime():
    dte = RSAPrimeDTE(4)
    rng = Mock(spec=Random)
    rng.randrange.side_effect = [4, 0, 5, 1]
    first, second = dte.encode(13, rng), dte.encode(13, rng)
    assert first != second
    assert dte.decode(first) == dte.decode(second) == 13


def test_encode_is_reproducible_with_seeded_rng():
    dte = RSAPrimeDTE(8)
    assert dte.encode(251, Random(2026)) == dte.encode(251, Random(2026))


def test_encode_uses_secure_default_only_without_caller_rng(monkeypatch):
    dte = RSAPrimeDTE(4)
    default_factory = Mock(return_value=Random(2026))
    monkeypatch.setattr("dte.rsa_prime.default_rng", default_factory)

    expected = dte.encode(13, Random(2026))
    default_factory.assert_not_called()
    assert dte.encode(13) == expected
    default_factory.assert_called_once_with()


@pytest.mark.parametrize("message", [True, False, 11.0, "11", None])
def test_encode_rejects_non_integer_messages(message):
    with pytest.raises(TypeError, match="message must be an integer prime"):
        RSAPrimeDTE(4).encode(message)


@pytest.mark.parametrize("message", [-11, 0, 1, 2, 7, 16, 17])
def test_encode_rejects_out_of_domain_messages(message):
    with pytest.raises(ValueError, match="message must be a 4-bit prime"):
        RSAPrimeDTE(4).encode(message)


@pytest.mark.parametrize("message", [8, 9, 10, 12])
def test_encode_rejects_composites_in_domain(message):
    with pytest.raises(ValueError, match="message must be prime"):
        RSAPrimeDTE(4).encode(message)


@pytest.mark.parametrize("bits", [3, 4, 8, 16])
def test_generated_primes_are_in_domain_and_can_be_encoded(bits):
    dte = RSAPrimeDTE(bits)
    rng = Random(2026)
    for _ in range(30):
        prime = generate_real_prime(bits, rng)
        assert type(prime) is int
        assert prime.bit_length() == bits
        assert small_is_prime(prime)
        assert dte.lower_bound <= prime <= dte.max_prime
        assert dte.decode(dte.encode(prime, rng)) == prime


@pytest.mark.parametrize(
    "bits, smallest_prime, largest_prime",
    [(3, 5, 7), (4, 11, 13), (8, 131, 251), (16, 32771, 65521)],
)
def test_prime_generator_can_reach_both_domain_boundaries(bits, smallest_prime, largest_prime):
    for prime in (smallest_prime, largest_prime):
        rng = Mock(spec=Random)
        rng.randrange.return_value = prime
        assert generate_real_prime(bits, rng) == prime
        rng.randrange.assert_called_once_with(2 ** (bits - 1) + 1, largest_prime + 1, 2)


def test_prime_generator_retries_composites_without_using_decoder(monkeypatch):
    def forbidden_decode(*args):
        raise AssertionError("real-prime generation must not sample via decode")

    monkeypatch.setattr(RSAPrimeDTE, "decode", forbidden_decode)
    rng = Mock(spec=Random)
    rng.randrange.side_effect = [9, 13]
    assert generate_real_prime(4, rng) == 13
    assert rng.randrange.call_args_list == [call(9, 14, 2), call(9, 14, 2)]


def test_prime_generator_is_reproducible():
    def samples(rng):
        return [generate_real_prime(16, rng) for _ in range(20)]

    assert samples(Random(2026)) == samples(Random(2026))


def test_prime_generator_uses_secure_default_only_without_caller_rng(monkeypatch):
    default_factory = Mock(return_value=Random(2026))
    monkeypatch.setattr("dte.rsa_prime.default_rng", default_factory)
    expected = generate_real_prime(16, Random(2026))
    default_factory.assert_not_called()
    assert generate_real_prime(16) == expected
    default_factory.assert_called_once_with()


@pytest.mark.parametrize("bits", [True, False, 4.0, "4", None])
def test_prime_generator_rejects_non_integer_bit_counts(bits):
    with pytest.raises(TypeError, match="bits must be an integer"):
        generate_real_prime(bits)


@pytest.mark.parametrize("bits", [-10, -1, 0, 1, 2])
def test_prime_generator_rejects_bit_counts_below_three(bits):
    with pytest.raises(ValueError, match="bits must be at least 3"):
        generate_real_prime(bits)
