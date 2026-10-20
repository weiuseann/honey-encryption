"""Small all-PIN trials only; real-size enumeration is an explicit experiment."""

import json

import pytest

from experiments.demo_rsa import run_demo, save_result


def deterministic_part(result):
    return {key: value for key, value in result.items() if not key.endswith("seconds")}


def test_small_full_demo_and_repeatability():
    first = run_demo(16, 2026)
    second = run_demo(16, 2026)
    assert deterministic_part(first) == deterministic_part(second)
    assert first["p"] != first["q"]
    assert first["p"] * first["q"] == first["N"]
    assert first["p"].bit_length() == first["q"].bit_length() == 16
    assert first["modulus_bits"] == first["N"].bit_length()
    assert first["candidate_count"] == 10_000
    assert first["correct_pin_recovers_p"] and first["true_pin_survived"]
    assert all(first["N"] % p == 0 for _, p in first["matches"])


def test_tiny_domains_report_ambiguity_instead_of_assuming_one_pin():
    result = run_demo(4, 2026)
    assert result["reduced_size"]
    assert result["matching_pin_count"] == 10_000
    assert result["unique_factor_count"] == 2
    assert result["true_pin_survived"]


def test_benchmark_only_skips_full_enumeration(monkeypatch):
    def forbidden_brute_force(*args):
        raise AssertionError("benchmark-only must not enumerate all PINs")
    monkeypatch.setattr("experiments.demo_rsa.brute_force", forbidden_brute_force)
    result = run_demo(16, 2026, benchmark_guesses=3, benchmark_only=True)
    assert result["status"] == "benchmark-only"
    assert result["benchmark"]["guesses"] == 3
    assert result["benchmark"]["estimated_full_seconds"] >= 0
    assert "candidate_count" not in result


def test_save_result_preserves_pin_text_metadata_and_refuses_overwrite(tmp_path):
    path = tmp_path / "demo.json"
    save_result({"true_pin": "0042"}, path)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["result"]["true_pin"] == "0042"
    assert saved["metadata"]["versions"]["sympy"]
    assert len(saved["metadata"]["source_sha256"]) == 5
    with pytest.raises(FileExistsError):
        save_result({}, path)


@pytest.mark.parametrize("options", [
    {"bits": 2}, {"seed": "2026"}, {"benchmark_guesses": -1},
    {"benchmark_guesses": 10001}, {"benchmark_guesses": True},
    {"benchmark_only": True},
])
def test_invalid_options(options):
    with pytest.raises((TypeError, ValueError)):
        run_demo(**options)
