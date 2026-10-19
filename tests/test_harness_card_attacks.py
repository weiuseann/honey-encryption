"""Exercise the harness composition, leaving attack mathematics to Seann's tests."""

from random import Random

import pytest

from experiments import success_vs_baseline as harness
from experiments.results import load_results, save_results
from framework.he import ALL_PINS


@pytest.mark.parametrize("setup", ["pin", "format-pin"])
@pytest.mark.parametrize("dte", ["weak", "good"])
def test_popularity_real_pipeline_is_reproducible(setup, dte):
    first = harness.run_trials(setup, 1, 2026, dte=dte, prior="calibrated")
    second = harness.run_trials(setup, 1, 2026, dte=dte, prior="calibrated")
    assert first["trials"] == second["trials"]
    assert first["summary"] == second["summary"]
    assert first["trials"][0]["candidate_count"] == 10000
    assert first["metadata"]["max_pin_prior_reference"] == pytest.approx(0.10713)
    assert "data/pin_frequencies.csv" in first["metadata"]["environment"]["data_sha256"]


def test_selected_prior_is_loaded_once_and_used_for_both_sides(monkeypatch):
    freqs = dict.fromkeys(ALL_PINS, 0.0)
    freqs["0007"] = 1.0
    loads = []

    def load(path):
        loads.append(path)
        return freqs

    monkeypatch.setattr(harness, "load_pin_frequencies", load)
    result = harness.run_trials("pin", 2, 5, prior="calibrated")
    assert loads == [harness.PIN_PATH]
    assert [(r["true_pin"], r["rank"]) for r in result["trials"]] == [("0007", 1)] * 2
    assert result["metadata"]["max_pin_prior_reference"] == 1


def test_format_precedes_popularity_in_combined_ranking(monkeypatch):
    freqs = dict.fromkeys(ALL_PINS, 0.0)
    freqs.update({"0007": 0.1, "1234": 0.9})
    captured = {}
    original = harness.encrypt

    def encrypt(dte, card, pin, rng):
        captured["card"] = card
        return original(dte, card, pin, rng)

    monkeypatch.setattr(harness, "load_pin_frequencies", lambda path: freqs)
    monkeypatch.setattr(harness, "sample_pins", lambda *args: ["0007"])
    monkeypatch.setattr(harness, "encrypt", encrypt)
    monkeypatch.setattr(harness, "brute_force", lambda *args:
                        [(p, captured["card"] if p == "0007" else "invalid") for p in ALL_PINS])
    assert harness.run_trials("pin", 1, prior="calibrated")["trials"][0]["rank"] == 2
    assert harness.run_trials("format-pin", 1, prior="calibrated")["trials"][0]["rank"] == 1


def test_accurate_side_facts_precede_a_more_popular_inconsistent_candidate(monkeypatch):
    freqs = dict.fromkeys(ALL_PINS, 0.0)
    freqs.update({"0007": 0.1, "1234": 0.9})
    captured = {}
    original = harness.encrypt

    def encrypt(dte, card, pin, rng):
        captured["card"] = card
        return original(dte, card, pin, rng)

    monkeypatch.setattr(harness, "load_pin_frequencies", lambda path: freqs)
    monkeypatch.setattr(harness, "sample_pins", lambda *args: ["0007"])
    monkeypatch.setattr(harness, "encrypt", encrypt)
    monkeypatch.setattr(harness, "brute_force", lambda *args:
                        [(p, captured["card"] if p == "0007" else "invalid") for p in ALL_PINS])
    assert harness.run_trials("side-bank-last4-pin", 1, prior="calibrated")["trials"][0]["rank"] == 1


def test_uniform_popularity_control_matches_all_tied_baseline():
    baseline = harness.run_trials("baseline", 1, 2026)
    popular = harness.run_trials("pin", 1, 2026)
    assert baseline["trials"][0]["rank"] == popular["trials"][0]["rank"]
    assert "data/pin_frequencies.csv" not in popular["metadata"]["environment"]["data_sha256"]


def test_alternate_prior_records_actual_input_table():
    result = harness.run_trials("pin", 1, 2026, prior="uniform-tail")
    assert "data/pin_frequencies_uniform_tail.csv" in result["metadata"]["environment"]["data_sha256"]


@pytest.mark.parametrize("setup", ["side-bank", "side-last4", "side-bank-last4",
                                  "side-bank-last4-pin"])
def test_side_information_passes_only_declared_facts(setup, monkeypatch):
    captured, calls = {}, []
    original_encrypt, original_rank = harness.encrypt, harness.rank_by_side_info

    def encrypt(dte, card, pin, rng):
        captured.update(card=card, pin=pin, bins=dte.bins)
        return original_encrypt(dte, card, pin, rng)

    def rank(candidates, **kwargs):
        calls.append(kwargs)
        assert dict(candidates)[captured["pin"]] == captured["card"]
        return original_rank(candidates, **kwargs)

    monkeypatch.setattr(harness, "encrypt", encrypt)
    monkeypatch.setattr(harness, "rank_by_side_info", rank)
    first = harness.run_trials(setup, 1, 2026, prior="calibrated")
    second = harness.run_trials(setup, 1, 2026, prior="calibrated")
    assert first["trials"] == second["trials"]
    bank = {e.bin: e.bank for e in captured["bins"]}[captured["card"][:6]]
    for call in calls:
        assert call["bank"] == (bank if "bank" in setup else None)
        assert call["last4"] == (captured["card"][-4:] if "last4" in setup else None)
        assert (call["freqs"] is not None) == setup.endswith("-pin")
        assert isinstance(call["rng"], Random)


@pytest.mark.parametrize("setup", ["wallet-simple", "wallet-simple-pin", "wallet-bayes-pin"])
def test_wallet_real_grouping_and_saved_result(setup, monkeypatch, tmp_path):
    captured = {}
    original_encrypt, original_brute = harness.encrypt_wallet, harness.brute_force_wallet

    def encrypt(dte, cards, pin, rng):
        ciphertexts = original_encrypt(dte, cards, pin, rng)
        assert len({ct.salt for ct in ciphertexts}) == len(cards)
        assert len({ct.nonce for ct in ciphertexts}) == len(cards)
        captured.update(cards=tuple(cards), pin=pin)
        return ciphertexts

    def brute(ciphertexts, dte):
        candidates = original_brute(ciphertexts, dte)
        assert [p for p, _ in candidates] == ALL_PINS
        assert dict(candidates)[captured["pin"]] == captured["cards"]
        assert all(len(cards) == 2 for _, cards in candidates)
        return candidates

    monkeypatch.setattr(harness, "encrypt_wallet", encrypt)
    monkeypatch.setattr(harness, "brute_force_wallet", brute)
    result = harness.run_trials(setup, 1, 2026, prior="calibrated")
    repeated = harness.run_trials(setup, 1, 2026, prior="calibrated")
    assert result["trials"] == repeated["trials"]
    row = result["trials"][0]
    assert (row["k"], row["rho"], row["candidate_count"]) == (2, 1.0, 10000)
    save_results(result, tmp_path / "wallet")
    assert load_results(tmp_path / "wallet") == result


@pytest.mark.parametrize("k", [3, 5])
@pytest.mark.parametrize("setup", ["wallet-simple", "wallet-simple-pin", "wallet-bayes-pin"])
def test_larger_wallet_routing(k, setup, monkeypatch):
    calls = []
    cards = ["fixture"] * k
    candidates = [(p, tuple(cards)) for p in ALL_PINS]

    def generate(dte, size, rho, rng):
        assert (size, rho) == (k, 1.0)
        return cards

    def encrypt(dte, messages, pin, rng):
        assert messages is cards
        calls.append(pin)
        return ["ciphertext"] * k

    def rank(rows, **kwargs):
        assert rows is candidates
        assert kwargs["rho"] == (1.0 if setup == "wallet-bayes-pin" else None)
        assert (kwargs["freqs"] is None) == (setup == "wallet-simple")
        return rows

    monkeypatch.setattr(harness, "generate_wallet", generate)
    monkeypatch.setattr(harness, "encrypt_wallet", encrypt)
    monkeypatch.setattr(harness, "brute_force_wallet", lambda cts, dte: candidates)
    monkeypatch.setattr(harness, "rank_wallets", rank)
    result = harness.run_trials(setup, 1, 2026, k=k, prior="calibrated")
    assert result["trials"][0]["rank"] == int(calls[0]) + 1
