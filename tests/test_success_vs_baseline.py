"""Validate future setup options and exercise real, small baseline trial batches."""

import pytest

from experiments import success_vs_baseline as harness
from framework.he import ALL_PINS, decrypt


@pytest.mark.parametrize("setup,dtes", list(harness.SETUPS.items()))
def test_all_declared_setups_validate_without_running(setup, dtes):
    for dte in dtes:
        options = harness.validate_setup(setup, 2, 2026, dte=dte)
        assert options["setup"] == setup
        assert options["dte"] == dte


def test_wallet_options_are_explicit_and_normalized():
    default = harness.validate_setup("wallet-simple")
    assert (default["k"], default["rho"]) == (2, 1.0)
    for k in (2, 3, 5):
        for rho in (0, 0.25, 0.5, 0.75, 1):
            assert harness.validate_setup("wallet-bayes-pin", k=k, rho=rho)["rho"] == rho
    for prior in harness.PRIORS:
        assert harness.validate_setup("pin", prior=prior)["prior"] == prior


@pytest.mark.parametrize("options", [
    {"setup": "unknown"}, {"setup": None}, {"n_trials": 0},
    {"n_trials": -1}, {"n_trials": True}, {"n_trials": 1.5},
    {"seed": True}, {"seed": "2026"}, {"dte": "weak"},
    {"prior": "unknown"}, {"prior": "calibrated"},
    {"k": 2}, {"rho": 0.5},
    {"setup": "side-bank", "dte": "weak"},
    {"setup": "wallet-simple", "k": 1},
    {"setup": "wallet-simple", "k": True},
    {"setup": "wallet-simple", "k": 2.0},
    {"setup": "wallet-bayes-pin", "rho": -0.1},
    {"setup": "wallet-bayes-pin", "rho": 1.1},
    {"setup": "wallet-bayes-pin", "rho": float("nan")},
    {"setup": "wallet-bayes-pin", "rho": True},
    {"setup": "wallet-simple", "rho": 0.5},
    {"setup": "rsa-verify", "dte": "good"},
    {"setup": "rsa-verify", "dte": "rsa", "prior": "calibrated"},
])
def test_invalid_options_fail_before_encryption(options, monkeypatch):
    def forbidden_encrypt(*args):
        raise AssertionError("invalid options must not start encryption")
    monkeypatch.setattr(harness, "encrypt", forbidden_encrypt)
    arguments = {"setup": "baseline", "n_trials": 1, "seed": 2026, **options}
    with pytest.raises(ValueError):
        harness.run_trials(**arguments)


@pytest.mark.parametrize("setup,dte", [("rsa-verify", "rsa")])
def test_valid_future_setups_do_not_silently_run_baselines(setup, dte, monkeypatch):
    def forbidden_dte():
        raise AssertionError("not-integrated setups must not start trials")
    monkeypatch.setattr(harness, "GoodCardDTE", forbidden_dte)
    with pytest.raises(NotImplementedError, match="not integrated yet"):
        harness.run_trials(setup, 1, 2026, dte=dte)


def test_baseline_uses_real_encryption_and_all_pin_candidates(monkeypatch):
    encrypted = []
    candidate_lists = []
    original_encrypt, original_brute_force = harness.encrypt, harness.brute_force

    def tracked_encrypt(dte, message, pin, rng):
        ct = original_encrypt(dte, message, pin, rng)
        encrypted.append((dte, message, pin, ct))
        return ct

    def tracked_brute_force(ct, dte):
        candidates = original_brute_force(ct, dte)
        candidate_lists.append(candidates)
        return candidates

    monkeypatch.setattr(harness, "encrypt", tracked_encrypt)
    monkeypatch.setattr(harness, "brute_force", tracked_brute_force)
    result = harness.run_trials("baseline", 2, 2026)
    assert result["metadata"]["rank_one_reference"] == 0.0001
    assert result["summary"]["n_trials"] == 2
    assert result["metadata"]["max_pin_prior_reference"] == 0.0001
    for record, candidates, (dte, message, pin, ct) in zip(result["trials"], candidate_lists, encrypted):
        assert [guess for guess, _ in candidates] == ALL_PINS
        assert sum(guess == pin for guess, _ in candidates) == 1
        assert dict(candidates)[pin] == decrypt(dte, ct, pin) == message
        assert record["true_pin"] == pin
        assert len(pin) == 4 and pin.isdigit()
        assert record["candidate_count"] == 10000
        assert 1 <= record["rank"] <= 10000


@pytest.mark.parametrize("setup", ["baseline", "baseline-format"])
def test_baseline_trials_are_reproducible(setup):
    first = harness.run_trials(setup, 3, 2026)
    second = harness.run_trials(setup, 3, 2026)
    for result in (first, second):
        result["metadata"].pop("elapsed_seconds")
        result["metadata"]["environment"].pop("created_utc")
    assert first == second
    assert [row["trial"] for row in first["trials"]] == [1, 2, 3]
    assert first["metadata"]["seed"] == 2026


def test_good_dte_format_control_leaves_all_candidates_and_same_ranks():
    baseline = harness.run_trials("baseline", 2, 2026)
    control = harness.run_trials("baseline-format", 2, 2026)
    for plain, formatted in zip(baseline["trials"], control["trials"]):
        assert formatted["format_funnel"] == {"all": 10000, "luhn": 10000,
                                               "network": 10000, "bin": 10000}
        assert (plain["true_pin"], plain["rank"]) == (formatted["true_pin"], formatted["rank"])


@pytest.mark.parametrize("dte_name", ["weak", "good"])
def test_format_setup_runs_with_real_cards_and_correct_encoder(dte_name, monkeypatch):
    encrypted = []
    original_encrypt = harness.encrypt

    def track(dte, card, pin, rng):
        encrypted.append((dte, card))
        return original_encrypt(dte, card, pin, rng)

    monkeypatch.setattr(harness, "encrypt", track)
    result = harness.run_trials("format", 2, 2026, dte=dte_name)
    good = harness.GoodCardDTE()
    for row, (encoder, card) in zip(result["trials"], encrypted):
        assert type(encoder).__name__ == ("WeakCardDTE" if dte_name == "weak" else "GoodCardDTE")
        good.encode(card)  # Real card is valid under the same good model in both runs.
        counts = list(row["format_funnel"].values())
        assert counts[0] == 10000
        assert all(a >= b for a, b in zip(counts, counts[1:]))
        assert counts[-1] >= 1
        if dte_name == "good":
            assert counts == [10000] * 4


def test_format_composes_existing_filter_with_invalid_decoys(monkeypatch):
    original_encrypt = harness.encrypt
    captured = {}

    def encrypt(dte, card, pin, rng):
        captured.update(card=card, pin=pin)
        return original_encrypt(dte, card, pin, rng)

    def candidates(ct, dte):
        # Only the chosen true PIN recovers the real card in this controlled fixture.
        rows = [(pin, "0000000000000001") for pin in ALL_PINS]
        pin = captured["pin"]
        rows[int(pin)] = (pin, captured["card"])
        return rows

    monkeypatch.setattr(harness, "encrypt", encrypt)
    monkeypatch.setattr(harness, "brute_force", candidates)
    result = harness.run_trials("format", 1, 2026, dte="weak")
    row = result["trials"][0]
    assert row["rank"] == 1
    assert row["format_funnel"] == {"all": 10000, "luhn": 1, "network": 1, "bin": 1}


def test_wallet_rho_sweep_is_explicitly_pending():
    with pytest.raises(NotImplementedError, match="task 6.5"):
        harness.run_trials("wallet-bayes-pin", 1, 2026, rho=0)


@pytest.mark.parametrize("prior", ["calibrated", "uniform-tail"])
def test_loaded_pin_reference_is_computed_from_table(prior):
    assert harness.max_pin_prior(prior) == pytest.approx(0.10713)
