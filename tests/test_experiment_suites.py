"""Verify explicit matrices, model routing and repeatable command-line evidence."""

from random import Random

import pytest

from attacks.pin_ranking import rank_by_pin_popularity
from attacks.two_card import rank_wallets
from experiments import cli
from experiments import success_vs_baseline as harness
from experiments.results import load_results
from framework.he import ALL_PINS


@pytest.mark.parametrize("k", harness.WALLET_SIZES)
@pytest.mark.parametrize("rho", harness.RHOS)
def test_rho_is_shared_by_generator_and_bayes_scorer(k, rho, monkeypatch):
    calls = []
    candidates = [(p, tuple(["fixture"] * k)) for p in ALL_PINS]

    def generate(dte, size, model_rho, rng):
        calls.append((size, model_rho))
        return ["fixture"] * size

    def rank(rows, **kwargs):
        assert kwargs["rho"] == rho
        assert rows is candidates
        return rows

    monkeypatch.setattr(harness, "generate_wallet", generate)
    monkeypatch.setattr(harness, "encrypt_wallet", lambda *args: [None] * k)
    monkeypatch.setattr(harness, "brute_force_wallet", lambda *args: candidates)
    monkeypatch.setattr(harness, "rank_wallets", rank)
    result = harness.run_trials("wallet-bayes-pin", 1, 2026, k=k, rho=rho)
    assert calls == [(k, rho)]
    assert (result["trials"][0]["k"], result["trials"][0]["rho"]) == (k, rho)


def test_zero_rho_is_exactly_pin_ranking_and_one_rejects_mixed_wallets():
    good = harness.GoodCardDTE()
    by_bank = {}
    rng = Random(12)
    while len(by_bank) < 2:
        card = good.sample(rng)
        bank = {e.bin: e.bank for e in good.bins}[card[:6]]
        by_bank[bank] = card
    a, b = list(by_bank.values())
    candidates = [("0000", (a, b)), ("0001", (a, a)), ("0002", (b, b))]
    freqs = {"0000": 0.8, "0001": 0.1, "0002": 0.1}
    assert rank_wallets(candidates, freqs, 0, good.bins, Random(8)) == \
        rank_by_pin_popularity(candidates, freqs, Random(8))
    assert rank_wallets(candidates, freqs, 1, good.bins, Random(8))[-1][0] == "0000"


def test_matrix_covers_rho_sizes_and_all_prior_dependent_pairs():
    correlation = harness.experiment_matrix("correlation")
    assert {(r["k"], r["rho"]) for r in correlation} == \
        {(k, rho) for k in harness.WALLET_SIZES for rho in harness.RHOS}
    assert {r["setup"] for r in correlation} == {"wallet-bayes-pin"}
    full = harness.experiment_matrix()
    sensitivity = harness.experiment_matrix("sensitivity")
    names = [harness.configuration_name(r) for r in full]
    assert len(names) == len(set(names))
    expected = {"pin", "format-pin", "side-bank-last4-pin", "wallet-simple-pin", "wallet-bayes-pin"}
    assert {r["setup"] for r in sensitivity} == expected
    for row in sensitivity:
        other = dict(row, prior="calibrated" if row["prior"] == "uniform-tail" else "uniform-tail")
        assert other in sensitivity
    for family in ("full", "smoke", "single", "side", "wallet", "correlation", "sensitivity"):
        for row in harness.experiment_matrix(family):
            assert row["setup"] != "rsa-verify"
            harness.validate_setup(**row, n_trials=1)


@pytest.mark.parametrize("prior", ["calibrated", "uniform-tail"])
@pytest.mark.parametrize("setup", ["pin", "format-pin", "side-bank-last4-pin", "wallet-bayes-pin"])
def test_selected_table_shared_by_sampler_and_scorer(prior, setup, monkeypatch):
    original_load, original_sample = harness.load_pin_frequencies, harness.sample_pins
    loaded = []
    selected = {}

    def load(path):
        loaded.append(path)
        selected["freqs"] = original_load(path)
        return selected["freqs"]

    def sample(freqs, n, rng):
        assert freqs is selected["freqs"]
        return original_sample(freqs, n, rng)

    def wrap(original):
        def rank(candidates, *args, **kwargs):
            freqs = args[0] if args else kwargs["freqs"]
            assert freqs is selected["freqs"]
            return original(candidates, *args, **kwargs)
        return rank

    monkeypatch.setattr(harness, "load_pin_frequencies", load)
    monkeypatch.setattr(harness, "sample_pins", sample)
    monkeypatch.setattr(harness, "rank_by_pin_popularity", wrap(harness.rank_by_pin_popularity))
    monkeypatch.setattr(harness, "rank_by_side_info", wrap(harness.rank_by_side_info))
    monkeypatch.setattr(harness, "rank_wallets", wrap(harness.rank_wallets))
    # Combined ranker reads the same dictionary in its score closure; verify its resulting order.
    original_order = harness.order_by_score
    if setup == "format-pin":
        def order(candidates, score, rng):
            for c in candidates[:20]:
                assert score(c)[1] == selected["freqs"][c[0]]
            return original_order(candidates, score, rng)
        monkeypatch.setattr(harness, "order_by_score", order)
    first = harness.run_trials(setup, 1, 2026, prior=prior)
    second = harness.run_trials(setup, 1, 2026, prior=prior)
    assert first["trials"] == second["trials"]
    expected_path = harness.PIN_PATH if prior == "calibrated" else harness.UNIFORM_TAIL_PIN_PATH
    assert loaded == [expected_path, expected_path]
    assert expected_path.name in next(name for name in first["metadata"]["environment"]["data_sha256"]
                                      if "pin_frequencies" in name)


def test_cli_help_and_invalid_options_never_run_trials(monkeypatch, tmp_path, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid options must not execute")
    monkeypatch.setattr(cli, "run_trials", forbidden)
    with pytest.raises(SystemExit) as help_exit:
        cli.main(["--help"])
    assert help_exit.value.code == 0
    assert "--rho-sweep" in capsys.readouterr().out
    for arguments in ([], ["--setup", "baseline", "--trials", "0"],
                      ["--setup", "baseline", "--dte", "weak"],
                      ["--setup", "wallet-simple", "--rho-sweep"],
                      ["--family", "wallet", "--prior", "uniform"],
                      ["--setup", "pin", "--bits", "1024"]):
        with pytest.raises(SystemExit) as error:
            cli.main([*arguments, "--output", str(tmp_path / "invalid")])
        assert error.value.code == 2
    assert not (tmp_path / "invalid").exists()


def test_cli_real_single_run_can_be_rerun_from_recorded_seed(tmp_path, capsys):
    output = tmp_path / "first"
    cli.main(["--setup", "baseline", "--seed", "2026", "--output", str(output)])
    first = load_results(output / "baseline-good-uniform")
    options = first["metadata"]
    repeated = harness.run_trials(options["setup"], options["n_trials"], options["seed"],
                                  dte=options["dte"], prior=options["prior"])
    assert first["trials"] == repeated["trials"]
    assert "trial 1/1" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(["--setup", "baseline", "--output", str(output)])


@pytest.mark.parametrize("suite", ["smoke", "full"])
def test_suite_excludes_rsa_and_records_distinct_names(suite, tmp_path, monkeypatch):
    calls = []

    def run(**options):
        options.pop("progress")(1, options["n_trials"])
        calls.append(options)
        return {"summary": {"rank_one_successes": 0, "median_rank": 123}}

    monkeypatch.setattr(cli, "run_trials", run)
    monkeypatch.setattr(cli, "save_results", lambda *args: None)
    monkeypatch.setattr(cli, "run_demo", lambda *args, **kwargs: pytest.fail("suite dispatched RSA"))
    manifest = cli.run_suite(harness.experiment_matrix(suite), 1, 2026, tmp_path / suite)
    assert len(calls) == len(manifest["runs"])
    assert all(r["status"] == "complete" for r in manifest["runs"])
    for row in manifest["runs"]:
        for other in manifest["runs"]:
            a, b = row["options"], other["options"]
            if all(a[key] == b[key] for key in ("setup", "dte", "k", "rho")):
                assert a["seed"] == b["seed"]


def test_cli_explicit_rsa_reuses_demo_without_card_dispatch(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "run_trials", lambda **kwargs: pytest.fail("RSA ran card trials"))
    monkeypatch.setattr(cli, "run_demo", lambda bits, seed, **kwargs:
                        calls.append((bits, seed)) or {"matching_pin_count": 1, "true_pin_survived": True})
    monkeypatch.setattr(cli, "save_result", lambda result, path: calls.append(path))
    cli.main(["--setup", "rsa-verify", "--output", str(tmp_path / "rsa.json")])
    assert calls == [(16, 2026), tmp_path / "rsa.json"]


def test_suite_validates_all_rows_before_creating_output(tmp_path):
    with pytest.raises(ValueError):
        cli.run_suite([{"setup": "baseline"}, {"setup": "wallet-simple", "rho": .5}],
                      1, 2026, tmp_path / "invalid")
    assert not (tmp_path / "invalid").exists()


def test_cli_full_defaults_and_bayes_sweep_are_explicit(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "run_suite", lambda rows, n, seed, output: calls.append((rows, n, seed)))
    cli.main(["--suite", "full", "--output", str(tmp_path / "full")])
    assert len(calls[-1][0]) == 56 and calls[-1][1] == 1000
    cli.main(["--setup", "wallet-bayes-pin", "--rho-sweep", "--k", "3",
              "--output", str(tmp_path / "sweep")])
    assert {(r["k"], r["rho"]) for r in calls[-1][0]} == {(3, rho) for rho in harness.RHOS}
    assert calls[-1][1] == 1


def test_duplicate_names_fail_before_creating_output(tmp_path):
    row = {"setup": "baseline", "dte": "good", "prior": "uniform"}
    with pytest.raises(ValueError, match="duplicate"):
        cli.run_suite([row, row], 1, 2026, tmp_path / "duplicate")
    assert not (tmp_path / "duplicate").exists()
