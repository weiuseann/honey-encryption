"""Known saved ranks verify chart values and the read-only plotting boundary."""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pytest

from experiments import plot_results as plots
from experiments.results import save_results, summarize_ranks
from experiments.success_vs_baseline import configuration_name, experiment_matrix, validate_setup


def save_synthetic(root, config=None, ranks=(1, 2, 10, 100)):
    config = config or {"setup": "baseline", "dte": "good", "prior": "uniform"}
    options = validate_setup(**config, n_trials=len(ranks), seed=2026)
    hashes = {"data/bin_list.csv": "fixed-bin"}
    if options["prior"] != "uniform":
        hashes[f"data/pin_frequencies-{options['prior']}.csv"] = options["prior"]
    result = {"metadata": {**options, "max_pin_prior_reference": .0001 if options["prior"] == "uniform" else .10713,
                           "environment": {"data_sha256": hashes}},
              "summary": summarize_ranks(list(ranks)),
              "trials": [{"trial": i, **{key: options[key] for key in ("setup", "dte", "prior", "k", "rho")},
                          "true_pin": "0007", "rank": rank, "candidate_count": 10000}
                         for i, rank in enumerate(ranks, 1)]}
    path = root / configuration_name(options)
    save_results(result, path)
    return path


def evidence_paths(root):
    aes, rsa = root / "aes.json", root / "rsa.json"
    aes.write_text(json.dumps({"seed": 2026, "guesses_per_mode": 10000,
                               "accepted": {"CTR": 10000, "GCM": 1, "CBC": 45}}))
    rsa.write_text(json.dumps({"result": {"status": "complete", "candidate_count": 10000,
        "matching_pin_count": 1, "unique_factor_count": 1, "true_pin_survived": True,
        "bits": 1024, "modulus_bits": 2048, "seed": 2026, "brute_force_seconds": 777.245,
        "verification_seconds": .045071}}))
    return aes, rsa


def test_known_rank_rates_wilson_bounds_and_cdf(tmp_path):
    rows = plots.load_card_runs([save_synthetic(tmp_path)])
    rate = plots.rate_figure(rows, "Known ranks", baseline=True)
    ax = rate.axes[0]
    assert list(ax.lines[0].get_xdata()) == [25]
    interval = ax.collections[0].get_segments()[0][:, 0]
    summary = rows[0]["summary"]
    assert list(interval) == pytest.approx([summary["ci95_low"] * 100, summary["ci95_high"] * 100])
    assert rate.axes[1].get_xlim() == (0, .05)
    assert list(ax.lines[-1].get_xdata()) == [.01, .01]
    cdf = plots.cdf_figure(rows, "Known CDF")
    assert list(cdf.axes[0].lines[0].get_xdata()) == [0, 1, 2, 10, 100, 10000]
    assert list(cdf.axes[0].lines[0].get_ydata()) == [0, 25, 50, 75, 100, 100]
    assert "n=4" in ax.get_yticklabels()[0].get_text()


def test_export_never_calls_cryptography_and_records_saved_sources(tmp_path, monkeypatch):
    from experiments import success_vs_baseline as harness
    from experiments import demo_rsa, aes_mode_pitfall
    from framework import he

    def forbidden(*args, **kwargs):
        pytest.fail("plotting must not run cryptography")

    for module, name in ((harness, "run_trials"), (demo_rsa, "run_demo"),
                         (aes_mode_pitfall, "count_accepting_pins"), (he, "encrypt"), (he, "decrypt")):
        monkeypatch.setattr(module, name, forbidden)
    path = save_synthetic(tmp_path)
    output = tmp_path / "charts"
    names = plots.plot_saved([path], output)
    assert names == ["rate-baseline-uniform", "cdf-baseline-uniform"]
    for name in names:
        assert (output / f"{name}.png").stat().st_size > 1000
        assert "<svg" in (output / f"{name}.svg").read_text(encoding="utf-8")
    provenance = json.loads((output / "charts.json").read_text())
    assert provenance["card_inputs"][0]["summary"]["rank_one_rate"] == .25
    assert set(provenance["card_inputs"][0]["input_sha256"]) == {"metadata.json", "summary.json", "summary.csv", "trials.csv"}
    assert not plt.get_fignums()
    with pytest.raises(ValueError, match="already exists"):
        plots.plot_saved([path], output)


def test_synthetic_full_matrix_covers_wallet_and_prior_figures(tmp_path):
    paths = [save_synthetic(tmp_path, config) for config in experiment_matrix("full")]
    rows = plots.load_card_runs(paths)
    wallets = plots.wallet_figures(rows)
    assert set(wallets) == {"wallet-rho-calibrated", "wallet-rho-uniform-tail",
                            "wallet-rules-calibrated-k2", "wallet-rules-calibrated-k3", "wallet-rules-calibrated-k5"}
    for ax in wallets["wallet-rho-calibrated"].axes:
        assert list(ax.lines[0].get_xdata()) == [0, .25, .5, .75, 1]
        assert list(ax.lines[0].get_ydata()) == [25] * 5
    prior = plots.prior_figures(rows)
    assert len(prior) == 3  # 23 matched configurations, eight per page.
    assert list(prior["prior-comparison-1"].axes[0].lines[0].get_xdata()) == [25] * 8
    assert {t.get_text() for t in prior["prior-comparison-1"].axes[0].get_legend().texts} == {"calibrated", "uniform-tail"}


def test_evidence_panels_have_distinct_counts_and_units(tmp_path):
    aes, rsa = evidence_paths(tmp_path)
    figures = plots.evidence_figures(aes, rsa)
    assert [p.get_height() for p in figures["aes-acceptance"].axes[0].patches] == [10000, 1, 45]
    assert [p.get_height() for p in figures["rsa-verification"].axes[0].patches] == [10000, 1, 1]
    assert "Accepted" in figures["aes-acceptance"].axes[0].get_ylabel()
    names = plots.plot_saved([], tmp_path / "evidence", kind="evidence", aes=aes, rsa=rsa)
    assert set(names) == {"aes-acceptance", "rsa-verification"}


def test_missing_comparisons_and_incompatible_inputs_fail_clearly(tmp_path):
    a = save_synthetic(tmp_path)
    rows = plots.load_card_runs([a])
    with pytest.raises(ValueError, match="require saved Bayes"):
        plots.wallet_figures(rows)
    with pytest.raises(ValueError, match="require calibrated"):
        plots.prior_figures(rows)
    b = save_synthetic(tmp_path, {"setup": "wallet-bayes-pin", "prior": "calibrated"})
    with pytest.raises(ValueError, match="incomplete wallet rho"):
        plots.wallet_figures(plots.load_card_runs([b]))
    with pytest.raises(ValueError, match="duplicate"):
        plots.load_card_runs([a, a])
    metadata_path = b / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["environment"]["data_sha256"]["data/bin_list.csv"] = "different"
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="incompatible data"):
        plots.load_card_runs([a, b])
    suite = tmp_path / "incomplete"
    suite.mkdir()
    (suite / "suite.json").write_text(json.dumps({"runs": [{"status": "planned"}]}))
    with pytest.raises(ValueError, match="incomplete"):
        plots.load_card_runs([suite])


def test_cli_missing_input_and_invalid_evidence_do_not_create_output(tmp_path):
    with pytest.raises(SystemExit) as error:
        plots.main(["--output", str(tmp_path / "empty")])
    assert error.value.code == 2
    assert not (tmp_path / "empty").exists()
    aes, rsa = evidence_paths(tmp_path)
    data = json.loads(aes.read_text())
    data["accepted"]["GCM"] = -1
    aes.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="AES evidence"):
        plots.evidence_figures(aes, None)
    data = json.loads(rsa.read_text())
    data["result"]["status"] = "benchmark-only"
    rsa.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="RSA evidence"):
        plots.evidence_figures(None, rsa)
