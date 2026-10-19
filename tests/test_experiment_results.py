"""Check hand-computable summaries and portable, cross-checked result files."""

import hashlib
import json

import pytest

from experiments.results import load_results, save_results, summarize_ranks
from experiments.success_vs_baseline import run_trials


def test_summary_of_hand_computable_ranks():
    result = summarize_ranks([1, 2, 1, 4])
    assert result["n_trials"] == 4
    assert result["rank_one_successes"] == 2
    assert result["rank_one_rate"] == 0.5
    assert result["median_rank"] == 1.5
    assert result["ci95_low"] == pytest.approx(0.15003898915214953)
    assert result["ci95_high"] == pytest.approx(0.8499610108478505)
    assert result["success_at_rank"]["1"] == 0.5
    assert result["success_at_rank"]["10"] == 1
    assert result["rank_cdf"][:4] == [
        {"rank": 0, "success": 0}, {"rank": 1, "success": 0.5},
        {"rank": 2, "success": 0.75}, {"rank": 4, "success": 1},
    ]


def test_zero_successes_have_positive_upper_bound():
    result = summarize_ranks([2] * 1000)
    assert result["rank_one_rate"] == 0
    assert result["ci95_low"] == 0
    assert result["ci95_high"] == pytest.approx(0.0038267584855551234)


@pytest.mark.parametrize("ranks", [[1], [10000], [1] * 1000])
def test_extreme_and_single_trial_intervals(ranks):
    result = summarize_ranks(ranks)
    assert 0 <= result["ci95_low"] <= result["rank_one_rate"] <= result["ci95_high"] <= 1
    assert result["rank_cdf"][-1] == {"rank": 10000, "success": 1}


@pytest.mark.parametrize("ranks", [[], [0], [10001], [True], [1.0], [None]])
def test_invalid_rank_input(ranks):
    with pytest.raises(ValueError, match="nonempty list"):
        summarize_ranks(ranks)


def test_save_load_actual_format_run_without_running_trials_again(tmp_path, monkeypatch):
    result = run_trials("baseline-format", 1, 2026)
    directory = tmp_path / "run"
    save_results(result, directory)

    def forbidden_trials(*args, **kwargs):
        raise AssertionError("loading must not run experiments")
    monkeypatch.setattr("experiments.success_vs_baseline.run_trials", forbidden_trials)
    assert load_results(directory) == result
    assert {p.name for p in directory.iterdir()} == {
        "metadata.json", "trials.csv", "summary.json", "summary.csv",
    }
    environment = result["metadata"]["environment"]
    from dte.good_card import BIN_PATH
    assert environment["data_sha256"]["data/bin_list.csv"] == hashlib.sha256(BIN_PATH.read_bytes()).hexdigest()
    assert environment["versions"]["scipy"]
    assert environment["git_revision"]
    with pytest.raises(FileExistsError):
        save_results(result, directory)


def synthetic_result():
    row = {"trial": 1, "setup": "baseline", "dte": "good", "prior": "uniform",
           "k": None, "rho": None, "true_pin": "0042", "rank": 2, "candidate_count": 10000}
    return {"metadata": {"n_trials": 1}, "trials": [row], "summary": summarize_ranks([2])}


def test_pin_leading_zeroes_round_trip_as_text(tmp_path):
    directory = tmp_path / "leading-zero"
    save_results(synthetic_result(), directory)
    assert load_results(directory)["trials"][0]["true_pin"] == "0042"


@pytest.mark.parametrize("filename", ["metadata.json", "summary.json", "trials.csv", "summary.csv"])
def test_missing_result_files_have_clear_errors(tmp_path, filename):
    directory = tmp_path / "missing"
    save_results(synthetic_result(), directory)
    (directory / filename).unlink()
    with pytest.raises(ValueError, match="cannot load experiment results"):
        load_results(directory)


def test_corrupt_and_inconsistent_results_have_clear_errors(tmp_path):
    directory = tmp_path / "corrupt"
    save_results(synthetic_result(), directory)
    summary = json.loads((directory / "summary.json").read_text())
    summary["rank_one_rate"] = 1
    (directory / "summary.json").write_text(json.dumps(summary))
    with pytest.raises(ValueError, match="summary does not match raw ranks"):
        load_results(directory)
    (directory / "metadata.json").write_text("not JSON")
    with pytest.raises(ValueError, match="cannot load experiment results"):
        load_results(directory)
