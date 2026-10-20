"""Small statistics and CSV/JSON helpers for inspectable experiment results."""

import csv
import hashlib
import json
import platform
import subprocess
from collections import Counter
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from statistics import median

from scipy.stats import binomtest

ROOT = Path(__file__).resolve().parent.parent
TRIAL_FIELDS = ("trial", "setup", "dte", "prior", "k", "rho", "true_pin",
                "rank", "candidate_count", "format_funnel")
SUMMARY_FIELDS = ("n_trials", "rank_one_successes", "rank_one_rate", "ci95_low",
                  "ci95_high", "median_rank")


def summarize_ranks(ranks: list[int]) -> dict:
    """Summarize original-PIN ranks; Wilson bounds describe sampling uncertainty."""
    if not ranks or any(isinstance(r, bool) or not isinstance(r, int) or not 1 <= r <= 10000
                        for r in ranks):
        raise ValueError("ranks must be a nonempty list of integers from 1 through 10000")
    n = len(ranks)
    successes = ranks.count(1)
    interval = binomtest(successes, n).proportion_ci(confidence_level=0.95, method="wilson")
    counts = Counter(ranks)
    cdf, cumulative = [{"rank": 0, "success": 0.0}], 0
    for rank, count in sorted(counts.items()):
        cumulative += count
        cdf.append({"rank": rank, "success": cumulative / n})
    if cdf[-1]["rank"] != 10000:
        cdf.append({"rank": 10000, "success": 1.0})
    return {
        "n_trials": n, "rank_one_successes": successes, "rank_one_rate": successes / n,
        "ci95_low": float(interval.low), "ci95_high": float(interval.high),
        "median_rank": float(median(ranks)),
        "success_at_rank": {str(k): sum(r <= k for r in ranks) / n
                            for k in (1, 10, 100, 1000, 10000)},
        "rank_cdf": cdf,
    }


def capture_environment(data_paths: list[Path]) -> dict:
    """Capture the inputs and software identity before a run starts."""
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                              text=True, check=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,
                           text=True, check=True).stdout.strip()
    return {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(), "git_revision": revision, "git_dirty": bool(dirty),
        "versions": {name: version(name) for name in
                     ("cryptography", "numpy", "scipy", "sympy", "matplotlib")},
        "data_sha256": {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in data_paths},
        "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                          ("experiments/success_vs_baseline.py", "experiments/results.py",
                           "experiments/cli.py")},
    }


def _check_result(result: dict) -> None:
    trials = result["trials"]
    if len(trials) != result["metadata"]["n_trials"]:
        raise ValueError("metadata trial count does not match raw trials")
    for index, row in enumerate(trials, start=1):
        if row["trial"] != index or row["candidate_count"] != 10000:
            raise ValueError("invalid trial index or candidate count")
        if not isinstance(row["true_pin"], str) or len(row["true_pin"]) != 4 or not row["true_pin"].isdigit():
            raise ValueError("PIN must remain a four-character digit string")
    if result["summary"] != summarize_ranks([row["rank"] for row in trials]):
        raise ValueError("saved summary does not match raw ranks")


def save_results(result: dict, directory: str | Path) -> None:
    """Save one new result directory; refuse to overwrite even an empty directory."""
    _check_result(result)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    for filename, value in (("metadata.json", result["metadata"]), ("summary.json", result["summary"])):
        (directory / filename).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    with (directory / "trials.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=TRIAL_FIELDS)
        writer.writeheader()
        for row in result["trials"]:
            writer.writerow({**row, "format_funnel": json.dumps(row.get("format_funnel"))})
    with (directory / "summary.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=SUMMARY_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerow(result["summary"])


def load_results(directory: str | Path) -> dict:
    """Read and cross-check saved data without running any experiment."""
    directory = Path(directory)
    try:
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        with (directory / "trials.csv").open(newline="", encoding="utf-8") as file:
            trials = list(csv.DictReader(file))
        for row in trials:
            for name in ("trial", "rank", "candidate_count"):
                row[name] = int(row[name])
            row["k"] = int(row["k"]) if row["k"] else None
            row["rho"] = float(row["rho"]) if row["rho"] else None
            funnel = json.loads(row.pop("format_funnel"))
            if funnel is not None:
                row["format_funnel"] = funnel
        result = {"metadata": metadata, "trials": trials, "summary": summary}
        _check_result(result)
        with (directory / "summary.csv").open(newline="", encoding="utf-8") as file:
            summary_rows = list(csv.DictReader(file))
        if summary_rows != [{key: str(summary[key]) for key in SUMMARY_FIELDS}]:
            raise ValueError("summary CSV does not match summary JSON")
        return result
    except (OSError, ValueError, TypeError, KeyError, csv.Error) as error:
        raise ValueError(f"cannot load experiment results from {directory}: {error}") from error
