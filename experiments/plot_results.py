"""Plot saved experiment evidence only; no encryption or trial execution imports."""

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from experiments.results import load_results


ASSUMPTIONS = ("Synthetic cards; assumed BIN shares; modelled PIN tails; accurate side information.\n"
               "Points are measured rates; bars are 95% Wilson intervals. Interpret results within this model.")


def load_card_runs(paths: list[Path]) -> list[dict]:
    """Accept saved run directories or completed suite directories, with input hashes."""
    runs, identities, bin_hashes, prior_hashes = [], set(), set(), defaultdict(set)
    for path in paths:
        manifest = path / "suite.json"
        if manifest.exists():
            rows = json.loads(manifest.read_text(encoding="utf-8"))["runs"]
            if not rows or any(row["status"] != "complete" for row in rows):
                raise ValueError(f"suite is incomplete: {path}")
            directories = [path / row["directory"] for row in rows]
        else:
            directories = [path]
        for directory in directories:
            result = load_results(directory)
            m = result["metadata"]
            identity = tuple(m[key] for key in ("setup", "dte", "prior", "k", "rho"))
            if identity in identities:
                raise ValueError(f"duplicate configuration: {directory}; select one run per configuration")
            identities.add(identity)
            hashes = m["environment"]["data_sha256"]
            bin_hashes.add(hashes["data/bin_list.csv"])
            prior_hashes[m["prior"]].update(value for name, value in hashes.items() if "pin_frequencies" in name)
            runs.append({**result, "source": str(directory.resolve()),
                         "input_sha256": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                                          for name in ("metadata.json", "trials.csv", "summary.json", "summary.csv")}})
    if not runs:
        raise ValueError("no saved card runs supplied")
    if len(bin_hashes) != 1 or any(len(values) > 1 for values in prior_hashes.values()):
        raise ValueError("incompatible data checksums: compare runs using the same BIN and per-prior PIN data")
    return runs


def label(run: dict, include_prior: bool = False) -> str:
    m = run["metadata"]
    name = f"{m['setup']} / {m['dte']}"
    if m["k"] is not None:
        name += f" / k={m['k']}, rho={m['rho']:g}"
    if include_prior:
        name += f" / {m['prior']}"
    return f"{name} (n={m['n_trials']})"


def _finish(fig, title: str, caption: str = ASSUMPTIONS):
    fig.suptitle(title, fontsize=12)
    fig.text(.02, .025, caption, fontsize=8, va="bottom")
    fig.tight_layout(rect=(0, .14, 1, .93))
    plt.close(fig)
    return fig


def _rate_points(ax, rows: list[dict], offset: float = 0, **kwargs):
    summary = [r["summary"] for r in rows]
    rates = [s["rank_one_rate"] * 100 for s in summary]
    errors = [[(s["rank_one_rate"] - s["ci95_low"]) * 100 for s in summary],
              [(s["ci95_high"] - s["rank_one_rate"]) * 100 for s in summary]]
    ax.errorbar(rates, [i + offset for i in range(len(rows))], xerr=errors,
                fmt="o", capsize=3, **kwargs)
    ax.set_xlim(-1, 101)
    ax.set_xlabel("True PIN ranked first (% of trials)")
    ax.grid(axis="x", alpha=.25)


def rate_figure(rows: list[dict], title: str, baseline: bool = False):
    fig, axes = plt.subplots(1, 2 if baseline else 1, squeeze=False,
                             figsize=(12 if baseline else 10, max(4.5, .6 * len(rows) + 2.2)))
    for ax in axes[0]:
        _rate_points(ax, rows, color="#17678d")
        ax.set_yticks(range(len(rows)), [label(r) for r in rows], fontsize=9)
        ax.invert_yaxis()
        ax.axvline(.01, color="#a54b16", ls="--", label="Uniform matched baseline: 0.01%")
        prior_max = rows[0]["metadata"]["max_pin_prior_reference"] * 100
        if rows[0]["metadata"]["prior"] != "uniform":
            ax.axvline(prior_max, color="#6554a4", ls=":",
                       label=f"Max PIN prior: {prior_max:.3f}%\nMatched messages; no extra evidence reference")
        ax.legend(fontsize=7, loc="upper center", bbox_to_anchor=(.5, -.24))
    if baseline:
        axes[0][1].set_xlim(0, .05)
        axes[0][1].set_title("Baseline zoom; intervals extend outside view", fontsize=9)
    return _finish(fig, title)


def cdf_figure(rows: list[dict], title: str):
    fig, ax = plt.subplots(figsize=(12, 5.5))
    for row in rows:
        cdf = row["summary"]["rank_cdf"]
        ax.step([p["rank"] for p in cdf], [p["success"] * 100 for p in cdf],
                where="post", label=label(row))
    ax.set_xscale("symlog", linthresh=1)
    ax.set_xlim(0, 10000)
    ax.set_ylim(0, 102)
    ax.set_xlabel("Guess budget (log spacing above 1)")
    ax.set_ylabel("True PIN within guess budget (% of trials)")
    ax.grid(alpha=.25)
    ax.legend(fontsize=8, loc="center left", bbox_to_anchor=(1.02, .5))
    return _finish(fig, title, "Empirical cumulative success; no confidence band is implied.\n" + ASSUMPTIONS.split("\n")[0])


def card_figures(runs: list[dict]) -> dict:
    groups = defaultdict(list)
    for run in runs:
        m = run["metadata"]
        if m["setup"].startswith("baseline"):
            group = "baseline"
        elif m["setup"].startswith("wallet"):
            group = f"wallet-k{m['k']}"
        elif m["setup"].startswith("side"):
            group = "side"
        else:
            group = "single-card"
        groups[f"{group}-{m['prior']}"].append(run)
    figures = {}
    for name, rows in groups.items():
        figures[f"rate-{name}"] = rate_figure(rows, f"Rank-one success: {name}", name.startswith("baseline"))
        figures[f"cdf-{name}"] = cdf_figure(rows, f"Success within a guess budget: {name}")
    return figures


def wallet_figures(runs: list[dict]) -> dict:
    bayes = defaultdict(dict)
    for run in runs:
        m = run["metadata"]
        if m["setup"] == "wallet-bayes-pin":
            bayes[m["prior"]][(m["k"], m["rho"])] = run
    if not bayes:
        raise ValueError("wallet charts require saved Bayes rho runs for k=2/3/5")
    figures = {}
    for prior, lookup in bayes.items():
        required = {(k, rho) for k in (2, 3, 5) for rho in (0, .25, .5, .75, 1)}
        if not required <= lookup.keys():
            raise ValueError(f"incomplete wallet rho grid for {prior}; require k=2/3/5 and all five rho values")
        fig, axes = plt.subplots(1, 3, figsize=(12, 5), sharey=True)
        for ax, k in zip(axes, (2, 3, 5)):
            rows = [lookup[k, rho] for rho in (0, .25, .5, .75, 1)]
            s = [r["summary"] for r in rows]
            rates = [v["rank_one_rate"] * 100 for v in s]
            ax.errorbar([0, .25, .5, .75, 1], rates,
                        yerr=[[(v["rank_one_rate"] - v["ci95_low"]) * 100 for v in s],
                              [(v["ci95_high"] - v["rank_one_rate"]) * 100 for v in s]],
                        fmt="o-", capsize=3, color="#17678d")
            ax.set_title(f"k={k}; n per point: {','.join(str(r['metadata']['n_trials']) for r in rows)}", fontsize=9)
            ax.set_xlabel("rho (shared-bank branch probability)", fontsize=8)
            ax.set_xticks([0, .25, .5, .75, 1])
            ax.set_ylim(-2, 102)
            ax.grid(alpha=.25)
        axes[0].set_ylabel("True PIN ranked first (% of trials)")
        figures[f"wallet-rho-{prior}"] = _finish(fig, f"Bayes wallet correlation sweep / {prior}")
    # Simple rules exist at rho=1; compare only priors with the full three-rule set.
    for prior in sorted({r["metadata"]["prior"] for r in runs if r["metadata"]["setup"] == "wallet-simple"}):
        for k in (2, 3, 5):
            rows = [r for r in runs if r["metadata"]["prior"] == prior
                    and r["metadata"]["k"] == k and r["metadata"]["rho"] == 1]
            if {r["metadata"]["setup"] for r in rows} != {"wallet-simple", "wallet-simple-pin", "wallet-bayes-pin"}:
                raise ValueError(f"incomplete simple/Bayes wallet comparison for {prior}, k={k}")
            figures[f"wallet-rules-{prior}-k{k}"] = rate_figure(rows, f"Same-bank rule versus PIN and Bayes / {prior}, k={k}, rho=1")
    return figures


def prior_figures(runs: list[dict]) -> dict:
    pairs = defaultdict(dict)
    for run in runs:
        m = run["metadata"]
        if m["setup"] in ("pin", "format-pin", "side-bank-last4-pin", "wallet-simple-pin", "wallet-bayes-pin"):
            pairs[m["setup"], m["dte"], m["k"], m["rho"]][m["prior"]] = run
    if not pairs or any(not {"calibrated", "uniform-tail"} <= pair.keys() for pair in pairs.values()):
        raise ValueError("prior charts require calibrated and uniform-tail results for each selected PIN-scored setup")
    figures = {}
    items = list(pairs.values())
    for start in range(0, len(items), 8):
        page = items[start:start + 8]
        fig, ax = plt.subplots(figsize=(12, max(5, len(page) * .8 + 2)))
        for prior, offset, color in (("calibrated", -.15, "#17678d"), ("uniform-tail", .15, "#c47717")):
            _rate_points(ax, [p[prior] for p in page], offset, label=prior, color=color)
        labels = [label(p["calibrated"]).split(" (n=")[0] +
                  f" (n={p['calibrated']['metadata']['n_trials']}/{p['uniform-tail']['metadata']['n_trials']})" for p in page]
        ax.set_yticks(range(len(page)), labels, fontsize=9)
        ax.invert_yaxis()
        ax.legend(loc="upper center", bbox_to_anchor=(.5, -.15), ncol=2)
        figures[f"prior-comparison-{start // 8 + 1}"] = _finish(fig, "PIN-model sensitivity: calibrated versus uniform-tail")
    return figures


def evidence_figures(aes_path: Path | None, rsa_path: Path | None) -> dict:
    """Separate count panels; these are not card rank-one success estimates."""
    figures = {}
    if aes_path is not None:
        data = json.loads(aes_path.read_text(encoding="utf-8"))
        counts = [data["accepted"][mode] for mode in ("CTR", "GCM", "CBC")]
        total = data["guesses_per_mode"]
        if total != 10000 or any(type(c) is not int or not 0 <= c <= total for c in counts):
            raise ValueError("AES evidence requires valid acceptance counts out of 10000")
        fig, ax = plt.subplots(figsize=(8, 4.5))
        bars = ax.bar(["CTR", "GCM", "CBC + PKCS#7"], counts, color=["#17678d", "#7e6a9c", "#c47717"])
        ax.bar_label(bars, padding=4)
        ax.set_yscale("symlog", linthresh=1)
        ax.set_ylim(0, 30000)
        ax.set_ylabel("Accepted PIN guesses (log spacing above 1)")
        figures["aes-acceptance"] = _finish(fig, f"AES acceptance checks / {total} guesses per mode / seed={data['seed']}",
            "Acceptance means a mode check passes; it does not imply correct plaintext.\nCTR has no check; GCM checks its tag; CBC checks padding. Saved evidence only.")
    if rsa_path is not None:
        data = json.loads(rsa_path.read_text(encoding="utf-8"))["result"]
        counts = [data["candidate_count"], data["matching_pin_count"], data["unique_factor_count"]]
        if (data["status"] != "complete" or counts[0] != 10000 or
                any(type(c) is not int or not 0 <= c <= 10000 for c in counts) or
                not 1 <= counts[2] <= counts[1] or data["true_pin_survived"] is not True):
            raise ValueError("RSA evidence requires a complete verified run with true PIN retained")
        fig, ax = plt.subplots(figsize=(8, 4.5))
        bars = ax.bar(["Enumerated\nPINs", "Verified\nPINs", "Distinct\nfactors"], counts, color="#17678d")
        ax.bar_label(bars, padding=4)
        ax.set_yscale("log")
        ax.set_ylim(.5, 30000)
        ax.set_ylabel("Count (log scale)")
        figures["rsa-verification"] = _finish(fig, f"RSA public verification / {data['bits']}-bit factors / N: {data['modulus_bits']} bits",
            f"Seed={data['seed']}; true PIN retained; brute force {data['brute_force_seconds']:.3f}s; verification {data['verification_seconds']:.6f}s.\n"
            "Factor discovery is distinct from unique PIN recovery; next-prime gap bias applies. Saved evidence only.")
    if not figures:
        raise ValueError("evidence charts require --aes and/or --rsa saved JSON")
    return figures


def presentation_figures(runs: list[dict], aes: Path | None, rsa: Path | None) -> dict:
    """Five summary figures; detailed diagnostics remain available with --kind all."""
    lookup = {(r["metadata"]["setup"], r["metadata"]["dte"], r["metadata"]["prior"]): r
              for r in runs if r["metadata"]["k"] is None}
    try:
        single = [lookup[s, d, "calibrated"] for s, d in
                  (("format", "weak"), ("format", "good"), ("pin", "good"),
                   ("side-last4", "good"), ("side-bank-last4", "good"),
                   ("side-bank-last4-pin", "good"))]
        budgets = [lookup["baseline", "good", "uniform"], single[2], single[3], single[5]]
    except KeyError as error:
        raise ValueError(f"presentation requires the full card matrix; missing {error}") from error
    if aes is None or rsa is None:
        raise ValueError("presentation requires both --aes and --rsa saved evidence")
    wallets = wallet_figures(runs)
    return {"card-attacks": rate_figure(single, "Valid decoys versus PIN popularity and accurate side information"),
            "guess-budgets": cdf_figure(budgets, "Uniform baseline versus calibrated-PIN attack scenarios"),
            "wallet-correlation": wallets["wallet-rho-calibrated"],
            **evidence_figures(aes, rsa)}


def plot_saved(paths: list[Path], output: Path, *, kind: str = "cards",
               aes: Path | None = None, rsa: Path | None = None) -> list[str]:
    if kind not in ("cards", "wallet", "prior", "evidence", "all", "presentation"):
        raise ValueError("unknown chart kind")
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    runs = load_card_runs(paths) if paths else []
    figures = {}
    try:
        if kind != "evidence" and not runs:
            raise ValueError("card charts require saved result or suite directories")
        if kind == "presentation":
            figures.update(presentation_figures(runs, aes, rsa))
        if kind in ("cards", "all"):
            figures.update(card_figures(runs))
        if kind in ("wallet", "all"):
            figures.update(wallet_figures(runs))
        if kind in ("prior", "all"):
            figures.update(prior_figures(runs))
        if kind in ("evidence", "all"):
            figures.update(evidence_figures(aes, rsa))
        output.mkdir(parents=True, exist_ok=False)
        for name, fig in figures.items():
            for extension in ("png", "svg"):
                fig.savefig(output / f"{name}.{extension}", dpi=150)
        provenance = {"kind": kind, "charts": list(figures),
                      "plot_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      "card_inputs": [{"source": r["source"], "input_sha256": r["input_sha256"],
                                       "metadata": r["metadata"], "summary": r["summary"]} for r in runs],
                      "evidence_inputs": {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest()
                                          for p in (aes, rsa) if p is not None}}
        (output / "charts.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        return list(figures)
    finally:
        for fig in figures.values():
            plt.close(fig)


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path, help="saved card run/suite directories")
    parser.add_argument("--output", type=Path, required=True, help="new chart directory")
    parser.add_argument("--kind", choices=("cards", "wallet", "prior", "evidence", "all", "presentation"), default="cards")
    parser.add_argument("--aes", type=Path, help="saved AES comparison JSON")
    parser.add_argument("--rsa", type=Path, help="saved RSA demo JSON")
    args = parser.parse_args(argv)
    try:
        names = plot_saved(args.inputs, args.output, kind=args.kind, aes=args.aes, rsa=args.rsa)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(f"Saved {len(names)} charts as PNG and SVG in {args.output.resolve()}")


if __name__ == "__main__":
    main()
