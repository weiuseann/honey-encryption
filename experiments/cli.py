"""Select, describe and save explicit experiment runs; never launch RSA in a card suite."""

import argparse
import json
from pathlib import Path

from experiments.demo_rsa import run_demo, save_result
from experiments.results import save_results
from experiments.success_vs_baseline import (
    PRIORS, RHOS, SETUPS, WALLET_SIZES, configuration_name, experiment_matrix,
    run_trials, validate_setup,
)


def run_suite(configurations: list[dict], n_trials: int, seed: int, output: Path) -> dict:
    """Validate all rows first, save each finished run, and record arithmetic seeds."""
    if not configurations:
        raise ValueError("suite must contain at least one configuration")
    rows, seed_indices = [], {}
    for config in configurations:
        # Prior variants get identical seeds and otherwise identical options.
        key = tuple((name, config.get(name)) for name in ("setup", "dte", "k", "rho"))
        index = seed_indices.setdefault(key, len(seed_indices))
        options = validate_setup(**config, n_trials=n_trials, seed=seed + index)
        if options["setup"] == "rsa-verify":
            raise ValueError("RSA must be selected separately")
        rows.append({"directory": configuration_name(options), "options": options,
                     "status": "planned"})
    if len({row["directory"] for row in rows}) != len(rows):
        raise ValueError("duplicate suite configurations")
    attempts = sum(10000 * n_trials * (r["options"]["k"] or 1) for r in rows)
    print(f"Card workload: {len(rows)} setups x {n_trials} trials; "
          f"{attempts:,} card decryptions; base seed={seed}", flush=True)
    print(f"Output: {output.resolve()}", flush=True)
    for row in rows:
        print(f"  {row['directory']}: seed={row['options']['seed']}", flush=True)
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"base_seed": seed, "seed_rule": "base + first-seen configuration index, excluding prior",
                "n_trials": n_trials, "card_decryptions": attempts, "runs": rows}
    manifest_path = output / "suite.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    for index, row in enumerate(rows, 1):
        print(f"[{index}/{len(rows)}] {row['directory']}", flush=True)

        def progress(done, total):
            if done == 1 or done == total or done % 10 == 0:
                print(f"  trial {done}/{total}", flush=True)

        result = run_trials(**row["options"], progress=progress)
        save_results(result, output / row["directory"])
        row["status"] = "complete"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        summary = result["summary"]
        print(f"  rank-one={summary['rank_one_successes']}/{n_trials}; "
              f"median rank={summary['median_rank']:g}; saved", flush=True)
    return manifest


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--setup", choices=SETUPS)
    selection.add_argument("--family", choices=("single", "side", "wallet", "correlation", "sensitivity"))
    selection.add_argument("--suite", choices=("smoke", "full"),
                           help="smoke defaults to 1 trial per row; full to 1000")
    parser.add_argument("--trials", type=int, help="trials per card configuration (default 1, full 1000)")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--dte", choices=("weak", "good", "rsa"))
    parser.add_argument("--prior", choices=PRIORS)
    parser.add_argument("--k", type=int, choices=WALLET_SIZES)
    parser.add_argument("--rho", type=float)
    parser.add_argument("--rho-sweep", action="store_true", help="Bayes only; all k unless --k is given")
    parser.add_argument("--bits", type=int, help="RSA factor size only; default 16, explicitly 1024 for real-size")
    parser.add_argument("--output", type=Path, required=True,
                        help="new card suite directory, or new RSA JSON file")
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError(f"output already exists: {args.output}")
        n = args.trials if args.trials is not None else (1000 if args.suite == "full" else 1)
        if n < 1:
            raise ValueError("trials must be positive")
        if args.setup == "rsa-verify":
            if (args.dte not in (None, "rsa") or args.prior not in (None, "uniform")
                    or args.k is not None or args.rho is not None or args.rho_sweep or n != 1):
                raise ValueError("RSA uses one explicit trial, uniform PIN and no wallet options")
            bits = 16 if args.bits is None else args.bits
            if bits < 3:
                raise ValueError("RSA bits must be at least 3")
            print(f"Explicit RSA: bits={bits}, seed={args.seed}, 10000 guesses; "
                  f"output={args.output.resolve()}", flush=True)
            result = run_demo(bits, args.seed, verbose=True)
            save_result(result, args.output)
            print(f"Verified PINs={result['matching_pin_count']}; "
                  f"true PIN survives={result['true_pin_survived']}; saved", flush=True)
            return
        if args.bits is not None:
            raise ValueError("--bits applies only to --setup rsa-verify")
        if args.setup is not None:
            config = {"setup": args.setup, "dte": args.dte or "good",
                      "prior": args.prior or "uniform", "k": args.k, "rho": args.rho}
            if args.rho_sweep:
                if args.setup != "wallet-bayes-pin" or args.rho is not None:
                    raise ValueError("--rho-sweep requires wallet-bayes-pin and no --rho")
                configurations = [dict(config, k=k, rho=rho)
                                  for k in ((args.k,) if args.k is not None else WALLET_SIZES)
                                  for rho in RHOS]
            else:
                configurations = [config]
        else:
            if any(v is not None for v in (args.dte, args.prior, args.k, args.rho)) or args.rho_sweep:
                raise ValueError("family/suite options are fixed; use --setup for custom options")
            configurations = experiment_matrix(args.family or args.suite)
        run_suite(configurations, n, args.seed, args.output)
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
