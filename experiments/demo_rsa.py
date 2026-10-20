"""Narrated RSA honey-encryption demo; default factor size is reduced for learning.

Run: python -m experiments.demo_rsa --bits 16 --seed 2026
Real-size runs require explicit --bits 1024 and can take substantially longer.
"""

import argparse
import hashlib
import json
import platform
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from random import Random
from time import perf_counter

from sympy.external.gmpy import GROUND_TYPES

from attacks.brute_force import brute_force
from attacks.rsa_verify import find_real_prime
from dte.rsa_prime import RSAPrimeDTE, generate_real_prime
from framework.he import ALL_PINS, decrypt, encrypt


def run_demo(bits: int = 16, seed: int = 2026, *, benchmark_guesses: int = 0,
             benchmark_only: bool = False, verbose: bool = False) -> dict:
    """Run one reproducible trial, returning measurements and generated toy secrets."""
    started = perf_counter()
    dte = RSAPrimeDTE(bits)
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TypeError("seed must be an integer")
    if isinstance(benchmark_guesses, bool) or not isinstance(benchmark_guesses, int):
        raise TypeError("benchmark_guesses must be an integer")
    if not 0 <= benchmark_guesses <= len(ALL_PINS):
        raise ValueError("benchmark_guesses must be between 0 and 10000")
    if benchmark_only and benchmark_guesses == 0:
        raise ValueError("benchmark_only requires at least one benchmark guess")

    if verbose:
        label = "real-size factors" if bits >= 1024 else "REDUCED-SIZE teaching example"
        print(f"{label}: bits={bits}, seed={seed}", flush=True)
        print("Victim: generating distinct p/q and encrypting p under a uniform PIN.", flush=True)
    rng = Random(seed)
    p = generate_real_prime(bits, rng)
    q = generate_real_prime(bits, rng)
    while q == p:
        q = generate_real_prime(bits, rng)
    N = p * q
    pin = rng.choice(ALL_PINS)
    ct = encrypt(dte, p, pin, rng)
    result = {
        "bits": bits, "seed": seed, "reduced_size": bits < 1024,
        "p": p, "q": q, "N": N, "modulus_bits": N.bit_length(),
        "true_pin": pin, "pin_distribution": "uniform",
        "ciphertext_hex": ct.to_bytes().hex(),
        "ciphertext_bytes": len(ct.to_bytes()),
        "correct_pin_recovers_p": decrypt(dte, ct, pin) == p,
        "benchmark": None,
    }

    if benchmark_guesses:
        bench_start = perf_counter()
        for guess in ALL_PINS[:benchmark_guesses]:
            decrypt(dte, ct, guess)
        seconds = perf_counter() - bench_start
        estimate = seconds / benchmark_guesses * len(ALL_PINS)
        result["benchmark"] = {
            "guesses": benchmark_guesses, "seconds": seconds,
            "estimated_full_seconds": estimate,
        }
        if verbose:
            print(f"Benchmark: {benchmark_guesses} guesses in {seconds:.3f}s; "
                  f"estimated 10000-guess time {estimate:.1f}s (approximate).", flush=True)
    if benchmark_only:
        result["status"] = "benchmark-only"
        result["elapsed_seconds"] = perf_counter() - started
        return result

    if verbose:
        print("Attacker: enumerating all 10000 PINs using only ciphertext and the DTE.", flush=True)
    attack_start = perf_counter()
    candidates = brute_force(ct, dte)
    brute_seconds = perf_counter() - attack_start
    verify_start = perf_counter()
    matches = find_real_prime(candidates, N)
    verify_seconds = perf_counter() - verify_start
    result.update({
        "status": "complete", "candidate_count": len(candidates),
        "matches": matches, "matching_pin_count": len(matches),
        "unique_factor_count": len({factor for _, factor in matches}),
        "true_pin_survived": (pin, p) in matches,
        "brute_force_seconds": brute_seconds,
        "verification_seconds": verify_seconds,
        "elapsed_seconds": perf_counter() - started,
    })
    return result


def save_result(result: dict, path: Path) -> None:
    """Save a new JSON record with versions and source identity; never overwrite."""
    root = Path(__file__).resolve().parent.parent
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                              capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                           capture_output=True, text=True, check=True).stdout.strip()
    sources = ["experiments/demo_rsa.py", "dte/rsa_prime.py", "framework/he.py",
               "attacks/brute_force.py", "attacks/rsa_verify.py"]
    versions = {name: version(name) for name in ("sympy", "cryptography")}
    try:
        versions["gmpy2"] = version("gmpy2")
    except PackageNotFoundError:
        versions["gmpy2"] = None
    metadata = {
        "python": platform.python_version(), "platform": platform.platform(),
        "versions": versions, "sympy_ground_types": GROUND_TYPES,
        "git_revision": revision, "git_dirty": bool(dirty),
        "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                          for name in sources},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as file:
        json.dump({"result": result, "metadata": metadata}, file, indent=2)
        file.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bits", type=int, default=16, help="factor bits; 1024 for real-size run")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--benchmark-guesses", type=int, default=0)
    parser.add_argument("--benchmark-only", action="store_true")
    parser.add_argument("--output", type=Path, help="new JSON file, including generated demo secrets")
    args = parser.parse_args()
    if args.output is not None and args.output.exists():
        parser.error(f"output already exists: {args.output}")
    try:
        result = run_demo(args.bits, args.seed, benchmark_guesses=args.benchmark_guesses,
                          benchmark_only=args.benchmark_only, verbose=True)
    except (TypeError, ValueError) as error:
        parser.error(str(error))
    print(f"Public modulus: {result['modulus_bits']} bits; "
          f"ciphertext: {result['ciphertext_bytes']} bytes.")
    if result["status"] == "complete":
        print(f"Candidates: {result['candidate_count']}; matching PINs: {result['matching_pin_count']}; "
              f"distinct factors: {result['unique_factor_count']}.")
        print(f"Evaluation: correct PIN recovers p={result['correct_pin_recovers_p']}; "
              f"true PIN survives verification={result['true_pin_survived']}.")
        print(f"Matching PINs (first 5): {[pin for pin, _ in result['matches'][:5]]}")
        print(f"Brute force: {result['brute_force_seconds']:.3f}s; "
              f"public verification: {result['verification_seconds']:.6f}s.")
        print("Factor recovery does not guarantee unique original-PIN recovery. "
              "This verifies guessed secrets; it does not break AES or factor N without candidates.")
    if args.output is not None:
        save_result(result, args.output)
        print(f"Saved: {args.output.resolve()}")


if __name__ == "__main__":
    main()
