# Final evidence: 1,000 trials per card configuration

Start with [the project conclusion](../../CONCLUSION.md). This directory contains
the final measured evidence, not the earlier three-trial smoke outputs.

| Path | Contents |
|---|---|
| `cards/suite.json` | All 56 configurations, exact options, per-run seeds and complete statuses. |
| `cards/<configuration>/trials.csv` | All 1,000 raw true-PIN ranks for that configuration. |
| `cards/<configuration>/summary.json` and `summary.csv` | Rates, Wilson intervals, median ranks and guess-budget summaries. |
| `cards/<configuration>/metadata.json` | Original timestamps, revisions, dirty state, settings, versions and input/source hashes. |
| `summary.csv` | Compact comparison of all 56 configurations. Rates are fractions, not percentages. |
| `evidence/aes.json` | Original measured CTR/GCM/CBC acceptance counts. |
| `evidence/rsa-1024.json` | Original real-size RSA run, including generated demonstration factors. |
| `charts/` | Five selected figures, each PNG/SVG, with input provenance in `charts.json`. |
| `verification.json` | Audited counts, timing and SHA-256 inventory of original raw evidence. |

These are synthetic demonstration secrets, not real card data or production RSA
keys. Original results were copied byte-for-byte from the external experiment
workspace; the originals were retained. `.gitattributes` disables line-ending
conversion for evidence so recorded hashes survive Git checkout.

## Coverage

The 56 configurations comprise 2 uniform controls, 6 single-card attacks, 4
side-information attacks, 9 same-bank wallet configurations, 12 additional
Bayes correlation rows and 23 alternative-prior counterparts. Total: **56,000
trials and 1.47 billion card decryptions**. Sum of the recorded configuration
runtimes is **38,594.880 seconds (10.72 hours)**; this is not a promise about
another machine's runtime.

The run started at revision `e69c1c0` (21 configurations) and continued at
`e615caa` (35 configurations) after the plotting/documentation commit. The
recorded harness/result/CLI source hashes and data hashes are identical to the
audited source; no cryptographic algorithm changed during the run. Original
metadata and dirty-state flags have not been rewritten to imply a single clean
revision. The supplied RSA/AES source hashes also match the audited crypto code.
Environment/timestamp and original Git metadata remain evidence of execution,
not settings to substitute when reproducing a trial.

## Reproduce charts without rerunning experiments

From the repository root, choose a **new** output directory:

```powershell
.\.venv\Scripts\python.exe -m experiments.plot_results results/final-2026-10-20/cards --kind presentation --aes results/final-2026-10-20/evidence/aes.json --rsa results/final-2026-10-20/evidence/rsa-1024.json --output results/my-five-charts
```

Use `--kind all` instead for the full 32-figure diagnostic set. The five selected
figures use the same saved results and plotting functions. Plotting performs
no encryption. `charts.json` contains the generation machine's absolute source
locations plus hashes; after cloning, use the relative paths above to regenerate
provenance for your own checkout.

## Reproduce an experiment

The recorded study command was:

```powershell
.\.venv\Scripts\python.exe -m experiments.success_vs_baseline --suite full --trials 1000 --seed 2026 --output results/my-new-full-run
```

This performs the expensive calculation again. To repeat a single row, read its
options in `cards/suite.json` and use `--setup` with its exact seed, trial count,
DTE, prior and k/rho where applicable. Per-run seeds can differ from base seed
2026. Keep software/data fixed; nonuniform draws are batched, so trial count
also affects the random draw sequence. Runtime and timestamps will differ.

No statistical significance or real-world probability is inferred merely from
two point estimates. The rare 0.01% theoretical baseline is not precisely
estimated by 1,000 trials. Use the assumptions and intervals in the conclusion.
